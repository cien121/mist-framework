package mistcore

// RTO formula tests (chan 2026-10-23).
//
// The old formula RTO = SRTT + 4*RTTVAR (floored at 200ms) collapsed to
// ~1xRTT on stable paths where RTTVAR -> 0, causing ~3.5% spurious
// retransmits on a clean 200ms link (phone -> VPS over WireGuard).
//
// New formula: RTO = SRTT + max(4*RTTVAR, SRTT/8, 1ms) + max_ack_delay.

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"
)

// manualClock is a deterministic clock for reliability tests.
type manualClock struct {
	t time.Time
}

func (c *manualClock) Now() time.Time          { return c.t }
func (c *manualClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// newTestReliability creates a UDPReliability driven by a manual clock.
// BBR is nil: these tests target RTO/retransmit logic, not congestion
// control.
func newTestReliability() (*UDPReliability, *manualClock) {
	clk := &manualClock{t: time.Unix(1700000000, 0)}
	rel := NewUDPReliability(nil)
	rel.now = clk.Now
	rel.lastAckSent = clk.Now()
	return rel, clk
}

// TestRTOFormulaIncludesAckDelay pins the RTO formula. With perfectly stable
// 200ms RTT samples, RTTVAR collapses and the RTO must be
// 200ms + max(0, 200ms/8, 1ms) + 10ms = 235ms.
//
// Negative verification: dropping the max_ack_delay term yields 225ms,
// dropping the SRTT/8 floor yields 211ms — both fail this test.
func TestRTOFormulaIncludesAckDelay(t *testing.T) {
	rel, _ := newTestReliability()
	const n = 50
	for i := 0; i < n; i++ {
		pn := uint32(i)
		rel.PacketSent(pn, [][]byte{{0x01}}, 100)
		if !rel.PacketAcked(pn, 200*time.Millisecond) {
			t.Fatalf("packet %d not newly acked", i)
		}
	}
	want := 200*time.Millisecond + 25*time.Millisecond + UDPMaxAckDelay
	if got := rel.RTO(); got != want {
		t.Fatalf("RTO = %v, want %v (formula must be SRTT + max(4*RTTVAR, SRTT/8, 1ms) + max_ack_delay)", got, want)
	}
	// Sanity: comfortably above one RTT plus a full delayed ACK.
	if rel.RTO() <= 200*time.Millisecond+UDPAckTimeout {
		t.Fatalf("RTO %v not above RTT+max_ack_delay", rel.RTO())
	}
}

// TestAckFrameDelayRoundTrip verifies the ack_delay wire field survives
// encode -> decode.
func TestAckFrameDelayRoundTrip(t *testing.T) {
	largest := uint32(12345)
	delay := 7 * time.Millisecond
	ranges := [][2]uint32{{1, 10}, {20, 30}}
	frame := EncodeAckFrame(3, largest, delay, ranges)
	frames, err := DecodeUDPFrames(frame)
	if err != nil {
		t.Fatalf("decode frames: %v", err)
	}
	if len(frames) != 1 || frames[0].Type != UDPFrameAck {
		t.Fatalf("expected 1 ACK frame, got %d", len(frames))
	}
	dl, ad, rs, err := DecodeAckFrame(frames[0].Payload)
	if err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if dl != largest {
		t.Fatalf("largest = %d, want %d", dl, largest)
	}
	if ad != delay {
		t.Fatalf("ackDelay = %v, want %v", ad, delay)
	}
	if len(rs) != len(ranges) || rs[0] != ranges[0] || rs[1] != ranges[1] {
		t.Fatalf("ranges = %v, want %v", rs, ranges)
	}
}

// rtoSimResult summarizes a simulated transfer.
type rtoSimResult struct {
	retransmits int // packets retransmitted via RTO or fast retransmit
	completed  bool
}

// simulateTransfer runs numPkts packets from sender to receiver over a
// deterministic virtual network.
// oneWay gives the one-way delay as a function of send time; pace is the
// inter-packet send interval (0 = burst all at t=0); lossRate is the
// per-datagram drop probability (seeded). The receiver uses real delayed-ACK
// behavior (10ms timeout, 10-packet threshold); the sender runs CheckRTO
// every 10ms of virtual time. Virtual time is free: no real sleeps happen.
//
// NOTE: oneWay must vary slowly relative to pace, otherwise consecutive
// packets reorder and the (correct) 3-dup-ACK fast retransmit fires.
// That's by design; the jitter test below models RTT drift, not reordering.
func simulateTransfer(t *testing.T, oneWay func(sendTime time.Time) time.Duration, numPkts int, pace time.Duration, lossRate float64, seed int64) rtoSimResult {
	t.Helper()
	clk := &manualClock{t: time.Unix(1700000000, 0)}
	sender := NewUDPReliability(nil)
	sender.now = clk.Now
	sender.lastAckSent = clk.Now()
	receiver := NewUDPReliability(nil)
	receiver.now = clk.Now
	receiver.lastAckSent = clk.Now()

	rng := rand.New(rand.NewSource(seed))

	type dataMsg struct {
		deliverAt time.Time
		pn        uint32
	}
	type ackMsg struct {
		deliverAt time.Time
		largest   uint32
		ranges    [][2]uint32
		ackDelay  time.Duration
	}
	var dataQ []dataMsg
	var ackQ []ackMsg

	const pktBytes = 1300
	var nextPN uint32
	dropped := func() bool { return rng.Float64() < lossRate }
	injectData := func(pn uint32) {
		if dropped() {
			return
		}
		dataQ = append(dataQ, dataMsg{deliverAt: clk.Now().Add(oneWay(clk.Now())), pn: pn})
	}

	retransmits := 0
	sender.OnRetransmit = func(frames [][]byte) error {
		// Re-inject each frame as a new packet, mirroring the session
		// (new packet number, re-tracked via PacketSent).
		for _, f := range frames {
			retransmits++
			pn := nextPN
			nextPN++
			sender.PacketSent(pn, [][]byte{f}, pktBytes)
			injectData(pn)
		}
		return nil
	}
	receiver.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		if dropped() {
			return
		}
		rc := append([][2]uint32(nil), ranges...)
		ackQ = append(ackQ, ackMsg{
			deliverAt: clk.Now().Add(oneWay(clk.Now())),
			largest:   largest,
			ranges:    rc,
			ackDelay:  ackDelay,
		})
	}

	// Paced (or burst) send schedule.
	t0 := clk.Now()
	sendTimes := make([]time.Time, numPkts)
	for i := range sendTimes {
		sendTimes[i] = t0.Add(time.Duration(i) * pace)
	}
	sentCount := 0

	deadline := clk.Now().Add(120 * time.Second)
	for {
		// 0. Send due packets.
		for sentCount < numPkts && !sendTimes[sentCount].After(clk.Now()) {
			pn := nextPN
			nextPN++
			sender.PacketSent(pn, [][]byte{{byte(sentCount)}}, pktBytes)
			injectData(pn)
			sentCount++
		}

		// 1. Deliver due data packets.
		kept := dataQ[:0]
		for _, m := range dataQ {
			if !m.deliverAt.After(clk.Now()) {
				receiver.PacketReceived(m.pn)
			} else {
				kept = append(kept, m)
			}
		}
		dataQ = kept

		// 2. Receiver ACK flush tick (delayed-ACK timeout).
		receiver.FlushAck()

		// 3. Deliver due ACKs.
		keptAck := ackQ[:0]
		for _, m := range ackQ {
			if !m.deliverAt.After(clk.Now()) {
				sender.ProcessAck(m.largest, m.ackDelay, m.ranges)
			} else {
				keptAck = append(keptAck, m)
			}
		}
		ackQ = keptAck

		// 4. Sender RTO check.
		sender.CheckRTO()

		// 5. Done when all sent, nothing unacked, nothing in flight.
		if sentCount == numPkts && len(sender.sentPackets) == 0 && len(dataQ) == 0 && len(ackQ) == 0 {
			return rtoSimResult{retransmits: retransmits, completed: true}
		}
		if !clk.Now().Before(deadline) {
			return rtoSimResult{retransmits: retransmits, completed: false}
		}

		// 6. Advance to the next event (or 10ms tick for FlushAck/RTO).
		next := deadline
		if sentCount < numPkts && sendTimes[sentCount].Before(next) {
			next = sendTimes[sentCount]
		}
		for _, m := range dataQ {
			if m.deliverAt.Before(next) {
				next = m.deliverAt
			}
		}
		for _, m := range ackQ {
			if m.deliverAt.Before(next) {
				next = m.deliverAt
			}
		}
		if tick := clk.Now().Add(10 * time.Millisecond); tick.Before(next) {
			next = tick
		}
		if !next.After(clk.Now()) {
			next = clk.Now().Add(time.Millisecond)
		}
		clk.Advance(next.Sub(clk.Now()))
	}
}

// TestRTONoSpuriousWithDelayedAck replays the phone->VPS联调 scenario:
// 200ms RTT, receiver holds the tail ACK the full 10ms delayed-ACK timeout.
// ~100KB (77 x 1300B) must complete with zero RTO retransmits.
// With the old formula (RTO ~= 200ms) the 7 tail packets fired spuriously.
func TestRTONoSpuriousWithDelayedAck(t *testing.T) {
	res := simulateTransfer(t,
		func(time.Time) time.Duration { return 100 * time.Millisecond },
		77, 0, 0, 1)
	if !res.completed {
		t.Fatal("transfer did not complete")
	}
	if res.retransmits != 0 {
		t.Fatalf("spurious retransmits on clean 200ms link: %d, want 0", res.retransmits)
	}
}

// TestRTONoSpuriousWithJitter: RTT drifts 180-260ms over time (sine, 400ms
// period), packets paced 5ms apart so the drift never reorders them.
// The 4*RTTVAR term must absorb the drift: still zero spurious retransmits.
func TestRTONoSpuriousWithJitter(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	res := simulateTransfer(t,
		func(sendTime time.Time) time.Duration {
			// 90ms + 40ms*(0.5+0.5*sin): one-way 90-130ms, RTT 180-260ms.
			// Max slope ~0.63ms/ms << 5ms pace: no reordering.
			phase := 2 * math.Pi * sendTime.Sub(t0).Seconds() / 0.4
			return 90*time.Millisecond + time.Duration(40*(0.5+0.5*math.Sin(phase))*float64(time.Millisecond))
		},
		77, 5*time.Millisecond, 0, 1)
	if !res.completed {
		t.Fatal("transfer did not complete")
	}
	if res.retransmits != 0 {
		t.Fatalf("spurious retransmits with 180-260ms RTT drift: %d, want 0", res.retransmits)
	}
}

// TestRTOLossRecoveryMultiSeed: 25 seeds x {5%, 8%, 10%} loss.
// Validates the larger RTO doesn't break loss recovery: every transfer
// must complete with all packets acknowledged.
func TestRTOLossRecoveryMultiSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-seed loss sweep in short mode")
	}
	for _, loss := range []float64{0.05, 0.08, 0.10} {
		for seed := int64(1); seed <= 25; seed++ {
			name := fmt.Sprintf("loss=%.2f/seed=%d", loss, seed)
			t.Run(name, func(t *testing.T) {
				res := simulateTransfer(t,
					func(time.Time) time.Duration { return 100 * time.Millisecond },
					50, 0, loss, seed*1000+int64(loss*100))
				if !res.completed {
					t.Fatalf("transfer did not complete (loss=%.2f seed=%d)", loss, seed)
				}
			})
		}
	}
}

// TestAckDelayClampedToMax verifies that a peer-supplied ack_delay above
// UDPMaxAckDelay is truncated before RTT sampling (chan 2026-10-23).
//
// Without truncation, a faulty or malicious receiver reporting a huge
// ack_delay would collapse SRTT (and BBR's min RTT) toward zero, since
// the sample is (now - sendTime) - ackDelay.
func TestAckDelayClampedToMax(t *testing.T) {
	rel, clk := newTestReliability()

	// Seed SRTT with a stable 200ms.
	for i := 0; i < 20; i++ {
		pn := uint32(i)
		rel.PacketSent(pn, [][]byte{{0x01}}, 100)
		if !rel.PacketAcked(pn, 200*time.Millisecond) {
			t.Fatalf("packet %d not newly acked", i)
		}
	}
	if rel.srtt < 190*time.Millisecond || rel.srtt > 210*time.Millisecond {
		t.Fatalf("precondition: srtt = %v, want ~200ms", rel.srtt)
	}

	// Malicious peer: claims it held the ACK for an hour.
	pn := uint32(100)
	rel.PacketSent(pn, [][]byte{{0x01}}, 100)
	clk.Advance(200 * time.Millisecond) // true RTT is 200ms
	rel.ProcessAck(pn, time.Hour, [][2]uint32{{100, 100}})

	// The corrected sample must be 200ms - UDPMaxAckDelay (truncated),
	// not ~1us (which an untruncated hour-long delay would produce).
	// SRTT moves 1/8 toward the new sample per RFC 6298.
	wantSample := 200*time.Millisecond - UDPMaxAckDelay
	wantSRTT := (7*200*time.Millisecond + wantSample) / 8
	if rel.srtt < wantSRTT-time.Millisecond || rel.srtt > wantSRTT+time.Millisecond {
		t.Fatalf("srtt = %v after malicious ack_delay, want ~%v (ack_delay must be truncated to %v)",
			rel.srtt, wantSRTT, UDPMaxAckDelay)
	}
	if rel.srtt < 100*time.Millisecond {
		t.Fatalf("srtt collapsed to %v: malicious ack_delay was not truncated", rel.srtt)
	}

	// Boundary: exactly max is fine, 1ns over must also truncate.
	pn2 := uint32(101)
	rel.PacketSent(pn2, [][]byte{{0x01}}, 100)
	clk.Advance(200 * time.Millisecond)
	srttBefore := rel.srtt
	rel.ProcessAck(pn2, UDPMaxAckDelay+time.Nanosecond, [][2]uint32{{101, 101}})
	wantSample2 := 200*time.Millisecond - UDPMaxAckDelay
	wantSRTT2 := (7*srttBefore + wantSample2) / 8
	if rel.srtt < wantSRTT2-time.Millisecond || rel.srtt > wantSRTT2+time.Millisecond {
		t.Fatalf("srtt = %v after ack_delay=max+1ns, want ~%v", rel.srtt, wantSRTT2)
	}
}

// TestRTORetiredPacketLateAck: a late ACK for an RTO-retired packet must be
// a no-op.
//
// Scenario (false retransmit, happens on real networks): RTO fires, the
// original packet is retired from sentPackets (inflight deducted) and its
// frames are retransmitted under a NEW packet number. The original was
// merely slow — its ACK arrives later.
//
// Required behavior:
//  1. PacketAcked(oldPN) returns false (not newly acknowledged).
//  2. bytesInFlight is unchanged (no double deduction — never negative,
//     never eats another packet's credit).
//  3. The RTT sample is NOT fed to the RTO estimator (the sample belongs
//     to a packet that no longer exists; using it would corrupt SRTT).
//
// The sandbox's random-loss suites never cover this: they drop packets,
// they don't delay them past RTO and then deliver the ACK anyway.
func TestRTORetiredPacketLateAck(t *testing.T) {
	rel, clk := newTestReliability()

	// Seed RTT as a real 200ms-RTT session would have after handshakes.
	// RTO = 200ms + max(4*25ms, 200ms/8, 1ms) + 10ms = 310ms.
	rel.srtt = 200 * time.Millisecond
	rel.rttvar = 25 * time.Millisecond
	rel.rto = 310 * time.Millisecond

	// Send two packets.
	rel.PacketSent(1, [][]byte{{0x01}}, 100)
	rel.PacketSent(2, [][]byte{{0x02}}, 100)
	if got := rel.BytesInFlight(); got != 200 {
		t.Fatalf("inflight = %d, want 200", got)
	}

	// RTO retransmit: caller seals new packets with new numbers (simulated
	// here by re-tracking them directly, as sealPacketTracked would).
	var nextPN uint32 = 100
	rel.OnRetransmit = func(frames [][]byte) error {
		for _, f := range frames {
			nextPN++
			rel.PacketSent(nextPN, [][]byte{f}, 100)
		}
		return nil
	}

	// Advance past RTO and fire it.
	clk.Advance(400 * time.Millisecond)
	rel.CheckRTO()

	// Both originals retired; only the two retransmits are in flight.
	if got := rel.BytesInFlight(); got != 200 {
		t.Fatalf("inflight after RTO = %d, want 200 (2 retransmits)", got)
	}
	if _, ok := rel.sentPackets[1]; ok {
		t.Fatalf("pn=1 still tracked after RTO retirement")
	}
	if _, ok := rel.sentPackets[2]; ok {
		t.Fatalf("pn=2 still tracked after RTO retirement")
	}

	srttBefore := rel.srtt
	inflightBefore := rel.BytesInFlight()

	// The late ACK for the retired original arrives.
	// Use a wildly different RTT (50ms vs 200ms SRTT) so any sampling
	// would be visible.
	if rel.PacketAcked(1, 50*time.Millisecond) {
		t.Fatalf("PacketAcked(retired pn=1) returned true, want false")
	}

	// 1. inflight must be unchanged — no double deduction.
	if got := rel.BytesInFlight(); got != inflightBefore {
		t.Fatalf("inflight changed by late ACK: %d -> %d, want unchanged",
			inflightBefore, got)
	}
	// 2. Never negative, even in a degenerate interleaving.
	if got := rel.BytesInFlight(); got < 0 {
		t.Fatalf("inflight went negative: %d", got)
	}
	// 3. SRTT must be untouched — the sample belongs to a dead packet.
	if rel.srtt != srttBefore {
		t.Fatalf("srtt changed by late ACK: %v -> %v, want unchanged",
			srttBefore, rel.srtt)
	}

	// Sanity: the retransmit's own ACK still works normally.
	if !rel.PacketAcked(101, 200*time.Millisecond) {
		t.Fatalf("PacketAcked(retransmit pn=101) returned false, want true")
	}
	if got := rel.BytesInFlight(); got != 100 {
		t.Fatalf("inflight after acking retransmit = %d, want 100", got)
	}
}

// TestRTORetiredPacketLateAckNoRetransmit covers the degenerate case: RTO
// fires but OnRetransmit is nil (nothing to retransmit with), so the old
// entries are kept. A late ACK must still ack the ORIGINAL packet normally
// — it was never retired.
func TestRTORetiredPacketLateAckNoRetransmit(t *testing.T) {
	rel, clk := newTestReliability()
	rel.srtt = 200 * time.Millisecond
	rel.rttvar = 25 * time.Millisecond
	rel.rto = 310 * time.Millisecond

	rel.PacketSent(1, [][]byte{{0x01}}, 100)

	// No OnRetransmit: CheckRTO returns early, entries are kept.
	clk.Advance(400 * time.Millisecond)
	rel.CheckRTO()

	if _, ok := rel.sentPackets[1]; !ok {
		t.Fatalf("pn=1 retired even though OnRetransmit was nil")
	}
	if !rel.PacketAcked(1, 200*time.Millisecond) {
		t.Fatalf("PacketAcked(pn=1) returned false, want true (never retired)")
	}
	if got := rel.BytesInFlight(); got != 0 {
		t.Fatalf("inflight = %d, want 0", got)
	}
}
