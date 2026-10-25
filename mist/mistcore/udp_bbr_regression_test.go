package mistcore

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/monotime"

	"mist/mistcore/bbr"
)

// fakeClock is a manually-advanced clock implementing bbr.Clock.
// It lets tests drive BBR on a fully deterministic timeline instead of
// depending on real time (which would make the test flaky).
type fakeClock struct {
	now time.Time
}

func (f *fakeClock) Now() monotime.Time { return monotime.FromTime(f.now) }

// Advance moves the clock forward by d.
func (f *fakeClock) Advance(d time.Duration) { f.now = f.now.Add(d) }

var _ bbr.Clock = (*fakeClock)(nil)

// TestBBRStartupExitSimulatedLink is a regression test for the 2026-10-22 bug:
//
//	BBRController.OnPacketAcked/OnPacketLost routed to bbrSender.OnPacketAcked/
//	OnPacketLost, which are no-ops ("// Do nothing."). BBR then received zero
//	bandwidth samples: the congestion window stayed frozen at the initial
//	window and BBR never left Startup (found by the weak-network stress test,
//	where cwnd was stuck at 13.2KB).
//
// The test drives BBR over a simulated link with a fixed rate and RTT using
// the fake clock above (no real time is involved), then asserts:
//  1. BBR leaves Startup after a few RTTs (user requirement, 2026-10-23).
//  2. The bandwidth estimate converges to the simulated link rate (±10%):
//     asserting only the state transition could pass even with wrong samples.
//  3. The congestion window grows past the initial window (direct signal that
//     ACKs actually feed bandwidth samples into BBR).
//
// If OnPacketAcked regresses to the no-op, all three assertions fail: with no
// samples the cwnd never grows, the bandwidth estimate stays zero, and
// Startup never exits.
func TestBBRStartupExitSimulatedLink(t *testing.T) {
	const (
		pktSize         = 1350
		packetsPerRound = 74
		// leaveUnacked keeps this many packets of each round unacknowledged
		// until the next round, so the link never fully drains. A fully
		// drained link looks app-limited to BBR, which would suppress the
		// full-bandwidth detection this test relies on.
		leaveUnacked = 10
		rtt          = 100 * time.Millisecond
		rounds       = 8
	)
	// Simulated link rate implied by the traffic pattern: packetsPerRound
	// packets of pktSize bytes delivered every rtt.
	linkRateBps := uint64(packetsPerRound) * uint64(pktSize) * 8 * uint64(time.Second) / uint64(rtt)

	clk := &fakeClock{now: time.Now()}
	ctl := NewBBRControllerWithClock(pktSize, clk)

	if !ctl.InSlowStart() {
		t.Fatal("BBR should start in Startup")
	}
	if got := ctl.CongestionWindow(); got != 10*pktSize {
		t.Fatalf("initial cwnd = %d, want %d", got, 10*pktSize)
	}

	sendInterval := rtt / packetsPerRound // even pacing at exactly the link rate

	var pktNum, acked uint32
	inflight := 0

	for r := 0; r < rounds; r++ {
		roundStart := clk.now
		// Send one round's worth of packets, evenly paced.
		for i := 0; i < packetsPerRound; i++ {
			clk.Advance(sendInterval)
			ctl.OnPacketSent(pktNum, pktSize, inflight)
			inflight += pktSize
			pktNum++
		}
		// Acks arrive exactly one RTT after the round started.
		clk.Advance(roundStart.Add(rtt).Sub(clk.now))
		// Ack everything except the last leaveUnacked packets.
		for acked < pktNum-uint32(leaveUnacked) {
			ctl.OnPacketAcked(acked, pktSize, inflight-pktSize, rtt)
			inflight -= pktSize
			acked++
		}
	}

	// 1. BBR must have left Startup.
	if ctl.InSlowStart() {
		t.Fatalf("BBR still in Startup after %d RTTs on a %.3f Mbps link; "+
			"bandwidth samples are not reaching BBR (see 2026-10-22 no-op bug)",
			rounds, float64(linkRateBps)/1e6)
	}

	// 2. Bandwidth estimate must converge to the simulated link rate.
	est := ctl.BandwidthEstimate()
	lo, hi := linkRateBps*9/10, linkRateBps*11/10
	if est < lo || est > hi {
		t.Fatalf("bandwidth estimate = %d bps, want within ±10%% of link rate %d bps",
			est, linkRateBps)
	}

	// 3. cwnd must have grown past the initial window.
	if got := ctl.CongestionWindow(); got <= 10*pktSize {
		t.Fatalf("cwnd = %d, want > initial window %d; ACKs are not feeding BBR",
			got, 10*pktSize)
	}

	t.Logf("BBR left Startup; bandwidth estimate = %d bps (link %d bps), cwnd = %d",
		est, linkRateBps, ctl.CongestionWindow())
}
