// Package mistcore: Mist UDP reliability layer.
//
// Implements per-packet reliability per UDP-DESIGN.md §6:
//   - ACK frames: cumulative + up to 8 ranges, sent every 10ms or 10 packets
//   - Retransmission: RTO (Jacobson) + fast retransmit (3 dup ACKs)
//   - Retransmissions use NEW packet numbers (QUIC style, §6.4):
//     retransmitted frames keep their STREAM OFFSET, but the packet number
//     (and hence nonce) is new. Receiver dedups by OFFSET, not packet number.
//   - Replay detection: sliding window bitmap (not strict monotonic,
//     because retransmits use new numbers)
//   - RTT sampling: ALL newly-acknowledged packets participate (§11;
//     no ambiguity with new-number retransmits)
//   - Flow control: connection-level via BBR window; stream-level via
//     WINDOW_UPDATE (256KB initial)
//
// Depends on header protection being applied first: ACK/replay logic uses
// the unmasked real packet number (§3.2, §4.2).
package mistcore

import (
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Constants (per design §6)
// ---------------------------------------------------------------------------

const (
	// UDPAckTimeout is the max delay before sending an ACK.
	UDPAckTimeout = 10 * time.Millisecond
	// UDPAckPacketThreshold sends an ACK every N received packets.
	UDPAckPacketThreshold = 10
	// UDPMaxAckRanges caps ACK ranges at 8 (§6.3).
	UDPMaxAckRanges = 8
	// UDPDupAckThreshold triggers fast retransmit (§6.4).
	UDPDupAckThreshold = 3
	// UDPInitialRTO is the initial retransmission timeout (§6.4).
	UDPInitialRTO = 1 * time.Second
	// UDPMinRTO floors the RTO. It is a backstop for near-zero RTT paths
	// only; the real margin comes from the relative terms in the formula.
	UDPMinRTO = 20 * time.Millisecond
	// UDPMaxRTO caps the RTO (exponential backoff ceiling).
	UDPMaxRTO = 60 * time.Second
	// UDPMaxAckDelay is the receiver's maximum delayed-ACK hold time.
	// The sender adds this to the RTO so a delayed ACK never triggers a
	// spurious retransmit on a healthy path.
	// TODO: negotiate max_ack_delay in the handshake instead of a shared
	// constant, so the receiver's timer can change independently.
	UDPMaxAckDelay = UDPAckTimeout // 10ms
	// UDPStreamWindowInitial is the initial per-stream flow control window (§6.5).
	UDPStreamWindowInitial = 256 * 1024 // 256KB
)

// ---------------------------------------------------------------------------
// Sliding window bitmap (replay detection)
// ---------------------------------------------------------------------------

// SlidingWindow tracks received packet numbers using a bitmap.
// Supports out-of-order receipt and new-number retransmissions.
type SlidingWindow struct {
	mu sync.Mutex
	// base is the lowest packet number in the window.
	base uint32
	// bits tracks receipt: bit i corresponds to packet base+i.
	// Window size is 1024 packets.
	bits [16]uint64 // 16*64 = 1024 bits
}

const slidingWindowSize = 1024

// NewSlidingWindow creates an empty receive window.
func NewSlidingWindow() *SlidingWindow {
	return &SlidingWindow{}
}

// Mark records packet n as received.
// Returns true if this is the first time n was seen (not a duplicate/replay).
func (w *SlidingWindow) Mark(n uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Too old: below window.
	if n < w.base {
		return false // duplicate or reordered beyond window
	}
	// Too far ahead: slide window forward.
	if n >= w.base+slidingWindowSize {
		shift := n - (w.base + slidingWindowSize) + 1
		w.slideLocked(shift)
	}
	offset := n - w.base
	word := offset / 64
	bit := offset % 64
	if w.bits[word]&(1<<bit) != 0 {
		return false // already seen: duplicate
	}
	w.bits[word] |= 1 << bit
	return true
}

// slideLocked advances the window base, clearing old bits.
func (w *SlidingWindow) slideLocked(shift uint32) {
	words := int(shift / 64)
	bits := shift % 64
	if words >= 16 {
		for i := range w.bits {
			w.bits[i] = 0
		}
	} else {
		for i := 0; i < 16; i++ {
			var v uint64
			if i+words < 16 {
				v = w.bits[i+words] >> bits
				if bits != 0 && i+words+1 < 16 {
					v |= w.bits[i+words+1] << (64 - bits)
				}
			}
			w.bits[i] = v
		}
	}
	w.base += shift
}

// Ranges returns up to maxRanges [start,end] received intervals,
// ordered from highest to lowest (for ACK frames).
func (w *SlidingWindow) Ranges(maxRanges int) [][2]uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()

	var ranges [][2]uint32
	// Scan from highest bit downward.
	var curEnd uint32
	inRange := false
	// Find highest set bit first.
	for offset := int(slidingWindowSize) - 1; offset >= 0 && len(ranges) < maxRanges; offset-- {
		word := offset / 64
		bit := uint(offset % 64)
		set := w.bits[word]&(1<<bit) != 0
		pktNum := w.base + uint32(offset)
		if set {
			if !inRange {
				curEnd = pktNum
				inRange = true
			}
		} else {
			if inRange {
				ranges = append(ranges, [2]uint32{pktNum + 1, curEnd})
				inRange = false
			}
		}
	}
	if inRange {
		// Range extends contiguously down to base (we scanned top-down
		// and never hit an unset bit, so all bits in [base, curEnd] are set).
		ranges = append(ranges, [2]uint32{w.base, curEnd})
	}
	return ranges
}

// Largest returns the highest received packet number, or 0 if none.
func (w *SlidingWindow) Largest() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	for offset := int(slidingWindowSize) - 1; offset >= 0; offset-- {
		word := offset / 64
		bit := uint(offset % 64)
		if w.bits[word]&(1<<bit) != 0 {
			return w.base + uint32(offset)
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Sent packet tracking
// ---------------------------------------------------------------------------

// SentPacket records an unacknowledged sent packet.
type SentPacket struct {
	// Frames are the raw encoded frames (for retransmission with new packet number).
	Frames [][]byte
	// Bytes is the total UDP datagram size (for BBR accounting).
	Bytes int
	// SendTime is when the packet was (last) transmitted.
	SendTime time.Time
	// Retransmitted counts how many times this logical packet was resent.
	Retransmitted int
}

// ---------------------------------------------------------------------------
// Reliability state (per direction, typically per session)
// ---------------------------------------------------------------------------

// UDPReliability manages per-direction reliability: sent tracking, ACK
// generation, loss detection, and retransmission scheduling.
//
// Byte accounting unit (2026-10-23): all inflight/cwnd accounting uses the
// UDP datagram size, i.e. QUIC short header (13) + ciphertext (plaintext +
// 16-byte AEAD tag). This is the UDP payload length as seen by the socket
// (what sealPacket returns as len(datagram)). It does NOT include the IP
// header (20) or UDP header (8). BBR's bandwidth samples, congestion window,
// and pacing rate use the same unit, so the cwnd gate
// (bytesInFlight + pktSize <= cwnd) is dimensionally consistent.
// QUIC (RFC 9002) uses the same convention.
type UDPReliability struct {
	mu sync.Mutex

	// now returns the current time. Overridable in tests for a
	// deterministic clock; defaults to time.Now.
	now func() time.Time

	// Send side.
	sentPackets   map[uint32]*SentPacket // packetNum → info
	bytesInFlight int
	nextAckNum    uint32 // for fast-retransmit dup counting

	// RTO state (Jacobson).
	srtt     time.Duration
	rttvar   time.Duration
	rto      time.Duration
	rtoCount int // backoff counter

	// Receive side.
	recvWindow *SlidingWindow
	// largestRecvPN/Time track the newest received packet: its arrival
	// time is reported as ack_delay so the peer can correct RTT samples.
	largestRecvPN   uint32
	largestRecvTime time.Time
	// ackPending counts received packets since last ACK.
	ackPending int
	lastAckSent time.Time

	// Fast retransmit: count of ACKs that didn't advance largest.
	dupAckCount  int
	lastAckLargest uint32

	// BBR controller (for CanSend and RTT updates).
	bbr *BBRController

	// Callbacks (set by session).
	// OnRetransmit is called with frames to retransmit (new packet number
	// assigned by caller via SealPacket). It must return nil on success.
	// On error, the reliability layer keeps the old sentPackets entries so
	// the next tick retries instead of dropping data. Callers must chunk
	// frames to fit MaxUDPPlaintext per datagram.
	OnRetransmit func(frames [][]byte) error
	// OnPacketsRetired is called (if set) after CheckRTO successfully
	// retires old sentPackets entries. Receives the retired packet numbers
	// and their byte sizes. Used by tests to keep independent inflight
	// accounting in sync: a retired packet is no longer "in flight" even
	// though it was never ACKed (its retransmit takes its place).
	// Production code typically leaves this nil.
	OnPacketsRetired func(pns []uint32, bytes []int)
	// OnAckNeeded is called when an ACK should be sent; receives the
	// largest packet number, the ranges, and ack_delay: how long the ACK
	// was held after the largest packet arrived. The peer subtracts it
	// from its RTT samples.
	OnAckNeeded func(largest uint32, ranges [][2]uint32, ackDelay time.Duration)
}

// NewUDPReliability creates a reliability tracker.
func NewUDPReliability(bbr *BBRController) *UDPReliability {
	return &UDPReliability{
		sentPackets: make(map[uint32]*SentPacket),
		now:         time.Now,
		rto:         UDPInitialRTO,
		recvWindow:  NewSlidingWindow(),
		lastAckSent: time.Now(),
		bbr:         bbr,
	}
}

// PacketSent records a sent packet for reliability tracking.
// Must be called with the real (unmasked) packet number.
func (r *UDPReliability) PacketSent(packetNum uint32, frames [][]byte, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Copy frames for potential retransmission.
	cp := make([][]byte, len(frames))
	for i, f := range frames {
		c := make([]byte, len(f))
		copy(c, f)
		cp[i] = c
	}
	r.sentPackets[packetNum] = &SentPacket{
		Frames:   cp,
		Bytes:    bytes,
		SendTime: r.now(),
	}
	r.bytesInFlight += bytes
}

// PacketAcked processes an ACK for a single packet number.
// rtt is the measured round-trip time for this packet.
// Returns true if the packet was newly acknowledged.
func (r *UDPReliability) PacketAcked(packetNum uint32, rtt time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	sp, ok := r.sentPackets[packetNum]
	if !ok {
		return false // already acked or unknown
	}
	delete(r.sentPackets, packetNum)
	r.bytesInFlight -= sp.Bytes
	if r.bytesInFlight < 0 {
		r.bytesInFlight = 0
	}
	// Update RTO (Jacobson). All newly-acked packets participate (§11).
	r.updateRTOLocked(rtt)
	// Notify BBR (also updates its RTT).
	if r.bbr != nil {
		r.bbr.OnPacketAcked(packetNum, sp.Bytes, r.bytesInFlight, rtt)
	}
	// Reset RTO backoff on successful ACK.
	r.rtoCount = 0
	r.rto = r.computeRTOLocked()
	return true
}

// computeRTOLocked returns the retransmission timeout (§6.4):
//
//	RTO = SRTT + max(4*RTTVAR, SRTT/8, 1ms) + max_ack_delay
//
// The SRTT/8 term keeps ~12% headroom on stable paths where RTTVAR
// collapses toward zero (without it the RTO hugs 1xRTT and any delayed
// ACK looks like a loss). max_ack_delay covers the receiver's
// delayed-ACK timer so the tail of a burst is never spuriously
// retransmitted on a healthy path.
func (r *UDPReliability) computeRTOLocked() time.Duration {
	varTerm := 4 * r.rttvar
	if rel := r.srtt / 8; varTerm < rel {
		varTerm = rel
	}
	if varTerm < time.Millisecond {
		varTerm = time.Millisecond
	}
	rto := r.srtt + varTerm + UDPMaxAckDelay
	if rto < UDPMinRTO {
		rto = UDPMinRTO
	}
	if rto > UDPMaxRTO {
		rto = UDPMaxRTO
	}
	return rto
}

// updateRTOLocked updates SRTT/RTTVAR per RFC 6298.
func (r *UDPReliability) updateRTOLocked(rtt time.Duration) {
	if r.srtt == 0 {
		r.srtt = rtt
		r.rttvar = rtt / 2
	} else {
		delta := r.srtt - rtt
		if delta < 0 {
			delta = -delta
		}
		r.rttvar = (3*r.rttvar + delta) / 4
		r.srtt = (7*r.srtt + rtt) / 8
	}
}

// ProcessAck handles an incoming ACK frame (largest + ranges + ack_delay).
// ackDelay is how long the receiver held the ACK after the largest packet
// arrived; it is subtracted from every RTT sample so delayed ACKs don't
// inflate SRTT (or BBR's min RTT).
//
// ackDelay comes from the peer, so it is untrusted: values above
// UDPMaxAckDelay are truncated (a buggy/malicious peer must not be able
// to collapse our SRTT and BBR's min RTT toward zero). The corrected
// sample is additionally floored at 1us to guard against underflow.
// Returns the list of newly-acked packet numbers.
func (r *UDPReliability) ProcessAck(largest uint32, ackDelay time.Duration, ranges [][2]uint32) []uint32 {
	now := r.now()
	var newlyAcked []uint32

	// Fast retransmit detection: if largest didn't advance, count dup.
	r.mu.Lock()
	if largest == r.lastAckLargest {
		r.dupAckCount++
	} else {
		r.dupAckCount = 0
		r.lastAckLargest = largest
	}
	needFastRetransmit := r.dupAckCount >= UDPDupAckThreshold
	r.mu.Unlock()

	// Ack all packets in ranges.
	for _, rng := range ranges {
		for pn := rng[0]; pn <= rng[1]; pn++ {
			r.mu.Lock()
			sp, ok := r.sentPackets[pn]
			r.mu.Unlock()
			if !ok {
				continue
			}
			// Correct the sample for the receiver's ACK hold time.
			// ackDelay is peer-supplied: truncate anything above our advertised
			// max before subtracting, so a faulty or malicious receiver cannot
			// drive SRTT / BBR min RTT toward zero.
			if ackDelay > UDPMaxAckDelay {
				ackDelay = UDPMaxAckDelay
			}
			rtt := now.Sub(sp.SendTime) - ackDelay
			if rtt < time.Microsecond {
				rtt = time.Microsecond
			}
			if r.PacketAcked(pn, rtt) {
				newlyAcked = append(newlyAcked, pn)
			}
			// Prevent infinite loop on huge ranges (shouldn't happen, max 8 ranges).
			if pn == ^uint32(0) {
				break
			}
		}
	}

	// Fast retransmit: resend the earliest unacked packet.
	if needFastRetransmit {
		r.mu.Lock()
		var earliest uint32
		var earliestPkt *SentPacket
		first := true
		for pn, sp := range r.sentPackets {
			if first || pn < earliest {
				earliest, earliestPkt, first = pn, sp, false
			}
		}
		cb := r.OnRetransmit
		r.mu.Unlock()
		if earliestPkt != nil && cb != nil {
			earliestPkt.Retransmitted++
			// Seal+transmit FIRST; retire the old entry only on success,
			// so a failed seal keeps the entry for retry (same as CheckRTO).
			if err := cb(earliestPkt.Frames); err == nil {
				r.mu.Lock()
				if sp, ok := r.sentPackets[earliest]; ok && sp == earliestPkt {
					delete(r.sentPackets, earliest)
					r.bytesInFlight -= earliestPkt.Bytes
					if r.bytesInFlight < 0 {
						r.bytesInFlight = 0
					}
					if r.bbr != nil {
						r.bbr.OnPacketLost(earliest, earliestPkt.Bytes, r.bytesInFlight)
					}
				}
				r.mu.Unlock()
			}
		}
		// Reset dup count after triggering.
		r.mu.Lock()
		r.dupAckCount = 0
		r.mu.Unlock()
	}

	return newlyAcked
}

// PacketReceived records a received packet number.
// Returns true if this is a new packet (not duplicate), and whether
// an ACK should be sent now.
func (r *UDPReliability) PacketReceived(packetNum uint32) (isNew bool, ackNow bool) {
	isNew = r.recvWindow.Mark(packetNum)
	if !isNew {
		return false, false
	}
	r.mu.Lock()
	// Track the newest packet's arrival for ack_delay reporting.
	if r.largestRecvTime.IsZero() || packetNum > r.largestRecvPN {
		r.largestRecvPN = packetNum
		r.largestRecvTime = r.now()
	}
	r.ackPending++
	shouldAck := r.ackPending >= UDPAckPacketThreshold ||
		r.now().Sub(r.lastAckSent) >= UDPAckTimeout
	var ackDelay time.Duration
	if shouldAck {
		r.ackPending = 0
		r.lastAckSent = r.now()
		ackDelay = r.lastAckSent.Sub(r.largestRecvTime)
		if ackDelay < 0 {
			ackDelay = 0
		}
	}
	cb := r.OnAckNeeded
	r.mu.Unlock()

	if shouldAck && cb != nil {
		largest := r.recvWindow.Largest()
		ranges := r.recvWindow.Ranges(UDPMaxAckRanges)
		cb(largest, ranges, ackDelay)
	}
	return true, shouldAck
}

// FlushAck sends a pending ACK if packets were received since the last ACK
// and the ACK timeout has elapsed. Call periodically (e.g., every 10ms) so
// the tail of a burst gets ACKed promptly even when no more packets arrive.
// The reported ack_delay lets the sender correct its RTT samples; the RTO
// formula's max_ack_delay term keeps the tail from being spuriously
// retransmitted even if the ACK is held the full timeout.
func (r *UDPReliability) FlushAck() {
	r.mu.Lock()
	if r.ackPending == 0 || r.now().Sub(r.lastAckSent) < UDPAckTimeout {
		r.mu.Unlock()
		return
	}
	r.ackPending = 0
	r.lastAckSent = r.now()
	ackDelay := r.lastAckSent.Sub(r.largestRecvTime)
	if ackDelay < 0 {
		ackDelay = 0
	}
	cb := r.OnAckNeeded
	r.mu.Unlock()

	if cb != nil {
		largest := r.recvWindow.Largest()
		ranges := r.recvWindow.Ranges(UDPMaxAckRanges)
		cb(largest, ranges, ackDelay)
	}
}

// CheckRTO scans for packets that have timed out and returns their frames
// for retransmission (with new packet numbers, per §6.4).
// Seal+transmit happens FIRST via OnRetransmit; the old sentPackets entries
// are retired only after the callback returns nil. On error the old entries
// are kept so the next tick retries instead of the data being silently
// dropped (2026-10-23 lab tail-loss root cause #2: multi-packet RTO batches
// exceeding MaxUDPPlaintext failed the seal and lost the packets).
// Call periodically (e.g., every 10ms) from the session's timer loop.
func (r *UDPReliability) CheckRTO() [][]byte {
	r.mu.Lock()
	now := r.now()
	type rtoPending struct {
		pn uint32
		sp *SentPacket
	}
	var pending []rtoPending
	for pn, sp := range r.sentPackets {
		if now.Sub(sp.SendTime) >= r.rto {
			pending = append(pending, rtoPending{pn, sp})
		}
	}
	if len(pending) > 0 {
		// Exponential backoff.
		r.rtoCount++
		backoff := r.rto * 2
		if backoff > UDPMaxRTO {
			backoff = UDPMaxRTO
		}
		r.rto = backoff
	}
	cb := r.OnRetransmit
	r.mu.Unlock()

	if len(pending) == 0 || cb == nil {
		return nil
	}
	var toRetransmit [][]byte
	for _, p := range pending {
		toRetransmit = append(toRetransmit, p.sp.Frames...)
	}

	// Deliver retransmit callback outside lock.
	// Note: caller assigns new packet numbers via SealPacket, and must chunk
	// frames to fit MaxUDPPlaintext per datagram.
	if err := cb(toRetransmit); err != nil {
		// Retransmit failed: keep old entries; next tick retries.
		return toRetransmit
	}
	// Success: new packets were sealed+tracked with new packet numbers.
	// Retire the old entries (skip any that were ACKed concurrently).
	var retiredPNs []uint32
	var retiredBytes []int
	r.mu.Lock()
	for _, p := range pending {
		if sp, ok := r.sentPackets[p.pn]; ok && sp == p.sp {
			delete(r.sentPackets, p.pn)
			r.bytesInFlight -= sp.Bytes
			retiredPNs = append(retiredPNs, p.pn)
			retiredBytes = append(retiredBytes, sp.Bytes)
			// Notify BBR of loss.
			if r.bbr != nil {
				r.bbr.OnPacketLost(p.pn, sp.Bytes, r.bytesInFlight)
			}
		}
	}
	if r.bytesInFlight < 0 {
		r.bytesInFlight = 0
	}
	retireCb := r.OnPacketsRetired
	r.mu.Unlock()
	if retireCb != nil && len(retiredPNs) > 0 {
		retireCb(retiredPNs, retiredBytes)
	}
	return toRetransmit
}

// BytesInFlight returns current unacknowledged bytes.
func (r *UDPReliability) BytesInFlight() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytesInFlight
}

// CanSend reports whether the congestion window allows sending.
func (r *UDPReliability) CanSend() bool {
	if r.bbr == nil {
		return true
	}
	return r.bbr.CanSend(r.BytesInFlight())
}

// RTO returns the current retransmission timeout.
func (r *UDPReliability) RTO() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rto
}

// SRTT returns the smoothed RTT (for pacing rate fallback).
func (r *UDPReliability) SRTT() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.srtt
}

// ---------------------------------------------------------------------------
// Stream-level flow control (§6.5)
// ---------------------------------------------------------------------------

// StreamFlowControl tracks per-stream send/receive windows.
type StreamFlowControl struct {
	mu sync.Mutex
	// sendWindow is how many bytes we may still send on this stream.
	sendWindow uint64
	// recvOffset is how many bytes we've received (for WINDOW_UPDATE).
	recvOffset uint64
	// recvWindow is the window we've advertised to the peer.
	recvWindow uint64
}

// NewStreamFlowControl creates flow control state with the initial window.
func NewStreamFlowControl() *StreamFlowControl {
	return &StreamFlowControl{
		sendWindow: UDPStreamWindowInitial,
		recvWindow: UDPStreamWindowInitial,
	}
}

// CanSend returns how many bytes may be sent (capped by window).
func (f *StreamFlowControl) CanSend(want uint64) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if want > f.sendWindow {
		return f.sendWindow
	}
	return want
}

// Sent records that n bytes were sent.
func (f *StreamFlowControl) Sent(n uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n > f.sendWindow {
		f.sendWindow = 0
	} else {
		f.sendWindow -= n
	}
}

// OnMaxStreamData handles a MAX_STREAM_DATA frame (raises send window).
func (f *StreamFlowControl) OnMaxStreamData(maxOffset uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// maxOffset is the absolute max byte offset we're allowed to send.
	// We track it as a window; simplified: set directly.
	f.sendWindow = maxOffset
}

// Received records n received bytes; returns true if a WINDOW_UPDATE
// should be sent (when half the window is consumed).
func (f *StreamFlowControl) Received(n uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recvOffset += n
	// Send WINDOW_UPDATE when half the advertised window is consumed.
	return f.recvOffset >= f.recvWindow/2
}

// WindowUpdate advances the receive window and returns the new value.
func (f *StreamFlowControl) WindowUpdate() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recvWindow = f.recvOffset + UDPStreamWindowInitial
	return f.recvWindow
}
