// Stage B (B4, REALQUIC-DESIGN-v3 §3.2/§3.4): per-leg PMTU reporting
// for a Q4 split session.
//
// The split mechanism itself lives in split.go and is untouched here:
// this file only owns the split session's PMTU state and its report
// port. One PMTUSet per SplitClient (created in NewSplitClient) gives
// each leg ("up", "down") its own tracker per address family, reusing
// pmtu.go's tracker API — no second tracker implementation exists.
// The §3.2 rule "each leg, each family independent" is therefore the
// PMTUSet's own rule, not a new invariant this file has to enforce:
//
//   - an mtu_updated / parameters_set event fed to one leg's trace
//     moves only that leg's target;
//   - ResetUpLeg / ResetDownLeg (and the down-rebuild reset in
//     ensureDown) clears only that leg's generation;
//   - the up leg's Target_IP decides up-leg chunking (UpChunkSize /
//     UpSplitDatagram) and the down leg's Target_IP decides down-leg
//     chunking (§3.4: "下行腿的 Target_IP 决定下行 JS，上行腿的
//     Target_IP 决定上行 JS，各自独立探测、独立回落").
//
// Wiring (lab instrument, same status as pmtu.go): UpTrace /
// DownTrace return the pmtu.go qlog accessor
// (NewPMTUQlogTrace) bound to that leg's tracker, so a lab harness
// can plug a leg's tracker into a dial's Config.Tracer — see
// DialPacketConnWithPMTUTrace in client.go. The mem transport used
// by the split tests carries no address family and emits no stack
// PMTU events, so the family flag (ipv6) is an explicit caller
// argument here, not inferred from the transport; on real UDP the
// caller passes the dialled leg's family. Production MUST NOT depend
// on parsing qlog for runtime decisions (pmtu.go header): these
// targets are Mist-layer reporting / chunking inputs, and the stack's
// own send sizes remain governed by the stack itself.
//
// Ceiling: the set is created with ceiling 0 (unset). Profile
// SizePolicy records only the ceiling's mechanism name
// ("operator-expectation"), never a numeric ceiling, so there is no
// profile value to seed a numeric ceiling from; a deployment that
// wants one must construct the set with it explicitly, which
// NewSplitClient deliberately does not do by inventing a number.
package realquic

import (
	"github.com/quic-go/quic-go/qlogwriter"
)

// Leg names for the split session's PMTUSet. They are the PMTUSet
// keys, not wire values: nothing about a leg name ever leaves the
// process.
const (
	pmtuLegUp   = "up"
	pmtuLegDown = "down"
)

// PMTUSet returns the split session's per-leg PMTU registry. It is
// never nil after NewSplitClient; a zero SplitClient (never built by
// NewSplitClient) has no set, and its leg accessors return nil
// trackers rather than panicking — callers must build via
// NewSplitClient, as every existing SplitClient does.
func (sc *SplitClient) PMTUSet() *PMTUSet {
	return sc.pmtu
}

func (sc *SplitClient) legTracker(leg string, ipv6 bool) *PMTUTracker {
	if sc.pmtu == nil {
		return nil
	}
	return sc.pmtu.Tracker(leg, ipv6)
}

// UpTracker returns the up leg's tracker for the given family, and
// DownTracker the down leg's. The two legs (and the two families of
// one leg) never share a tracker object: pointer inequality across
// legs/families is itself part of the B4 contract and is asserted in
// tests.
func (sc *SplitClient) UpTracker(ipv6 bool) *PMTUTracker   { return sc.legTracker(pmtuLegUp, ipv6) }
func (sc *SplitClient) DownTracker(ipv6 bool) *PMTUTracker { return sc.legTracker(pmtuLegDown, ipv6) }

// UpTargetIP / DownTargetIP report the leg's Mist-layer target in IP
// length bytes (min(validated, ceiling, peer cap), floored at 1200,
// capped at the stack-limit mapping; see PMTUTracker.TargetIP).
// A zero SplitClient reports 0 (no set), never a fabricated target.
func (sc *SplitClient) UpTargetIP(ipv6 bool) int   { return targetOrZero(sc.UpTracker(ipv6)) }
func (sc *SplitClient) DownTargetIP(ipv6 bool) int { return targetOrZero(sc.DownTracker(ipv6)) }

// UpValidatedIP / DownValidatedIP report the leg's validated PMTU in
// IP length bytes (the initial size before the first mtu_updated
// event of this generation).
func (sc *SplitClient) UpValidatedIP(ipv6 bool) int   { return validatedOrZero(sc.UpTracker(ipv6)) }
func (sc *SplitClient) DownValidatedIP(ipv6 bool) int { return validatedOrZero(sc.DownTracker(ipv6)) }

// UpStackEnforcedTargetIP / DownStackEnforcedTargetIP report the
// leg's target with the operator ceiling removed (what the stack
// actually honours; see PMTUTracker.StackEnforcedTargetIP). With no
// ceiling configured — the SplitClient default — the two targets of
// a leg are identical; the split exists so a future ceiling can
// never be mistaken for a stack rule.
func (sc *SplitClient) UpStackEnforcedTargetIP(ipv6 bool) int {
	return stackTargetOrZero(sc.UpTracker(ipv6))
}
func (sc *SplitClient) DownStackEnforcedTargetIP(ipv6 bool) int {
	return stackTargetOrZero(sc.DownTracker(ipv6))
}

func targetOrZero(t *PMTUTracker) int {
	if t == nil {
		return 0
	}
	return t.TargetIP()
}

func validatedOrZero(t *PMTUTracker) int {
	if t == nil {
		return 0
	}
	return t.ValidatedIP()
}

func stackTargetOrZero(t *PMTUTracker) int {
	if t == nil {
		return 0
	}
	return t.StackEnforcedTargetIP()
}

// UpChunkSize / DownChunkSize return the leg's Mist-layer STREAM
// write-block starting value for its own target (see
// PMTUTracker.ChunkSize). This is the §3.4 wiring point: down-leg
// JS chunking must call DownChunkSize, never the up leg's value, and
// vice versa — the two legs' chunk sizes diverge exactly when their
// targets diverge.
func (sc *SplitClient) UpChunkSize(ipv6 bool, quicHeaderReserve, frameOverhead int) int {
	return chunkOrZero(sc.UpTracker(ipv6), quicHeaderReserve, frameOverhead)
}
func (sc *SplitClient) DownChunkSize(ipv6 bool, quicHeaderReserve, frameOverhead int) int {
	return chunkOrZero(sc.DownTracker(ipv6), quicHeaderReserve, frameOverhead)
}

func chunkOrZero(t *PMTUTracker, quicHeaderReserve, frameOverhead int) int {
	if t == nil {
		return 0
	}
	return t.ChunkSize(quicHeaderReserve, frameOverhead)
}

// UpSplitDatagram / DownSplitDatagram split a Mist-layer datagram
// body into pieces no larger than the leg's own target UDP payload,
// so the stack is never handed more than one packet's worth on that
// leg (see PMTUTracker.SplitDatagram).
func (sc *SplitClient) UpSplitDatagram(ipv6 bool, body []byte) [][]byte {
	return splitOrNil(sc.UpTracker(ipv6), body)
}
func (sc *SplitClient) DownSplitDatagram(ipv6 bool, body []byte) [][]byte {
	return splitOrNil(sc.DownTracker(ipv6), body)
}

func splitOrNil(t *PMTUTracker, body []byte) [][]byte {
	if t == nil {
		return nil
	}
	return t.SplitDatagram(body)
}

// UpTrace / DownTrace return the pmtu.go qlog accessor bound to the
// leg's tracker, for a lab harness to plug into a dial's
// Config.Tracer (see DialPacketConnWithPMTUTrace). Feeding events
// through the returned trace moves exactly the report port's target:
// the trace and the report read the same tracker object, so there is
// no second copy of leg state to drift. A zero SplitClient returns
// nil (no tracker to bind); the dial helper treats a nil trace as
// "no tracer", matching plain DialPacketConn.
func (sc *SplitClient) UpTrace(ipv6 bool) qlogwriter.Trace {
	return traceOrNil(sc.UpTracker(ipv6))
}
func (sc *SplitClient) DownTrace(ipv6 bool) qlogwriter.Trace {
	return traceOrNil(sc.DownTracker(ipv6))
}

func traceOrNil(t *PMTUTracker) qlogwriter.Trace {
	if t == nil {
		return nil
	}
	return NewPMTUQlogTrace(t)
}

// ResetUpLeg / ResetDownLeg start a new PMTU generation for one leg
// and family only (path migration / new leg): the leg's validated
// value returns to the initial size, Done clears, and the peer cap
// is forgotten until the new leg's handshake re-reports it. Other
// legs and families are untouched. The down-leg rebuild path in
// ensureDown calls ResetDownLeg itself, so ordinary rebuilds need no
// caller action; these methods exist for lab harnesses and for an
// explicit migration reset.
func (sc *SplitClient) ResetUpLeg(ipv6 bool) {
	if sc.pmtu != nil {
		sc.pmtu.ResetLeg(pmtuLegUp, ipv6)
	}
}
func (sc *SplitClient) ResetDownLeg(ipv6 bool) {
	if sc.pmtu != nil {
		sc.pmtu.ResetLeg(pmtuLegDown, ipv6)
	}
}
