package realquic

import (
	"bytes"
	"testing"

	"github.com/quic-go/quic-go/qlog"
)

// Stage B (B3, REALQUIC-DESIGN-v3 §3): PMTU tracker tests. Units are
// stated on every assertion: qlog MTUUpdated Value is UDP payload
// bytes, tracker targets are IP length bytes (+28 v4 / +48 v6).

func TestPMTUTrackerEventsToTarget(t *testing.T) {
	// IPv6, default initial: 1280 UDP + 48 = 1328 IP before any event.
	tr := NewPMTUTracker(true, 0, 0)
	if got := tr.ValidatedIP(); got != 1328 {
		t.Fatalf("pre-event validated=%d, want 1328 (1280+48)", got)
	}
	if got := tr.TargetIP(); got != 1328 {
		t.Fatalf("pre-event target=%d, want 1328", got)
	}
	// mtu_updated 1452 UDP -> 1500 IP (v6 stack limit, reachable).
	tr.ObserveMTUUpdated(1452, false)
	if got := tr.ValidatedIP(); got != 1500 {
		t.Fatalf("validated=%d, want 1500 (1452+48)", got)
	}
	if tr.Done() {
		t.Fatalf("done set before a Done event")
	}
	// Peer cap 1400 UDP -> 1448 IP binds the target below validated.
	tr.ObservePeerCap(1400)
	if got, ok := tr.PeerCapIP(); !ok || got != 1448 {
		t.Fatalf("peer cap=%d ok=%v, want 1448 true", got, ok)
	}
	if got := tr.TargetIP(); got != 1448 {
		t.Fatalf("target=%d, want min(1500, 1448)=1448", got)
	}
	// A LOWER later event never lowers the validated value (same
	// generation only rises); Done is still recorded.
	tr.ObserveMTUUpdated(1300, true)
	if got := tr.ValidatedIP(); got != 1500 {
		t.Fatalf("lower event lowered validated to %d, want monotonic 1500", got)
	}
	if !tr.Done() {
		t.Fatalf("Done event did not set done")
	}
	if got := tr.TargetIP(); got != 1448 {
		t.Fatalf("target after lower event=%d, want 1448 (peer cap still binds)", got)
	}
}

func TestPMTUTrackerIPv4StackLimitNot1500(t *testing.T) {
	// IPv4: 1452 UDP + 28 = 1480 IP. 1500 is NEVER an IPv4 target
	// on this stack, even at a 1500 path MTU.
	tr := NewPMTUTracker(false, 0, 0)
	if got := tr.ValidatedIP(); got != 1308 {
		t.Fatalf("pre-event validated=%d, want 1308 (1280+28)", got)
	}
	tr.ObserveMTUUpdated(1452, true)
	if got := tr.TargetIP(); got != 1480 {
		t.Fatalf("v4 target=%d, want 1480 (stack limit), never 1500", got)
	}
	// An event value above the stack limit clamps, it does not leak.
	tr.ObserveMTUUpdated(2000, true)
	if got := tr.TargetIP(); got != 1480 {
		t.Fatalf("oversize event target=%d, want clamped 1480", got)
	}
}

func TestPMTUTrackerFloorAndPeerCap(t *testing.T) {
	// A tiny peer cap cannot drag the target below the 1200 IP floor.
	tr := NewPMTUTracker(false, 0, 0)
	tr.ObservePeerCap(1000) // 1028 IP
	if got := tr.TargetIP(); got != 1200 {
		t.Fatalf("target=%d, want floored 1200 (peer cap 1028 IP)", got)
	}
	// Non-positive feeds are ignored, never shrink state.
	tr.ObserveMTUUpdated(0, false)
	tr.ObservePeerCap(-5)
	if got := tr.TargetIP(); got != 1200 {
		t.Fatalf("non-positive feed changed target to %d, want 1200", got)
	}
}

func TestPMTUTrackerCeilingIsExpectationNotStackRule(t *testing.T) {
	// Ceiling 1300 IP with validated 1500 (v6): the Mist-layer
	// expectation moves to 1300, but the stack-enforced target does
	// not move — the stack has no ceiling knob, and no test may
	// claim otherwise.
	tr := NewPMTUTracker(true, 0, 1300)
	tr.ObserveMTUUpdated(1452, true)
	if got := tr.TargetIP(); got != 1300 {
		t.Fatalf("TargetIP=%d, want ceiling expectation 1300", got)
	}
	if got := tr.StackEnforcedTargetIP(); got != 1500 {
		t.Fatalf("StackEnforcedTargetIP=%d, want 1500 (ceiling must not move it)", got)
	}
	// Without a ceiling the two targets are identical.
	plain := NewPMTUTracker(true, 0, 0)
	plain.ObserveMTUUpdated(1452, true)
	if plain.TargetIP() != plain.StackEnforcedTargetIP() {
		t.Fatalf("no-ceiling targets differ: %d vs %d", plain.TargetIP(), plain.StackEnforcedTargetIP())
	}
}

func TestPMTUSetLegFamilyIndependenceAndScopedReset(t *testing.T) {
	set := NewPMTUSet(0, 0)
	up6 := set.Tracker("up", true)
	down6 := set.Tracker("down", true)
	up4 := set.Tracker("up", false)
	up6.ObserveMTUUpdated(1452, true)   // 1500
	down6.ObserveMTUUpdated(1400, true) // 1448
	if got := up4.TargetIP(); got != 1308 {
		t.Fatalf("up v4 target=%d, want untouched initial 1308", got)
	}
	if got := down6.TargetIP(); got != 1448 {
		t.Fatalf("down v6 target=%d, want 1448", got)
	}
	// Peer caps are per-leg too.
	up6.ObservePeerCap(1300) // 1348 IP
	if got := up6.TargetIP(); got != 1348 {
		t.Fatalf("up v6 target=%d, want peer-capped 1348", got)
	}
	if got := down6.TargetIP(); got != 1448 {
		t.Fatalf("up peer cap leaked to down: down target=%d, want 1448", got)
	}
	// Migration reset of ONE leg: up v6 returns to initial and
	// forgets its peer cap; down v6 is untouched.
	set.ResetLeg("up", true)
	if got := up6.TargetIP(); got != 1328 {
		t.Fatalf("reset up v6 target=%d, want initial 1328", got)
	}
	if _, ok := up6.PeerCapIP(); ok {
		t.Fatalf("reset up v6 kept its peer cap, want forgotten")
	}
	if up6.Done() {
		t.Fatalf("reset up v6 kept done, want cleared")
	}
	if got := down6.TargetIP(); got != 1448 {
		t.Fatalf("reset leaked to down: down target=%d, want 1448", got)
	}
	// Tracker() returns the same instance per leg/family.
	if set.Tracker("up", true) != up6 || set.Tracker("down", true) != down6 {
		t.Fatalf("registry returned a different tracker for a known leg/family")
	}
}

func TestPMTUTrackerChunkSizeAndSplitNeverOversize(t *testing.T) {
	tr := NewPMTUTracker(false, 0, 0)
	tr.ObserveMTUUpdated(1452, true) // v4 target payload 1452
	if got := tr.TargetUDPPayload(); got != 1452 {
		t.Fatalf("target payload=%d, want 1452", got)
	}
	// Stream chunk start value: target payload minus reserves.
	if got := tr.ChunkSize(20, 30); got != 1402 {
		t.Fatalf("chunk size=%d, want 1452-20-30=1402", got)
	}
	// Reserves at/above the target yield 0 ("do not write"), never
	// a clamped positive size that would overshoot the target.
	if got := tr.ChunkSize(1452, 1); got != 0 {
		t.Fatalf("oversize-reserve chunk=%d, want 0", got)
	}
	// Datagram split: no piece above the target, reassembly exact.
	body := bytes.Repeat([]byte("d"), 4000)
	parts := tr.SplitDatagram(body)
	if len(parts) != 3 {
		t.Fatalf("split %d bytes into %d parts, want 3 (1452/1452/1096)", len(body), len(parts))
	}
	for i, p := range parts {
		if len(p) > 1452 {
			t.Fatalf("part %d len=%d exceeds target payload 1452", i, len(p))
		}
	}
	if got := bytes.Join(parts, nil); !bytes.Equal(got, body) {
		t.Fatalf("split parts do not reassemble to the input")
	}
	// Exact-target body is a single piece; empty body is nothing.
	if parts := tr.SplitDatagram(bytes.Repeat([]byte("x"), 1452)); len(parts) != 1 {
		t.Fatalf("exact-target split gave %d parts, want 1", len(parts))
	}
	if parts := tr.SplitDatagram(nil); parts != nil {
		t.Fatalf("empty split gave %d parts, want nil", len(parts))
	}
}

func TestPMTUQlogTraceFiltersOnlyTwoKinds(t *testing.T) {
	tr := NewPMTUTracker(true, 0, 0)
	trace := NewPMTUQlogTrace(tr)
	if trace.SupportsSchemas("urn:ietf:params:qlog:events") {
		t.Fatalf("filter trace claims schema support, want false (it consumes, not records)")
	}
	rec := trace.AddProducer()
	rec.RecordEvent(qlog.MTUUpdated{Value: 1452, Done: true})
	if got := tr.ValidatedIP(); got != 1500 {
		t.Fatalf("qlog mtu_updated: validated=%d, want 1500", got)
	}
	if !tr.Done() {
		t.Fatalf("qlog mtu_updated Done not recorded")
	}
	// Local parameters_set must NOT become a peer cap.
	rec.RecordEvent(qlog.ParametersSet{Initiator: qlog.InitiatorLocal, MaxUDPPayloadSize: 1000})
	if _, ok := tr.PeerCapIP(); ok {
		t.Fatalf("local parameters_set became a peer cap, want peer-only")
	}
	// Remote parameters_set DOES become the peer cap.
	rec.RecordEvent(qlog.ParametersSet{Initiator: qlog.InitiatorRemote, MaxUDPPayloadSize: 1400})
	if got, ok := tr.PeerCapIP(); !ok || got != 1448 {
		t.Fatalf("remote parameters_set peer cap=%d ok=%v, want 1448 true", got, ok)
	}
	if got := tr.TargetIP(); got != 1448 {
		t.Fatalf("target after qlog feed=%d, want 1448", got)
	}
	// Any other event kind is dropped without touching state.
	rec.RecordEvent(qlog.RecoveryParametersSet{})
	if got := tr.TargetIP(); got != 1448 {
		t.Fatalf("unrelated event moved target to %d, want 1448", got)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}
}

func TestSizePolicyValidation(t *testing.T) {
	if err := (SizePolicy{}).Validate(); err != nil {
		t.Fatalf("zero size policy rejected: %v (pre-Stage-B profiles must decode cleanly)", err)
	}
	good := SizePolicy{
		PMTUAlignMode:        "stack-native-dplpmtud",
		CeilingMode:          "operator-expectation",
		FallbackMode:         "initial-size",
		ProbePolicy:          "stack-native",
		TailPadEnabled:       true,
		TailPadOverheadLimit: 0.01,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid size policy rejected: %v", err)
	}
	bad := good
	bad.PMTUAlignMode = "custom-probes"
	if err := bad.Validate(); err == nil {
		t.Fatalf("custom probe mechanism accepted, want rejection (stack-native only)")
	}
	bad = good
	bad.CeilingMode = "stack-enforced"
	if err := bad.Validate(); err == nil {
		t.Fatalf("stack-enforced ceiling accepted, want rejection (ceiling is expectation-only)")
	}
	bad = good
	bad.TailPadEnabled = true
	bad.TailPadOverheadLimit = 0
	if err := bad.Validate(); err == nil {
		t.Fatalf("enabled tail pad with zero limit accepted, want rejection")
	}
	bad = good
	bad.TailPadOverheadLimit = 0.02
	if err := bad.Validate(); err == nil {
		t.Fatalf("tail pad limit above the 1%% hard cap accepted, want rejection")
	}
	bad = good
	bad.TailPadEnabled = false
	if err := bad.Validate(); err == nil {
		t.Fatalf("disabled tail pad with a limit set accepted, want rejection")
	}
	// A profile carrying the policy still validates end to end.
	p := BootstrapProfile()
	p.Size = good
	if err := p.Validate(); err != nil {
		t.Fatalf("profile with size policy rejected: %v", err)
	}
	if enc, err := EncodeProfile(p); err != nil {
		t.Fatalf("encode profile with size policy: %v", err)
	} else if dec, err := DecodeProfile(enc); err != nil {
		t.Fatalf("decode profile with size policy: %v", err)
	} else if dec.Size != good {
		t.Fatalf("size policy round-trip mismatch: got %+v, want %+v", dec.Size, good)
	}
}

func TestTailPadderDefaultClosed(t *testing.T) {
	pad := NewTailPadder(false, 0)
	pad.RecordData(100000)
	tail := bytes.Repeat([]byte("t"), 1400)
	if got := pad.Pad(tail, 1452); !bytes.Equal(got, tail) {
		t.Fatalf("disabled padder changed a near-full tail (len %d, want unchanged %d)", len(got), len(tail))
	}
	if pad.PaddedBytes() != 0 {
		t.Fatalf("disabled padder padded %d bytes, want 0", pad.PaddedBytes())
	}
	if pad.Stopped() {
		t.Fatalf("disabled padder reports stopped, want false (never started)")
	}
}

func TestTailPadderNearFullOnlyAndOverheadAccounting(t *testing.T) {
	pad := NewTailPadder(true, 0.01)
	pad.RecordData(100000)
	// Near-full tail (1400 >= 1452/2): padded to exactly the target.
	tail := bytes.Repeat([]byte("t"), 1400)
	got := pad.Pad(tail, 1452)
	if len(got) != 1452 {
		t.Fatalf("near-full tail padded to %d, want exactly target 1452", len(got))
	}
	if pad.PaddedBytes() != 52 {
		t.Fatalf("padded bytes=%d, want 52", pad.PaddedBytes())
	}
	// Small tail (< half target): never padded, however much budget.
	small := bytes.Repeat([]byte("s"), 100)
	if out := pad.Pad(small, 1452); !bytes.Equal(out, small) {
		t.Fatalf("small tail padded to %d, want unchanged", len(out))
	}
	// Budget breach: a fresh padder with little data stops instead
	// of exceeding the limit, and stays stopped.
	broke := NewTailPadder(true, 0.01)
	broke.RecordData(1000)
	big := bytes.Repeat([]byte("b"), 1400)
	if out := broke.Pad(big, 1452); !bytes.Equal(out, big) {
		t.Fatalf("over-budget tail padded (len %d), want unchanged", len(out))
	}
	if !broke.Stopped() {
		t.Fatalf("over-budget padder did not report stopped")
	}
	if broke.PaddedBytes() != 0 {
		t.Fatalf("over-budget padder padded %d bytes, want 0", broke.PaddedBytes())
	}
	// Misconfigured gate fails closed, not open.
	open := NewTailPadder(true, 0.5)
	if out := open.Pad(tail, 1452); !bytes.Equal(out, tail) {
		t.Fatalf("misconfigured padder padded, want fail-closed unchanged")
	}
}
