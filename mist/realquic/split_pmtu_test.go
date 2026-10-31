// Stage B (B4, REALQUIC-DESIGN-v3 §3.2/§3.4): per-leg PMTU reporting
// for a split session. The split mechanism itself is covered by
// split_test.go; these tests cover only the B4 wiring: each leg's
// tracker is independent, the qlog trace feeds exactly the report
// port's tracker, chunk/split decisions follow the owning leg's
// target, and a down-leg rebuild resets only the down leg.
//
// Lab honesty notes, stated so a reader does not over-read these
// tests: (1) the mem transport emits no stack PMTU events (quic-go
// starts discovery only on DF-capable conns, connection.go:933, and
// a mem conn is not one; probes additionally need 5 RTTs after
// handshake confirmation), so "initial value" assertions taken
// immediately after an echo are deterministic here — they prove the
// plumbing leaves state intact, NOT that the stack probed; (2) real
// stack events are therefore simulated by feeding the leg's own
// qlog trace, which is exactly the pmtu.go accessor the lab dial
// plugs in (DialPacketConnWithPMTUTrace); (3) the family flag is an
// explicit caller argument because the mem transport carries no
// family — on real UDP the caller passes the dialled leg's family.
package realquic

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/qlog"
)

func TestSplitPMTULegsIndependentViaOwnTraces(t *testing.T) {
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	e := newSplitEnv(t, prof, 2, false)
	up := e.dialUp(t, 0)
	sc, _ := e.splitClient(t, up, 1)

	// Legs and families never share a tracker object.
	if sc.UpTracker(false) == sc.DownTracker(false) {
		t.Fatalf("up and down v4 share one tracker, want independent instances")
	}
	if sc.UpTracker(false) == sc.UpTracker(true) {
		t.Fatalf("up v4 and up v6 share one tracker, want per-family instances")
	}
	if sc.UpTracker(false) != sc.UpTracker(false) {
		t.Fatalf("UpTracker not stable across calls")
	}
	// Initial values: 1280 UDP payload + header (v4 28 / v6 48).
	if got := sc.UpValidatedIP(false); got != 1308 {
		t.Fatalf("up v4 initial validated=%d, want 1308", got)
	}
	if got := sc.DownValidatedIP(true); got != 1328 {
		t.Fatalf("down v6 initial validated=%d, want 1328", got)
	}
	// Feed the UP v4 trace: only the up v4 target moves.
	sc.UpTrace(false).AddProducer().RecordEvent(qlog.MTUUpdated{Value: 1400, Done: false})
	if got := sc.UpValidatedIP(false); got != 1428 {
		t.Fatalf("up v4 after feed=%d, want 1428", got)
	}
	if got := sc.DownValidatedIP(false); got != 1308 {
		t.Fatalf("up feed moved down v4 to %d, want untouched 1308", got)
	}
	if got := sc.UpValidatedIP(true); got != 1328 {
		t.Fatalf("up v4 feed moved up v6 to %d, want untouched 1328", got)
	}
	// Feed the DOWN v4 trace: only the down v4 target moves.
	sc.DownTrace(false).AddProducer().RecordEvent(qlog.MTUUpdated{Value: 1350, Done: false})
	if got := sc.DownValidatedIP(false); got != 1378 {
		t.Fatalf("down v4 after feed=%d, want 1378", got)
	}
	if got := sc.UpValidatedIP(false); got != 1428 {
		t.Fatalf("down feed moved up v4 to %d, want untouched 1428", got)
	}
	// Feed the DOWN v6 trace: only the down v6 target moves.
	sc.DownTrace(true).AddProducer().RecordEvent(qlog.MTUUpdated{Value: 1400, Done: false})
	if got := sc.DownValidatedIP(true); got != 1448 {
		t.Fatalf("down v6 after feed=%d, want 1448", got)
	}
	if got := sc.DownValidatedIP(false); got != 1378 {
		t.Fatalf("down v6 feed moved down v4 to %d, want untouched 1378", got)
	}
	// Report port targets follow the owning leg only.
	if got := sc.UpTargetIP(false); got != 1428 {
		t.Fatalf("up target=%d, want 1428", got)
	}
	if got := sc.DownTargetIP(false); got != 1378 {
		t.Fatalf("down v4 target=%d, want 1378", got)
	}
	if got := sc.DownTargetIP(true); got != 1448 {
		t.Fatalf("down v6 target=%d, want 1448", got)
	}
	// Peer cap: a LOCAL parameters_set must not cap anything; a
	// REMOTE one caps only the leg/family it was fed to, and caps
	// the target without rewriting the validated value.
	sc.DownTrace(false).AddProducer().RecordEvent(
		qlog.ParametersSet{Initiator: qlog.InitiatorLocal, MaxUDPPayloadSize: 1000})
	if got := sc.DownTargetIP(false); got != 1378 {
		t.Fatalf("local parameters_set capped down v4 to %d, want 1378", got)
	}
	sc.UpTrace(false).AddProducer().RecordEvent(
		qlog.ParametersSet{Initiator: qlog.InitiatorRemote, MaxUDPPayloadSize: 1300})
	if got := sc.UpTargetIP(false); got != 1328 {
		t.Fatalf("up target after peer cap=%d, want 1328", got)
	}
	if got := sc.UpValidatedIP(false); got != 1428 {
		t.Fatalf("peer cap rewrote up validated to %d, want still 1428", got)
	}
	if got := sc.DownTargetIP(false); got != 1378 {
		t.Fatalf("up peer cap moved down v4 to %d, want untouched 1378", got)
	}
	// No ceiling is configured on a SplitClient, so the two targets
	// of a leg agree (the split exists for a future ceiling, not
	// for a difference today).
	if got := sc.UpStackEnforcedTargetIP(false); got != sc.UpTargetIP(false) {
		t.Fatalf("up stack-enforced=%d differs from target=%d with no ceiling", got, sc.UpTargetIP(false))
	}
}

func TestSplitPMTULegResetScoped(t *testing.T) {
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	e := newSplitEnv(t, prof, 2, false)
	up := e.dialUp(t, 0)
	sc, _ := e.splitClient(t, up, 1)
	sc.UpTrace(false).AddProducer().RecordEvent(qlog.MTUUpdated{Value: 1400, Done: false})
	sc.DownTrace(false).AddProducer().RecordEvent(qlog.MTUUpdated{Value: 1350, Done: false})
	// Resetting the down leg returns only it to the initial size.
	sc.ResetDownLeg(false)
	if got := sc.DownValidatedIP(false); got != 1308 {
		t.Fatalf("down v4 after reset=%d, want initial 1308", got)
	}
	if got := sc.UpValidatedIP(false); got != 1428 {
		t.Fatalf("down reset moved up v4 to %d, want untouched 1428", got)
	}
	// Resetting an untouched family is inert for the other family.
	sc.ResetDownLeg(true)
	if got := sc.DownValidatedIP(true); got != 1328 {
		t.Fatalf("down v6 after reset=%d, want initial 1328", got)
	}
	if got := sc.DownValidatedIP(false); got != 1308 {
		t.Fatalf("down v6 reset moved down v4 to %d, want 1308", got)
	}
	// Resetting the up leg likewise touches only the up leg.
	sc.ResetUpLeg(false)
	if got := sc.UpValidatedIP(false); got != 1308 {
		t.Fatalf("up v4 after reset=%d, want initial 1308", got)
	}
}

func TestSplitPMTUChunkAndSplitFollowOwningLeg(t *testing.T) {
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	e := newSplitEnv(t, prof, 2, false)
	up := e.dialUp(t, 0)
	sc, _ := e.splitClient(t, up, 1)
	// Divergent targets: up v4 target 1428 (payload 1400), down v4
	// target 1378 (payload 1350).
	sc.UpTrace(false).AddProducer().RecordEvent(qlog.MTUUpdated{Value: 1400, Done: false})
	sc.DownTrace(false).AddProducer().RecordEvent(qlog.MTUUpdated{Value: 1350, Done: false})
	// §3.4 wiring: chunk sizes follow the owning leg's target.
	if got := sc.UpChunkSize(false, 20, 30); got != 1350 {
		t.Fatalf("up chunk=%d, want 1400-50=1350", got)
	}
	if got := sc.DownChunkSize(false, 20, 30); got != 1300 {
		t.Fatalf("down chunk=%d, want 1350-50=1300", got)
	}
	// Datagram splitting follows the owning leg's payload limit: a
	// 2800-byte body is 2 up-leg pieces but 3 down-leg pieces, and
	// both reassemble byte-identically.
	body := bytes.Repeat([]byte("d"), 2800)
	upParts := sc.UpSplitDatagram(false, body)
	if len(upParts) != 2 || len(upParts[0]) != 1400 || len(upParts[1]) != 1400 {
		t.Fatalf("up split of 2800: got %d pieces, want [1400 1400]", len(upParts))
	}
	downParts := sc.DownSplitDatagram(false, body)
	if len(downParts) != 3 || len(downParts[0]) != 1350 || len(downParts[1]) != 1350 || len(downParts[2]) != 100 {
		t.Fatalf("down split of 2800: got %d pieces, want [1350 1350 100]", len(downParts))
	}
	if got := bytes.Join(upParts, nil); !bytes.Equal(got, body) {
		t.Fatalf("up split does not reassemble")
	}
	if got := bytes.Join(downParts, nil); !bytes.Equal(got, body) {
		t.Fatalf("down split does not reassemble")
	}
}

func TestSplitPMTUTracedDownDialAndRebuildReset(t *testing.T) {
	// B4 end-to-end under B2+B3: the down leg is dialled through the
	// lab qlog dial (DialPacketConnWithPMTUTrace) bound to the
	// SplitClient's own down trace, so the dial helper and the
	// report port share one tracker. The up leg is dialled plainly
	// (its trace accessor is covered by the unit tests above, and
	// the up Client must exist before the SplitClient that owns the
	// up trace); the down-leg traced dial proves the helper itself.
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	// 3 pairs: up, down-1, down-2 (rebuild).
	e := newSplitEnv(t, prof, 3, false)
	up := e.dialUp(t, 0)
	var sc *SplitClient
	next := 1
	var mu sync.Mutex
	dialDown := func(ctx context.Context) (*Client, error) {
		mu.Lock()
		i := next
		next++
		mu.Unlock()
		if i >= len(e.cliPCs) {
			return nil, errNoPair
		}
		return DialPacketConnWithPMTUTrace(ctx, e.cliPCs[i], e.srvPCs[i].LocalAddr(), e.key, sc.DownTrace(false))
	}
	sc = NewSplitClient(up, dialDown)
	// B2: the up connection adopted the issued (burst default-on)
	// profile, and the split session sees it.
	if !sc.UpProfile().Steady.BurstEnabled() {
		t.Fatalf("split up profile has burst off, want B2 default-on from issuance")
	}
	if got := sc.UpProfile().Version; got != 1 {
		t.Fatalf("split up profile version=%d, want issued 1", got)
	}
	// The traced down dial must not break split traffic.
	ss, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("split over traced down dial: %v", err)
	}
	echoRoundTrip(t, ss, []byte("b4-traced-down"))
	_ = ss.Close()
	// Immediately after the echo the legs are still at their initial
	// sizes: the mem transport starts no stack discovery (see the
	// file header), so the traced dial left reporting state intact.
	if got := sc.UpTargetIP(false); got != 1308 {
		t.Fatalf("up target after traced split=%d, want initial 1308", got)
	}
	if got := sc.DownTargetIP(false); got != 1308 {
		t.Fatalf("down target after traced split=%d, want initial 1308", got)
	}
	// Divergent simulated events through the legs' own traces, then
	// a second split echo on the already-bound leg: targets persist
	// (no rebind, no reset) and traffic still flows.
	sc.UpTrace(false).AddProducer().RecordEvent(qlog.MTUUpdated{Value: 1400, Done: false})
	sc.DownTrace(false).AddProducer().RecordEvent(qlog.MTUUpdated{Value: 1350, Done: false})
	ss2, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("second split: %v", err)
	}
	echoRoundTrip(t, ss2, []byte("b4-second-split"))
	_ = ss2.Close()
	if got := sc.UpTargetIP(false); got != 1428 {
		t.Fatalf("up target after second split=%d, want preserved 1428", got)
	}
	if got := sc.DownTargetIP(false); got != 1378 {
		t.Fatalf("down target after second split=%d, want preserved 1378", got)
	}
	// Down-leg rebuild: the fresh leg is a new generation, so its
	// target resets to initial while the up leg is untouched — the
	// §3.2 migration-reset rule, on the rebuild path, with traffic
	// still flowing afterwards.
	sc.MarkDownDead()
	ss3, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("split after down rebuild: %v", err)
	}
	defer ss3.Close()
	echoRoundTrip(t, ss3, []byte("b4-after-rebuild"))
	if got := sc.DownTargetIP(false); got != 1308 {
		t.Fatalf("down target after rebuild=%d, want reset to initial 1308", got)
	}
	if got := sc.UpTargetIP(false); got != 1428 {
		t.Fatalf("down rebuild moved up target to %d, want untouched 1428", got)
	}
}
