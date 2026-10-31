package realquic

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"
)

// P1 step B (Q3) tests. These tests only add coverage; they do not
// modify any existing test's assertions. Timing assertions use a
// 2ms tolerance below the profile minimum: time.Sleep never fires
// early by more than timer granularity, so a gap below min-2ms would
// mean pacing did not happen; scheduling lateness only ever inflates
// gaps, so upper bounds are loose sanity checks, not shaping claims.

func shapingProfile(up, down int, lenKind string, lenMin, lenMax, lenMean, timMin, timMax, timMean float64, steadyLen, steadyTimMin, steadyTimMax, steadyTimMean float64) Profile {
	return Profile{
		Version:  1,
		IssuedAt: time.Now().Unix(),
		Shaping: ShapingParams{
			NPacketsUp:   up,
			NPacketsDown: down,
			LenDist:      Distribution{Kind: lenKind, Min: lenMin, Max: lenMax, Mean: lenMean},
			TimingDist:   Distribution{Kind: "uniform", Min: timMin, Max: timMax, Mean: timMean},
			MergePolicy:  "same_flight",
			TailPolicy:   "transition_to_steady",
		},
		Steady: SteadyBaseline{
			LenDist:        Distribution{Kind: "uniform", Min: steadyLen, Max: steadyLen + 100, Mean: steadyLen + 50},
			TimingDist:     Distribution{Kind: "uniform", Min: steadyTimMin, Max: steadyTimMax, Mean: steadyTimMean},
			DirectionRatio: 0.5,
		},
	}
}

func TestShaperBudgetAndTailTransition(t *testing.T) {
	p := shapingProfile(2, 2, "fixed", 100, 100, 100, 5, 10, 7.5, 200, 50, 60, 55)
	s := NewShaper("up", p)
	if s.Budget() != 2 {
		t.Fatalf("budget=%d, want 2", s.Budget())
	}
	if got := s.SampleLen(); got != 100 {
		t.Fatalf("pre-tail SampleLen=%d, want shaping 100", got)
	}
	if d := s.BeforeSend(); d != 0 {
		t.Fatalf("first datagram gap=%v, want 0 (no predecessor)", d)
	}
	s.AfterSend(100)
	if s.InTail() {
		t.Fatalf("in tail after 1/2 datagrams, want shaping phase")
	}
	gap := s.BeforeSend()
	if gap < 5*time.Millisecond || gap > 10*time.Millisecond {
		t.Fatalf("second gap=%v, want shaping timing [5ms, 10ms]", gap)
	}
	s.AfterSend(100)
	if !s.InTail() {
		t.Fatalf("not in tail after budget exhausted (2/2)")
	}
	if got := s.SampleLen(); got < 200 || got > 300 {
		t.Fatalf("tail SampleLen=%d, want steady [200, 300]", got)
	}
	// The tail never goes bare: the next gap is still sampled, now
	// from the steady distribution, not zero.
	gap = s.BeforeSend()
	if gap < 50*time.Millisecond || gap > 60*time.Millisecond {
		t.Fatalf("tail gap=%v, want steady timing [50ms, 60ms]", gap)
	}
	s.AfterSend(100)
	evs := s.Events()
	if len(evs) != 3 {
		t.Fatalf("events=%d, want 3", len(evs))
	}
	if evs[0].Tail || evs[1].Tail || !evs[2].Tail {
		t.Fatalf("event tail flags=%v %v %v, want false false true (the datagram that exhausts the budget was still shaped)", evs[0].Tail, evs[1].Tail, evs[2].Tail)
	}
}

func TestShaperPerDirectionBudgets(t *testing.T) {
	p := shapingProfile(2, 3, "fixed", 100, 100, 100, 5, 10, 7.5, 200, 50, 60, 55)
	up := NewShaper("up", p)
	down := NewShaper("down", p)
	for i := 0; i < 2; i++ {
		up.BeforeSend()
		up.AfterSend(10)
		down.BeforeSend()
		down.AfterSend(10)
	}
	if !up.InTail() {
		t.Fatalf("up not in tail after its budget of 2")
	}
	if down.InTail() {
		t.Fatalf("down in tail after 2/3 datagrams: budgets must be per-direction")
	}
	down.BeforeSend()
	down.AfterSend(10)
	if !down.InTail() {
		t.Fatalf("down not in tail after its budget of 3")
	}
}

func TestShaperFixedTimingIsJittered(t *testing.T) {
	p := shapingProfile(1000, 1000, "fixed", 100, 100, 100, 20, 20, 20, 200, 50, 60, 55)
	p.Shaping.TimingDist = Distribution{Kind: "fixed", Min: 20, Max: 20, Mean: 20}
	s := NewShaper("up", p)
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		gap := s.SampleGap()
		if gap < 18*time.Millisecond || gap > 22*time.Millisecond {
			t.Fatalf("fixed timing sample=%v, want jittered [18ms, 22ms]", gap)
		}
		seen[gap] = true
	}
	if len(seen) < 2 {
		t.Fatalf("50 fixed-timing samples all identical: a fixed interval is itself a feature, the shaper must jitter it")
	}
	// Length sampling of a fixed distribution is NOT jittered: a
	// fixed length is not a timing feature.
	if got := s.SampleLen(); got != 100 {
		t.Fatalf("fixed SampleLen=%d, want exactly 100", got)
	}
}

func TestShaperPendingNextWindow(t *testing.T) {
	v1 := shapingProfile(100, 100, "fixed", 100, 100, 100, 10, 10, 10, 200, 50, 60, 55)
	v1.Shaping.TimingDist = Distribution{Kind: "fixed", Min: 10, Max: 10, Mean: 10}
	v1.Version = 1
	v2 := shapingProfile(100, 100, "fixed", 100, 100, 100, 100, 100, 100, 200, 50, 60, 55)
	v2.Shaping.TimingDist = Distribution{Kind: "fixed", Min: 100, Max: 100, Mean: 100}
	v2.Version = 2
	s := NewShaper("up", v1)
	// A flight is in progress: one datagram already sent.
	s.BeforeSend()
	s.AfterSend(10)
	if !s.QueuePending(v2) {
		t.Fatalf("QueuePending(v2) rejected")
	}
	// In-flight window unaffected: effective profile and timing
	// still come from v1.
	if got := s.EffectiveProfile().Version; got != 1 {
		t.Fatalf("in-flight effective version=%d, want 1 (push must not rewrite the window)", got)
	}
	if gap := s.SampleGap(); gap > 50*time.Millisecond {
		t.Fatalf("in-flight gap=%v, want v1 timing (~10ms), not v2", gap)
	}
	// Stale and invalid pendings are ignored.
	stale := v2
	stale.Version = 1
	if s.QueuePending(stale) {
		t.Fatalf("stale pending accepted")
	}
	bad := v2
	bad.Version = 3
	bad.Shaping.TimingDist.Kind = "bogus"
	if s.QueuePending(bad) {
		t.Fatalf("invalid pending accepted")
	}
	// Next window boundary: the pending profile takes over.
	s.BeginWindow(nil)
	if got := s.EffectiveProfile().Version; got != 2 {
		t.Fatalf("next-window effective version=%d, want 2", got)
	}
	if gap := s.SampleGap(); gap < 90*time.Millisecond || gap > 110*time.Millisecond {
		t.Fatalf("next-window gap=%v, want v2 timing [90ms, 110ms]", gap)
	}
	if s.SentInWindow() != 0 {
		t.Fatalf("next-window count=%d, want 0 (count resets at the boundary)", s.SentInWindow())
	}
}

func TestShapingPacketConnPacingAndCounting(t *testing.T) {
	cliPC, srvPC := NewMemPair()
	defer cliPC.Close()
	defer srvPC.Close()
	p := shapingProfile(2, 2, "fixed", 100, 100, 100, 20, 30, 25, 200, 80, 90, 85)
	sc := newSingleShapingConn(cliPC, "up", p)
	buf := make([]byte, 64)
	go func() {
		for i := 0; i < 4; i++ {
			if _, _, err := srvPC.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 4; i++ {
		if _, err := sc.WriteTo([]byte("x"), srvPC.LocalAddr()); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	evs := sc.single.Events()
	if len(evs) != 4 {
		t.Fatalf("events=%d, want 4", len(evs))
	}
	gap1 := evs[1].At.Sub(evs[0].At)
	if gap1 < 18*time.Millisecond {
		t.Fatalf("gap1=%v, want >= 18ms (shaping timing min 20ms - tolerance)", gap1)
	}
	// evs[2] is the first tail datagram: its preceding gap was
	// sampled from the steady distribution (budget 2 exhausted by
	// evs[1]).
	gapTail := evs[2].At.Sub(evs[1].At)
	if gapTail < 78*time.Millisecond {
		t.Fatalf("tail gap=%v, want >= 78ms (steady timing min 80ms - tolerance)", gapTail)
	}
	if !sc.single.InTail() {
		t.Fatalf("not in tail after 4/2 datagrams")
	}
	if got := sc.single.SentInWindow(); got != 4 {
		t.Fatalf("sent=%d, want 4", got)
	}
	// A failed write is not a send event and consumes no budget.
	_ = srvPC.Close()
	if _, err := sc.WriteTo([]byte("y"), srvPC.LocalAddr()); err == nil {
		t.Fatalf("write to closed peer succeeded, want failure")
	}
	if got := sc.single.SentInWindow(); got != 4 {
		t.Fatalf("failed write changed sent to %d, want 4", got)
	}
}

// setupShapedEnv mirrors setupEnv but with an operator-supplied server
// profile, so the integration tests can use deterministic shaping
// values (fixed server length, bounded timing) instead of bootstrap.
func setupShapedEnv(t *testing.T, serverProfile Profile) *testEnv {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Key: key, Profile: &serverProfile})
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{srv: srv}
	var remote net.Addr
	if loopbackUDPUsable() {
		env.transport = "udp"
		srvPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		cliPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		env.srvPC, env.cliPC = srvPC, cliPC
		remote = srvPC.LocalAddr()
	} else {
		env.transport = "mem"
		cliPC, srvPC := NewMemPair()
		env.srvPC, env.cliPC = srvPC, cliPC
		remote = srvPC.LocalAddr()
	}
	t.Logf("transport=%s", env.transport)
	go func() { _ = srv.ServePacketConn(env.srvPC) }()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	env.cancel = cancel
	cli, err := DialPacketConn(ctx, env.cliPC, remote, key)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	env.cli = cli
	env.cli.key = key
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
		_ = env.srvPC.Close()
		_ = env.cliPC.Close()
		cancel()
	})
	return env
}

func windowEvents(evs []SendEvent, w uint64) []SendEvent {
	var out []SendEvent
	for _, e := range evs {
		if e.Window == w {
			out = append(out, e)
		}
	}
	return out
}

func assertPacedGaps(t *testing.T, name string, evs []SendEvent, minGap time.Duration) {
	t.Helper()
	if len(evs) < 2 {
		t.Fatalf("%s: only %d datagrams in window, need >= 2 to observe pacing", name, len(evs))
	}
	for i := 1; i < len(evs); i++ {
		gap := evs[i].At.Sub(evs[i-1].At)
		if gap < minGap {
			t.Fatalf("%s: gap %d = %v, want >= %v (profile min - 2ms tolerance)", name, i, gap, minGap)
		}
	}
	t.Logf("%s: %d datagrams, gaps paced (>= %v)", name, len(evs), minGap)
}

// assertServerWindow0BurstTail asserts the server window 0 gap
// distribution under Stage B B2 issued-burst behavior. Events
// recorded before the budget flip (Tail=false) form the shaping
// segment and keep paced gaps >= 8ms; gaps from the transition
// onward (the first tail datagram's gap plus gaps between tail
// datagrams) must be either intra-burst (< 1ms, line speed) or
// inter-burst idle (>= 40ms, nominal uniform 50-300ms with timer
// tolerance). No gap may fall in [1ms, 40ms): that band is where
// uniform pacing (10-20ms) would land, so it is the regression
// signal for the old behavior. At least one intra-burst gap must
// be observed, proving the burst regime is actually exercised.
func assertServerWindow0BurstTail(t *testing.T, evs []SendEvent) {
	t.Helper()
	if len(evs) < 2 {
		t.Fatalf("server window 0: only %d datagrams, need >= 2 to observe pacing", len(evs))
	}
	var seg, tail []SendEvent
	for _, e := range evs {
		if e.Tail {
			tail = append(tail, e)
		} else {
			seg = append(seg, e)
		}
	}
	if len(seg) < 2 {
		t.Fatalf("server window 0: only %d shaping-segment datagrams, need >= 2", len(seg))
	}
	if len(tail) == 0 {
		t.Fatalf("server window 0: no tail datagrams, burst regime not exercised (budget not exhausted?)")
	}
	assertPacedGaps(t, "server window 0 shaping", seg, 8*time.Millisecond)
	// Gaps from the transition onward: the transition gap first,
	// then gaps between consecutive tail datagrams.
	gaps := []time.Duration{tail[0].At.Sub(seg[len(seg)-1].At)}
	for i := 1; i < len(tail); i++ {
		gaps = append(gaps, tail[i].At.Sub(tail[i-1].At))
	}
	intra, idle := 0, 0
	var maxIntra, minIdle time.Duration
	for i, g := range gaps {
		switch {
		case g < time.Millisecond:
			intra++
			if g > maxIntra {
				maxIntra = g
			}
		case g >= 40*time.Millisecond:
			idle++
			if minIdle == 0 || g < minIdle {
				minIdle = g
			}
		default:
			t.Fatalf("server window 0 tail: gap %d = %v, want < 1ms (intra-burst) or >= 40ms (idle); middle band indicates uniform pacing", i, g)
		}
	}
	if intra == 0 {
		t.Fatalf("server window 0 tail: no intra-burst gap observed in %d tail gaps, burst regime not exercised", len(gaps))
	}
	t.Logf("server window 0: %d shaping datagrams paced (>= 8ms), %d tail datagrams: %d intra-burst (max %v), %d idle (min %v)", len(seg), len(tail), intra, maxIntra, idle, minIdle)
}

func TestShapingFirstFlightBidirectional(t *testing.T) {
	serverProfile := shapingProfile(20, 20, "fixed", 700, 700, 700, 10, 20, 15, 900, 30, 40, 35)
	env := setupShapedEnv(t, serverProfile)
	// Before AUTH: bootstrap (version 0) governs the client window.
	if got := env.cli.Shaper().EffectiveProfile().Version; got != 0 {
		t.Fatalf("pre-AUTH shaper version=%d, want bootstrap 0", got)
	}
	preAuthTail := env.cli.Shaper().InTail()
	status, body, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || status != http.StatusOK {
		t.Fatalf("auth: status=%d err=%v", status, err)
	}
	// After AUTH: the server profile governs the next window.
	if got := env.cli.Shaper().EffectiveProfile().Version; got != 1 {
		t.Fatalf("post-AUTH shaper version=%d, want issued 1", got)
	}
	// Client length: the AUTH request body was padded from the
	// bootstrap LenDist (uniform 200-1200) unless the window was
	// already in tail (bootstrap steady uniform 200-1400).
	reqLen := env.srv.LastAuthContentLength()
	lo, hi := int64(200), int64(1200)
	if preAuthTail {
		hi = 1400
	}
	if reqLen < lo || reqLen > hi {
		t.Fatalf("AUTH request Content-Length=%d, want [%d, %d] (preAuthTail=%v)", reqLen, lo, hi, preAuthTail)
	}
	t.Logf("AUTH request padded to %d bytes (preAuthTail=%v)", reqLen, preAuthTail)
	// Server length: the AUTH_OK body padding is the server profile's
	// fixed LenDist (700), since the down budget (20) cannot be
	// exhausted by a handshake.
	var ok authSuccess
	if err := json.Unmarshal(body, &ok); err != nil {
		t.Fatalf("auth body not JSON: %v", err)
	}
	if len(ok.Padding) != 700 {
		t.Fatalf("AUTH_OK padding=%d bytes, want exactly 700 (server fixed LenDist)", len(ok.Padding))
	}
	// Client quantity + timing, window 0 (bootstrap timing 5-50ms).
	up0 := windowEvents(env.cli.ShapingEvents(), 0)
	assertPacedGaps(t, "client window 0", up0, 3*time.Millisecond)
	// Server quantity + timing, window 0 (server timing 10-20ms).
	// INTENDED BEHAVIOR CHANGE (Stage B B2, chan-confirmed
	// design-round authority): the server down shaper runs the
	// ISSUED profile from the start (server.go newPerAddrShapingConn
	// "down", s.IssuedProfile), and issuance now fills a missing
	// burst with the default, so the window 0 tail (after the
	// 20-datagram shaping budget) paces in bursts instead of
	// uniformly. The shaping segment keeps the >= 8ms paced-gap
	// assertion; the tail is asserted as a burst distribution
	// (line-speed intra-burst gaps, idle gaps only at burst
	// boundaries). This is not a weakening: a uniform-paced tail
	// (the old expectation) would land in the forbidden middle
	// band and fail. Bootstrap-closed (FINALIZED) refers to the
	// client Version 0 window only and is untouched.
	down0 := windowEvents(env.srv.DownEvents(), 0)
	assertServerWindow0BurstTail(t, down0)
	// Post-AUTH traffic is still shaped (window 1, server profile
	// timing 10-20ms shaping or 30-40ms steady: either way >= 8ms).
	cs, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT after AUTH: %v", err)
	}
	defer cs.Close()
	msg := []byte("shaped-post-auth")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("CONNECT echo %q, want %q", got, msg)
	}
	up1 := windowEvents(env.cli.ShapingEvents(), 1)
	if len(up1) >= 2 {
		assertPacedGaps(t, "client window 1", up1, 8*time.Millisecond)
	} else {
		t.Logf("client window 1: only %d datagrams (coalesced), pacing asserted at unit level", len(up1))
	}
}

func TestShapingMergeRule(t *testing.T) {
	// Merge rule, second half (ordering): the first proxy request
	// may only be issued after the AUTH response. The first half
	// (AUTH shares the connection's H3 initialisation flight) holds
	// structurally: AUTH is the first request on the Dial connection,
	// so its HEADERS travel with the H3 control stream setup, not on
	// a separate connection or a later flight.
	env := setupEnv(t)
	if _, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t)); err == nil {
		t.Fatalf("CONNECT before AUTH succeeded: the first proxy request must wait for the AUTH response")
	}
	st, _, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("auth: status=%d err=%v", st, err)
	}
	cs, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT after AUTH: %v", err)
	}
	defer cs.Close()
	msg := []byte("merge-rule-echo")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("CONNECT echo %q, want %q", got, msg)
	}
}

func TestShapingPushNextWindowIntegration(t *testing.T) {
	env := setupEnv(t)
	if _, _, _, err := env.cli.Auth(env.ctx(t)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if got := env.cli.Shaper().EffectiveProfile().Version; got != 1 {
		t.Fatalf("post-AUTH shaper version=%d, want issued 1", got)
	}
	srvConn := serverConnOf(t, env.srv)
	env.srv.RotateProfile()
	pushed, err := env.srv.PushCurrentProfile(srvConn)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if pushed.Version != 2 {
		t.Fatalf("pushed version=%d, want 2", pushed.Version)
	}
	// Step A selection moves on push...
	waitForProfile(t, "client never applied pushed version 2", func() bool {
		return env.cli.ActiveProfile().Version == 2
	})
	// ...but the shaper's in-flight window must not: the push is
	// pending until the next window boundary.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := env.cli.Shaper().PendingProfile(); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pend, ok := env.cli.Shaper().PendingProfile(); !ok || pend.Version != 2 {
		t.Fatalf("shaper pending=%v ok=%v, want version 2 pending", pend.Version, ok)
	}
	if got := env.cli.Shaper().EffectiveProfile().Version; got != 1 {
		t.Fatalf("in-flight shaper version=%d, want 1 (push must not rewrite the window)", got)
	}
	// Next window boundary: a re-AUTH adopts the current issued
	// profile (v2) and advances the shaper window to it.
	st, _, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("re-auth: status=%d err=%v", st, err)
	}
	if got := env.cli.Shaper().EffectiveProfile().Version; got != 2 {
		t.Fatalf("next-window shaper version=%d, want 2", got)
	}
	// The session still works after the window advance.
	cs, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT after window advance: %v", err)
	}
	defer cs.Close()
	msg := []byte("push-window-echo")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("CONNECT echo %q, want %q", got, msg)
	}
}
