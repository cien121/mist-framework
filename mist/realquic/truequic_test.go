package realquic

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// True-QUIC round (design §3–§8) tests. These assert mechanism
// behaviour only: no threshold here is a measured target, and no test
// asserts indistinguishability, production behaviour, or any
// undecided item's value.

// TestTrueQUICStackPin proves the quic-go pin: the module file must
// require exactly v0.64.1, and the StackVersion witness must agree.
// A drift in either fails the test loudly instead of silently
// shipping a different stack from the one the design pins.
func TestTrueQUICStackPin(t *testing.T) {
	raw, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	pinned := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "github.com/quic-go/quic-go v0.64.1" {
			pinned = true
		}
	}
	if !pinned {
		t.Fatalf("go.mod does not pin github.com/quic-go/quic-go v0.64.1")
	}
	if got := StackVersion(); got != "v0.64.1" {
		t.Fatalf("StackVersion() = %q, want v0.64.1", got)
	}
}

// TestParrotRegistry proves the borrowed-identity tracking rules:
// registration requires a version, duplicates are refused, selection
// refuses unknown and retired targets, and retirement records its
// replacement.
func TestParrotRegistry(t *testing.T) {
	r := NewParrotRegistry()
	if _, err := r.Select("chrome"); err == nil {
		t.Fatalf("select of unregistered target succeeded")
	}
	if err := r.Register(ParrotTarget{ID: "chrome"}); err == nil {
		t.Fatalf("versionless registration succeeded")
	}
	if err := r.Register(ParrotTarget{ID: "", Version: "140"}); err == nil {
		t.Fatalf("ID-less registration succeeded")
	}
	if err := r.Register(ParrotTarget{ID: "chrome", Version: "140"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := r.Register(ParrotTarget{ID: "chrome", Version: "141"}); err == nil {
		t.Fatalf("duplicate registration succeeded")
	}
	got, err := r.Select("chrome")
	if err != nil || got.Version != "140" {
		t.Fatalf("select: got %+v err %v", got, err)
	}
	if err := r.Retire("firefox", "chrome"); err == nil {
		t.Fatalf("retire of unknown target succeeded")
	}
	if err := r.Retire("chrome", "chrome-141"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := r.Select("chrome"); err == nil {
		t.Fatalf("select of retired target succeeded")
	}
}

// TestECHApplicabilityDefault proves the Q11/U17 rule in code: the
// default treats SNI as NOT hidden, stack capability alone never
// flips it, empty evidence is refused, and only a named verification
// flips it.
func TestECHApplicabilityDefault(t *testing.T) {
	e := DefaultECHApplicability()
	if !e.StackCarriesECH {
		t.Fatalf("default must record stack ECH capability")
	}
	if e.VerifiedEndToEnd || e.SNIHidden() {
		t.Fatalf("default must not treat SNI as hidden")
	}
	if _, err := e.RecordVerification(""); err == nil {
		t.Fatalf("empty evidence accepted")
	}
	if e.SNIHidden() {
		t.Fatalf("failed verification attempt flipped SNIHidden")
	}
	verified, err := e.RecordVerification("lab ECH handshake accept path, run <evidence>")
	if err != nil {
		t.Fatalf("RecordVerification: %v", err)
	}
	if !verified.VerifiedEndToEnd || !verified.SNIHidden() {
		t.Fatalf("recorded verification did not flip SNIHidden")
	}
	if verified.Evidence == "" {
		t.Fatalf("recorded verification lost its evidence")
	}
}

// TestDecoyLimiter proves the Q12 per-connection budget: the cap is
// sampled inside the configured interval, bytes are counted, and
// once the cap is reached further site responses on the same
// connection get 429 instead of content.
func TestDecoyLimiter(t *testing.T) {
	if _, err := NewDecoyLimiter(0, 10); err == nil {
		t.Fatalf("non-positive minimum accepted")
	}
	if _, err := NewDecoyLimiter(10, 5); err == nil {
		t.Fatalf("maximum below minimum accepted")
	}
	for i := 0; i < 20; i++ {
		lim, err := NewDecoyLimiter(100, 200)
		if err != nil {
			t.Fatalf("NewDecoyLimiter: %v", err)
		}
		if lim.Cap() < 100 || lim.Cap() > 200 {
			t.Fatalf("sampled cap %d outside [100, 200]", lim.Cap())
		}
	}
	// Deterministic interval: min == max pins the cap exactly.
	srv := &Server{
		site: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("hello"))
		}),
		decoyLimitMin: 5,
		decoyLimitMax: 5,
	}
	cs := &connState{}
	rec1 := httptest.NewRecorder()
	srv.serveSite(rec1, httptest.NewRequest(http.MethodGet, "/", nil), &cs.decoyLim)
	if rec1.Code != http.StatusOK || rec1.Body.String() != "hello" {
		t.Fatalf("first site response: code=%d body=%q", rec1.Code, rec1.Body.String())
	}
	rec2 := httptest.NewRecorder()
	srv.serveSite(rec2, httptest.NewRequest(http.MethodGet, "/", nil), &cs.decoyLim)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second site response after cap: code=%d, want 429", rec2.Code)
	}
	// A fresh connection gets a fresh budget: no cross-connection leak.
	cs2 := &connState{}
	rec3 := httptest.NewRecorder()
	srv.serveSite(rec3, httptest.NewRequest(http.MethodGet, "/", nil), &cs2.decoyLim)
	if rec3.Code != http.StatusOK {
		t.Fatalf("fresh connection site response: code=%d, want 200", rec3.Code)
	}
}

// TestIssueProfile proves the Q16 server-instruction value rotation:
// new parameter values issue at the next version, the burst is
// filled when the supplied profile carries none, invalid profiles
// are refused without moving the issued version, and version-only
// RotateProfile still does not change parameters.
func TestIssueProfile(t *testing.T) {
	env := setupEnv(t)
	before := env.srv.IssuedProfile()
	next := before
	next.Steady.Burst = SteadyBurst{} // burst-less on purpose
	next.MaxStreamsPerConn = 3
	issued, err := env.srv.IssueProfile(next)
	if err != nil {
		t.Fatalf("IssueProfile: %v", err)
	}
	if issued.Version != before.Version+1 {
		t.Fatalf("issued version = %d, want %d", issued.Version, before.Version+1)
	}
	if !issued.Steady.BurstEnabled() {
		t.Fatalf("issued profile lacks the filled-in burst")
	}
	if cur := env.srv.IssuedProfile(); cur.MaxStreamsPerConn != 3 {
		t.Fatalf("issued MaxStreamsPerConn = %d, want 3", cur.MaxStreamsPerConn)
	}
	bad := issued
	bad.StaggerDelayMinMs = 100
	bad.StaggerDelayMaxMs = 50
	if _, err := env.srv.IssueProfile(bad); err == nil {
		t.Fatalf("invalid profile issued")
	}
	if cur := env.srv.IssuedProfile(); cur.Version != issued.Version {
		t.Fatalf("failed issue moved version to %d", cur.Version)
	}
	rotated := env.srv.RotateProfile()
	if rotated.Version != issued.Version+1 {
		t.Fatalf("rotated version = %d, want %d", rotated.Version, issued.Version+1)
	}
	if rotated.MaxStreamsPerConn != 3 {
		t.Fatalf("version-only rotation changed parameters")
	}
}

// TestClientRequireSession proves the client-side D11 gate: Mist
// semantics (CONNECT, UDP registration, datagrams) are refused before
// AUTH on both legs, while ordinary H3 (visitor GET, and AUTH itself)
// is not gated — and after AUTH the same calls work.
func TestClientRequireSession(t *testing.T) {
	env := setupEnv(t)
	ctx := env.ctx(t)
	if _, err := env.cli.Connect(ctx, "127.0.0.1:1"); err == nil {
		t.Fatalf("pre-AUTH CONNECT succeeded")
	}
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}
	if err := env.cli.RegisterUDP(ctx, sid, "127.0.0.1:1"); err == nil {
		t.Fatalf("pre-AUTH RegisterUDP succeeded")
	}
	if err := env.cli.SendDatagram(sid, []byte("x")); err == nil {
		t.Fatalf("pre-AUTH SendDatagram succeeded")
	}
	if _, _, err := env.cli.ReceiveDatagram(ctx); err == nil {
		t.Fatalf("pre-AUTH ReceiveDatagram succeeded")
	}
	// Visitor H3 is not gated: the pre-AUTH GET still works.
	if st, _, _, err := env.cli.Get(ctx, "/"); err != nil || st != http.StatusOK {
		t.Fatalf("pre-AUTH visitor GET: status=%d err=%v", st, err)
	}
	if st, _, _, err := env.cli.Auth(ctx); err != nil || st != http.StatusOK {
		t.Fatalf("AUTH: status=%d err=%v", st, err)
	}
	cs, err := env.cli.Connect(ctx, startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("post-AUTH CONNECT: %v", err)
	}
	_ = cs.Close()
	// TCP leg: same gate, then AUTH unlocks it. The TCP leg needs its
	// own listener (the mem-pair QUIC server has none).
	tcpSrv := env.srv.TCPServer()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = tcpSrv.Serve(ln) }()
	t.Cleanup(func() {
		_ = tcpSrv.Close()
		_ = ln.Close()
	})
	tcpCli, err := DialTCP(ctx, ln.Addr().String(), env.cli.key)
	if err != nil {
		t.Fatalf("TCP dial: %v", err)
	}
	defer tcpCli.Close()
	if _, err := tcpCli.Connect(ctx, "127.0.0.1:1"); err == nil {
		t.Fatalf("pre-AUTH TCP CONNECT succeeded")
	}
	if err := tcpCli.Auth(ctx); err != nil {
		t.Fatalf("TCP AUTH: %v", err)
	}
	tcs, err := tcpCli.Connect(ctx, startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("post-AUTH TCP CONNECT: %v", err)
	}
	_ = tcs.Close()
}

// TestBootstrapUseCount proves the Q16 first-connection exposure
// observation: dials with no stored server profile count, and a dial
// after the store holds an issued profile does not.
func TestBootstrapUseCount(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	// One mem pair per dial (same pattern as the multi-instance
	// tests): separate QUIC connections never share a PacketConn.
	var cliPCs, srvPCs []net.PacketConn
	for i := 0; i < 3; i++ {
		cliPC, srvPC := NewMemPair()
		cliPCs = append(cliPCs, cliPC)
		srvPCs = append(srvPCs, srvPC)
	}
	t.Cleanup(func() {
		for _, pc := range cliPCs {
			_ = pc.Close()
		}
		for _, pc := range srvPCs {
			_ = pc.Close()
		}
	})
	go func() { _ = srv.ServePacketConns(srvPCs) }()
	defer srv.Close()
	time.Sleep(100 * time.Millisecond)
	store := NewProfileStore()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli1, err := DialPacketConnWithProfileStore(ctx, cliPCs[0], srvPCs[0].LocalAddr(), key, store, "test-server")
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer cli1.Close()
	if n := store.BootstrapUseCount("test-server"); n != 1 {
		t.Fatalf("after first dial count = %d, want 1", n)
	}
	cli2, err := DialPacketConnWithProfileStore(ctx, cliPCs[1], srvPCs[1].LocalAddr(), key, store, "test-server")
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer cli2.Close()
	if n := store.BootstrapUseCount("test-server"); n != 2 {
		t.Fatalf("after second pre-AUTH dial count = %d, want 2", n)
	}
	if st, _, _, err := cli1.Auth(ctx); err != nil || st != http.StatusOK {
		t.Fatalf("AUTH: status=%d err=%v", st, err)
	}
	cli3, err := DialPacketConnWithProfileStore(ctx, cliPCs[2], srvPCs[2].LocalAddr(), key, store, "test-server")
	if err != nil {
		t.Fatalf("dial 3: %v", err)
	}
	defer cli3.Close()
	if n := store.BootstrapUseCount("test-server"); n != 2 {
		t.Fatalf("after post-AUTH dial count = %d, want 2", n)
	}
}

// TestShapingPacketConnCountsFullLength proves the Q13 accounting
// rule at the Mist layer: shapingPacketConn.WriteTo counts the final
// datagram length actually written — padding included — and a small
// datagram (at or below AckLenMax) neither opens nor consumes a data
// burst in tail.
func TestShapingPacketConnCountsFullLength(t *testing.T) {
	a, _ := NewMemPair()
	defer a.Close()
	prof := BootstrapProfile()
	prof.Shaping.NPacketsUp = 2
	prof.Shaping.TimingDist = Distribution{Kind: "fixed", Mean: 0}
	burst := DefaultIssuedBurst()
	burst.MinPackets = 2
	burst.MaxPackets = 2
	burst.GapDist = Distribution{Kind: "fixed", Mean: 0}
	burst.IdleDist = Distribution{Kind: "fixed", Mean: 0}
	prof.Steady.Burst = burst
	wrapped := newSingleShapingConn(a, "up", prof)
	peer := a.LocalAddr()
	write := func(n int) {
		t.Helper()
		buf := make([]byte, n)
		if _, err := wrapped.WriteTo(buf, peer); err != nil {
			t.Fatalf("WriteTo(%d): %v", n, err)
		}
	}
	write(1000) // window datagram 1
	write(1000) // window datagram 2: budget exhausted -> tail
	sh := wrapped.single
	if sh.burstLeft != 0 {
		t.Fatalf("burstLeft after window = %d, want 0", sh.burstLeft)
	}
	write(100) // small datagram, AckLenMax 200: must not touch burstLeft
	if sh.burstLeft != 0 {
		t.Fatalf("small datagram consumed burst: burstLeft = %d, want 0", sh.burstLeft)
	}
	write(1000) // data datagram in tail: opens a burst of 2
	if sh.burstLeft != 1 {
		t.Fatalf("burstLeft after opening datagram = %d, want 1", sh.burstLeft)
	}
	write(1500) // padded-length datagram: counted at full length
	if sh.burstLeft != 0 {
		t.Fatalf("burstLeft after burst datagram = %d, want 0", sh.burstLeft)
	}
	events := sh.Events()
	want := []int{1000, 1000, 100, 1000, 1500}
	if len(events) != len(want) {
		t.Fatalf("events = %d, want %d", len(events), len(want))
	}
	for i, w := range want {
		if events[i].Len != w {
			t.Fatalf("event %d Len = %d, want %d", i, events[i].Len, w)
		}
	}
}

// TestShapingPacketConnCountsFullLengthPeer makes sure the test above
// does not depend on the peer address: WriteTo with a nil address
// still counts the full length (mem pair ignores the address).
func TestShapingPacketConnCountsFullLengthPeer(t *testing.T) {
	a, _ := NewMemPair()
	defer a.Close()
	prof := BootstrapProfile()
	prof.Shaping.NPacketsUp = 1
	prof.Shaping.TimingDist = Distribution{Kind: "fixed", Mean: 0}
	wrapped := newSingleShapingConn(a, "up", prof)
	buf := make([]byte, 1452)
	if _, err := wrapped.WriteTo(buf, nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	events := wrapped.single.Events()
	if len(events) != 1 || events[0].Len != 1452 {
		t.Fatalf("events = %+v, want one 1452-byte event", events)
	}
}
