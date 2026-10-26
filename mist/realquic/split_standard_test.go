// Q4 split standard-form test (P2 step 2). Same discipline as the P1
// supplementary test (standard_form_test.go): the server is a real
// kernel-UDP listener (net.ListenUDP, unconnected) served by
// ServePacketConn, and each client leg dials from its own unconnected
// net.ListenUDP socket to that one server address — exactly like a
// production listener, which never Connects to any client in advance
// and distinguishes the two legs by QUIC connection ID. There is
// deliberately NO fallback here: no mem transport, no connected
// adapter, no skip on dial failure. In the step-1 sandbox this test
// FAILS at dial with EPERM (seccomp blocks sendmsg with a destination
// address); that failure is expected and is the reason this test
// exists. It is written for CI on a host where unconnected UDP send
// works, and its pass there is the standard-form gate for Q4.
//
// Per family, the test proves:
//  1. Up-leg H3 AUTH gets 200.
//  2. A split CONNECT over real UDP echoes a small payload and a
//     100KB multi-frame payload byte-identically (down leg carries
//     the response), and a second request reuses the bound down leg.
//  3. Down-leg rebuild over real UDP: after MarkDownDead, a fresh
//     UDP socket + re-dial + re-AUTH + fresh-nonce re-bind serves a
//     new request byte-identically.
//
// Only the socket bind itself may skip a family (a host without that
// loopback family cannot run it at all). Anything after a successful
// bind (dial, AUTH, split CONNECT, echo) must fail or pass on its own
// merits, never skip.
package realquic

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

func TestSplitStandardForm(t *testing.T) {
	families := []struct {
		name    string
		network string
		ip      string
	}{
		{"v4", "udp4", "127.0.0.1"},
		{"v6", "udp6", "::1"},
	}
	for _, fam := range families {
		fam := fam
		t.Run(fam.name, func(t *testing.T) {
			runSplitStandardFormFamily(t, fam.network, fam.ip)
		})
	}
}

func runSplitStandardFormFamily(t *testing.T, network, ip string) {
	t.Helper()
	t.Logf("standard-form split: network=%s ip=%s (no mem fallback, no connected adapter)", network, ip)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	srv, err := NewServer(ServerConfig{Key: key, Profile: &prof})
	if err != nil {
		t.Fatal(err)
	}
	srvPC, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		// Only the socket itself missing is environmental: a host
		// without this loopback family cannot run this family at all.
		// Anything after a successful bind must fail or pass on its
		// own merits, never skip.
		t.Skipf("standard-form split %s: loopback listen failed (%v); host lacks this family", network, err)
	}
	t.Cleanup(func() { _ = srvPC.Close() })
	go func() { _ = srv.ServePacketConn(srvPC) }()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() { _ = srv.Close() })

	echoAddr := startEcho(t)
	newSocket := func() net.PacketConn {
		t.Helper()
		pc, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
		if err != nil {
			t.Fatalf("client UDP socket: %v", err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		return pc
	}
	dialCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 30*time.Second)
	}

	// (1) Up leg: dial + H3 AUTH 200 over real UDP.
	upPC := newSocket()
	ctx, cancel := dialCtx()
	up, err := DialPacketConn(ctx, upPC, srvPC.LocalAddr(), key)
	cancel()
	if err != nil {
		t.Fatalf("standard-form split up dial: %v (in the step-1 sandbox this fails with EPERM by design; this test is for CI on a host where unconnected UDP send works)", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	ctx, cancel = dialCtx()
	status, _, _, err := up.Auth(ctx)
	cancel()
	if err != nil || status != 200 {
		t.Fatalf("(1) up AUTH: status=%d err=%v, want 200", status, err)
	}
	t.Logf("(1) up H3 AUTH 200")

	// Down legs dial from fresh sockets, one per (re)build.
	dialDown := func(ctx context.Context) (*Client, error) {
		return DialPacketConn(ctx, newSocket(), srvPC.LocalAddr(), key)
	}
	sc := NewSplitClient(up, dialDown)
	reqCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 60*time.Second)
	}

	// (2) Split echo: small payload, then 100KB multi-frame, then a
	// second request on the same bound down leg.
	ctx, cancel = reqCtx()
	ss, err := sc.SplitConnect(ctx, echoAddr)
	cancel()
	if err != nil {
		t.Fatalf("(2) split connect: %v", err)
	}
	echoRoundTrip(t, ss, []byte("standard-form-split"))
	big := make([]byte, 100*1024)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	echoRoundTrip(t, ss, big)
	_ = ss.Close()
	ctx, cancel = reqCtx()
	ss2, err := sc.SplitConnect(ctx, echoAddr)
	cancel()
	if err != nil {
		t.Fatalf("(2) second split connect: %v", err)
	}
	echoRoundTrip(t, ss2, []byte("second-request-same-down-leg"))
	_ = ss2.Close()
	t.Logf("(2) split echo small + 100KB + second request byte-identical")

	// (3) Down-leg rebuild: kill the leg, then a fresh socket +
	// re-dial + re-AUTH + fresh-nonce re-bind must serve a new
	// request. The in-flight gap is covered by the mem test
	// (TestSplitDownRebuild): a dead leg's in-flight read errors,
	// only a fresh SplitConnect recovers — that behaviour is
	// transport-independent and is not re-proven here.
	sc.MarkDownDead()
	ctx, cancel = reqCtx()
	ss3, err := sc.SplitConnect(ctx, echoAddr)
	cancel()
	if err != nil {
		t.Fatalf("(3) split connect after down rebuild: %v", err)
	}
	defer ss3.Close()
	payload := []byte("after-rebuild-over-real-udp")
	if _, err := ss3.Write(payload); err != nil {
		t.Fatalf("(3) write: %v", err)
	}
	got, err := io.ReadAll(io.LimitReader(splitReader{ss3}, int64(len(payload))))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("(3) echo: err=%v got=%d want=%d", err, len(got), len(payload))
	}
	t.Logf("(3) down-leg rebuild over real UDP byte-identical")
}
