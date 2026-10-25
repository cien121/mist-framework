package realquic

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestStandardFormSupplementary is the Phase 1 sign-off supplementary
// test (REALQUIC-DESIGN.md §7, first phase): the same four items step 3
// ran over real kernel UDP, but in standard form — the form step 3 could
// not run in its sandbox:
//
//   - Server: net.ListenUDP (unconnected) + ServePacketConn. The server
//     never Connects to any client; client addresses are unknown in
//     advance, exactly like a production listener.
//   - Client: net.ListenUDP (unconnected, ephemeral port) +
//     DialPacketConn. quic-go sends with destination addresses.
//
// There is deliberately NO fallback here: no mem transport, no connected
// adapter, no skip on dial failure. In the step-3 sandbox this test
// FAILS at dial with EPERM (seccomp blocks sendmsg with a destination
// address); that failure is expected and is the reason this test exists.
// It is written for CI on a host where unconnected UDP send works, and
// its pass there is the hard prerequisite for M1/M2 sign-off.
//
// Four items per address family, mirroring step 3's four items but
// through the framework's step-4/5 code (Peek dispatch, magic-byte
// frame format, AUTH flow, session codec):
//
//  1. H3 AUTH gets 200.
//  2. Custom-frame echo, byte-identical. The framework server has no
//     generic echo frame (unknown custom types are cancelled by design),
//     so echo is exercised as CONNECT relay echo through a loopback TCP
//     echo service: CONNECT + DATA frames through the Peek dispatch and
//     the post-AUTH session codec.
//  3. A second H3 request (GET /) gets 200 with the site body, proving
//     control flow, SETTINGS and QPACK survived the custom stream.
//  4. A second CONNECT echo (300 bytes, the S1 misroute size: in the
//     old [LEN][TYPE] format its LEN high byte was 0x01) plus a
//     connection-alive check, proving the connection is intact.
//
// The echo target is a 127.0.0.1 TCP service in both families: the
// family under test is the QUIC leg, not the relay target's family.
func TestStandardFormSupplementary(t *testing.T) {
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
			runStandardFormFamily(t, fam.network, fam.ip)
		})
	}
}

func runStandardFormFamily(t *testing.T, network, ip string) {
	t.Helper()
	t.Logf("standard-form supplementary: network=%s ip=%s (no mem fallback, no connected adapter)", network, ip)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	srvPC, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		// Only the socket itself missing is environmental: a host
		// without this loopback family cannot run this family at all.
		// Anything after a successful bind (dial, send) must fail or
		// pass on its own merits, never skip.
		t.Skipf("standard-form %s: loopback listen failed (%v); host lacks this family", network, err)
	}
	cliPC, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServePacketConn(srvPC) }()
	// Give the server goroutine a moment to start listening.
	time.Sleep(100 * time.Millisecond)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dialCancel()
	cli, err := DialPacketConn(dialCtx, cliPC, srvPC.LocalAddr(), key)
	if err != nil {
		t.Fatalf("standard-form dial: %v (in the step-3 sandbox this fails with EPERM by design; this test is for CI on a host where unconnected UDP send works)", err)
	}
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
		_ = srvPC.Close()
		_ = cliPC.Close()
	})

	ctx := func() context.Context {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		return c
	}

	// (1) H3 AUTH gets 200.
	st, _, _, err := cli.Auth(ctx())
	if err != nil || st != http.StatusOK {
		t.Fatalf("(1) AUTH: status=%d err=%v, want 200", st, err)
	}
	t.Logf("(1) H3 AUTH 200")

	// (2) Custom-frame echo, byte-identical, via CONNECT relay.
	echoAddr := startTCPEchoServer(t)
	cs, err := cli.Connect(ctx(), echoAddr)
	if err != nil {
		t.Fatalf("(2) CONNECT: %v", err)
	}
	msg := []byte("standard-form-echo")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("(2) CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("(2) CONNECT echo %q, want %q", got, msg)
	}
	_ = cs.Close()
	t.Logf("(2) custom-frame echo byte-identical (%d bytes)", len(msg))

	// (3) Second H3 on the same connection: control/SETTINGS/QPACK intact.
	st, body, _, err := cli.Get(ctx(), "/")
	if err != nil || st != http.StatusOK || string(body) != "realquic lab site\n" {
		t.Fatalf("(3) GET / after CONNECT: status=%d body=%q err=%v, want 200 site content", st, body, err)
	}
	t.Logf("(3) second H3 200 after custom stream")

	// (4) Second CONNECT echo at the S1 misroute size, then alive check.
	cs2, err := cli.Connect(ctx(), echoAddr)
	if err != nil {
		t.Fatalf("(4) CONNECT: %v", err)
	}
	big := patternPayload(300)
	if _, err := cs2.Write(big); err != nil {
		t.Fatalf("(4) CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs2, len(big)); !bytes.Equal(got, big) {
		t.Fatalf("(4) 300-byte CONNECT echo mismatch")
	}
	_ = cs2.Close()
	if err := cli.qconn.Context().Err(); err != nil {
		t.Fatalf("(4) connection dead after second echo: %v", err)
	}
	st, body, _, err = cli.Get(ctx(), "/")
	if err != nil || st != http.StatusOK || string(body) != "realquic lab site\n" {
		t.Fatalf("(4) GET / after second echo: status=%d body=%q err=%v, want 200 site content", st, body, err)
	}
	t.Logf("(4) 300-byte echo OK, connection alive, H3 still 200")
}
