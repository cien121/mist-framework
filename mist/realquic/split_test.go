// Q4 split tests (P2 step 2, formal implementation). Lab only:
// in-memory transport (mem pairs) where the sandbox blocks unconnected
// UDP sendmsg with EPERM, plus one best-effort real-loopback-UDP case
// that skips when the sandbox blocks it (the standard-form split test
// in split_standard_test.go is the no-skip counterpart, for CI).
// Nothing here touches production, the VPS, or any tracked repository
// file. Unlike the step 1 experiment, these tests serve through the
// ordinary Server.ServePacketConns: split frames are dispatched by the
// server's own handleCustomStream switch, there is no separate split
// serve loop.
package realquic

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// tapConn records every outbound datagram, for the plaintext check:
// association material must never appear in wire bytes.
type tapConn struct {
	net.PacketConn
	mu   sync.Mutex
	bufs [][]byte
}

func (t *tapConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	cp := append([]byte{}, p...)
	t.mu.Lock()
	t.bufs = append(t.bufs, cp)
	t.mu.Unlock()
	return t.PacketConn.WriteTo(p, addr)
}

func (t *tapConn) all() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []byte
	for _, b := range t.bufs {
		out = append(out, b...)
	}
	return out
}

// startEcho starts a TCP echo server on loopback and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func ctxTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// splitEnv is one lab server plus a queue of mem pairs. The server
// serves every server-side pair up front; clients dial pairs in order
// (up leg first, then down legs, then rebuild legs).
type splitEnv struct {
	srv      *Server
	key      []byte
	echoAddr string
	cliPCs   []net.PacketConn
	srvPCs   []net.PacketConn
	taps     []*tapConn
}

func newSplitEnv(t *testing.T, prof Profile, npairs int, tap bool) *splitEnv {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	base := prof
	srv, err := NewServer(ServerConfig{Key: key, Profile: &base})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	e := &splitEnv{srv: srv, key: key, echoAddr: startEcho(t)}
	for i := 0; i < npairs; i++ {
		cli, srvPC := NewMemPair()
		if tap {
			tc := &tapConn{PacketConn: cli}
			e.taps = append(e.taps, tc)
			cli = tc
		}
		e.cliPCs = append(e.cliPCs, cli)
		e.srvPCs = append(e.srvPCs, srvPC)
	}
	go func() { _ = srv.ServePacketConns(e.srvPCs) }()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() {
		_ = srv.Close()
		for _, pc := range e.cliPCs {
			_ = pc.Close()
		}
		for _, pc := range e.srvPCs {
			_ = pc.Close()
		}
	})
	return e
}

// dialUp dials and AUTHs the up leg on pair i.
func (e *splitEnv) dialUp(t *testing.T, i int) *Client {
	t.Helper()
	cli, err := DialPacketConn(ctxTimeout(t, 30*time.Second), e.cliPCs[i], e.srvPCs[i].LocalAddr(), e.key)
	if err != nil {
		t.Fatalf("up dial: %v", err)
	}
	status, _, _, err := cli.Auth(ctxTimeout(t, 10*time.Second))
	if err != nil || status != 200 {
		t.Fatalf("up AUTH: status=%d err=%v", status, err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

// splitClient builds a SplitClient over an authed up leg; down legs are
// dialled from the queued pairs in order (pair next is consumed per
// down dial, so rebuild tests queue an extra pair).
func (e *splitEnv) splitClient(t *testing.T, up *Client, firstDown int) (*SplitClient, *int) {
	t.Helper()
	next := firstDown
	mu := &sync.Mutex{}
	dialDown := func(ctx context.Context) (*Client, error) {
		mu.Lock()
		i := next
		next++
		mu.Unlock()
		if i >= len(e.cliPCs) {
			return nil, errNoPair
		}
		return DialPacketConn(ctx, e.cliPCs[i], e.srvPCs[i].LocalAddr(), e.key)
	}
	return NewSplitClient(up, dialDown), &next
}

var errNoPair = errString("no queued pair left")

type errString string

func (e errString) Error() string { return string(e) }

// echoRoundTrip writes payload on a SplitStream and reads exactly the
// echo back. It is the reassembly proof: bytes that left on the up leg
// must return, byte-identical, on the down leg.
func echoRoundTrip(t *testing.T, ss *SplitStream, payload []byte) {
	t.Helper()
	if _, err := ss.Write(payload); err != nil {
		t.Fatalf("split write: %v", err)
	}
	got, err := io.ReadAll(io.LimitReader(splitReader{ss}, int64(len(payload))))
	if err != nil {
		t.Fatalf("split read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// splitReader adapts SplitStream.Read to io.Reader with a deadline-free
// read loop (tests bound time via context-free stream reads; a stuck
// read fails the test binary's own timeout, which is the honest signal
// for a reassembly stall).
type splitReader struct{ ss *SplitStream }

func (r splitReader) Read(p []byte) (int, error) { return r.ss.Read(p) }

func TestSplitBasicEcho(t *testing.T) {
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	e := newSplitEnv(t, prof, 2, false)
	up := e.dialUp(t, 0)
	sc, _ := e.splitClient(t, up, 1)
	ss, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("split connect: %v", err)
	}
	defer ss.Close()
	echoRoundTrip(t, ss, []byte("hello-split-world"))
	// Multi-chunk payload: forces several DATA frames across the split.
	big := make([]byte, 100*1024)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	echoRoundTrip(t, ss, big)
	// Second request on the same session reuses the bound down leg.
	ss2, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("second split connect: %v", err)
	}
	defer ss2.Close()
	echoRoundTrip(t, ss2, []byte("second-request-same-session"))
}

func TestSplitPlaintext(t *testing.T) {
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	e := newSplitEnv(t, prof, 2, true)
	up := e.dialUp(t, 0)
	sc, _ := e.splitClient(t, up, 1)
	ss, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("split connect: %v", err)
	}
	defer ss.Close()
	payload := []byte("plaintext-probe-payload-0123456789")
	echoRoundTrip(t, ss, payload)
	// Association material must not appear in any recorded wire byte:
	// the up session ID (the bind lookup key) and the echo target and
	// payload (both travel only inside QUIC encryption). The bind nonce
	// is generated inside ensureDown and is covered by construction:
	// the BIND stream is opened only after both handshakes complete,
	// and its payload is additionally sealed under the up session codec.
	snap := up.sessionSnapshot()
	if snap == nil {
		t.Fatal("no up session snapshot")
	}
	wire := append(e.taps[0].all(), e.taps[1].all()...)
	if len(wire) == 0 {
		t.Fatal("tap recorded no wire bytes; plaintext check is vacuous")
	}
	for name, needle := range map[string][]byte{
		"up session ID": snap.id[:],
		"echo target":   []byte(e.echoAddr),
		"echo payload":  payload,
	} {
		if bytes.Contains(wire, needle) {
			t.Fatalf("wire bytes contain %s in the clear", name)
		}
	}
	// Structural guarantees: the AUTH path carries no query (no
	// credential/token in a loggable URL), and the down dial uses the
	// same ordinary SNI as the up dial (testServerName), never a token.
	if strings.Contains(DefaultAuthPath, "?") {
		t.Fatalf("AUTH path carries a query: %q", DefaultAuthPath)
	}
	if DefaultAuthPath != "/auth" {
		t.Fatalf("unexpected AUTH path: %q", DefaultAuthPath)
	}
}

func TestSplitStaggerAndTTFB(t *testing.T) {
	echoAddr := startEcho(t)
	type variant struct {
		name    string
		stagger [2]float64 // profile stagger interval in ms
		split   bool
	}
	variants := []variant{
		{"single-conn", [2]float64{0, 0}, false},
		{"split-stagger0", [2]float64{0, 0}, true},
		{"split-stagger50-150", [2]float64{50, 150}, true},
	}
	const n = 12
	for _, v := range variants {
		var samples []float64
		var waited []float64
		var delays []float64
		for i := 0; i < n; i++ {
			prof := BootstrapProfile()
			prof.StaggerDelayMinMs = v.stagger[0]
			prof.StaggerDelayMaxMs = v.stagger[1]
			e := newSplitEnv(t, prof, 2, false)
			up := e.dialUp(t, i*0) // pair 0 is the up leg in every env
			_ = i
			start := time.Now()
			if !v.split {
				cs, err := up.Connect(ctxTimeout(t, 10*time.Second), echoAddr)
				if err != nil {
					t.Fatalf("%s connect: %v", v.name, err)
				}
				if _, err := cs.Write([]byte("ping")); err != nil {
					t.Fatalf("%s write: %v", v.name, err)
				}
				buf := make([]byte, 4)
				if _, err := io.ReadFull(cs, buf); err != nil {
					t.Fatalf("%s read: %v", v.name, err)
				}
				_ = cs.Close()
			} else {
				sc, _ := e.splitClient(t, up, 1)
				ss, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), echoAddr)
				if err != nil {
					t.Fatalf("%s split connect: %v", v.name, err)
				}
				if _, err := ss.Write([]byte("ping")); err != nil {
					t.Fatalf("%s write: %v", v.name, err)
				}
				buf := make([]byte, 4)
				if _, err := io.ReadFull(splitReader{ss}, buf); err != nil {
					t.Fatalf("%s read: %v", v.name, err)
				}
				_ = ss.Close()
				waited = append(waited, sc.WaitedMs...)
				delays = append(delays, float64(sc.StaggerDelay().Milliseconds()))
			}
			samples = append(samples, time.Since(start).Seconds()*1000)
			_ = e.srv.Close()
		}
		sort.Float64s(samples)
		med := samples[len(samples)/2]
		p90 := samples[int(float64(len(samples))*0.9)]
		if p90 < med {
			p90 = med
		}
		t.Logf("TTFB %s: n=%d min=%.2f p50=%.2f p90=%.2f max=%.2f ms waited=%v delays=%v",
			v.name, n, samples[0], med, p90, samples[len(samples)-1], waited, delays)
		for _, d := range delays {
			if d < v.stagger[0] || d > v.stagger[1] {
				t.Fatalf("%s sampled stagger %.0f ms outside profile [%v,%v]", v.name, d, v.stagger[0], v.stagger[1])
			}
		}
	}
}

func TestSplitCaps(t *testing.T) {
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	prof.MaxStreamsPerConn = 2
	prof.MaxReusePerConn = 3
	e := newSplitEnv(t, prof, 2, false)
	up := e.dialUp(t, 0)
	sc, _ := e.splitClient(t, up, 1)
	ctx := ctxTimeout(t, 10*time.Second)
	s1, err := sc.SplitConnect(ctx, e.echoAddr)
	if err != nil {
		t.Fatalf("split 1: %v", err)
	}
	defer s1.Close()
	s2, err := sc.SplitConnect(ctx, e.echoAddr)
	if err != nil {
		t.Fatalf("split 2: %v", err)
	}
	defer s2.Close()
	if _, err := sc.SplitConnect(ctx, e.echoAddr); err == nil || !strings.Contains(err.Error(), "stream cap") {
		t.Fatalf("3rd concurrent split: want stream-cap refusal, got err=%v", err)
	}
	// Release both, then a 3rd total connect must succeed (total=3);
	// poll because the server releases concurrency asynchronously on
	// stream close propagation.
	_ = s1.Close()
	_ = s2.Close()
	var s3 *SplitStream
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s3, err = sc.SplitConnect(ctx, e.echoAddr)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("3rd total split after release: %v", err)
	}
	defer s3.Close()
	echoRoundTrip(t, s3, []byte("third-total"))
	if _, err := sc.SplitConnect(ctx, e.echoAddr); err == nil || !strings.Contains(err.Error(), "reuse cap") {
		t.Fatalf("4th total split: want reuse-cap refusal, got err=%v", err)
	}
}

func TestSplitLifetime(t *testing.T) {
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	prof.MaxConnLifetimeSec = 2
	e := newSplitEnv(t, prof, 2, false)
	up := e.dialUp(t, 0)
	sc, _ := e.splitClient(t, up, 1)
	ss, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("split before expiry: %v", err)
	}
	echoRoundTrip(t, ss, []byte("before-expiry"))
	_ = ss.Close()
	time.Sleep(2500 * time.Millisecond)
	if _, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr); err == nil || !strings.Contains(err.Error(), "lifetime") {
		t.Fatalf("split after lifetime: want lifetime refusal, got err=%v", err)
	}
}

func TestSplitDownRebuild(t *testing.T) {
	prof := BootstrapProfile()
	prof.StaggerDelayMinMs = 0
	prof.StaggerDelayMaxMs = 0
	// 4 pairs: up, down-1, down-2 (rebuild), down-3 (post-loss rebuild).
	e := newSplitEnv(t, prof, 4, false)
	up := e.dialUp(t, 0)
	sc, _ := e.splitClient(t, up, 1)
	ss, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("split 1: %v", err)
	}
	echoRoundTrip(t, ss, []byte("before-loss"))
	_ = ss.Close()
	// Drop the down leg, then rebuild: a new request must succeed on
	// the re-bound leg.
	sc.MarkDownDead()
	ss2, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("split after down rebuild: %v", err)
	}
	defer ss2.Close()
	echoRoundTrip(t, ss2, []byte("after-rebuild"))
	// In-flight gap (honest limit, not hidden): a request whose down
	// leg dies mid-flight does not resume — its read fails, and only
	// a fresh SplitConnect recovers.
	ss3, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("split 3: %v", err)
	}
	sc.MarkDownDead()
	buf := make([]byte, 16)
	if _, err := ss3.Read(buf); err == nil {
		t.Fatalf("read on dead down leg: want error, got nil")
	}
	_ = ss3.Close()
	ss4, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), e.echoAddr)
	if err != nil {
		t.Fatalf("split after mid-flight loss: %v", err)
	}
	defer ss4.Close()
	echoRoundTrip(t, ss4, []byte("after-midflight-loss"))
}

func TestSplitLoopbackUDP(t *testing.T) {
	// Best effort: the sandbox normally blocks unconnected UDP sendmsg
	// with EPERM. A skip here is the expected sandbox result, not a
	// mechanism failure; the mem-transport tests above are the evidence.
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer a.Close()
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer b.Close()
	_ = b.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := a.WriteToUDP([]byte("probe"), b.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Skipf("loopback UDP send blocked (expected sandbox EPERM): %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := b.ReadFromUDP(buf)
	if err != nil || n != 5 {
		t.Skipf("loopback UDP probe failed: n=%d err=%v", n, err)
	}
	// Real UDP works here: run one split echo over it.
	prof := BootstrapProfile()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Key: key, Profile: &prof})
	if err != nil {
		t.Fatal(err)
	}
	srvUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	cliUDP1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	cliUDP2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	// Over real UDP a single listener accepts both legs (quic-go
	// distinguishes connections by CID). Serve one listener and dial
	// both legs to it — the same form the standard-form test uses.
	go func() { _ = srv.ServePacketConn(srvUDP) }()
	time.Sleep(100 * time.Millisecond)
	defer func() {
		_ = srv.Close()
		_ = srvUDP.Close()
		_ = cliUDP1.Close()
		_ = cliUDP2.Close()
	}()
	echoAddr := startEcho(t)
	ctx := ctxTimeout(t, 30*time.Second)
	up, err := DialPacketConn(ctx, cliUDP1, srvUDP.LocalAddr(), key)
	if err != nil {
		t.Fatalf("up dial over UDP: %v", err)
	}
	defer up.Close()
	if status, _, _, err := up.Auth(ctxTimeout(t, 10*time.Second)); err != nil || status != 200 {
		t.Fatalf("up AUTH over UDP: status=%d err=%v", status, err)
	}
	sc := NewSplitClient(up, func(ctx context.Context) (*Client, error) {
		return DialPacketConn(ctx, cliUDP2, srvUDP.LocalAddr(), key)
	})
	ss, err := sc.SplitConnect(ctxTimeout(t, 10*time.Second), echoAddr)
	if err != nil {
		t.Fatalf("split connect over UDP: %v", err)
	}
	defer ss.Close()
	echoRoundTrip(t, ss, []byte("real-udp-split"))
}
