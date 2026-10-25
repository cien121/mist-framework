package realquic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func randKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

// TestSessionCodecRoundTrip proves the step-5 AEAD codec round-trips at
// the frame LEN boundaries, and that sealed bytes are never the
// plaintext (the payload on the wire is ciphertext, not QUIC-only
// plaintext).
func TestSessionCodecRoundTrip(t *testing.T) {
	codec := clientSessionCodec(randKey(t), randKey(t))
	// A client-sealed payload opens under the mirror (server) codec,
	// which holds the same keys in the opposite directions.
	mirror := serverSessionCodec(codec.sealKey, codec.openKey)
	for _, n := range []int{0, 1, 255, 256, 511, 512, 4096, 32768} {
		payload := patternPayload(n)
		sealed, err := codec.Seal(payload)
		if err != nil {
			t.Fatalf("size %d: seal: %v", n, err)
		}
		if len(sealed) != n+40 {
			t.Fatalf("size %d: sealed len %d, want %d (24 nonce + 16 tag)", n, len(sealed), n+40)
		}
		if n > 0 && bytes.Equal(sealed[24:], payload) {
			t.Fatalf("size %d: sealed payload equals plaintext", n)
		}
		opened, err := mirror.Open(sealed)
		if err != nil {
			t.Fatalf("size %d: open: %v", n, err)
		}
		if !bytes.Equal(opened, payload) {
			t.Fatalf("size %d: round-trip mismatch", n)
		}
	}
	// Direction-correct round-trip: client seals, server opens.
	c2s, s2c := randKey(t), randKey(t)
	cli := clientSessionCodec(c2s, s2c)
	srv := serverSessionCodec(c2s, s2c)
	for _, n := range []int{0, 1, 255, 256, 511, 512, 4096, 32768} {
		payload := patternPayload(n)
		var buf bytes.Buffer
		if err := WriteFrameCodec(&buf, frameData, payload, cli); err != nil {
			t.Fatalf("size %d: frame write: %v", n, err)
		}
		fr, err := ReadFrameCodec(bytes.NewReader(buf.Bytes()), srv)
		if err != nil {
			t.Fatalf("size %d: frame read: %v", n, err)
		}
		if fr.Type != frameData || !bytes.Equal(fr.Payload, payload) {
			t.Fatalf("size %d: frame round-trip mismatch", n)
		}
	}
}

// TestSessionCodecTamperRejected proves AEAD authentication: any change
// to nonce, ciphertext or tag, or any truncation, fails Open.
func TestSessionCodecTamperRejected(t *testing.T) {
	codec := clientSessionCodec(randKey(t), randKey(t))
	mirror := serverSessionCodec(codec.sealKey, codec.openKey)
	sealed, err := codec.Seal([]byte("tamper-me"))
	if err != nil {
		t.Fatal(err)
	}
	mangle := func(name string, fn func([]byte)) {
		t.Run(name, func(t *testing.T) {
			cp := append([]byte{}, sealed...)
			fn(cp)
			if _, err := mirror.Open(cp); err == nil {
				t.Fatalf("tampered payload opened without error")
			}
		})
	}
	mangle("nonce byte", func(b []byte) { b[0] ^= 0xff })
	mangle("ciphertext byte", func(b []byte) { b[30] ^= 0x01 })
	mangle("tag byte", func(b []byte) { b[len(b)-1] ^= 0xff })
	// Truncation is a slice case, not an in-place edit, so it is
	// checked separately below rather than via mangle.
	if _, err := mirror.Open(sealed[:len(sealed)-1]); err == nil {
		t.Fatalf("truncated payload opened without error")
	}
	if _, err := mirror.Open(sealed[:10]); err == nil {
		t.Fatalf("short payload opened without error")
	}
}

// TestSessionCodecWrongKeyRejected proves a payload sealed under one
// session's keys cannot be opened under another session's keys.
func TestSessionCodecWrongKeyRejected(t *testing.T) {
	a := clientSessionCodec(randKey(t), randKey(t))
	b := serverSessionCodec(randKey(t), randKey(t))
	sealed, err := a.Seal([]byte("not-for-you"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed); err == nil {
		t.Fatalf("payload opened under wrong session keys")
	}
}

// TestSessionCodecDirectionIsolation proves the two directions use
// different keys: a c2s-sealed payload cannot be opened as if it were
// s2c, and vice versa.
func TestSessionCodecDirectionIsolation(t *testing.T) {
	c2s, s2c := randKey(t), randKey(t)
	cli := clientSessionCodec(c2s, s2c)
	srv := serverSessionCodec(c2s, s2c)
	sealedC2S, err := cli.Seal([]byte("up"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Open(sealedC2S); err == nil {
		t.Fatalf("c2s payload opened with the client codec (wrong direction)")
	}
	if _, err := srv.Open(sealedC2S); err != nil {
		t.Fatalf("c2s payload failed to open with the server codec: %v", err)
	}
	sealedS2C, err := srv.Seal([]byte("down"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Open(sealedS2C); err == nil {
		t.Fatalf("s2c payload opened with the server codec (wrong direction)")
	}
	if _, err := cli.Open(sealedS2C); err != nil {
		t.Fatalf("s2c payload failed to open with the client codec: %v", err)
	}
}

// TestCodecIsolationAuthedVsUnauthed proves the authed/unauthenticated
// codec boundary at frame level: a session-sealed frame read with the
// identity codec yields ciphertext, never plaintext; and a plaintext
// (identity) frame read with a session codec fails AEAD.
func TestCodecIsolationAuthedVsUnauthed(t *testing.T) {
	cli := clientSessionCodec(randKey(t), randKey(t))
	srv := serverSessionCodec(cli.sealKey, cli.openKey)
	plain := []byte("secret-payload")
	var buf bytes.Buffer
	if err := WriteFrameCodec(&buf, frameData, plain, cli); err != nil {
		t.Fatal(err)
	}
	fr, err := ReadFrameCodec(bytes.NewReader(buf.Bytes()), IdentityCodec{})
	if err != nil {
		t.Fatalf("identity read of sealed frame: %v", err)
	}
	if bytes.Equal(fr.Payload, plain) {
		t.Fatalf("identity codec recovered plaintext from a sealed frame")
	}
	var buf2 bytes.Buffer
	if err := WriteFrame(&buf2, frameData, plain); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrameCodec(bytes.NewReader(buf2.Bytes()), srv); err == nil {
		t.Fatalf("session codec opened a plaintext (identity) frame")
	}
}

// TestSessionDerivationSymmetry proves both sides derive identical
// direction keys from their own private key plus the peer's public key,
// and that a different ephemeral pair gives different keys.
func TestSessionDerivationSymmetry(t *testing.T) {
	var cPriv, cPub, sPriv, sPub [32]byte
	if _, err := rand.Read(cPriv[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(sPriv[:]); err != nil {
		t.Fatal(err)
	}
	curve25519.ScalarBaseMult(&cPub, &cPriv)
	curve25519.ScalarBaseMult(&sPub, &sPriv)
	sharedC, err := deriveShared(cPriv, sPub)
	if err != nil {
		t.Fatal(err)
	}
	sharedS, err := deriveShared(sPriv, cPub)
	if err != nil {
		t.Fatal(err)
	}
	if sharedC != sharedS {
		t.Fatalf("X25519 shared secrets differ between sides")
	}
	c2sC, s2cC, err := deriveDirectionKeys(sharedC, cPub, sPub)
	if err != nil {
		t.Fatal(err)
	}
	c2sS, s2cS, err := deriveDirectionKeys(sharedS, cPub, sPub)
	if err != nil {
		t.Fatal(err)
	}
	if c2sC != c2sS || s2cC != s2cS {
		t.Fatalf("direction keys differ between sides")
	}
	if c2sC == s2cC {
		t.Fatalf("c2s and s2c keys are equal (must differ)")
	}
	// A different client ephemeral pair must give different keys.
	var cPriv2, cPub2 [32]byte
	if _, err := rand.Read(cPriv2[:]); err != nil {
		t.Fatal(err)
	}
	curve25519.ScalarBaseMult(&cPub2, &cPriv2)
	shared2, err := deriveShared(cPriv2, sPub)
	if err != nil {
		t.Fatal(err)
	}
	c2s2, _, err := deriveDirectionKeys(shared2, cPub2, sPub)
	if err != nil {
		t.Fatal(err)
	}
	if c2s2 == c2sC {
		t.Fatalf("different ephemeral pair gave identical c2s key")
	}
}

// TestAuthedConnectUsesSessionCodec is the live proof that AUTH installs
// a working session codec: after AUTH the client holds resume identity,
// and CONNECT traffic (sealed both ways) echoes exactly, including a
// chunked 70 KiB transfer.
func TestAuthedConnectUsesSessionCodec(t *testing.T) {
	env := setupEnv(t)
	st, _, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("AUTH: status=%d err=%v", st, err)
	}
	if sess := env.cli.sessionSnapshot(); sess == nil || !sess.hasResume {
		t.Fatalf("AUTH did not install a resumable session (session=%v)", sess != nil)
	}
	cs, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	defer cs.Close()
	big := patternPayload(70000)
	if _, err := cs.Write(big); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(big)); !bytes.Equal(got, big) {
		t.Fatalf("70 KiB sealed CONNECT echo mismatch")
	}
}

// --- Q7 multi-port / shared-handler coverage ---

// TestMultiPortFallbackCoverage proves Q7 in lab form: one server over
// three mem PacketConns (standing in for three ports) serves the same
// site handler everywhere — visitor responses, failed-AUTH responses
// and AUTH success are identical on every instance, and proxy service
// works on an instance too. Real v4/v6 sockets are a step-6 gate: the
// shared-handler code path is socket-family independent, and this test
// proves the sharing, not the socket families.
func TestMultiPortFallbackCoverage(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("shared-site\n"))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found\n"))
	})
	srv, err := NewServer(ServerConfig{Key: key, Site: site})
	if err != nil {
		t.Fatal(err)
	}
	const n = 3
	var srvPCs, cliPCs []net.PacketConn
	for i := 0; i < n; i++ {
		cliPC, srvPC := NewMemPair()
		cliPCs = append(cliPCs, cliPC)
		srvPCs = append(srvPCs, srvPC)
	}
	go func() { _ = srv.ServePacketConns(srvPCs) }()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var clients []*Client
	for i := 0; i < n; i++ {
		cli, err := DialPacketConn(ctx, cliPCs[i], srvPCs[i].LocalAddr(), key)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		clients = append(clients, cli)
	}
	t.Cleanup(func() {
		for _, c := range clients {
			_ = c.Close()
		}
		_ = srv.Close()
		for _, pc := range cliPCs {
			_ = pc.Close()
		}
		for _, pc := range srvPCs {
			_ = pc.Close()
		}
	})
	reqCtx := func() context.Context {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		return c
	}
	// Visitor GET / and failed AUTH must be byte-identical everywhere.
	var wantStatus int
	var wantBody, wantFailBody []byte
	for i, cli := range clients {
		st, body, _, err := cli.Get(reqCtx(), "/")
		if err != nil {
			t.Fatalf("instance %d GET /: %v", i, err)
		}
		fst, fbody, _, err := cli.Request(reqCtx(), http.MethodPost, DefaultAuthPath, "")
		if err != nil {
			t.Fatalf("instance %d visitor AUTH path: %v", i, err)
		}
		if i == 0 {
			wantStatus, wantBody, wantFailBody = st, body, fbody
			if st != http.StatusOK || string(body) != "shared-site\n" {
				t.Fatalf("instance 0 GET /: status=%d body=%q", st, body)
			}
			if fst != http.StatusNotFound || string(fbody) != "not found\n" {
				t.Fatalf("instance 0 visitor AUTH path: status=%d body=%q", fst, fbody)
			}
		} else {
			if st != wantStatus || !bytes.Equal(body, wantBody) {
				t.Fatalf("instance %d GET / differs: status=%d body=%q, want status=%d body=%q", i, st, body, wantStatus, wantBody)
			}
			if fst != http.StatusNotFound || !bytes.Equal(fbody, wantFailBody) {
				t.Fatalf("instance %d visitor AUTH path differs: status=%d body=%q", i, fst, fbody)
			}
		}
		// AUTH succeeds on every instance (shared verifier, shared keys).
		ast, _, _, err := cli.Auth(reqCtx())
		if err != nil || ast != http.StatusOK {
			t.Fatalf("instance %d AUTH: status=%d err=%v", i, ast, err)
		}
	}
	// Proxy service works through the shared handler on instance 0.
	cs, err := clients[0].Connect(reqCtx(), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT on instance 0: %v", err)
	}
	defer cs.Close()
	msg := []byte("multi-port-connect")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("CONNECT echo %q, want %q", got, msg)
	}
	t.Logf("Q7 lab coverage PASS: %d instances, identical visitor/failed-AUTH responses, AUTH + CONNECT on shared handler", n)
}

// --- TCP leg ---

type tcpEnv struct {
	key []byte
	srv *Server
	tcp *TCPServer
	ln  net.Listener
}

func setupTCPEnv(t *testing.T) *tcpEnv {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	tcp := srv.TCPServer()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = tcp.Serve(ln) }()
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = ln.Close()
		_ = srv.Close()
	})
	return &tcpEnv{key: key, srv: srv, tcp: tcp, ln: ln}
}

func (e *tcpEnv) ctx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func readAllWithDeadline(t *testing.T, conn net.Conn, secs int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(secs) * time.Second))
	out, err := io.ReadAll(conn)
	if err != nil && len(out) == 0 {
		t.Fatalf("read: %v", err)
	}
	return out
}

func rawTLSConn(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // lab only: in-memory test certificate
		ServerName:         testServerName,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("raw TLS dial: %v", err)
	}
	return conn
}

// TestTCP LegDialAuthConnect proves the TCP leg end to end: uTLS
// handshake, AUTH, and a sealed CONNECT relay (including chunked
// 70 KiB).
func TestTCPLegDialAuthConnect(t *testing.T) {
	env := setupTCPEnv(t)
	cli, err := DialTCP(env.ctx(t), env.ln.Addr().String(), env.key)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer cli.Close()
	if err := cli.Auth(env.ctx(t)); err != nil {
		t.Fatalf("TCP AUTH: %v", err)
	}
	cs, err := cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("TCP CONNECT: %v", err)
	}
	defer cs.Close()
	big := patternPayload(70000)
	if _, err := cs.Write(big); err != nil {
		t.Fatalf("TCP CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(big)); !bytes.Equal(got, big) {
		t.Fatalf("TCP 70 KiB sealed echo mismatch")
	}
}

// TestTCPVisitorMatchesFailedAuth proves the TCP visitor fallback: a
// plain HTTP first byte and a bad AUTH token get byte-identical site
// responses, and neither gets any proxy service.
func TestTCPVisitorMatchesFailedAuth(t *testing.T) {
	env := setupTCPEnv(t)
	visitorConn := rawTLSConn(t, env.ln.Addr().String())
	_, _ = visitorConn.Write([]byte("GET / HTTP/1.1\r\nHost: realquic.test\r\n\r\n"))
	visitorBytes := readAllWithDeadline(t, visitorConn, 5)
	_ = visitorConn.Close()
	if !bytes.Contains(visitorBytes, []byte("realquic lab site\n")) {
		t.Fatalf("visitor response missing site body: %q", visitorBytes)
	}

	badConn := rawTLSConn(t, env.ln.Addr().String())
	token, _, _, err := freshTokenForKey(env.key)
	if err != nil {
		t.Fatal(err)
	}
	bad := corruptToken(t, token)
	if err := WriteFrame(badConn, frameAuth, []byte(bad)); err != nil {
		t.Fatalf("bad AUTH write: %v", err)
	}
	badBytes := readAllWithDeadline(t, badConn, 5)
	_ = badConn.Close()
	if !bytes.Equal(visitorBytes, badBytes) {
		t.Fatalf("failed-AUTH response differs from visitor:\nvisitor=%q\nfailed=%q", visitorBytes, badBytes)
	}
	t.Logf("TCP visitor == failed-AUTH bytes (%d bytes)", len(visitorBytes))
}

// TestTCPResumeFromQUICSession proves cross-leg resume: a session
// established by QUIC AUTH resumes on the TCP leg with no fresh K_auth
// token, and CONNECT then works over TCP.
func TestTCPResumeFromQUICSession(t *testing.T) {
	env := setupEnv(t)
	st, _, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("QUIC AUTH: status=%d err=%v", st, err)
	}
	session := env.cli.sessionSnapshot()
	if session == nil || !session.hasResume {
		t.Fatalf("QUIC AUTH produced no resumable session")
	}
	// The TCP leg must share this QUIC server's session table: build
	// it from the same Server, not from a fresh one.
	tcp := env.srv.TCPServer()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = tcp.Serve(ln) }()
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = ln.Close()
	})
	cli, err := DialTCP(env.ctx(t), ln.Addr().String(), env.cli.key)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer cli.Close()
	if err := cli.Resume(session); err != nil {
		t.Fatalf("TCP resume: %v", err)
	}
	cs, err := cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT after resume: %v", err)
	}
	defer cs.Close()
	msg := []byte("resumed-via-tcp")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("write after resume: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("echo after resume %q, want %q", got, msg)
	}
	// A wrong resume token must fail (and must not open proxy service).
	bad := *session
	bad.resumeToken[0] ^= 0xff
	cli2, err := DialTCP(env.ctx(t), ln.Addr().String(), env.cli.key)
	if err != nil {
		t.Fatalf("DialTCP 2: %v", err)
	}
	defer cli2.Close()
	if err := cli2.Resume(&bad); err == nil {
		t.Fatalf("TCP resume with wrong token succeeded")
	} else {
		t.Logf("wrong-token resume refused as expected: %v", err)
	}
}

// --- Fallback client ---

// TestFallbackDialTimeout proves QUIC-first with TCP fallback: with no
// QUIC server listening, the dial times out (lab value 2s, not a design
// number) and the client lands on the TCP leg with working traffic.
func TestFallbackDialTimeout(t *testing.T) {
	tcpEnv := setupTCPEnv(t)
	cliPC, srvPC := NewMemPair()
	// Blackhole, not a never-reading peer: a background drain consumes
	// the client's Initials and answers nothing, the way a UDP path
	// that drops replies behaves. (A peer that never reads at all
	// deadlocks quic-go's send queue on the bounded mem channel — a
	// mem-transport artifact, not a dial-timeout property — so the
	// drain loop is part of the fixture, not the code under test.)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := srvPC.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	defer cliPC.Close()
	defer srvPC.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dual, err := DialDual(ctx, cliPC, srvPC.LocalAddr(), tcpEnv.ln.Addr().String(),
		DialDualConfig{Key: tcpEnv.key, QUICDialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("DialDual: %v", err)
	}
	defer dual.Close()
	if dual.Leg() != "tcp" {
		t.Fatalf("leg=%q, want tcp after QUIC dial timeout", dual.Leg())
	}
	cs, err := dual.Connect(ctx, startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT on fallback TCP leg: %v", err)
	}
	defer cs.Close()
	msg := []byte("fallback-traffic")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("fallback echo %q, want %q", got, msg)
	}
}

// TestFallbackResumeAfterQUICDeath proves transport-death fallback: a
// QUIC session whose server side closes is resumed on the TCP leg
// (shared session table) without a fresh AUTH, and traffic flows.
func TestFallbackResumeAfterQUICDeath(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	cliPC, srvPC := NewMemPair()
	go func() { _ = srv.ServePacketConn(srvPC) }()
	time.Sleep(100 * time.Millisecond)
	tcp := srv.TCPServer()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = tcp.Serve(ln) }()
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = ln.Close()
		_ = srv.Close()
		_ = cliPC.Close()
		_ = srvPC.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dual, err := DialDual(ctx, cliPC, srvPC.LocalAddr(), ln.Addr().String(),
		DialDualConfig{Key: key, QUICDialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("DialDual: %v", err)
	}
	defer dual.Close()
	if dual.Leg() != "quic" {
		t.Fatalf("leg=%q, want quic before death", dual.Leg())
	}
	// Kill the QUIC side only: closing the server closes its tracked
	// QUIC connections; the TCP listener and session table survive.
	_ = srv.Close()
	switched := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ok, err := dual.ReconnectIfNeeded(ctx)
		if err != nil {
			t.Fatalf("ReconnectIfNeeded: %v", err)
		}
		if ok {
			switched = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !switched {
		t.Fatalf("QUIC death did not trigger a TCP resume within 10s (leg=%q)", dual.Leg())
	}
	if dual.Leg() != "tcp" {
		t.Fatalf("leg=%q after resume, want tcp", dual.Leg())
	}
	cs, err := dual.Connect(ctx, startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT after resume: %v", err)
	}
	defer cs.Close()
	msg := []byte("after-death-traffic")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("post-resume echo %q, want %q", got, msg)
	}
}
