package realquic

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// P1 step A (Q6) tests. These tests only add coverage; they do not
// modify any existing test's assertions.

func TestProfileBootstrapAndValidation(t *testing.T) {
	b := BootstrapProfile()
	if b.Version != 0 {
		t.Fatalf("bootstrap version=%d, want 0 (reserved for bootstrap)", b.Version)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("bootstrap profile must validate: %v", err)
	}
	// Hopping off and split caps unset are the P1 defaults, and they
	// must still be present (carried) in the schema.
	if b.HopWindowMinSec != 0 || b.HopWindowMaxSec != 0 {
		t.Fatalf("bootstrap hop window must be 0/0 (off), got [%v, %v]", b.HopWindowMinSec, b.HopWindowMaxSec)
	}
	if b.StaggerDelayMinMs != 0 || b.StaggerDelayMaxMs != 0 {
		t.Fatalf("bootstrap stagger must be 0/0 (carried, not executed), got [%v, %v]", b.StaggerDelayMinMs, b.StaggerDelayMaxMs)
	}
	// Invalid values must be rejected at the boundary, not carried.
	bad := b
	bad.Shaping.MergePolicy = "whatever"
	if err := bad.Validate(); err == nil {
		t.Fatalf("bad merge_policy must fail validation")
	}
	bad = b
	bad.HopWindowMinSec = 30
	bad.HopWindowMaxSec = 10
	if err := bad.Validate(); err == nil {
		t.Fatalf("inverted hop window must fail validation")
	}
	bad = b
	bad.Shaping.LenDist.Kind = "exponential"
	if err := bad.Validate(); err == nil {
		t.Fatalf("unknown distribution kind must fail validation")
	}
	bad = b
	bad.Steady.DirectionRatio = 1.5
	if err := bad.Validate(); err == nil {
		t.Fatalf("direction_ratio outside [0,1] must fail validation")
	}
	if _, err := NewServer(ServerConfig{Key: make([]byte, 32), Profile: &bad}); err == nil {
		// bad here is the direction-ratio case; either way an invalid
		// base must fail construction.
		t.Fatalf("NewServer with an invalid base profile must fail")
	}
}

func TestProfileEncodeDecodeRoundTrip(t *testing.T) {
	p := newIssuedFrom(BootstrapProfile())
	p.HopWindowMinSec = 20
	p.HopWindowMaxSec = 40
	p.MaxStreamsPerConn = 10
	enc, err := EncodeProfile(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := DecodeProfile(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Version != p.Version || dec.HopWindowMaxSec != 40 || dec.MaxStreamsPerConn != 10 {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", dec, p)
	}
	if _, err := DecodeProfile([]byte("{not json")); err == nil {
		t.Fatalf("malformed JSON must fail decode")
	}
	if _, err := DecodeProfile([]byte(`{"version":9,"shaping":{"merge_policy":"nope"}}`)); err == nil {
		t.Fatalf("invalid profile JSON must fail decode validation")
	}
}

func TestProfileStoreVersionGate(t *testing.T) {
	s := NewProfileStore()
	if got := s.ActiveFor("srv.example"); got.Version != 0 {
		t.Fatalf("empty store must yield bootstrap (version 0), got %d", got.Version)
	}
	v1 := newIssuedFrom(BootstrapProfile())
	if !s.Put("srv.example", v1) {
		t.Fatalf("first Put must store")
	}
	if s.Put("srv.example", v1) {
		t.Fatalf("same-version Put must be rejected (stale/duplicate)")
	}
	stale := v1
	stale.Version = 0
	if s.Put("srv.example", stale) {
		t.Fatalf("older-version Put must be rejected")
	}
	v2 := v1
	v2.Version = 2
	if !s.Put("srv.example", v2) {
		t.Fatalf("newer-version Put must store")
	}
	got, ok := s.Get("srv.example")
	if !ok || got.Version != 2 {
		t.Fatalf("stored version=%d ok=%v, want 2 true", got.Version, ok)
	}
	// Invalid profiles never enter the store.
	bad := v2
	bad.Version = 3
	bad.Shaping.TailPolicy = "nope"
	if s.Put("other.example", bad) {
		t.Fatalf("invalid profile must not be stored")
	}
}

func TestRotationDelayAndRotate(t *testing.T) {
	srv, err := NewServer(ServerConfig{Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.NextRotationDelay(); ok {
		t.Fatalf("unconfigured rotation must report disabled")
	}
	if _, ok := nextRotationDelay(5*time.Second, time.Second); ok {
		t.Fatalf("inverted interval must report disabled")
	}
	if d, ok := nextRotationDelay(50*time.Millisecond, 50*time.Millisecond); !ok || d != 50*time.Millisecond {
		t.Fatalf("degenerate interval must return itself, got %v ok=%v", d, ok)
	}
	// Random picks stay inside the interval.
	for i := 0; i < 50; i++ {
		d, ok := nextRotationDelay(100*time.Millisecond, 200*time.Millisecond)
		if !ok || d < 100*time.Millisecond || d > 200*time.Millisecond {
			t.Fatalf("random delay %v ok=%v outside [100ms, 200ms]", d, ok)
		}
	}
	v1 := srv.IssuedProfile()
	if v1.Version != 1 {
		t.Fatalf("first issued version=%d, want 1", v1.Version)
	}
	v2 := srv.RotateProfile()
	if v2.Version != 2 {
		t.Fatalf("rotated version=%d, want 2", v2.Version)
	}
}

// serverConnOf returns the server side of the test connection, polling
// until the server has registered it.
func serverConnOf(t *testing.T, srv *Server) *quic.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		var found *quic.Conn
		for c := range srv.conns {
			found = c
			break
		}
		srv.mu.Unlock()
		if found != nil {
			return found
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server never registered the connection")
	return nil
}

func waitForProfile(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestAuthIssuesProfileAndReceipt(t *testing.T) {
	env := setupEnv(t)
	if got := env.cli.ActiveProfile(); got.Version != 0 {
		t.Fatalf("pre-AUTH active version=%d, want bootstrap 0", got.Version)
	}
	if _, _, _, err := env.cli.Auth(env.ctx(t)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	got := env.cli.ActiveProfile()
	if got.Version != 1 {
		t.Fatalf("post-AUTH active version=%d, want issued 1", got.Version)
	}
	stored, ok := env.cli.ProfileStore().Get(testServerName)
	if !ok || stored.Version != 1 {
		t.Fatalf("store version=%d ok=%v, want 1 true", stored.Version, ok)
	}
	// The AUTH receipt (sent by Auth) must arrive and match.
	srvConn := serverConnOf(t, env.srv)
	waitForProfile(t, "server never recorded a compliant receipt", func() bool {
		_, _, seen, downgraded, ok := env.srv.ConnProfileState(srvConn)
		return ok && seen && !downgraded
	})
	issued, receipt, _, _, _ := env.srv.ConnProfileState(srvConn)
	if issued != 1 || receipt != 1 {
		t.Fatalf("conn state issued=%d receipt=%d, want 1 1", issued, receipt)
	}
}

func TestProfilePushAppliesNextWindow(t *testing.T) {
	env := setupEnv(t)
	if _, _, _, err := env.cli.Auth(env.ctx(t)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	srvConn := serverConnOf(t, env.srv)
	// Rotate, then push: the client must move to version 2.
	env.srv.RotateProfile()
	pushed, err := env.srv.PushCurrentProfile(srvConn)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if pushed.Version != 2 {
		t.Fatalf("pushed version=%d, want 2", pushed.Version)
	}
	waitForProfile(t, "client never applied pushed version 2", func() bool {
		return env.cli.ActiveProfile().Version == 2
	})
	waitForProfile(t, "server never recorded receipt for version 2", func() bool {
		_, receipt, seen, downgraded, _ := env.srv.ConnProfileState(srvConn)
		return seen && receipt == 2 && !downgraded
	})
	// A stale push (older version) must be ignored, not applied.
	stale := pushed
	stale.Version = 1
	// Deliver the stale frame directly over a server stream, sealed
	// under the session codec, as PushCurrentProfile would.
	srvState := func() *connState {
		env.srv.mu.Lock()
		defer env.srv.mu.Unlock()
		return env.srv.connStates[srvConn]
	}()
	enc, err := EncodeProfile(stale)
	if err != nil {
		t.Fatal(err)
	}
	ctx := env.ctx(t)
	str, err := srvConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrameCodec(str, frameProfileUpdate, enc, srvState.sessionCodec()); err != nil {
		t.Fatal(err)
	}
	_ = str.Close()
	time.Sleep(300 * time.Millisecond)
	if got := env.cli.ActiveProfile().Version; got != 2 {
		t.Fatalf("stale push changed active version to %d, want 2", got)
	}
}

func TestProfilePushFailureKeepsOldProfileAndSession(t *testing.T) {
	env := setupEnv(t)
	if _, _, _, err := env.cli.Auth(env.ctx(t)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	srvConn := serverConnOf(t, env.srv)
	srvState := func() *connState {
		env.srv.mu.Lock()
		defer env.srv.mu.Unlock()
		return env.srv.connStates[srvConn]
	}()
	// Malformed push: garbage payload, correct frame type, sealed.
	ctx := env.ctx(t)
	str, err := srvConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrameCodec(str, frameProfileUpdate, []byte("not-a-profile"), srvState.sessionCodec()); err != nil {
		t.Fatal(err)
	}
	_ = str.Close()
	time.Sleep(300 * time.Millisecond)
	if got := env.cli.ActiveProfile().Version; got != 1 {
		t.Fatalf("malformed push changed active version to %d, want 1", got)
	}
	// Session still works: visitor H3 still served, and a CONNECT
	// relay still functions (echo server on loopback TCP).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	cs, err := env.cli.Connect(env.ctx(t), ln.Addr().String())
	if err != nil {
		t.Fatalf("CONNECT after failed push: %v", err)
	}
	defer cs.Close()
	if _, err := cs.Write([]byte("hello")); err != nil {
		t.Fatalf("write after failed push: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := readFullWithTimeout(cs, buf); err != nil {
		t.Fatalf("echo after failed push: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo=%q, want hello", buf)
	}
}

func readFullWithTimeout(cs *ConnectStream, buf []byte) (int, error) {
	done := make(chan error, 1)
	var n int
	go func() {
		var err error
		total := 0
		for total < len(buf) {
			var m int
			m, err = cs.Read(buf[total:])
			total += m
			if err != nil {
				break
			}
		}
		n = total
		done <- err
	}()
	select {
	case err := <-done:
		return n, err
	case <-time.After(5 * time.Second):
		return n, errTimeout
	}
}

var errTimeout = errTestTimeout

type testTimeoutError struct{}

func (testTimeoutError) Error() string { return "read timeout" }

var errTestTimeout error = testTimeoutError{}

func TestNonCompliantReceiptDowngradesToVisitor(t *testing.T) {
	env := setupEnv(t)
	if _, _, _, err := env.cli.Auth(env.ctx(t)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	srvConn := serverConnOf(t, env.srv)
	// Wait for the genuine receipt first, so the stale receipt below
	// is unambiguously a second, non-compliant one.
	waitForProfile(t, "genuine receipt never recorded", func() bool {
		_, _, seen, _, _ := env.srv.ConnProfileState(srvConn)
		return seen
	})
	// Send a stale receipt (bootstrap version 0) on a fresh stream,
	// sealed under the session codec — exactly what a client that
	// never applied the issued profile would receipt.
	payload, err := encodeProfileReceipt(profileReceipt{Version: 0, ServerID: testServerName})
	if err != nil {
		t.Fatal(err)
	}
	ctx := env.ctx(t)
	str, err := env.cli.qconn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrameCodec(str, frameProfileReceipt, payload, env.cli.codecOrIdentity()); err != nil {
		t.Fatal(err)
	}
	_ = str.Close()
	waitForProfile(t, "server never downgraded on stale receipt", func() bool {
		_, _, _, downgraded, _ := env.srv.ConnProfileState(srvConn)
		return downgraded
	})
	// Downgraded: Mist service stops (CONNECT refused with the same
	// cancellation as a pre-AUTH stream), visitor H3 keeps working.
	if _, err := env.cli.Connect(env.ctx(t), "127.0.0.1:1"); err == nil {
		t.Fatalf("CONNECT on downgraded connection must fail")
	}
	st, _, _, err := env.cli.Get(env.ctx(t), "/")
	if err != nil {
		t.Fatalf("visitor GET on downgraded connection: %v", err)
	}
	if st != 200 {
		t.Fatalf("visitor GET status=%d, want 200 (site still served)", st)
	}
	// Re-AUTH clears the downgrade (fresh issuance).
	if _, _, _, err := env.cli.Auth(env.ctx(t)); err != nil {
		t.Fatalf("re-auth: %v", err)
	}
	waitForProfile(t, "re-AUTH did not clear downgrade", func() bool {
		_, _, _, downgraded, _ := env.srv.ConnProfileState(srvConn)
		return !downgraded
	})
}

func TestLaterSessionUsesServerProfile(t *testing.T) {
	// First session: AUTH stores version 1 in a shared store.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	store := NewProfileStore()
	cliPC, srvPC := NewMemPair()
	go func() { _ = srv.ServePacketConn(srvPC) }()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := DialPacketConnWithProfileStore(ctx, cliPC, srvPC.LocalAddr(), key, store, testServerName)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()
	defer srv.Close()
	if got := cli.ActiveProfile().Version; got != 0 {
		t.Fatalf("first session pre-AUTH version=%d, want bootstrap 0", got)
	}
	if _, _, _, err := cli.Auth(ctx); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if got := cli.ActiveProfile().Version; got != 1 {
		t.Fatalf("first session post-AUTH version=%d, want 1", got)
	}
	// Second session, same store, before its own AUTH: must start from
	// the server profile, not bootstrap.
	cliPC2, srvPC2 := NewMemPair()
	go func() { _ = srv.ServePacketConn(srvPC2) }()
	time.Sleep(100 * time.Millisecond)
	cli2, err := DialPacketConnWithProfileStore(ctx, cliPC2, srvPC2.LocalAddr(), key, store, testServerName)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer cli2.Close()
	if got := cli2.ActiveProfile().Version; got != 1 {
		t.Fatalf("second session pre-AUTH version=%d, want stored server profile 1", got)
	}
}

func TestServerRotationTimer(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Key: key, RotationMin: 100 * time.Millisecond, RotationMax: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_, srvPC := NewMemPair()
	go func() { _ = srv.ServePacketConn(srvPC) }()
	defer srv.Close()
	defer srvPC.Close()
	waitForProfile(t, "rotation timer never advanced the issued version", func() bool {
		return srv.IssuedProfile().Version >= 2
	})
}
