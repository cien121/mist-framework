package realquic

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"sort"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// loopbackUDPUsable probes real loopback UDP the way the sandbox blocks it:
// a sendmsg that comes back EPERM means "not usable here". Real UDP
// verification on a capable host is a step-3 gate, not a step-2 failure.
func loopbackUDPUsable() bool {
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return false
	}
	defer a.Close()
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return false
	}
	defer b.Close()
	_ = b.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := a.WriteToUDP([]byte("probe"), b.LocalAddr().(*net.UDPAddr)); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, _, err := b.ReadFromUDP(buf)
	return err == nil && n == 5
}

type testEnv struct {
	transport string
	srvPC     net.PacketConn
	cliPC     net.PacketConn
	srv       *Server
	cli       *Client
	cancel    context.CancelFunc
}

func setupEnv(t *testing.T) *testEnv {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Key: key})
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
	// Give the server goroutine a moment to start listening.
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	env.cancel = cancel
	cli, err := DialPacketConn(ctx, env.cliPC, remote, key)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	env.cli = cli
	// Keep the test key reachable for hand-built tokens via the client.
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

func (e *testEnv) ctx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// visitor performs the plain-visitor request for the AUTH path: same method
// and path as an AUTH request, but with no token. Every failure case must
// be indistinguishable from this response.
func (e *testEnv) visitor(t *testing.T) (int, []byte) {
	t.Helper()
	status, body, _, err := e.cli.Request(e.ctx(t), http.MethodPost, DefaultAuthPath, "")
	if err != nil {
		t.Fatalf("visitor request: %v", err)
	}
	return status, body
}

func mustEphPub(t *testing.T) [32]byte {
	t.Helper()
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return pub
}

func corruptToken(t *testing.T, token string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff // flip a MAC byte: valid shape, bad HMAC
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestAuthSuccess(t *testing.T) {
	env := setupEnv(t)
	status, body, _, err := env.cli.Auth(env.ctx(t))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("auth status=%d body=%q, want 200", status, body)
	}
	var ok authSuccess
	if err := json.Unmarshal(body, &ok); err != nil {
		t.Fatalf("auth body not JSON: %v (%q)", err, body)
	}
	decoded, err := base64.StdEncoding.DecodeString(ok.ServerEphPub)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("server_eph_pub not 32 bytes: %q err=%v", ok.ServerEphPub, err)
	}
	if ok.ProfileNote == "" {
		t.Fatalf("profile placeholder note missing (P1 Q6 must be explicit, not silent)")
	}
	t.Logf("auth success: server_eph_pub=%s profile_note=%q", ok.ServerEphPub, ok.ProfileNote)
}

func TestAuthFailuresMatchVisitor(t *testing.T) {
	env := setupEnv(t)
	vStatus, vBody := env.visitor(t)
	if vStatus != http.StatusNotFound {
		t.Fatalf("visitor status=%d, want 404 (site's own response for /auth)", vStatus)
	}
	cases := map[string]func() string{
		"bad HMAC": func() string {
			tok, err := env.cli.freshToken()
			if err != nil {
				t.Fatal(err)
			}
			return corruptToken(t, tok)
		},
		"expired timestamp": func() string {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				t.Fatal(err)
			}
			return MakeToken(env.cli.key, mustEphPub(t), time.Now().Add(-time.Hour), nonce)
		},
		"replayed nonce": func() string {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				t.Fatal(err)
			}
			tok := MakeToken(env.cli.key, mustEphPub(t), time.Now(), nonce)
			// First use succeeds; the replay below must fail.
			st, _, _, err := env.cli.Request(env.ctx(t), http.MethodPost, DefaultAuthPath, tok)
			if err != nil || st != http.StatusOK {
				t.Fatalf("first use of replay token: status=%d err=%v, want 200", st, err)
			}
			return tok
		},
		"no AUTH": func() string { return "" },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			token := build()
			status, body, _, err := env.cli.Request(env.ctx(t), http.MethodPost, DefaultAuthPath, token)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if status != vStatus || string(body) != string(vBody) {
				t.Fatalf("failure response differs from visitor: status=%d body=%q, visitor status=%d body=%q",
					status, body, vStatus, vBody)
			}
			t.Logf("%s: status=%d body=%q == visitor", name, status, body)
		})
	}
}

func TestConnectionSurvivesFailure(t *testing.T) {
	env := setupEnv(t)
	// A failed AUTH first...
	tok, err := env.cli.freshToken()
	if err != nil {
		t.Fatal(err)
	}
	st, _, _, err := env.cli.Request(env.ctx(t), http.MethodPost, DefaultAuthPath, corruptToken(t, tok))
	if err != nil || st != http.StatusNotFound {
		t.Fatalf("failed auth: status=%d err=%v, want 404", st, err)
	}
	// ...then the same connection must still serve ordinary H3.
	st, body, _, err := env.cli.Get(env.ctx(t), "/")
	if err != nil {
		t.Fatalf("GET / after failure: %v", err)
	}
	if st != http.StatusOK || string(body) != "realquic lab site\n" {
		t.Fatalf("GET / after failure: status=%d body=%q, want 200 site content", st, body)
	}
	// And a valid AUTH still works on the same connection afterwards.
	st, _, _, err = env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("auth after failure: status=%d err=%v, want 200", st, err)
	}
}

func meanMedian(durs []time.Duration) (mean, median time.Duration) {
	if len(durs) == 0 {
		return 0, 0
	}
	var sum time.Duration
	sorted := append([]time.Duration{}, durs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	for _, d := range durs {
		sum += d
	}
	mean = sum / time.Duration(len(durs))
	median = sorted[len(sorted)/2]
	return mean, median
}

// TestLatencyFailureVsVisitor is preliminary M2 timing evidence only: it
// reports the failure-path vs visitor-path round-trip distributions. The
// full M2 matrix (probe types x ports x address families) is a later step.
func TestLatencyFailureVsVisitor(t *testing.T) {
	env := setupEnv(t)
	const rounds = 25
	var visitorDurs, failedDurs []time.Duration
	for i := 0; i < rounds; i++ {
		_, _, d, err := env.cli.Request(env.ctx(t), http.MethodPost, DefaultAuthPath, "")
		if err != nil {
			t.Fatalf("visitor round %d: %v", i, err)
		}
		visitorDurs = append(visitorDurs, d)
		tok, err := env.cli.freshToken()
		if err != nil {
			t.Fatal(err)
		}
		_, _, d, err = env.cli.Request(env.ctx(t), http.MethodPost, DefaultAuthPath, corruptToken(t, tok))
		if err != nil {
			t.Fatalf("failed round %d: %v", i, err)
		}
		failedDurs = append(failedDurs, d)
	}
	vMean, vMed := meanMedian(visitorDurs)
	fMean, fMed := meanMedian(failedDurs)
	delta := math.Abs(float64(fMean - vMean))
	t.Logf("transport=%s rounds=%d visitor mean=%s median=%s | failed mean=%s median=%s | |mean delta|=%s (%.1f%% of visitor mean)",
		env.transport, rounds, vMean, vMed, fMean, fMed, time.Duration(delta),
		100*delta/math.Max(float64(vMean), 1))
}
