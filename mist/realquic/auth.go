package realquic

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"sync"
	"time"
)

// AUTH token layout (opaque, header-carried, Q2.2):
// [version:1][timestamp int64 BE][nonce:16][client EPH_PUB:32][HMAC-SHA256:32]
// Total 89 bytes, base64 RawURLEncoding. The HMAC covers the domain label
// plus version, timestamp, nonce and client EPH_PUB, keyed by K_auth.
// VER / TS / EPH_PUB / FEAT semantics follow the design; FEAT is not
// negotiated in this step and is intentionally absent from the token.
const (
	authVersion byte = 1

	// DefaultAuthHeader is the lab default header carrying the token.
	// Per the design, header (and path) names are deployment configuration,
	// not protocol constants; ServerConfig/ClientConfig may override them.
	DefaultAuthHeader = "X-Mist-Auth"
	// DefaultAuthPath is the lab default AUTH request path.
	DefaultAuthPath = "/auth"
	// DefaultWindow is the lab default timestamp acceptance window.
	DefaultWindow = 5 * time.Minute
)

const (
	authTokenLen = 1 + 8 + 16 + 32 + 32
	authMacOff   = 1 + 8 + 16 + 32
)

func authMAC(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// MakeToken builds an AUTH token for the given test K_auth, client ephemeral
// public key, timestamp and nonce. Callers (tests, later steps) own nonce
// uniqueness; replay protection on the server side is by nonce cache.
func MakeToken(key []byte, ephPub [32]byte, ts time.Time, nonce [16]byte) string {
	raw := make([]byte, authTokenLen)
	raw[0] = authVersion
	binary.BigEndian.PutUint64(raw[1:9], uint64(ts.Unix()))
	copy(raw[9:25], nonce[:])
	copy(raw[25:57], ephPub[:])
	// HMAC input is label || version || ts || nonce || ephPub.
	copy(raw[57:], authMAC(key, append([]byte("mist-realquic-auth-v1"), raw[:57]...)))
	return base64.RawURLEncoding.EncodeToString(raw)
}

// verifier checks AUTH tokens: HMAC (constant-time compare), timestamp
// window, and nonce replay cache. It deliberately runs the same sequence
// for every input — including unparsable or missing tokens, where it
// computes a dummy HMAC and compares against zeros — so that the failure
// path does not fork on the outcome (design Q2.2, hard rule 1).
type verifier struct {
	key    []byte
	window time.Duration

	mu     sync.Mutex
	nonces map[string]time.Time // nonce -> expiry (token ts + window)
}

func newVerifier(key []byte, window time.Duration) *verifier {
	if window <= 0 {
		window = DefaultWindow
	}
	return &verifier{key: key, window: window, nonces: map[string]time.Time{}}
}

// Verify returns true only if HMAC, timestamp window and nonce freshness
// all pass. A nonce is recorded only on full success, so a failed attempt
// can never poison the cache, and a successful token replayed later fails
// on the nonce check and falls through to the visitor path.
func (v *verifier) Verify(token string, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != authTokenLen || raw[0] != authVersion {
		// Dummy work on the same shape as the real path.
		zero := make([]byte, 57)
		dummy := authMAC(v.key, append([]byte("mist-realquic-auth-v1"), zero...))
		hmac.Equal(dummy, make([]byte, 32))
		return false
	}
	want := authMAC(v.key, append([]byte("mist-realquic-auth-v1"), raw[:57]...))
	hmacOK := hmac.Equal(want, raw[57:])
	ts := time.Unix(int64(binary.BigEndian.Uint64(raw[1:9])), 0)
	windowOK := !ts.After(now.Add(v.window)) && !ts.Before(now.Add(-v.window))

	v.mu.Lock()
	defer v.mu.Unlock()
	for n, exp := range v.nonces {
		if exp.Before(now) {
			delete(v.nonces, n)
		}
	}
	nonceKey := string(raw[9:25])
	_, replayed := v.nonces[nonceKey]
	if hmacOK && windowOK && !replayed {
		v.nonces[nonceKey] = ts.Add(v.window)
		return true
	}
	return false
}
