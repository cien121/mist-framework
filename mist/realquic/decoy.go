package realquic

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
)

// True-QUIC round (design §4, Q12): the decoy fallback limiter. When
// a connection is not authenticated, it is served real HTTP/3
// content from the same stack (Mode A), never a forward to a
// third-party target. That content must be rate-limited, and the
// limit must be randomised per connection: a fixed, predictable cap
// is itself a fingerprint. The cap is therefore sampled once per
// connection, uniformly inside an operator-configured interval
// [minBytes, maxBytes]; the interval is deployment configuration,
// not a protocol constant, and this file invents no default interval
// — a server that leaves the interval unset runs with the limiter
// off (see ServerConfig.DecoyLimitMinBytes).
//
// The limiter counts response bytes served to the site handler on
// one connection. Once the cap is reached, further site responses on
// that connection get 429 instead of content. The response that
// crosses the cap is delivered whole, never truncated mid-body:
// truncation would make the crossing response distinguishable from
// an ordinary response. The 429 applies to site responses on that
// connection only, authenticated or not, so the limit cannot become
// an oracle between authenticated and unauthenticated connections:
// both hit the same wall at the same per-connection cap.

// DecoyLimiter is a per-connection byte budget for decoy site
// responses. The zero value is unusable: use NewDecoyLimiter.
type DecoyLimiter struct {
	capBytes int64
	used     atomic.Int64
}

// NewDecoyLimiter samples one cap uniformly in [minBytes, maxBytes]
// and returns a limiter for a single connection. It refuses a
// non-positive minimum or a maximum below the minimum.
func NewDecoyLimiter(minBytes, maxBytes int64) (*DecoyLimiter, error) {
	if minBytes <= 0 {
		return nil, errors.New("realquic: decoy limit minimum must be positive")
	}
	if maxBytes < minBytes {
		return nil, fmt.Errorf("realquic: decoy limit maximum %d below minimum %d", maxBytes, minBytes)
	}
	span := big.NewInt(maxBytes - minBytes + 1)
	n, err := rand.Int(rand.Reader, span)
	if err != nil {
		return nil, fmt.Errorf("realquic: decoy limit sample: %w", err)
	}
	return &DecoyLimiter{capBytes: minBytes + n.Int64()}, nil
}

// Cap reports the sampled cap for this connection.
func (l *DecoyLimiter) Cap() int64 { return l.capBytes }

// Used reports bytes counted so far.
func (l *DecoyLimiter) Used() int64 { return l.used.Load() }

// Remaining reports cap minus used, floored at zero.
func (l *DecoyLimiter) Remaining() int64 {
	if r := l.capBytes - l.used.Load(); r > 0 {
		return r
	}
	return 0
}

// Allow reports whether a new site response may be served: true
// while used is below cap. It does not consume budget; the counting
// writer records actual bytes written.
func (l *DecoyLimiter) Allow() bool { return l.used.Load() < l.capBytes }

// countingResponseWriter passes a site response through while
// counting bytes written to the limiter. Headers and status pass
// through unchanged.
type countingResponseWriter struct {
	http.ResponseWriter
	limiter *DecoyLimiter
}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.limiter.used.Add(int64(n))
	return n, err
}

// decoyMu guards lazy limiter creation on connState; the limiter
// itself is created once per connection.
type decoyLimiterHolder struct {
	mu      sync.Mutex
	limiter *DecoyLimiter
}

// decoyLimiterFor returns the connection's limiter, creating it on
// first use from the server's configured interval. It returns nil
// when the server has no decoy limit configured (limiter off).
func (s *Server) decoyLimiterFor(h *decoyLimiterHolder) *DecoyLimiter {
	if s.decoyLimitMin <= 0 || s.decoyLimitMax < s.decoyLimitMin {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.limiter == nil {
		lim, err := NewDecoyLimiter(s.decoyLimitMin, s.decoyLimitMax)
		if err != nil {
			return nil
		}
		h.limiter = lim
	}
	return h.limiter
}

// serveSite serves the decoy site for one connection, applying the
// per-connection limiter when configured. The limit is identical for
// authenticated and unauthenticated connections: it must not become
// an oracle between the two. A nil holder means no per-connection
// state exists (defensive path); the site is served unmetered.
func (s *Server) serveSite(w http.ResponseWriter, r *http.Request, h *decoyLimiterHolder) {
	if h == nil {
		s.site.ServeHTTP(w, r)
		return
	}
	lim := s.decoyLimiterFor(h)
	if lim == nil {
		s.site.ServeHTTP(w, r)
		return
	}
	if !lim.Allow() {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("too many requests\n"))
		return
	}
	s.site.ServeHTTP(&countingResponseWriter{ResponseWriter: w, limiter: lim}, r)
}
