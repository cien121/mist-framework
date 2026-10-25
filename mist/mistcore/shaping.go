package mistcore

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"
)

// Shaper implements SPEC 8 (traffic shaping, heavy-first then light).
// One Shaper instance is used per direction of a session.
type Shaper struct {
	mu            sync.Mutex
	heavyTotal    int // N from config
	heavyDone     int
	padMin, padMax int
	jitterMaxMs   int
	tailPad       int
}

// NewShaper creates a shaper. heavyTotal=0 disables shaping entirely.
//
// padMax is clamped to 255: PLEN is a single byte on the wire (SPEC 7.1),
// so the appendix B range "64-1400" for shaping_pad_max cannot be honored
// beyond 255. Coordinator decision: wire format wins.
func NewShaper(heavyTotal, padMin, padMax, jitterMaxMs, tailPad int) *Shaper {
	if padMax > 255 {
		padMax = 255
	}
	if padMin > padMax {
		padMin = padMax
	}
	return &Shaper{
		heavyTotal:  heavyTotal,
		padMin:      padMin,
		padMax:      padMax,
		jitterMaxMs: jitterMaxMs,
		tailPad:     tailPad,
	}
}

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// PadLen returns the random padding length for the next frame.
func (s *Shaper) PadLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.heavyDone < s.heavyTotal {
		span := s.padMax - s.padMin
		if span < 0 {
			span = 0
		}
		return s.padMin + randInt(span+1)
	}
	if s.tailPad > 0 {
		return randInt(s.tailPad + 1)
	}
	return 0
}

// Delay sleeps a random jitter before sending (heavy phase only).
func (s *Shaper) Delay() {
	s.mu.Lock()
	heavy := s.heavyDone < s.heavyTotal
	jmax := s.jitterMaxMs
	s.mu.Unlock()
	if heavy && jmax > 0 {
		time.Sleep(time.Duration(randInt(jmax+1)) * time.Millisecond)
	}
}

// Done records one sent frame.
func (s *Shaper) Done() {
	s.mu.Lock()
	s.heavyDone++
	s.mu.Unlock()
}

// InHeavy reports whether the shaper is still in the heavy phase.
func (s *Shaper) InHeavy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heavyDone < s.heavyTotal
}

// Fragment splits b into 1-3 irregular chunks during the heavy phase
// (irregular write fragmentation, SPEC 8.2). Outside the heavy phase it
// returns b as a single chunk.
func (s *Shaper) Fragment(b []byte) [][]byte {
	if !s.InHeavy() || len(b) < 64 {
		return [][]byte{b}
	}
	n := 1 + randInt(3) // 1..3 chunks
	if n == 1 {
		return [][]byte{b}
	}
	out := make([][]byte, 0, n)
	rest := b
	for i := 0; i < n-1 && len(rest) > 0; i++ {
		cut := 1 + randInt(len(rest)-1)
		out = append(out, rest[:cut])
		rest = rest[cut:]
	}
	out = append(out, rest)
	return out
}

// HeavyDoneCount is for tests/diagnostics.
func (s *Shaper) HeavyDoneCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heavyDone
}
