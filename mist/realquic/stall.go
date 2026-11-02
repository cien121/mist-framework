package realquic

import (
	"sync"
	"time"
)

// B10 option 1 (Mist-layer blackhole detection + reconnect, new generation).
//
// The QUIC stack (quic-go v0.64.1) never shrinks its sending size inside a
// connection generation: its DPLPMTUD discoverer only rises, converges once,
// and never re-probes, while oversize packets under DF die silently with
// EMSGSIZE. The Mist layer cannot see packet sizes, so the closest
// size-correlated signal it owns is STREAM progress: bytes actually
// delivered to the application. A connection that is alive (its context
// has not errored) but delivers zero bytes for a sustained window is
// treated as stalled; the caller then closes it and dials a fresh
// connection (new generation), re-AUTHs, and resumes at object
// granularity.
//
// Honest boundaries, carried from the B10 investigation:
//   - Detection is "zero progress", never "slow progress": a slow path
//     must not trigger a reconnect. Only reports of n > 0 reset the timer.
//   - Resume is per-object, not per-byte: an object already completed is
//     never refetched, but an in-flight object restarts from byte 0.
//     In-flight responses are NOT recovered (Q4 known gap); callers must
//     not claim byte-range resume.
//   - The stall timeout T is NOT calibrated yet (V7 needs lab traffic):
//     callers supply it explicitly. The lab client's provisional default
//     (8s) is a placeholder in the 5-10s estimate band, not a measurement.

// StallDetector tracks application-level byte delivery and reports
// whether delivery has stalled for at least timeout. It is safe for
// concurrent use: one goroutine reports progress while another polls.
type StallDetector struct {
	mu      sync.Mutex
	timeout time.Duration
	now     func() time.Time
	started bool
	last    time.Time // last time progress was observed (or Start)
	total   int64
}

// NewStallDetector creates a detector with the given stall timeout.
// A nil clock means time.Now (production); tests inject a fake clock.
// A non-positive timeout disables stalling (Stalled always false) so a
// misconfigured caller fails safe towards "no reconnect" rather than
// "reconnect loop".
func NewStallDetector(timeout time.Duration, now func() time.Time) *StallDetector {
	if now == nil {
		now = time.Now
	}
	return &StallDetector{timeout: timeout, now: now}
}

// Start arms the detector: the stall window runs from this moment, so a
// session that delivers nothing from the very first byte still trips at
// timeout. Call it once per generation, before the first fetch.
func (d *StallDetector) Start() {
	d.mu.Lock()
	d.last = d.now()
	d.started = true
	d.mu.Unlock()
}

// Report records n delivered bytes. Only n > 0 advances the last-progress
// timestamp: empty reads must not keep a stalled stream alive.
func (d *StallDetector) Report(n int64) {
	if n <= 0 {
		return
	}
	d.mu.Lock()
	d.last = d.now()
	d.total += n
	d.mu.Unlock()
}

// Stalled reports whether the detector is armed and no progress has been
// observed for at least timeout. An unstarted detector, or a
// non-positive timeout, never reports stalled.
func (d *StallDetector) Stalled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.started || d.timeout <= 0 {
		return false
	}
	return !d.now().Before(d.last.Add(d.timeout))
}

// Idle returns the time since the last observed progress (zero when
// unstarted). It is the queryable form of the stall signal for logging.
func (d *StallDetector) Idle() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.started {
		return 0
	}
	return d.now().Sub(d.last)
}

// Total returns the bytes reported so far in this generation.
func (d *StallDetector) Total() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.total
}

// Reset re-arms the detector for a new generation: clock restarts, totals
// clear. It does not change the timeout.
func (d *StallDetector) Reset() {
	d.mu.Lock()
	d.last = d.now()
	d.started = true
	d.total = 0
	d.mu.Unlock()
}

// ReconnectPolicy bounds option-1 reconnects: exponential backoff plus a
// hard cap, so a flapping path degrades to a reported error instead of
// an infinite reconnect loop.
type ReconnectPolicy struct {
	// MaxReconnects caps the reconnect attempts per session (0 = default 3).
	MaxReconnects int
	// BaseDelay is the delay before the first reconnect (0 = default 1s).
	BaseDelay time.Duration
	// MaxDelay caps the backoff growth (0 = default 8s).
	MaxDelay time.Duration
}

func (p ReconnectPolicy) maxReconnects() int {
	if p.MaxReconnects <= 0 {
		return 3
	}
	return p.MaxReconnects
}

func (p ReconnectPolicy) baseDelay() time.Duration {
	if p.BaseDelay <= 0 {
		return time.Second
	}
	return p.BaseDelay
}

func (p ReconnectPolicy) maxDelay() time.Duration {
	if p.MaxDelay <= 0 {
		return 8 * time.Second
	}
	return p.MaxDelay
}

// Delay returns the backoff before reconnect attempt (0-based): base,
// doubled per attempt, capped at MaxDelay.
func (p ReconnectPolicy) Delay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := p.baseDelay()
	for i := 0; i < attempt; i++ {
		d *= 2
		if d >= p.maxDelay() {
			return p.maxDelay()
		}
	}
	if d > p.maxDelay() {
		return p.maxDelay()
	}
	return d
}

// Exhausted reports whether reconnects already used reaches the cap.
func (p ReconnectPolicy) Exhausted(reconnects int) bool {
	return reconnects >= p.maxReconnects()
}
