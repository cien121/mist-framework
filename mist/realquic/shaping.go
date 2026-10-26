package realquic

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"net"
	"sync"
	"time"
)

// P1 step B: Q3 handshake shaping engine wiring
// (REALQUIC-DESIGN.md Q3, Q6, §7 second phase).
//
// What this file wires, and what it honestly cannot:
//
//   - Wired: the profile's Q3 shaping parameters are applied to real
//     sends, limited to the handshake first flight in both directions
//     (client Initial + AUTH/H3-init flight, server response flight),
//     on three dimensions:
//     length — via AUTH payload padding (see below, because quic-go
//     offers no public API to inject a PADDING frame into a handshake
//     packet, and this step does not fork quic-go or use its internal
//     packages);
//     quantity — per-direction datagram budgets from the profile
//     (NPacketsUp / NPacketsDown), counted at the actual send event
//     (the PacketConn WriteTo that hands a datagram to the transport),
//     never at an application-layer write;
//     timing — per-datagram pacing gaps sampled from the profile's
//     timing distribution with CSPRNG jitter, applied at the actual
//     send point (the wrapper sleeps before WriteTo). A fixed interval
//     is itself a feature, so a fixed timing distribution is jittered
//     ±10% (length sampling is not jittered: a fixed length is not a
//     timing feature).
//   - NOT wired at packet level (API gap, reported, not faked):
//     quic-go's public API exposes no hook to set the length of an
//     individual handshake packet, and no per-packet pacing callback.
//     Length shaping therefore rides on what the application layer can
//     legitimately control: the AUTH request body (client) and the
//     AUTH_OK response body (server) are padded to a length sampled
//     from the profile's LenDist, and the stack packetises the result.
//     The observed datagram lengths are the stack's own packetisation
//     of a padded flight, not a byte-exact target. Padding a UDP
//     datagram's tail with garbage bytes is NOT used: trailing bytes
//     after a QUIC packet are parsed as a further packet, so that
//     would corrupt the flight instead of shaping it. Likewise the
//     TCP leg has no PacketConn/datagram layer, so it is not shaped
//     by this engine (its AUTH envelope is unchanged from step A).
//
// Window (the unit "next window" means, defined here, not left vague):
//   - A window is one flight phase of one connection. Window 0 starts
//     at connection creation: client side at Dial (bootstrap, or the
//     stored server profile on a later session), server side at the
//     first datagram to a peer address (the currently issued profile).
//   - The client window advances at AUTH success: the AUTH request
//     itself is window 0 (bootstrap), and everything after the AUTH
//     response is window 1 (the server profile just adopted). A
//     pushed profile never rewrites the window in flight: it is queued
//     as pending and becomes effective only at the next window
//     boundary (the next AUTH on that connection, or an explicit
//     BeginWindow call). That is the "in-flight flight unaffected,
//     next window uses the new profile" rule, enforced by the Shaper,
//     not by convention.
//   - The server window advances at a re-AUTH on an already
//     authenticated connection (the re-AUTH response belongs to the
//     new window); the first AUTH response stays in window 0. A push
//     queues a pending profile on that connection's down shaper in
//     the same way.
//
// Tail rule (the step's key semantic, enforced, not aspirational):
//   - When a window's per-direction budget is exhausted, sending does
//     NOT go bare. The shaper transitions to the profile's steady
//     baseline slot (Steady, values provisional until the P2 baseline
//     measurement, D2): subsequent datagrams in the same window keep
//     being paced, now from the steady timing distribution, and the
//     steady length distribution becomes the padding target. There is
//     no code path that hands the QUIC stack an unwrapped PacketConn:
//     DialPacketConnWithProfileStore and listenPacketConn always wrap,
//     so every datagram the stack emits passes this layer. A budget of
//     0 means "already in tail" from the first datagram.
//   - Steady shaping itself (distribution shaping of post-handshake
//     traffic toward a measured browsing baseline) is P2's work. This
//     step only builds the transition mechanism: budget exhaustion ->
//     steady slot continues to constrain. The steady slot's numbers
//     are provisional placeholders, never presented as measured.
//
// P2 step 4: Q5 adaptive steady shaping (burst pacing).
//
//   Why the P1 steady pacing failed the baseline (P2 step 3, frozen
//   thresholds): uniform 5–100 ms pacing made traffic MORE regular,
//   not more browsing-like — inter-arrival KS 0.81/0.96 (threshold
//   0.20), burstiness Fano ratio 0.0052 (threshold [0.25, 4]), and the
//   pacing interval exceeded quic-go's ACK-coalescing scale, so ACKs
//   could not coalesce: Mist up/down datagrams ran near 1:1 versus
//   the browsing-mode control's ~1:5, and the small-up-packet proxy
//   ratio ran 5.48× (threshold [0.5, 2]). Changing the uniform mean
//   cannot fix any of these: they are shape failures, not level
//   failures.
//
//   Mechanism (profile-driven, all values provisional until D2):
//   once in tail, if the active profile's steady burst structure is
//   enabled, pacing follows a two-state machine per direction per
//   connection — a burst of BurstPackets datagrams at line speed
//   (intra-burst gaps from GapDist, normally fixed 0: pacing acts
//   BETWEEN bursts, not inside them), then one inter-burst gap from
//   IdleDist, then the next burst. The line-speed interior is load
//   bearing, and the step 4 first verification run proved why: with
//   sampled 0–2 ms intra-burst gaps the up/down ratio moved only
//   from 1:1.01 to 1:1.44, because quic-go's receiver run loop drains
//   its receive queue in batches at a sub-millisecond scale —
//   packets arriving ~1 ms apart wake the loop one by one, and the
//   ACK rule (one ACK per 2 ack-eliciting packets, internal const
//   packetsBeforeAck = 2 in quic-go v0.64.1, plus the 25 ms MaxAckDelay
//   timer for leftovers) then fires near once per data packet. Only
//   a burst arriving faster than the drain batching window lets one
//   ACK cover the whole burst. That is the ACK lever this layer
//   actually has. ACK-only datagrams cannot be exempted from pacing
//   here: at the PacketConn layer datagrams are opaque ciphertext,
//   and telling ACKs apart would mean parsing QUIC packets (fork or
//   internal packages — rejected, same rule as P1). Idle gaps are
//   therefore bounded (the step 4 issued example caps at 300 ms): an
//   unbounded idle would delay ACKs into PTO-probe storms, trading
//   one feature for retransmission noise.
//   The handshake window is untouched: burst pacing applies to the
//   steady slot only. Burst is opt-in via a server-issued profile
//   (the bootstrap profile carries no burst, so pre-AUTH window-0
//   tail keeps the P1 uniform pacing pinned by existing tests); every
//   authenticated session adopts the issued profile at AUTH, so all
//   steady traffic runs under it.
//   Small-datagram class (AckLenMax, see BeforeSendFor): datagrams at
//   or below the bound skip idle gaps. Without it, the first ACK of
//   each up-burst waited out a full idle gap (50–300 ms in the step 4
//   issued example) while the peer's PTO scale on loopback is ~25 ms,
//   and the step 4 second verification run still showed a symmetric
//   excess of ~80 datagrams per session per direction — the PTO
//   retransmission loop signature. The class bound is a profile
//   parameter, not a hard-coded constant, and 0 disables it.
//
//   Deliberately NOT wired in this step (decisions, not oversights):
//   - Steady LenDist at datagram level: no quic-go public API injects
//     a PADDING frame, and tail-padding a datagram corrupts QUIC
//     parsing (see the P1 header). Forcing the provisional uniform
//     200–1400 shape would also move away from the measured browsing
//     shape (downlink ~81% in the 1200–1400 bin). The packet-length
//     JS already passes via same-stack packetisation; SampleLen in
//     tail still returns the steady LenDist as the hook for a future
//     stream-chunking layer, whose pacing-coalescing interaction
//     needs its own experiment.
//   - DirectionRatio as an enforcement setpoint: the provisional 0.5
//     contradicts the measured browsing mix (up-share ~0.013), so
//     enforcing it means injecting cover bytes. The ratio moves
//     toward browsing here through ACK coalescing alone, with zero
//     cover bytes. See profile.go's P2 step 4 note.
//
//   Burst accounting lives in BeforeSend (the gap decision point): a
//   failed WriteTo therefore miscounts the burst position by one.
//   Writes fail only on a dead connection, after which the shaper is
//   dead too, so the miscount has no observable effect; counting
//   successful sends for the budget (AfterSend) is unchanged.
//
// Server-side counting note: one listener PacketConn serves many
// connections, so the server wrapper keys sub-shapers by peer address
// (the WriteTo destination). On real UDP each peer has its own
// address and counts independently; on the in-memory lab transport
// every peer shares one address string, so lab multi-client counts
// would merge into one shaper — a lab-transport artefact, not a
// production semantic, and single-client lab tests are unaffected.

// SendEvent is one observed datagram send: the test hook that makes
// shaping observable without decrypting anything. At is the time the
// datagram was handed to the transport (after pacing); Tail reports
// whether the steady slot was already in force for this datagram.
type SendEvent struct {
	At        time.Time
	Len       int
	Direction string
	Window    uint64
	Tail      bool
}

// maxShapingPad caps AUTH padding bodies. A profile is operator data,
// not trusted input: without a cap a rogue profile could force
// megabyte AUTH bodies. 64 KiB is far above any handshake-flight need
// and bounds the worst case; it is a lab safety bound, not a design
// number.
const maxShapingPad = 64 * 1024

// Shaper is one direction's shaping state machine for one connection
// (client side) or one peer address (server side). The zero value is
// not usable; use NewShaper.
type Shaper struct {
	mu        sync.Mutex
	direction string
	active    Profile
	pending   *Profile
	window    uint64
	sent      int
	tail      bool
	lastSend  time.Time
	log       []SendEvent
	// burstLeft counts the datagrams remaining in the current steady
	// burst AFTER the next datagram is sent (see BeforeSend). It is
	// meaningful only in tail with burst pacing enabled; 0 means the
	// next gap is an inter-burst idle gap that opens a new burst.
	burstLeft int
}

// NewShaper returns a shaper for direction ("up" or "down") starting in
// window 0 on profile p. A zero budget (NPackets for the direction)
// starts the shaper already in tail.
func NewShaper(direction string, p Profile) *Shaper {
	s := &Shaper{direction: direction, active: p}
	if s.budgetLocked() == 0 {
		s.tail = true
	}
	return s
}

func (s *Shaper) budgetLocked() int {
	if s.direction == "down" {
		return s.active.Shaping.NPacketsDown
	}
	return s.active.Shaping.NPacketsUp
}

// Budget reports the current window's per-direction packet budget.
func (s *Shaper) Budget() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.budgetLocked()
}

// EffectiveProfile returns the profile governing the current window.
// A queued push does not change this until the next window.
func (s *Shaper) EffectiveProfile() Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// PendingProfile returns the queued push profile, if any.
func (s *Shaper) PendingProfile() (Profile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return Profile{}, false
	}
	return *s.pending, true
}

// Window returns the current window number (0-based).
func (s *Shaper) Window() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.window
}

// SentInWindow returns the datagram count in the current window.
func (s *Shaper) SentInWindow() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

// InTail reports whether the current window has exhausted its budget
// and transitioned to the steady slot.
func (s *Shaper) InTail() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tail
}

// Events returns a snapshot of the recorded send log (capped: the log
// keeps at most 10000 events, oldest dropped, so a long-lived
// connection cannot grow it without bound).
func (s *Shaper) Events() []SendEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SendEvent, len(s.log))
	copy(out, s.log)
	return out
}

// QueuePending queues a pushed profile for the next window. It applies
// only if the profile is valid and strictly newer than both the active
// profile and any already-queued pending profile; anything else is
// ignored silently, exactly like step A's push rule. Queueing never
// touches the current window's parameters.
func (s *Shaper) QueuePending(p Profile) bool {
	if err := p.Validate(); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Version <= s.active.Version {
		return false
	}
	if s.pending != nil && p.Version <= s.pending.Version {
		return false
	}
	cp := p
	s.pending = &cp
	return true
}

// BeginWindow advances to the next window. If p is non-nil and valid,
// it becomes the new active profile (the AUTH rule: AUTH is
// authoritative for its own connection); otherwise a queued pending
// profile is activated if one exists, else the active profile carries
// over. Either way the per-window count resets and the tail flag is
// recomputed from the new budget. A nil p with no pending profile is
// still a window advance (count reset), which is what a re-AUTH with
// an unchanged profile means.
func (s *Shaper) BeginWindow(p *Profile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p != nil && p.Validate() == nil {
		s.active = *p
		s.pending = nil
	} else if s.pending != nil {
		s.active = *s.pending
		s.pending = nil
	}
	s.window++
	s.sent = 0
	s.lastSend = time.Time{}
	s.tail = s.budgetLocked() == 0
	s.burstLeft = 0
}

// SampleLen samples the current phase's target length in bytes: the
// shaping LenDist while the budget lasts, the steady LenDist once in
// tail. Sampling consumes no budget and changes no state, so an AUTH
// body can be sized from it before its flight is sent. The result is
// capped at maxShapingPad (see above).
func (s *Shaper) SampleLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var d Distribution
	if s.tail {
		d = s.active.Steady.LenDist
	} else {
		d = s.active.Shaping.LenDist
	}
	v := sampleDistribution(d, false)
	if v < 0 {
		v = 0
	}
	if v > maxShapingPad {
		v = maxShapingPad
	}
	return int(v)
}

// SampleGap samples the current phase's inter-datagram gap: the
// shaping TimingDist while the budget lasts, the steady TimingDist
// once in tail. Sampling consumes no budget and changes no state.
// It is a distribution probe, not the pacing path: the pacing path is
// BeforeSend, which in tail with burst pacing enabled returns gaps
// from the burst GapDist/IdleDist instead of this TimingDist sample.
// Callers must not use SampleGap to predict steady pacing when burst
// pacing is on.
func (s *Shaper) SampleGap() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sampleGapLocked()
}

func (s *Shaper) sampleGapLocked() time.Duration {
	var d Distribution
	if s.tail {
		d = s.active.Steady.TimingDist
	} else {
		d = s.active.Shaping.TimingDist
	}
	// Timing gets the anti-fixed-interval jitter (see file header);
	// length sampling does not.
	v := sampleDistribution(d, true)
	if v < 0 {
		v = 0
	}
	return time.Duration(v * float64(time.Millisecond))
}

// burstEnabledLocked reports whether the current window's steady slot
// paces in bursts. Burst pacing applies to the tail (steady slot)
// only; the handshake window always uses the shaping TimingDist.
func (s *Shaper) burstEnabledLocked() bool {
	return s.tail && s.active.Steady.BurstEnabled()
}

// sampleBurstSizeLocked samples one burst size uniformly from the
// profile's inclusive [MinPackets, MaxPackets] range with CSPRNG.
func (s *Shaper) sampleBurstSizeLocked() int {
	b := s.active.Steady.Burst
	if b.MaxPackets <= b.MinPackets {
		return b.MinPackets
	}
	span := b.MaxPackets - b.MinPackets + 1
	return b.MinPackets + int(cryptoFloat()*float64(span))
}

// sampleBurstGapLocked samples one gap from the burst's gap or idle
// distribution. Timing distributions get the anti-fixed-interval
// jitter, exactly like sampleGapLocked.
func (s *Shaper) sampleBurstGapLocked(idle bool) time.Duration {
	d := s.active.Steady.Burst.GapDist
	if idle {
		d = s.active.Steady.Burst.IdleDist
	}
	v := sampleDistribution(d, true)
	if v < 0 {
		v = 0
	}
	return time.Duration(v * float64(time.Millisecond))
}

// BeforeSend computes the pacing delay for the next datagram of
// unknown length (the data-class burst machine; see BeforeSendFor).
// Existing callers use it; the PacketConn path uses BeforeSendFor
// with the real datagram length so the small-datagram class applies.
func (s *Shaper) BeforeSend() time.Duration {
	return s.BeforeSendFor(-1)
}

// BeforeSendFor computes the pacing delay for the next datagram of
// length n. n < 0 means "length unknown" and takes the data-class
// path. The first datagram of a window has no predecessor, so its gap
// is zero; every later datagram waits a sampled gap before it is
// written. The caller sleeps outside the lock, then calls AfterSend
// on success (a failed write is not a send event and consumes no
// budget).
// In tail with burst pacing enabled, the gap follows the burst
// machine: burstLeft > 0 means this datagram continues the current
// burst (intra-burst gap, burstLeft decremented); burstLeft == 0
// means this datagram opens a new burst (inter-burst idle gap, and
// burstLeft is set to the new burst's remaining size minus this
// datagram). The very first tail datagram after budget exhaustion
// therefore takes one idle gap — the transition cost of entering the
// burst regime, paid once per window.
// Small-datagram class: when the burst's AckLenMax > 0 and 0 <= n <=
// AckLenMax, the datagram never takes an idle gap — it takes an
// intra-burst gap and leaves burstLeft untouched, so it neither
// opens nor consumes a data burst. Rationale: ACK-only datagrams are
// small by construction but unidentifiable under encryption, and the
// step 4 verification showed idle gaps (50–300 ms) delaying ACKs past
// the peer's PTO scale (loopback PTO ≈ the 25 ms ACK-delay scale plus
// near-zero RTT) into a retransmission loop that inflates BOTH
// directions' counts. Letting small datagrams through at line speed
// keeps ACKs inside the PTO scale while data bursts keep their
// separation. Small data datagrams (requests, control frames, stream
// tails) share the fast path; in browsing-like traffic those are few
// and also unpaced, so the fast path does not invent a new shape.
func (s *Shaper) BeforeSendFor(n int) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sent == 0 {
		return 0
	}
	if s.burstEnabledLocked() {
		b := s.active.Steady.Burst
		if b.AckLenMax > 0 && n >= 0 && n <= b.AckLenMax {
			return s.sampleBurstGapLocked(false)
		}
		if s.burstLeft > 0 {
			s.burstLeft--
			return s.sampleBurstGapLocked(false)
		}
		size := s.sampleBurstSizeLocked()
		if size < 1 {
			size = 1
		}
		s.burstLeft = size - 1
		return s.sampleBurstGapLocked(true)
	}
	return s.sampleGapLocked()
}

// AfterSend records one actually-sent datagram of length n and
// advances the window count; reaching the budget flips the window
// into tail (steady slot) for subsequent datagrams.
func (s *Shaper) AfterSend(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	// The event records the phase that governed this datagram: a
	// datagram that exhausts the budget was still shaped under the
	// shaping parameters; only subsequent datagrams are tail.
	wasTail := s.tail
	s.sent++
	if s.budgetLocked() > 0 && s.sent >= s.budgetLocked() {
		s.tail = true
	}
	s.lastSend = now
	if len(s.log) >= 10000 {
		s.log = append(s.log[:0], s.log[1:]...)
	}
	s.log = append(s.log, SendEvent{At: now, Len: n, Direction: s.direction, Window: s.window, Tail: wasTail})
}

// cryptoFloat returns a uniform float64 in [0, 1) from crypto/rand.
// A crypto failure degrades to 0.5 (the distribution midpoint) rather
// than failing the send: shaping randomness must never block traffic.
func cryptoFloat() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5
	}
	return float64(binary.BigEndian.Uint64(b[:])) / float64(uint64(1)<<63) / 2
}

// sampleDistribution samples d. jitterFixed applies the ±10% CSPRNG
// jitter to fixed-kind distributions only (timing); other kinds are
// already random, and length samples never get this jitter.
func sampleDistribution(d Distribution, jitterFixed bool) float64 {
	switch d.Kind {
	case "fixed":
		v := d.Mean
		if jitterFixed {
			v = v * (1 + (cryptoFloat()*2-1)*0.1)
		}
		return v
	case "uniform":
		if d.Max <= d.Min {
			return d.Min
		}
		return d.Min + cryptoFloat()*(d.Max-d.Min)
	case "normal":
		// Box-Muller with sigma = range/4, clamped to [Min, Max], so
		// the bulk of samples sit inside the range and the mean is
		// honoured; clamping keeps the sample inside the profile's
		// stated range by construction.
		u1 := cryptoFloat()
		if u1 <= 0 {
			u1 = 1e-9
		}
		u2 := cryptoFloat()
		z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
		sigma := (d.Max - d.Min) / 4
		v := d.Mean + z*sigma
		if v < d.Min {
			v = d.Min
		}
		if v > d.Max {
			v = d.Max
		}
		return v
	default:
		return d.Mean
	}
}

// shapingPacketConn is a net.PacketConn wrapper that paces and counts
// every datagram the QUIC stack writes, in one direction. In single
// mode (client) one shaper serves all writes; in per-address mode
// (server listener) each peer address gets its own shaper, created
// lazily from profileFunc (the server's current issued profile at
// first sight of that address). Reads and deadlines pass through
// untouched: shaping constrains sends only, and the wrapper is the
// only PacketConn the stack ever sees, so there is no unwrapped
// (bare) send path.
type shapingPacketConn struct {
	inner       net.PacketConn
	direction   string
	single      *Shaper
	perAddr     map[string]*Shaper
	profileFunc func() Profile
	mu          sync.Mutex
}

func newSingleShapingConn(inner net.PacketConn, direction string, p Profile) *shapingPacketConn {
	return &shapingPacketConn{inner: inner, direction: direction, single: NewShaper(direction, p)}
}

func newPerAddrShapingConn(inner net.PacketConn, direction string, profileFunc func() Profile) *shapingPacketConn {
	return &shapingPacketConn{inner: inner, direction: direction, perAddr: map[string]*Shaper{}, profileFunc: profileFunc}
}

func (c *shapingPacketConn) shaperFor(addr net.Addr) *Shaper {
	if c.single != nil {
		return c.single
	}
	key := ""
	if addr != nil {
		key = addr.String()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sh, ok := c.perAddr[key]
	if !ok {
		sh = NewShaper(c.direction, c.profileFunc())
		c.perAddr[key] = sh
	}
	return sh
}

// shaperIfExists returns the shaper for addr without creating one.
func (c *shapingPacketConn) shaperIfExists(addr net.Addr) *Shaper {
	if c.single != nil {
		return c.single
	}
	key := ""
	if addr != nil {
		key = addr.String()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.perAddr[key]
}

// queuePendingFor queues a push profile on the shaper for addr.
func (c *shapingPacketConn) queuePendingFor(addr net.Addr, p Profile) bool {
	if sh := c.shaperIfExists(addr); sh != nil {
		return sh.QueuePending(p)
	}
	return false
}

// beginWindowFor advances the window of the shaper for addr.
func (c *shapingPacketConn) beginWindowFor(addr net.Addr, p *Profile) {
	if sh := c.shaperIfExists(addr); sh != nil {
		sh.BeginWindow(p)
	}
}

// allEvents aggregates every sub-shaper's send log.
func (c *shapingPacketConn) allEvents() []SendEvent {
	if c.single != nil {
		return c.single.Events()
	}
	c.mu.Lock()
	keys := make([]*Shaper, 0, len(c.perAddr))
	for _, sh := range c.perAddr {
		keys = append(keys, sh)
	}
	c.mu.Unlock()
	var out []SendEvent
	for _, sh := range keys {
		out = append(out, sh.Events()...)
	}
	return out
}

func (c *shapingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	sh := c.shaperFor(addr)
	if delay := sh.BeforeSendFor(len(p)); delay > 0 {
		time.Sleep(delay)
	}
	n, err := c.inner.WriteTo(p, addr)
	if err == nil {
		sh.AfterSend(len(p))
	}
	return n, err
}

func (c *shapingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.inner.ReadFrom(p)
}

func (c *shapingPacketConn) Close() error { return c.inner.Close() }

func (c *shapingPacketConn) LocalAddr() net.Addr { return c.inner.LocalAddr() }

// Note: net.PacketConn has no RemoteAddr (that is a Conn method); the
// wrapper therefore does not expose one either. quic-go only needs the
// PacketConn interface here.

func (c *shapingPacketConn) SetDeadline(t time.Time) error { return c.inner.SetDeadline(t) }

func (c *shapingPacketConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}

func (c *shapingPacketConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}

// padBytes returns n zero bytes for AUTH body padding. The content is
// meaningless filler: the shaping signal is the flight's length, and
// the padding must carry no token, key, or other meaningful data.
func padBytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	return make([]byte, n)
}
