package realquic

import (
	"sync"

	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// Stage B (B3, REALQUIC-DESIGN-v3 §3): PMTU tracking for the true-QUIC
// stack, built only on quic-go v0.64.1 public API. There is no PMTU
// getter anywhere in the public API (ConnectionState has no MTU field;
// the finder, the discoverer and maxMTU are all unexported), so this
// file does NOT pretend to query the stack. It reconstructs state from
// the two qlog event kinds the stack publicly emits, and it computes
// Mist-layer targets from that reconstruction.
//
// # Event model (audit: nextround/stage-a/pmtu-api-audit.md §3)
//
//   - recovery:mtu_updated (qlog.MTUUpdated{Value, Done}): emitted
//     when a probe packet is ACKed. Value is UDP payload bytes, NOT IP
//     length: IP length = Value + 28 (IPv4) / +48 (IPv6). Before the
//     first event, the validated value is InitialPacketSize (default
//     1280 UDP payload bytes). Done means the search interval has
//     narrowed to <= 21 bytes; after Done, this generation probes no
//     more.
//   - parameters_set (qlog.ParametersSet, InitiatorRemote only): the
//     handshake event carrying the PEER's max_udp_payload_size
//     (PeerCap). The stack enforces min(1452, peer value) internally;
//     this tracker only reconstructs it for reporting and for the
//     Mist-layer target formula.
//
// What is NOT readable, and is therefore never claimed here: the
// in-flight probe candidate (loss is silent, OnLost emits nothing)
// and any "last decrease time" (within one generation the validated
// value only rises, so there is no decrease event).
//
// # Lab instrument, not production telemetry
//
// qlog records every event on the connection, so a production tracer
// would be heavy; and an event stream is not a getter (the
// application can only rebuild the latest Value + Done, never query
// at an arbitrary moment). Production MUST NOT depend on parsing qlog
// for runtime decisions: Target_IP here is a Mist-layer reporting /
// chunking input, and the stack's own send sizes are governed by the
// stack itself. The wire adapter (PMTUQlogTrace) exists so a lab
// harness can plug a tracker into Config.Tracer; it is not wired
// into Dial/Listen by this step.
//
// # Target formula (§3.1, all IP-length units)
//
//	Target_IP = min(PMTU_validated, Ceiling, PeerCap), Target_IP >= 1200
//
// Ceiling is an operator expectation the stack does NOT enforce:
// there is no public ceiling knob (InitialPacketSize is a floor /
// start point, DisablePathMTUDiscovery is an on/off switch, neither
// is a ceiling), and Mist-layer chunking cannot push stack send
// sizes down (the stack coalesces frames up to its MTU). The tracker
// therefore reports two targets: TargetIP (with the ceiling, the
// Mist-layer expectation used for chunking and reporting) and
// StackEnforcedTargetIP (without it: what the stack actually
// honours). A test that confuses the two — e.g. claiming the stack
// enforces a ceiling — is a test bug, and the two-method split
// exists to make that confusion impossible.
//
// # Stack hard limit (§3.1)
//
// quic-go v0.64.1 never emits a UDP payload above 1452 bytes, i.e.
// IP length at most 1480 (IPv4) / 1500 (IPv6). Target_IP is always
// capped at that mapping. 1500 is NEVER written as an IPv4 target:
// the IPv4 target at a 1500 path MTU is 1480, not 1500.
//
// # Monotonicity and reset (§3.2, stack behaviour as written)
//
// Within one generation the validated value only rises: a smaller
// event value never lowers it. There is no fast drop, no hold period
// and no in-generation reprobe — discovery is a one-shot process
// per generation. The only reset is a generation change (path
// migration, new leg, address-family change), which clears the
// validated value back to the initial size and forgets the peer cap
// until the new leg's handshake re-reports it. The operator ceiling
// survives a reset: it is deployment configuration, not path state.
//
// # Never fragment
//
// The tracker never emits a size above its target, the datagram
// splitter never hands the stack more than one packet's worth, and
// the stream chunker starts below the target after header reserves.
// Whether a path fragments is a path property, not a stack promise;
// the laboratory fragment count = 0 check (§5.2 item 9) still applies
// at verification time and is not replaced by this tracker.

// IPv4 / IPv6 UDP-over-IP header sizes in bytes (UDP 8 + IP 20/40).
const (
	ipv4HeaderBytes = 28
	ipv6HeaderBytes = 48
)

// StackMaxUDPPayload is the quic-go v0.64.1 single-packet UDP payload
// hard limit (protocol.MaxPacketBufferSize). It is a stack behaviour
// constant, observable but not settable from public API.
const StackMaxUDPPayload = 1452

// DefaultInitialPacketSize is quic-go's default InitialPacketSize in
// UDP payload bytes (the pre-first-event validated value).
const DefaultInitialPacketSize = 1280

// MinTargetIP is the RFC 9000 Initial floor, in IP length bytes.
// Target_IP never goes below it, even if an operator ceiling would.
const MinTargetIP = 1200

// PMTUTracker holds one generation of PMTU state for one connection,
// one leg, one address family. The zero value is not usable; use
// NewPMTUTracker. All methods are safe for concurrent use.
type PMTUTracker struct {
	mu sync.Mutex
	// ipv6 selects the address family (and therefore the header size
	// and the stack-limit mapping). Family is fixed per tracker: a
	// family change is a new tracker (see PMTUSet), never a mutation.
	ipv6 bool
	// initialUDP is the generation's starting UDP payload size
	// (InitialPacketSize, clamped to the stack limit).
	initialUDP int
	// validatedIP is the current validated value in IP length bytes.
	validatedIP int
	// done reports whether the stack's search has narrowed (Done on
	// the last mtu_updated event). After Done, no further probe
	// event for this generation is expected.
	done bool
	// peerCapIP is the peer's max_udp_payload_size converted to IP
	// length bytes; peerCapSet reports whether it has been observed
	// in this generation (unset until the handshake parameters_set
	// event arrives).
	peerCapIP  int
	peerCapSet bool
	// ceilingIP is the operator ceiling expectation in IP length
	// bytes; 0 means unset (unbounded). It is NOT enforced by the
	// stack; see TargetIP vs StackEnforcedTargetIP.
	ceilingIP int
}

// NewPMTUTracker returns a tracker for one address family. initialUDP
// is the stack's InitialPacketSize in UDP payload bytes (0 selects
// the 1280 default); it is clamped to the stack limit. ceilingIP is
// the operator ceiling expectation in IP length bytes (0 = unset).
func NewPMTUTracker(ipv6 bool, initialUDP uint16, ceilingIP int) *PMTUTracker {
	init := int(initialUDP)
	if init == 0 {
		init = DefaultInitialPacketSize
	}
	if init > StackMaxUDPPayload {
		init = StackMaxUDPPayload
	}
	if init < 0 {
		init = 0
	}
	t := &PMTUTracker{ipv6: ipv6, initialUDP: init, ceilingIP: ceilingIP}
	t.validatedIP = init + t.headerBytes()
	return t
}

func (t *PMTUTracker) headerBytes() int {
	if t.ipv6 {
		return ipv6HeaderBytes
	}
	return ipv4HeaderBytes
}

func (t *PMTUTracker) stackLimitIP() int {
	if t.ipv6 {
		return StackMaxUDPPayload + ipv6HeaderBytes // 1500
	}
	return StackMaxUDPPayload + ipv4HeaderBytes // 1480, never 1500
}

// IsIPv6 reports the tracker's address family.
func (t *PMTUTracker) IsIPv6() bool {
	return t.ipv6
}

// CeilingIP returns the configured operator ceiling expectation in IP
// length bytes (0 = unset).
func (t *PMTUTracker) CeilingIP() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ceilingIP
}

// ValidatedIP returns the current validated PMTU in IP length bytes
// (the initial size before the first mtu_updated event).
func (t *PMTUTracker) ValidatedIP() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.validatedIP
}

// Done reports whether the stack's search for this generation has
// narrowed (last mtu_updated event had Done set).
func (t *PMTUTracker) Done() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.done
}

// PeerCapIP returns the peer's max_udp_payload_size converted to IP
// length bytes, and whether it has been observed this generation.
func (t *PMTUTracker) PeerCapIP() (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peerCapIP, t.peerCapSet
}

// ObserveMTUUpdated feeds one recovery:mtu_updated event into the
// tracker. valueUDP is the event's Value in UDP payload bytes;
// done is the event's Done flag. Values at or below zero are ignored
// (no such event exists; the guard keeps a corrupt feed from
// shrinking the target). Within a generation the validated value
// only rises: a smaller event value never lowers it, and the result
// is capped at the stack-limit mapping.
func (t *PMTUTracker) ObserveMTUUpdated(valueUDP int, done bool) {
	if valueUDP <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	ip := valueUDP + t.headerBytes()
	if ip > t.stackLimitIP() {
		ip = t.stackLimitIP()
	}
	if ip > t.validatedIP {
		t.validatedIP = ip
	}
	if done {
		t.done = true
	}
}

// ObservePeerCap feeds one parameters_set event's peer
// max_udp_payload_size (UDP payload bytes) into the tracker. Values
// at or below zero are ignored. The peer cap is a generation-scoped
// observation: Reset clears it until the new leg's handshake
// re-reports it.
func (t *PMTUTracker) ObservePeerCap(maxUDPPayload int) {
	if maxUDPPayload <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peerCapIP = maxUDPPayload + t.headerBytes()
	t.peerCapSet = true
}

// targetLocked computes the §3.1 target in IP length bytes.
// includeCeiling selects the Mist-layer expectation (true) versus
// the stack-enforced value (false).
func (t *PMTUTracker) targetLocked(includeCeiling bool) int {
	target := t.validatedIP
	if includeCeiling && t.ceilingIP > 0 && t.ceilingIP < target {
		target = t.ceilingIP
	}
	if t.peerCapSet && t.peerCapIP < target {
		target = t.peerCapIP
	}
	if target > t.stackLimitIP() {
		target = t.stackLimitIP()
	}
	if target < MinTargetIP {
		target = MinTargetIP
	}
	return target
}

// TargetIP returns min(validated, ceiling, peer cap) in IP length
// bytes, floored at 1200 and capped at the stack-limit mapping. This
// is the Mist-layer expectation used for stream chunking, datagram
// splitting and reporting. It is NOT a promise about stack send
// sizes when a ceiling is set: the stack does not enforce ceilings.
func (t *PMTUTracker) TargetIP() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.targetLocked(true)
}

// StackEnforcedTargetIP returns the target with the operator ceiling
// removed: min(validated, peer cap), floored and capped the same way.
// This is what the stack actually honours. When no ceiling is set
// the two targets are identical; when one is set, only TargetIP
// moves, which is exactly the sense in which a ceiling is
// "stack-unenforced".
func (t *PMTUTracker) StackEnforcedTargetIP() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.targetLocked(false)
}

// TargetUDPPayload returns TargetIP converted back to UDP payload
// bytes (the unit Mist-layer chunking and splitting work in).
func (t *PMTUTracker) TargetUDPPayload() int {
	return t.TargetIP() - t.headerBytes()
}

// Reset starts a new generation for this tracker (path migration,
// new leg, address-family change at the caller level): the validated
// value returns to the initial size, Done clears, and the peer cap is
// forgotten until the new leg's handshake re-reports it. The
// operator ceiling survives: it is deployment configuration, not
// path state. Old-generation values are never carried into the new
// generation.
func (t *PMTUTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.validatedIP = t.initialUDP + t.headerBytes()
	t.done = false
	t.peerCapIP = 0
	t.peerCapSet = false
}

// ChunkSize returns the Mist-layer STREAM write-block starting value
// for this target: Target UDP payload minus the QUIC header reserve
// minus frame-header and AEAD overhead, all in bytes. It is a
// STARTING value only: §3.1 requires calibration against the
// laboratory-observed IP-length mode (§5.2 item 7), and the arithmetic
// value must never be presented as a substitute for that measurement.
// A non-positive result (reserves at or above the target) is
// returned as 0, meaning "no chunk fits — do not write", never as a
// clamped positive size that would overshoot the target.
func (t *PMTUTracker) ChunkSize(quicHeaderReserve, frameOverhead int) int {
	v := t.TargetUDPPayload() - quicHeaderReserve - frameOverhead
	if v < 0 {
		return 0
	}
	return v
}

// SplitDatagram splits a Mist-layer datagram body into pieces no
// larger than the target UDP payload, so the stack is never handed
// more than one packet's worth: the stack does not fragment
// datagrams for the application, an oversize body would only error
// or drop. An empty body splits to nothing; the pieces reassemble
// to exactly the input in order.
func (t *PMTUTracker) SplitDatagram(body []byte) [][]byte {
	limit := t.TargetUDPPayload()
	if len(body) == 0 || limit <= 0 {
		return nil
	}
	var out [][]byte
	for len(body) > 0 {
		n := limit
		if len(body) < n {
			n = len(body)
		}
		chunk := make([]byte, n)
		copy(chunk, body[:n])
		out = append(out, chunk)
		body = body[n:]
	}
	return out
}

// pmtuLegKey identifies one leg of one connection for the registry:
// the leg name (e.g. "up"/"down" after a split, or "" for a single
// connection) plus the address family. Two legs, or two families of
// one leg, never share a tracker.
type pmtuLegKey struct {
	leg  string
	ipv6 bool
}

// PMTUSet is a per-connection registry of trackers: one tracker per
// leg per address family, created on demand with the same initial
// size and ceiling. It is the "each leg, each family independent"
// rule in one place: observing an event on one leg never moves
// another leg's target, and resetting one leg never touches another.
type PMTUSet struct {
	mu       sync.Mutex
	trackers map[pmtuLegKey]*PMTUTracker
	initial  uint16
	ceiling  int
}

// NewPMTUSet returns an empty registry. initialUDP and ceilingIP
// follow NewPMTUTracker's units (UDP payload bytes; IP length bytes;
// 0 = default / unset).
func NewPMTUSet(initialUDP uint16, ceilingIP int) *PMTUSet {
	return &PMTUSet{trackers: map[pmtuLegKey]*PMTUTracker{}, initial: initialUDP, ceiling: ceilingIP}
}

// Tracker returns the tracker for leg/ipv6, creating it (at the
// initial size) on first use.
func (s *PMTUSet) Tracker(leg string, ipv6 bool) *PMTUTracker {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := pmtuLegKey{leg: leg, ipv6: ipv6}
	t, ok := s.trackers[key]
	if !ok {
		t = NewPMTUTracker(ipv6, s.initial, s.ceiling)
		s.trackers[key] = t
	}
	return t
}

// ResetLeg resets only the named leg/family tracker to a fresh
// generation (path migration / new leg). Other legs and families
// are untouched; a leg that was never tracked is still created, so
// a reset before first use is not silently lost.
func (s *PMTUSet) ResetLeg(leg string, ipv6 bool) {
	s.Tracker(leg, ipv6).Reset()
}

// pmtuQlogRecorder is the filtering recorder behind PMTUQlogTrace:
// it forwards exactly two event kinds to the tracker and drops
// everything else (packet-level events, recovery parameters, local
// parameters, and so on). It is safe for concurrent use by the
// stack's producers.
type pmtuQlogRecorder struct {
	tracker *PMTUTracker
}

func (r *pmtuQlogRecorder) RecordEvent(ev qlogwriter.Event) {
	switch e := ev.(type) {
	case qlog.MTUUpdated:
		r.tracker.ObserveMTUUpdated(e.Value, e.Done)
	case qlog.ParametersSet:
		// Only the PEER's parameters bound this side's sends. A
		// local parameters_set describes what we advertised, not
		// what the peer accepts; feeding it in as a peer cap would
		// misreport the target.
		if e.Initiator == qlog.InitiatorRemote {
			r.tracker.ObservePeerCap(int(e.MaxUDPPayloadSize))
		}
	}
}

func (r *pmtuQlogRecorder) Close() error { return nil }

// pmtuQlogTrace adapts one tracker to the qlogwriter.Trace interface
// so a lab harness can plug it into quic-go's Config.Tracer:
//
//	Tracer: func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
//	    return NewPMTUQlogTrace(tracker)
//	}
//
// SupportsSchemas reports false: this trace consumes events, it does
// not produce qlog JSON, and it must not be mistaken for a recording
// trace. Production must not use it for runtime decisions (see the
// file header): it is the laboratory observation path for the two
// event kinds, nothing more.
type pmtuQlogTrace struct {
	recorder *pmtuQlogRecorder
}

// NewPMTUQlogTrace returns a qlogwriter.Trace feeding tracker. It is
// a lab instrument: wire it only in lab harnesses via Config.Tracer.
func NewPMTUQlogTrace(tracker *PMTUTracker) qlogwriter.Trace {
	if tracker == nil {
		panic("realquic: PMTUQlogTrace requires a non-nil tracker")
	}
	return &pmtuQlogTrace{recorder: &pmtuQlogRecorder{tracker: tracker}}
}

func (t *pmtuQlogTrace) AddProducer() qlogwriter.Recorder {
	return t.recorder
}

func (t *pmtuQlogTrace) SupportsSchemas(schema string) bool {
	return false
}

// TailPadder is the §3.3 tail-padding exception gate: padding is
// default-off and profile-gated, and when enabled it pads only
// near-full tails under a per-session overhead accounting.
//
// Rules enforced here (all §3.3):
//   - Disabled (the default) pads nothing, ever.
//   - Only tails at least half the target payload are padded
//     ("near-full"); smaller tails go out as-is, so a session does
//     not acquire a padded-to-full spike for every small tail.
//   - Padded bytes / session data bytes never exceeds the limit
//     (which itself never exceeds the 1% hard cap; see SizePolicy).
//     When the next pad would breach the limit, the tail goes out
//     unpadded and padding stops for the rest of the session's
//     budget — it does not borrow from later data.
//   - The padded body is returned for the caller to write through
//     the normal stream/write path, so padded bytes count in
//     pacing, burst and congestion accounting exactly like data
//     bytes: there is no "padded but uncounted" path in this API.
//     (The padder accounts overhead; the transport accounts sends.)
//   - Wire scatter after padding comes from QUIC header / CID /
//     frame boundaries at packetisation, not from this padder:
//     the padder pads the Mist-layer body to the target payload and
//     manufactures no artificial size variation.
//
// The padder is NOT the handshake padding mechanism (Q3 AUTH body
// padding): the two never share state or distributions.
type TailPadder struct {
	mu         sync.Mutex
	enabled    bool
	limit      float64
	dataBytes  int64
	paddedByte int64
	stopped    bool
}

// NewTailPadder builds a padder from a profile's SizePolicy tail-pad
// fields. An enabled padder with an out-of-range limit is clamped to
// disabled rather than silently running uncapped: a misconfigured
// gate must fail closed, not open.
func NewTailPadder(enabled bool, limit float64) *TailPadder {
	if enabled && (limit <= 0 || limit > TailPadOverheadHardCap) {
		enabled = false
		limit = 0
	}
	if !enabled {
		limit = 0
	}
	return &TailPadder{enabled: enabled, limit: limit}
}

// RecordData accounts unpadded payload bytes written in the session
// (the overhead denominator). Callers record the payload length of
// every downlink data write, padded or not, before or after Pad.
func (p *TailPadder) RecordData(n int) {
	if n <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dataBytes += int64(n)
}

// Pad returns the body to write for one stream tail: the input padded
// to targetPayload when eligible and within budget, otherwise the
// input unchanged. It never returns a body longer than
// targetPayload, and it never pads when disabled.
func (p *TailPadder) Pad(tail []byte, targetPayload int) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled || p.stopped || len(tail) == 0 || targetPayload <= 0 {
		return tail
	}
	// Near-full only: tails under half the target go out as-is.
	if len(tail)*2 < targetPayload {
		return tail
	}
	add := int64(targetPayload - len(tail))
	if add <= 0 {
		return tail
	}
	// Overhead accounting: padded bytes / session data bytes must
	// stay within the limit, counting this tail's payload in the
	// denominator (it is data being sent in this session).
	denom := p.dataBytes + int64(len(tail))
	if denom <= 0 || float64(p.paddedByte+add)/float64(denom) > p.limit {
		p.stopped = true
		return tail
	}
	p.paddedByte += add
	out := make([]byte, targetPayload)
	copy(out, tail)
	return out
}

// PaddedBytes returns the total padding bytes applied this session.
func (p *TailPadder) PaddedBytes() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.paddedByte
}

// DataBytes returns the total payload bytes recorded this session.
func (p *TailPadder) DataBytes() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dataBytes
}

// Stopped reports whether padding has stopped for budget reasons
// (over-limit). A disabled padder never reports stopped: it never
// started.
func (p *TailPadder) Stopped() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopped
}
