package realquic

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// P1 step A: Q6 server-issued profile mechanism
// (REALQUIC-DESIGN.md Q6, Q3 schema, §7 second phase).
//
// What this file is:
//   - The profile schema (Go struct + JSON wire encoding), covering the
//     full Q6 field set: shaping parameters, hopping window range,
//     reuse caps, downstream stagger delay range, steady-state baseline
//     parameters.
//   - The bootstrap profile used for a client's first connection to a
//     server it has never heard a profile from.
//   - Per-server client storage (keyed by server identity, holding no
//     key material) with a version gate: a stored profile is replaced
//     only by a strictly newer version.
//   - Server-side issuance state: the server is the version authority
//     (first issued version is 1, rotations increment), and the rotation
//     period is picked uniformly at random inside a deployment-configured
//     interval — the interval is operator configuration, the period
//     itself is never a protocol constant.
//
// What this file is NOT (mechanism first, values provisional):
//   - Every numeric value in BootstrapProfile is PROVISIONAL. D2 final
//     values wait for the P2 baseline measurement; nothing here is a
//     tuned value, and nothing here may be quoted as one.
//   - The Q3 shaping engine itself is not in this step: profiles are
//     issued, stored, validated and applied (active profile selection),
//     but no packet-length / timing shaping is executed yet. The fields
//     listed under "carried but not executed in P1" below are schema,
//     storage and validation only.
//   - No separate signature scheme for the envelope. Authenticity this
//     step rests on the channel: the envelope travels inside the AUTH
//     success body over a Mode A connection — a real QUIC/TLS 1.3
//     connection to the server's own CA-signed identity (lab: the
//     in-memory test certificate), authenticated before any profile is
//     trusted. Inventing a second signature here would add a new
//     mechanism the design does not ask for; see the step report.
//
// Carried but NOT executed in P1 (schema present, stored, validated,
// deliberately not applied — hopping stays default-off per design §7,
// the up/down split is P2):
//   - HopWindowMinSec / HopWindowMaxSec (port-hopping window range)
//   - StaggerDelayMinMs / StaggerDelayMaxMs (downstream stagger delay)
//   - MaxStreamsPerConn / MaxReusePerConn / MaxConnLifetimeSec
//     (split-connection reuse caps; the split itself is P2, so the caps
//     have nothing to constrain yet)
// Applying any of these fields before their owning step exists would be
// pretending at a mechanism. They are validated on receipt so a bad
// value is caught at the boundary, not silently carried.
//
// P2 step 4 (Q5 steady shaping) note — what changed, what did not:
//   - NEW and executed: Steady.Burst (burst pacing in the steady slot,
//     driven by the profile like every other shaping parameter; see
//     shaping.go). Burst is opt-in via a server-issued profile; a
//     profile without a burst field (including the bootstrap profile)
//     decodes to burst-off and paces exactly as before, so old
//     server-issued profiles and the P1 bootstrap contract keep their
//     behaviour. The step 4 verification harness opts in explicitly
//     on the issued profile, the same way it already sets the stagger
//     range.
//   - STILL stored-only, deliberately not enforced: Steady.DirectionRatio.
//     The provisional 0.5 contradicts the measured browsing mix
//     (laboratory browsing-mode control: down-share ≈ 0.987, up-share
//     ≈ 0.013); enforcing 0.5 would require injecting roughly half the
//     session's bytes as upstream cover traffic — anti-browsing and
//     cost-explosive. A byte ratio is an outcome of the traffic mix
//     plus ACK behaviour, not a per-packet setpoint; step 4 moves it
//     toward browsing with zero cover bytes, via ACK coalescing from
//     burst pacing. A ratio-enforcing controller (cover traffic) is a
//     new mechanism needing a design decision, not something to smuggle
//     into this step. D2 should treat DirectionRatio as a diagnostic
//     target, not an enforcement setpoint, or redefine it.
//   - STILL not wired at datagram level: Steady.LenDist. The quic-go
//     public API offers no PADDING-frame injection (the P1 API gap,
//     unchanged for the steady phase), and padding a datagram's tail
//     corrupts QUIC parsing. Forcing the provisional uniform 200–1400
//     distribution would also move AWAY from the measured browsing
//     shape (downlink ≈ 81% in the 1200–1400 bin), worsening the
//     packet-length JS that currently passes via same-stack
//     packetisation. SampleLen in tail already returns the steady
//     LenDist, so a future stream-chunking layer has a hook; chunking
//     was not wired here because chunked application writes are
//     re-coalesced by the stack under PacketConn pacing, and that
//     interaction needs its own experiment, not an assertion.
//
// P2 step 5 (D2 adjudication, 2026-10-26; evidence: step 3 baseline
// REPORT + step 4 REPORT run2/run4, frozen thresholds, same seed
// 20261026; M3 4/6, still not passed):
//   - PROVISIONAL (values unchanged; no loopback millisecond written
//     as a design value): steady TimingDist uniform 5–100 ms /
//     52.5 ms and all burst numerics (cluster 8–24, GapDist fixed 0
//     interior, IdleDist uniform 50–300 ms, AckLenMax 200);
//     handshake values (8/8, LenDist 200–1200/700, TimingDist
//     5–50/27.5 ms); stagger [50, 150] ms; reuse caps (bootstrap 0 =
//     unset). Loopback Fano-vs-ACK tension (Fano needs cluster
//     >= ~40, ACK needs cluster <= ~24) blocks any loopback-derived
//     final value; timing numerics need a real-network (RTT-scale)
//     baseline.
//   - REDEFINED: steady LenDist is no longer a steady datagram
//     length target — its only live role is the SampleLen hook for a
//     future stream-chunking layer; steady packet length today is
//     same-stack packetisation (JS passes). Steady DirectionRatio is
//     no longer an enforcement setpoint — it is a diagnostic
//     (measured ratio vs the browsing control); the stored 0.5 is
//     schema compat only, never a target, and no cover traffic is
//     generated from it.
//   - FINALIZED (P2 scope): hopping 0/0 (off) — design §7 default
//     closed, M4 untouched, no evidence to open; reopening needs M4
//     evidence plus a coordinator decision. Bootstrap burst default
//     off — verified: custom streams/datagrams unlock only on AUTH
//     success and the client window advances at AUTH, so all Mist
//     steady traffic runs under a window 1+ issued profile; no
//     pre-AUTH Mist steady traffic exists. Flipping the default
//     would require adjudicating the pinned window-0 tail-gap test
//     and is NOT done here.
//   - DROPPED from the D2 table: the 64 KiB maxShapingPad bound —
//     a lab safety bound, not a design number; the code bound itself
//     is unchanged.

// Distribution is one shaping distribution. Units are fixed by the field
// that carries it: lengths in bytes, timings in milliseconds.
// Kind is a provisional enum: "uniform", "normal", "fixed".
// For "fixed", Min must equal Max; for the other kinds Mean must lie
// inside [Min, Max].
type Distribution struct {
	Kind string  `json:"kind"`
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
	Mean float64 `json:"mean"`
}

// Validate checks one distribution. Zero values are rejected unless the
// caller genuinely means a degenerate distribution: Min must be >= 0 and
// Max must be >= Min, so a field that means "unset" must be omitted by
// using a different representation (see Profile: hopping/stagger ranges
// use 0/0 to mean "off", which Validate accepts as the off state).
func (d Distribution) Validate() error {
	switch d.Kind {
	case "uniform", "normal", "fixed":
	default:
		return fmt.Errorf("realquic: distribution kind %q not in {uniform, normal, fixed}", d.Kind)
	}
	if d.Min < 0 || d.Max < d.Min {
		return fmt.Errorf("realquic: distribution range [%v, %v] invalid", d.Min, d.Max)
	}
	if d.Kind == "fixed" {
		if d.Min != d.Max || d.Mean != d.Min {
			return fmt.Errorf("realquic: fixed distribution must have min == max == mean")
		}
		return nil
	}
	if d.Mean < d.Min || d.Mean > d.Max {
		return fmt.Errorf("realquic: distribution mean %v outside [%v, %v]", d.Mean, d.Min, d.Max)
	}
	return nil
}

// ShapingParams is the Q3 parameter set carried inside a profile.
// MergePolicy: "same_flight" (AUTH + H3 init in one flight, Q2.2/Q3)
// or "separate". TailPolicy: "transition_to_steady" (budget exhausted
// -> glide to the steady profile, never send bare) or "hold" (hold the
// last shaping level until the steady profile takes over).
type ShapingParams struct {
	NPacketsUp   int          `json:"n_packets_up"`
	NPacketsDown int          `json:"n_packets_down"`
	LenDist      Distribution `json:"len_dist"`
	TimingDist   Distribution `json:"timing_dist"`
	MergePolicy  string       `json:"merge_policy"`
	TailPolicy   string       `json:"tail_policy"`
}

func (s ShapingParams) Validate() error {
	if s.NPacketsUp < 0 || s.NPacketsDown < 0 {
		return fmt.Errorf("realquic: n_packets must be >= 0 (up=%d down=%d)", s.NPacketsUp, s.NPacketsDown)
	}
	if err := s.LenDist.Validate(); err != nil {
		return fmt.Errorf("realquic: len_dist: %w", err)
	}
	if err := s.TimingDist.Validate(); err != nil {
		return fmt.Errorf("realquic: timing_dist: %w", err)
	}
	switch s.MergePolicy {
	case "same_flight", "separate":
	default:
		return fmt.Errorf("realquic: merge_policy %q not in {same_flight, separate}", s.MergePolicy)
	}
	switch s.TailPolicy {
	case "transition_to_steady", "hold":
	default:
		return fmt.Errorf("realquic: tail_policy %q not in {transition_to_steady, hold}", s.TailPolicy)
	}
	return nil
}

// SteadyBaseline is the Q5 steady-state shaping baseline carried in the
// profile. DirectionRatio is the up/(up+down) byte share, in [0, 1].
// It is stored and validated only: P2 step 4 deliberately does NOT wire
// it as an enforcement setpoint (see the P2 step 4 note in shaping.go),
// and P2 step 5 (D2) REDEFINED it as a diagnostic: the measured ratio
// vs the browsing control, never a target; the stored value is schema
// compat only. LenDist is likewise REDEFINED by D2 step 5: not a steady
// datagram length target, only the SampleLen hook for a future
// stream-chunking layer.
// Burst is the P2 step 4 steady burst-pacing structure: when enabled
// (MaxPackets > 0) the steady slot paces in bursts — GapDist gaps
// inside a burst, IdleDist gaps between bursts — instead of the
// uniform TimingDist pacing. When disabled (MaxPackets == 0, the
// pre-step-4 default that old profiles decode to) the steady slot
// paces exactly as before, from TimingDist alone.
type SteadyBaseline struct {
	LenDist        Distribution `json:"len_dist"`
	TimingDist     Distribution `json:"timing_dist"`
	DirectionRatio float64      `json:"direction_ratio"`
	Burst          SteadyBurst  `json:"burst"`
}

// SteadyBurst is one steady burst-pacing structure. D2 step 5
// (2026-10-26): all values remain PROVISIONAL — the loopback
// Fano-vs-ACK tension (Fano needs cluster >= ~40, ACK needs cluster
// <= ~24) blocks any loopback-derived final value, and timing
// numerics need a real-network (RTT-scale) baseline. The mechanism
// (burst size range + two gap distributions + the small-datagram
// class) is what step 4 fixed, not the numbers.
//
// AckLenMax is the small-datagram class bound in bytes. A tail
// datagram of length <= AckLenMax never takes an inter-burst idle gap
// (see shaping.go): at the PacketConn layer datagrams are opaque
// ciphertext, so ACK-only datagrams cannot be identified — but they
// are small by construction, and delaying them past the peer's PTO
// scale feeds a retransmission loop (delayed ACK -> PTO probe ->
// retransmit -> more ACKs). AckLenMax == 0 disables the class (all
// datagrams take the data-class burst machine, the pre-ACK-class
// behaviour). The 200-byte boundary matches the small-packet proxy
// the step 3 measurement itself uses for ACK accounting.
type SteadyBurst struct {
	MinPackets int          `json:"min_packets"`
	MaxPackets int          `json:"max_packets"`
	GapDist    Distribution `json:"gap_dist"`
	IdleDist   Distribution `json:"idle_dist"`
	AckLenMax  int          `json:"ack_len_max"`
}

func (b SteadyBaseline) Validate() error {
	if err := b.LenDist.Validate(); err != nil {
		return fmt.Errorf("realquic: steady len_dist: %w", err)
	}
	if err := b.TimingDist.Validate(); err != nil {
		return fmt.Errorf("realquic: steady timing_dist: %w", err)
	}
	if b.DirectionRatio < 0 || b.DirectionRatio > 1 {
		return fmt.Errorf("realquic: steady direction_ratio %v outside [0, 1]", b.DirectionRatio)
	}
	if err := b.Burst.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate checks one burst structure. MaxPackets == 0 means burst
// pacing is off: MinPackets must then also be 0, and the gap
// distributions are not validated (a zero-value Distribution has an
// empty Kind, which is not a valid distribution on its own — but an
// off burst must decode cleanly from pre-step-4 profiles that carry
// no burst field at all). When enabled, the packet range must be
// ordered with MinPackets >= 1 and both gap distributions valid.
func (b SteadyBurst) Validate() error {
	if b.MaxPackets == 0 {
		if b.MinPackets != 0 {
			return fmt.Errorf("realquic: steady burst min_packets %d with max_packets 0", b.MinPackets)
		}
		return nil
	}
	if b.MinPackets < 1 || b.MaxPackets < b.MinPackets {
		return fmt.Errorf("realquic: steady burst packet range [%d, %d] invalid", b.MinPackets, b.MaxPackets)
	}
	if err := b.GapDist.Validate(); err != nil {
		return fmt.Errorf("realquic: steady burst gap_dist: %w", err)
	}
	if err := b.IdleDist.Validate(); err != nil {
		return fmt.Errorf("realquic: steady burst idle_dist: %w", err)
	}
	if b.AckLenMax < 0 {
		return fmt.Errorf("realquic: steady burst ack_len_max %d invalid", b.AckLenMax)
	}
	return nil
}

// BurstEnabled reports whether burst pacing applies for this baseline.
func (b SteadyBaseline) BurstEnabled() bool {
	return b.Burst.MaxPackets > 0
}

// Stage B (B2, REALQUIC-DESIGN-v3 §4.3 rule 2): issued-profile burst
// is default-on. DefaultIssuedBurst is the burst structure a server
// issuance fills in when its base profile carries no burst. Its
// numbers are NOT new tuned values: they are the P2 step 4
// verification-harness example, unchanged (see the "Example issued
// burst values" note on BootstrapProfile), and they stay PROVISIONAL
// under D2 step 5 — the mechanism (default-on at issuance) is what
// Stage B fixes, not the numbers. The bootstrap profile is never
// filled by this function: BootstrapProfile keeps burst off
// (FINALIZED, P2 scope), and only the issuance path (newIssuedFrom)
// applies the default.
func DefaultIssuedBurst() SteadyBurst {
	return SteadyBurst{
		MinPackets: 8,
		MaxPackets: 24,
		GapDist:    Distribution{Kind: "fixed", Min: 0, Max: 0, Mean: 0},
		IdleDist:   Distribution{Kind: "uniform", Min: 50, Max: 300, Mean: 175},
		AckLenMax:  200,
	}
}

// SizePolicy is the Stage B (B3, REALQUIC-DESIGN-v3 §3) size-rule
// mechanism record carried in a profile. It records mechanism names
// only — never tuned numbers, never a stack guarantee:
//
//   - PMTUAlignMode: how steady datagram sizes align to the path.
//     The only supported mechanism is the stack-native one
//     ("stack-native-dplpmtud"); "" means unset (pre-Stage-B
//     profiles decode cleanly).
//   - CeilingMode: the operator ceiling's role. The only supported
//     value is "operator-expectation": an expectation the stack
//     does NOT enforce (there is no public ceiling knob; see
//     pmtu.go). "" means no ceiling configured (unbounded).
//   - FallbackMode: what sizes fall back to with no validated PMTU.
//     The only supported value is "initial-size" (the stack's
//     InitialPacketSize, default 1280 UDP payload bytes). Path
//     shrinkage recovery is by migration reset, not by fallback.
//   - ProbePolicy: the probe mechanism. The only supported value
//     is "stack-native": Mist never sends its own probe packets.
//   - TailPadEnabled / TailPadOverheadLimit: the §3.3 tail-padding
//     exception gate. Padding is default-off (Enabled false, limit
//     0). When enabled, the limit is the per-session padded-bytes /
//     data-bytes fraction, and it may not exceed the §3.3 hard cap
//     of 1% (0.01); the padder enforces the same cap at runtime.
type SizePolicy struct {
	PMTUAlignMode        string  `json:"pmtu_align_mode"`
	CeilingMode          string  `json:"ceiling_mode"`
	FallbackMode         string  `json:"fallback_mode"`
	ProbePolicy          string  `json:"probe_policy"`
	TailPadEnabled       bool    `json:"tail_pad_enabled"`
	TailPadOverheadLimit float64 `json:"tail_pad_overhead_limit"`
}

// TailPadOverheadHardCap is the §3.3 per-session padding hard cap
// (padded bytes / downlink data bytes), not a tunable: an operator
// limit above it is rejected at validation.
const TailPadOverheadHardCap = 0.01

func (s SizePolicy) Validate() error {
	switch s.PMTUAlignMode {
	case "", "stack-native-dplpmtud":
	default:
		return fmt.Errorf("realquic: size pmtu_align_mode %q not in {\"\", stack-native-dplpmtud}", s.PMTUAlignMode)
	}
	switch s.CeilingMode {
	case "", "operator-expectation":
	default:
		return fmt.Errorf("realquic: size ceiling_mode %q not in {\"\", operator-expectation}", s.CeilingMode)
	}
	switch s.FallbackMode {
	case "", "initial-size":
	default:
		return fmt.Errorf("realquic: size fallback_mode %q not in {\"\", initial-size}", s.FallbackMode)
	}
	switch s.ProbePolicy {
	case "", "stack-native":
	default:
		return fmt.Errorf("realquic: size probe_policy %q not in {\"\", stack-native}", s.ProbePolicy)
	}
	if s.TailPadEnabled {
		if s.TailPadOverheadLimit <= 0 || s.TailPadOverheadLimit > TailPadOverheadHardCap {
			return fmt.Errorf("realquic: size tail_pad_overhead_limit %v invalid (enabled requires (0, %v])", s.TailPadOverheadLimit, TailPadOverheadHardCap)
		}
	} else if s.TailPadOverheadLimit != 0 {
		return fmt.Errorf("realquic: size tail_pad_overhead_limit %v set while tail padding is disabled", s.TailPadOverheadLimit)
	}
	return nil
}

// Profile is one Q6 server-issued behaviour profile. Version 0 is
// reserved for the bootstrap profile only; every server-issued profile
// has Version >= 1 (the server assigns versions, see newIssuedFrom).
// IssuedAt is Unix seconds; 0 means "unset" and is accepted (the
// bootstrap profile carries 0; issued profiles always carry a time).
type Profile struct {
	Version  uint64        `json:"version"`
	IssuedAt int64         `json:"issued_at"`
	Shaping  ShapingParams `json:"shaping"`
	// Carried but NOT executed in P1 (see the file header): validated
	// and stored, never applied to traffic by this step.
	HopWindowMinSec    float64        `json:"hop_window_min_sec"`
	HopWindowMaxSec    float64        `json:"hop_window_max_sec"`
	MaxStreamsPerConn  int            `json:"max_streams_per_conn"`
	MaxReusePerConn    int            `json:"max_reuse_per_conn"`
	MaxConnLifetimeSec int64          `json:"max_conn_lifetime_sec"`
	StaggerDelayMinMs  float64        `json:"stagger_delay_min_ms"`
	StaggerDelayMaxMs  float64        `json:"stagger_delay_max_ms"`
	Steady             SteadyBaseline `json:"steady"`
	// Stage B (B3): size-rule mechanism record (names only, see
	// SizePolicy). Zero value decodes from pre-Stage-B profiles.
	Size SizePolicy `json:"size"`
}

// Validate checks the whole profile structurally. It does not check
// version authority (bootstrap 0 vs issued >= 1): that is enforced by
// the issuer (newIssuedFrom) and by the client's version gate, not by
// the wire format.
func (p Profile) Validate() error {
	if p.IssuedAt < 0 {
		return errors.New("realquic: issued_at must be >= 0")
	}
	if err := p.Shaping.Validate(); err != nil {
		return err
	}
	if err := p.Steady.Validate(); err != nil {
		return err
	}
	// Hop window: 0/0 means hopping off (the P1 default). Any other
	// value must be a non-negative ordered range.
	if p.HopWindowMinSec < 0 || p.HopWindowMaxSec < p.HopWindowMinSec {
		return fmt.Errorf("realquic: hop window [%v, %v] invalid", p.HopWindowMinSec, p.HopWindowMaxSec)
	}
	if p.MaxStreamsPerConn < 0 || p.MaxReusePerConn < 0 || p.MaxConnLifetimeSec < 0 {
		return fmt.Errorf("realquic: reuse caps must be >= 0 (streams=%d reuse=%d lifetime=%d)",
			p.MaxStreamsPerConn, p.MaxReusePerConn, p.MaxConnLifetimeSec)
	}
	if p.StaggerDelayMinMs < 0 || p.StaggerDelayMaxMs < p.StaggerDelayMinMs {
		return fmt.Errorf("realquic: stagger delay [%v, %v] invalid", p.StaggerDelayMinMs, p.StaggerDelayMaxMs)
	}
	if err := p.Size.Validate(); err != nil {
		return err
	}
	return nil
}

// BootstrapProfile is the profile a client uses for its first connection
// to a server it has never received a profile from. EVERY numeric value
// below is PROVISIONAL — a placeholder that lets the mechanism run, not
// a tuned value. D2 final values are set by the P2 baseline measurement;
// until then no value here may be presented as measured or optimal.
// Hopping is off (0/0 window) and stagger/reuse caps are unset (0),
// matching the design §7 P1 defaults; the fields are present so the
// schema, storage and validation paths are exercised end to end.
func BootstrapProfile() Profile {
	return Profile{
		Version:  0, // bootstrap only; server-issued versions start at 1
		IssuedAt: 0,
		Shaping: ShapingParams{
			NPacketsUp:   8,                                                             // D2 step 5: PROVISIONAL (handshake not in step 3/4 main verdicts)
			NPacketsDown: 8,                                                             // D2 step 5: PROVISIONAL
			LenDist:      Distribution{Kind: "uniform", Min: 200, Max: 1200, Mean: 700}, // D2 step 5: PROVISIONAL
			TimingDist:   Distribution{Kind: "uniform", Min: 5, Max: 50, Mean: 27.5},    // D2 step 5: PROVISIONAL, ms
			MergePolicy:  "same_flight",
			TailPolicy:   "transition_to_steady",
		},
		HopWindowMinSec:    0, // hopping off (D2 step 5: FINALIZED, P2 scope; reopening needs M4 evidence + coordinator decision)
		HopWindowMaxSec:    0,
		MaxStreamsPerConn:  0, // unset (D2 step 5: PROVISIONAL — interval-random values, no fixed constant to finalize)
		MaxReusePerConn:    0, // unset (D2 step 5: PROVISIONAL)
		MaxConnLifetimeSec: 0, // unset (D2 step 5: PROVISIONAL)
		StaggerDelayMinMs:  0, // bootstrap unset; issued [50, 150] ms is D2 step 5: PROVISIONAL (D3 bound, needs real-network baseline)
		StaggerDelayMaxMs:  0,
		Steady: SteadyBaseline{
			LenDist:        Distribution{Kind: "uniform", Min: 200, Max: 1400, Mean: 800}, // D2 step 5: REDEFINED role (future chunk-layer hook only), value unfinalized
			TimingDist:     Distribution{Kind: "uniform", Min: 5, Max: 100, Mean: 52.5},   // D2 step 5: PROVISIONAL, ms
			DirectionRatio: 0.5,                                                           // D2 step 5: REDEFINED as diagnostic only; stored value is schema compat, never a target
			// Burst is OFF in the bootstrap profile (zero value), by
			// design, not by omission: the bootstrap tail's uniform
			// pacing is the P1 contract pinned by existing tests
			// (window-0 tail gaps floor at the steady TimingDist
			// minimum), and burst interiors necessarily go below that
			// floor. Burst pacing is opt-in via a server-issued
			// profile: every authenticated session adopts the issued
			// profile at AUTH (window 1), so all steady traffic runs
			// under it; only pre-AUTH window-0 tail (handshake
			// overshoot, a few datagrams) keeps uniform pacing.
			// Flipping the bootstrap default on is a D2/operator
			// decision, not something this step smuggles in — it
			// would require adjudicating the pinned window-0 test.
			// D2 step 5 (2026-10-26) FINALIZED (P2 scope): the
			// default stays off — verified against this tree, no
			// pre-AUTH Mist steady traffic exists (custom streams /
			// datagrams unlock only on AUTH success; the client
			// window advances at AUTH, so all Mist steady traffic
			// runs under a window 1+ issued profile where burst
			// opt-in applies). The window-0 tail-gap test assertion
			// is untouched.
			// Example issued burst values (provisional, used by the
			// step 4 verification harness, NOT defaults): bursts of
			// 8–24 datagrams, line-speed interiors (GapDist fixed 0),
			// idle gaps uniform 50–300 ms (mean 175 ms).
		},
	}
}

// newIssuedFrom stamps an operator-supplied (or bootstrap) base profile
// as a server-issued profile: the server is the version authority, so
// the input version is ignored and the issued version starts at 1.
// RotateProfile advances from there.
//
// Stage B (B2): issuance is burst default-on. A base profile without
// burst parameters (including the bootstrap base) is issued WITH the
// default burst filled in, so a server can no longer issue a
// burst-less window 1+ profile by omission — the labserver-style
// "Key + rotation only, no opt-in" deployment shape that caused the
// old-stack thin flow is a configuration error at the client
// self-check, not a runnable steady state. A base profile that
// already carries burst parameters is issued unchanged: issuance
// fills a missing burst, it never overwrites an operator's burst.
func newIssuedFrom(base Profile) Profile {
	p := base
	p.Version = 1
	p.IssuedAt = time.Now().Unix()
	if !p.Steady.BurstEnabled() {
		p.Steady.Burst = DefaultIssuedBurst()
	}
	return p
}

// EncodeProfile validates then marshals a profile for the wire. The
// AUTH body and the push frame both use this encoding (JSON, the same
// encoding the AUTH body already uses).
func EncodeProfile(p Profile) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// DecodeProfile unmarshals and validates a received profile. A profile
// that fails validation is never applied: the caller keeps its previous
// profile (see Client.applyProfile / adoptProfile).
func DecodeProfile(b []byte) (Profile, error) {
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return Profile{}, err
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// ProfileStore is per-server client-side profile storage. The key is the
// server identity (lab: the test server name; production: the server's
// configured domain identity) — never key material, never a session id.
// A profile is stored only if it is valid and strictly newer than the
// stored one, so a stale or replayed profile can never roll a client
// back to older behaviour.
type ProfileStore struct {
	mu       sync.Mutex
	byServer map[string]Profile
}

// NewProfileStore returns an empty store.
func NewProfileStore() *ProfileStore {
	return &ProfileStore{byServer: map[string]Profile{}}
}

// Get returns the stored profile for serverID, if any.
func (s *ProfileStore) Get(serverID string) (Profile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byServer[serverID]
	return p, ok
}

// Put stores p for serverID if p is valid and strictly newer than the
// stored profile (or if nothing is stored yet). It reports whether the
// store changed. A rejected Put changes nothing.
func (s *ProfileStore) Put(serverID string, p Profile) bool {
	if err := p.Validate(); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.byServer[serverID]; ok && p.Version <= cur.Version {
		return false
	}
	s.byServer[serverID] = p
	return true
}

// ActiveFor returns the stored profile for serverID, or the bootstrap
// profile when the server has never issued one to this store. This is
// the "first connection uses bootstrap, later sessions use the server
// profile" rule (design Q6) in one place.
func (s *ProfileStore) ActiveFor(serverID string) Profile {
	if p, ok := s.Get(serverID); ok {
		return p
	}
	return BootstrapProfile()
}

// profileReceipt is the client's acknowledgement of an issued profile,
// carried on a subsequent control message (a dedicated custom stream,
// frameProfileReceipt, sealed under the session codec). The server
// compares Version against the versions issued to this connection; a
// version never issued downgrades the connection to an ordinary HTTP/3
// visitor (see connState.noteReceipt). ServerID echoes the client's server identity
// for future multi-tenant checks; this step's server keys the state by
// connection and does not re-derive identity from the receipt.
type profileReceipt struct {
	Version  uint64 `json:"version"`
	ServerID string `json:"server_id"`
}

func encodeProfileReceipt(r profileReceipt) ([]byte, error) {
	return json.Marshal(r)
}

func decodeProfileReceipt(b []byte) (profileReceipt, error) {
	var r profileReceipt
	if err := json.Unmarshal(b, &r); err != nil {
		return profileReceipt{}, err
	}
	return r, nil
}

// nextRotationDelay picks the next profile rotation delay uniformly at
// random inside [min, max], using crypto/rand. The interval is operator
// deployment configuration (ServerConfig.RotationMin/Max); the picked
// delay is never a protocol constant and is never written into a
// profile. It reports false when rotation is not configured (min <= 0
// or max < min): an unconfigured server does not rotate.
func nextRotationDelay(min, max time.Duration) (time.Duration, bool) {
	if min <= 0 || max < min {
		return 0, false
	}
	if min == max {
		return min, true
	}
	span := int64(max - min)
	n, err := rand.Int(rand.Reader, big.NewInt(span+1))
	if err != nil {
		return 0, false
	}
	return min + time.Duration(n.Int64()), true
}
