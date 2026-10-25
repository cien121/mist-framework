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
type SteadyBaseline struct {
	LenDist        Distribution `json:"len_dist"`
	TimingDist     Distribution `json:"timing_dist"`
	DirectionRatio float64      `json:"direction_ratio"`
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
			NPacketsUp:   8,                                                             // provisional
			NPacketsDown: 8,                                                             // provisional
			LenDist:      Distribution{Kind: "uniform", Min: 200, Max: 1200, Mean: 700}, // provisional
			TimingDist:   Distribution{Kind: "uniform", Min: 5, Max: 50, Mean: 27.5},    // provisional, ms
			MergePolicy:  "same_flight",
			TailPolicy:   "transition_to_steady",
		},
		HopWindowMinSec:    0, // hopping off in P1
		HopWindowMaxSec:    0,
		MaxStreamsPerConn:  0, // unset in P1 (split is P2)
		MaxReusePerConn:    0, // unset in P1
		MaxConnLifetimeSec: 0, // unset in P1
		StaggerDelayMinMs:  0, // carried, not executed in P1 (split is P2)
		StaggerDelayMaxMs:  0,
		Steady: SteadyBaseline{
			LenDist:        Distribution{Kind: "uniform", Min: 200, Max: 1400, Mean: 800}, // provisional
			TimingDist:     Distribution{Kind: "uniform", Min: 5, Max: 100, Mean: 52.5},   // provisional, ms
			DirectionRatio: 0.5,                                                           // provisional
		},
	}
}

// newIssuedFrom stamps an operator-supplied (or bootstrap) base profile
// as a server-issued profile: the server is the version authority, so
// the input version is ignored and the issued version starts at 1.
// RotateProfile advances from there.
func newIssuedFrom(base Profile) Profile {
	p := base
	p.Version = 1
	p.IssuedAt = time.Now().Unix()
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
