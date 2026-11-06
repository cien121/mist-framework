package realquic

import (
	"errors"
	"fmt"
	"sync"
)

// True-QUIC round (design §3, Q10): stack pin and borrowed-identity
// registry. The stack is quic-go, pinned, not forked, not swapped for
// another candidate. Every implementation and validation report for
// this round must name the quic-go version: QuicGoVersion.
//
// The pin is enforced by a test (truequic_test.go reads mist/go.mod
// and requires the exact require line), not by this constant alone:
// a constant can drift from the module file, a test against go.mod
// cannot drift silently.

// QuicGoVersion is the pinned quic-go release for the true-QUIC
// round. The stack hard ceiling that follows from it is a single UDP
// payload of at most 1452 bytes (IPv4 IP length 1480, IPv6 1500);
// see pmtu.go StackMaxUDPPayload.
const QuicGoVersion = "v0.64.1"

// StackVersion reports the pinned quic-go version.
func StackVersion() string { return QuicGoVersion }

// ParrotTarget is one borrowed handshake parameter set: the identity
// (browser name and version) whose handshake parameters a parrot
// implementation copies. Version is mandatory and must track the
// parrot target's real releases: a parrot pinned to an old version
// while its parameters have rotated is a split state, and the design
// (§5, Q16) forbids parameters rotating while the parrot stays pinned
// to the old version. Retirement is an explicit operator action;
// there is no numeric threshold for it in this code, because the
// design leaves parrot follow-up cadence (U19) undecided.
//
// Current wiring, stated honestly: the QUIC leg uses Go's standard
// library TLS and no parrot; the TCP leg uses utls HelloChrome_Auto,
// which is a parrot of Chrome. This registry is the tracking
// mechanism for any borrowed parameter set: a borrowed set must be
// registered here, selected through Select, and retired through
// Retire when its target version is superseded. An unregistered or
// retired target must never be selected.
type ParrotTarget struct {
	// ID names the borrowed identity, e.g. "chrome".
	ID string
	// Version is the target's release the parameters were copied
	// from, e.g. "140". Empty means unknown, and unknown is refused.
	Version string
	// Retired marks a target whose version has been superseded.
	// Select refuses retired targets.
	Retired bool
	// SupersededBy names the ParrotTarget ID that replaces a retired
	// target, when one is known. Empty means unknown, not "none".
	SupersededBy string
}

// ParrotRegistry tracks borrowed handshake identities. The zero value
// is unusable: use NewParrotRegistry.
type ParrotRegistry struct {
	mu      sync.Mutex
	targets map[string]ParrotTarget
}

// NewParrotRegistry returns an empty registry.
func NewParrotRegistry() *ParrotRegistry {
	return &ParrotRegistry{targets: map[string]ParrotTarget{}}
}

// Register records a borrowed identity. It refuses an empty ID, an
// empty version, and a duplicate ID: re-registering the same ID with
// different parameters would silently change what Select returns, so
// a parameter change must go through Retire + Register of the new
// target instead.
func (r *ParrotRegistry) Register(t ParrotTarget) error {
	if t.ID == "" {
		return errors.New("realquic: parrot target ID must not be empty")
	}
	if t.Version == "" {
		return errors.New("realquic: parrot target version must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.targets[t.ID]; ok {
		return fmt.Errorf("realquic: parrot target %q already registered", t.ID)
	}
	r.targets[t.ID] = t
	return nil
}

// Retire marks the target retired, recording its replacement when
// known. Retiring an unknown ID is an error: it would otherwise
// silently create a retired entry that was never a live target.
func (r *ParrotRegistry) Retire(id, supersededBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.targets[id]
	if !ok {
		return fmt.Errorf("realquic: cannot retire unknown parrot target %q", id)
	}
	t.Retired = true
	t.SupersededBy = supersededBy
	r.targets[id] = t
	return nil
}

// Select returns the target for use, or an error when it is unknown,
// retired, or versionless. A caller that gets an error must not fall
// back to a retired target: the fallback is to refuse the borrowed
// identity, not to use the stale one.
func (r *ParrotRegistry) Select(id string) (ParrotTarget, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.targets[id]
	if !ok {
		return ParrotTarget{}, fmt.Errorf("realquic: unknown parrot target %q", id)
	}
	if t.Retired {
		return ParrotTarget{}, fmt.Errorf("realquic: parrot target %q is retired", id)
	}
	if t.Version == "" {
		return ParrotTarget{}, fmt.Errorf("realquic: parrot target %q has no version", id)
	}
	return t, nil
}
