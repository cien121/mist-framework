package realquic

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"sync"
	"time"

	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Step-5 session keys (REALQUIC-DESIGN.md Q2.2, SPEC §6.4 shape).
//
// After a successful AUTH, both sides hold the client's ephemeral public
// key (from the AUTH token) and the server's ephemeral public key (from
// the AUTH success body). Each side computes the same X25519 shared
// secret from its own ephemeral private key and the peer's public key,
// then derives two direction keys with HKDF-SHA256:
//
//	salt = client_eph_pub || server_eph_pub (32 + 32 bytes)
//	okm  = HKDF-SHA256(salt, ikm=shared, info="mist-realquic/session-v1", L=64)
//	k_c2s = okm[0:32], k_s2c = okm[32:64]
//
// The info string is deliberately distinct from the SPEC v0.2 TCP info
// ("mist-v0.1/session"): the two legs must never share key material even
// if the same ephemeral pair were reused across legs. The keys are
// independent of TLS: no TLS exporter is used (design D5, optional).
// There is no key rotation in this step (the design does not ask for
// one); a fresh AUTH derives fresh keys, and re-AUTH on a connection
// rekeys it (in-flight streams sealed under the old key then fail
// AEAD and terminate, fail-closed).

const sessionHKDFInfo = "mist-realquic/session-v1"

// deriveShared computes the X25519 shared secret from one side's
// ephemeral private key and the peer's ephemeral public key.
func deriveShared(ownPriv, peerPub [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(ownPriv[:], peerPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	if len(shared) != 32 {
		return [32]byte{}, errors.New("realquic: X25519 shared secret has wrong length")
	}
	var out [32]byte
	copy(out[:], shared)
	return out, nil
}

// deriveDirectionKeys splits the shared secret into the two direction
// keys. clientPub/serverPub order is fixed (client first), so both sides
// derive identical keys regardless of which side they are.
func deriveDirectionKeys(shared, clientPub, serverPub [32]byte) (c2s, s2c [32]byte, err error) {
	salt := make([]byte, 0, 64)
	salt = append(salt, clientPub[:]...)
	salt = append(salt, serverPub[:]...)
	r := hkdf.New(sha256.New, shared[:], salt, []byte(sessionHKDFInfo))
	okm := make([]byte, 64)
	if _, err := io.ReadFull(r, okm); err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	copy(c2s[:], okm[:32])
	copy(s2c[:], okm[32:])
	return c2s, s2c, nil
}

// SessionCodec is the step-5 PayloadCodec: frame (and datagram) payloads
// are sealed with XChaCha20-Poly1305 under the direction keys (SPEC §6.4
// AEAD choice). The wire form of a sealed payload is:
//
//	[nonce(24, random)][ciphertext][tag(16)]
//
// XChaCha20-Poly1305 takes a 24-byte nonce. A random nonce per payload
// is deliberate: it needs no counter state shared between the peers,
// so it stays correct on unordered QUIC datagrams as well as on
// ordered streams, and a nonce can never repeat for a given key in
// practice (2^192 space). Cost is 24 + 16 = 40 bytes per payload,
// inside the uint16 frame LEN (DATA chunks are 32 KiB, so the sealed
// form always fits).
type SessionCodec struct {
	sealKey [32]byte
	openKey [32]byte
}

// clientSessionCodec seals c2s and opens s2c; serverSessionCodec is the
// mirror. The two directions use different keys, so a payload sealed in
// one direction can never be opened as if it were the other direction.
func clientSessionCodec(c2s, s2c [32]byte) SessionCodec {
	return SessionCodec{sealKey: c2s, openKey: s2c}
}

func serverSessionCodec(c2s, s2c [32]byte) SessionCodec {
	return SessionCodec{sealKey: s2c, openKey: c2s}
}

func (c SessionCodec) Seal(p []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.sealKey[:])
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 24+len(p)+aead.Overhead())
	out = append(out, nonce[:]...)
	return aead.Seal(out, nonce[:], p, nil), nil
}

func (c SessionCodec) Open(p []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.openKey[:])
	if err != nil {
		return nil, err
	}
	if len(p) < 24+aead.Overhead() {
		return nil, errors.New("realquic: sealed payload too short")
	}
	return aead.Open(nil, p[:24], p[24:], nil)
}

// sessionParams is what a client keeps after AUTH: the direction keys
// plus the resume identity for the TCP leg (see tcp.go). The resume
// token is never sent in the clear: on the TCP leg it travels sealed
// under the c2s key, and the server compares it in constant time.
type sessionParams struct {
	id          [16]byte
	resumeToken [32]byte
	c2s         [32]byte
	s2c         [32]byte
	hasResume   bool
}

func (p *sessionParams) clientCodec() SessionCodec {
	return clientSessionCodec(p.c2s, p.s2c)
}

func (p *sessionParams) serverCodec() SessionCodec {
	return serverSessionCodec(p.c2s, p.s2c)
}

// sessionRecord is the server side of sessionParams, kept in a
// server-level table (not per-connection) so a session established on
// the QUIC leg can be resumed on the TCP leg and vice versa.
type sessionRecord struct {
	id          [16]byte
	resumeToken [32]byte
	c2s         [32]byte
	s2c         [32]byte
}

func (r *sessionRecord) serverCodec() SessionCodec {
	return serverSessionCodec(r.c2s, r.s2c)
}

type sessionTable struct {
	mu   sync.Mutex
	byID map[[16]byte]*sessionRecord
}

func newSessionTable() *sessionTable {
	return &sessionTable{byID: map[[16]byte]*sessionRecord{}}
}

// newRecord creates a record with fresh random id and resume token.
// Records do not expire in this lab step; a production server must add
// a TTL and a size cap (open item, see doc.go).
func (t *sessionTable) newRecord(c2s, s2c [32]byte) (*sessionRecord, error) {
	rec := &sessionRecord{c2s: c2s, s2c: s2c}
	if _, err := rand.Read(rec.id[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(rec.resumeToken[:]); err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.byID[rec.id] = rec
	t.mu.Unlock()
	return rec, nil
}

// resume looks a session up by id and checks the token in constant time.
// A wrong id, a wrong token, or a missing record all fail identically.
func (t *sessionTable) resume(id [16]byte, token [32]byte) (*sessionRecord, bool) {
	t.mu.Lock()
	rec := t.byID[id]
	t.mu.Unlock()
	if rec == nil {
		return nil, false
	}
	if subtle.ConstantTimeCompare(rec.resumeToken[:], token[:]) != 1 {
		return nil, false
	}
	return rec, true
}

// freshTokenForKey builds a one-use AUTH token plus the ephemeral
// keypair behind it. The caller keeps the private key: it is needed to
// derive the session keys once the server's ephemeral public key comes
// back in the AUTH success body.
func freshTokenForKey(key []byte) (token string, priv, pub [32]byte, err error) {
	var nonce16 [16]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", priv, pub, err
	}
	if _, err := rand.Read(nonce16[:]); err != nil {
		return "", priv, pub, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return MakeToken(key, pub, time.Now(), nonce16), priv, pub, nil
}
