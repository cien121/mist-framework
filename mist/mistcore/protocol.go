// Package mistcore implements the Mist (雾) protocol v0.1 wire format.
//
// Source of truth: ~/workspace/mist-protocol/SPEC.md.
// Two iron rules: (1) silent on probe (never return feature errors),
// (2) a (key, nonce) pair is never reused.
//
// AEAD note (coordinator decision, binds all implementations):
// the spec mandates XChaCha20-Poly1305 while defining a 12-byte nonce
// (epoch|dir|counter). XChaCha20 needs 24-byte nonces, so every AEAD call
// uses nonce24 = 0x00*12 || nonce12 with chacha20poly1305.NewX.
package mistcore

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	Version byte = 0x01

	// Frame limits (SPEC 7.1, B.1).
	MaxFrameLen = 16384 // LEN field max: bytes after the LEN field itself
	MaxLineLen  = 16386 // max on-wire frame size

	// Stream id space (SPEC 9.1).
	SidControl = 0
	SidMax     = 15

	// Flags: high nibble of the SID/F byte (SPEC 7.1).
	FlagSYN = 0x80
	FlagFIN = 0x40
	FlagRST = 0x20

	// Nonce direction words (SPEC 7.2).
	DirC2S uint32 = 0x00000000
	DirS2C uint32 = 0xFFFFFFFF

	// Control-stream message types (SPEC 9.6).
	MsgConnectReq   = 0x01
	MsgConnectResp  = 0x02
	MsgUDPAssocReq  = 0x03
	MsgWindowUpdate = 0x04
	MsgPing         = 0x05
	MsgPong         = 0x06
	MsgResume       = 0x07
	MsgResumeOK     = 0x08
	MsgCloseSession = 0x09

	// CONNECT address types (SPEC 9.2).
	ATypIPv4   = 0x01
	ATypDomain = 0x03
	ATypIPv6   = 0x04

	// AUTH wire sizes.
	AuthWireLen   = 89  // 16 + 12 + (45 + 16)
	AuthOKWireLen = 124 // 12 + (96 + 16)

	aeadTagLen = 16
)

// Defaults (SPEC appendix B.2).
const (
	DefaultHeartbeatSec      = 30
	DefaultShapingHeavyPkts  = 32
	DefaultShapingPadMin     = 64
	DefaultShapingPadMax     = 512
	DefaultShapingJitterMs   = 15
	DefaultShapingTailPad    = 0
	DefaultMaxStreams        = 16
	DefaultInitWindow        = 32 * 1024 * 1024
	DefaultWindowUpdateEvery = 1024 * 1024
	DefaultAuthWindowSec     = 60
	DefaultNonceCacheTTL     = 120 // seconds
)

var (
	ErrFrameTooBig   = errors.New("mist: frame too big")
	ErrFrameTooSmall = errors.New("mist: frame too small")
	ErrAEADFailed    = errors.New("mist: aead open failed")
	ErrBadAuth       = errors.New("mist: bad auth")
	ErrReplayed      = errors.New("mist: replayed nonce")
	ErrStaleTS       = errors.New("mist: timestamp outside window")
	ErrUnknownCID    = errors.New("mist: unknown client id")
)

// ---------------------------------------------------------------------------
// AEAD (XChaCha20-Poly1305, 24-byte nonce = 12 zero bytes || 12-byte nonce)
// ---------------------------------------------------------------------------

func newAEAD(key *[32]byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key[:])
}

// expandNonce converts the 12-byte (epoch|dir|counter) nonce to the 24-byte
// nonce XChaCha20 requires.
func expandNonce(nonce12 []byte) []byte {
	n := make([]byte, 24)
	copy(n[12:], nonce12)
	return n
}

// BuildNonce assembles the 12-byte nonce: epoch(4,BE) | dir(4) | ctr(4,BE).
func BuildNonce(epoch, dir, ctr uint32) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[0:4], epoch)
	binary.BigEndian.PutUint32(n[4:8], dir)
	binary.BigEndian.PutUint32(n[8:12], ctr)
	return n
}

func seal(key *[32]byte, nonce12, plaintext, aad []byte) ([]byte, error) {
	a, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, expandNonce(nonce12), plaintext, aad), nil
}

func open(key *[32]byte, nonce12, ciphertext, aad []byte) ([]byte, error) {
	a, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, expandNonce(nonce12), ciphertext, aad)
	if err != nil {
		return nil, ErrAEADFailed
	}
	return pt, nil
}

// RandomBytes returns n CSPRNG bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// Zeroize clears key material.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------------------
// Frame codec (SPEC 7)
// ---------------------------------------------------------------------------

// EncodeFrame builds one on-wire frame.
// Layout: [LEN(2,BE)][PLEN(1)][SID/F(1)][ENC_PAYLOAD][PADDING(PLEN)]
// LEN = 2 + len(ENC_PAYLOAD) + padLen, i.e. everything after the LEN field.
// aad is the 4-byte header. padLen bytes of random padding are appended.
func EncodeFrame(sidFlags byte, plaintext []byte, padLen int, key *[32]byte, epoch, dir, ctr uint32) ([]byte, error) {
	if padLen < 0 || padLen > 255 {
		// PLEN is a single byte (SPEC 7.1); the appendix B range
		// "64-1400" for shaping_pad_max is clamped to 255 here.
		return nil, errors.New("mist: bad padLen")
	}
	encLen := len(plaintext) + aeadTagLen
	total := 2 + encLen + padLen
	if total > MaxFrameLen || total < 2 {
		return nil, ErrFrameTooBig
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], uint16(total))
	header[2] = byte(padLen)
	header[3] = sidFlags
	enc, err := seal(key, BuildNonce(epoch, dir, ctr), plaintext, header)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+len(enc)+padLen)
	out = append(out, header...)
	out = append(out, enc...)
	if padLen > 0 {
		out = append(out, RandomBytes(padLen)...)
	}
	return out, nil
}

// DecodedFrame is the result of DecodeFrame.
type DecodedFrame struct {
	SidFlags byte
	Payload  []byte // decrypted
}

// DecodeFrame parses one full frame from buf (which must hold exactly one
// frame: 2 + LEN bytes). ctr is the expected counter for this direction;
// it is NOT incremented here.
func DecodeFrame(buf []byte, key *[32]byte, epoch, dir, ctr uint32) (*DecodedFrame, error) {
	if len(buf) < 2 {
		return nil, ErrFrameTooSmall
	}
	ln := int(binary.BigEndian.Uint16(buf[0:2]))
	if ln < 2 || ln > MaxFrameLen {
		return nil, ErrFrameTooBig
	}
	if len(buf) < 2+ln {
		return nil, ErrFrameTooSmall
	}
	header := buf[0:4]
	padLen := int(buf[2])
	sidFlags := buf[3]
	encLen := ln - 2 - padLen
	if encLen < aeadTagLen {
		return nil, ErrFrameTooSmall
	}
	enc := buf[4 : 4+encLen]
	pt, err := open(key, BuildNonce(epoch, dir, ctr), enc, header)
	if err != nil {
		return nil, err
	}
	return &DecodedFrame{SidFlags: sidFlags, Payload: pt}, nil
}

// FrameWireLen returns the total on-wire bytes (2 + LEN) for a frame whose
// first two bytes are available. Returns 0 if fewer than 2 bytes.
func FrameWireLen(first2 []byte) int {
	if len(first2) < 2 {
		return 0
	}
	return 2 + int(binary.BigEndian.Uint16(first2))
}

// ---------------------------------------------------------------------------
// Handshake: AUTH / AUTH_OK (SPEC 6)
// ---------------------------------------------------------------------------

// BuildAUTH constructs the 89-byte AUTH message.
// Returns wire bytes and the client's ephemeral public key.
func BuildAUTH(cid [16]byte, kAuth *[32]byte, feat byte, now time.Time) (wire []byte, ephPub [32]byte, ephPriv [32]byte, err error) {
	priv := RandomBytes(32)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, ephPub, ephPriv, err
	}
	copy(ephPriv[:], priv)
	copy(ephPub[:], pub)
	Zeroize(priv)

	plain := make([]byte, 45)
	plain[0] = Version
	binary.BigEndian.PutUint64(plain[1:9], uint64(now.Unix()))
	copy(plain[9:41], ephPub[:])
	plain[41] = feat
	// plain[42:45] RSVD = 0

	nonce := RandomBytes(12)
	ct, err := seal(kAuth, nonce, plain, cid[:])
	if err != nil {
		return nil, ephPub, ephPriv, err
	}
	wire = make([]byte, 0, AuthWireLen)
	wire = append(wire, cid[:]...)
	wire = append(wire, nonce...)
	wire = append(wire, ct...)
	return wire, ephPub, ephPriv, nil
}

// AuthResult is a successfully validated AUTH.
type AuthResult struct {
	CID    [16]byte
	EphPub [32]byte
	TS     int64
	Feat   byte
}

// ParseAUTH validates an 89-byte AUTH message (server side, SPEC 6.2 six steps).
// lookup resolves CID -> K_auth. On ANY failure it returns an error and the
// caller must switch the connection to guest mode (never signal the reason).
func ParseAUTH(wire []byte, lookup func(cid [16]byte) (kAuth *[32]byte, ok bool), now time.Time, windowSec int64, cache *NonceCache) (*AuthResult, error) {
	if len(wire) != AuthWireLen {
		return nil, ErrBadAuth
	}
	var cid [16]byte
	copy(cid[:], wire[0:16])
	nonce := wire[16:28]
	ct := wire[28:]

	kAuth, ok := lookup(cid)
	if !ok {
		return nil, ErrUnknownCID
	}
	pt, err := open(kAuth, nonce, ct, cid[:])
	if err != nil || len(pt) != 45 {
		return nil, ErrBadAuth
	}
	if pt[0] != Version {
		return nil, ErrBadAuth
	}
	ts := int64(binary.BigEndian.Uint64(pt[1:9]))
	if abs64(now.Unix()-ts) > windowSec {
		return nil, ErrStaleTS
	}
	var n12 [12]byte
	copy(n12[:], nonce)
	if cache.Seen(n12) {
		return nil, ErrReplayed
	}
	res := &AuthResult{CID: cid, TS: ts, Feat: pt[41]}
	copy(res.EphPub[:], pt[9:41])
	return res, nil
}

// BuildAuthOK constructs the 124-byte AUTH_OK message (server side).
func BuildAuthOK(kAuth *[32]byte, srvEphPub [32]byte, connID [16]byte, resumeTok [32]byte, maxStreams byte, hbSec uint16, now time.Time) ([]byte, error) {
	plain := make([]byte, 96)
	copy(plain[0:32], srvEphPub[:])
	copy(plain[32:48], connID[:])
	copy(plain[48:80], resumeTok[:])
	binary.BigEndian.PutUint64(plain[80:88], uint64(now.Unix()))
	plain[88] = maxStreams
	binary.BigEndian.PutUint16(plain[89:91], hbSec)
	// plain[91:96] RSVD = 0

	nonce := RandomBytes(12)
	ct, err := seal(kAuth, nonce, plain, []byte("mist-v0.1-auth-ok"))
	if err != nil {
		return nil, err
	}
	wire := make([]byte, 0, AuthOKWireLen)
	wire = append(wire, nonce...)
	wire = append(wire, ct...)
	return wire, nil
}

// AuthOKResult is a validated AUTH_OK.
type AuthOKResult struct {
	SrvEphPub  [32]byte
	ConnID     [16]byte
	ResumeTok  [32]byte
	SrvTS      int64
	MaxStreams byte
	HBSec      uint16
}

// ParseAuthOK validates a 124-byte AUTH_OK message (client side).
func ParseAuthOK(wire []byte, kAuth *[32]byte) (*AuthOKResult, error) {
	if len(wire) != AuthOKWireLen {
		return nil, ErrBadAuth
	}
	nonce, ct := wire[0:12], wire[12:]
	pt, err := open(kAuth, nonce, ct, []byte("mist-v0.1-auth-ok"))
	if err != nil || len(pt) != 96 {
		return nil, ErrBadAuth
	}
	res := &AuthOKResult{SrvTS: int64(binary.BigEndian.Uint64(pt[80:88])), MaxStreams: pt[88], HBSec: binary.BigEndian.Uint16(pt[89:91])}
	copy(res.SrvEphPub[:], pt[0:32])
	copy(res.ConnID[:], pt[32:48])
	copy(res.ResumeTok[:], pt[48:80])
	return res, nil
}

// DeriveSessionKeys implements SPEC 6.4.
// shared = X25519(priv, peerPub); salt = clientEphPub | serverEphPub;
// okm = HKDF-SHA256(salt, shared, "mist-v0.1/session", 64);
// kC2S = okm[0:32], kS2C = okm[32:64].
func DeriveSessionKeys(clientEphPub, serverEphPub, shared [32]byte) (kC2S, kS2C [32]byte) {
	salt := make([]byte, 0, 64)
	salt = append(salt, clientEphPub[:]...)
	salt = append(salt, serverEphPub[:]...)
	okm := make([]byte, 64)
	kdf := hkdf.New(sha256.New, shared[:], salt, []byte("mist-v0.1/session"))
	if _, err := kdf.Read(okm); err != nil {
		panic("mist: hkdf read failed: " + err.Error())
	}
	copy(kC2S[:], okm[0:32])
	copy(kS2C[:], okm[32:64])
	Zeroize(okm)
	return kC2S, kS2C
}

// X25519Shared computes X25519(priv, pub).
func X25519Shared(priv, pub *[32]byte) ([32]byte, error) {
	var out [32]byte
	s, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return out, err
	}
	copy(out[:], s)
	Zeroize(s)
	return out, nil
}

// X25519Keypair generates an ephemeral keypair.
func X25519Keypair() (priv, pub [32]byte, err error) {
	p := RandomBytes(32)
	q, err := curve25519.X25519(p, curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(priv[:], p)
	copy(pub[:], q)
	Zeroize(p)
	return priv, pub, nil
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
