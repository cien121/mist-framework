// Package mistcore: Mist UDP session management.
//
// A UDP session is established via the Initial handshake (§5):
//
//	Client → Server: Initial(AUTH)    [QUIC long header]
//	Server → Client: Initial(AUTH_OK) [QUIC long header]
//
// Then both sides use short headers for data.
//
// Phase 1 scope: handshake + basic packet send/recv.
// Phase 2 will add: reliability (ACK/retransmit), BBR, full header protection.
package mistcore

import (
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"
)

// UDPSession represents a Mist UDP session.
type UDPSession struct {
	// Session ID (16 bytes, from AUTH_OK CONN_ID).
	SessionID [16]byte

	// Keys (derived via X25519 + HKDF, §5.3).
	KeyC2S [32]byte // client → server
	KeyS2C [32]byte // server → client

	// Header protection keys (per direction, §3.2).
	// Derived at session creation; used for QUIC short header masking.
	HPKeyC2S [32]byte
	HPKeyS2C [32]byte

	// Packet numbers (per direction, independent).
	nextPktNumC2S uint32
	nextPktNumS2C uint32

	// Remote address (for server: client's UDP address).
	RemoteAddr *net.UDPAddr

	// Codec for Initial packets (interface allows Phase 0 replacement).
	Codec InitialCodec

	// BBR congestion controller (Phase 2, §7).
	BBR *BBRController
	// Reliability tracker (Phase 2, §6): sent tracking + recv window + ACK.
	Rel *UDPReliability

	// Created time (for idle timeout).
	CreatedAt  time.Time
	LastActive time.Time

	mu sync.Mutex
}

// NewUDPSession creates a new UDP session after handshake.
func NewUDPSession(sessionID [16]byte, keyC2S, keyS2C [32]byte, remoteAddr *net.UDPAddr, codec InitialCodec) *UDPSession {
	now := time.Now()
	var sid8 [8]byte
	copy(sid8[:], sessionID[:8])
	// Header protection keys (per direction, §3.2).
	hpC2S := UDPDeriveHPKey(&keyC2S, sid8, DirC2S)
	hpS2C := UDPDeriveHPKey(&keyS2C, sid8, DirS2C)
	// BBR + reliability (Phase 2).
	bbrCtl := NewBBRController(1350) // §8.4 MTU
	rel := NewUDPReliability(bbrCtl)
	return &UDPSession{
		SessionID:  sessionID,
		KeyC2S:     keyC2S,
		KeyS2C:     keyS2C,
		HPKeyC2S:   hpC2S,
		HPKeyS2C:   hpS2C,
		RemoteAddr: remoteAddr,
		Codec:      codec,
		BBR:        bbrCtl,
		Rel:        rel,
		CreatedAt:  now,
		LastActive: now,
	}
}

// NextPacketNum returns the next packet number for the given direction
// and increments the counter. Thread-safe.
func (s *UDPSession) NextPacketNum(dir uint32) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir == DirC2S {
		n := s.nextPktNumC2S
		s.nextPktNumC2S++
		return n
	}
	n := s.nextPktNumS2C
	s.nextPktNumS2C++
	return n
}

// SessionID8 returns the first 8 bytes of the session ID (for DCID and nonce).
func (s *UDPSession) SessionID8() [8]byte {
	var out [8]byte
	copy(out[:], s.SessionID[:8])
	return out
}

// Touch updates the last-active time. Thread-safe.
func (s *UDPSession) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActive = time.Now()
}

// Tick runs the session's periodic maintenance: flush pending ACKs and scan
// for retransmission timeouts. Call it every ~10ms from the session's timer
// loop (both ends: client and server).
//
// Bundling FlushAck + CheckRTO here makes "forgot to call one of them"
// structurally impossible. 2026-10-23 lab root cause: the server's loop only
// called FlushAck, so server->client loss was never retransmitted and 100KB
// echo stalled at 101200/102400 with no recovery.
func (s *UDPSession) Tick() {
	s.Rel.FlushAck()
	s.Rel.CheckRTO()
}

// FlushAck sends a pending ACK without scanning RTOs. readPump calls
// this per received packet: ACKs stay prompt (FlushAck's own 10ms
// throttle governs), while the O(in-flight) CheckRTO scan runs only
// on the 10ms timer loop. Calling full Tick per packet made RTO-scan
// CPU grow quadratically with throughput (packet rate x in-flight:
// ~4% of a core at 32 Mbps, ~45% at 100 Mbps in benchmarks), which
// capped sustained throughput on phones well below the link rate.
func (s *UDPSession) FlushAck() {
	s.Rel.FlushAck()
}

// SealPacket encrypts frames into a UDP datagram.
//
// Steps:
//  1. Concatenate frame plaintexts (total ≤ MaxUDPPlaintext).
//  2. Build nonce: [SESSION_ID(8)][DIR(4)][PACKET_NUM(4)][RESERVED(8)].
//     Uses the REAL (pre-mask) packet number (§4.2).
//  3. AEAD encrypt with direction key, AAD = QUIC short header (unmasked).
//  4. Apply header protection mask to the header (§3.2, Phase 2):
//     sample = first 16 bytes of ciphertext.
//  5. Prepend masked QUIC short header.
//
// Returns the full UDP datagram.
// sealPacketTracked is the package-private entry point for tracked sends.
// Only UDPSendScheduler may call it: this makes "bypass the cwnd/pacing
// gate" a compile error instead of a code-review catch.
//
// (The public SealPacket wrapper was removed; use the scheduler.)
func (s *UDPSession) sealPacketTracked(dir uint32, frames [][]byte) ([]byte, error) {
	return s.sealPacket(dir, frames, true)
}

// SealPacketUntracked encrypts frames into a UDP datagram without
// reliability tracking or BBR accounting.
//
// Use for ACK-only packets: ACKs are never acknowledged themselves, so
// tracking them would leak sentPackets entries, inflate bytesInFlight,
// and cause spurious RTO retransmissions of ACKs.
func (s *UDPSession) SealPacketUntracked(dir uint32, frames [][]byte) ([]byte, error) {
	return s.sealPacket(dir, frames, false)
}

func (s *UDPSession) sealPacket(dir uint32, frames [][]byte, track bool) ([]byte, error) {
	// Concatenate frames.
	var plaintext []byte
	for _, f := range frames {
		plaintext = append(plaintext, f...)
	}
	if len(plaintext) > MaxUDPPlaintext {
		return nil, errors.New("udp: plaintext exceeds max")
	}

	// Get packet number (real, pre-mask).
	pktNum := s.NextPacketNum(dir)

	// Select key and HP key.
	var key *[32]byte
	var hpKey [32]byte
	if dir == DirC2S {
		key = &s.KeyC2S
		hpKey = s.HPKeyC2S
	} else {
		key = &s.KeyS2C
		hpKey = s.HPKeyS2C
	}

	// Build QUIC short header (AAD uses UNMASKED header, §4.2).
	dcid := s.SessionID8()
	header := BuildShortHeader(dcid, pktNum, false)

	// Build nonce (pre-mask real packet number, §4.2).
	nonce := UDPNonce(dcid, dir, pktNum)

	// Encrypt.
	ciphertext, err := UDPSeal(key, nonce, plaintext, header[:])
	if err != nil {
		return nil, err
	}

	// Header protection: sample = first 16 bytes of ciphertext.
	if len(ciphertext) < 16 {
		return nil, errors.New("udp: ciphertext too short for header protection sample")
	}
	sample := ciphertext[:16]
	hdr := header[:] // copy to mutable slice
	if err := ApplyHeaderProtection(hdr, hpKey, sample); err != nil {
		return nil, err
	}

	// Assemble datagram: masked header + ciphertext.
	datagram := make([]byte, 0, len(hdr)+len(ciphertext))
	datagram = append(datagram, hdr...)
	datagram = append(datagram, ciphertext...)

	// Reliability tracking (Phase 2, §6.2).
	// Skipped for untracked packets (e.g. ACKs): they are never ACKed
	// themselves, so tracking would leak and cause spurious RTOs.
	if track {
		if s.Rel != nil {
			s.Rel.PacketSent(pktNum, frames, len(datagram))
		}
		if s.BBR != nil {
			s.BBR.OnPacketSent(pktNum, len(datagram), s.Rel.BytesInFlight())
		}
	}

	return datagram, nil
}

// OpenPacket decrypts a UDP datagram and returns the frames.
//
// Steps:
//  1. Extract header protection sample from ciphertext (datagram[13:29]).
//  2. Remove header protection mask → real header with real packet number.
//  3. Parse real header (get DCID, packet number).
//  4. Build nonce from REAL (unmasked) packet number (§4.2).
//  5. AEAD decrypt with direction key, AAD = unmasked header.
//  6. Decode frames from plaintext.
//  7. Reliability: mark packet received (may trigger ACK).
func (s *UDPSession) OpenPacket(dir uint32, datagram []byte) ([]UDPFrame, uint32, error) {
	if len(datagram) < QUICShortHeaderLen+16 {
		return nil, 0, errors.New("udp: datagram too short")
	}

	// Select HP key.
	var hpKey [32]byte
	if dir == DirC2S {
		hpKey = s.HPKeyC2S
	} else {
		hpKey = s.HPKeyS2C
	}

	// Extract sample BEFORE unmasking (sample is from ciphertext).
	sample, err := HeaderProtectSample(datagram)
	if err != nil {
		return nil, 0, err
	}

	// Copy header and remove protection to get real packet number.
	var hdrBuf [QUICShortHeaderLen]byte
	copy(hdrBuf[:], datagram[:QUICShortHeaderLen])
	if err := RemoveHeaderProtection(hdrBuf[:], hpKey, sample); err != nil {
		return nil, 0, err
	}

	// Parse unmasked header.
	dcid, pktNum, _, err := ParseShortHeader(hdrBuf[:])
	if err != nil {
		return nil, 0, err
	}

	// Verify DCID matches session (first 8 bytes of session ID).
	expectedDCID := s.SessionID8()
	if dcid != expectedDCID {
		return nil, 0, errors.New("udp: DCID mismatch")
	}

	// Select key.
	var key *[32]byte
	if dir == DirC2S {
		key = &s.KeyC2S
	} else {
		key = &s.KeyS2C
	}

	// Build nonce with REAL (unmasked) packet number.
	// AAD is the UNMASKED header (§4.2).
	nonce := UDPNonce(dcid, dir, pktNum)

	// Decrypt.
	ciphertext := datagram[QUICShortHeaderLen:]
	plaintext, err := UDPOpen(key, nonce, ciphertext, hdrBuf[:])
	if err != nil {
		return nil, 0, err
	}

	// Decode frames.
	frames, err := DecodeUDPFrames(plaintext)
	if err != nil {
		return nil, 0, err
	}

	// Reliability: mark received (may trigger ACK via callback).
	if s.Rel != nil {
		s.Rel.PacketReceived(pktNum)
	}

	s.Touch()
	return frames, pktNum, nil
}

// ---------------------------------------------------------------------------
// Server-side handshake
// ---------------------------------------------------------------------------

// UDPHandshakeResult contains the result of a successful server-side handshake.
type UDPHandshakeResult struct {
	Session *UDPSession
	// Response packet to send back to client (Initial AUTH_OK).
	Response []byte
}

// UDPServerHandshake processes a client's Initial(AUTH) packet.
// This is the server side of the §5.1 handshake.
//
// Steps:
//  1. Parse Initial packet (get AUTH payload).
//  2. Decrypt AUTH (using K_auth lookup via HANDSHAKE_CID).
//  3. Verify timestamp, anti-replay.
//  4. Generate server ephemeral keypair, derive session keys.
//  5. Create session, build AUTH_OK response.
func UDPServerHandshake(
	codec InitialCodec,
	packet []byte,
	clientAddr *net.UDPAddr,
	lookupAuth func(handshakeCID [16]byte, nonce [24]byte) (kAuth *[32]byte, cid [16]byte, ok bool),
) (*UDPHandshakeResult, error) {
	// 1. Parse Initial packet.
	authWire, _, scid, _, err := codec.OpenInitial(packet)
	if err != nil {
		return nil, err
	}
	// authWire = [HANDSHAKE_CID(16)][NONCE(24)][CIPHERTEXT]
	if len(authWire) < 16+24+16 {
		return nil, errors.New("udp: AUTH wire too short")
	}
	var handshakeCID [16]byte
	copy(handshakeCID[:], authWire[:16])
	var nonce [24]byte
	copy(nonce[:], authWire[16:40])
	ciphertext := authWire[40:]

	// 2. Lookup K_auth via HANDSHAKE_CID.
	kAuth, cid, ok := lookupAuth(handshakeCID, nonce)
	if !ok {
		return nil, errors.New("udp: unknown handshake CID")
	}

	// 3. Decrypt AUTH using K_auth.
	aead, err := udpAEAD(kAuth)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce[:], ciphertext, handshakeCID[:])
	if err != nil {
		return nil, errors.New("udp: AUTH decrypt failed")
	}

	// Parse AUTH_PLAIN: [VER(1)][TS(8)][EPH_PUB(32)][FEAT(1)][MODE(1)][RSVD(2)]
	if len(plain) < 45 {
		return nil, errors.New("udp: AUTH_PLAIN too short")
	}
	if plain[0] != 0x02 {
		return nil, errors.New("udp: not UDP version")
	}
	// TODO: verify timestamp, anti-replay (Phase 1 simplified: skip for now)
	_ = cid

	var clientEphPub [32]byte
	copy(clientEphPub[:], plain[9:41])

	// 4. Generate server ephemeral keypair.
	serverPriv, serverPub, err := X25519Keypair()
	if err != nil {
		return nil, err
	}

	// Derive shared secret.
	shared, err := X25519Shared(&serverPriv, &clientEphPub)
	if err != nil {
		return nil, err
	}

	// Derive session keys (same as TCP §6.4).
	kC2S, kS2C := DeriveSessionKeys(clientEphPub, serverPub, shared)

	// 5. Generate session ID (CONN_ID, 16 bytes random).
	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, err
	}

	// Build AUTH_OK payload (simplified).
	// Format: [SRV_EPH_PUB(32)][CONN_ID(16)]...
	// For Phase 1, minimal: just enough for client to derive keys.
	authOKPlain := make([]byte, 48)
	copy(authOKPlain[0:32], serverPub[:])
	copy(authOKPlain[32:48], sessionID[:])

	// Encrypt AUTH_OK with K_auth (simplified; real will use proper format).
	var authOKNonce [24]byte
	if _, err := rand.Read(authOKNonce[:]); err != nil {
		return nil, err
	}
	authOKCipher, err := UDPSeal(kAuth, authOKNonce, authOKPlain, nil)
	if err != nil {
		return nil, err
	}
	// Wire: [NONCE(24)][CIPHERTEXT]
	authOKWire := make([]byte, 0, 24+len(authOKCipher))
	authOKWire = append(authOKWire, authOKNonce[:]...)
	authOKWire = append(authOKWire, authOKCipher...)

	// Build Initial response packet.
	// DCID = client's SCID (so client can match).
	response, err := codec.SealInitialResponse(authOKWire, scid, sessionID8(sessionID), 0)
	if err != nil {
		return nil, err
	}

	// Create session.
	session := NewUDPSession(sessionID, kC2S, kS2C, clientAddr, codec)

	return &UDPHandshakeResult{
		Session:  session,
		Response: response,
	}, nil
}

// sessionID8 extracts first 8 bytes of session ID.
func sessionID8(sid [16]byte) [8]byte {
	var out [8]byte
	copy(out[:], sid[:8])
	return out
}
