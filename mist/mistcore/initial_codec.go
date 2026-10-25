// Package mistcore: Mist UDP Initial packet codec.
//
// The InitialCodec interface abstracts Initial packet encoding/decoding.
// Phase 0 provides the real QUIC Initial implementation (QUICInitialCodec).
// RandomCiphertextCodec is retired and always fails.
//
// Interface covers both directions (per 2026-10-22 review):
//   - Client→Server: SealInitial / OpenInitial (AUTH)
//   - Server→Client: SealInitialResponse / OpenInitialResponse (AUTH_OK)
//
// Safety gate (2026-10-24, Phase 0 complete):
//   - RandomCiphertextCodec is retired; its methods always fail.
//   - QUICInitialCodec is production-safe (ProductionSafe() == true).
//   - CheckInitialCodecSafeForAddr (initial_codec_safety.go)
//     refuses public listen/peer addresses for non-production-safe codecs.
package mistcore

import (
	"crypto/rand"
	"crypto/sha256"
)

// ---------------------------------------------------------------------------
// InitialCodec interface
// ---------------------------------------------------------------------------

// InitialCodec encodes/decodes QUIC Initial packets for the Mist UDP handshake.
//
// Implementations:
//   - QUICInitialCodec (Phase 0): real QUIC Initial encryption per RFC 9001.
//     Production-safe; the only codec used by client and server.
//   - RandomCiphertextCodec (retired): always fails. Kept only so old
//     references compile and safety-gate tests have a non-safe example.
type InitialCodec interface {
	// SealInitial encrypts an AUTH payload into a QUIC Initial packet.
	// Returns the full UDP datagram (QUIC long header + encrypted payload).
	SealInitial(authPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error)

	// OpenInitial decrypts a QUIC Initial packet, returning the AUTH payload.
	// Returns the SCID from the packet header for session tracking.
	OpenInitial(packet []byte) (authPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32, err error)

	// SealInitialResponse encrypts an AUTH_OK payload into a QUIC Initial packet.
	// dcid is the client's SCID (so the client can match the response).
	SealInitialResponse(authOKPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error)

	// OpenInitialResponse decrypts a QUIC Initial packet, returning the AUTH_OK payload.
	OpenInitialResponse(packet []byte) (authOKPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32, err error)
}

// handshakeCID computes HANDSHAKE_CID = HMAC-SHA256(K_auth, NONCE)[0:16].
// Per design §5.2: prevents tracking via fixed CID in Initial packets.
func handshakeCID(kAuth *[32]byte, nonce [24]byte) [16]byte {
	// HMAC-SHA256(key=K_auth, msg=NONCE), truncate to 16 bytes.
	// Simplified: use SHA256(K_auth || NONCE) and truncate.
	// Full HMAC will be implemented in Phase 1 final.
	h := sha256.New()
	h.Write(kAuth[:])
	h.Write(nonce[:])
	sum := h.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// randomBytes generates n random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
