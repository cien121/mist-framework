package mistcore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// RFC 9001 Appendix A.5 test vectors for ChaCha20-based header protection.
// These are the authoritative vectors from the RFC; do not modify.
//
//   hp key (32 bytes) = HKDF-Expand-Label(secret, "quic hp", "", 32)
//   sample (16 bytes) = ciphertext with first byte skipped
//   mask   (5 bytes)  = first 5 bytes of ChaCha20 keystream
func rfcA5Vectors(t *testing.T) (hpKey [32]byte, sample []byte, wantMask [5]byte) {
	t.Helper()
	hpHex := "25a282b9e82f06f21f488917a4fc8f1b" +
		"73573685608597d0efcb076b0ab7a7a4"
	sampleHex := "5e5cd55c41f69080575d7999c25a5bfb"
	maskHex := "aefefe7d03"

	hpBytes, err := hex.DecodeString(hpHex)
	if err != nil {
		t.Fatalf("bad hp key hex: %v", err)
	}
	copy(hpKey[:], hpBytes)

	sample, err = hex.DecodeString(sampleHex)
	if err != nil {
		t.Fatalf("bad sample hex: %v", err)
	}
	maskBytes, err := hex.DecodeString(maskHex)
	if err != nil {
		t.Fatalf("bad mask hex: %v", err)
	}
	copy(wantMask[:], maskBytes)
	return hpKey, sample, wantMask
}

// TestHeaderProtectMaskRFC9001A5 verifies headerProtectMask against the
// RFC 9001 Appendix A.5 ChaCha20 test vector.
//
// This locks in the counter/nonce derivation that was corrected during
// design review (third round):
//   counter = little-endian uint32 of sample[0:4]
//   nonce   = sample[4:16] (12 bytes)
// A fixed counter/nonce would make the mask constant per direction and
// the protection ineffective; this test would catch that regression.
func TestHeaderProtectMaskRFC9001A5(t *testing.T) {
	hpKey, sample, wantMask := rfcA5Vectors(t)

	gotMask, err := headerProtectMask(hpKey, sample)
	if err != nil {
		t.Fatalf("headerProtectMask failed: %v", err)
	}
	if gotMask != wantMask {
		t.Fatalf("mask mismatch:\n got %x\nwant %x", gotMask, wantMask)
	}
}

// TestHeaderProtectCounterNonceDerivation explicitly pins the
// counter/nonce derivation rules from RFC 9001 §5.4.4, independent of
// the mask function implementation.
func TestHeaderProtectCounterNonceDerivation(t *testing.T) {
	_, sample, _ := rfcA5Vectors(t)

	// counter = sample[0:4] as little-endian uint32.
	// sample starts with 5e5cd55c -> 0x5cd55c5e.
	counter := binary.LittleEndian.Uint32(sample[0:4])
	if counter != 0x5cd55c5e {
		t.Fatalf("counter = %#x, want 0x5cd55c5e", counter)
	}

	// nonce = sample[4:16] (12 bytes).
	nonce := sample[4:16]
	wantNonce, _ := hex.DecodeString("41f69080575d7999c25a5bfb")
	if !bytes.Equal(nonce, wantNonce) {
		t.Fatalf("nonce = %x, want %x", nonce, wantNonce)
	}
}

// TestHeaderProtectRFC9001A5FullPacket applies the RFC mask to the
// RFC's unprotected short header and checks the protected result.
//
// RFC A.5: unprotected header 4200bff4 (3-byte packet number 00bff4),
// mask aefefe7d03 -> protected header 4cfe4189.
// Byte 0: 0x42 ^ (0xae & 0x1f) = 0x42 ^ 0x0e = 0x4c (spin bit untouched).
// PN: 00bff4 ^ fefe7d = fe4189.
func TestHeaderProtectRFC9001A5FullPacket(t *testing.T) {
	hpKey, sample, _ := rfcA5Vectors(t)

	unprotected, _ := hex.DecodeString("4200bff4")
	protected, _ := hex.DecodeString("4cfe4189")

	// Apply mask manually the same way ApplyHeaderProtection does for
	// short headers: low 5 bits of byte 0, then packet number bytes.
	mask, err := headerProtectMask(hpKey, sample)
	if err != nil {
		t.Fatalf("headerProtectMask failed: %v", err)
	}
	got := make([]byte, 4)
	copy(got, unprotected)
	got[0] ^= mask[0] & 0x1F
	for i := 0; i < 3; i++ {
		got[1+i] ^= mask[1+i]
	}
	if !bytes.Equal(got, protected) {
		t.Fatalf("protected header mismatch:\n got %x\nwant %x", got, protected)
	}
}
