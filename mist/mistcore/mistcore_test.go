package mistcore

import (
	"bytes"
	"testing"
	"time"
)

func TestFrameRoundtrip(t *testing.T) {
	var key [32]byte
	copy(key[:], RandomBytes(32))
	pt := []byte("hello mist world, this is a test payload")
	for _, pad := range []int{0, 64, 200, 255} {
		wire, err := EncodeFrame(0x03, pt, pad, &key, 0, DirC2S, 7)
		if err != nil {
			t.Fatal(err)
		}
		if got := FrameWireLen(wire[:2]); got != len(wire) {
			t.Fatalf("wire len mismatch: %d vs %d", got, len(wire))
		}
		dec, err := DecodeFrame(wire, &key, 0, DirC2S, 7)
		if err != nil {
			t.Fatal(err)
		}
		if dec.SidFlags != 0x03 || !bytes.Equal(dec.Payload, pt) {
			t.Fatal("payload mismatch")
		}
		// Wrong counter must fail (AEAD).
		if _, err := DecodeFrame(wire, &key, 0, DirC2S, 8); err == nil {
			t.Fatal("expected failure with wrong ctr")
		}
		// Wrong direction must fail.
		if _, err := DecodeFrame(wire, &key, 0, DirS2C, 7); err == nil {
			t.Fatal("expected failure with wrong dir")
		}
	}
}

func TestHandshakeRoundtrip(t *testing.T) {
	var cid [16]byte
	copy(cid[:], RandomBytes(16))
	var kAuth [32]byte
	copy(kAuth[:], RandomBytes(32))
	lookup := func(c [16]byte) (*[32]byte, bool) {
		if c == cid {
			return &kAuth, true
		}
		return nil, false
	}
	cache := NewNonceCache(120 * time.Second)
	now := time.Now()

	wire, cliPub, cliPriv, err := BuildAUTH(cid, &kAuth, 0x01, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != AuthWireLen {
		t.Fatalf("AUTH len %d", len(wire))
	}
	ar, err := ParseAUTH(wire, lookup, now, DefaultAuthWindowSec, cache)
	if err != nil {
		t.Fatal(err)
	}
	if ar.EphPub != cliPub || ar.Feat != 0x01 {
		t.Fatal("auth result mismatch")
	}
	// Replay must fail.
	if _, err := ParseAUTH(wire, lookup, now, DefaultAuthWindowSec, cache); err != ErrReplayed {
		t.Fatalf("expected replay error, got %v", err)
	}
	// Tampered ciphertext must fail.
	bad := append([]byte{}, wire...)
	bad[80] ^= 0xFF
	if _, err := ParseAUTH(bad, lookup, now, DefaultAuthWindowSec, cache); err == nil {
		t.Fatal("expected failure on tampered ct")
	}

	// Server side of key exchange.
	srvPriv, srvPub, err := X25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	sharedS, err := X25519Shared(&srvPriv, &ar.EphPub)
	if err != nil {
		t.Fatal(err)
	}
	sharedC, err := X25519Shared(&cliPriv, &srvPub)
	if err != nil {
		t.Fatal(err)
	}
	if sharedS != sharedC {
		t.Fatal("x25519 mismatch")
	}
	kC2S_s, kS2C_s := DeriveSessionKeys(ar.EphPub, srvPub, sharedS)
	kC2S_c, kS2C_c := DeriveSessionKeys(cliPub, srvPub, sharedC)
	if kC2S_s != kC2S_c || kS2C_s != kS2C_c {
		t.Fatal("derived keys mismatch")
	}
	if kC2S_s == kS2C_s {
		t.Fatal("direction keys must differ")
	}

	// AUTH_OK roundtrip.
	var connID [16]byte
	copy(connID[:], RandomBytes(16))
	var tok [32]byte
	copy(tok[:], RandomBytes(32))
	okWire, err := BuildAuthOK(&kAuth, srvPub, connID, tok, 16, 30, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(okWire) != AuthOKWireLen {
		t.Fatalf("AUTH_OK len %d", len(okWire))
	}
	okr, err := ParseAuthOK(okWire, &kAuth)
	if err != nil {
		t.Fatal(err)
	}
	if okr.ConnID != connID || okr.ResumeTok != tok || okr.HBSec != 30 {
		t.Fatal("auth_ok mismatch")
	}
}

func TestShaping(t *testing.T) {
	s := NewShaper(4, 64, 128, 5, 0)
	pads := make([]int, 0, 8)
	for i := 0; i < 8; i++ {
		pads = append(pads, s.PadLen())
		s.Done()
	}
	for _, p := range pads[:4] {
		if p < 64 || p > 128 {
			t.Fatalf("heavy pad out of range: %d", p)
		}
	}
	for _, p := range pads[4:] {
		if p != 0 {
			t.Fatalf("light pad should be 0, got %d", p)
		}
	}
	// At least one heavy pad should differ (randomness sanity, flaky-proof: range check only).
}

func TestDatagram(t *testing.T) {
	d := EncodeDatagram(ATypDomain, []byte("dns.google"), 53, []byte{1, 2, 3})
	atyp, addr, port, data, err := DecodeDatagram(d)
	if err != nil {
		t.Fatal(err)
	}
	if atyp != ATypDomain || string(addr) != "dns.google" || port != 53 || len(data) != 3 {
		t.Fatal("datagram mismatch")
	}
	c := EncodeConnectReq(ATypIPv4, []byte{1, 1, 1, 1}, 443)
	a2, ad2, p2, err := DecodeConnectReq(c)
	if err != nil || a2 != ATypIPv4 || p2 != 443 || len(ad2) != 4 {
		t.Fatal("connect req mismatch")
	}
}
