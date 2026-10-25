package mistcore

import (
	"bytes"
	"testing"
)

// Tag-tail interop (see EncodeDatagramTagged): tag 0 is byte-identical
// to the old untagged frame, a tagged frame round-trips its tag, and
// any malformed tail (wrong magic, wrong length) decodes as untagged
// (tag 0) with the declared data untouched — old DecodeDatagram
// behavior is unchanged.
func TestEncodeDecodeDatagramTagged(t *testing.T) {
	data := []byte("hello-datagram")
	addr := []byte{93, 184, 216, 34}

	// Tag 0 == old EncodeDatagram output, byte for byte.
	if got := EncodeDatagramTagged(ATypIPv4, addr, 443, data, 0); !bytes.Equal(got, EncodeDatagram(ATypIPv4, addr, 443, data)) {
		t.Fatal("tag 0 must be identical to untagged EncodeDatagram")
	}

	// Tagged round-trip.
	tagged := EncodeDatagramTagged(ATypIPv4, addr, 443, data, 42)
	atyp, raddr, port, rdata, tag, err := DecodeDatagramTagged(tagged)
	if err != nil || atyp != ATypIPv4 || !bytes.Equal(raddr, addr) || port != 443 || !bytes.Equal(rdata, data) || tag != 42 {
		t.Fatalf("tagged round-trip = (%v %v %d %q tag=%d err=%v)", atyp, raddr, port, rdata, tag, err)
	}

	// Old decoder on a tagged frame still returns exactly the data
	// (it ignores everything after the declared length).
	if _, _, _, rdata, err := DecodeDatagram(tagged); err != nil || !bytes.Equal(rdata, data) {
		t.Fatalf("old DecodeDatagram on tagged frame = %q err=%v", rdata, err)
	}

	// Untagged frame decodes with tag 0.
	if _, _, _, _, tag, err := DecodeDatagramTagged(EncodeDatagram(ATypIPv4, addr, 443, data)); err != nil || tag != 0 {
		t.Fatalf("untagged frame tag = %d err=%v, want 0", tag, err)
	}

	// Wrong magic tail -> tag 0, data untouched.
	badMagic := append(append([]byte(nil), EncodeDatagram(ATypIPv4, addr, 443, data)...), 0x4D, 0x55, 7)
	if _, _, _, rdata, tag, err := DecodeDatagramTagged(badMagic); err != nil || tag != 0 || !bytes.Equal(rdata, data) {
		t.Fatalf("bad-magic tail = tag %d data %q err=%v", tag, rdata, err)
	}

	// Wrong-length tail (2 bytes, 4 bytes) -> tag 0, data untouched.
	for _, tail := range [][]byte{{0x4D, 0x54}, {0x4D, 0x54, 9, 9}} {
		p := append(append([]byte(nil), EncodeDatagram(ATypIPv4, addr, 443, data)...), tail...)
		if _, _, _, rdata, tag, err := DecodeDatagramTagged(p); err != nil || tag != 0 || !bytes.Equal(rdata, data) {
			t.Fatalf("tail %v = tag %d data %q err=%v", tail, tag, rdata, err)
		}
	}
}
