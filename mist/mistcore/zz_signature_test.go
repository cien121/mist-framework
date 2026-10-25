// Signature hardening tests (F1–F5, field-level only).
//
// These tests prove functional correctness of the wire changes. They do
// NOT prove anything about DPI resistance: a green test here means the
// bytes are well-formed, not that the protocol is indistinguishable
// from genuine QUIC (it is not: the Initial CRYPTO payload is Mist
// AUTH, not a TLS ClientHello).
package mistcore

import (
	"bytes"
	"testing"
	"time"
)

func testSignatureSession() *UDPSession {
	var sid [16]byte
	for i := range sid {
		sid[i] = byte(i + 1)
	}
	var kC2S, kS2C [32]byte
	for i := range kC2S {
		kC2S[i] = byte(i + 11)
		kS2C[i] = byte(0x80 + i)
	}
	return NewUDPSession(sid, kC2S, kS2C, nil, &QUICInitialCodec{})
}

// TestF2InitialPaddedBothDirections: SealInitial and SealInitialResponse
// both produce datagrams >= 1200 bytes, and the codec round-trips the
// payload while skipping the PADDING tail.
func TestF2InitialPaddedBothDirections(t *testing.T) {
	codec := &QUICInitialCodec{}
	var dcid, scid [8]byte
	for i := range dcid {
		dcid[i] = byte(i + 1)
		scid[i] = byte(0x40 + i)
	}
	auth := []byte("test-auth-wire-bytes")
	pkt, err := codec.SealInitial(auth, dcid, scid, 0)
	if err != nil {
		t.Fatalf("SealInitial: %v", err)
	}
	if len(pkt) < 1200 {
		t.Fatalf("SealInitial len %d < 1200", len(pkt))
	}
	got, _, _, _, err := codec.OpenInitial(pkt)
	if err != nil {
		t.Fatalf("OpenInitial: %v", err)
	}
	if !bytes.Equal(got, auth) {
		t.Fatalf("OpenInitial payload mismatch: %q", got)
	}

	authOK := []byte("test-auth-ok-wire-bytes")
	resp, err := codec.SealInitialResponse(authOK, scid, dcid, 0)
	if err != nil {
		t.Fatalf("SealInitialResponse: %v", err)
	}
	if len(resp) < 1200 {
		t.Fatalf("SealInitialResponse len %d < 1200", len(resp))
	}
	got, _, _, _, err = codec.OpenInitialResponse(resp)
	if err != nil {
		t.Fatalf("OpenInitialResponse: %v", err)
	}
	if !bytes.Equal(got, authOK) {
		t.Fatalf("OpenInitialResponse payload mismatch: %q", got)
	}
}

// TestF2LegacyUnpaddedStillDecodes: a CRYPTO-only plaintext (no PADDING
// tail, as sent by pre-F2 peers) still decodes at the codec layer.
func TestF2LegacyUnpaddedStillDecodes(t *testing.T) {
	plain := encodeCryptoFrame(0, []byte("legacy-auth"))
	got, err := decodeInitialPlaintext(plain)
	if err != nil {
		t.Fatalf("decodeInitialPlaintext legacy: %v", err)
	}
	if string(got) != "legacy-auth" {
		t.Fatalf("legacy payload mismatch: %q", got)
	}
	// Nonzero trailing bytes are not PADDING and must be rejected.
	bad := append(append([]byte(nil), plain...), 0x01)
	if _, err := decodeInitialPlaintext(bad); err == nil {
		t.Fatal("nonzero trailing byte after CRYPTO frame should be rejected")
	}
}

// TestF3PacketNumberLengthBoundary: 65535 uses the 11-byte header,
// 65536 uses the 13-byte header, and both round-trip through a session.
func TestF3PacketNumberLengthBoundary(t *testing.T) {
	if got := ShortHeaderLen(65535); got != 11 {
		t.Fatalf("ShortHeaderLen(65535) = %d, want 11", got)
	}
	if got := ShortHeaderLen(65536); got != 13 {
		t.Fatalf("ShortHeaderLen(65536) = %d, want 13", got)
	}
	sender := testSignatureSession()
	receiver := testSignatureSession()
	sender.nextPktNumC2S = 65534
	frame := EncodeUDPFrame(UDPFramePing, 0, nil)
	for _, wantPN := range []uint32{65534, 65535, 65536} {
		pkt, pn, err := sender.SealTrackedPacket(DirC2S, [][]byte{frame})
		if err != nil {
			t.Fatalf("seal pn %d: %v", wantPN, err)
		}
		if pn != wantPN {
			t.Fatalf("sealed pn = %d, want %d", pn, wantPN)
		}
		wantLen := 11
		if wantPN >= 65536 {
			wantLen = 13
		}
		// Datagram length = header + frame + AEAD tag (16).
		if len(pkt) != wantLen+len(frame)+16 {
			t.Fatalf("pn %d: datagram len %d, want header %d + frame %d + tag 16",
				wantPN, len(pkt), wantLen, len(frame))
		}
		frames, gotPN, err := receiver.OpenPacket(DirC2S, pkt)
		if err != nil {
			t.Fatalf("open pn %d: %v", wantPN, err)
		}
		if gotPN != wantPN || len(frames) != 1 || frames[0].Type != UDPFramePing {
			t.Fatalf("open pn %d: got pn %d frames %v", wantPN, gotPN, frames)
		}
	}
}

// TestF4SpinFlipsPerRTT: after an RTT sample exists, a seal past one
// RTT since the last flip toggles the (unmasked) spin bit.
func TestF4SpinFlipsPerRTT(t *testing.T) {
	s := testSignatureSession()
	frame := EncodeUDPFrame(UDPFramePing, 0, nil)
	pkt1, pn1, err := s.SealTrackedPacket(DirC2S, [][]byte{frame})
	if err != nil {
		t.Fatalf("seal1: %v", err)
	}
	if pkt1[0]&0x20 != 0 {
		t.Fatal("initial spin should be 0")
	}
	// Feed one RTT sample so SRTT > 0.
	if !s.Rel.PacketAcked(pn1, 50*time.Millisecond) {
		t.Fatal("PacketAcked should report newly acked")
	}
	if s.Rel.SRTT() <= 0 {
		t.Fatalf("SRTT should be > 0 after ACK, got %v", s.Rel.SRTT())
	}
	// A seal within the same RTT window must not flip.
	pkt2, _, err := s.SealTrackedPacket(DirC2S, [][]byte{frame})
	if err != nil {
		t.Fatalf("seal2: %v", err)
	}
	if pkt2[0]&0x20 != pkt1[0]&0x20 {
		t.Fatal("spin flipped within one RTT window")
	}
	// A seal past one RTT since the last flip must flip.
	s.mu.Lock()
	s.lastSpinFlip = time.Now().Add(-200 * time.Millisecond)
	s.mu.Unlock()
	pkt3, _, err := s.SealTrackedPacket(DirC2S, [][]byte{frame})
	if err != nil {
		t.Fatalf("seal3: %v", err)
	}
	if pkt3[0]&0x20 == pkt1[0]&0x20 {
		t.Fatal("spin did not flip after one RTT elapsed")
	}
}

// TestF5DCIDRotateFrameAndAlias: DCID_ROTATE encodes/decodes, and a
// receiver that registered the rotation accepts both the new DCID and
// in-flight old-DCID packets (alias grace), because the nonce never
// follows the DCID.
func TestF5DCIDRotateFrameAndAlias(t *testing.T) {
	var newDCID [8]byte
	for i := range newDCID {
		newDCID[i] = byte(0xA0 + i)
	}
	frame := EncodeDCIDRotateFrame(newDCID, 12345)
	frames, err := DecodeUDPFrames(frame)
	if err != nil || len(frames) != 1 || frames[0].Type != UDPFrameDCIDRotate {
		t.Fatalf("DCID_ROTATE frame decode: frames=%v err=%v", frames, err)
	}
	gotDCID, window, err := DecodeDCIDRotateFrame(frames[0].Payload)
	if err != nil {
		t.Fatalf("DecodeDCIDRotateFrame: %v", err)
	}
	if gotDCID != newDCID || window != 12345 {
		t.Fatalf("DCID_ROTATE roundtrip: dcid=%x window=%d", gotDCID, window)
	}

	sender := testSignatureSession()
	receiver := testSignatureSession()
	ping := EncodeUDPFrame(UDPFramePing, 0, nil)
	// Packet sealed BEFORE rotation (old DCID).
	oldPkt, _, err := sender.SealTrackedPacket(DirC2S, [][]byte{ping})
	if err != nil {
		t.Fatalf("seal old: %v", err)
	}
	// Both sides rotate (receiver learned the rotation from the frame).
	sender.RotateDCID(newDCID)
	receiver.RotateDCID(newDCID)
	if sender.CurrentDCID() != newDCID || receiver.CurrentDCID() != newDCID {
		t.Fatal("CurrentDCID did not switch after RotateDCID")
	}
	// Packet sealed AFTER rotation (new DCID).
	newPkt, _, err := sender.SealTrackedPacket(DirC2S, [][]byte{ping})
	if err != nil {
		t.Fatalf("seal new: %v", err)
	}
	// New-DCIP packet opens.
	if _, _, err := receiver.OpenPacket(DirC2S, newPkt); err != nil {
		t.Fatalf("open new-DCIP packet: %v", err)
	}
	// In-flight old-DCIP packet still opens via the alias.
	if _, _, err := receiver.OpenPacket(DirC2S, oldPkt); err != nil {
		t.Fatalf("open old-DCIP packet via alias: %v", err)
	}
	// HP keys must NOT have changed with rotation (they stay bound to
	// the original SessionID8).
	if sender.HPKeyC2S != receiver.HPKeyC2S {
		t.Fatal("HP keys diverged (rotation must not re-derive them)")
	}
}

// TestHopDoesNotDisturbDatagramTag: a tagged datagram sealed through a
// rotated session (hop on, new DCID) still carries its tag intact, and
// the receiver recovers the same tag. Hopping changes only the outer
// UDP destination/DCID; it never touches the payload or the tag that
// the same-target routing fix (batch 4) depends on. This is the
// hop-on leg of the串线 test matrix; the hop-off leg is the existing
// tagged-datagram suites run unchanged.
func TestHopDoesNotDisturbDatagramTag(t *testing.T) {
	sender := testSignatureSession()
	receiver := testSignatureSession()
	var newDCID [8]byte
	for i := range newDCID {
		newDCID[i] = byte(0x50 + i)
	}
	sender.RotateDCID(newDCID)
	receiver.RotateDCID(newDCID)
	dg := EncodeDatagramTagged(ATypIPv4, []byte{192, 0, 2, 1}, 53, []byte{0xDE, 0xAD}, 7)
	frame := EncodeUDPFrame(UDPFrameDatagram, 0, dg)
	pkt, _, err := sender.SealTrackedPacket(DirC2S, [][]byte{frame})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	frames, _, err := receiver.OpenPacket(DirC2S, pkt)
	if err != nil {
		t.Fatalf("open after rotation: %v", err)
	}
	if len(frames) != 1 || frames[0].Type != UDPFrameDatagram {
		t.Fatalf("frames = %v", frames)
	}
	_, addr, port, data, tag, err := DecodeDatagramTagged(frames[0].Payload)
	if err != nil {
		t.Fatalf("DecodeDatagramTagged: %v", err)
	}
	if tag != 7 || port != 53 || !bytes.Equal(data, []byte{0xDE, 0xAD}) || !bytes.Equal(addr, []byte{192, 0, 2, 1}) {
		t.Fatalf("tag roundtrip mismatch: tag=%d port=%d addr=%v data=%x", tag, port, addr, data)
	}
}

// TestV6LiteralSingleCandidate: a literal address (v4 or v6) yields
// exactly one candidate, so literal nodes never change family (§3.5).
// Domain fallback ordering (v6 first) is exercised by the client at
// Connect time and needs DNS, so it is not unit-tested here.
func TestV6LiteralSingleCandidate(t *testing.T) {
	ctx := t.Context()
	codec := &QUICInitialCodec{}
	for _, addr := range []string{"[2001:db8::1]:8443", "192.0.2.1:8443"} {
		cands, err := ResolvePeerAddrsSafe(ctx, addr, codec)
		if err != nil {
			t.Fatalf("ResolvePeerAddrsSafe(%q): %v", addr, err)
		}
		if len(cands) != 1 {
			t.Fatalf("ResolvePeerAddrsSafe(%q): %d candidates, want 1", addr, len(cands))
		}
		if cands[0].Port != 8443 {
			t.Fatalf("candidate port = %d, want 8443", cands[0].Port)
		}
	}
	v6, err := ResolvePeerAddrsSafe(ctx, "[2001:db8::1]:8443", codec)
	if err != nil {
		t.Fatalf("v6 literal: %v", err)
	}
	if v6[0].IP.To4() != nil {
		t.Fatalf("v6 candidate resolved to v4 %s", v6[0].IP)
	}
}

// TestF5UnknownDCIDRejected: a packet whose DCID is neither current nor
// an alias fails to open (wrong candidate fails DCID before AEAD).
func TestF5UnknownDCIDRejected(t *testing.T) {	sender := testSignatureSession()
	receiver := testSignatureSession()
	ping := EncodeUDPFrame(UDPFramePing, 0, nil)
	pkt, _, err := sender.SealTrackedPacket(DirC2S, [][]byte{ping})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Rotate the receiver to an unrelated DCID without aliasing the
	// sender's DCID: first rotate to something else, then expire the
	// alias by hand (same-package test may touch the map).
	var other [8]byte
	for i := range other {
		other[i] = byte(0xF0 + i)
	}
	receiver.RotateDCID(other)
	receiver.mu.Lock()
	for dcid := range receiver.dcidAliases {
		receiver.dcidAliases[dcid] = time.Now().Add(-time.Second)
	}
	receiver.mu.Unlock()
	if _, _, err := receiver.OpenPacket(DirC2S, pkt); err == nil {
		t.Fatal("packet with expired-alias DCID should be rejected")
	}
}
