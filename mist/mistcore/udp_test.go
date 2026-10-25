package mistcore

import (
	"bytes"
	"testing"
)

// Test UDP frame encode/decode roundtrip.
func TestUDPFrameCodec(t *testing.T) {
	payload := []byte("hello world")
	encoded := EncodeUDPFrame(UDPFrameStream, 1, payload)

	frames, err := DecodeUDPFrames(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].Type != UDPFrameStream {
		t.Errorf("type mismatch: got %02x", frames[0].Type)
	}
	if frames[0].SID != 1 {
		t.Errorf("sid mismatch: got %d", frames[0].SID)
	}
	if !bytes.Equal(frames[0].Payload, payload) {
		t.Errorf("payload mismatch")
	}
}

// Test multiple frames in one packet.
func TestUDPFrameMulti(t *testing.T) {
	f1 := EncodeUDPFrame(UDPFramePing, 0, nil)
	f2 := EncodeStreamFrame(1, 0, []byte("data"))
	f3 := EncodeFinFrame(1, 4)

	combined := append(append(f1, f2...), f3...)
	frames, err := DecodeUDPFrames(combined)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(frames))
	}
	if frames[0].Type != UDPFramePing || frames[1].Type != UDPFrameStream || frames[2].Type != UDPFrameFin {
		t.Errorf("frame type order wrong")
	}
}

// Test STREAM frame with offset.
func TestUDPStreamOffset(t *testing.T) {
	data := []byte("test data")
	encoded := EncodeStreamFrame(5, 12345, data)
	frames, err := DecodeUDPFrames(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(frames[0].Payload) < 8 {
		t.Fatalf("stream payload too short")
	}
	// OFFSET is first 8 bytes, big-endian.
	offset := uint64(frames[0].Payload[0])<<56 | uint64(frames[0].Payload[1])<<48 |
		uint64(frames[0].Payload[2])<<40 | uint64(frames[0].Payload[3])<<32 |
		uint64(frames[0].Payload[4])<<24 | uint64(frames[0].Payload[5])<<16 |
		uint64(frames[0].Payload[6])<<8 | uint64(frames[0].Payload[7])
	if offset != 12345 {
		t.Errorf("offset mismatch: got %d", offset)
	}
	if !bytes.Equal(frames[0].Payload[8:], data) {
		t.Errorf("data mismatch")
	}
}

// Test short header build/parse roundtrip.
func TestUDPShortHeader(t *testing.T) {
	var dcid [8]byte
	for i := range dcid {
		dcid[i] = byte(i)
	}
	header := BuildShortHeader(dcid, 42, false)
	if len(header) != 13 {
		t.Fatalf("header len != 13")
	}
	parsedDCID, pktNum, spin, err := ParseShortHeader(header[:])
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsedDCID != dcid {
		t.Errorf("dcid mismatch")
	}
	if pktNum != 42 {
		t.Errorf("packet num mismatch: got %d", pktNum)
	}
	if spin {
		t.Errorf("spin should be false")
	}
}

// Test UDP nonce construction.
func TestUDPNonce(t *testing.T) {
	var sid [8]byte
	for i := range sid {
		sid[i] = byte(i + 10)
	}
	nonce := UDPNonce(sid, DirC2S, 12345)
	if len(nonce) != 24 {
		t.Fatalf("nonce len != 24")
	}
	// Check session ID.
	if !bytes.Equal(nonce[0:8], sid[:]) {
		t.Errorf("session id mismatch")
	}
	// Check dir (big-endian).
	if nonce[8] != 0 || nonce[9] != 0 || nonce[10] != 0 || nonce[11] != 0 {
		t.Errorf("dir should be 0 for C2S")
	}
	// Check packet number.
	pktNum := uint32(nonce[12])<<24 | uint32(nonce[13])<<16 | uint32(nonce[14])<<8 | uint32(nonce[15])
	if pktNum != 12345 {
		t.Errorf("packet num mismatch: got %d", pktNum)
	}
	// Reserved should be zero.
	for i := 16; i < 24; i++ {
		if nonce[i] != 0 {
			t.Errorf("reserved byte %d not zero", i)
		}
	}
}

// Test UDP AEAD seal/open roundtrip.
func TestUDPSealOpen(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	var nonce [24]byte
	for i := range nonce {
		nonce[i] = byte(i * 2)
	}
	plaintext := []byte("secret message")
	aad := []byte("header")

	ciphertext, err := UDPSeal(&key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	if len(ciphertext) != len(plaintext)+16 {
		t.Errorf("ciphertext len wrong: got %d", len(ciphertext))
	}

	decrypted, err := UDPOpen(&key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch")
	}

	// Wrong AAD should fail.
	_, err = UDPOpen(&key, nonce, ciphertext, []byte("wrong"))
	if err == nil {
		t.Errorf("open with wrong AAD should fail")
	}
}

// Test InitialCodec seal/open roundtrip (QUICInitialCodec, Phase 0).
func TestInitialCodec(t *testing.T) {
	codec := &QUICInitialCodec{}
	var dcid, scid [8]byte
	for i := range dcid {
		dcid[i] = byte(i)
		scid[i] = byte(i + 100)
	}
	payload := []byte("auth payload data")

	packet, err := codec.SealInitial(payload, dcid, scid, 0)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}

	opened, rdcid, rscid, pktNum, err := codec.OpenInitial(packet)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if !bytes.Equal(opened, payload) {
		t.Errorf("payload mismatch")
	}
	if rdcid != dcid {
		t.Errorf("dcid mismatch")
	}
	if rscid != scid {
		t.Errorf("scid mismatch")
	}
	if pktNum != 0 {
		t.Errorf("packet num mismatch")
	}
}

// Test session seal/open packet roundtrip.
func TestUDPSessionPacket(t *testing.T) {
	var sid [16]byte
	for i := range sid {
		sid[i] = byte(i)
	}
	var kC2S, kS2C [32]byte
	for i := range kC2S {
		kC2S[i] = byte(i)
		kS2C[i] = byte(255 - i)
	}
	codec := &QUICInitialCodec{}
	session := NewUDPSession(sid, kC2S, kS2C, nil, codec)

	// Client seals a packet (C2S).
	frames := [][]byte{
		EncodeUDPFrame(UDPFramePing, 0, nil),
		EncodeStreamFrame(1, 0, []byte("hello")),
	}
	datagram, err := session.sealPacketTracked(DirC2S, frames)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}

	// Server opens it (expects C2S).
	opened, pktNum, err := session.OpenPacket(DirC2S, datagram)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if pktNum != 0 {
		t.Errorf("packet num should be 0, got %d", pktNum)
	}
	if len(opened) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(opened))
	}
	if opened[0].Type != UDPFramePing {
		t.Errorf("first frame should be PING")
	}
	if opened[1].Type != UDPFrameStream {
		t.Errorf("second frame should be STREAM")
	}

	// Wrong direction should fail (different key).
	_, _, err = session.OpenPacket(DirS2C, datagram)
	if err == nil {
		t.Errorf("open with wrong direction key should fail")
	}
}
