package mistcore

import (
	"testing"
	"time"
)

// TestHeaderProtectRoundTrip verifies mask apply/remove round-trip.
func TestHeaderProtectRoundTrip(t *testing.T) {
	var hpKey [32]byte
	for i := range hpKey {
		hpKey[i] = byte(i * 7)
	}
	var dcid [8]byte
	for i := range dcid {
		dcid[i] = byte(i + 1)
	}

	// Build a header, apply protection, then remove.
	orig := BuildShortHeader(dcid, 42, false) // 2-byte pn form: 11 bytes
	// Fake ciphertext (need 16 bytes for sample).
	ciphertext := make([]byte, 32)
	for i := range ciphertext {
		ciphertext[i] = byte(i * 3)
	}
	sample := ciphertext[:16]

	masked := make([]byte, len(orig))
	copy(masked, orig)
	if err := ApplyHeaderProtection(masked, hpKey, sample); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Masked header should differ (packet number masked: bytes 9,10).
	if masked[9] == orig[9] && masked[10] == orig[10] {
		t.Fatal("header protection did not change packet number")
	}
	// Spin bit (bit 5) should be unchanged.
	if (masked[0] & 0x20) != (orig[0] & 0x20) {
		t.Fatal("spin bit was masked (should stay)")
	}
	// Remove protection.
	unmasked := append([]byte(nil), masked...)
	if err := RemoveHeaderProtection(unmasked, hpKey, sample); err != nil {
		t.Fatalf("remove: %v", err)
	}
	for i := range orig {
		if unmasked[i] != orig[i] {
			t.Fatalf("round-trip mismatch at byte %d", i)
		}
	}
}

// TestHeaderProtectSampleRequires16Bytes verifies sample length check.
func TestHeaderProtectSampleRequires16Bytes(t *testing.T) {
	var hpKey [32]byte
	hdr := make([]byte, QUICShortHeaderLen)
	short := make([]byte, 10) // too short
	if err := ApplyHeaderProtection(hdr, hpKey, short); err == nil {
		t.Fatal("expected error for short sample")
	}
}

// TestSessionSealOpenWithProtection verifies end-to-end with header protection.
func TestSessionSealOpenWithProtection(t *testing.T) {
	var sid [16]byte
	var kC2S, kS2C [32]byte
	for i := range sid {
		sid[i] = byte(i)
	}
	for i := range kC2S {
		kC2S[i] = byte(i + 10)
		kS2C[i] = byte(i + 20)
	}
	sess := NewUDPSession(sid, kC2S, kS2C, nil, nil)

	// Seal a packet.
	ping := EncodeUDPFrame(UDPFramePing, 0, []byte("hello"))
	datagram, err := sess.sealPacketTracked(DirC2S, [][]byte{ping})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// The packet number in the datagram should be masked (not 0).
	// First packet: real number 0, masked should differ (unless mask happens to be 0).
	// We can't assert inequality reliably, but we can verify OpenPacket works.

	// Open it back.
	frames, pktNum, err := sess.OpenPacket(DirC2S, datagram)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if pktNum != 0 {
		t.Fatalf("expected packet 0, got %d", pktNum)
	}
	if len(frames) != 1 || frames[0].Type != UDPFramePing {
		t.Fatalf("unexpected frames: %+v", frames)
	}
}

// TestSlidingWindowBasic verifies mark/duplicate detection.
func TestSlidingWindowBasic(t *testing.T) {
	w := NewSlidingWindow()
	if !w.Mark(0) {
		t.Fatal("first mark(0) should be new")
	}
	if w.Mark(0) {
		t.Fatal("second mark(0) should be duplicate")
	}
	if !w.Mark(5) {
		t.Fatal("mark(5) should be new")
	}
	if w.Largest() != 5 {
		t.Fatalf("largest = %d, want 5", w.Largest())
	}
	ranges := w.Ranges(8)
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d: %v", len(ranges), ranges)
	}
	// Ranges ordered high to low: [5,5], [0,0].
	if ranges[0] != [2]uint32{5, 5} || ranges[1] != [2]uint32{0, 0} {
		t.Fatalf("unexpected ranges: %v", ranges)
	}
}

// TestSlidingWindowContiguous verifies single range for contiguous packets.
func TestSlidingWindowContiguous(t *testing.T) {
	w := NewSlidingWindow()
	for i := uint32(0); i < 10; i++ {
		w.Mark(i)
	}
	ranges := w.Ranges(8)
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %v", ranges)
	}
	if ranges[0] != [2]uint32{0, 9} {
		t.Fatalf("unexpected range: %v", ranges[0])
	}
}

// TestReliabilityAckFlow verifies sent→acked flow.
func TestReliabilityAckFlow(t *testing.T) {
	bbrCtl := NewBBRController(1350)
	rel := NewUDPReliability(bbrCtl)

	frames := [][]byte{EncodeUDPFrame(UDPFramePing, 0, nil)}
	rel.PacketSent(0, frames, 100)
	rel.PacketSent(1, frames, 100)
	if rel.BytesInFlight() != 200 {
		t.Fatalf("inflight = %d, want 200", rel.BytesInFlight())
	}

	// Ack packet 0.
	if !rel.PacketAcked(0, 50*time.Millisecond) {
		t.Fatal("packet 0 should be newly acked")
	}
	if rel.BytesInFlight() != 100 {
		t.Fatalf("inflight = %d, want 100", rel.BytesInFlight())
	}
	// Duplicate ack should return false.
	if rel.PacketAcked(0, 50*time.Millisecond) {
		t.Fatal("duplicate ack should return false")
	}
}

// TestReliabilityFastRetransmit verifies 3-dup-ACK triggers retransmit.
func TestReliabilityFastRetransmit(t *testing.T) {
	bbrCtl := NewBBRController(1350)
	rel := NewUDPReliability(bbrCtl)

	var retransmitted [][]byte
	rel.OnRetransmit = func(frames [][]byte) error {
		retransmitted = frames
		return nil
	}

	frames := [][]byte{EncodeUDPFrame(UDPFramePing, 0, nil)}
	rel.PacketSent(0, frames, 100) // will be "lost"
	rel.PacketSent(1, frames, 100)
	rel.PacketSent(2, frames, 100)
	rel.PacketSent(3, frames, 100)

	// Ack 1,2,3 without acking 0 → 3 dup ACKs (largest stays at 3).
	// First ACK advances largest to 1.
	rel.ProcessAck(1, 0, [][2]uint32{{1, 1}})
	// These don't advance largest beyond... actually largest goes 1→2→3.
	// To simulate dup ACKs, we ack the same largest repeatedly.
	// Simpler: ack packets 1,2,3 in a way that largest stays.
	// Let's do: ack {2,2}, {3,3} etc. Actually ProcessAck with largest=3
	// three times counts as dup.
	rel.ProcessAck(3, 0, [][2]uint32{{1, 3}})
	rel.ProcessAck(3, 0, [][2]uint32{{1, 3}})
	rel.ProcessAck(3, 0, [][2]uint32{{1, 3}})
	rel.ProcessAck(3, 0, [][2]uint32{{1, 3}})
	// Fourth dup (3rd counted) should trigger fast retransmit of packet 0.
	if len(retransmitted) == 0 {
		t.Fatal("expected fast retransmit after 3 dup ACKs")
	}
}

// TestBBRBasic verifies BBR controller basic operation.
func TestBBRBasic(t *testing.T) {
	ctl := NewBBRController(1350)
	if ctl.CongestionWindow() <= 0 {
		t.Fatal("congestion window should be positive")
	}
	// Initial window: 10 packets * 1350 bytes.
	if got := ctl.CongestionWindow(); got != 10*1350 {
		t.Fatalf("initial cwnd = %d, want %d", got, 10*1350)
	}
	// Pacing rate should be positive.
	if ctl.PacingRate() <= 0 {
		t.Fatal("pacing rate should be positive")
	}
	// CanSend with empty flight.
	if !ctl.CanSend(0) {
		t.Fatal("should be able to send with empty flight")
	}
	// Simulate sending and acking.
	ctl.OnPacketSent(0, 1350, 0)
	ctl.OnPacketAcked(0, 1350, 0, 50*time.Millisecond)
	if ctl.SmoothedRTT() != 50*time.Millisecond {
		t.Fatalf("smoothed RTT = %v, want 50ms", ctl.SmoothedRTT())
	}
}

// TestPacerBasic verifies pacing delays.
func TestPacerBasic(t *testing.T) {
	p := NewUDPPacer(1000) // 1000 bytes/sec
	// First packet: no delay (nextSendTime starts at now).
	if d := p.Delay(); d > 10*time.Millisecond {
		t.Fatalf("first packet delay = %v, want ~0", d)
	}
	p.PacketSent(1000) // 1000 bytes at 1000 B/s = 1 second
	if d := p.Delay(); d < 900*time.Millisecond || d > 1100*time.Millisecond {
		t.Fatalf("delay after 1000B = %v, want ~1s", d)
	}
}

// TestStreamFlowControl verifies window accounting.
func TestStreamFlowControl(t *testing.T) {
	fc := NewStreamFlowControl()
	if got := fc.CanSend(1000); got != 1000 {
		t.Fatalf("CanSend = %d, want 1000", got)
	}
	fc.Sent(1000)
	if got := fc.CanSend(UDPStreamWindowInitial); got != UDPStreamWindowInitial-1000 {
		t.Fatalf("CanSend after sent = %d", got)
	}
	// Receive half window → should trigger WINDOW_UPDATE.
	half := uint64(UDPStreamWindowInitial / 2)
	if !fc.Received(half) {
		t.Fatal("should trigger WINDOW_UPDATE at half window")
	}
	newWin := fc.WindowUpdate()
	if newWin != half+UDPStreamWindowInitial {
		t.Fatalf("new window = %d", newWin)
	}
}
