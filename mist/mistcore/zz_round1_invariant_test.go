// Round 1 validation: prove the invariant tests catch the old direct-send bug.
//
// This test mimics the OLD send pattern (direct seal + send, no scheduler,
// no cwnd gate) and asserts the cwnd invariant. It MUST FAIL (red) because
// the old path lets inflight grow unbounded while cwnd stays at 10 packets.
//
// If this test is GREEN, the invariant check is broken and the scheduler's
// "passing" tests are meaningless.

package mistcore

import (
	"testing"
)

// TestRound1OldPathViolatesCwnd sends 874 packets via the direct path
// (seal + immediate "send", no scheduler) and asserts inflight <= cwnd.
// Expected: FAIL - inflight reaches 874*1350 while cwnd stays ~10*1350.
func TestRound1OldPathViolatesCwnd(t *testing.T) {
	var sid [16]byte
	for i := range sid {
		sid[i] = byte(i)
	}
	var k1, k2 [32]byte
	for i := range k1 {
		k1[i] = 0x11
		k2[i] = 0x22
	}
	sess := NewUDPSession(sid, k1, k2, nil, nil)

	// Simulate the OLD direct-send pattern: seal packet, "send" immediately,
	// no cwnd check, no pacing. This is what cmd/mist-udp-test did before
	// the scheduler.
	violations := 0
	for i := 0; i < 874; i++ {
		// Build a dummy frame (1300 bytes payload).
		frame := make([]byte, 1300)
		frame[0] = 0x01 // STREAM frame type

		// Seal (internal API, same as old public SealPacket).
		_, err := sess.sealPacketTracked(DirC2S, [][]byte{frame})
		if err != nil {
			t.Fatalf("seal failed at packet %d: %v", i, err)
		}
		// "Send" immediately - no gate. This is the bug.

		// Check invariant AFTER accounting (sealPacketTracked calls
		// Rel.PacketSent and BBR.OnPacketSent).
		inflight := sess.Rel.BytesInFlight()
		cwnd := sess.BBR.CongestionWindow()
		if inflight > cwnd {
			violations++
			if violations == 1 {
				t.Logf("FIRST VIOLATION at packet %d: inflight=%d > cwnd=%d",
					i, inflight, cwnd)
			}
		}
	}

	if violations == 0 {
		t.Errorf("expected cwnd invariant violations on old direct-send path, got 0 - test is broken")
	} else {
		t.Logf("OK (red as expected): %d/874 packets violated inflight<=cwnd", violations)
		// Deliberately fail to prove the test catches the bug.
		t.Errorf("ROUND1: old path violates cwnd invariant (%d violations) - test correctly RED", violations)
	}
}

// TestRound1BurstUnbounded verifies that the old path can emit hundreds of
// packets in a sub-millisecond burst with no pacing.
func TestRound1BurstUnbounded(t *testing.T) {
	var sid [16]byte
	var k1, k2 [32]byte
	sess := NewUDPSession(sid, k1, k2, nil, nil)

	// Count how many packets can be "sent" without any delay.
	// Old path: all 874 go out immediately.
	sent := 0
	for i := 0; i < 874; i++ {
		frame := make([]byte, 1300)
		frame[0] = 0x01
		if _, err := sess.sealPacketTracked(DirC2S, [][]byte{frame}); err != nil {
			t.Fatalf("seal failed: %v", err)
		}
		sent++
	}

	// If we got here without blocking, the burst was unbounded.
	// A proper scheduler would have blocked after ~10 packets (initial cwnd).
	t.Logf("sent %d packets with zero blocking", sent)
	if sent == 874 {
		t.Errorf("ROUND1: old path sent all 874 packets with no gating - test correctly RED (unbounded burst)")
	}
}
