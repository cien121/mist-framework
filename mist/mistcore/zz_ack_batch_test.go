// ACK batch test: verify burst bound under batched ACK arrivals.
//
// Real devices (especially on WiFi) receive ACKs in batches, not uniformly.
// This test verifies the token bucket mechanism: each packet sent must
// consume tokens, and the total in any window T must not exceed C + R*T.
package mistcore

import (
	"testing"
	"time"
)

// TestAckBatchBurstBound verifies the token bucket bound under batched ACKs.
func TestAckBatchBurstBound(t *testing.T) {
	clock := newSchedManualClock()
	var sid [16]byte
	var k1, k2 [32]byte
	sess := NewUDPSession(sid, k1, k2, nil, nil)
	// BBR nil => fallback pacing rate: 10 * 1350 bytes/sec.
	// R = 13500 / 1000 / 1241 ≈ 0.0109 packets/ms.
	sess.BBR = nil
	sess.Rel = nil

	var sentTimes []time.Time
	sched := NewUDPSendScheduler(sess, DirC2S, func(pkt []byte) error {
		sentTimes = append(sentTimes, clock.Now())
		return nil
	})
	sched.now = clock.Now
	sched.newTimer = clock.NewTimer

	// Queue 100 packets.
	for i := 0; i < 100; i++ {
		frame := make([]byte, 1200)
		if err := sched.Write([][]byte{frame}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Simulate: drain, advance 15ms, repeat (like batched ACK wakeups).
	for batch := 0; batch < 10; batch++ {
		for sched.trySend() {
		}
		clock.Advance(15 * time.Millisecond)
	}

	// Verify bound: packets in any T ms window <= C + R*T.
	// C = 4, R = 0.0109 pkt/ms (fallback rate).
	const C = float64(UDPSchedulerBucketPackets)
	const R = 13500.0 / 1000 / 1241 // packets per ms

	for _, windowMs := range []float64{1, 5, 10} {
		bound := C + R*windowMs
		for i := 0; i < len(sentTimes); i++ {
			count := 0
			windowEnd := sentTimes[i].Add(time.Duration(windowMs * float64(time.Millisecond)))
			for j := i; j < len(sentTimes) && !sentTimes[j].After(windowEnd); j++ {
				count++
			}
			if float64(count) > bound+0.5 { // +0.5 for integer rounding
				t.Fatalf("window %.0fms: got %d packets, bound %.2f", windowMs, count, bound)
			}
		}
	}
	t.Logf("ACK batch test passed")
}
