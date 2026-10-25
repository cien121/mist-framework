// Late wakeup test: verify burst upper bound is guaranteed by code,
// not by timer accuracy.
//
// If the scheduler's timer wakes up late (common on phones: Go timers can
// be delayed by milliseconds under load), the token bucket refill must
// still be capped at capacity. A late wakeup must not release more than
// UDPSchedulerBucketPackets worth of packets in a burst.
//
// This is a deterministic test using the manual clock: we advance time by
// 5ms/20ms/100ms without firing the timer, then verify trySend() releases
// at most bucket capacity packets.
package mistcore

import (
	"testing"
	"time"
)

// TestLateWakeupBurstBound verifies that after a long elapsed time (simulating
// a late timer wakeup), the scheduler does not release more than bucket
// capacity packets in a burst.
func TestLateWakeupBurstBound(t *testing.T) {
	for _, lateBy := range []time.Duration{5 * time.Millisecond, 20 * time.Millisecond, 100 * time.Millisecond} {
		t.Run(lateBy.String(), func(t *testing.T) {
			clock := newSchedManualClock()
			var sid [16]byte
			var k1, k2 [32]byte
			sess := NewUDPSession(sid, k1, k2, nil, nil)
			// Disable BBR/cwnd gate for this test: focus on pacing bucket.
			sess.BBR = nil
			sess.Rel = nil

			sent := 0
			sched := NewUDPSendScheduler(sess, DirC2S, func(pkt []byte) error {
				sent++
				return nil
			})
			sched.now = clock.Now
			sched.newTimer = clock.NewTimer

			// Queue 100 packets (each 1200 bytes).
			for i := 0; i < 100; i++ {
				frame := make([]byte, 1200)
				if err := sched.Write([][]byte{frame}); err != nil {
					t.Fatalf("write %d: %v", i, err)
				}
			}

			// Drain initial burst (bucket starts full: 4 packets).
			initial := 0
			for sched.trySend() {
				initial++
			}
			if initial != UDPSchedulerBucketPackets {
				t.Fatalf("initial burst = %d, want %d", initial, UDPSchedulerBucketPackets)
			}

			// Simulate late wakeup: advance clock by lateBy WITHOUT
			// firing the timer. The next trySend() will call refillLocked()
			// with the full elapsed time.
			clock.Advance(lateBy)

			// Count packets in the post-wakeup burst.
			burst := 0
			for sched.trySend() {
				burst++
				// Safety: don't loop forever if something is wrong.
				if burst > 100 {
					t.Fatalf("burst exceeded 100, tokens not capped?")
				}
			}

			// The burst must not exceed bucket capacity.
			// (Refill is capped at capacity, so late wakeup cannot
			// accumulate more than 4 packets worth of tokens.)
			if burst > UDPSchedulerBucketPackets {
				t.Fatalf("late wakeup (%v): burst = %d, want <= %d (bucket capacity)",
					lateBy, burst, UDPSchedulerBucketPackets)
			}
			t.Logf("late wakeup (%v): burst = %d (capacity %d) OK",
				lateBy, burst, UDPSchedulerBucketPackets)
		})
	}
}
