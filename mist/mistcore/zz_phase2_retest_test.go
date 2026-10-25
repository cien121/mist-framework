// Phase 2 re-test (2026-10-23, user-directed): 5% random loss + 200ms RTT
// through the scheduler+BBR, measuring link utilization vs the 85%
// baseline measured before the scheduler existed.
//
// If utilization drops below 70%, the DRAIN-stuck issue is likely the
// cause (open issue, not a known limitation).
package mistcore

import (
	"context"
	"math"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"
)

func TestZZPhase2Retest(t *testing.T) {
	withWatchdog(t, 300*time.Second, func(context.Context) {
		const baseRTT = 200 * time.Millisecond
		const ackDelay = 10 * time.Millisecond
		const stepDur = 5 * time.Millisecond
		const linkRateBps = 8e6 // 8Mbps like the original Phase 2 cell
		const lossRate = 0.05
		const nPackets = 8740 // ~10MB

		packetsPerStep := int(math.Round(linkRateBps * stepDur.Seconds() / (nominalSealedPktBytes * 8)))
		if packetsPerStep < 1 {
			packetsPerStep = 1
		}

		clock := newSchedManualClock()
		sess := testSchedulerSession()
		sess.BBR = NewBBRControllerWithClock(1350, &bbrClockAdapter{clock})
		rel := NewUDPReliability(sess.BBR)
		rel.now = clock.Now
		sess.Rel = rel
		// Deep queue (no bottleneck drops); loss is random 5%.
		acks := newFaithfulAckSim(clock, sess, baseRTT, ackDelay)
		acks.checkCwnd = sess.BBR.CongestionWindow()

		rng := rand.New(rand.NewSource(42))
		var lastWasRtx atomic.Bool
		var sentTotal, dropped atomic.Int64
		var wireBytesOrig atomic.Int64

		sendFunc := func(pkt []byte) error {
			if rng.Float64() < lossRate {
				dropped.Add(1)
				acks.onSendNoAck(len(pkt))
				return nil
			}
			sentTotal.Add(1)
			wireBytesOrig.Add(int64(len(pkt)))
			// No queueing: releaseDelay ~0, ACK at baseRTT+ackDelay.
			acks.onSend(len(pkt), 0)
			return nil
		}
		sched := NewUDPSendScheduler(sess, DirC2S, sendFunc)
		sched.now = clock.Now
		sched.newTimer = clock.NewTimer
		sched.dequeueHook = func(wasRtx bool) { lastWasRtx.Store(wasRtx) }
		acks.sched = sched
		sess.Rel.OnRetransmit = func(frames [][]byte) error {
			return sched.WriteRetransmitChunked(frames)
		}
		sess.Rel.OnPacketsRetired = func(pns []uint32, bytes []int) {
			acks.onPacketsRetired(pns, bytes)
		}

		payload := make([]byte, 1200)
		enqueued := 0
		start := clock.Now()
		completed := false
		maxDrainSteps := 0
		curDrainSteps := 0
		for step := 0; step < 60000; step++ {
			for i := 0; i < 10 && enqueued < nPackets; i++ {
				sched.mu.Lock()
				full := sched.queueLen >= UDPSchedulerMaxQueue
				sched.mu.Unlock()
				if full {
					break
				}
				fr := EncodeUDPFrame(UDPFrameStream, byte(enqueued), payload)
				if err := sched.Write([][]byte{fr}); err != nil {
					t.Fatalf("Write %d: %v", enqueued, err)
				}
				enqueued++
			}
			for {
				acks.mu.Lock()
				acks.checkCwnd = sess.BBR.CongestionWindow()
				acks.mu.Unlock()
				if !sched.trySend() {
					break
				}
			}
			sess.Rel.CheckRTO()
			for {
				acks.mu.Lock()
				acks.checkCwnd = sess.BBR.CongestionWindow()
				acks.mu.Unlock()
				if !sched.trySend() {
					break
				}
			}
			clock.Advance(stepDur)
			acks.fireDue()

			if sess.BBR.InDrain() {
				curDrainSteps++
			} else {
				if curDrainSteps > maxDrainSteps {
					maxDrainSteps = curDrainSteps
				}
				curDrainSteps = 0
			}

			if enqueued == nPackets && acks.testInflight() == 0 {
				sched.mu.Lock()
				qlen := sched.queueLen
				sched.mu.Unlock()
				if qlen == 0 {
					completed = true
					break
				}
			}
		}
		if curDrainSteps > maxDrainSteps {
			maxDrainSteps = curDrainSteps
		}
		elapsed := clock.Now().Sub(start)

		// Utilization: original bytes / (link rate * elapsed).
		// Note: retransmits waste capacity; utilization counts only
		// original bytes vs theoretical max.
		trueByteRate := float64(packetsPerStep) * nominalSealedPktBytes / stepDur.Seconds()
		util := float64(wireBytesOrig.Load()) / (trueByteRate * elapsed.Seconds()) * 100

		t.Logf("5%%loss/200ms: completed=%v elapsed=%v sent=%d dropped=%d wireOrig=%d util=%.1f%% maxDrainSteps=%d (%.1fms)",
			completed, elapsed, sentTotal.Load(), dropped.Load(), wireBytesOrig.Load(),
			util, maxDrainSteps, float64(maxDrainSteps)*5)
		if !completed {
			t.Fatal("transfer did not complete")
		}
	})
}
