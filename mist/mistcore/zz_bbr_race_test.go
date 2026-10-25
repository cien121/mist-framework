package mistcore

import (
	"sync"
	"testing"
	"time"
)

// Regression: BBRController is called from three goroutines in production:
//   - scheduler loop: PacingRate / CongestionWindow / CanSend / OnPacketSent
//   - readPump:       OnPacketAcked (via Rel.ProcessAck, under Rel.mu)
//   - tickLoop:       OnPacketLost  (via Rel.CheckRTO, under Rel.mu)
//
// The scheduler path holds sched.mu, the other two hold Rel.mu: different
// outer locks, so before the 2026-10-25 fix the BBR internals
// (bbrSender, sampler, pacer, filters) were accessed concurrently with
// no mutual exclusion — -race showed 200+ races and the sampler ring
// buffer corrupted its indices and panicked, killing the app process
// through JNI (1.0.41 freeze + crash). BBRController.mu now serializes
// all of it; this test must pass clean under -race.
func TestBBRControllerConcurrentRace(t *testing.T) {
	bbr := NewBBRController(1350)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Scheduler-like caller.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var pn uint32
		for {
			select {
			case <-stop:
				return
			default:
			}
			pn++
			bbr.OnPacketSent(pn, 1300, 13000)
			_ = bbr.PacingRate()
			_ = bbr.CongestionWindow()
			_ = bbr.CanSend(13000)
		}
	}()
	// readPump-like caller (ACKs).
	wg.Add(1)
	go func() {
		defer wg.Done()
		var pn uint32
		for {
			select {
			case <-stop:
				return
			default:
			}
			pn++
			bbr.OnPacketAcked(pn, 1300, 13000, 200*time.Millisecond)
		}
	}()
	// tickLoop-like caller (losses).
	wg.Add(1)
	go func() {
		defer wg.Done()
		var pn uint32
		for {
			select {
			case <-stop:
				return
			default:
			}
			pn++
			bbr.OnPacketLost(pn, 1300, 13000)
		}
	}()
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
}
