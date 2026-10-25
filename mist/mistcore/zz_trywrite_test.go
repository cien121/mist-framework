package mistcore

import (
	"net"
	"testing"
)

// TestSchedulerTryWrite: TryWrite never blocks — it drops when the
// queue is full (teardown FIN/RST path) and accepts when there is
// room. The blocking Write is for data backpressure only; teardown
// must never wedge on it (1.0.41 freeze).
func TestSchedulerTryWrite(t *testing.T) {
	var sid [16]byte
	var kC2S, kS2C [32]byte
	session := NewUDPSession(sid, kC2S, kS2C, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}, &QUICInitialCodec{})
	sched := NewUDPSendScheduler(session, DirC2S, func([]byte) error { return nil })
	// Never started: the queue never drains.
	for i := 0; i < UDPSchedulerMaxQueue+10; i++ {
		sched.WriteRetransmit([][]byte{[]byte("x")})
	}
	if sched.TryWrite([][]byte{[]byte("fin")}) {
		t.Fatal("TryWrite on a full queue should drop (false)")
	}
	fresh := NewUDPSendScheduler(session, DirC2S, func([]byte) error { return nil })
	if !fresh.TryWrite([][]byte{[]byte("fin")}) {
		t.Fatal("TryWrite with room should accept (true)")
	}
	if fresh.queueLen != 1 {
		t.Fatalf("queueLen = %d, want 1", fresh.queueLen)
	}
}
