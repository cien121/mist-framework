package core

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"mist/mistcore"
)

// testClient builds a MistUDPClient with no network: a real scheduler
// (never started, so its queue never drains) and an empty stream
// table. Used to prove teardown paths never block on a wedged
// session (1.0.41 freeze: stream Close blocked on a full scheduler
// queue / wedged writer, wedging e.mu and the whole tunnel).
func testClient(t *testing.T) *MistUDPClient {
	t.Helper()
	var sid [16]byte
	var kC2S, kS2C [32]byte
	session := mistcore.NewUDPSession(sid, kC2S, kS2C, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}, &mistcore.QUICInitialCodec{})
	sched := mistcore.NewUDPSendScheduler(session, mistcore.DirC2S, func([]byte) error { return nil })
	return &MistUDPClient{
		sched:   sched,
		streams: make(map[byte]*mistStreamConn),
		done:    make(chan struct{}),
	}
}

// closePrompt asserts fn returns within d, failing the test otherwise
// (a blocked Close would hang the test binary without this guard).
func closePrompt(t *testing.T, d time.Duration, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v (wedged close path)", name, d)
	}
}

// TestStreamClosePromptWithFullScheduler: the scheduler queue is full
// and the send loop is not running (wedged session). The old Close
// blocked forever in sched.Write; the new Close drops the FIN via
// TryWrite and returns promptly.
func TestStreamClosePromptWithFullScheduler(t *testing.T) {
	c := testClient(t)
	for i := 0; i < 300; i++ {
		c.sched.WriteRetransmit([][]byte{[]byte("x")})
	}
	st := newMistStreamConn(c, 7, "example.com:443")
	c.streams[7] = st
	closePrompt(t, 2*time.Second, "stream Close with full scheduler", func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if !st.closed {
		t.Fatal("stream not marked closed")
	}
	if _, ok := c.streams[7]; ok {
		t.Fatal("SID not freed on Close")
	}
	if _, err := st.Write([]byte("after close")); err == nil {
		t.Fatal("Write after Close should fail")
	}
}

// TestStreamClosePromptWithWedgedWriter: a Write holds writeMu
// (wedged in scheduler Write). The old Close blocked on writeMu
// forever; the new Close takes the TryLock-fail path: it frees the
// SID and unblocks readers without waiting for the writer.
func TestStreamClosePromptWithWedgedWriter(t *testing.T) {
	c := testClient(t)
	st := newMistStreamConn(c, 9, "example.com:443")
	c.streams[9] = st
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	closePrompt(t, 2*time.Second, "stream Close with wedged writer", func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if !st.closed {
		t.Fatal("stream not marked closed")
	}
	if _, ok := c.streams[9]; ok {
		t.Fatal("SID not freed on wedged Close")
	}
}

// TestStreamPendingCapResets: out-of-order chunks that never fill
// their gap must trip the reorder cap and reset the stream instead
// of growing pending forever (the 1.0.41 memory-eating path).
func TestStreamPendingCapResets(t *testing.T) {
	c := testClient(t)
	st := newMistStreamConn(c, 3, "example.com:443")
	c.streams[3] = st
	chunk := make([]byte, 1200)
	// Gap at [0,1200): every chunk lands in pending.
	for i := 0; ; i++ {
		off := uint64(1200 + i*1200)
		payload := make([]byte, 8+len(chunk))
		binary.BigEndian.PutUint64(payload, off)
		copy(payload[8:], chunk)
		st.deliver(mistcore.UDPFrame{Type: mistcore.UDPFrameStream, SID: 3, Payload: payload})
		if st.closed {
			break
		}
		if i > 50000 {
			t.Fatal("pending cap never tripped")
		}
	}
	if !errors.Is(st.err, errPendingOverflow) {
		t.Fatalf("stream err = %v, want errPendingOverflow", st.err)
	}
	if _, ok := c.streams[3]; ok {
		t.Fatal("reset stream not removed from table")
	}
	if got := c.pendingRSTs.Load(); got != 1 {
		t.Fatalf("pendingRSTs = %d, want 1", got)
	}
	// A blocked Read must return the reset error, not hang.
	st2 := newMistStreamConn(c, 4, "example.com:443")
	st2.markClosed(errors.New("x"))
	if _, err := st2.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read on closed stream should fail")
	}
}

// TestWatchdogCountsStalledPump: a readPump that stops iterating
// (wedged, not exited) is counted exactly once per episode.
func TestWatchdogCountsStalledPump(t *testing.T) {
	c := &MistUDPClient{done: make(chan struct{})}
	c.pumpLastIter.Store(time.Now().Add(-10 * time.Second).UnixNano())
	c.wg.Add(1)
	go c.watchdogLoop(10*time.Millisecond, 50*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for c.pumpDeaths.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := c.pumpDeaths.Load(); got != 1 {
		t.Fatalf("pumpDeaths = %d, want 1 (one episode)", got)
	}
	// Fresh iterations clear the episode: simulate a live pump
	// refreshing every 10ms (production refreshes at least every
	// 500ms against a 2s stale threshold, so a live pump never
	// trips). A single store would go stale again under the
	// test's 50ms threshold, so keep refreshing through the window.
	stopRefresh := make(chan struct{})
	go func() {
		tk := time.NewTicker(10 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stopRefresh:
				return
			case <-tk.C:
				c.pumpLastIter.Store(time.Now().UnixNano())
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	close(stopRefresh)
	if got := c.pumpDeaths.Load(); got != 1 {
		t.Fatalf("pumpDeaths after recovery = %d, want 1", got)
	}
	c.pumpLastIter.Store(time.Now().Add(-10 * time.Second).UnixNano())
	deadline = time.Now().Add(2 * time.Second)
	for c.pumpDeaths.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := c.pumpDeaths.Load(); got != 2 {
		t.Fatalf("pumpDeaths = %d, want 2 (second episode)", got)
	}
	close(c.done)
	c.wg.Wait()
}
