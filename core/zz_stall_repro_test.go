package core

// Repro/regression tests for the 1.0.41 intermittent stall:
// Speedtest hits ~90 Mbps then the whole tunnel goes dead (UI still
// shows connected, counters frozen, zero traffic), while a fresh
// session on the same phone runs 142 Mbps to completion. The stall is
// intermittent, not a speed threshold, so the targets are permanent
// wedges with timing-dependent triggers, not throughput caps.
//
// R1. readPump exits permanently on a non-timeout UDP read error.
//     readPump (mist_udp.go) returns on ANY non-timeout error, and it
//     is started exactly once (Connect). On Linux, an ICMP
//     port-unreachable (carrier CGNAT reset, DPI kill, NAT expiry)
//     surfaces on ReadFromUDP as ECONNREFUSED, which is not a
//     timeout, so readPump returns and the session goes permanently
//     deaf: downloads stop, app TCP stalls for lack of replies,
//     counters freeze with no error, UI stays "connected", a fresh
//     dial (new socket) works, reconnect fixes. The exit itself is
//     unchanged (still returns); the 2026-10-25 fix makes it
//     OBSERVABLE instead of silent: the exit is counted in
//     pumpDeaths, logged, and a watchdog counts wedged-but-alive
//     pumps too, so the UI layer can surface "session dead"
//     instead of showing a frozen "connected".
// R2. stream.Close() blocks forever when the send scheduler queue is
//     full, and three engine paths call Close while holding e.mu
//     (finishConnLocked, dropTCP, sweeper). If a connection closes
//     exactly when the 256-packet scheduler queue is full, Close
//     parks in sched.Write, e.mu is never released, and every
//     engine path (handleTCP, pumpTCP window checks, retransmitLoop,
//     sweeper) piles onto e.mu: total engine wedge, counters frozen,
//     UI alive, reconnect (new engine) fixes. Intermittent because
//     it needs close-during-full-queue timing (Speedtest opens and
//     closes dozens of connections per run).
//     FIXED 2026-10-25: stream Close never blocks (writeMu TryLock
//     + FIN via scheduler TryWrite, dropped when full) and
//     Engine.Close / dropTCP / sweeper close streams outside e.mu.
//     The R2 test below is now a regression test asserting the
//     fixed behavior (prompt return, e.mu stays free).

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"mist/mistcore"
)

// TestReadPumpExitsOnNonTimeoutReadError proves the R1 exit branch:
// readPump returns on ANY non-timeout read error and is never
// restarted (started exactly once, in Connect). The production
// trigger is ICMP port-unreachable surfacing as ECONNREFUSED on
// ReadFromUDP (same error class: net.Error, Timeout()==false);
// this sandbox blocks loopback UDP sends, so the literal ICMP
// variant cannot run here, and the test uses a closed socket
// instead, which produces the same non-timeout error class and
// exercises the identical return branch.
func TestReadPumpExitsOnNonTimeoutReadError(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	c := &MistUDPClient{conn: conn, done: make(chan struct{})}
	c.wg.Add(1)
	go c.readPump()
	time.Sleep(200 * time.Millisecond) // let readPump block in ReadFromUDP
	// Closing the socket forces ReadFromUDP to fail with a
	// non-timeout error ("use of closed network connection").
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	exited := make(chan struct{})
	go func() { c.wg.Wait(); close(exited) }()
	select {
	case <-exited:
		t.Logf("REPRODUCED R1: readPump goroutine exited on a non-timeout read error; no restart exists (only started in Connect)")
	case <-time.After(6 * time.Second):
		t.Fatalf("readPump still alive after 6s: R1 not reproduced")
	}
	// The production trigger is the same error class: an ICMP
	// port-unreachable surfaces as ECONNREFUSED, for which
	// Timeout() is false, so the identical `return` branch fires.
	var sysErr syscall.Errno = syscall.ECONNREFUSED
	if ne, ok := interface{}(sysErr).(net.Error); ok && ne.Timeout() {
		t.Fatalf("ECONNREFUSED unexpectedly reports Timeout()==true")
	}
	_ = errors.Is
}

// TestStreamCloseBlocksWhenSchedulerFull is the R2 REGRESSION test
// (renamed behavior, same name kept for continuity): with the
// scheduler queue full (256) and the send loop not draining,
// stream.Close() must return promptly — the FIN is dropped via
// TryWrite instead of parking in sched.Write — and a second engine
// path needing e.mu must proceed immediately. Before the fix this
// test failed the other way (Close parked forever, e.mu wedged).
func TestStreamCloseBlocksWhenSchedulerFull(t *testing.T) {
	var sid [16]byte
	sess := mistcore.NewUDPSession(sid, [32]byte{}, [32]byte{},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}, nil)
	sched := mistcore.NewUDPSendScheduler(sess, mistcore.DirC2S,
		func([]byte) error { return nil })
	// Deliberately do NOT Start: the drain loop is stopped, so the
	// queue stays full, modeling a stalled drain (cwnd/pacing gated).
	for i := 0; i < mistcore.UDPSchedulerMaxQueue; i++ {
		if err := sched.Write([][]byte{[]byte("x")}); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	c := &MistUDPClient{sched: sched, streams: map[byte]*mistStreamConn{}}
	st := newMistStreamConn(c, 1, "127.0.0.1:443")
	c.streams[1] = st

	// Simulate the engine's e.mu-held close path: hold a mutex across
	// Close the way finishConnLocked/dropTCP/sweeper do, then show a
	// second e.mu user proceeds promptly (no wedge).
	var emu sync.Mutex
	emu.Lock()
	closed := make(chan struct{})
	go func() {
		_ = st.Close() // must return promptly: FIN dropped, SID freed
		emu.Unlock()
		close(closed)
	}()
	select {
	case <-closed:
		t.Logf("R2 FIXED: Close returned promptly with a full queue")
	case <-time.After(3 * time.Second):
		t.Fatalf("Close parked with a full queue: R2 regression")
	}
	// A second engine path needing e.mu proceeds immediately.
	blocked := make(chan struct{})
	go func() {
		emu.Lock()
		emu.Unlock()
		close(blocked)
	}()
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatalf("e.mu wedged behind Close: R2 regression")
	}
	if _, ok := c.streams[1]; ok {
		t.Fatalf("SID not freed by prompt Close")
	}
}
