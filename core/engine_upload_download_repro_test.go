package core

// Regression tests for the 1.0.38 follow-up failures (upload breaks,
// Speedtest "DOWNLOAD TEST ERROR: socket error"), fixed by the
// protocol-hardening batch in engine.go / mist_udp.go / ip.go.
//
// Upload side (any-size upload breaks, chat/small uplink works):
//   U1. FIN+data combined segment: handleTCP's FIN branch used to
//       ignore the payload in the same segment, so the final upload
//       chunk never reached the stream (server waits for the rest
//       of the body).
//   U2. Stream never closed on normal teardown: pumpTCP EOF and the
//       pure-ACK cleanup never called stream.Close(), so with a real
//       MistUDPClient the 1-byte SID space (1..255) leaked until the
//       sweeper; after 255 dials SIDs wrapped and collided with
//       leaked streams (client dispatch routes old frames to the new
//       stream, server treats CONNECT bytes as data to the old
//       target). Fits: fresh session works, degrades after many short
//       connections (Speedtest burns dozens), small uploads fail
//       regardless of size, reconnect (fresh SIDs) fixes it.
//   U3. Immediate ACK + unbounded FIFO: with a blocked stream the
//       engine used to ACK every app segment at once while the queue
//       grew without cap — the app believed data delivered while
//       nothing left the phone. Now the FIFO is capped at the
//       advertised window and over-cap segments are not ACKed
//       (backpressure; the app retransmits).
//
// Download side (Speedtest "DOWNLOAD TEST ERROR: socket error"):
//   D1. Dropped download segment is never retransmitted: pumpTCP had
//       no retransmit timer, ignored duplicate ACKs and the app's
//       advertised window (ParseTCP did not even parse the window
//       field). One lost TUN segment left a permanent gap; the app
//       timed out and reset the connection.

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// closeRecConn records whether Close was ever called.
type closeRecConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *closeRecConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *closeRecConn) wasClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// gateConn blocks Write until release is closed, recording payloads.
type gateConn struct {
	mu      sync.Mutex
	writes  [][]byte
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newGateConn() *gateConn {
	return &gateConn{release: make(chan struct{}), closed: make(chan struct{})}
}

func (c *gateConn) Write(b []byte) (int, error) {
	<-c.release
	cp := append([]byte(nil), b...)
	c.mu.Lock()
	c.writes = append(c.writes, cp)
	c.mu.Unlock()
	return len(b), nil
}

func (c *gateConn) Read(b []byte) (int, error) {
	<-c.closed
	return 0, errClosed
}

func (c *gateConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *gateConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *gateConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *gateConn) SetDeadline(t time.Time) error      { return nil }
func (c *gateConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *gateConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *gateConn) allBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []byte
	for _, w := range c.writes {
		out = append(out, w...)
	}
	return out
}

func (c *gateConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

// readTCPSegments collects data segments from tun.writeCh until n are
// found or the deadline passes.
func readTCPSegments(t *testing.T, tun *mockTUN, n int, timeout time.Duration) []*TCPSegment {
	t.Helper()
	var segs []*TCPSegment
	deadline := time.Now().Add(timeout)
	for len(segs) < n && time.Now().Before(deadline) {
		select {
		case out := <-tun.writeCh:
			p, err := ParseIP(out)
			if err != nil {
				continue
			}
			s, err := ParseTCP(p.Payload)
			if err != nil || len(s.Payload) == 0 {
				continue
			}
			segs = append(segs, s)
		case <-time.After(50 * time.Millisecond):
		}
	}
	return segs
}

// U1: app sends its final upload chunk together with FIN (close-after-
// write coalescing, common for small uploads). The payload must reach
// the stream; on current code the FIN branch drops it.
func TestUploadFinPayloadDropped(t *testing.T) {
	rc := newRecConn(0)
	defer rc.Close()
	mc := &mockClient{dialFunc: func(addr string) (net.Conn, error) { return rc, nil }}
	tun := newMockTUN()
	e := NewEngine(EngineConfig{TUN: tun, Client: mc})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")
	const appPort, dstPort = 40100, 443
	appSeq := uint32(1000)
	isn := driveTCPHandshake(t, tun, appIP, dstIP, appPort, dstPort, appSeq)
	appSeq++ // SYN consumed

	seg := BuildTCP(appIP, dstIP, appPort, dstPort, appSeq, isn+1,
		TCPPsh|TCPAck|TCPFin, []byte("LASTBYTES"))
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 30, seg)
	time.Sleep(500 * time.Millisecond)
	if got := string(rc.allBytes()); got != "LASTBYTES" {
		t.Fatalf("FIN+data payload lost: stream got %q want %q "+
			"(handleTCP FIN branch ignores segment payload)", got, "LASTBYTES")
	}
}

// U2: server closes first (normal HTTP close), app ACKs the FIN.
// The engine must close the Mist stream (freeing the SID); on
// current code it never does, so SIDs leak until the sweeper.
func TestStreamNotClosedOnServerEOF(t *testing.T) {
	var wraps []*closeRecConn
	var srvs []net.Conn
	mc := &mockClient{dialFunc: func(addr string) (net.Conn, error) {
		cli, srv := net.Pipe()
		w := &closeRecConn{Conn: cli}
		wraps = append(wraps, w)
		srvs = append(srvs, srv)
		return w, nil
	}}
	tun := newMockTUN()
	e := NewEngine(EngineConfig{TUN: tun, Client: mc})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")
	const dstPort = 443
	for i := 0; i < 3; i++ {
		appPort := uint16(40200 + i)
		appSeq := uint32(1000)
		isn := driveTCPHandshake(t, tun, appIP, dstIP, appPort, dstPort, appSeq)
		// Server closes: pumpTCP must FIN the app.
		srvs[i].Close()
		finSeen := false
		deadline := time.Now().Add(3 * time.Second)
		for !finSeen && time.Now().Before(deadline) {
			select {
			case out := <-tun.writeCh:
				p, err := ParseIP(out)
				if err != nil {
					continue
				}
				s, err := ParseTCP(p.Payload)
				if err != nil {
					continue
				}
				if s.Flags&TCPFin != 0 {
					finSeen = true
				}
			case <-time.After(50 * time.Millisecond):
			}
		}
		if !finSeen {
			t.Fatalf("conn %d: no FIN to app after server close", i)
		}
		// App ACKs the FIN (ack = ourSeq after FIN increment).
		ack := BuildTCP(appIP, dstIP, appPort, dstPort, appSeq+1, isn+2, TCPAck, nil)
		tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, uint16(40+i), ack)
		time.Sleep(300 * time.Millisecond)
	}
	closed := 0
	for _, w := range wraps {
		if w.wasClosed() {
			closed++
		}
	}
	if closed != 3 {
		t.Fatalf("stream.Close called %d/3 times after normal teardown "+
			"(want 3: SIDs leak until the 10-minute sweeper, then wrap at 255)", closed)
	}
}

// U3: stream Write blocked; the engine must NOT ACK beyond the
// FIFO cap. With 100 x 1000-byte segments against the 65535-byte
// cap, only a prefix is ACKed, the queue stays bounded, and after
// the stream unblocks + the unacked tail is resent (as a real app
// retransmit would), every byte arrives in order exactly once.
func TestUploadBurstQueueCapBackpressure(t *testing.T) {
	gc := newGateConn()
	defer gc.Close()
	mc := &mockClient{dialFunc: func(addr string) (net.Conn, error) { return gc, nil }}
	tun := newMockTUN()
	e := NewEngine(EngineConfig{TUN: tun, Client: mc})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")
	const appPort, dstPort = 40300, 443
	appSeq := uint32(1000)
	isn := driveTCPHandshake(t, tun, appIP, dstIP, appPort, dstPort, appSeq)
	appSeq++
	_ = isn
	firstSeq := appSeq

	// Drain engine->app ACKs so mockTUN.writeCh never backpressures,
	// tracking the highest ACK number seen.
	var maxAck atomic.Uint32
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case out := <-tun.writeCh:
				p, err := ParseIP(out)
				if err != nil {
					continue
				}
				s, err := ParseTCP(p.Payload)
				if err != nil || len(s.Payload) != 0 || s.Flags&TCPAck == 0 {
					continue
				}
				for {
					old := maxAck.Load()
					if s.Ack <= old || maxAck.CompareAndSwap(old, s.Ack) {
						break
					}
				}
			case <-done:
				return
			}
		}
	}()

	const nSeg = 100
	type sent struct {
		seq     uint32
		payload []byte
	}
	var sentSegs []sent
	var want []byte
	for i := 0; i < nSeg; i++ {
		payload := make([]byte, 1000)
		for j := range payload {
			payload[j] = byte('A' + i%26)
		}
		want = append(want, payload...)
		sentSegs = append(sentSegs, sent{seq: appSeq, payload: payload})
		seg := BuildTCP(appIP, dstIP, appPort, dstPort, appSeq, 0, TCPPsh|TCPAck, payload)
		appSeq += uint32(len(payload))
		tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, uint16(50+i), seg)
	}
	finalSeq := appSeq
	time.Sleep(500 * time.Millisecond) // let the engine process all segments
	maxAcked := maxAck.Load()
	if maxAcked >= finalSeq {
		t.Fatalf("no backpressure: everything ACKed (maxAck=%d final=%d); "+
			"queue cap did not stop early ACKs", maxAcked, finalSeq)
	}
	// Queue depth while the stream is blocked: one item is in Write,
	// the rest queued, bounded by the cap. queuedBytes is guarded by
	// sendMu, not e.mu: look the connection up under e.mu, then read
	// queue state under sendMu (same order the writer uses).
	tuple := FourTuple{SrcIP: appIP.String(), SrcPort: appPort, DstIP: dstIP.String(), DstPort: dstPort, Proto: ProtoTCP}
	e.mu.Lock()
	conn, ok := e.tcp[tuple]
	e.mu.Unlock()
	if !ok {
		t.Fatal("connection gone while stream blocked")
	}
	conn.sendMu.Lock()
	queuedBytes := conn.queuedBytes
	conn.sendMu.Unlock()
	t.Logf("blocked stream: maxAck=%d (accepted %d bytes) queuedBytes=%d (cap %d)",
		maxAcked, maxAcked-firstSeq, queuedBytes, maxSendQueueBytes)
	if queuedBytes <= 0 || queuedBytes > maxSendQueueBytes {
		t.Fatalf("queue not bounded: queuedBytes=%d want (0, %d]", queuedBytes, maxSendQueueBytes)
	}
	accepted := int((maxAcked - firstSeq) / 1000)
	close(gc.release)
	waitFor(t, "accepted prefix drained", func() bool {
		return gc.writeCount() == accepted
	})
	// Resend the unacked tail in order, as an app retransmit would.
	for _, s := range sentSegs {
		if s.seq < maxAcked {
			continue
		}
		seg := BuildTCP(appIP, dstIP, appPort, dstPort, s.seq, 0, TCPPsh|TCPAck, s.payload)
		tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 200, seg)
	}
	waitFor(t, "all burst bytes written in order", func() bool {
		return gc.writeCount() == nSeg
	})
	if got := gc.allBytes(); string(got) != string(want) {
		t.Fatalf("burst bytes out of order/corrupt: got %d bytes want %d", len(got), len(want))
	}
}

// D1: server replies 5000 bytes (5 chunks); the app misses chunk 2
// and sends duplicate ACKs. A correct engine retransmits chunk 2;
// on current code nothing ever comes back and the connection is
// permanently wedged (app RTO -> RST -> "socket error").
func TestDownloadDroppedSegmentNeverRetransmitted(t *testing.T) {
	cli, srv := net.Pipe()
	mc := &mockClient{dialFunc: func(addr string) (net.Conn, error) { return cli, nil }}
	tun := newMockTUN()
	e := NewEngine(EngineConfig{TUN: tun, Client: mc})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	defer srv.Close()

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")
	const appPort, dstPort = 40400, 443
	appSeq := uint32(1000)
	isn := driveTCPHandshake(t, tun, appIP, dstIP, appPort, dstPort, appSeq)
	appSeq++ // SYN

	// App sends GET; server reads it.
	seg := BuildTCP(appIP, dstIP, appPort, dstPort, appSeq, isn+1, TCPPsh|TCPAck, []byte("GET"))
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 60, seg)
	appSeq += 3
	buf := make([]byte, 4096)
	_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := srv.Read(buf); err != nil || string(buf[:n]) != "GET" {
		t.Fatalf("server read GET: n=%d err=%v", n, err)
	}
	// Server replies 5000 bytes in 5 identifiable chunks.
	var resp []byte
	for k := 0; k < 5; k++ {
		n := 1200
		if k == 4 {
			n = 200
		}
		for j := 0; j < n; j++ {
			resp = append(resp, byte('A'+k))
		}
	}
	if _, err := srv.Write(resp); err != nil {
		t.Fatalf("server write resp: %v", err)
	}
	segs := readTCPSegments(t, tun, 5, 3*time.Second)
	if len(segs) != 5 {
		t.Fatalf("got %d download chunks want 5", len(segs))
	}
	seg2seq := segs[1].Seq
	seg2data := append([]byte(nil), segs[1].Payload...)
	// App missed chunk 2: duplicate ACKs for end of chunk 1.
	for i := 0; i < 3; i++ {
		dup := BuildTCP(appIP, dstIP, appPort, dstPort, appSeq, seg2seq, TCPAck, nil)
		tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, uint16(70+i), dup)
		time.Sleep(100 * time.Millisecond)
	}
	// 1.5s: does chunk 2 ever come back?
	deadline := time.Now().Add(1500 * time.Millisecond)
	retransmitted := false
	for time.Now().Before(deadline) {
		select {
		case out := <-tun.writeCh:
			p, err := ParseIP(out)
			if err != nil {
				continue
			}
			s, err := ParseTCP(p.Payload)
			if err != nil || len(s.Payload) == 0 {
				continue
			}
			if s.Seq == seg2seq && string(s.Payload) == string(seg2data) {
				retransmitted = true
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !retransmitted {
		t.Fatalf("dropped download chunk never retransmitted: " +
			"pumpTCP has no retransmit timer and ignores duplicate ACKs " +
			"(gap is permanent; app RTO -> RST -> socket error)")
	}
}
