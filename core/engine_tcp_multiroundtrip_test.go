package core

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// Regression tests for the "first roundtrip OK, later roundtrips die"
// failure mode: concurrent per-segment stream Writes raced on the
// stream offset and scrambled the byte stream (TLS corruption).
// Fixed by per-connection FIFO writer serialization in engine.go
// plus stream-level writeMu in mist_udp.go.
//
// Test 1 (TestEngineTCPMultiRoundtrip): 3 request/response roundtrips
// plus one app retransmit. Verifies appSeq/ack tracking and that a
// duplicate app segment is NOT forwarded into the stream twice.
// Test 2 (TestEngineTCPBackToBackWriteOrder): app sends many segments
// back-to-back; verifies the stream receives them in order. The
// engine spawns one goroutine per app segment (engine.go handleTCP)
// with no per-connection write serialization, so order is not
// guaranteed once Write has any latency at all.

// recConn records every Write payload in arrival order. Reads block
// until closed (pumpTCP parks on Read); the test never replies.
type recConn struct {
	mu     sync.Mutex
	writes [][]byte
	delay  time.Duration
	closed chan struct{}
	once   sync.Once
}

func newRecConn(delay time.Duration) *recConn {
	return &recConn{delay: delay, closed: make(chan struct{})}
}

func (c *recConn) Write(b []byte) (int, error) {
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	cp := append([]byte(nil), b...)
	c.mu.Lock()
	c.writes = append(c.writes, cp)
	c.mu.Unlock()
	return len(b), nil
}

func (c *recConn) Read(b []byte) (int, error) {
	<-c.closed
	return 0, errClosed
}

func (c *recConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *recConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *recConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *recConn) SetDeadline(t time.Time) error      { return nil }
func (c *recConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *recConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *recConn) allBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []byte
	for _, w := range c.writes {
		out = append(out, w...)
	}
	return out
}

func (c *recConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

// driveTCPHandshake sends SYN and returns the SYN-ACK's seq (isn).
func driveTCPHandshake(t *testing.T, tun *mockTUN, appIP, dstIP net.IP, appPort, dstPort uint16, isnSeq uint32) uint32 {
	t.Helper()
	syn := BuildTCP(appIP, dstIP, appPort, dstPort, isnSeq, 0, TCPSyn, nil)
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 1, syn)
	select {
	case out := <-tun.writeCh:
		p, err := ParseIP(out)
		if err != nil {
			t.Fatalf("parse synack: %v", err)
		}
		seg, err := ParseTCP(p.Payload)
		if err != nil {
			t.Fatalf("parse synack tcp: %v", err)
		}
		if seg.Flags&(TCPSyn|TCPAck) != TCPSyn|TCPAck || seg.Ack != isnSeq+1 {
			t.Fatalf("bad synack: flags=%x ack=%d want ack=%d", seg.Flags, seg.Ack, isnSeq+1)
		}
		return seg.Seq
	case <-time.After(3 * time.Second):
		t.Fatal("no synack")
		return 0
	}
}

// drainTUNACKs collects pure-ACK segments until deadline, returning the
// last ack number seen (used to confirm appSeq advancement).
func drainTUNACKs(t *testing.T, tun *mockTUN, timeout time.Duration) (acks []uint32) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case out := <-tun.writeCh:
			p, err := ParseIP(out)
			if err != nil {
				continue
			}
			seg, err := ParseTCP(p.Payload)
			if err != nil {
				continue
			}
			if len(seg.Payload) == 0 && seg.Flags&TCPAck != 0 {
				acks = append(acks, seg.Ack)
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	return acks
}

func TestEngineTCPMultiRoundtrip(t *testing.T) {
	tun := newMockTUN()
	cli, srv := net.Pipe()
	mc := &mockClient{dialFunc: func(addr string) (net.Conn, error) { return cli, nil }}
	e := NewEngine(EngineConfig{TUN: tun, Client: mc})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")
	const appPort, dstPort = 40000, 443
	appSeq := uint32(1000)
	isn := driveTCPHandshake(t, tun, appIP, dstIP, appPort, dstPort, appSeq)
	appSeq++ // SYN consumed one

	// Server side: read one request, reply once, per roundtrip.
	roundtrip := func(req, resp string, id uint16) {
		t.Helper()
		seg := BuildTCP(appIP, dstIP, appPort, dstPort, appSeq, isn+1, TCPPsh|TCPAck, []byte(req))
		tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, id, seg)
		appSeq += uint32(len(req))
		// Server must receive exactly req.
		buf := make([]byte, 4096)
		_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := srv.Read(buf)
		if err != nil {
			t.Fatalf("server read req %q: %v", req, err)
		}
		if string(buf[:n]) != req {
			t.Fatalf("server got %q want %q", buf[:n], req)
		}
		// Server replies; engine must deliver it to the app.
		if _, err := srv.Write([]byte(resp)); err != nil {
			t.Fatalf("server write resp: %v", err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
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
				if string(s.Payload) == resp {
					if s.Ack != appSeq {
						t.Fatalf("resp %q ack=%d want %d (appSeq drift)", resp, s.Ack, appSeq)
					}
					return
				}
				// Pure ACKs for our own sends: ignore.
			case <-time.After(50 * time.Millisecond):
			}
		}
		t.Fatalf("app never received resp %q", resp)
	}

	roundtrip("REQ1", "RESP1", 10)
	roundtrip("REQ2", "RESP2", 11)
	roundtrip("REQ3", "RESP3", 12)

	// App retransmits REQ2 (old seq 1005): engine must ACK current
	// expectation and must NOT forward the bytes again.
	dupSeq := uint32(1005)
	dup := BuildTCP(appIP, dstIP, appPort, dstPort, dupSeq, isn+1, TCPPsh|TCPAck, []byte("REQ2"))
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 13, dup)
	_ = srv.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	if n, err := srv.Read(buf); err == nil {
		t.Fatalf("duplicate app segment forwarded into stream: %q (want nothing)", buf[:n])
	}
	// Engine should have ACKed current expectation (appSeq = 1013).
	acks := drainTUNACKs(t, tun, 500*time.Millisecond)
	found := false
	for _, a := range acks {
		if a == appSeq {
			found = true
		}
	}
	if !found {
		t.Fatalf("no ACK of current appSeq %d after duplicate; acks=%v", appSeq, acks)
	}
}

func TestEngineTCPBackToBackWriteOrder(t *testing.T) {
	// App sends 20 segments back-to-back. A correct engine forwards
	// them in order; the goroutine-per-segment design does not
	// guarantee this once Write takes any time (real Mist writes go
	// through chunking + UDP socket). 500us stands in for that.
	const nSeg = 20
	rc := newRecConn(500 * time.Microsecond)
	defer rc.Close()
	mc := &mockClient{dialFunc: func(addr string) (net.Conn, error) { return rc, nil }}
	tun := newMockTUN()
	e := NewEngine(EngineConfig{TUN: tun, Client: mc})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	done := make(chan struct{})
	defer close(done)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")
	const appPort, dstPort = 40001, 443
	appSeq := uint32(5000)
	_ = driveTCPHandshake(t, tun, appIP, dstIP, appPort, dstPort, appSeq)
	appSeq++
	// Drain engine->app TUN packets (per-segment ACKs) so the
	// 16-slot mock channel never backpressures handleTCP. Started
	// after the handshake so the SYN-ACK is not stolen.
	go func() {
		for {
			select {
			case <-tun.writeCh:
			case <-done:
				return
			}
		}
	}()

	var want []byte
	for i := 0; i < nSeg; i++ {
		payload := []byte{byte('A' + i)}
		want = append(want, payload...)
		seg := BuildTCP(appIP, dstIP, appPort, dstPort, appSeq, 0, TCPPsh|TCPAck, payload)
		appSeq++
		tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, uint16(20+i), seg)
	}
	waitFor(t, "all segment writes", func() bool {
		return rc.writeCount() == nSeg
	})
	got := rc.allBytes()
	if string(got) != string(want) {
		t.Fatalf("stream byte order scrambled:\n got %q\nwant %q\n(each Write is one app segment; concurrent goroutine Writes raced)", got, want)
	}
}
