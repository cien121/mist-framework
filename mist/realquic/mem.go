package realquic

import (
	"net"
	"os"
	"sync"
	"time"
)

// This file is a lab-only transport: an in-memory net.PacketConn pair that
// lets the full quic-go stack (handshake, crypto, streams, H3) run where
// the sandbox blocks UDP sendmsg even on loopback (EPERM). It is not a
// production transport and must not be used outside tests and lab runs.

type memAddr struct{ s string }

func (a memAddr) Network() string { return "udp" }
func (a memAddr) String() string  { return a.s }

type memPacket struct{ b []byte }

type memPacketConn struct {
	mu       sync.Mutex
	peer     *memPacketConn
	recv     chan memPacket
	local    memAddr
	remote   memAddr
	closed   bool
	readDead time.Time
	// wake is closed (and replaced) by every SetReadDeadline, so a
	// ReadFrom blocked without a deadline wakes and re-evaluates the
	// new deadline — the PacketConn contract a real UDPConn honours
	// and quic-go's Transport.Close relies on. Without it, a dial
	// timeout over a mem pair deadlocks: Transport.Close waits for
	// its listen loop, which waits forever on a blocked receive that
	// no deadline change can interrupt.
	wake chan struct{}
}

// NewMemPair returns a connected pair: first is the client side, second is
// the server side. Dial the server side's LocalAddr from the client side.
func NewMemPair() (net.PacketConn, net.PacketConn) {
	a := &memPacketConn{recv: make(chan memPacket, 1024), local: memAddr{"mem-client"}, remote: memAddr{"mem-server"}, wake: make(chan struct{})}
	b := &memPacketConn{recv: make(chan memPacket, 1024), local: memAddr{"mem-server"}, remote: memAddr{"mem-client"}, wake: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (c *memPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		dead := c.readDead
		wake := c.wake
		closed := c.closed
		c.mu.Unlock()
		if closed {
			// Checked first: after Close both recv and wake are
			// closed, and a wake-only loop would spin forever.
			return 0, nil, net.ErrClosed
		}
		var timerCh <-chan time.Time
		var timer *time.Timer
		if !dead.IsZero() {
			timer = time.NewTimer(time.Until(dead))
			timerCh = timer.C
		}
		select {
		case pkt, ok := <-c.recv:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return copy(p, pkt.b), c.remote, nil
		case <-timerCh:
			return 0, nil, os.ErrDeadlineExceeded
		case <-wake:
			// Deadline changed (or connection closed): re-evaluate.
			// A close also closes recv, so the next iteration ends
			// via the recv branch; a future deadline just waits again.
			if timer != nil {
				timer.Stop()
			}
			continue
		}
	}
}

func (c *memPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	peer := c.peer
	peer.mu.Lock()
	closed := peer.closed
	peer.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	cp := append([]byte{}, p...)
	peer.recv <- memPacket{b: cp}
	return len(p), nil
}

func (c *memPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		// NOTE (step 6): recv is deliberately NOT closed here. Closing
		// it raced with a concurrent WriteTo send on the peer (a
		// -race failure reproduced in step 6: mem.go Close vs WriteTo
		// on the recv channel). A blocked ReadFrom still exits: Close
		// closes wake, the select wakes, and the loop-top closed check
		// returns ErrClosed. Buffered packets after Close are orphaned
		// and harmless. This file is lab-only test transport.
		close(c.wake)
	}
	return nil
}

func (c *memPacketConn) LocalAddr() net.Addr           { return c.local }
func (c *memPacketConn) RemoteAddr() net.Addr          { return c.remote }
func (c *memPacketConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *memPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDead = t
	if !c.closed {
		close(c.wake)
		c.wake = make(chan struct{})
	}
	c.mu.Unlock()
	return nil
}
func (c *memPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
