package core

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// mockTUN is a channel-backed TUNDevice for tests.
type mockTUN struct {
	readCh  chan []byte
	writeCh chan []byte
	done    chan struct{}
	once    sync.Once
}

func newMockTUN() *mockTUN {
	return &mockTUN{
		readCh:  make(chan []byte, 16),
		writeCh: make(chan []byte, 16),
		done:    make(chan struct{}),
	}
}

func (m *mockTUN) Read(b []byte) (int, error) {
	select {
	case pkt := <-m.readCh:
		return copy(b, pkt), nil
	case <-m.done:
		return 0, errors.New("tun closed")
	}
}

func (m *mockTUN) Write(b []byte) (int, error) {
	pkt := append([]byte(nil), b...)
	select {
	case m.writeCh <- pkt:
		return len(b), nil
	case <-m.done:
		return 0, errors.New("tun closed")
	}
}

func (m *mockTUN) Close() error {
	m.once.Do(func() { close(m.done) })
	return nil
}

// mockClient implements ProtocolClient + DatagramClient.
type mockClient struct {
	mu       sync.Mutex
	dialed   []string
	dgSent   []dgRecord
	dgH      DatagramHandler
	dialFunc func(addr string) (net.Conn, error)
}

type dgRecord struct {
	target string
	data   []byte
}

func (c *mockClient) Name() string { return "mock" }

func (c *mockClient) Dial(ctx context.Context, addr string) (net.Conn, error) {
	c.mu.Lock()
	c.dialed = append(c.dialed, addr)
	fn := c.dialFunc
	c.mu.Unlock()
	if fn != nil {
		return fn(addr)
	}
	cli, srv := net.Pipe()
	_ = srv // held by the test via dialFunc normally; default: close it
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := srv.Read(buf); err != nil {
				return
			}
		}
	}()
	return cli, nil
}

func (c *mockClient) Close() error { return nil }

func (c *mockClient) SendDatagram(target string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dgSent = append(c.dgSent, dgRecord{target, append([]byte(nil), data...)})
	return nil
}

func (c *mockClient) OnDatagram(h DatagramHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dgH = h
}

func (c *mockClient) emitDatagram(srcAddr string, data []byte) {
	c.mu.Lock()
	h := c.dgH
	c.mu.Unlock()
	if h != nil {
		h(srcAddr, data)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestEngineUDPv4(t *testing.T) {
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dnsIP := net.ParseIP("8.8.8.8")
	seg := BuildUDP(appIP, dnsIP, 12345, 53, []byte("hello-dns"))
	pkt := BuildIPv4(appIP, dnsIP, ProtoUDP, 1, seg)
	tun.readCh <- pkt

	waitFor(t, "datagram forward", func() bool {
		cli.mu.Lock()
		defer cli.mu.Unlock()
		return len(cli.dgSent) == 1
	})
	cli.mu.Lock()
	rec := cli.dgSent[0]
	cli.mu.Unlock()
	if rec.target != "8.8.8.8:53" || string(rec.data) != "hello-dns" {
		t.Fatalf("bad forward: %+v", rec)
	}

	// Simulate the relay response.
	cli.emitDatagram("8.8.8.8:53", []byte("response"))
	select {
	case out := <-tun.writeCh:
		p, err := ParseIP(out)
		if err != nil {
			t.Fatalf("parse return: %v", err)
		}
		if p.Version != 4 || !p.Src.Equal(dnsIP) || !p.Dst.Equal(appIP) {
			t.Fatalf("bad return headers: %+v", p)
		}
		dg, err := ParseUDP(p.Payload)
		if err != nil {
			t.Fatalf("parse return udp: %v", err)
		}
		if dg.SrcPort != 53 || dg.DstPort != 12345 || string(dg.Payload) != "response" {
			t.Fatalf("bad return udp: %+v", dg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no return packet")
	}
}

func TestEngineUDPv6(t *testing.T) {
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("fd00::2")
	dnsIP := net.ParseIP("2606:4700:4700::1111")
	seg := BuildUDP(appIP, dnsIP, 12345, 53, []byte("v6-dns"))
	pkt := BuildIPv6(appIP, dnsIP, ProtoUDP, seg)
	tun.readCh <- pkt

	waitFor(t, "v6 datagram forward", func() bool {
		cli.mu.Lock()
		defer cli.mu.Unlock()
		return len(cli.dgSent) == 1
	})
	cli.mu.Lock()
	rec := cli.dgSent[0]
	cli.mu.Unlock()
	if rec.target != "[2606:4700:4700::1111]:53" || string(rec.data) != "v6-dns" {
		t.Fatalf("bad v6 forward: %+v", rec)
	}

	cli.emitDatagram("[2606:4700:4700::1111]:53", []byte("v6-resp"))
	select {
	case out := <-tun.writeCh:
		p, err := ParseIP(out)
		if err != nil {
			t.Fatalf("parse v6 return: %v", err)
		}
		if p.Version != 6 || !p.Src.Equal(dnsIP) || !p.Dst.Equal(appIP) {
			t.Fatalf("bad v6 return headers: %+v", p)
		}
		dg, err := ParseUDP(p.Payload)
		if err != nil {
			t.Fatalf("parse v6 return udp: %v", err)
		}
		if string(dg.Payload) != "v6-resp" {
			t.Fatalf("bad v6 return payload: %q", dg.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no v6 return packet")
	}
}

func TestEngineTCPSYN(t *testing.T) {
	tun := newMockTUN()
	srvCh := make(chan net.Conn, 1)
	cli := &mockClient{
		dialFunc: func(addr string) (net.Conn, error) {
			cli, srv := net.Pipe()
			srvCh <- srv
			return cli, nil
		},
	}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("1.2.3.4")
	syn := BuildTCP(appIP, dstIP, 40000, 443, 1000, 0, TCPSyn, nil)
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 1, syn)

	// Expect SYN-ACK.
	var synAck []byte
	select {
	case synAck = <-tun.writeCh:
	case <-time.After(3 * time.Second):
		t.Fatal("no SYN-ACK")
	}
	p, err := ParseIP(synAck)
	if err != nil {
		t.Fatalf("parse synack: %v", err)
	}
	seg, err := ParseTCP(p.Payload)
	if err != nil {
		t.Fatalf("parse synack tcp: %v", err)
	}
	if seg.Flags&(TCPSyn|TCPAck) != TCPSyn|TCPAck || seg.Ack != 1001 {
		t.Fatalf("bad SYN-ACK: flags=%x ack=%d", seg.Flags, seg.Ack)
	}
	if seg.SrcPort != 443 || seg.DstPort != 40000 {
		t.Fatalf("bad SYN-ACK ports: %+v", seg)
	}

	// App ACKs + sends data.
	ack := BuildTCP(appIP, dstIP, 40000, 443, 1001, seg.Seq+1, TCPAck, nil)
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 2, ack)
	data := BuildTCP(appIP, dstIP, 40000, 443, 1001, seg.Seq+1, TCPPsh|TCPAck, []byte("hello"))
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 3, data)

	// The stream should receive "hello".
	var srv net.Conn
	select {
	case srv = <-srvCh:
	case <-time.After(3 * time.Second):
		t.Fatal("dial never happened")
	}
	srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("stream got %q", buf[:n])
	}

	// Server replies; engine must emit a PSH+ACK segment.
	if _, err := srv.Write([]byte("world")); err != nil {
		t.Fatalf("stream write: %v", err)
	}
	// Drain any ACKs the engine sent for our data segments first.
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case out := <-tun.writeCh:
			pp, err := ParseIP(out)
			if err != nil {
				t.Fatalf("parse data seg: %v", err)
			}
			ss, err := ParseTCP(pp.Payload)
			if err != nil {
				t.Fatalf("parse data tcp: %v", err)
			}
			if string(ss.Payload) == "world" {
				return // success
			}
			// Otherwise it's an ACK for our data; keep waiting.
		case <-time.After(time.Until(deadline)):
			t.Fatal("no data segment from server")
		}
	}
}
