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
	dgTH     DatagramTaggedHandler
	dialFunc func(addr string) (net.Conn, error)
}

type dgRecord struct {
	target string
	data   []byte
	tag    uint8
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
	return c.SendDatagramTagged(target, 0, data)
}

func (c *mockClient) SendDatagramTagged(target string, tag uint8, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dgSent = append(c.dgSent, dgRecord{target, append([]byte(nil), data...), tag})
	return nil
}

func (c *mockClient) OnDatagram(h DatagramHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dgH = h
}

// OnDatagramTagged records the tagged handler; emitDatagram (the
// old-server path) delivers to it with tag 0, so existing tests
// keep their semantics while the engine registers the tagged path.
func (c *mockClient) OnDatagramTagged(h DatagramTaggedHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dgTH = h
}

func (c *mockClient) emitDatagram(srcAddr string, data []byte) {
	c.emitDatagramTagged(srcAddr, 0, data)
}

func (c *mockClient) emitDatagramTagged(srcAddr string, tag uint8, data []byte) {
	c.mu.Lock()
	th, h := c.dgTH, c.dgH
	c.mu.Unlock()
	if th != nil {
		th(srcAddr, tag, data)
	} else if h != nil {
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

// TestEngineTCPChunking is the regression test for the 1.0.33
// return-path failure: one 5000-byte server reply must arrive as
// several IP packets each within the TUN MTU (1400), with contiguous
// sequence numbers, not as one oversized DF packet.
func TestEngineTCPChunking(t *testing.T) {
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
	ack := BuildTCP(appIP, dstIP, 40000, 443, 1001, seg.Seq+1, TCPAck, nil)
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 2, ack)

	var srv net.Conn
	select {
	case srv = <-srvCh:
	case <-time.After(3 * time.Second):
		t.Fatal("dial never happened")
	}
	big := make([]byte, 5000)
	for i := range big {
		big[i] = byte(i % 251)
	}
	go func() {
		_, _ = srv.Write(big)
	}()

	var got []byte
	var wantSeq uint32
	first := true
	deadline := time.Now().Add(3 * time.Second)
	for len(got) < len(big) {
		select {
		case out := <-tun.writeCh:
			if len(out) > 1400 {
				t.Fatalf("oversized TUN packet: %d bytes", len(out))
			}
			pp, err := ParseIP(out)
			if err != nil {
				t.Fatalf("parse seg: %v", err)
			}
			ss, err := ParseTCP(pp.Payload)
			if err != nil {
				t.Fatalf("parse tcp: %v", err)
			}
			if len(ss.Payload) == 0 {
				continue // engine ACK for app segments
			}
			if first {
				wantSeq = ss.Seq
				first = false
			}
			if ss.Seq != wantSeq {
				t.Fatalf("seq gap: got %d want %d", ss.Seq, wantSeq)
			}
			wantSeq += uint32(len(ss.Payload))
			got = append(got, ss.Payload...)
		case <-time.After(time.Until(deadline)):
			t.Fatalf("only %d/%d bytes arrived", len(got), len(big))
		}
	}
	if string(got) != string(big) {
		t.Fatal("reassembled payload mismatch")
	}
	if e.Stats().TunWriteErrors != 0 {
		t.Fatalf("unexpected tun write errors: %d", e.Stats().TunWriteErrors)
	}
}

// TestDatagramSourceAddr locks the dispatch -> onDatagram address
// contract: the relay response source address must survive
// net.SplitHostPort, for v4 and v6 alike. The old
// fmt.Sprintf("%s:%d") formatting produced unbracketed IPv6
// ("2001:4860:4860::8888:53"), which SplitHostPort rejects with
// "too many colons" and drops the response before it reaches TUN.
func TestDatagramSourceAddr(t *testing.T) {
	v6 := datagramSourceAddr(net.ParseIP("2001:4860:4860::8888"), 53)
	if v6 != "[2001:4860:4860::8888]:53" {
		t.Fatalf("bad v6 source addr: %q", v6)
	}
	if _, _, err := net.SplitHostPort(v6); err != nil {
		t.Fatalf("SplitHostPort rejects v6 source addr %q: %v", v6, err)
	}
	v4 := datagramSourceAddr(net.ParseIP("8.8.8.8"), 53)
	if v4 != "8.8.8.8:53" {
		t.Fatalf("bad v4 source addr: %q", v4)
	}
	if _, _, err := net.SplitHostPort(v4); err != nil {
		t.Fatalf("SplitHostPort rejects v4 source addr %q: %v", v4, err)
	}
}

// sendUDPQuery injects one app UDP packet into the engine's TUN.
func sendUDPQuery(t *testing.T, tun *mockTUN, appIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) {
	t.Helper()
	seg := BuildUDP(appIP, dstIP, srcPort, dstPort, payload)
	if appIP.To4() != nil {
		tun.readCh <- BuildIPv4(appIP, dstIP, ProtoUDP, 1, seg)
	} else {
		tun.readCh <- BuildIPv6(appIP, dstIP, ProtoUDP, seg)
	}
}

// collectUDPReturns reads n return packets from the TUN and maps
// each payload to the destination (app) port it was delivered to.
func collectUDPReturns(t *testing.T, tun *mockTUN, n int) map[string]uint16 {
	t.Helper()
	out := make(map[string]uint16)
	deadline := time.Now().Add(3 * time.Second)
	for len(out) < n {
		select {
		case pkt := <-tun.writeCh:
			p, err := ParseIP(pkt)
			if err != nil {
				t.Fatalf("parse return: %v", err)
			}
			dg, err := ParseUDP(p.Payload)
			if err != nil {
				t.Fatalf("parse return udp: %v", err)
			}
			out[string(dg.Payload)] = dg.DstPort
		case <-time.After(time.Until(deadline)):
			t.Fatalf("only %d/%d returns", len(out), n)
		}
	}
	return out
}

func waitDatagrams(t *testing.T, cli *mockClient, n int) {
	t.Helper()
	waitFor(t, "datagram forwards", func() bool {
		cli.mu.Lock()
		defer cli.mu.Unlock()
		return len(cli.dgSent) == n
	})
}

// TestEngineDNSConcurrentV4: two apps query the same DNS server
// concurrently. Responses must land on the querying app's own source
// port, matched by DNS transaction ID — not both on the last
// querier's port, which the old dst-only return map did.
func TestEngineDNSConcurrentV4(t *testing.T) {
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dnsIP := net.ParseIP("8.8.8.8")
	q1 := append([]byte{0x12, 0x34}, []byte("query-one")...)
	q2 := append([]byte{0xab, 0xcd}, []byte("query-two")...)
	sendUDPQuery(t, tun, appIP, dnsIP, 12345, 53, q1)
	sendUDPQuery(t, tun, appIP, dnsIP, 23456, 53, q2)
	waitDatagrams(t, cli, 2)

	// Responses in reverse order: the second query's answer first.
	r2 := append([]byte{0xab, 0xcd}, []byte("resp-two")...)
	r1 := append([]byte{0x12, 0x34}, []byte("resp-one")...)
	cli.emitDatagram("8.8.8.8:53", r2)
	cli.emitDatagram("8.8.8.8:53", r1)

	got := collectUDPReturns(t, tun, 2)
	if got[string(r2)] != 23456 {
		t.Fatalf("resp-two delivered to port %d, want 23456", got[string(r2)])
	}
	if got[string(r1)] != 12345 {
		t.Fatalf("resp-one delivered to port %d, want 12345 (cross-wired)", got[string(r1)])
	}
}

// TestEngineDNSConcurrentV6: same disambiguation over IPv6, with
// the response source address in the exact form the fixed dispatch
// emits (bracketed via datagramSourceAddr).
func TestEngineDNSConcurrentV6(t *testing.T) {
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("fd00::2")
	dnsIP := net.ParseIP("2001:4860:4860::8888")
	q1 := append([]byte{0x00, 0x01}, []byte("v6-query-one")...)
	q2 := append([]byte{0x00, 0x02}, []byte("v6-query-two")...)
	sendUDPQuery(t, tun, appIP, dnsIP, 12345, 53, q1)
	sendUDPQuery(t, tun, appIP, dnsIP, 23456, 53, q2)
	waitDatagrams(t, cli, 2)

	src := datagramSourceAddr(dnsIP, 53)
	r2 := append([]byte{0x00, 0x02}, []byte("v6-resp-two")...)
	r1 := append([]byte{0x00, 0x01}, []byte("v6-resp-one")...)
	cli.emitDatagram(src, r2)
	cli.emitDatagram(src, r1)

	got := collectUDPReturns(t, tun, 2)
	if got[string(r2)] != 23456 {
		t.Fatalf("v6-resp-two delivered to port %d, want 23456", got[string(r2)])
	}
	if got[string(r1)] != 12345 {
		t.Fatalf("v6-resp-one delivered to port %d, want 12345 (cross-wired)", got[string(r1)])
	}
}

// TestEngineDNSConcurrentParallel: N concurrent queries from
// distinct source ports with distinct transaction IDs, all to the
// same server, answered out of order. Every response must reach
// its own querier.
func TestEngineDNSConcurrentParallel(t *testing.T) {
	const n = 8
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dnsIP := net.ParseIP("8.8.8.8")
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			txID := uint16(0x1000 + i)
			q := append([]byte{byte(txID >> 8), byte(txID)}, []byte("q")...)
			sendUDPQuery(t, tun, appIP, dnsIP, uint16(30000+i), 53, q)
		}(i)
	}
	wg.Wait()
	waitDatagrams(t, cli, n)

	for i := n - 1; i >= 0; i-- {
		txID := uint16(0x1000 + i)
		r := append([]byte{byte(txID >> 8), byte(txID)}, []byte("r")...)
		cli.emitDatagram("8.8.8.8:53", r)
	}

	got := collectUDPReturns(t, tun, n)
	for i := 0; i < n; i++ {
		txID := uint16(0x1000 + i)
		payload := string(append([]byte{byte(txID >> 8), byte(txID)}, []byte("r")...))
		if got[payload] != uint16(30000+i) {
			t.Fatalf("response %d delivered to port %d, want %d", i, got[payload], 30000+i)
		}
	}
}
