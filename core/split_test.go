package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

// Unit + engine tests for split routing, DNS-leak protection and
// DNS-layer ad blocking (see split.go). The decision mechanism is
// domain-driven (v1 has no CN CIDR table): domestic domains resolve
// locally and their answer IPs are learned for direct routing;
// private/reserved IPs are always direct; literal IPs with no
// domestic-resolution record default to the tunnel.

func buildDNSQuery(id uint16, name string, qtype uint16) []byte {
	out := make([]byte, 0, 64)
	var h [12]byte
	binary.BigEndian.PutUint16(h[0:2], id)
	binary.BigEndian.PutUint16(h[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(h[4:6], 1)      // QDCOUNT
	out = append(out, h[:]...)
	for _, label := range splitLabels(name) {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	var q [4]byte
	binary.BigEndian.PutUint16(q[0:2], qtype)
	binary.BigEndian.PutUint16(q[2:4], 1) // CLASS IN
	out = append(out, q[:]...)
	return out
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	return append(out, name[start:])
}

// sendDNSQuery injects one DNS query from the app into the TUN.
func sendDNSQuery(t *testing.T, tun *mockTUN, appPort uint16, id uint16, name string, qtype uint16) {
	t.Helper()
	appIP := net.ParseIP("10.0.0.2")
	dnsIP := net.ParseIP("8.8.8.8")
	seg := BuildUDP(appIP, dnsIP, appPort, 53, buildDNSQuery(id, name, qtype))
	tun.readCh <- BuildIPv4(appIP, dnsIP, ProtoUDP, id, seg)
}

// readDNSResponse reads one TUN packet and returns its UDP payload.
func readDNSResponse(t *testing.T, tun *mockTUN) (uint16, []byte) {
	t.Helper()
	return readTUNUDP(t, tun)
}

// parseFirstAnswer extracts (flags, ancount, first answer TYPE,
// first answer RDATA) from a DNS response. It fails the test on
// malformed input.
func parseFirstAnswer(t *testing.T, resp []byte) (flags uint16, ancount uint16, atype uint16, rdata []byte) {
	t.Helper()
	if len(resp) < 12 {
		t.Fatalf("dns response too short: %d bytes", len(resp))
	}
	flags = binary.BigEndian.Uint16(resp[2:4])
	ancount = binary.BigEndian.Uint16(resp[6:8])
	_, _, qEnd, err := parseDNSQuestion(resp)
	if err != nil {
		t.Fatalf("parse question in response: %v", err)
	}
	if ancount == 0 {
		return flags, ancount, 0, nil
	}
	off := qEnd
	if off+2 > len(resp) || resp[off] != 0xC0 {
		t.Fatalf("answer name is not a compression pointer: %x", resp[off:])
	}
	off += 2
	if off+10 > len(resp) {
		t.Fatalf("answer header truncated")
	}
	atype = binary.BigEndian.Uint16(resp[off : off+2])
	rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
	off += 10
	if off+rdlen > len(resp) {
		t.Fatalf("answer rdata truncated")
	}
	return flags, ancount, atype, resp[off : off+rdlen]
}

// pipeLocalDNSDial returns a dial func whose "resolver" is an
// in-memory net.Pipe serving one fixed A record for any query it can
// parse (ID + question copied from the query, response bytes
// verbatim-style). It stands in for a real UDP resolver because UDP
// replies are dropped by this sandbox's proxy, while the engine's
// local-resolution path (forward query bytes, return response bytes,
// learn A/AAAA) is transport-agnostic.
func pipeLocalDNSDial(t *testing.T, answerIP net.IP) func(network, address string, timeout time.Duration) (net.Conn, error) {
	t.Helper()
	return func(network, address string, timeout time.Duration) (net.Conn, error) {
		cli, srv := net.Pipe()
		go func() {
			defer srv.Close()
			buf := make([]byte, 4096)
			n, err := srv.Read(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			_, _, qEnd, err := parseDNSQuestion(query)
			if err != nil || qEnd > len(query) {
				return
			}
			resp := make([]byte, 0, qEnd+16)
			resp = append(resp, query[0], query[1]) // ID preserved
			var h [10]byte
			binary.BigEndian.PutUint16(h[0:2], 0x8180) // QR + RA, NOERROR
			binary.BigEndian.PutUint16(h[2:4], 1)      // QDCOUNT
			binary.BigEndian.PutUint16(h[4:6], 1)      // ANCOUNT
			resp = append(resp, h[:]...)
			resp = append(resp, query[12:qEnd]...) // question verbatim
			resp = append(resp, 0xC0, 0x0C)        // NAME pointer
			var a [10]byte
			binary.BigEndian.PutUint16(a[0:2], 1) // TYPE A
			binary.BigEndian.PutUint16(a[2:4], 1) // CLASS IN
			binary.BigEndian.PutUint32(a[4:8], 60)
			binary.BigEndian.PutUint16(a[8:10], 4)
			resp = append(resp, a[:]...)
			resp = append(resp, answerIP.To4()...)
			_, _ = srv.Write(resp)
		}()
		return cli, nil
	}
}

func TestSplitShouldDirect(t *testing.T) {
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli, SplitEnabled: true})
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.5", true},    // private
		{"10.0.0.9", true},       // private
		{"127.0.0.1", true},      // loopback
		{"100.64.1.2", true},     // CGNAT reserved
		{"8.8.8.8", false},       // foreign literal, no record
		{"93.184.216.34", false}, // foreign literal, no record
	}
	for _, tc := range cases {
		if got := e.shouldDirect(tc.ip); got != tc.want {
			t.Errorf("split on: shouldDirect(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	// A domestic-resolution record flips a foreign IP to direct.
	e.learnIP("180.101.49.12")
	if !e.shouldDirect("180.101.49.12") {
		t.Error("learned domestic IP should route direct")
	}
	// An expired record does not.
	e.learnedMu.Lock()
	e.learnedIPs["9.9.9.9"] = time.Now().Add(-time.Minute)
	e.learnedMu.Unlock()
	if e.isLearnedIP("9.9.9.9") || e.shouldDirect("9.9.9.9") {
		t.Error("expired learned IP must not route direct")
	}
	// Split off: nothing is direct, not even private/learned IPs.
	e.SetSplitEnabled(false)
	for _, tc := range cases {
		if e.shouldDirect(tc.ip) {
			t.Errorf("split off: shouldDirect(%s) must be false", tc.ip)
		}
	}
	if e.shouldDirect("180.101.49.12") {
		t.Error("split off: learned IP must not route direct")
	}
}

func TestSplitDomainClassification(t *testing.T) {
	domestic := []string{"baidu.com", "www.baidu.com", "WWW.BAIDU.COM.", "example.com.cn", "foo.bar.cn", "weibo.cn", "qq.com"}
	for _, d := range domestic {
		if !isDomesticDomain(d) {
			t.Errorf("isDomesticDomain(%q) = false, want true", d)
		}
	}
	foreign := []string{"google.com", "www.google.com", "youtube.com", "facebook.com", "example.cn.com", "cn.example.com", "notcn.org", ""}
	for _, d := range foreign {
		if isDomesticDomain(d) {
			t.Errorf("isDomesticDomain(%q) = true, want false", d)
		}
	}
	ads := []string{"doubleclick.net", "ads.doubleclick.net", "adservice.google.com"}
	for _, d := range ads {
		if !isAdblockDomain(d) {
			t.Errorf("isAdblockDomain(%q) = false, want true", d)
		}
	}
	notAds := []string{"google.com", "baidu.com", "example.com", ""}
	for _, d := range notAds {
		if isAdblockDomain(d) {
			t.Errorf("isAdblockDomain(%q) = true, want false", d)
		}
	}
}

func TestSplitParseLocalDNS(t *testing.T) {
	def := parseLocalDNSServers("")
	if len(def) != 2 || def[0] != "223.5.5.5:53" || def[1] != "114.114.114.114:53" {
		t.Fatalf("default local DNS = %v, want [223.5.5.5:53 114.114.114.114:53]", def)
	}
	got := parseLocalDNSServers("8.8.8.8, 1.1.1.1:5353")
	if len(got) != 2 || got[0] != "8.8.8.8:53" || got[1] != "1.1.1.1:5353" {
		t.Fatalf("parseLocalDNSServers custom = %v", got)
	}
	got = parseLocalDNSServers("2001:4860:4860::8888")
	if len(got) != 1 || got[0] != "[2001:4860:4860::8888]:53" {
		t.Fatalf("parseLocalDNSServers bare IPv6 = %v", got)
	}
	if got := parseLocalDNSServers(" , "); len(got) != 2 {
		t.Fatalf("blank local DNS must restore defaults, got %v", got)
	}
}

func TestSplitAdblockResponseShape(t *testing.T) {
	// A -> 0.0.0.0, preserving ID + question, QR=1, RA=1, NOERROR.
	q := buildDNSQuery(0xABCD, "ads.doubleclick.net", 1)
	resp, ok := buildAdblockResponse(q)
	if !ok {
		t.Fatal("buildAdblockResponse failed for A query")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0xABCD {
		t.Fatalf("adblock response ID = %04x, want abcd", binary.BigEndian.Uint16(resp[0:2]))
	}
	flags, an, atype, rdata := parseFirstAnswer(t, resp)
	if flags&0x8000 == 0 || flags&0x0080 == 0 || flags&0x000F != 0 {
		t.Fatalf("adblock flags = %04x, want QR+RA and RCODE 0", flags)
	}
	if an != 1 || atype != 1 || net.IP(rdata).String() != "0.0.0.0" {
		t.Fatalf("adblock A answer: an=%d type=%d rdata=%v", an, atype, rdata)
	}
	// AAAA -> ::.
	q = buildDNSQuery(0x1234, "ads.doubleclick.net", 28)
	resp, ok = buildAdblockResponse(q)
	if !ok {
		t.Fatal("buildAdblockResponse failed for AAAA query")
	}
	_, an, atype, rdata = parseFirstAnswer(t, resp)
	if an != 1 || atype != 28 || net.IP(rdata).String() != "::" {
		t.Fatalf("adblock AAAA answer: an=%d type=%d rdata=%v", an, atype, rdata)
	}
	// Other types -> NOERROR with no answers.
	q = buildDNSQuery(0x5678, "ads.doubleclick.net", 15) // MX
	resp, ok = buildAdblockResponse(q)
	if !ok {
		t.Fatal("buildAdblockResponse failed for MX query")
	}
	_, an, _, _ = parseFirstAnswer(t, resp)
	if an != 0 {
		t.Fatalf("adblock MX answer count = %d, want 0", an)
	}
}

func TestSplitAdblockEngine(t *testing.T) {
	// Ad blocking is independent of SplitEnabled: with split OFF,
	// ads are still blocked before the tunnel.
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli, AdblockEnabled: false, SplitEnabled: false})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	// Adblock off: the ad query goes to the tunnel.
	sendDNSQuery(t, tun, 20001, 0x1001, "ads.doubleclick.net", 1)
	waitDgSent(t, cli, 1)

	// Live toggle on: the next ad query is answered locally with
	// the null address and never reaches the tunnel client.
	e.SetAdblockEnabled(true)
	sendDNSQuery(t, tun, 20002, 0x1002, "ads.doubleclick.net", 1)
	port, payload := readDNSResponse(t, tun)
	if port != 20002 {
		t.Fatalf("adblock response port = %d, want 20002", port)
	}
	_, an, _, rdata := parseFirstAnswer(t, payload)
	if an != 1 || net.IP(rdata).String() != "0.0.0.0" {
		t.Fatalf("adblock engine answer: an=%d rdata=%v", an, rdata)
	}
	cli.mu.Lock()
	n := len(cli.dgSent)
	cli.mu.Unlock()
	if n != 1 {
		t.Fatalf("adblock query reached the tunnel: dgSent = %d, want 1", n)
	}
}

func TestSplitDomesticLocalDNS(t *testing.T) {
	answerIP := net.ParseIP("180.101.49.12")

	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli, SplitEnabled: true})
	e.localDNSDial = pipeLocalDNSDial(t, answerIP)
	e.SetLocalDNS("127.0.0.1:53") // live update, not just Start config
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	// Domestic domain: resolved locally, verbatim response, the
	// answer IP is learned, and nothing goes to the tunnel.
	sendDNSQuery(t, tun, 20001, 0x2001, "www.baidu.com", 1)
	_, payload := readDNSResponse(t, tun)
	_, an, _, rdata := parseFirstAnswer(t, payload)
	if an != 1 || net.IP(rdata).String() != "180.101.49.12" {
		t.Fatalf("domestic local answer: an=%d rdata=%v", an, rdata)
	}
	if !e.isLearnedIP("180.101.49.12") {
		t.Fatal("domestic local answer IP was not learned")
	}
	if e.shouldDirect("180.101.49.12") != true {
		t.Fatal("learned domestic IP should route direct")
	}
	cli.mu.Lock()
	n := len(cli.dgSent)
	cli.mu.Unlock()
	if n != 0 {
		t.Fatalf("domestic query reached the tunnel: dgSent = %d", n)
	}

	// Foreign domain: NOT resolved locally — it goes to the tunnel
	// (the local resolver is never consulted for it).
	sendDNSQuery(t, tun, 20002, 0x2002, "www.google.com", 1)
	waitDgSent(t, cli, 1)
	if _, _, ok := tryReadTUNUDP(tun, 300*time.Millisecond); ok {
		t.Fatal("foreign query must not get a local TUN answer")
	}
}

func TestSplitDomesticLocalDNSFallback(t *testing.T) {
	// A dead local resolver degrades to tunnel DNS, never to a
	// dropped query: the domestic query still reaches the tunnel.
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli, SplitEnabled: true, LocalDNS: "256.256.256.256:53"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	sendDNSQuery(t, tun, 20001, 0x3001, "www.baidu.com", 1)
	waitDgSent(t, cli, 1)
	cli.mu.Lock()
	rec := cli.dgSent[0]
	cli.mu.Unlock()
	if rec.target != "8.8.8.8:53" {
		t.Fatalf("fallback target = %q, want 8.8.8.8:53", rec.target)
	}
}

func TestSplitDirectUDP(t *testing.T) {
	// Private/loopback UDP bypasses the tunnel: one DialUDP conn per
	// tuple, the datagram leaves on the direct socket (direct upload
	// counter moves), and nothing reaches the tunnel client.
	// (A full echo round-trip cannot run here: this sandbox's proxy
	// drops UDP replies. The return loop writes through the same
	// writeTUNLocked path the adblock/DNS tests already cover.)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	echoPort := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli, SplitEnabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("127.0.0.1")
	seg := BuildUDP(appIP, dstIP, 20001, echoPort, []byte("ping-direct"))
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoUDP, 1, seg)
	waitFor(t, "direct udp send", func() bool {
		return e.Stats().DirectUploadBytes == uint64(len("ping-direct"))
	})
	e.mu.Lock()
	sess, ok := e.udp[FourTuple{SrcIP: "10.0.0.2", DstIP: "127.0.0.1", SrcPort: 20001, DstPort: echoPort, Proto: ProtoUDP}]
	e.mu.Unlock()
	if !ok || !sess.direct || sess.directConn == nil {
		t.Fatalf("direct session missing: ok=%v direct=%v conn=%v", ok, sess.direct, sess.directConn != nil)
	}
	cli.mu.Lock()
	n := len(cli.dgSent)
	cli.mu.Unlock()
	if n != 0 {
		t.Fatalf("direct udp reached the tunnel: dgSent = %d", n)
	}
}

func TestSplitDirectTCPFallback(t *testing.T) {
	// A direct TCP dial failure falls back to the tunnel (fail-closed
	// to the tunnel, never fail-open to a refused connection).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listens here anymore: direct dial refused

	tun := newMockTUN()
	srvCh := make(chan net.Conn, 1)
	cli := &mockClient{
		dialFunc: func(addr string) (net.Conn, error) {
			c, s := net.Pipe()
			srvCh <- s
			return c, nil
		},
	}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli, SplitEnabled: true})
	e.learnIP("127.0.0.1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("127.0.0.1")
	syn := BuildTCP(appIP, dstIP, 40000, uint16(closedPort), 1000, 0, TCPSyn, nil)
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoTCP, 1, syn)

	// Expect SYN-ACK from the tunnel fallback, not an RST.
	var synAck []byte
	select {
	case synAck = <-tun.writeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("no SYN-ACK from tunnel fallback")
	}
	p, err := ParseIP(synAck)
	if err != nil {
		t.Fatalf("parse synack: %v", err)
	}
	seg, err := ParseTCP(p.Payload)
	if err != nil {
		t.Fatalf("parse synack tcp: %v", err)
	}
	if seg.Flags&(TCPSyn|TCPAck) != TCPSyn|TCPAck {
		t.Fatalf("fallback reply flags = %x, want SYN+ACK", seg.Flags)
	}
	cli.mu.Lock()
	dialed := append([]string(nil), cli.dialed...)
	cli.mu.Unlock()
	want := fmt.Sprintf("127.0.0.1:%d", closedPort)
	found := false
	for _, d := range dialed {
		if d == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("tunnel fallback dial missing: dialed = %v, want %s", dialed, want)
	}
}
