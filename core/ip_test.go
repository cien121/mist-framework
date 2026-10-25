package core

import (
	"encoding/binary"
	"net"
	"testing"
)

// verifyIPChecksum returns true if the header checksum is valid
// (checksum over the whole header, including the field, is 0).
func verifyIPChecksum(hdr []byte) bool {
	return checksum(hdr) == 0
}

func TestIPv4RoundTrip(t *testing.T) {
	src := net.ParseIP("10.0.0.2")
	dst := net.ParseIP("8.8.8.8")
	seg := BuildUDP(src, dst, 12345, 53, []byte("hello"))
	pkt := BuildIPv4(src, dst, ProtoUDP, 42, seg)
	p, err := ParseIP(pkt)
	if err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Version != 4 || !p.Src.Equal(src) || !p.Dst.Equal(dst) || p.Proto != ProtoUDP {
		t.Fatalf("bad parse: %+v", p)
	}
	dg, err := ParseUDP(p.Payload)
	if err != nil {
		t.Fatalf("ParseUDP: %v", err)
	}
	if dg.SrcPort != 12345 || dg.DstPort != 53 || string(dg.Payload) != "hello" {
		t.Fatalf("bad udp: %+v", dg)
	}
	if !verifyIPChecksum(pkt[:20]) {
		t.Fatal("ipv4 header checksum invalid")
	}
	// UDP checksum: pseudo-header + datagram including checksum sums to 0.
	ph := pseudoHeader(src, dst, ProtoUDP, len(seg))
	if checksum(append(ph, seg...)) != 0 {
		t.Fatal("udp checksum invalid")
	}
}

func TestIPv6RoundTrip(t *testing.T) {
	src := net.ParseIP("fd00::2")
	dst := net.ParseIP("2606:4700:4700::1111")
	seg := BuildUDP(src, dst, 12345, 53, []byte("dns-query"))
	pkt := BuildIPv6(src, dst, ProtoUDP, seg)
	p, err := ParseIP(pkt)
	if err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if p.Version != 6 || !p.Src.Equal(src) || !p.Dst.Equal(dst) || p.Proto != ProtoUDP {
		t.Fatalf("bad parse: %+v", p)
	}
	dg, err := ParseUDP(p.Payload)
	if err != nil {
		t.Fatalf("ParseUDP: %v", err)
	}
	if string(dg.Payload) != "dns-query" {
		t.Fatalf("bad payload: %q", dg.Payload)
	}
	ph := pseudoHeader(src, dst, ProtoUDP, len(seg))
	if checksum(append(ph, seg...)) != 0 {
		t.Fatal("udp v6 checksum invalid")
	}
}

func TestIPv6ExtensionWalk(t *testing.T) {
	src := net.ParseIP("fd00::2")
	dst := net.ParseIP("fd00::1")
	seg := BuildUDP(src, dst, 9999, 53, []byte("x"))
	// Insert a Destination Options header (type 60, len 0 => 8 bytes)
	// between the IPv6 header and the UDP datagram.
	inner := BuildIPv6(src, dst, ProtoUDP, seg)
	out := make([]byte, 0, len(inner)+8)
	out = append(out, inner[:40]...)
	out[6] = extDestOpts // next header
	// Dest Options header: NextHeader=UDP, HdrExtLen=0 (8 bytes total).
	out = append(out, ProtoUDP, 0, 0, 0, 0, 0, 0, 0)
	out = append(out, inner[40:]...)
	// Fix payload length.
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	p, err := ParseIP(out)
	if err != nil {
		t.Fatalf("ParseIP ext: %v", err)
	}
	if p.Proto != ProtoUDP {
		t.Fatalf("walk stopped at proto %d", p.Proto)
	}
	if _, err := ParseUDP(p.Payload); err != nil {
		t.Fatalf("ParseUDP after walk: %v", err)
	}
}

func TestIPv6FragmentDropped(t *testing.T) {
	src := net.ParseIP("fd00::2")
	dst := net.ParseIP("fd00::1")
	seg := BuildUDP(src, dst, 9999, 53, []byte("x"))
	inner := BuildIPv6(src, dst, ProtoUDP, seg)
	out := make([]byte, 0, len(inner)+8)
	out = append(out, inner[:40]...)
	out[6] = extFragment
	// Fragment header: next=UDP, reserved, offset=1 (non-first).
	out = append(out, ProtoUDP, 0, 0, 8, 0, 0, 0, 1)
	out = append(out, inner[40:]...)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	if _, err := ParseIP(out); err != errNonFirstFrag {
		t.Fatalf("expected errNonFirstFrag, got %v", err)
	}
}

func TestTCPBuildParse(t *testing.T) {
	src := net.ParseIP("10.0.0.2")
	dst := net.ParseIP("1.2.3.4")
	seg := BuildTCP(src, dst, 40000, 443, 1000, 5000, TCPPsh|TCPAck, []byte("data"))
	ts, err := ParseTCP(seg)
	if err != nil {
		t.Fatalf("ParseTCP: %v", err)
	}
	if ts.SrcPort != 40000 || ts.DstPort != 443 || ts.Seq != 1000 || ts.Ack != 5000 {
		t.Fatalf("bad tcp: %+v", ts)
	}
	if ts.Flags&(TCPPsh|TCPAck) != TCPPsh|TCPAck || string(ts.Payload) != "data" {
		t.Fatalf("bad flags/payload: %+v", ts)
	}
	ph := pseudoHeader(src, dst, ProtoTCP, len(seg))
	if checksum(append(ph, seg...)) != 0 {
		t.Fatal("tcp checksum invalid")
	}
}

func TestTCPv6BuildParse(t *testing.T) {
	src := net.ParseIP("fd00::2")
	dst := net.ParseIP("2607:f130::1")
	seg := BuildTCP(src, dst, 40000, 443, 777, 888, TCPSyn, nil)
	ts, err := ParseTCP(seg)
	if err != nil {
		t.Fatalf("ParseTCP v6: %v", err)
	}
	if ts.Seq != 777 || ts.Flags&TCPSyn == 0 {
		t.Fatalf("bad tcp v6: %+v", ts)
	}
	ph := pseudoHeader(src, dst, ProtoTCP, len(seg))
	if checksum(append(ph, seg...)) != 0 {
		t.Fatal("tcp v6 checksum invalid")
	}
	pkt := BuildIP(src, dst, ProtoTCP, 0, seg)
	p, err := ParseIP(pkt)
	if err != nil {
		t.Fatalf("ParseIP v6 tcp: %v", err)
	}
	if p.Version != 6 || p.Proto != ProtoTCP {
		t.Fatalf("bad v6 tcp packet: %+v", p)
	}
}
