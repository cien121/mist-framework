// IP packet parsing and building for the TUN forwarding engine.
//
// IPv4 + IPv6 dual stack (chan 2026-10-24 requirement: the Mist
// production egress is VPS IPv6, so v6 routing is mandatory).
// TCP and UDP headers are parsed; checksums are computed with the
// IPv4 or IPv6 pseudo-header as appropriate.
//
// IPv6 extension headers are walked to find the upper-layer header
// (Hop-by-Hop, Routing, Fragment, Destination Options, AH). ESP
// cannot be walked and non-first fragments carry no L4 header;
// both are dropped by the engine.
package core

import (
	"encoding/binary"
	"errors"
	"net"
)

// IP protocol numbers (shared by v4 and v6 next-header field).
const (
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMP   = 1
	ProtoICMPv6 = 58
)

// IPv6 extension header types.
const (
	extHopByHop = 0
	extRouting  = 43
	extFragment = 44
	extAH       = 51
	extESP      = 50
	extDestOpts = 60
)

// TCP flags.
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10
)

// IPPacket is a parsed IP packet, v4 or v6. Payload is the L4 segment
// (TCP or UDP, including its header). The byte slice aliases the
// original packet buffer; do not retain it past the current packet.
type IPPacket struct {
	Version int // 4 or 6
	Src     net.IP
	Dst     net.IP
	Proto   uint8 // upper-layer protocol after extension walk
	Payload []byte
}

// IPv4Packet is a parsed IPv4 packet (kept for direct v4 use).
type IPv4Packet struct {
	Src     net.IP // 4 bytes
	Dst     net.IP // 4 bytes
	Proto   uint8
	Payload []byte
	ID      uint16
	TTL     uint8
}

// IPv6Packet is a parsed IPv6 packet (kept for direct v6 use).
type IPv6Packet struct {
	Src     net.IP // 16 bytes
	Dst     net.IP // 16 bytes
	Proto   uint8  // upper-layer protocol after extension walk
	Payload []byte
}

// TCPSegment is a parsed TCP segment.
type TCPSegment struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Payload []byte
}

// UDPPacket is a parsed UDP datagram.
type UDPPacket struct {
	SrcPort uint16
	DstPort uint16
	Payload []byte
}

var (
	errShortIP      = errors.New("ip: packet too short")
	errBadVersion   = errors.New("ip: unknown version")
	errNotIPv4      = errors.New("ip: not IPv4")
	errBadIHL       = errors.New("ip: bad header length")
	errShortIPv6    = errors.New("ip: ipv6 packet too short")
	errExtWalk      = errors.New("ip: cannot walk extension headers")
	errNonFirstFrag = errors.New("ip: non-first fragment, no L4 header")
	errShortTCP     = errors.New("tcp: segment too short")
	errShortUDP     = errors.New("udp: datagram too short")
)

// ParseIP dispatches on the version nibble and parses v4 or v6.
func ParseIP(b []byte) (*IPPacket, error) {
	if len(b) < 1 {
		return nil, errShortIP
	}
	switch b[0] >> 4 {
	case 4:
		p, err := ParseIPv4(b)
		if err != nil {
			return nil, err
		}
		return &IPPacket{Version: 4, Src: p.Src, Dst: p.Dst, Proto: p.Proto, Payload: p.Payload}, nil
	case 6:
		p, err := ParseIPv6(b)
		if err != nil {
			return nil, err
		}
		return &IPPacket{Version: 6, Src: p.Src, Dst: p.Dst, Proto: p.Proto, Payload: p.Payload}, nil
	default:
		return nil, errBadVersion
	}
}

// ParseIPv4 parses an IPv4 packet. It does not verify checksums
// (packets from the local TUN are trusted).
func ParseIPv4(b []byte) (*IPv4Packet, error) {
	if len(b) < 20 {
		return nil, errShortIP
	}
	if b[0]>>4 != 4 {
		return nil, errNotIPv4
	}
	ihl := int(b[0]&0x0F) * 4
	if ihl < 20 || len(b) < ihl {
		return nil, errBadIHL
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total > len(b) {
		total = len(b)
	}
	if total < ihl {
		return nil, errBadIHL
	}
	return &IPv4Packet{
		Src:     net.IP(b[12:16]).To4(),
		Dst:     net.IP(b[16:20]).To4(),
		Proto:   b[9],
		Payload: b[ihl:total],
		ID:      binary.BigEndian.Uint16(b[4:6]),
		TTL:     b[8],
	}, nil
}

// ParseIPv6 parses an IPv6 packet, walking extension headers to the
// upper-layer header. Returns errNonFirstFrag for non-first fragments
// and errExtWalk for ESP or truncated extension headers.
func ParseIPv6(b []byte) (*IPv6Packet, error) {
	if len(b) < 40 {
		return nil, errShortIPv6
	}
	if b[0]>>4 != 6 {
		return nil, errBadVersion
	}
	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	end := 40 + payloadLen
	if end > len(b) {
		end = len(b)
	}
	next := b[6]
	off := 40
	for isExtHeader(next) {
		if off+2 > end {
			return nil, errExtWalk
		}
		switch next {
		case extFragment:
			if off+8 > end {
				return nil, errExtWalk
			}
			// Fragment offset is bits 3-15 of bytes 2-3.
			fragOff := (binary.BigEndian.Uint16(b[off+2:off+4]) >> 3) & 0x1FFF
			if fragOff != 0 {
				return nil, errNonFirstFrag
			}
			next = b[off]
			off += 8
		case extAH:
			// AH length: (PayloadLen+2)*4.
			hdrLen := (int(b[off+1]) + 2) * 4
			if off+hdrLen > end {
				return nil, errExtWalk
			}
			next = b[off]
			off += hdrLen
		default: // Hop-by-Hop, Routing, Destination Options
			hdrLen := (int(b[off+1]) + 1) * 8
			if off+hdrLen > end {
				return nil, errExtWalk
			}
			next = b[off]
			off += hdrLen
		}
	}
	if next == extESP {
		return nil, errExtWalk
	}
	return &IPv6Packet{
		Src:     net.IP(b[8:24]).To16(),
		Dst:     net.IP(b[24:40]).To16(),
		Proto:   next,
		Payload: b[off:end],
	}, nil
}

func isExtHeader(nh uint8) bool {
	switch nh {
	case extHopByHop, extRouting, extFragment, extAH, extDestOpts:
		return true
	}
	return false
}

// ParseTCP parses a TCP segment (header + payload).
func ParseTCP(b []byte) (*TCPSegment, error) {
	if len(b) < 20 {
		return nil, errShortTCP
	}
	off := int(b[12]>>4) * 4
	if off < 20 || len(b) < off {
		return nil, errShortTCP
	}
	return &TCPSegment{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Seq:     binary.BigEndian.Uint32(b[4:8]),
		Ack:     binary.BigEndian.Uint32(b[8:12]),
		Flags:   b[13] & 0x3F,
		Payload: b[off:],
	}, nil
}

// ParseUDP parses a UDP datagram (header + payload).
func ParseUDP(b []byte) (*UDPPacket, error) {
	if len(b) < 8 {
		return nil, errShortUDP
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length > len(b) {
		length = len(b)
	}
	if length < 8 {
		return nil, errShortUDP
	}
	return &UDPPacket{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Payload: b[8:length],
	}, nil
}

// checksum computes the Internet checksum (RFC 1071) over b.
// If b has odd length it is padded with a zero byte.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// pseudoHeader builds the checksum pseudo-header for src->dst.
// v4: src(4)+dst(4)+zero(1)+proto(1)+len(2).
// v6: src(16)+dst(16)+len(4)+zeros(3)+proto(1).
func pseudoHeader(src, dst net.IP, proto uint8, length int) []byte {
	if src4 := src.To4(); src4 != nil {
		ph := make([]byte, 12)
		copy(ph[0:4], src4)
		copy(ph[4:8], dst.To4())
		ph[8] = 0
		ph[9] = proto
		binary.BigEndian.PutUint16(ph[10:12], uint16(length))
		return ph
	}
	ph := make([]byte, 40)
	copy(ph[0:16], src.To16())
	copy(ph[16:32], dst.To16())
	binary.BigEndian.PutUint32(ph[32:36], uint32(length))
	ph[39] = proto
	return ph
}

// BuildIPv4 builds an IPv4 packet (no options) with a correct header
// checksum. proto is ProtoTCP or ProtoUDP.
func BuildIPv4(src, dst net.IP, proto uint8, id uint16, payload []byte) []byte {
	out := make([]byte, 20+len(payload))
	out[0] = 0x45 // version 4, IHL 5
	out[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	binary.BigEndian.PutUint16(out[4:6], id)
	binary.BigEndian.PutUint16(out[6:8], 0x4000) // DF
	out[8] = 64                                  // TTL
	out[9] = proto
	copy(out[12:16], src.To4())
	copy(out[16:20], dst.To4())
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	copy(out[20:], payload)
	return out
}

// BuildIPv6 builds an IPv6 packet (no extension headers) with the
// given next-header protocol.
func BuildIPv6(src, dst net.IP, proto uint8, payload []byte) []byte {
	out := make([]byte, 40+len(payload))
	out[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)))
	out[6] = proto
	out[7] = 64 // hop limit
	copy(out[8:24], src.To16())
	copy(out[24:40], dst.To16())
	copy(out[40:], payload)
	return out
}

// BuildIP builds a v4 or v6 packet based on the address family of src.
// proto is the upper-layer protocol (TCP/UDP).
func BuildIP(src, dst net.IP, proto uint8, id uint16, payload []byte) []byte {
	if src.To4() != nil {
		return BuildIPv4(src, dst, proto, id, payload)
	}
	return BuildIPv6(src, dst, proto, payload)
}

// BuildTCP builds a TCP segment (no options) with a correct checksum
// over the v4 or v6 pseudo-header (chosen by src family).
func BuildTCP(src, dst net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	out := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(out[0:2], srcPort)
	binary.BigEndian.PutUint16(out[2:4], dstPort)
	binary.BigEndian.PutUint32(out[4:8], seq)
	binary.BigEndian.PutUint32(out[8:12], ack)
	out[12] = 0x50 // data offset 5
	out[13] = flags
	binary.BigEndian.PutUint16(out[14:16], 65535) // window
	copy(out[20:], payload)
	// Checksum over pseudo-header + segment (payload must be in place first).
	ph := pseudoHeader(src, dst, ProtoTCP, len(out))
	sum := checksum(append(ph, out...))
	binary.BigEndian.PutUint16(out[16:18], sum)
	return out
}

// BuildUDP builds a UDP datagram with a correct checksum over the
// v4 or v6 pseudo-header. A zero checksum is valid for UDP but we
// always compute one (some stacks drop zero-checksum packets).
func BuildUDP(src, dst net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(out[0:2], srcPort)
	binary.BigEndian.PutUint16(out[2:4], dstPort)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)))
	copy(out[8:], payload)
	ph := pseudoHeader(src, dst, ProtoUDP, len(out))
	sum := checksum(append(ph, out...))
	if sum == 0 {
		sum = 0xFFFF // transmitted zero means "no checksum"; avoid it
	}
	binary.BigEndian.PutUint16(out[6:8], sum)
	return out
}

// FourTuple identifies a TUN-side flow. IPs are strings so v4 and v6
// share one key type.
type FourTuple struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	Proto   uint8
}

// TupleOf builds a FourTuple from a parsed packet and its L4 ports.
func TupleOf(p *IPPacket, srcPort, dstPort uint16) FourTuple {
	return FourTuple{
		SrcIP:   p.Src.String(),
		SrcPort: srcPort,
		DstIP:   p.Dst.String(),
		DstPort: dstPort,
		Proto:   p.Proto,
	}
}
