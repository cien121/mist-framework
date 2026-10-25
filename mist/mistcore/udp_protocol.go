// Package mistcore: Mist UDP frame protocol.
//
// UDP uses whole-packet AEAD (one encryption per UDP datagram), unlike TCP's
// per-frame encryption. Frame headers are NOT visible on the wire.
//
// Frame format (plaintext, after decryption):
//   [LEN(2)][TYPE(1)][SID(1)][PAYLOAD]
//
// UDP datagram:
//   [QUIC short header (13)][AEAD(frame1|frame2|...)]

package mistcore

import (
	"encoding/binary"
	"errors"
	"time"
)

// UDP frame types (§4.1).
const (
	UDPFramePadding       = 0x00
	UDPFrameStream        = 0x01
	UDPFrameSyn           = 0x02
	UDPFrameFin           = 0x03
	UDPFrameRst           = 0x04
	UDPFrameAck           = 0x05
	UDPFramePing          = 0x06
	UDPFramePong          = 0x07
	UDPFrameDatagram      = 0x08
	UDPFramePathChallenge = 0x09
	UDPFramePathResponse  = 0x0A
	UDPFrameMigrate       = 0x0B
	UDPFrameMaxStreamData = 0x0C
	UDPFrameWindowUpdate  = 0x0D
	// UDPFrameDCIDRotate rotates the short-header DCID alongside a port
	// hop (signature hardening F5). Payload: [NEW_DCID(8)][WINDOW(4, BE)].
	// It travels inside the AEAD ciphertext, so the rotation signal
	// itself is invisible to passive DPI; only the new DCID (an
	// unrelated random value) appears on the wire afterwards.
	UDPFrameDCIDRotate = 0x0E
)

// UDP limits (§4.1).
const (
	// MaxUDPPlaintext is the max decrypted payload per UDP datagram.
	// 1350 (MTU) - 13 (QUIC header) - 16 (AEAD tag) = 1321, rounded to 1300.
	MaxUDPPlaintext = 1300

	// QUICShortHeaderLen is the MAX short header size (4-byte packet
	// number form). The 2-byte form is QUICShortHeaderLenMin (11).
	// Variable packet-number length (signature hardening F3):
	// packet number < 65536 uses 2 bytes, otherwise 4 bytes.
	QUICShortHeaderLen    = 13
	QUICShortHeaderLenMin = 11
)

// ShortHeaderLen returns the short header length for a packet number
// (F3): 11 bytes below 65536, 13 bytes at and above.
func ShortHeaderLen(packetNum uint32) int {
	if packetNum < 65536 {
		return QUICShortHeaderLenMin
	}
	return QUICShortHeaderLen
}

// UDPFrame is a decoded Mist UDP frame.
type UDPFrame struct {
	Type    byte
	SID     byte
	Payload []byte
}

// EncodeUDPFrame encodes a single frame: [LEN(2)][TYPE(1)][SID(1)][PAYLOAD].
// LEN = 2 + len(PAYLOAD) (bytes after the LEN field itself).
func EncodeUDPFrame(frameType byte, sid byte, payload []byte) []byte {
	// LEN(2) + TYPE(1) + SID(1) + PAYLOAD
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(out[0:], uint16(2+len(payload)))
	out[2] = frameType
	out[3] = sid
	copy(out[4:], payload)
	return out
}

// DecodeUDPFrames decodes concatenated frames from a decrypted payload.
// Returns the list of frames.
func DecodeUDPFrames(plaintext []byte) ([]UDPFrame, error) {
	var frames []UDPFrame
	off := 0
	for off < len(plaintext) {
		if off+4 > len(plaintext) {
			return nil, errors.New("udp: frame header truncated")
		}
		length := int(binary.BigEndian.Uint16(plaintext[off:]))
		frameType := plaintext[off+2]
		sid := plaintext[off+3]
		if length < 2 {
			return nil, errors.New("udp: invalid frame length")
		}
		payloadLen := length - 2
		if off+4+payloadLen > len(plaintext) {
			return nil, errors.New("udp: frame payload truncated")
		}
		frames = append(frames, UDPFrame{
			Type:    frameType,
			SID:     sid,
			Payload: plaintext[off+4 : off+4+payloadLen],
		})
		off += 4 + payloadLen
	}
	return frames, nil
}

// EncodeStreamFrame encodes a STREAM frame: [OFFSET(8)][DATA].
func EncodeStreamFrame(sid byte, offset uint64, data []byte) []byte {
	payload := make([]byte, 8+len(data))
	binary.BigEndian.PutUint64(payload[0:], offset)
	copy(payload[8:], data)
	return EncodeUDPFrame(UDPFrameStream, sid, payload)
}

// EncodeFinFrame encodes a FIN frame: [FINAL_SIZE(8)].
func EncodeFinFrame(sid byte, finalSize uint64) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload[0:], finalSize)
	return EncodeUDPFrame(UDPFrameFin, sid, payload)
}

// EncodePaddingFrame encodes a PADDING frame with the given total frame size.
// Per §4.1: [LEN(2)][TYPE(1)=0x00][SID(1)][zeros], minimum 4 bytes.
func EncodePaddingFrame(sid byte, totalLen int) []byte {
	if totalLen < 4 {
		totalLen = 4
	}
	payloadLen := totalLen - 4
	payload := make([]byte, payloadLen) // zeros
	return EncodeUDPFrame(UDPFramePadding, sid, payload)
}

// EncodeAckFrame encodes an ACK frame:
// [LARGEST(4)][ACK_DELAY_MS(2)][RANGE_N(1)][RANGE_1(8)]...
// Each range is [start(4)][end(4)] (closed interval, big-endian).
// ackDelay is how long the sender held this ACK after the largest packet
// arrived; the peer subtracts it from its RTT samples. Capped at 65535ms.
func EncodeAckFrame(sid byte, largest uint32, ackDelay time.Duration, ranges [][2]uint32) []byte {
	if len(ranges) > 8 {
		ranges = ranges[:8]
	}
	ms := ackDelay.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	if ms > 0xFFFF {
		ms = 0xFFFF
	}
	payload := make([]byte, 4+2+1+len(ranges)*8)
	binary.BigEndian.PutUint32(payload[0:], largest)
	binary.BigEndian.PutUint16(payload[4:], uint16(ms))
	payload[6] = byte(len(ranges))
	off := 7
	for _, r := range ranges {
		binary.BigEndian.PutUint32(payload[off:], r[0])
		binary.BigEndian.PutUint32(payload[off+4:], r[1])
		off += 8
	}
	return EncodeUDPFrame(UDPFrameAck, sid, payload)
}

// DecodeAckFrame decodes an ACK frame payload.
// Returns the receiver-reported ack_delay for RTT correction.
func DecodeAckFrame(payload []byte) (largest uint32, ackDelay time.Duration, ranges [][2]uint32, err error) {
	if len(payload) < 7 {
		return 0, 0, nil, errors.New("udp: ack payload too short")
	}
	largest = binary.BigEndian.Uint32(payload[0:])
	ackDelay = time.Duration(binary.BigEndian.Uint16(payload[4:])) * time.Millisecond
	n := int(payload[6])
	if len(payload) < 7+n*8 {
		return 0, 0, nil, errors.New("udp: ack ranges truncated")
	}
	for i := 0; i < n; i++ {
		start := binary.BigEndian.Uint32(payload[7+i*8:])
		end := binary.BigEndian.Uint32(payload[7+i*8+4:])
		ranges = append(ranges, [2]uint32{start, end})
	}
	return largest, ackDelay, ranges, nil
}

// EncodeDCIDRotateFrame encodes a DCID_ROTATE frame (F5):
// [NEW_DCID(8)][WINDOW(4, big-endian)]. SID is always 0 (control).
func EncodeDCIDRotateFrame(newDCID [8]byte, window uint32) []byte {
	payload := make([]byte, 12)
	copy(payload[0:8], newDCID[:])
	binary.BigEndian.PutUint32(payload[8:12], window)
	return EncodeUDPFrame(UDPFrameDCIDRotate, 0, payload)
}

// DecodeDCIDRotateFrame decodes a DCID_ROTATE frame payload.
func DecodeDCIDRotateFrame(payload []byte) (newDCID [8]byte, window uint32, err error) {
	if len(payload) != 12 {
		return newDCID, 0, errors.New("udp: DCID_ROTATE payload must be 12 bytes")
	}
	copy(newDCID[:], payload[0:8])
	window = binary.BigEndian.Uint32(payload[8:12])
	return newDCID, window, nil
}

// BuildShortHeader builds a QUIC short header (F3, variable length).
//
// Format (§3.2):
//
//	[0|1|S|R|R|K|P P][DCID(8)][PacketNum(2 or 4)]
//	bit0=0, bit1=1 (short header)
//	S = spin bit (F4: flipped once per RTT estimate, not random)
//	K = key phase (0)
//	P P = 0b01 (2-byte packet number, packetNum < 65536)
//	      0b11 (4-byte packet number, packetNum >= 65536)
//
// The 1-byte form is deliberately unused: under loss, reconstructing
// a 1-byte packet number is ambiguous, and saving 1 byte is not worth it.
func BuildShortHeader(dcid [8]byte, packetNum uint32, spinBit bool) []byte {
	pnLen := 2
	pp := byte(0x01)
	if packetNum >= 65536 {
		pnLen = 4
		pp = 0x03
	}
	h := make([]byte, 1+8+pnLen)
	// Byte 0: 0|1|S|0|0|0|P|P
	h[0] = 0x40 | pp
	if spinBit {
		h[0] |= 0x20 // set S bit (bit 2)
	}
	copy(h[1:], dcid[:])
	if pnLen == 2 {
		binary.BigEndian.PutUint16(h[9:], uint16(packetNum))
	} else {
		binary.BigEndian.PutUint32(h[9:], packetNum)
	}
	return h
}

// ParseShortHeader parses a QUIC short header of either length.
// Returns dcid, packet number, and spin bit. The PP bits must agree
// with the supplied header length; anything else is rejected (this
// also rejects the unused 1-byte and 3-byte forms).
func ParseShortHeader(header []byte) (dcid [8]byte, packetNum uint32, spinBit bool, err error) {
	if len(header) != QUICShortHeaderLenMin && len(header) != QUICShortHeaderLen {
		return dcid, 0, false, errors.New("udp: short header length must be 11 or 13")
	}
	// Check bits: bit0=0, bit1=1
	if header[0]&0xC0 != 0x40 {
		return dcid, 0, false, errors.New("udp: not a short header")
	}
	spinBit = header[0]&0x20 != 0
	pp := header[0] & 0x03
	if len(header) == QUICShortHeaderLenMin {
		if pp != 0x01 {
			return dcid, 0, false, errors.New("udp: 11-byte header must use 2-byte packet number")
		}
		packetNum = uint32(binary.BigEndian.Uint16(header[9:11]))
	} else {
		if pp != 0x03 {
			return dcid, 0, false, errors.New("udp: 13-byte header must use 4-byte packet number")
		}
		packetNum = binary.BigEndian.Uint32(header[9:13])
	}
	copy(dcid[:], header[1:9])
	return dcid, packetNum, spinBit, nil
}
