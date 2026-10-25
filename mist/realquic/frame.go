package realquic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Production custom-frame format for taken-over (non-H3) streams.
//
// Wire layout, every frame, in order:
//
//	[MAGIC(1) = 0x4D][TYPE(1)][LEN(2) big-endian][PAYLOAD(LEN)]
//
// Why this shape, and why it is not the S1 spike format:
//   - The S1 format was [LEN(2) BE][TYPE(1)][PAYLOAD]. Its first byte is
//     the high byte of LEN, so a payload of 256-511 bytes makes the first
//     byte 0x01, which is exactly the H3 HEADERS frame type. The Peek
//     dispatcher (which must tell H3 streams from custom streams by their
//     first byte, because a blind takeover is closed by the H3 stack with
//     H3_FRAME_UNEXPECTED) then misroutes the stream and the stream is
//     cancelled. That failure was reproduced on real kernel UDP in step 3.
//   - This format puts a constant magic byte first. MAGIC is 0x4D ('M')
//     and is never 0x01, at any payload length, because it does not depend
//     on LEN at all. The dispatcher peeks one byte: 0x01 means H3
//     (HEADERS is always the first frame of an H3 request stream),
//     0x4D means a custom frame, anything else is rejected.
//   - TYPE values also exclude 0x01 (belt and braces: the magic byte is
//     the discriminator, but no type byte may ever read as HEADERS either).
//   - Parsing always reads the magic byte first, then TYPE, then LEN, then
//     exactly LEN payload bytes. No field is ever inferred from a length
//     byte, and no payload content can change the frame boundary.
//
// Step-5 layering (session keys), implemented in session.go:
//   - Frame payloads pass through a PayloadCodec. Before AUTH the
//     identity codec is used (the server refuses pre-AUTH custom
//     streams anyway); after AUTH both sides install the session-key
//     AEAD codec (SessionCodec), and the outer [MAGIC][TYPE][LEN]
//     structure does not change, only the payload bytes between LEN
//     and the next frame do. DATA writes are chunked to maxDataChunk
//     (32 KiB) so the AEAD overhead (24-byte nonce + 16-byte tag)
//     still fits comfortably inside the uint16 LEN field.
const frameMagic byte = 0x4D // 'M'; constant, never 0x01

// Custom frame types. None is 0x01 (H3 HEADERS).
const (
	frameConnect     byte = 0x10 // client -> server: CONNECT request
	frameConnectOK   byte = 0x11 // server -> client: dial succeeded
	frameConnectErr  byte = 0x12 // server -> client: dial failed (payload: message)
	frameData        byte = 0x13 // either direction, on a CONNECT stream: relay bytes
	frameRegisterUDP byte = 0x14 // client -> server: register a UDP session
	frameRegisterOK  byte = 0x15 // server -> client: session registered
	frameRegisterErr byte = 0x16 // server -> client: registration failed (payload: message)
)

// maxDataChunk bounds one DATA frame's payload, leaving headroom for the
// step-5 AEAD tag inside the uint16 LEN field.
const maxDataChunk = 32 * 1024

// maxFramePayload is the largest payload a single frame may carry.
const maxFramePayload = 65535

// PayloadCodec transforms a frame payload. IdentityCodec is the pre-AUTH
// codec; SessionCodec (session.go) is the post-AUTH session-key AEAD
// codec. Swapping codecs never changes the frame structure.
type PayloadCodec interface {
	Seal(payload []byte) ([]byte, error)
	Open(payload []byte) ([]byte, error)
}

// IdentityCodec passes payloads through unchanged.
type IdentityCodec struct{}

func (IdentityCodec) Seal(p []byte) ([]byte, error) { return p, nil }
func (IdentityCodec) Open(p []byte) ([]byte, error) { return p, nil }

// Frame is one decoded custom frame.
type Frame struct {
	Type    byte
	Payload []byte
}

// WriteFrame writes one frame with the identity codec.
func WriteFrame(w io.Writer, typ byte, payload []byte) error {
	return WriteFrameCodec(w, typ, payload, IdentityCodec{})
}

// WriteFrameCodec writes one frame, sealing the payload through codec.
// It rejects TYPE 0x01 outright: no custom frame may ever present as H3.
func WriteFrameCodec(w io.Writer, typ byte, payload []byte, codec PayloadCodec) error {
	if typ == 0x01 {
		return errors.New("realquic: frame type 0x01 is reserved for H3 HEADERS")
	}
	sealed, err := codec.Seal(payload)
	if err != nil {
		return err
	}
	if len(sealed) > maxFramePayload {
		return fmt.Errorf("realquic: frame payload %d exceeds %d", len(sealed), maxFramePayload)
	}
	out := make([]byte, 4+len(sealed))
	out[0] = frameMagic
	out[1] = typ
	binary.BigEndian.PutUint16(out[2:4], uint16(len(sealed)))
	copy(out[4:], sealed)
	_, err = w.Write(out)
	return err
}

// ReadFrame reads one frame with the identity codec.
func ReadFrame(r io.Reader) (Frame, error) {
	return ReadFrameCodec(r, IdentityCodec{})
}

// ReadFrameCodec reads one frame: magic first, then type, then length,
// then exactly that many payload bytes, opened through codec.
func ReadFrameCodec(r io.Reader, codec PayloadCodec) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	if hdr[0] != frameMagic {
		return Frame{}, fmt.Errorf("realquic: bad frame magic 0x%02x, want 0x%02x", hdr[0], frameMagic)
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4]))
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	opened, err := codec.Open(payload)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Type: hdr[1], Payload: opened}, nil
}

// encodeTarget encodes a dial target ("host:port") as [len(1)][bytes].
func encodeTarget(addr string) ([]byte, error) {
	if len(addr) == 0 || len(addr) > 255 {
		return nil, fmt.Errorf("realquic: target length %d out of range", len(addr))
	}
	out := make([]byte, 1+len(addr))
	out[0] = byte(len(addr))
	copy(out[1:], addr)
	return out, nil
}

// decodeTarget decodes an encodeTarget payload.
func decodeTarget(p []byte) (string, error) {
	if len(p) < 1 || int(p[0]) != len(p)-1 {
		return "", errors.New("realquic: malformed target encoding")
	}
	return string(p[1:]), nil
}

// encodeUDPRegistration encodes a UDP session registration as
// [sessionID(16)][targetLen(1)][target bytes].
func encodeUDPRegistration(sid [16]byte, addr string) ([]byte, error) {
	t, err := encodeTarget(addr)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16+len(t))
	copy(out[:16], sid[:])
	copy(out[16:], t)
	return out, nil
}

// decodeUDPRegistration decodes an encodeUDPRegistration payload.
func decodeUDPRegistration(p []byte) ([16]byte, string, error) {
	var sid [16]byte
	if len(p) < 17 {
		return sid, "", errors.New("realquic: malformed UDP registration")
	}
	copy(sid[:], p[:16])
	addr, err := decodeTarget(p[16:])
	return sid, addr, err
}

// encodeDatagram builds a QUIC datagram body: [sessionID(16)][payload].
// The session ID is the routing key only; payload encryption is the
// step-5 codec layer, applied to the payload portion, not to the routing
// header (callers seal/open the payload portion around this encoding).
func encodeDatagram(sid [16]byte, payload []byte) []byte {
	out := make([]byte, 16+len(payload))
	copy(out[:16], sid[:])
	copy(out[16:], payload)
	return out
}

// decodeDatagram splits a QUIC datagram body into session ID and payload.
func decodeDatagram(p []byte) ([16]byte, []byte, error) {
	var sid [16]byte
	if len(p) < 16 {
		return sid, nil, errors.New("realquic: datagram shorter than session ID")
	}
	copy(sid[:], p[:16])
	return sid, p[16:], nil
}
