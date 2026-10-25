package mistcore

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Control / CONNECT / datagram message builders (SPEC 9)
// ---------------------------------------------------------------------------

// EncodeConnectReq builds a CONNECT request payload (SYN).
func EncodeConnectReq(atyp byte, addr []byte, port uint16) []byte {
	out := make([]byte, 0, 1+1+len(addr)+2)
	out = append(out, atyp)
	if atyp == ATypDomain {
		out = append(out, byte(len(addr)))
	}
	out = append(out, addr...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	out = append(out, pb[:]...)
	return out
}

// DecodeConnectReq parses a CONNECT request payload.
func DecodeConnectReq(p []byte) (atyp byte, addr []byte, port uint16, err error) {
	if len(p) < 1+2 {
		return 0, nil, 0, errors.New("mist: short connect req")
	}
	atyp = p[0]
	rest := p[1:]
	switch atyp {
	case ATypIPv4:
		if len(rest) < 4+2 {
			return 0, nil, 0, errors.New("mist: short ipv4")
		}
		addr = rest[:4]
		port = binary.BigEndian.Uint16(rest[4:6])
	case ATypIPv6:
		if len(rest) < 16+2 {
			return 0, nil, 0, errors.New("mist: short ipv6")
		}
		addr = rest[:16]
		port = binary.BigEndian.Uint16(rest[16:18])
	case ATypDomain:
		if len(rest) < 1 {
			return 0, nil, 0, errors.New("mist: short domain")
		}
		dl := int(rest[0])
		if len(rest) < 1+dl+2 {
			return 0, nil, 0, errors.New("mist: short domain2")
		}
		addr = rest[1 : 1+dl]
		port = binary.BigEndian.Uint16(rest[1+dl : 1+dl+2])
	default:
		return 0, nil, 0, errors.New("mist: bad atyp")
	}
	return atyp, addr, port, nil
}

// EncodeDatagram builds a UDP relay datagram payload (SPEC 9.4).
func EncodeDatagram(atyp byte, addr []byte, port uint16, data []byte) []byte {
	hdr := EncodeConnectReq(atyp, addr, port)
	out := make([]byte, 0, len(hdr)+2+len(data))
	out = append(out, hdr...)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(data)))
	out = append(out, lb[:]...)
	out = append(out, data...)
	return out
}

// DecodeDatagram parses a UDP relay datagram payload.
func DecodeDatagram(p []byte) (atyp byte, addr []byte, port uint16, data []byte, err error) {
	atyp, addr, port, err = DecodeConnectReq(p)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	hdrLen := 1 + len(addr) + 2
	if atyp == ATypDomain {
		hdrLen++
	}
	if len(p) < hdrLen+2 {
		return 0, nil, 0, nil, errors.New("mist: short dgram")
	}
	dl := int(binary.BigEndian.Uint16(p[hdrLen : hdrLen+2]))
	if len(p) < hdrLen+2+dl {
		return 0, nil, 0, nil, errors.New("mist: short dgram data")
	}
	return atyp, addr, port, p[hdrLen+2 : hdrLen+2+dl], nil
}

// BuildResumeMsg builds a RESUME control payload (SPEC 10.2).
func BuildResumeMsg(connID [16]byte, tok [32]byte, newEpoch uint32) []byte {
	out := make([]byte, 0, 57)
	out = append(out, MsgResume)
	out = append(out, connID[:]...)
	out = append(out, tok[:]...)
	var eb [4]byte
	binary.BigEndian.PutUint32(eb[:], newEpoch)
	out = append(out, eb[:]...)
	out = append(out, 0, 0, 0, 0)
	return out
}

// ParseResumeMsg parses a RESUME control payload.
func ParseResumeMsg(p []byte) (connID [16]byte, tok [32]byte, newEpoch uint32, ok bool) {
	if len(p) != 57 || p[0] != MsgResume {
		return connID, tok, 0, false
	}
	copy(connID[:], p[1:17])
	copy(tok[:], p[17:49])
	return connID, tok, binary.BigEndian.Uint32(p[49:53]), true
}

// BuildResumeOKMsg builds a RESUME_OK control payload.
func BuildResumeOKMsg(newEpoch uint32) []byte {
	out := make([]byte, 5)
	out[0] = MsgResumeOK
	binary.BigEndian.PutUint32(out[1:5], newEpoch)
	return out
}

// maxPlainPerFrame keeps LEN within limits even with max padding.
const maxPlainPerFrame = 14000

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

// Stream is one multiplexed byte stream (SPEC 9).
type Stream struct {
	sid     byte
	sess    *Session
	udpMode bool

	readCh  chan []byte
	readBuf []byte
	readErr error
	readMu  sync.Mutex

	sendWindow int64 // atomic; init DefaultInitWindow
	recvCount  int64 // bytes received since last WINDOW_UPDATE

	writeMu   sync.Mutex
	writeDone bool

	closeOnce sync.Once
	closed    chan struct{}
}

// Read implements io.Reader. Returns io.EOF after FIN and buffered data.
func (s *Stream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.readBuf) == 0 {
		if s.readErr != nil {
			return 0, s.readErr
		}
		s.readMu.Unlock()
		select {
		case b, ok := <-s.readCh:
			if !ok {
				s.readMu.Lock()
				if s.readErr == nil {
					s.readErr = io.EOF
				}
				err := s.readErr
				s.readMu.Unlock()
				s.readMu.Lock()
				return 0, err
			}
			s.readMu.Lock()
			s.readBuf = b
		case <-s.closed:
			s.readMu.Lock()
			if s.readErr == nil {
				s.readErr = io.EOF
			}
			return 0, s.readErr
		}
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

// Write implements io.Writer with per-stream flow control.
func (s *Stream) Write(p []byte) (int, error) {
	// v0.2: No application-layer flow control. Relies on TCP.
	if s.isClosed() {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxPlainPerFrame {
			n = maxPlainPerFrame
		}
		if err := s.sess.writeFrame(s.sid, 0, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// ReadDatagram returns the next whole frame payload (for UDP-relay bearer
// streams, where each frame carries exactly one datagram). Do not mix with
// Read on the same stream.
func (s *Stream) ReadDatagram() ([]byte, error) {
	s.readMu.Lock()
	if s.readErr != nil && len(s.readBuf) == 0 {
		err := s.readErr
		s.readMu.Unlock()
		return nil, err
	}
	s.readMu.Unlock()
	select {
	case b, ok := <-s.readCh:
		if !ok {
			return nil, io.EOF
		}
		return b, nil
	case <-s.closed:
		return nil, io.EOF
	}
}

// SID returns the stream id.
func (s *Stream) SID() byte { return s.sid }

// CloseWrite sends FIN (half-close).
func (s *Stream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeDone {
		return nil
	}
	s.writeDone = true
	return s.sess.writeFrame(s.sid, FlagFIN, nil)
}

// Close sends RST and releases the stream.
// Lock order: stream closeOnce -> session sendMu -> session streamsMu.
// closeOnce bodies never block on streamsMu (see removeStream).
func (s *Stream) Close() error {
	first := false
	s.closeOnce.Do(func() {
		first = true
		close(s.closed)
	})
	if first {
		_ = s.sess.writeFrame(s.sid, FlagRST, nil)
		s.sess.removeStream(s.sid)
	}
	return nil
}

func (s *Stream) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// deliver appends a decrypted payload to the read queue.
func (s *Stream) deliver(b []byte, fin bool) {
	if fin {
		s.readMu.Lock()
		if s.readErr == nil {
			s.readErr = io.EOF
		}
		s.readMu.Unlock()
	}
	if len(b) == 0 {
		return
	}
	select {
	case s.readCh <- b:
		// Flow control: WINDOW_UPDATE every DefaultWindowUpdateEvery bytes.
		if c := atomic.AddInt64(&s.recvCount, int64(len(b))); c >= DefaultWindowUpdateEvery {
			atomic.AddInt64(&s.recvCount, -DefaultWindowUpdateEvery)
			_ = s.sess.sendWindowUpdate(s.sid, DefaultWindowUpdateEvery)
		}
	case <-s.closed:
	}
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

// SessionParams configures a new Session.
type SessionParams struct {
	Conn       net.Conn
	IsClient   bool
	KC2S       [32]byte // client->server key (decrypt on server, encrypt on client)
	KS2C       [32]byte // server->client key
	Epoch      uint32
	Shaper     *Shaper // shaping for the sending direction; nil = none
	MaxStreams byte
	// OnAccept is called (server side) for each new inbound SYN stream.
	OnAccept func(*Stream)
	// OnControl is called for control messages not handled internally
	// (e.g. UDP_ASSOC_REQ, RESUME on a live session).
	OnControl func(typ byte, body []byte)
}

// Session is one Mist-over-TLS connection with multiplexed streams.
type Session struct {
	conn     net.Conn
	isClient bool
	encKey   [32]byte // key for frames we SEND
	decKey   [32]byte // key for frames we RECEIVE
	encDir   uint32
	decDir   uint32
	epoch    uint32

	sendCtr uint32
	recvCtr uint32
	sendMu  sync.Mutex

	shaper *Shaper

	streamsMu  sync.Mutex
	streams    map[byte]*Stream
	nextSid    byte
	maxStreams byte
	onAccept   func(*Stream)

	pingMu   sync.Mutex
	pending  map[[8]byte]time.Time
	pongCh   chan [8]byte
	onControl func(typ byte, body []byte)

	closed   chan struct{}
	closeOnce sync.Once
	wg       sync.WaitGroup
}

// NewSession creates a session over an established (TLS) conn.
// Keys are direction-named per SPEC 6.4 (kC2S, kS2C); enc/dec are picked
// by side automatically.
func NewSession(p SessionParams) *Session {
	s := &Session{
		conn:       p.Conn,
		isClient:   p.IsClient,
		epoch:      p.Epoch,
		shaper:     p.Shaper,
		streams:    make(map[byte]*Stream),
		nextSid:    1,
		maxStreams: p.MaxStreams,
		onAccept:   p.OnAccept,
		onControl:  p.OnControl,
		pending:    make(map[[8]byte]time.Time),
		pongCh:     make(chan [8]byte, 16),
		closed:     make(chan struct{}),
	}
	if s.maxStreams == 0 {
		s.maxStreams = DefaultMaxStreams
	}
	if p.IsClient {
		s.encKey, s.decKey = p.KC2S, p.KS2C
		s.encDir, s.decDir = DirC2S, DirS2C
	} else {
		s.encKey, s.decKey = p.KS2C, p.KC2S
		s.encDir, s.decDir = DirS2C, DirC2S
	}
	s.wg.Add(1)
	go s.readLoop()
	return s
}

// writeFrame encrypts and sends one frame (shaping applied).
// The shaper Delay() sleep happens BEFORE acquiring sendMu, so concurrent
// streams don't block each other during the (up to 15ms) shaping delay.
// sendMu still serializes counter increment + encrypt + TCP write to keep
// nonces unique and frames in counter order on the wire.
func (s *Session) writeFrame(sidFlags byte, flags byte, plaintext []byte) error {
	select {
	case <-s.closed:
		return io.ErrClosedPipe
	default:
	}

	// Shaping delay outside the send lock: it's just a sleep, no shared
	// state that needs sendMu. This lets multiple streams delay in parallel
	// instead of serializing on the global lock.
	if s.shaper != nil {
		s.shaper.Delay()
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	var pad int
	if s.shaper != nil {
		pad = s.shaper.PadLen()
	}
	enc, err := EncodeFrame(sidFlags|flags, plaintext, pad, &s.encKey, s.epoch, s.encDir, s.sendCtr)
	if err != nil {
		return err
	}
	s.sendCtr++
	chunks := [][]byte{enc}
	if s.shaper != nil {
		chunks = s.shaper.Fragment(enc)
	}
	for _, c := range chunks {
		if _, err := s.conn.Write(c); err != nil {
			return err
		}
	}
	if s.shaper != nil {
		s.shaper.Done()
	}
	return nil
}

// writeControl sends a control-stream message.
func (s *Session) writeControl(payload []byte) error {
	return s.writeFrame(SidControl, 0, payload)
}

func (s *Session) sendWindowUpdate(sid byte, inc int64) error {
	var b [6]byte
	b[0] = MsgWindowUpdate
	b[1] = sid
	binary.BigEndian.PutUint32(b[2:6], uint32(inc))
	return s.writeControl(b[:])
}

// OpenStream opens a new client-initiated stream (CONNECT).
func (s *Session) OpenStream(connectPayload []byte) (*Stream, error) {
	s.streamsMu.Lock()
	if len(s.streams) >= int(s.maxStreams) {
		s.streamsMu.Unlock()
		return nil, errors.New("mist: too many streams")
	}
	sid := s.nextSid
	s.nextSid++
	if s.nextSid > SidMax {
		s.nextSid = 1
	}
	// Avoid collision with live streams.
	for i := 0; i < SidMax; i++ {
		if _, ok := s.streams[sid]; !ok {
			break
		}
		sid++
		if sid > SidMax {
			sid = 1
		}
	}
	if _, ok := s.streams[sid]; ok {
		s.streamsMu.Unlock()
		return nil, errors.New("mist: no free stream id")
	}
	st := s.newStreamLocked(sid)
	s.streamsMu.Unlock()

	if err := s.writeFrame(sid, FlagSYN, connectPayload); err != nil {
		s.removeStream(sid)
		return nil, err
	}
	return st, nil
}

func (s *Session) newStreamLocked(sid byte) *Stream {
	st := &Stream{
		sid:        sid,
		sess:       s,
		readCh:     make(chan []byte, 32),
		sendWindow: DefaultInitWindow,
		closed:     make(chan struct{}),
	}
	s.streams[sid] = st
	return st
}

func (s *Session) removeStream(sid byte) {
	s.streamsMu.Lock()
	st, ok := s.streams[sid]
	if ok {
		delete(s.streams, sid)
	}
	s.streamsMu.Unlock()
	if ok {
		st.closeOnce.Do(func() { close(st.closed) })
	}
}

func (s *Session) getStream(sid byte) (*Stream, bool) {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	st, ok := s.streams[sid]
	return st, ok
}

// readFrame reads one full frame and decrypts it.
func (s *Session) readFrame() (*DecodedFrame, error) {
	var lbuf [2]byte
	if _, err := io.ReadFull(s.conn, lbuf[:]); err != nil {
		return nil, err
	}
	ln := int(binary.BigEndian.Uint16(lbuf[:]))
	if ln < 2 || ln > MaxFrameLen {
		return nil, ErrFrameTooBig
	}
	buf := make([]byte, 2+ln)
	copy(buf, lbuf[:])
	if _, err := io.ReadFull(s.conn, buf[2:]); err != nil {
		return nil, err
	}
	s.sendMu.Lock()
	ctr := s.recvCtr
	s.recvCtr++
	s.sendMu.Unlock()
	return DecodeFrame(buf, &s.decKey, s.epoch, s.decDir, ctr)
}

func (s *Session) readLoop() {
	defer s.wg.Done()
	defer s.Close()
	for {
		select {
		case <-s.closed:
			return
		default:
		}
		f, err := s.readFrame()
		if err != nil {
			return // silent close (iron rule)
		}
		s.dispatch(f)
	}
}

func (s *Session) dispatch(f *DecodedFrame) {
	sid := f.SidFlags & 0x0F
	flags := f.SidFlags & 0xF0
	if sid == SidControl {
		s.handleControl(f.Payload)
		return
	}
	if flags&FlagSYN != 0 {
		s.streamsMu.Lock()
		st, exists := s.streams[sid]
		if !exists {
			st = s.newStreamLocked(sid)
		}
		s.streamsMu.Unlock()
		if !exists && s.onAccept != nil {
			// Deliver SYN payload via readCh so the acceptor can parse it.
			st.deliver(f.Payload, false)
			s.onAccept(st)
		} else {
			st.deliver(f.Payload, flags&FlagFIN != 0)
		}
		return
	}
	st, ok := s.getStream(sid)
	if !ok {
		return
	}
	if flags&FlagRST != 0 {
		s.removeStream(sid)
		return
	}
	st.deliver(f.Payload, flags&FlagFIN != 0)
}

func (s *Session) handleControl(p []byte) {
	if len(p) == 0 {
		return
	}
	switch p[0] {
	case MsgPing:
		if len(p) == 9 {
			var cookie [8]byte
			copy(cookie[:], p[1:9])
			resp := append([]byte{MsgPong}, cookie[:]...)
			_ = s.writeControl(resp)
		}
	case MsgPong:
		if len(p) == 9 {
			var cookie [8]byte
			copy(cookie[:], p[1:9])
			s.pingMu.Lock()
			delete(s.pending, cookie)
			s.pingMu.Unlock()
			select {
			case s.pongCh <- cookie:
			default:
			}
		}
	case MsgWindowUpdate:
		if len(p) == 6 {
			sid := p[1]
			inc := int64(binary.BigEndian.Uint32(p[2:6]))
			if st, ok := s.getStream(sid); ok {
				atomic.AddInt64(&st.sendWindow, inc)
			}
		}
	case MsgCloseSession:
		s.Close()
	default:
		if s.onControl != nil {
			s.onControl(p[0], p[1:])
		}
	}
}

// SendControl sends a raw control-stream payload.
func (s *Session) SendControl(payload []byte) error {
	return s.writeControl(payload)
}

// SendCtr returns the next send counter (for RESUME after rebind).
func (s *Session) SendCtr() uint32 {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sendCtr
}

// ResumeState captures what a client needs to resume a session (SPEC 10).
type ResumeState struct {
	ConnID  [16]byte
	Tok     [32]byte
	KC2S    [32]byte
	KS2C    [32]byte
	Epoch   uint32
	NextCtr uint32
}

// ClientResume performs the client side of SPEC 10.2/10.3 over conn.
// On failure it returns an error and the caller should fall back to full AUTH.
func ClientResume(conn net.Conn, rs *ResumeState, shaper *Shaper, maxStreams byte,
	onAccept func(*Stream)) (*Session, error) {
	newEpoch := rs.Epoch + 1
	msg := BuildResumeMsg(rs.ConnID, rs.Tok, newEpoch)
	frame, err := EncodeFrame(SidControl, msg, 0, &rs.KC2S, rs.Epoch, DirC2S, rs.NextCtr)
	if err != nil {
		return nil, err
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	// Expect RESUME_OK with the NEW keys/epoch, ctr=0.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var lbuf [2]byte
	if _, err := io.ReadFull(conn, lbuf[:]); err != nil {
		return nil, err
	}
	fl := 2 + int(binary.BigEndian.Uint16(lbuf[:]))
	if fl < 6 || fl > MaxLineLen {
		return nil, errors.New("mist: bad resume_ok frame")
	}
	buf := make([]byte, fl)
	copy(buf, lbuf[:])
	if _, err := io.ReadFull(conn, buf[2:]); err != nil {
		return nil, err
	}
	df, err := DecodeFrame(buf, &rs.KS2C, newEpoch, DirS2C, 0)
	if err != nil {
		return nil, err
	}
	if len(df.Payload) != 5 || df.Payload[0] != MsgResumeOK ||
		binary.BigEndian.Uint32(df.Payload[1:5]) != newEpoch {
		return nil, errors.New("mist: bad resume_ok")
	}
	conn.SetDeadline(time.Time{})
	return NewSession(SessionParams{
		Conn: conn, IsClient: true, KC2S: rs.KC2S, KS2C: rs.KS2C,
		Epoch: newEpoch, Shaper: shaper, MaxStreams: maxStreams,
		OnAccept: onAccept,
	}), nil
}

// Ping sends a heartbeat PING and waits for the PONG.
func (s *Session) Ping(timeout time.Duration) error {
	var cookie [8]byte
	copy(cookie[:], RandomBytes(8))
	s.pingMu.Lock()
	s.pending[cookie] = time.Now()
	s.pingMu.Unlock()
	msg := append([]byte{MsgPing}, cookie[:]...)
	if err := s.writeControl(msg); err != nil {
		return err
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		select {
		case c := <-s.pongCh:
			if c == cookie {
				return nil
			}
		case <-t.C:
			return errors.New("mist: ping timeout")
		case <-s.closed:
			return io.ErrClosedPipe
		}
	}
}

// StartHeartbeat runs PING every interval; onDead fires after 2 missed cycles.
func (s *Session) StartHeartbeat(interval time.Duration, onDead func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		missed := 0
		for {
			select {
			case <-s.closed:
				return
			case <-t.C:
				if err := s.Ping(2 * interval); err != nil {
					missed++
					if missed >= 2 {
						if onDead != nil {
							onDead()
						}
						return
					}
				} else {
					missed = 0
				}
			}
		}
	}()
}

// Close shuts the session down.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.conn.Close()
	})
	s.streamsMu.Lock()
	sts := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		sts = append(sts, st)
	}
	s.streams = make(map[byte]*Stream)
	s.streamsMu.Unlock()
	for _, st := range sts {
		st.closeOnce.Do(func() { close(st.closed) })
	}
	return nil
}

// Wait blocks until the read loop exits.
func (s *Session) Wait() { s.wg.Wait() }

// IsClosed reports session state.
func (s *Session) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}
