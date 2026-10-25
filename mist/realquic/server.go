package realquic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/curve25519"
)

// ServerConfig configures the lab server. Key is the test K_auth; it must
// be supplied by the caller (tests generate a fresh random key per run).
// AuthHeader/AuthPath are deployment configuration, not protocol constants.
type ServerConfig struct {
	Key        []byte
	AuthHeader string
	AuthPath   string
	Window     time.Duration
	// Site, if nil, is the default static test site.
	Site http.Handler
}

// Server is a Mode A lab server: a real QUIC + HTTP/3 site whose AUTH
// request is one ordinary HTTP/3 request. In this step it additionally
// takes over non-H3 streams (path S, design Q2.2/D9): the AcceptStream
// loop peeks one byte per stream — 0x01 (H3 HEADERS, always the first
// frame of an H3 request stream) goes to HandleRequestStream, any other
// first byte goes to the custom-frame handler. Control/QPACK
// unidirectional streams still go to HandleUnidirectionalStream and
// never enter the peek dispatch.
//
// Custom streams and datagrams are only served after a successful AUTH
// on the same connection (design Q2.2: Mist semantics begin after AUTH).
// Before AUTH, a custom stream is cancelled and datagrams are dropped;
// the connection itself survives, so a later AUTH still works.
type Server struct {
	verify     *verifier
	authHeader string
	authPath   string
	site       http.Handler
	ephPub     [32]byte

	mu       sync.Mutex
	listener *quic.Listener
	conns    map[*quic.Conn]struct{}
	dropped  atomic.Int64 // datagrams dropped (unknown session or pre-AUTH)
}

// defaultSite is the static test site content. It intentionally has no
// /auth route: a visitor (or a failed AUTH) requesting the AUTH path gets
// the site's own 404, exactly as an ordinary request to an unknown path.
func defaultSite() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("realquic lab site\n"))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found\n"))
	})
}

// authSuccess is the AUTH success body. server_eph_pub is the server's
// ephemeral X25519 public key (base64). profile is an explicit placeholder:
// the Q6 profile envelope is P1 work and is deferred, not silently omitted.
type authSuccess struct {
	ServerEphPub string      `json:"server_eph_pub"`
	Profile      interface{} `json:"profile"`
	ProfileNote  string      `json:"profile_note"`
}

// NewServer builds a server; it generates the server ephemeral keypair and
// the in-memory test certificate lazily at Serve time. No files are read.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Key) == 0 {
		return nil, errors.New("realquic: test K_auth key is required")
	}
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	s := &Server{
		verify:     newVerifier(cfg.Key, cfg.Window),
		authHeader: cfg.AuthHeader,
		authPath:   cfg.AuthPath,
		ephPub:     pub,
		conns:      map[*quic.Conn]struct{}{},
	}
	if s.authHeader == "" {
		s.authHeader = DefaultAuthHeader
	}
	if s.authPath == "" {
		s.authPath = DefaultAuthPath
	}
	s.site = cfg.Site
	if s.site == nil {
		s.site = defaultSite()
	}
	return s, nil
}

// handlerFor is the per-connection HTTP/3 handler. On AUTH success it
// marks the connection authenticated, which is what unlocks custom
// streams and datagrams on that connection.
func (s *Server) handlerFor(st *connState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == s.authPath {
			// One code path for every outcome: verify (constant-time
			// HMAC, window, nonce cache) and, on any failure, fall
			// through to the site handler. Nothing here logs the
			// token, and no failure produces a distinctive status,
			// body, or teardown.
			if s.verify.Verify(r.Header.Get(s.authHeader), time.Now()) {
				if st != nil {
					st.setAuthed()
				}
				body, _ := json.Marshal(authSuccess{
					ServerEphPub: base64.StdEncoding.EncodeToString(s.ephPub[:]),
					Profile:      nil,
					ProfileNote:  "P1 Q6 deferred: profile envelope not in this step",
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body)
				return
			}
		}
		s.site.ServeHTTP(w, r)
	})
}

// ServePacketConn serves the server over pc (net.PacketConn abstraction:
// real UDP where available, in-memory pair otherwise). It blocks until
// the server is closed or pc is closed. The certificate is generated in
// memory at this point; ALPN is "h3" only. Datagrams (RFC 9221) are
// enabled on the QUIC connection: they carry Mist UDP relay, not H3
// datagrams, and are handled at the quic.Conn level.
func (s *Server) ServePacketConn(pc net.PacketConn) error {
	cert, err := generateTestCertificate()
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
	ln, err := quic.Listen(pc, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	for {
		qconn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.conns[qconn] = struct{}{}
		s.mu.Unlock()
		go s.serveConn(qconn)
	}
}

// Close stops the listener and all tracked connections. It does not close
// the PacketConn, which remains owned by the caller.
func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.listener
	s.listener = nil
	conns := make([]*quic.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseWithError(0, "server closed")
	}
	if ln == nil {
		return nil
	}
	return ln.Close()
}

// DroppedDatagrams counts datagrams dropped because their session was
// unknown or the connection had not authenticated. Unknown sessions are
// dropped, never routed to any other (e.g. most recent) session: that
// no-fallback invariant (design §3) is what the old tag-based串线 bug
// violated, and it is preserved here by keying on the session ID alone.
func (s *Server) DroppedDatagrams() int64 {
	return s.dropped.Load()
}

// connState is per-QUIC-connection server state: the AUTH gate and the
// registered UDP sessions. Sessions live here, not in a stream handler,
// so a REGISTER stream may close after its acknowledgement while the
// session keeps relaying datagrams.
type connState struct {
	qconn *quic.Conn

	mu       sync.Mutex
	authed   bool
	sessions map[[16]byte]*udpSession
}

func newConnState(qconn *quic.Conn) *connState {
	return &connState{qconn: qconn, sessions: map[[16]byte]*udpSession{}}
}

func (st *connState) setAuthed() {
	st.mu.Lock()
	st.authed = true
	st.mu.Unlock()
}

func (st *connState) isAuthed() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.authed
}

func (st *connState) putSession(s *udpSession) (old *udpSession) {
	st.mu.Lock()
	old, st.sessions[s.sid] = st.sessions[s.sid], s
	st.mu.Unlock()
	return old
}

func (st *connState) getSession(sid [16]byte) *udpSession {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.sessions[sid]
}

// closeSessions closes every registered UDP target connection, which also
// unblocks their response pumps. Idempotent.
func (st *connState) closeSessions() {
	st.mu.Lock()
	sessions := make([]*udpSession, 0, len(st.sessions))
	for _, s := range st.sessions {
		sessions = append(sessions, s)
	}
	st.sessions = map[[16]byte]*udpSession{}
	st.mu.Unlock()
	for _, s := range sessions {
		_ = s.conn.Close()
	}
}

// udpSession is one registered UDP relay: datagrams tagged with sid are
// forwarded to conn, and replies from conn are sent back as datagrams
// tagged with the same sid.
type udpSession struct {
	sid  [16]byte
	conn net.Conn
}

// serveConn runs one accepted QUIC connection: the H3 raw server conn,
// the unidirectional-stream loop, the peek-dispatched bidirectional
// stream loop, and the datagram loop.
func (s *Server) serveConn(qconn *quic.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, qconn)
		s.mu.Unlock()
	}()
	st := newConnState(qconn)
	raw, err := (&http3.Server{Handler: s.handlerFor(st)}).NewRawServerConn(qconn)
	if err != nil {
		return
	}
	ctx := qconn.Context()
	go s.datagramLoop(ctx, st)
	go func() {
		for {
			us, err := qconn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			// Control/QPACK streams are long-lived; each gets its own
			// goroutine and never enters the peek dispatch.
			go raw.HandleUnidirectionalStream(us)
		}
	}()
	for {
		str, err := qconn.AcceptStream(ctx)
		if err != nil {
			// Connection closed: release UDP sessions so their pumps
			// unblock, then exit.
			st.closeSessions()
			return
		}
		go s.dispatchStream(st, raw, str)
	}
}

// dispatchStream is the S-path dispatcher. It peeks exactly one byte
// without consuming it: 0x01 is H3 (HEADERS is always the first frame of
// an H3 request stream) and goes to the H3 stack; anything else is a
// custom stream, whose first byte must be the frame magic 0x4D. A blind
// takeover (every stream to H3) is what the H3 stack closes with
// H3_FRAME_UNEXPECTED, so the peek is not optional.
func (s *Server) dispatchStream(st *connState, raw *http3.RawServerConn, str *quic.Stream) {
	var first [1]byte
	if _, err := str.Peek(first[:]); err != nil {
		return
	}
	if first[0] == 0x01 {
		raw.HandleRequestStream(str)
		return
	}
	s.handleCustomStream(st, str)
}

// errCodeNotAuthed cancels a custom stream opened before AUTH on its
// connection. The connection survives; only the stream is refused.
const errCodeNotAuthed quic.StreamErrorCode = 0x4D01

// handleCustomStream serves one taken-over stream. The first frame decides
// the stream's role; unknown frame types cancel the stream.
func (s *Server) handleCustomStream(st *connState, str *quic.Stream) {
	if !st.isAuthed() {
		str.CancelRead(errCodeNotAuthed)
		str.CancelWrite(errCodeNotAuthed)
		return
	}
	fr, err := ReadFrame(str)
	if err != nil {
		str.CancelRead(errCodeNotAuthed)
		str.CancelWrite(errCodeNotAuthed)
		return
	}
	switch fr.Type {
	case frameConnect:
		s.handleConnect(str, fr)
	case frameRegisterUDP:
		s.handleRegister(st, str, fr)
	default:
		str.CancelRead(errCodeNotAuthed)
		str.CancelWrite(errCodeNotAuthed)
	}
}

// handleConnect dials the requested TCP target and relays framed DATA in
// both directions until either side ends. The stream's lifecycle is the
// dial's lifecycle: stream EOF closes the TCP write side, TCP EOF closes
// the stream write side.
func (s *Server) handleConnect(str *quic.Stream, fr Frame) {
	target, err := decodeTarget(fr.Payload)
	if err != nil {
		_ = WriteFrame(str, frameConnectErr, []byte(err.Error()))
		_ = str.Close()
		return
	}
	tcp, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_ = WriteFrame(str, frameConnectErr, []byte(err.Error()))
		_ = str.Close()
		return
	}
	if err := WriteFrame(str, frameConnectOK, nil); err != nil {
		_ = tcp.Close()
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16*1024)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				if werr := WriteFrame(str, frameData, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	// Stream -> TCP pump on this goroutine.
	for {
		fr, err := ReadFrame(str)
		if err != nil {
			break
		}
		if fr.Type != frameData {
			break
		}
		if _, err := tcp.Write(fr.Payload); err != nil {
			break
		}
	}
	if tc, ok := tcp.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	<-done
	_ = tcp.Close()
	_ = str.Close()
}

// handleRegister registers a UDP session and acknowledges it, then closes
// the stream: the session itself persists in connState and keeps relaying
// datagrams until the connection closes.
func (s *Server) handleRegister(st *connState, str *quic.Stream, fr Frame) {
	sid, target, err := decodeUDPRegistration(fr.Payload)
	if err != nil {
		_ = WriteFrame(str, frameRegisterErr, []byte(err.Error()))
		_ = str.Close()
		return
	}
	udp, err := net.DialTimeout("udp", target, 5*time.Second)
	if err != nil {
		_ = WriteFrame(str, frameRegisterErr, []byte(err.Error()))
		_ = str.Close()
		return
	}
	sess := &udpSession{sid: sid, conn: udp}
	if old := st.putSession(sess); old != nil {
		_ = old.conn.Close()
	}
	go s.udpPump(st, sess)
	if err := WriteFrame(str, frameRegisterOK, nil); err != nil {
		_ = udp.Close()
		return
	}
	_ = str.Close()
}

// udpPump forwards replies from a UDP target back to the client as
// datagrams tagged with the session ID. It exits when the target closes
// (connection teardown closes all session conns) or a send fails.
func (s *Server) udpPump(st *connState, sess *udpSession) {
	buf := make([]byte, 4096)
	for {
		n, err := sess.conn.Read(buf)
		if n > 0 {
			if serr := st.qconn.SendDatagram(encodeDatagram(sess.sid, buf[:n])); serr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// datagramLoop routes inbound datagrams by session ID only. Unknown
// sessions and pre-AUTH datagrams are dropped and counted; there is no
// fallback to any other session.
func (s *Server) datagramLoop(ctx context.Context, st *connState) {
	for {
		data, err := st.qconn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		sid, payload, err := decodeDatagram(data)
		if err != nil || !st.isAuthed() {
			s.dropped.Add(1)
			continue
		}
		sess := st.getSession(sid)
		if sess == nil {
			s.dropped.Add(1)
			continue
		}
		if _, err := sess.conn.Write(payload); err != nil {
			s.dropped.Add(1)
		}
	}
}
