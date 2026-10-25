package realquic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/curve25519"
)

// Step-5 TCP leg (REALQUIC-DESIGN.md Q8, SPEC v0.2 minimal form).
//
// There was no reusable SPEC v0.2 honest-TLS leg in the repository: the
// old mistcore package is the retired custom UDP stack and core/ is
// framework interfaces only. So this leg is implemented here, in the
// smallest form that shares the QUIC leg's semantics:
//
//   - TCP (lab: loopback; production: 443) + TLS 1.3, server side
//     MinVersion TLS 1.3, client side uTLS HelloChrome_Auto (SPEC §4
//     Chrome ClientHello mimicry) with the same lab test name.
//   - The same K_auth model: AUTH token (header form reused as a frame
//     payload), same verifier — when built via Server.TCPServer() the
//     nonce cache itself is shared, so a token cannot be replayed
//     across legs. A standalone NewTCPServer gets its own verifier.
//   - The same proxy semantics: CONNECT + framed DATA, sealed under the
//     same session keys (same derivation, same PayloadCodec).
//   - The same resume idea (SPEC §10.2): AUTH_OK carries a session id
//     and resume token; a later TCP connection can send RESUME sealed
//     under the old c2s key instead of a fresh full AUTH.
//   - Visitor fallback, never open forwarding: a failed AUTH, a replayed
//     token, or a non-frame first byte (e.g. a plain HTTP request from
//     a browser) all get the same static site response the QUIC leg's
//     site handler serves, and the connection is then closed. No target
//     is ever dialled for an unauthenticated peer.
//
// Lab limits, stated not hidden:
//   - The server certificate is the same in-memory self-signed lab
//     certificate as the QUIC leg (generateTestCertificate); production
//     must use a real CA certificate for a real domain. The client
//     therefore skips verification in the lab, exactly as DialPacketConn
//     does. Nothing here is production TLS policy.
//   - The visitor response is a single static HTTP/1.1 response built
//     from the configured site handler (GET /); a production deployment
//     would serve the site as a real HTTP server on the same TLS
//     listener. The lab property that matters — failure and visitor
//     are byte-identical — is preserved.
//   - One TCP connection carries one CONNECT relay (no multiplexing
//     over the TCP leg in this step); the frame format is shared, so
//     multiplexing can be layered later without changing AUTH/resume.

// TCP-leg frame types. They reuse the [MAGIC][TYPE][LEN][PAYLOAD]
// outer format; none is 0x01, by the same convention as frame.go.
const (
	frameAuth     byte = 0x20 // client -> server: AUTH token (string)
	frameAuthOK   byte = 0x21 // server -> client: authSuccess JSON
	frameResume   byte = 0x22 // client -> server: [sessionID(16)][sealed resume token]
	frameResumeOK byte = 0x23 // server -> client: sealed empty payload
)

// TCPServerConfig configures a standalone TCP-leg server.
type TCPServerConfig struct {
	Key    []byte
	Window time.Duration
	// Site, if nil, is the default static test site.
	Site http.Handler
}

// TCPServer is the TCP leg. Fields are shared pointers when built via
// Server.TCPServer(); a standalone server owns fresh copies.
type TCPServer struct {
	verify   *verifier
	site     http.Handler
	ephPub   [32]byte
	ephPriv  [32]byte
	sessions *sessionTable
	// profile returns the currently issued profile for AUTH_OK. When
	// built via Server.TCPServer() it is the QUIC server's
	// IssuedProfile, so both legs issue the same profile; a standalone
	// server issues from bootstrap. Nil means bootstrap.
	profile func() Profile

	mu sync.Mutex
	ln net.Listener
}

// NewTCPServer builds a standalone TCP-leg server (own verifier,
// ephemeral pair and session table).
func NewTCPServer(cfg TCPServerConfig) (*TCPServer, error) {
	if len(cfg.Key) == 0 {
		return nil, errors.New("realquic: test K_auth key is required")
	}
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	s := &TCPServer{
		verify:   newVerifier(cfg.Key, cfg.Window),
		ephPub:   pub,
		ephPriv:  priv,
		sessions: newSessionTable(),
		profile:  func() Profile { return newIssuedFrom(BootstrapProfile()) },
	}
	s.site = cfg.Site
	if s.site == nil {
		s.site = defaultSite()
	}
	return s, nil
}

// Serve accepts TLS connections on ln until ln is closed. The TLS config
// is TLS 1.3 only with the in-memory lab certificate.
func (s *TCPServer) Serve(ln net.Listener) error {
	cert, err := generateTestCertificate()
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(tls.Server(raw, tlsConf))
	}
}

// Close stops accepting. It does not close ln (caller-owned).
func (s *TCPServer) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Close()
}

// visitorResponse renders the site handler for GET / as one static
// HTTP/1.1 response. Failed AUTH and plain-visitor first bytes both
// take this path, so their bytes are identical by construction.
func (s *TCPServer) visitorResponse() []byte {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.site.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	status := rec.Code
	if status == 0 {
		status = http.StatusOK
	}
	text := http.StatusText(status)
	if text == "" {
		text = "OK"
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\n", status, text)
	ct := rec.Header().Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}
	fmt.Fprintf(&buf, "Content-Type: %s\r\n", ct)
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	buf.WriteString("Connection: close\r\n\r\n")
	buf.Write(body)
	return buf.Bytes()
}

// bufferedConn keeps the peeked bytes: the AUTH/RESUME frame was read
// through br, so all later reads must go through the same br.
type bufferedConn struct {
	br *bufio.Reader
	c  net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error)  { return b.br.Read(p) }
func (b *bufferedConn) Write(p []byte) (int, error) { return b.c.Write(p) }
func (b *bufferedConn) Close() error                { return b.c.Close() }

// handleConn serves one TLS connection: peek, AUTH or RESUME or visitor,
// then at most one CONNECT relay.
func (s *TCPServer) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] != frameMagic {
		// Plain visitor (e.g. an HTTP request): site response, no proxy.
		_, _ = conn.Write(s.visitorResponse())
		return
	}
	bc := &bufferedConn{br: br, c: conn}
	fr, err := ReadFrame(bc)
	if err != nil {
		_, _ = conn.Write(s.visitorResponse())
		return
	}
	var codec PayloadCodec
	switch fr.Type {
	case frameAuth:
		codec = s.handleTCPAuth(bc, fr)
	case frameResume:
		codec = s.handleTCPResume(bc, fr)
	default:
		_, _ = conn.Write(s.visitorResponse())
		return
	}
	if codec == nil {
		// handleTCPAuth/handleTCPResume already sent the visitor
		// response on failure.
		return
	}
	// Authenticated: expect one CONNECT frame, then relay DATA.
	fr, err = ReadFrameCodec(bc, codec)
	if err != nil || fr.Type != frameConnect {
		return
	}
	s.relayTCP(bc, fr, codec)
}

// handleTCPAuth verifies the token frame. On success it derives the
// session keys, records the session, and replies AUTH_OK; on any failure
// it sends the visitor response and returns nil.
func (s *TCPServer) handleTCPAuth(bc *bufferedConn, fr Frame) PayloadCodec {
	clientPub, ok := s.verify.VerifyToken(string(fr.Payload), time.Now())
	if !ok {
		_, _ = bc.Write(s.visitorResponse())
		return nil
	}
	shared, err := deriveShared(s.ephPriv, clientPub)
	if err != nil {
		_, _ = bc.Write(s.visitorResponse())
		return nil
	}
	c2s, s2c, err := deriveDirectionKeys(shared, clientPub, s.ephPub)
	if err != nil {
		_, _ = bc.Write(s.visitorResponse())
		return nil
	}
	rec, err := s.sessions.newRecord(c2s, s2c)
	if err != nil {
		_, _ = bc.Write(s.visitorResponse())
		return nil
	}
	// Q6, same envelope as the QUIC leg (see server.go). The TCP leg
	// issues at AUTH; in-session pushes are a QUIC-leg control-stream
	// mechanism in this step (the TCP leg carries one CONNECT per
	// connection and has no server-initiated control stream yet).
	issuedProfile := newIssuedFrom(BootstrapProfile())
	if s.profile != nil {
		issuedProfile = s.profile()
	}
	resp := authSuccess{
		ServerEphPub: base64.StdEncoding.EncodeToString(s.ephPub[:]),
		Profile:      &issuedProfile,
		ProfileNote:  "Q6 profile envelope issued (P1 step A); all values provisional, D2 final values pending P2 baseline measurement",
		SessionID:    base64.StdEncoding.EncodeToString(rec.id[:]),
		ResumeToken:  base64.StdEncoding.EncodeToString(rec.resumeToken[:]),
	}
	body, _ := json.Marshal(resp)
	// AUTH_OK itself is not yet sealed: the client has no session keys
	// until it reads this body (same as the QUIC leg, where AUTH_OK is
	// an H3 response inside QUIC encryption). Everything after it is
	// sealed under the session keys.
	if err := WriteFrame(bc, frameAuthOK, body); err != nil {
		return nil
	}
	return rec.serverCodec()
}

// handleTCPResume verifies a sealed resume token against the stored
// session. On success it replies a sealed empty RESUME_OK and returns
// the session codec; on any failure it sends the visitor response.
func (s *TCPServer) handleTCPResume(bc *bufferedConn, fr Frame) PayloadCodec {
	if len(fr.Payload) < 16 {
		_, _ = bc.Write(s.visitorResponse())
		return nil
	}
	var id [16]byte
	copy(id[:], fr.Payload[:16])
	sealed := fr.Payload[16:]
	// The record must be found before the token can be opened: the
	// opening key is per-session. An unknown id fails exactly like a
	// wrong token (visitor response), so no oracle is offered.
	s.sessions.mu.Lock()
	rec := s.sessions.byID[id]
	s.sessions.mu.Unlock()
	if rec == nil {
		_, _ = bc.Write(s.visitorResponse())
		return nil
	}
	codec := rec.serverCodec()
	opened, err := codec.Open(sealed)
	if err != nil || len(opened) != 32 {
		_, _ = bc.Write(s.visitorResponse())
		return nil
	}
	var token [32]byte
	copy(token[:], opened)
	if _, ok := s.sessions.resume(id, token); !ok {
		_, _ = bc.Write(s.visitorResponse())
		return nil
	}
	sealedOK, err := codec.Seal(nil)
	if err != nil {
		return nil
	}
	if err := WriteFrame(bc, frameResumeOK, sealedOK); err != nil {
		return nil
	}
	return codec
}

// relayTCP dials the CONNECT target and relays framed DATA both ways
// over bc, mirroring the QUIC leg's handleConnect (same frame format,
// same codec, same lifecycle: stream EOF closes the target write side).
func (s *TCPServer) relayTCP(bc *bufferedConn, fr Frame, codec PayloadCodec) {
	target, err := decodeTarget(fr.Payload)
	if err != nil {
		_ = WriteFrameCodec(bc, frameConnectErr, []byte(err.Error()), codec)
		return
	}
	tcp, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_ = WriteFrameCodec(bc, frameConnectErr, []byte(err.Error()), codec)
		return
	}
	defer tcp.Close()
	if err := WriteFrameCodec(bc, frameConnectOK, nil, codec); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16*1024)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				if werr := WriteFrameCodec(bc, frameData, buf[:n], codec); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		fr, err := ReadFrameCodec(bc, codec)
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
}

// --- TCP client ---

// TCPClient is one TCP-leg connection: uTLS Chrome-mimicry TLS 1.3,
// then AUTH or RESUME, then at most one CONNECT relay.
type TCPClient struct {
	key  []byte
	conn net.Conn
	br   *bufio.Reader

	mu      sync.Mutex
	codec   PayloadCodec
	session *sessionParams
	// P1 step A (Q6): same per-server profile state as the QUIC
	// client (see client.go). The TCP leg adopts at AUTH; it has no
	// in-session push loop in this step.
	profileStore  *ProfileStore
	serverID      string
	activeProfile Profile
}

// ActiveProfile returns the profile this TCP connection currently applies.
func (c *TCPClient) ActiveProfile() Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeProfile
}

// DialTCP dials addr and performs a uTLS Chrome-mimicry TLS 1.3
// handshake (SPEC §4: HelloChrome_Auto). Verification is skipped: this
// is lab code talking to an in-memory test certificate for
// "realquic.test", exactly as the QUIC leg does. It must never be used
// against a production endpoint, where a real CA certificate is required.
func DialTCP(ctx context.Context, addr string, key []byte) (*TCPClient, error) {
	return DialTCPWithProfileStore(ctx, addr, key, NewProfileStore(), testServerName)
}

// DialTCPWithProfileStore is DialTCP with an explicit profile store and
// server identity (same semantics as DialPacketConnWithProfileStore).
func DialTCPWithProfileStore(ctx context.Context, addr string, key []byte, store *ProfileStore, serverID string) (*TCPClient, error) {
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(raw, &utls.Config{
		ServerName:         testServerName,
		InsecureSkipVerify: true, // lab only: in-memory test certificate
		MinVersion:         utls.VersionTLS13,
	}, utls.HelloChrome_Auto)
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if store == nil {
		store = NewProfileStore()
	}
	if serverID == "" {
		serverID = testServerName
	}
	return &TCPClient{key: key, conn: uconn, br: bufio.NewReader(uconn), profileStore: store, serverID: serverID, activeProfile: store.ActiveFor(serverID)}, nil
}

// Close closes the TCP-leg connection.
func (c *TCPClient) Close() error {
	return c.conn.Close()
}

func (c *TCPClient) codecOrIdentity() PayloadCodec {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codec != nil {
		return c.codec
	}
	return IdentityCodec{}
}

func (c *TCPClient) setSession(p *sessionParams) {
	c.mu.Lock()
	c.session = p
	c.codec = p.clientCodec()
	c.mu.Unlock()
}

// Auth performs a full AUTH over the TCP leg and installs the session
// keys, mirroring Client.Auth. A visitor HTTP response (not a frame)
// from the server is an authentication failure, not a transport error:
// it is returned as an error with the response bytes attached in the
// message for test diagnosis.
func (c *TCPClient) Auth(ctx context.Context) error {
	token, priv, pub, err := freshTokenForKey(c.key)
	if err != nil {
		return err
	}
	if err := WriteFrame(c, frameAuth, []byte(token)); err != nil {
		return err
	}
	fr, err := ReadFrame(c)
	if err != nil {
		return err
	}
	if fr.Type != frameAuthOK {
		return errors.New("realquic: TCP AUTH refused (no AUTH_OK frame)")
	}
	var ok authSuccess
	if err := json.Unmarshal(fr.Payload, &ok); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(ok.ServerEphPub)
	if err != nil || len(decoded) != 32 {
		return errors.New("realquic: TCP AUTH_OK has no valid server_eph_pub")
	}
	var serverPub [32]byte
	copy(serverPub[:], decoded)
	shared, err := deriveShared(priv, serverPub)
	if err != nil {
		return err
	}
	c2s, s2c, err := deriveDirectionKeys(shared, pub, serverPub)
	if err != nil {
		return err
	}
	params := &sessionParams{c2s: c2s, s2c: s2c}
	if ok.SessionID != "" && ok.ResumeToken != "" {
		sid, err1 := base64.StdEncoding.DecodeString(ok.SessionID)
		tok, err2 := base64.StdEncoding.DecodeString(ok.ResumeToken)
		if err1 == nil && err2 == nil && len(sid) == 16 && len(tok) == 32 {
			copy(params.id[:], sid)
			copy(params.resumeToken[:], tok)
			params.hasResume = true
		}
	}
	c.setSession(params)
	// Q6: adopt the server-issued profile (same rule as the QUIC
	// client). A missing/invalid envelope does not fail TCP AUTH.
	if ok.Profile != nil {
		if err := ok.Profile.Validate(); err == nil {
			c.mu.Lock()
			c.activeProfile = *ok.Profile
			store := c.profileStore
			serverID := c.serverID
			c.mu.Unlock()
			if store != nil {
				store.Put(serverID, *ok.Profile)
			}
		}
	}
	return nil
}

// Resume re-establishes a session created by an earlier AUTH (on either
// leg) without a fresh K_auth token: the resume token travels sealed
// under the old c2s key, prefixed by the clear session id for lookup.
func (c *TCPClient) Resume(p *sessionParams) error {
	if p == nil || !p.hasResume {
		return errors.New("realquic: no resume identity for TCP resume")
	}
	codec := p.clientCodec()
	sealed, err := codec.Seal(p.resumeToken[:])
	if err != nil {
		return err
	}
	payload := make([]byte, 0, 16+len(sealed))
	payload = append(payload, p.id[:]...)
	payload = append(payload, sealed...)
	if err := WriteFrame(c, frameResume, payload); err != nil {
		return err
	}
	fr, err := ReadFrame(c)
	if err != nil {
		return err
	}
	if fr.Type != frameResumeOK {
		return errors.New("realquic: TCP resume refused (no RESUME_OK frame)")
	}
	if _, err := codec.Open(fr.Payload); err != nil {
		return err
	}
	c.setSession(p)
	return nil
}

// Connect sends a CONNECT frame for target and returns the relay stream.
// Only meaningful after Auth or Resume on this connection.
func (c *TCPClient) Connect(ctx context.Context, target string) (*ConnectStream, error) {
	codec := c.codecOrIdentity()
	payload, err := encodeTarget(target)
	if err != nil {
		return nil, err
	}
	if err := WriteFrameCodec(c, frameConnect, payload, codec); err != nil {
		return nil, err
	}
	for {
		fr, err := ReadFrameCodec(c, codec)
		if err != nil {
			return nil, err
		}
		switch fr.Type {
		case frameConnectOK:
			return &ConnectStream{rw: c, codec: codec, closeFn: c.conn.Close}, nil
		case frameConnectErr:
			return nil, errors.New("realquic: TCP connect refused: " + string(fr.Payload))
		default:
			return nil, errors.New("realquic: unexpected frame on TCP CONNECT")
		}
	}
}

// Read/Write implement io.ReadWriter over the buffered TLS connection
// for ReadFrame/WriteFrame use. The buffered reader must be used for all
// reads: the server's first frames may already sit in its buffer.
func (c *TCPClient) Read(p []byte) (int, error)  { return c.br.Read(p) }
func (c *TCPClient) Write(p []byte) (int, error) { return c.conn.Write(p) }
