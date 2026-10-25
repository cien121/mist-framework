package realquic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Client is a lab client over one shared QUIC connection. It speaks
// HTTP/3, and in this step also taken-over custom streams (CONNECT,
// UDP registration) and RFC 9221 datagrams on the same connection.
type Client struct {
	key        []byte
	authHeader string
	authPath   string
	qconn      *quic.Conn
	h3         *http3.ClientConn

	// Step-5 session state, installed by Auth on success only.
	// codec is nil until then (identity behaviour for pre-AUTH
	// frames, which the server refuses anyway); session holds the
	// resume identity for the TCP leg.
	mu      sync.Mutex
	codec   PayloadCodec
	session *sessionParams
	// P1 step A (Q6) profile state. activeProfile is the profile this
	// connection shapes by (once the Q3 engine exists): bootstrap
	// before the first AUTH, the server-issued profile after it, and
	// the newest pushed profile after an in-session update. The store
	// is shared across this client's sessions when the caller supplies
	// one, so a later session starts from the server profile instead
	// of bootstrap. No key material is ever stored here.
	profileStore    *ProfileStore
	serverID        string
	activeProfile   Profile
	profileLoopOnce sync.Once
	// P1 step B (Q3): the shaper governing this connection's sends.
	// Its window profile lags pushes (see shaping.go): AUTH advances
	// the window, a push only queues a pending profile.
	shaper *Shaper
}

// codecOrIdentity returns the session codec once AUTH installed it,
// and the identity codec before that.
func (c *Client) codecOrIdentity() PayloadCodec {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codec != nil {
		return c.codec
	}
	return IdentityCodec{}
}

// setSession installs the session keys after a successful AUTH. It is
// only called on the success path; a failed AUTH never touches it, so
// a failed re-AUTH cannot downgrade an established session.
func (c *Client) setSession(p *sessionParams) {
	c.mu.Lock()
	c.session = p
	c.codec = p.clientCodec()
	c.mu.Unlock()
}

// sessionSnapshot returns the current session params, or nil.
func (c *Client) sessionSnapshot() *sessionParams {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// ActiveProfile returns the profile this connection currently applies
// (bootstrap before AUTH, server-issued after AUTH, newest pushed
// profile after an in-session update).
func (c *Client) ActiveProfile() Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeProfile
}

// Shaper returns this connection's Q3 shaper (nil only for clients
// not built through the Dial constructors, which never happens in
// this package). EffectiveProfile on it is the window profile: it
// lags pushes until the next window boundary, unlike ActiveProfile,
// which is step A's selection and moves on push.
func (c *Client) Shaper() *Shaper {
	return c.shaper
}

// ShapingEvents returns this connection's recorded datagram sends
// (empty when the client has no shaper).
func (c *Client) ShapingEvents() []SendEvent {
	if c.shaper == nil {
		return nil
	}
	return c.shaper.Events()
}

// ProfileStore returns the store this client records server profiles in
// (nil only for clients built without one, which never happens through
// the Dial constructors).
func (c *Client) ProfileStore() *ProfileStore {
	return c.profileStore
}

// adoptProfile installs a server-issued profile for this connection
// unconditionally (after validation): AUTH is authoritative for its own
// connection, even if the shared store already holds a newer version
// from another connection. The store itself keeps the newest version
// (ProfileStore.Put's gate), so later sessions still start from the
// newest server profile. It reports whether a profile was adopted.
func (c *Client) adoptProfile(p Profile) bool {
	if err := p.Validate(); err != nil {
		return false
	}
	c.mu.Lock()
	c.activeProfile = p
	store := c.profileStore
	serverID := c.serverID
	c.mu.Unlock()
	if store != nil {
		store.Put(serverID, p)
	}
	return true
}

// applyProfile installs a pushed profile only if it is valid and
// strictly newer than the active profile. A stale, replayed or invalid
// push is ignored silently: the session continues on the old profile
// until it ends, and no error surfaces to the caller. It reports
// whether the active profile changed.
func (c *Client) applyProfile(p Profile) bool {
	if err := p.Validate(); err != nil {
		return false
	}
	c.mu.Lock()
	cur := c.activeProfile
	store := c.profileStore
	serverID := c.serverID
	if p.Version <= cur.Version {
		c.mu.Unlock()
		return false
	}
	c.activeProfile = p
	c.mu.Unlock()
	if store != nil {
		store.Put(serverID, p)
	}
	return true
}

// SendProfileReceipt sends this connection's active profile version to
// the server as a Q6 receipt on a dedicated custom stream, sealed under
// the session codec. The server compares it against the connection's
// issued versions; a version never issued to it downgrades the
// connection to a visitor.
// Receipt delivery is best-effort: a failure here does not fail AUTH or
// the session (the absence of a receipt alone never downgrades).
func (c *Client) SendProfileReceipt(ctx context.Context) error {
	str, err := c.qconn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer str.Close()
	applyReadDeadline(str, ctx)
	c.mu.Lock()
	rec := profileReceipt{Version: c.activeProfile.Version, ServerID: c.serverID}
	c.mu.Unlock()
	payload, err := encodeProfileReceipt(rec)
	if err != nil {
		return err
	}
	return WriteFrameCodec(str, frameProfileReceipt, payload, c.codecOrIdentity())
}

// startProfileLoop starts the goroutine that accepts server-initiated
// custom streams (profile pushes). It runs once per client, started on
// the first successful AUTH. H3 request streams are client-opened and
// never enter this loop; control/QPACK unidirectional streams are
// handled by the H3 stack, not here.
func (c *Client) startProfileLoop() {
	c.profileLoopOnce.Do(func() {
		go func() {
			ctx := c.qconn.Context()
			for {
				str, err := c.qconn.AcceptStream(ctx)
				if err != nil {
					return
				}
				go c.handlePushedStream(str)
			}
		}()
	})
}

// handlePushedStream serves one server-initiated stream. Only a
// frameProfileUpdate frame is acted on: a valid, newer profile is
// applied (effective from the next window — in this step, where no Q3
// engine consumes profiles yet, "next window" means the next profile
// application point, i.e. subsequent sessions and any later push
// comparison; the in-flight session's already-started work is never
// retroactively reshaped), and a receipt for the new version is sent
// best-effort. Every failure mode — wrong first byte, bad frame,
// undecodable or stale profile, receipt send failure — closes the
// stream and leaves the session and its old profile untouched.
func (c *Client) handlePushedStream(str *quic.Stream) {
	defer str.Close()
	var first [1]byte
	if _, err := str.Peek(first[:]); err != nil {
		return
	}
	if first[0] == 0x01 {
		return // server-initiated H3 stream: not a push, ignore
	}
	fr, err := ReadFrameCodec(str, c.codecOrIdentity())
	if err != nil || fr.Type != frameProfileUpdate {
		return
	}
	p, err := DecodeProfile(fr.Payload)
	if err != nil {
		return
	}
	if !c.applyProfile(p) {
		return
	}
	// P1 step B: a push never rewrites the window in flight. The
	// shaper keeps the old profile until the next window boundary;
	// applyProfile above only moved step A's selection (and the
	// receipt below names the new version, as step A requires).
	if c.shaper != nil {
		c.shaper.QueuePending(p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.SendProfileReceipt(ctx)
}
func (c *Client) transportDead() bool {
	return c.qconn.Context().Err() != nil
}

// DialPacketConn dials over pc to remoteAddr (net.PacketConn abstraction).
// TLS verification is skipped: this is lab code talking to an in-memory
// test certificate for "realquic.test". It must never be used against a
// production endpoint.
func DialPacketConn(ctx context.Context, pc net.PacketConn, remoteAddr net.Addr, key []byte) (*Client, error) {
	return DialPacketConnWithProfileStore(ctx, pc, remoteAddr, key, NewProfileStore(), testServerName)
}

// DialPacketConnWithProfileStore is DialPacketConn with an explicit
// profile store and server identity. Sharing one store across clients
// is what makes "later sessions use the server profile" true: a client
// dialled with a store that already holds a profile for serverID starts
// from that profile instead of bootstrap, before its own AUTH. A nil
// store gets a fresh one; an empty serverID defaults to testServerName.
func DialPacketConnWithProfileStore(ctx context.Context, pc net.PacketConn, remoteAddr net.Addr, key []byte, store *ProfileStore, serverID string) (*Client, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // lab only: in-memory test certificate
		NextProtos:         []string{"h3"},
		ServerName:         testServerName,
	}
	if store == nil {
		store = NewProfileStore()
	}
	if serverID == "" {
		serverID = testServerName
	}
	// P1 step B (Q3): every datagram this connection sends passes
	// the shaping wrapper — window 0 runs on the store's active
	// profile (bootstrap on first contact, the server profile on
	// later sessions). The stack is never handed the raw PacketConn.
	shaped := newSingleShapingConn(pc, "up", store.ActiveFor(serverID))
	// EnableDatagrams negotiates RFC 9221 datagrams for the UDP relay;
	// it does not change the H3 behaviour of the connection.
	qconn, err := quic.Dial(ctx, shaped, remoteAddr, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return nil, err
	}
	return &Client{
		key:           key,
		authHeader:    DefaultAuthHeader,
		authPath:      DefaultAuthPath,
		qconn:         qconn,
		h3:            (&http3.Transport{}).NewClientConn(qconn),
		profileStore:  store,
		serverID:      serverID,
		activeProfile: store.ActiveFor(serverID),
		shaper:        shaped.single,
	}, nil
}

// Close closes the underlying QUIC connection.
func (c *Client) Close() error {
	return c.qconn.CloseWithError(0, "done")
}

// freshToken builds a one-use AUTH token with a fresh nonce and a fresh
// client ephemeral keypair.
func (c *Client) freshToken() (string, error) {
	token, _, _, err := freshTokenForKey(c.key)
	return token, err
}

// freshTokenWithKeys is freshToken plus the ephemeral keypair behind it,
// which Auth needs to derive the session keys.
func (c *Client) freshTokenWithKeys() (string, [32]byte, [32]byte, error) {
	return freshTokenForKey(c.key)
}

// Request performs one HTTP/3 request on the shared connection and returns
// status, body and round-trip time. token, when non-empty, is sent as the
// AUTH header value.
func (c *Client) Request(ctx context.Context, method, path, token string) (int, []byte, time.Duration, error) {
	return c.RequestWithBody(ctx, method, path, token, nil)
}

// RequestWithBody is Request with an explicit request body. Only Auth
// uses a non-nil body (Q3 length shaping, see Auth); visitor and
// failure probes keep a nil body so their request shape is unchanged.
func (c *Client) RequestWithBody(ctx context.Context, method, path, token string, body []byte) (int, []byte, time.Duration, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+testServerName+path, rdr)
	if err != nil {
		return 0, nil, 0, err
	}
	if token != "" {
		req.Header.Set(c.authHeader, token)
	}
	start := time.Now()
	resp, err := c.h3.RoundTrip(req)
	if err != nil {
		return 0, nil, time.Since(start), err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, time.Since(start), err
}

// Auth sends a fresh-token AUTH request and returns status, body, latency.
// On success only, it derives the step-5 session keys from the client's
// ephemeral private key and the server ephemeral public key in the
// response body, and installs the session codec plus the resume
// identity. On any failure (non-200, unparsable body, bad server key)
// the previous session state is left untouched.
func (c *Client) Auth(ctx context.Context) (int, []byte, time.Duration, error) {
	token, priv, pub, err := c.freshTokenWithKeys()
	if err != nil {
		return 0, nil, 0, err
	}
	// P1 step B (Q3 length): the AUTH request body is padded to a
	// length sampled from the current window's LenDist (bootstrap
	// before the first AUTH). This is the length-shaping wire point
	// quic-go's public API allows: the stack packetises the padded
	// flight, so the flight's datagrams grow with the sample. The
	// padding is meaningless zero bytes and carries no credential.
	var pad []byte
	if c.shaper != nil {
		pad = padBytes(c.shaper.SampleLen())
	}
	status, body, latency, err := c.RequestWithBody(ctx, http.MethodPost, c.authPath, token, pad)
	if err != nil || status != http.StatusOK {
		return status, body, latency, err
	}
	var ok authSuccess
	if err := json.Unmarshal(body, &ok); err != nil {
		return status, body, latency, err
	}
	decoded, err := base64.StdEncoding.DecodeString(ok.ServerEphPub)
	if err != nil || len(decoded) != 32 {
		return status, body, latency, errors.New("realquic: AUTH success body has no valid server_eph_pub")
	}
	var serverPub [32]byte
	copy(serverPub[:], decoded)
	shared, err := deriveShared(priv, serverPub)
	if err != nil {
		return status, body, latency, err
	}
	c2s, s2c, err := deriveDirectionKeys(shared, pub, serverPub)
	if err != nil {
		return status, body, latency, err
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
	// Q6: adopt the server-issued profile for this connection, start
	// accepting in-session pushes, and receipt the issued version.
	// A missing or invalid profile envelope does not fail AUTH — the
	// session keys are already valid — but the connection then keeps
	// its previous (bootstrap or stored) profile, and its receipt (if
	// any) will name a version never issued to this connection.
	if ok.Profile != nil {
		adopted := *ok.Profile
		c.adoptProfile(adopted)
		// P1 step B: AUTH success is a window boundary. The AUTH
		// request was window 0 (bootstrap); from here on the
		// server profile governs the shaper's window 1.
		if c.shaper != nil {
			c.shaper.BeginWindow(&adopted)
		}
	}
	c.startProfileLoop()
	_ = c.SendProfileReceipt(ctx)
	return status, body, latency, nil
}

// Get performs a plain visitor GET (no AUTH) on the shared connection.
func (c *Client) Get(ctx context.Context, path string) (int, []byte, time.Duration, error) {
	return c.Request(ctx, http.MethodGet, path, "")
}

// --- Step 4: taken-over streams and datagrams (path S) ---

// NewSessionID generates a fresh random 16-byte UDP session ID.
func NewSessionID() ([16]byte, error) {
	var sid [16]byte
	_, err := rand.Read(sid[:])
	return sid, err
}

// Connect opens a custom stream, sends a CONNECT frame for target
// ("host:port"), and waits for CONNECT_OK. The returned stream relays
// framed DATA in both directions; its lifecycle is the dial's lifecycle.
// Only meaningful after a successful AUTH on this connection (the server
// cancels custom streams on unauthenticated connections).
func (c *Client) Connect(ctx context.Context, target string) (*ConnectStream, error) {
	str, err := c.qconn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	applyReadDeadline(str, ctx)
	payload, err := encodeTarget(target)
	if err != nil {
		_ = str.Close()
		return nil, err
	}
	codec := c.codecOrIdentity()
	if err := WriteFrameCodec(str, frameConnect, payload, codec); err != nil {
		_ = str.Close()
		return nil, err
	}
	for {
		fr, err := ReadFrameCodec(str, codec)
		if err != nil {
			_ = str.Close()
			return nil, err
		}
		switch fr.Type {
		case frameConnectOK:
			clearReadDeadline(str)
			return &ConnectStream{rw: str, codec: codec, closeFn: str.Close}, nil
		case frameConnectErr:
			_ = str.Close()
			return nil, errors.New("realquic: connect refused: " + string(fr.Payload))
		default:
			_ = str.Close()
			return nil, errors.New("realquic: unexpected frame on CONNECT stream")
		}
	}
}

// RegisterUDP registers a UDP relay session on this connection: datagrams
// tagged with sid are forwarded to target, and replies come back tagged
// with the same sid. The registration stream closes after the
// acknowledgement; the session persists on the server until the
// connection closes.
func (c *Client) RegisterUDP(ctx context.Context, sid [16]byte, target string) error {
	str, err := c.qconn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer str.Close()
	applyReadDeadline(str, ctx)
	payload, err := encodeUDPRegistration(sid, target)
	if err != nil {
		return err
	}
	codec := c.codecOrIdentity()
	if err := WriteFrameCodec(str, frameRegisterUDP, payload, codec); err != nil {
		return err
	}
	fr, err := ReadFrameCodec(str, codec)
	if err != nil {
		return err
	}
	switch fr.Type {
	case frameRegisterOK:
		return nil
	case frameRegisterErr:
		return errors.New("realquic: UDP registration refused: " + string(fr.Payload))
	default:
		return errors.New("realquic: unexpected frame on REGISTER stream")
	}
}

// SendDatagram sends one UDP-relay datagram tagged with sid. Delivery is
// not guaranteed (RFC 9221 datagrams are not retransmitted). The payload
// portion is sealed under the session codec once AUTH installed it; the
// session ID routing header stays in the clear.
func (c *Client) SendDatagram(sid [16]byte, payload []byte) error {
	// codecOrIdentity is the identity codec pre-AUTH (a no-op seal)
	// and the session codec after AUTH, so one code path covers both.
	sealed, err := c.codecOrIdentity().Seal(payload)
	if err != nil {
		return err
	}
	return c.qconn.SendDatagram(encodeDatagram(sid, sealed))
}

// ReceiveDatagram receives one UDP-relay datagram and splits it into its
// session ID and payload. Unknown sessions never produce a datagram here:
// the server drops them instead of routing them anywhere. A payload that
// fails AEAD open is returned as an error, never delivered.
func (c *Client) ReceiveDatagram(ctx context.Context) ([16]byte, []byte, error) {
	data, err := c.qconn.ReceiveDatagram(ctx)
	if err != nil {
		return [16]byte{}, nil, err
	}
	sid, payload, err := decodeDatagram(data)
	if err != nil {
		return [16]byte{}, nil, err
	}
	opened, err := c.codecOrIdentity().Open(payload)
	if err != nil {
		return [16]byte{}, nil, err
	}
	return sid, opened, nil
}

func applyReadDeadline(str *quic.Stream, ctx context.Context) {
	if dl, ok := ctx.Deadline(); ok {
		_ = str.SetReadDeadline(dl)
	}
}

func clearReadDeadline(str *quic.Stream) {
	_ = str.SetReadDeadline(time.Time{})
}

// ConnectStream is one CONNECT relay: Write sends framed DATA, Read
// returns relayed DATA bytes (buffering a frame's leftover across calls).
// Close closes the underlying stream/connection; the read side ends when
// the server closes the stream (e.g. the TCP target closed).
//
// The relay is transport-generic: rw is a QUIC stream on the QUIC leg
// and the buffered TLS connection on the TCP leg, and codec is the
// session codec installed by AUTH (identity pre-AUTH, which the server
// refuses anyway). The TCP leg reuses this exact type so the two legs
// cannot drift apart in framing behaviour.
type ConnectStream struct {
	rw      io.ReadWriter
	codec   PayloadCodec
	closeFn func() error

	mu  sync.Mutex
	buf []byte
}

// Write sends p as one or more DATA frames, chunked to maxDataChunk.
func (cs *ConnectStream) Write(p []byte) (int, error) {
	total := len(p)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	codec := cs.codec
	if codec == nil {
		codec = IdentityCodec{}
	}
	for len(p) > 0 {
		n := len(p)
		if n > maxDataChunk {
			n = maxDataChunk
		}
		if err := WriteFrameCodec(cs.rw, frameData, p[:n], codec); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return total, nil
}

// Read returns buffered DATA bytes, or the next DATA frame's payload.
// A non-DATA frame or stream end terminates the read side.
func (cs *ConnectStream) Read(p []byte) (int, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	codec := cs.codec
	if codec == nil {
		codec = IdentityCodec{}
	}
	for len(cs.buf) == 0 {
		fr, err := ReadFrameCodec(cs.rw, codec)
		if err != nil {
			return 0, err
		}
		if fr.Type != frameData {
			return 0, io.EOF
		}
		cs.buf = fr.Payload
	}
	n := copy(p, cs.buf)
	cs.buf = cs.buf[n:]
	return n, nil
}

// Close closes the underlying stream (QUIC leg) or connection (TCP leg).
func (cs *ConnectStream) Close() error {
	if cs.closeFn != nil {
		return cs.closeFn()
	}
	return nil
}
