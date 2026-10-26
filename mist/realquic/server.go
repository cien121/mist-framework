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
	// Profile, if non-nil, is the operator-supplied base profile the
	// server issues from (its version is ignored: the server is the
	// version authority, first issued version is 1). If nil, the
	// bootstrap profile is the base. The base must validate, or
	// NewServer fails.
	Profile *Profile
	// RotationMin/RotationMax bound the server's profile rotation
	// period: each rotation delay is picked uniformly at random inside
	// [RotationMin, RotationMax] (deployment configuration, never a
	// protocol constant). Zero/negative RotationMin disables rotation:
	// the issued profile then changes only when the operator rotates it
	// explicitly via RotateProfile.
	RotationMin time.Duration
	RotationMax time.Duration
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
	ephPriv    [32]byte
	// sessions is server-level (not per-connection) so a session
	// established on the QUIC leg can be resumed on the TCP leg.
	sessions *sessionTable

	mu        sync.Mutex
	listeners []*quic.Listener
	conns     map[*quic.Conn]struct{}
	// connStates parallels conns: per-connection Q6 state (issued
	// profile version, last receipt, downgrade flag).
	connStates map[*quic.Conn]*connState
	dropped    atomic.Int64 // datagrams dropped (unknown session or pre-AUTH)
	// profileMu guards issued; rotationMu-free: RotateProfile and
	// IssuedProfile are the only writers/readers of issued.
	profileMu   sync.Mutex
	issued      Profile
	rotationMin time.Duration
	rotationMax time.Duration
	// rotatorStop is closed by Close; the rotator goroutine (if any)
	// exits on it. Guarded by rotatorOnce for start and stopOnce for close.
	rotatorOnce sync.Once
	rotatorStop chan struct{}
	stopOnce    sync.Once
	// P2 step 2 (Q4): the split-connection registry. Split sessions are
	// keyed by UP session ID and pendings by split request ID; both are
	// guarded by splitMu. The registry lives on the Server (not in a
	// package-level map) so two servers never share split state, and so
	// Server.Close() dropping the Server drops its split state with it.
	// A splitSession's lifetime clock starts at first bind (or at first
	// split CONNECT if that arrives first, defensively); its counters
	// are what the server-issued reuse caps (profile MaxStreamsPerConn /
	// MaxReusePerConn / MaxConnLifetimeSec) are enforced against, in
	// handleSplitConnect. Client-side pre-refusal is deliberately NOT
	// done: these counters are server-side state (see split.go header).
	splitMu       sync.Mutex
	splitSessions map[[16]byte]*splitSession
	splitPendings map[[16]byte]*splitPending
	// P1 step B (Q3): the shaping wrappers of this server's listeners
	// (one per listener PacketConn). Guarded by shapingMu; the
	// wrappers themselves own their per-peer shapers.
	shapingMu    sync.Mutex
	shapingConns []*shapingPacketConn
	// lastAuthContentLength records the Content-Length of the most
	// recent request to the AUTH path (any outcome): lab
	// observability for Q3 client-flight length shaping, nothing
	// more. A value of -1 means the request carried no length.
	lastAuthContentLength atomic.Int64
}

// LastAuthContentLength reports the Content-Length of the most recent
// AUTH-path request seen by this server.
func (s *Server) LastAuthContentLength() int64 {
	return s.lastAuthContentLength.Load()
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
// ephemeral X25519 public key (base64). profile is the Q6 profile
// envelope (P1 step A): the server's currently issued profile, carried
// inside this AUTH response over the Mode A QUIC/TLS connection — the
// connection itself is authenticated to the server's identity before
// any profile is trusted, so no separate envelope signature is added
// this step (see profile.go). profile_note states the provisional
// status of the values; it is kept non-empty so the envelope is never
// silently absent (an existing test asserts its presence).
// session_id / resume_token (base64) are the step-5 resume identity:
// the client keeps them to resume the same session on the TCP leg
// without a full re-AUTH (design Q8). They are absent only if the
// server could not create a record, in which case resume is unavailable
// but the session keys themselves are still valid.
type authSuccess struct {
	ServerEphPub string   `json:"server_eph_pub"`
	Profile      *Profile `json:"profile"`
	ProfileNote  string   `json:"profile_note"`
	SessionID    string   `json:"session_id,omitempty"`
	ResumeToken  string   `json:"resume_token,omitempty"`
	// Padding is P1 step B (Q3 length) shaping on the down flight:
	// meaningless zero bytes sized from the connection's down
	// shaper LenDist sample, so the AUTH_OK flight's length follows
	// the profile. It is omitted (not empty) when shaping is absent.
	Padding string `json:"padding,omitempty"`
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
	// Note: the server ephemeral pair is per-server-instance in this
	// step (step 4 behaviour, kept); per-connection rotation is a
	// follow-up, not a step-5 requirement. The private half is retained
	// here — step 4 generated it and discarded it, which is why step 5
	// must store it to derive session keys.
	s := &Server{
		verify:        newVerifier(cfg.Key, cfg.Window),
		authHeader:    cfg.AuthHeader,
		authPath:      cfg.AuthPath,
		ephPub:        pub,
		ephPriv:       priv,
		sessions:      newSessionTable(),
		conns:         map[*quic.Conn]struct{}{},
		connStates:    map[*quic.Conn]*connState{},
		splitSessions: map[[16]byte]*splitSession{},
		splitPendings: map[[16]byte]*splitPending{},
		rotationMin:   cfg.RotationMin,
		rotationMax:   cfg.RotationMax,
		rotatorStop:   make(chan struct{}),
	}
	// Q6 issuance state: the base profile (operator-supplied or
	// bootstrap) becomes the first issued profile, version 1. An
	// invalid base fails server construction rather than issuing a
	// profile clients would reject on receipt.
	base := BootstrapProfile()
	if cfg.Profile != nil {
		base = *cfg.Profile
	}
	if err := base.Validate(); err != nil {
		return nil, err
	}
	s.issued = newIssuedFrom(base)
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

// IssuedProfile returns a copy of the server's currently issued profile.
func (s *Server) IssuedProfile() Profile {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	return s.issued
}

// RotateProfile issues a new profile version (same parameters, new
// version and timestamp) and returns it. Rotation changes the version
// clients must receipt; it does not retroactively invalidate existing
// connections — those keep their per-connection issued version until
// they receive a push (PushCurrentProfile) or re-AUTH.
func (s *Server) RotateProfile() Profile {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	s.issued.Version++
	s.issued.IssuedAt = time.Now().Unix()
	return s.issued
}

// NextRotationDelay reports the delay until the next rotation, picked
// uniformly at random inside the configured interval. It reports false
// when rotation is not configured (see nextRotationDelay).
func (s *Server) NextRotationDelay() (time.Duration, bool) {
	return nextRotationDelay(s.rotationMin, s.rotationMax)
}

// startRotator launches the background rotation loop once, when the
// server starts serving. Each cycle sleeps a freshly picked random
// delay inside the configured interval, then rotates. An unconfigured
// server starts no loop. The loop never touches sessions: rotation
// only changes what new AUTHs receive and what pushes carry.
func (s *Server) startRotator() {
	s.rotatorOnce.Do(func() {
		go func() {
			for {
				delay, ok := s.NextRotationDelay()
				if !ok {
					return
				}
				select {
				case <-s.rotatorStop:
					return
				case <-time.After(delay):
				}
				s.RotateProfile()
			}
		}()
	})
}

// PushCurrentProfile pushes the server's currently issued profile to
// one authenticated connection over a server-initiated custom stream,
// sealed under that connection's session codec (the encrypted control
// flow of design Q6). On success it records the pushed version as that
// connection's issued version (joining the set its receipts may
// acknowledge). On any
// failure the connection's session is untouched: the old profile stays
// authoritative for that connection until its end, and no error reaches
// the client — the returned error is for the operator only, and the
// push may simply be retried later. A push to an unknown,
// unauthenticated or downgraded connection fails without side effects.
func (s *Server) PushCurrentProfile(qconn *quic.Conn) (Profile, error) {
	issued := s.IssuedProfile()
	s.mu.Lock()
	st, ok := s.connStates[qconn]
	s.mu.Unlock()
	if !ok || st == nil || !st.isAuthed() || st.isDowngraded() {
		return Profile{}, errors.New("realquic: cannot push profile to unknown, unauthenticated or downgraded connection")
	}
	codec := st.sessionCodec()
	if codec == nil {
		return Profile{}, errors.New("realquic: connection has no session codec")
	}
	encoded, err := EncodeProfile(issued)
	if err != nil {
		return Profile{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		return Profile{}, err
	}
	defer str.Close()
	if err := WriteFrameCodec(str, frameProfileUpdate, encoded, codec); err != nil {
		return Profile{}, err
	}
	// Only a delivered push moves the connection's issued version.
	st.noteIssued(issued.Version)
	// P1 step B: the push also queues on the connection's down
	// shaper as pending — the in-flight window keeps the old
	// profile; the new one takes effect at the next window
	// boundary (a re-AUTH on this connection).
	s.queueDownPending(qconn, issued)
	return issued, nil
}

// downShaperIfExists returns the down shaper for the peer address of
// qconn, if any listener wrapper has already created one for it.
func (s *Server) downShaperIfExists(addr net.Addr) *Shaper {
	s.shapingMu.Lock()
	conns := append([]*shapingPacketConn{}, s.shapingConns...)
	s.shapingMu.Unlock()
	for _, sc := range conns {
		if sh := sc.shaperIfExists(addr); sh != nil {
			return sh
		}
	}
	return nil
}

// queueDownPending queues a pushed profile on the down shaper for
// qconn's peer address (no-op when no shaper exists yet).
func (s *Server) queueDownPending(qconn *quic.Conn, p Profile) {
	if qconn == nil {
		return
	}
	if sh := s.downShaperIfExists(qconn.RemoteAddr()); sh != nil {
		sh.QueuePending(p)
	}
}

// DownEvents aggregates the recorded down-direction datagram sends
// across this server's listener wrappers (the test hook for Q3
// down-flight shaping).
func (s *Server) DownEvents() []SendEvent {
	s.shapingMu.Lock()
	conns := append([]*shapingPacketConn{}, s.shapingConns...)
	s.shapingMu.Unlock()
	var out []SendEvent
	for _, sc := range conns {
		out = append(out, sc.allEvents()...)
	}
	return out
}

// ConnProfileState reports one connection's Q6 state for tests and
// operators: the issued version (AUTH or last successful push), the
// last receipted version and whether any receipt arrived, and whether
// the connection has been downgraded. ok is false for unknown
// connections.
func (s *Server) ConnProfileState(qconn *quic.Conn) (issued, receipt uint64, receiptSeen, downgraded, ok bool) {
	s.mu.Lock()
	st, ok := s.connStates[qconn]
	s.mu.Unlock()
	if !ok || st == nil {
		return 0, 0, false, false, false
	}
	return st.profileState()
}

// handlerFor is the per-connection HTTP/3 handler. On AUTH success it
// marks the connection authenticated, which is what unlocks custom
// streams and datagrams on that connection.
func (s *Server) handlerFor(st *connState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == s.authPath {
			// P1 step B lab observability (see LastAuthContentLength).
			s.lastAuthContentLength.Store(r.ContentLength)
			// One code path for every outcome: verify (constant-time
			// HMAC, window, nonce cache) and, on any failure, fall
			// through to the site handler. Nothing here logs the
			// token, and no failure produces a distinctive status,
			// body, or teardown. On success only, derive the step-5
			// session keys from the verified client ephemeral public
			// key and the server ephemeral private key, and install
			// the session codec on this connection: from here on,
			// custom frames and datagram payloads on this connection
			// are sealed under the session keys. A derivation failure
			// is treated like an AUTH failure (visitor path), never
			// as a distinctive error.
			if clientPub, ok := s.verify.VerifyToken(r.Header.Get(s.authHeader), time.Now()); ok {
				shared, derr := deriveShared(s.ephPriv, clientPub)
				if derr == nil {
					c2s, s2c, kerr := deriveDirectionKeys(shared, clientPub, s.ephPub)
					if kerr == nil {
						// P1 step B: capture pre-AUTH state before
						// setSession overwrites it — a re-AUTH on an
						// already authenticated connection is a down
						// window boundary (see shaping.go).
						wasAuthed := st != nil && st.isAuthed()
						rec, rerr := s.sessions.newRecord(c2s, s2c)
						if rerr == nil && st != nil {
							st.setSession(rec.serverCodec())
						}
						// Q6: this connection's issued version is
						// recorded (see noteIssued/noteReceipt). It is
						// recorded on the AUTH success path only, never
						// on failure.
						issued := s.IssuedProfile()
						if st != nil {
							st.noteIssued(issued.Version)
						}
						// P1 step B: a re-AUTH advances the down
						// window (activating any queued push); the
						// first AUTH response stays in window 0.
						if wasAuthed && st != nil {
							if sh := s.downShaperIfExists(st.remoteAddr); sh != nil {
								sh.BeginWindow(nil)
							}
						}
						resp := authSuccess{
							ServerEphPub: base64.StdEncoding.EncodeToString(s.ephPub[:]),
							Profile:      &issued,
							ProfileNote:  "Q6 profile envelope issued (P1 step A); all values provisional, D2 final values pending P2 baseline measurement",
						}
						// P1 step B (Q3 length): pad the AUTH_OK body
						// from the down shaper's LenDist sample, so
						// the server response flight's length follows
						// the profile (meaningless zero bytes, capped
						// by SampleLen; no padding when no shaper).
						if st != nil {
							if sh := s.downShaperIfExists(st.remoteAddr); sh != nil {
								resp.Padding = string(padBytes(sh.SampleLen()))
							}
						}
						if rerr == nil {
							resp.SessionID = base64.StdEncoding.EncodeToString(rec.id[:])
							resp.ResumeToken = base64.StdEncoding.EncodeToString(rec.resumeToken[:])
						}
						body, _ := json.Marshal(resp)
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write(body)
						return
					}
				}
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
// listenPacketConn builds one QUIC listener over pc. The certificate is
// generated in memory; ALPN is "h3" only.
func (s *Server) listenPacketConn(pc net.PacketConn) (*quic.Listener, error) {
	cert, err := generateTestCertificate()
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
	// P1 step B (Q3): every datagram this listener sends passes the
	// shaping wrapper — per peer address, starting from the
	// currently issued profile. The stack is never handed the raw
	// PacketConn, so there is no unwrapped (bare) send path.
	shaped := newPerAddrShapingConn(pc, "down", s.IssuedProfile)
	s.shapingMu.Lock()
	s.shapingConns = append(s.shapingConns, shaped)
	s.shapingMu.Unlock()
	return quic.Listen(shaped, tlsConf, &quic.Config{EnableDatagrams: true})
}

func (s *Server) serveListener(ln *quic.Listener) error {
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

func (s *Server) ServePacketConn(pc net.PacketConn) error {
	ln, err := s.listenPacketConn(pc)
	if err != nil {
		return err
	}
	s.startRotator()
	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
	return s.serveListener(ln)
}

// ServePacketConns is the step-5 Q7 form: one server over many
// PacketConns (many ports, and in a capable environment both address
// families), all sharing this Server's verifier, site handler, ephemeral
// keys and session table — hence the same QUIC stack logic and the same
// HTTP/3 application on every port/family. There is no per-port or
// per-family special case anywhere in the handler: an unauthenticated
// prober gets the same site response from every instance, which is what
// the Q7 coverage test proves. It blocks until the first listener's
// Accept loop returns an error (e.g. Close).
func (s *Server) ServePacketConns(pcs []net.PacketConn) error {
	var listeners []*quic.Listener
	for _, pc := range pcs {
		ln, err := s.listenPacketConn(pc)
		if err != nil {
			for _, done := range listeners {
				_ = done.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, listeners...)
	s.mu.Unlock()
	s.startRotator()
	errs := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func(ln *quic.Listener) { errs <- s.serveListener(ln) }(ln)
	}
	return <-errs
}

// TCPServer returns a TCP-leg server sharing this server's verifier
// (including its nonce cache, so a token cannot be replayed across
// legs), site handler, ephemeral keys and session table. See tcp.go.
func (s *Server) TCPServer() *TCPServer {
	return &TCPServer{
		verify:   s.verify,
		site:     s.site,
		ephPub:   s.ephPub,
		ephPriv:  s.ephPriv,
		sessions: s.sessions,
		profile:  s.IssuedProfile,
	}
}

// Close stops all listeners and all tracked connections. It does not close
// the PacketConns, which remain owned by the caller.
func (s *Server) Close() error {
	s.stopOnce.Do(func() { close(s.rotatorStop) })
	s.mu.Lock()
	listeners := s.listeners
	s.listeners = nil
	conns := make([]*quic.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseWithError(0, "server closed")
	}
	var err error
	for _, ln := range listeners {
		if cerr := ln.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
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
	// remoteAddr is the peer address at accept time, used to find
	// this connection's down shaper (P1 step B).
	remoteAddr net.Addr

	mu       sync.Mutex
	authed   bool
	codec    PayloadCodec // step-5 session codec; nil until AUTH installs it
	sessions map[[16]byte]*udpSession
	// Q6 per-connection state. issuedVersion is the latest profile
	// version issued to this connection (set at AUTH, moved by a
	// successful push). issuedSet is every version ever issued to this
	// connection: receipts are judged against the set, not just the
	// latest version, because receipts are asynchronous — a receipt
	// for the previous version that was already in flight when a push
	// landed must not false-positive as non-compliance. A receipt
	// version outside the set (e.g. bootstrap 0, or another server's
	// version) is what downgrades. receiptVersion/receiptSeen record
	// the last well-formed receipt; downgraded is set when a receipt's
	// version falls outside issuedSet, and is sticky until a fresh
	// AUTH (setSession clears it).
	issuedVersion  uint64
	issuedSet      map[uint64]struct{}
	receiptVersion uint64
	receiptSeen    bool
	downgraded     bool
}

func newConnState(qconn *quic.Conn) *connState {
	return &connState{qconn: qconn, sessions: map[[16]byte]*udpSession{}, issuedSet: map[uint64]struct{}{}}
}

// setSession marks the connection authenticated and installs the session
// codec derived from this AUTH. The two are set together, atomically:
// there is no state in which a connection is authed but still speaking
// the identity codec, and no state in which an unauthenticated
// connection holds a session codec. A fresh AUTH also clears a prior
// downgrade and its receipt record: re-AUTH is a new issuance.
func (st *connState) setSession(codec PayloadCodec) {
	st.mu.Lock()
	st.authed = true
	st.codec = codec
	st.downgraded = false
	st.receiptSeen = false
	st.receiptVersion = 0
	st.issuedSet = map[uint64]struct{}{}
	st.mu.Unlock()
}

// noteIssued records a profile version issued to this connection
// (AUTH or a successful push): it becomes the latest version and joins
// the set of versions receipts may acknowledge.
func (st *connState) noteIssued(v uint64) {
	st.mu.Lock()
	st.issuedVersion = v
	if st.issuedSet == nil {
		st.issuedSet = map[uint64]struct{}{}
	}
	st.issuedSet[v] = struct{}{}
	st.mu.Unlock()
}

// noteReceipt records a well-formed receipt and applies the Q6
// non-compliance rule: a receipt whose version was never issued to
// this connection downgrades the connection to an ordinary HTTP/3
// visitor (see isDowngraded). It reports whether the receipt was
// compliant. Downgrade is sticky: a later compliant receipt does not
// clear it (only a fresh AUTH does), so a client cannot receipt its
// way out after demonstrating it is not applying issued profiles.
// A malformed receipt never reaches this method (the caller drops it
// silently), and the absence of a receipt never downgrades on its own:
// receipt streams are best-effort, and treating a dropped receipt as
// non-compliance would false-positive on ordinary loss.
func (st *connState) noteReceipt(v uint64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.receiptSeen = true
	st.receiptVersion = v
	if _, ok := st.issuedSet[v]; !ok {
		st.downgraded = true
		return false
	}
	return true
}

func (st *connState) isDowngraded() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.downgraded
}

func (st *connState) profileState() (issued, receipt uint64, receiptSeen, downgraded, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.issuedVersion, st.receiptVersion, st.receiptSeen, st.downgraded, true
}

func (st *connState) isAuthed() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.authed
}

func (st *connState) sessionCodec() PayloadCodec {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.codec
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
		delete(s.connStates, qconn)
		s.mu.Unlock()
	}()
	st := newConnState(qconn)
	st.remoteAddr = qconn.RemoteAddr()
	s.mu.Lock()
	s.connStates[qconn] = st
	s.mu.Unlock()
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
// the stream's role; unknown frame types cancel the stream. A downgraded
// connection is handled exactly like an unauthenticated one: its custom
// streams are cancelled with the same code and its datagrams dropped,
// while its HTTP/3 visitor requests keep being served normally — the
// downgrade produces no distinctive error, status, or teardown.
func (s *Server) handleCustomStream(st *connState, str *quic.Stream) {
	if st.isDowngraded() || !st.isAuthed() {
		str.CancelRead(errCodeNotAuthed)
		str.CancelWrite(errCodeNotAuthed)
		return
	}
	// Fail closed: an authed connection without a session codec is a
	// bug, and must not fall back to speaking plaintext frames.
	codec := st.sessionCodec()
	if codec == nil {
		str.CancelRead(errCodeNotAuthed)
		str.CancelWrite(errCodeNotAuthed)
		return
	}
	fr, err := ReadFrameCodec(str, codec)
	if err != nil {
		str.CancelRead(errCodeNotAuthed)
		str.CancelWrite(errCodeNotAuthed)
		return
	}
	switch fr.Type {
	case frameBindDown:
		s.handleSplitBind(st, str, fr, codec)
	case frameConnectSplit:
		s.handleSplitConnect(st, str, fr, codec)
	case frameDownReady:
		s.handleSplitDownReady(st, str, fr, codec)
	case frameConnect:
		s.handleConnect(str, fr, codec)
	case frameRegisterUDP:
		s.handleRegister(st, str, fr, codec)
	case frameProfileReceipt:
		// Receipt stream: record the version, then close normally
		// whether compliant or not. A downgrade (if any) is silent:
		// no error frame, no distinctive status — the connection
		// simply stops getting Mist service on later streams while
		// its H3 visitor traffic continues. A malformed receipt is
		// dropped the same silent way and does not downgrade.
		if rec, err := decodeProfileReceipt(fr.Payload); err == nil {
			st.noteReceipt(rec.Version)
		}
		_ = str.Close()
	default:
		str.CancelRead(errCodeNotAuthed)
		str.CancelWrite(errCodeNotAuthed)
	}
}

// handleConnect dials the requested TCP target and relays framed DATA in
// both directions until either side ends. The stream's lifecycle is the
// dial's lifecycle: stream EOF closes the TCP write side, TCP EOF closes
// the stream write side.
func (s *Server) handleConnect(str *quic.Stream, fr Frame, codec PayloadCodec) {
	target, err := decodeTarget(fr.Payload)
	if err != nil {
		_ = WriteFrameCodec(str, frameConnectErr, []byte(err.Error()), codec)
		_ = str.Close()
		return
	}
	tcp, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_ = WriteFrameCodec(str, frameConnectErr, []byte(err.Error()), codec)
		_ = str.Close()
		return
	}
	if err := WriteFrameCodec(str, frameConnectOK, nil, codec); err != nil {
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
				if werr := WriteFrameCodec(str, frameData, buf[:n], codec); werr != nil {
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
		fr, err := ReadFrameCodec(str, codec)
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
func (s *Server) handleRegister(st *connState, str *quic.Stream, fr Frame, codec PayloadCodec) {
	sid, target, err := decodeUDPRegistration(fr.Payload)
	if err != nil {
		_ = WriteFrameCodec(str, frameRegisterErr, []byte(err.Error()), codec)
		_ = str.Close()
		return
	}
	udp, err := net.DialTimeout("udp", target, 5*time.Second)
	if err != nil {
		_ = WriteFrameCodec(str, frameRegisterErr, []byte(err.Error()), codec)
		_ = str.Close()
		return
	}
	sess := &udpSession{sid: sid, conn: udp}
	if old := st.putSession(sess); old != nil {
		_ = old.conn.Close()
	}
	go s.udpPump(st, sess)
	if err := WriteFrameCodec(str, frameRegisterOK, nil, codec); err != nil {
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
			// Datagram payloads are sealed like frame payloads; the
			// 16-byte session ID routing header stays in the clear
			// (it is the routing key, not content). A missing codec
			// ends the pump rather than sending plaintext.
			codec := st.sessionCodec()
			if codec == nil {
				return
			}
			sealed, serr := codec.Seal(buf[:n])
			if serr != nil {
				return
			}
			if serr := st.qconn.SendDatagram(encodeDatagram(sess.sid, sealed)); serr != nil {
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
		if err != nil || !st.isAuthed() || st.isDowngraded() {
			s.dropped.Add(1)
			continue
		}
		sess := st.getSession(sid)
		if sess == nil {
			s.dropped.Add(1)
			continue
		}
		codec := st.sessionCodec()
		if codec == nil {
			s.dropped.Add(1)
			continue
		}
		// An AEAD failure here is a drop, never a plaintext forward
		// and never a route to another session.
		opened, err := codec.Open(payload)
		if err != nil {
			s.dropped.Add(1)
			continue
		}
		if _, err := sess.conn.Write(opened); err != nil {
			s.dropped.Add(1)
		}
	}
}
