// Package realquic — Q4 split implementation (P2 step 2, formal port of
// the P2 step 1 experiment in spikes/p2-q4-split).
//
// Design reference: REALQUIC-DESIGN.md Q4 (two independent QUIC
// connections, association token inside the encrypted stream only,
// staggered downstream dial, server-issued reuse caps) and Q6 (the
// stagger interval and the reuse caps are server-issued profile values,
// carried by the P1 profile mechanism; see profile.go).
//
// Mechanism, in one paragraph: the UP connection is an ordinary
// connection (Dial + H3 AUTH, session keys installed). The DOWN
// connection is a second, fully independent QUIC connection that also
// AUTHs normally (its own fresh token, its own session keys); its first
// custom stream then carries a BIND frame whose payload is
// [upSessionID(16)][upSealedNonce], where upSealedNonce is a fresh
// random nonce sealed under the UP session codec. The server looks the
// session up by ID in its server-level session table, opens the nonce
// with that session's server codec, and rejects replays via a per-session
// nonce cache. Nothing about the binding ever appears outside QUIC
// encryption: no URL path/query, no SNI, no plaintext extension — the
// BIND stream is opened only after both handshakes complete. A split
// CONNECT then works as: CONNECT_SPLIT on the up stream (request ID +
// target), DOWN_READY on a down stream (same request ID); the server
// pumps TCP replies as DATA frames onto the down stream, and the client
// reassembles by request ID (one up stream for writes, one down stream
// for reads, paired by that ID).
//
// Formal landing (vs the experiment): the split registry lives on the
// Server struct (splitSessions/splitPendings under splitMu), not in a
// package-level map; split frames are dispatched by the ordinary
// handleCustomStream switch in server.go, so there is no separate
// split serve loop — ServePacketConn/ServePacketConns serve split legs
// exactly like any other connection. The experiment's splitServe*
// helpers do not exist here.
//
// Enforcement decision (client pre-refusal: NO). The reuse caps
// (MaxStreamsPerConn, MaxReusePerConn, MaxConnLifetimeSec) are enforced
// server-side only, from the server's currently issued profile. The
// client does NOT pre-refuse: the counters the caps constrain (live
// concurrency, total served, lifetime since first bind) are server-side
// state that changes asynchronously, so any client-side count would be
// racy — it could refuse a request the server would accept, or allow
// one the server must refuse. Server refusal is authoritative and its
// message names the cap ("stream cap" / "reuse cap" / "lifetime"), which
// SplitConnect surfaces verbatim. Client pre-refusal would save at most
// one round trip and buy a second, inconsistent enforcement point; it
// is an optimisation, not a guarantee, and is deliberately not done.
//
// In-flight gap (honest limit, not hidden): a down-leg loss does NOT
// resume an in-flight response. The in-flight SplitStream's Read fails
// with an error once the down stream dies, and only a fresh
// SplitConnect (which rebuilds the down leg: re-dial + re-AUTH + fresh
// nonce re-bind) recovers — the application layer must retry. There is
// no byte-level resume or replay of the lost response, and no silent
// data substitution: a dead down leg surfaces as a read error, never
// as wrong bytes. "In-flight survives a down-leg loss" would need a
// separate resume/replay mechanism and is out of Q4 scope.
//
// Rate note (P2 step 2 profiling, see the step report): bulk down-leg
// throughput is bounded by the P1 Q3 shaper's steady-slot pacing (the
// profile's steady TimingDist, provisional until the P2 baseline
// measurement sets D2), not by the split mechanism itself; see
// splitSession/steady pacing comments in shaping.go and profile.go.
// The split code adds no pacing of its own.
package realquic

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Split frame types. None is 0x01 (H3 HEADERS), same rule as frame.go.
const (
	frameBindDown     byte = 0x19 // down -> server: bind down leg to an up session
	frameBindOK       byte = 0x1A // server -> down: bind accepted
	frameBindErr      byte = 0x1B // server -> down: bind refused (payload: message)
	frameConnectSplit byte = 0x1C // up -> server: split CONNECT (request ID + target)
	frameDownReady    byte = 0x1D // down -> server: down stream ready for a request ID
	frameDownOK       byte = 0x1E // server -> down: down stream accepted for the request
	frameDownErr      byte = 0x1F // server -> down: down stream refused
)

// splitSession / splitPending are the per-server split state, held on
// the Server struct (splitSessions/splitPendings under splitMu, see
// server.go). A splitSession is keyed by the UP session ID: it is the
// record that binds one up session to its current down leg and counts
// that session's split CONNECTs against the server-issued reuse caps.

type splitSession struct {
	mu         sync.Mutex
	upCodec    SessionCodec // server codec of the up session (key material for bind verification)
	downConn   *quic.Conn
	downCodec  PayloadCodec
	boundAt    time.Time // lifetime clock starts at first bind
	total      int       // CONNECTs served (MaxReusePerConn)
	concurrent int       // CONNECTs currently open (MaxStreamsPerConn)
	usedNonce  map[[32]byte]struct{}
}

type splitPending struct {
	ready   chan *splitDownStream
	created time.Time
}

type splitDownStream struct {
	str   *quic.Stream
	codec PayloadCodec
}

// handleSplitBind verifies a down-leg bind: payload is
// [upSessionID(16)][nonce sealed under the up session codec]. The
// session table is server-level, so the lookup does not depend on which
// connection the up session lives on. A replayed nonce, an unknown
// session ID, or an AEAD failure all fail identically with BindErr.
func (s *Server) handleSplitBind(st *connState, str *quic.Stream, fr Frame, downCodec PayloadCodec) {
	fail := func(msg string) {
		_ = WriteFrameCodec(str, frameBindErr, []byte(msg), downCodec)
		_ = str.Close()
	}
	if len(fr.Payload) < 16 {
		fail("short bind payload")
		return
	}
	var sid [16]byte
	copy(sid[:], fr.Payload[:16])
	sealed := fr.Payload[16:]
	s.sessions.mu.Lock()
	rec := s.sessions.byID[sid]
	s.sessions.mu.Unlock()
	if rec == nil {
		fail("unknown session")
		return
	}
	upCodec := rec.serverCodec()
	nonce, err := upCodec.Open(sealed)
	if err != nil || len(nonce) != 32 {
		fail("bind proof rejected")
		return
	}
	var nonce32 [32]byte
	copy(nonce32[:], nonce)
	s.splitMu.Lock()
	sess, ok := s.splitSessions[sid]
	if !ok {
		sess = &splitSession{upCodec: upCodec, usedNonce: map[[32]byte]struct{}{}}
		s.splitSessions[sid] = sess
	}
	s.splitMu.Unlock()
	sess.mu.Lock()
	if _, dup := sess.usedNonce[nonce32]; dup {
		sess.mu.Unlock()
		fail("bind proof rejected")
		return
	}
	sess.usedNonce[nonce32] = struct{}{}
	// Rebind replaces the previous down leg (down-leg rebuild path):
	// a fresh bind after a down-leg loss takes over for new requests.
	// In-flight pumps on the old down stream fail on write and exit.
	if sess.boundAt.IsZero() {
		sess.boundAt = time.Now()
	}
	sess.downConn = st.qconn
	sess.downCodec = downCodec
	sess.mu.Unlock()
	if err := WriteFrameCodec(str, frameBindOK, nil, downCodec); err != nil {
		return
	}
	_ = str.Close()
}

// splitSessionIDForConn finds the session ID whose server codec matches
// this connection's codec. SessionCodec is two [32]byte arrays, hence
// comparable; the lookup is over the lab-size session table.
func (s *Server) splitSessionIDForConn(codec PayloadCodec) ([16]byte, bool) {
	sc, ok := codec.(SessionCodec)
	if !ok {
		return [16]byte{}, false
	}
	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()
	for id, rec := range s.sessions.byID {
		if rec.serverCodec() == sc {
			return id, true
		}
	}
	return [16]byte{}, false
}

// handleSplitConnect serves a split CONNECT on the up leg: it dials the
// target, enforces the server-issued reuse caps, answers CONNECT_OK on
// the up stream, then waits for the matching DOWN_READY before pumping
// TCP replies onto the down stream. Up-stream DATA frames are pumped
// into the TCP socket, unchanged from the baseline direction.
func (s *Server) handleSplitConnect(st *connState, str *quic.Stream, fr Frame, upCodec PayloadCodec) {
	fail := func(msg string) {
		_ = WriteFrameCodec(str, frameConnectErr, []byte(msg), upCodec)
		_ = str.Close()
	}
	if len(fr.Payload) < 17 {
		fail("short connect-split payload")
		return
	}
	var reqID [16]byte
	copy(reqID[:], fr.Payload[:16])
	target, err := decodeTarget(fr.Payload[16:])
	if err != nil {
		fail(err.Error())
		return
	}
	sid, ok := s.splitSessionIDForConn(upCodec)
	if !ok {
		fail("no session for connection")
		return
	}
	prof := s.IssuedProfile()
	s.splitMu.Lock()
	sess, ok := s.splitSessions[sid]
	if !ok {
		// Defensive: a CONNECT_SPLIT that arrives before its BIND
		// still gets a session record, so cap counting never runs on
		// a nil session; the lifetime clock then starts here rather
		// than at first bind (the normal path binds first).
		sess = &splitSession{upCodec: upCodec.(SessionCodec), usedNonce: map[[32]byte]struct{}{}, boundAt: time.Now()}
		s.splitSessions[sid] = sess
	}
	s.splitMu.Unlock()
	sess.mu.Lock()
	if prof.MaxConnLifetimeSec > 0 && !sess.boundAt.IsZero() &&
		time.Since(sess.boundAt) > time.Duration(prof.MaxConnLifetimeSec)*time.Second {
		sess.mu.Unlock()
		fail("split session lifetime exceeded")
		return
	}
	if prof.MaxReusePerConn > 0 && sess.total >= prof.MaxReusePerConn {
		sess.mu.Unlock()
		fail("split reuse cap exceeded")
		return
	}
	if prof.MaxStreamsPerConn > 0 && sess.concurrent >= prof.MaxStreamsPerConn {
		sess.mu.Unlock()
		fail("split stream cap exceeded")
		return
	}
	sess.total++
	sess.concurrent++
	sess.mu.Unlock()
	release := func() {
		sess.mu.Lock()
		sess.concurrent--
		sess.mu.Unlock()
	}
	tcp, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		release()
		fail(err.Error())
		return
	}
	// Register the pending request BEFORE answering CONNECT_OK: the
	// client sends DOWN_READY as soon as it reads CONNECT_OK, and the
	// down handler runs on a different goroutine, so registering after
	// the write loses the race under load ("no pending request").
	// The deferred delete below cleans up if the OK write fails.
	pend := &splitPending{ready: make(chan *splitDownStream, 1), created: time.Now()}
	s.splitMu.Lock()
	s.splitPendings[reqID] = pend
	s.splitMu.Unlock()
	defer func() {
		s.splitMu.Lock()
		delete(s.splitPendings, reqID)
		s.splitMu.Unlock()
	}()
	if err := WriteFrameCodec(str, frameConnectOK, nil, upCodec); err != nil {
		release()
		_ = tcp.Close()
		return
	}
	// Up -> TCP pump (this goroutine's loop below is the same pump;
	// the TCP -> down pump runs concurrently once the down stream lands).
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case ds := <-pend.ready:
			buf := make([]byte, 16*1024)
			for {
				n, err := tcp.Read(buf)
				if n > 0 {
					if werr := WriteFrameCodec(ds.str, frameData, buf[:n], ds.codec); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		case <-time.After(10 * time.Second):
			return
		}
	}()
	for {
		fr, err := ReadFrameCodec(str, upCodec)
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
	release()
	_ = tcp.Close()
	_ = str.Close()
}

// handleSplitDownReady pairs a down stream with a pending split CONNECT
// by request ID. The pairing key travels only inside QUIC encryption.
func (s *Server) handleSplitDownReady(st *connState, str *quic.Stream, fr Frame, downCodec PayloadCodec) {
	fail := func(msg string) {
		_ = WriteFrameCodec(str, frameDownErr, []byte(msg), downCodec)
		_ = str.Close()
	}
	if len(fr.Payload) != 16 {
		fail("short down-ready payload")
		return
	}
	var reqID [16]byte
	copy(reqID[:], fr.Payload)
	s.splitMu.Lock()
	pend, ok := s.splitPendings[reqID]
	s.splitMu.Unlock()
	if !ok {
		fail("no pending request")
		return
	}
	select {
	case pend.ready <- &splitDownStream{str: str, codec: downCodec}:
		_ = WriteFrameCodec(str, frameDownOK, nil, downCodec)
		// The stream stays open: the TCP -> down pump owns it now.
		// This handler must not close it; it returns and the pump's
		// write failure (client close / conn loss) ends the pump.
	default:
		fail("request already paired")
	}
}

// --- Client side ---

// SplitClient is one Q4 split session: an authed up Client plus a
// lazily dialled, bound down Client. dialDown is supplied by the caller
// (tests: a fresh mem pair per down leg, or a fresh UDP socket to the
// server in standard form). The stagger timer is armed when the
// SplitClient is built (i.e. right after up AUTH): the down dial waits
// for the sampled profile delay to elapse, so a demand arriving after
// the timer fires dials immediately, and a demand arriving before it
// waits out the remainder. That is the design's "first of demand or
// random delay" rule, with demand expressed as the SplitConnect call.
type SplitClient struct {
	up       *Client
	dialDown func(ctx context.Context) (*Client, error)
	// Stage B (B4): one PMTUSet for this split session. Leg "up" and
	// leg "down" each get their own tracker per address family (see
	// split_pmtu.go); observing or resetting one leg never moves the
	// other. The set is created at construction, so the report port
	// exists before any leg is dialled.
	pmtu *PMTUSet

	mu           sync.Mutex
	down         *Client
	downDead     bool
	staggerDelay time.Duration
	staggerArmed time.Time
	// WaitedMs records, per SplitConnect call, how long the call waited
	// for the stagger timer (0 when the timer had already fired).
	WaitedMs []float64
}

// NewSplitClient builds a split session over an already-authed up
// Client. The stagger delay is sampled once, uniformly, from the up
// connection's server-issued profile interval; a [0,0] interval means
// no stagger (immediate down dial on demand).
func NewSplitClient(up *Client, dialDown func(ctx context.Context) (*Client, error)) *SplitClient {
	p := up.ActiveProfile()
	delay := time.Duration(0)
	if p.StaggerDelayMaxMs > 0 {
		span := p.StaggerDelayMaxMs - p.StaggerDelayMinMs
		if span < 0 {
			span = 0
		}
		delay = time.Duration(p.StaggerDelayMinMs+sampleUniform(span)) * time.Millisecond
	}
	return &SplitClient{up: up, dialDown: dialDown, staggerDelay: delay, staggerArmed: time.Now(), pmtu: NewPMTUSet(0, 0)}
}

func sampleUniform(span float64) float64 {
	if span <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1<<53))
	if err != nil {
		return span / 2
	}
	return float64(n.Int64()) / float64(1<<53) * span
}

// StaggerDelay reports the sampled stagger delay for this session.
func (sc *SplitClient) StaggerDelay() time.Duration { return sc.staggerDelay }

// UpProfile reports the server-issued profile the up connection adopted.
func (sc *SplitClient) UpProfile() Profile { return sc.up.ActiveProfile() }

// ensureDown dials (if needed), AUTHs, and binds a down leg. The bind
// proof is a fresh nonce sealed under the UP session codec; the up
// session ID travels alongside it, both strictly inside QUIC encryption
// (the down stream is opened after the down handshake completes).
func (sc *SplitClient) ensureDown(ctx context.Context) error {
	sc.mu.Lock()
	if sc.down != nil && !sc.downDead {
		sc.mu.Unlock()
		return nil
	}
	sc.mu.Unlock()
	// Stagger: wait out the sampled delay, if it has not elapsed.
	if wait := time.Until(sc.staggerArmed.Add(sc.staggerDelay)); wait > 0 {
		start := time.Now()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
		sc.mu.Lock()
		sc.WaitedMs = append(sc.WaitedMs, time.Since(start).Seconds()*1000)
		sc.mu.Unlock()
	} else {
		sc.mu.Lock()
		sc.WaitedMs = append(sc.WaitedMs, 0)
		sc.mu.Unlock()
	}
	down, err := sc.dialDown(ctx)
	if err != nil {
		return err
	}
	if _, _, _, err := down.Auth(ctx); err != nil {
		_ = down.Close()
		return fmt.Errorf("realquic: down AUTH: %w", err)
	}
	snap := sc.up.sessionSnapshot()
	if snap == nil || !snap.hasResume {
		_ = down.Close()
		return errors.New("realquic: up session has no resume identity for bind")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		_ = down.Close()
		return err
	}
	sealed, err := snap.clientCodec().Seal(nonce[:])
	if err != nil {
		_ = down.Close()
		return err
	}
	payload := make([]byte, 16+len(sealed))
	copy(payload[:16], snap.id[:])
	copy(payload[16:], sealed)
	str, err := down.qconn.OpenStreamSync(ctx)
	if err != nil {
		_ = down.Close()
		return err
	}
	downCodec := down.codecOrIdentity()
	if err := WriteFrameCodec(str, frameBindDown, payload, downCodec); err != nil {
		_ = str.Close()
		_ = down.Close()
		return err
	}
	fr, err := ReadFrameCodec(str, downCodec)
	if err != nil {
		_ = str.Close()
		_ = down.Close()
		return err
	}
	_ = str.Close()
	if fr.Type != frameBindOK {
		_ = down.Close()
		return fmt.Errorf("realquic: bind refused: %s", string(fr.Payload))
	}
	// Stage B (B4): a (re)bound down leg is a new PMTU generation
	// (§3.2 reset event: new leg). Both families reset — the leg's
	// family is not observable from the mem transport, and resetting
	// the unused family is inert — so a stale validated value from
	// a dead leg can never carry onto the rebuilt leg. The up leg
	// is untouched: its generation survives a down-leg rebuild.
	sc.pmtu.ResetLeg("down", false)
	sc.pmtu.ResetLeg("down", true)
	sc.mu.Lock()
	sc.down = down
	sc.downDead = false
	sc.mu.Unlock()
	return nil
}

// MarkDownDead forces the next SplitConnect to rebuild the down leg
// (re-dial + re-bind with a fresh nonce). It does NOT resume any
// in-flight response on the old leg: reads on an in-flight SplitStream
// fail once the leg dies (see the package header), and recovery is a
// fresh SplitConnect from the application layer.
func (sc *SplitClient) MarkDownDead() {
	sc.mu.Lock()
	if sc.down != nil {
		_ = sc.down.Close()
	}
	sc.down = nil
	sc.downDead = true
	sc.mu.Unlock()
}

// SplitConnect opens a split CONNECT: CONNECT_SPLIT on the up leg, then
// DOWN_READY on the down leg. The returned stream writes to the up
// stream and reads from the down stream; the pairing is the request ID.
func (sc *SplitClient) SplitConnect(ctx context.Context, target string) (*SplitStream, error) {
	if err := sc.ensureDown(ctx); err != nil {
		return nil, err
	}
	sc.mu.Lock()
	down := sc.down
	sc.mu.Unlock()
	var reqID [16]byte
	if _, err := rand.Read(reqID[:]); err != nil {
		return nil, err
	}
	payload, err := encodeTarget(target)
	if err != nil {
		return nil, err
	}
	upPayload := make([]byte, 16+len(payload))
	copy(upPayload[:16], reqID[:])
	copy(upPayload[16:], payload)
	upStr, err := sc.up.qconn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	upCodec := sc.up.codecOrIdentity()
	applyReadDeadline(upStr, ctx)
	if err := WriteFrameCodec(upStr, frameConnectSplit, upPayload, upCodec); err != nil {
		_ = upStr.Close()
		return nil, err
	}
	for {
		fr, err := ReadFrameCodec(upStr, upCodec)
		if err != nil {
			_ = upStr.Close()
			return nil, err
		}
		switch fr.Type {
		case frameConnectOK:
			clearReadDeadline(upStr)
			goto upOK
		case frameConnectErr:
			_ = upStr.Close()
			return nil, fmt.Errorf("realquic: split connect refused: %s", string(fr.Payload))
		default:
			_ = upStr.Close()
			return nil, errors.New("realquic: unexpected frame on split CONNECT stream")
		}
	}
upOK:
	downCodec := down.codecOrIdentity()
	downStr, err := down.qconn.OpenStreamSync(ctx)
	if err != nil {
		_ = upStr.Close()
		return nil, err
	}
	applyReadDeadline(downStr, ctx)
	if err := WriteFrameCodec(downStr, frameDownReady, reqID[:], downCodec); err != nil {
		_ = downStr.Close()
		_ = upStr.Close()
		return nil, err
	}
	fr, err := ReadFrameCodec(downStr, downCodec)
	if err != nil {
		_ = downStr.Close()
		_ = upStr.Close()
		return nil, err
	}
	if fr.Type != frameDownOK {
		_ = downStr.Close()
		_ = upStr.Close()
		return nil, fmt.Errorf("realquic: down ready refused: %s", string(fr.Payload))
	}
	clearReadDeadline(downStr)
	return &SplitStream{up: upStr, upCodec: upCodec, down: downStr, downCodec: downCodec}, nil
}

// SplitStream is one split CONNECT: writes go up, reads come down.
type SplitStream struct {
	mu        sync.Mutex
	up        *quic.Stream
	upCodec   PayloadCodec
	down      *quic.Stream
	downCodec PayloadCodec
	buf       []byte
}

// Write sends p as DATA frames on the UP stream, chunked like ConnectStream.
func (ss *SplitStream) Write(p []byte) (int, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	total := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > maxDataChunk {
			n = maxDataChunk
		}
		if err := WriteFrameCodec(ss.up, frameData, p[:n], ss.upCodec); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return total, nil
}

// Read returns buffered DATA bytes from the DOWN stream, or the next
// DATA frame's payload. A non-DATA frame or stream end terminates reads.
func (ss *SplitStream) Read(p []byte) (int, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for len(ss.buf) == 0 {
		fr, err := ReadFrameCodec(ss.down, ss.downCodec)
		if err != nil {
			return 0, err
		}
		if fr.Type != frameData {
			return 0, io.EOF
		}
		ss.buf = fr.Payload
	}
	n := copy(p, ss.buf)
	ss.buf = ss.buf[n:]
	return n, nil
}

// Close closes both legs' streams.
func (ss *SplitStream) Close() error {
	_ = ss.up.Close()
	return ss.down.Close()
}
