// Command labclient is the pilot-only load driver for Stage 3 pilot
// Tier 1. In Mist mode it dials the lab server
// (DialPacketConnWithPMTUTrace, tee-fed PMTU tracker + optional qlog),
// runs AUTH, then drives the synthetic load over Connect relay streams to
// the lab object server, issuing plain HTTP/1.1 GETs and reading to
// Content-Length. In --direct mode it fetches the same object list,
// in the same order, with the same concurrency, straight over
// net/http. Class A waits out its 35-second window after fetching;
// class B fetches its 12 fixed objects back-to-back with no idle.
//
// The pilot key comes only from the MIST_KEY environment variable
// (hex of 32 bytes). Session summaries print byte counts, timestamps,
// profile version and profile-encoding hash prefix only — never key
// material or profile parameter values.
//
// Stage C wiring (W-1), Mist arm only: -qlog writes this session's
// full client qlog JSON-SEQ file, -events-out writes the session's
// up-direction shaping events as JSON at session end, and the summary
// JSON gains udp_local (the server-visible address for this session,
// for joining against the server's per-address events) plus the
// session PMTU report (pmtu_* fields, from a per-session tracker fed
// by the same tee trace as the qlog file). The direct arm produces
// none of these: its summary omits them rather than fabricating
// values.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/qlogwriter"
	"mist/realquic"
)

// buildCommit is injected at build time with -ldflags -X main.buildCommit.
var buildCommit = "dev"

// aWindow is the class-A session window (PLAN §4.1).
const aWindow = 35 * time.Second

// bObjects is the frozen class-B object sequence (PLAN §4.2/D1):
// 12 x 256KiB = 3,145,728 bytes = 3.0MB per session.
var bObjects = []int{
	262144, 262144, 262144, 262144, 262144, 262144,
	262144, 262144, 262144, 262144, 262144, 262144,
}

func decodeKey(env string) ([]byte, error) {
	if env == "" {
		return nil, fmt.Errorf("MIST_KEY is not set")
	}
	key, err := hex.DecodeString(env)
	if err != nil {
		return nil, fmt.Errorf("MIST_KEY is not hex: %v", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("MIST_KEY decodes to %d bytes, want 32", len(key))
	}
	return key, nil
}

func profileHash12(p realquic.Profile) string {
	enc, err := realquic.EncodeProfile(p)
	if err != nil {
		return "encode-error"
	}
	sum := sha256.Sum256(enc)
	return hex.EncodeToString(sum[:])[:12]
}

// fetcher drives one object fetch against the lab object server.
type fetcher interface {
	fetchPage(ctx context.Context, path string) ([]int, error)
	fetchObject(ctx context.Context, size int) (up, down int64, err error)
}

// ---- Mist fetcher: Connect relay streams over one QUIC connection ----

type mistFetcher struct {
	cli    *realquic.Client
	target string // labobject host:port
	// firstByte, when non-nil, collects one first-body-byte latency
	// sample per object fetch (V7-A F arm). It is record-only: it
	// never influences fetching, and a fetch that delivers no body
	// byte records nothing (no sample is ever fabricated).
	firstByte *firstByteLog
}

// firstByteRecord is one object's first-body-byte latency sample for
// the V7-A F arm: time from the object request write to the first body
// byte delivered to the application (headers do not count, matching
// the stall detector's body-only progress rule).
type firstByteRecord struct {
	Size        int     `json:"size"`
	FirstByteMs float64 `json:"first_byte_ms"`
}

// firstByteLog collects first-byte samples across a session. All
// methods are safe for concurrent use by class-A fetch workers.
type firstByteLog struct {
	mu      sync.Mutex
	records []firstByteRecord
}

func (l *firstByteLog) record(size int, d time.Duration) {
	l.mu.Lock()
	l.records = append(l.records, firstByteRecord{Size: size, FirstByteMs: float64(d) / float64(time.Millisecond)})
	l.mu.Unlock()
}

func (l *firstByteLog) snapshot() []firstByteRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]firstByteRecord{}, l.records...)
}

// firstByteHook returns nil when recording is off, else a hook that
// records this object's first-byte latency on its first body byte.
func (m *mistFetcher) firstByteHook(size int) func(time.Duration) {
	if m.firstByte == nil {
		return nil
	}
	return func(d time.Duration) { m.firstByte.record(size, d) }
}

// fetchOverRelay performs one HTTP/1.1 GET over a fresh Connect stream.
// When wantBody is false the body is counted and discarded. report, when
// non-nil, is called with each body chunk size as it arrives (B10 option 1
// stall detection); nil reporting keeps the call identical to before.
// firstByte, when non-nil, is called once with the latency from the
// request write to the first body byte delivered to the application
// (V7-A F arm); nil keeps the call identical to before.
func (m *mistFetcher) fetchOverRelay(ctx context.Context, path string, wantBody bool, report func(int64), firstByte func(time.Duration)) (up, down int64, body []byte, err error) {
	cs, err := m.cli.Connect(ctx, m.target)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("connect: %w", err)
	}
	defer cs.Close()
	req := "GET " + path + " HTTP/1.1\r\nHost: " + m.target + "\r\nConnection: close\r\n\r\n"
	reqAt := time.Now()
	n, err := cs.Write([]byte(req))
	if err != nil {
		return 0, 0, nil, fmt.Errorf("write request: %w", err)
	}
	up = int64(n)
	br := bufio.NewReader(cs)
	status, err := br.ReadString('\n')
	if err != nil {
		return up, 0, nil, fmt.Errorf("read status: %w", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200 ") {
		return up, 0, nil, fmt.Errorf("unexpected status %q", strings.TrimSpace(status))
	}
	var cl int64 = -1
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return up, 0, nil, fmt.Errorf("read header: %w", err)
		}
		if line == "\r\n" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			cl, err = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return up, 0, nil, fmt.Errorf("bad content-length: %w", err)
			}
		}
	}
	if cl < 0 {
		return up, 0, nil, fmt.Errorf("missing content-length")
	}
	if wantBody {
		body, err = io.ReadAll(io.LimitReader(br, cl))
		if err != nil {
			return up, 0, nil, fmt.Errorf("read body: %w", err)
		}
		if int64(len(body)) != cl {
			return up, 0, nil, fmt.Errorf("short body: got %d want %d", len(body), cl)
		}
		return up, cl, body, nil
	}
	bodyReader := io.Reader(br)
	if report != nil || firstByte != nil {
		var first func()
		if firstByte != nil {
			first = func() { firstByte(time.Since(reqAt)) }
		}
		bodyReader = &progressReader{r: br, report: report, first: first}
	}
	down, err = io.CopyN(io.Discard, bodyReader, cl)
	if err != nil {
		return up, down, nil, fmt.Errorf("read body: %w", err)
	}
	return up, down, nil, nil
}

func (m *mistFetcher) fetchPage(ctx context.Context, path string) ([]int, error) {
	_, _, body, err := m.fetchOverRelay(ctx, path, true, nil, nil)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Objects []int `json:"objects"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse page: %w", err)
	}
	return doc.Objects, nil
}

// fetchPageProgress is fetchPage with a single progress report on success
// for B10 option 1 stall detection. The page body is small, so one report
// of its full length on success is the "exactly once" signal; a stalled
// or failed page fetch reports nothing, which is itself the stall signal.
// A page stall refetches the whole page on a new generation: in-flight
// responses are NOT recovered (Q4 known gap), and this must not be
// described as byte-range resume.
func (m *mistFetcher) fetchPageProgress(ctx context.Context, path string, report func(int64)) ([]int, error) {
	_, _, body, err := m.fetchOverRelay(ctx, path, true, nil, nil)
	if err != nil {
		return nil, err
	}
	if report != nil {
		report(int64(len(body)))
	}
	var doc struct {
		Objects []int `json:"objects"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse page: %w", err)
	}
	return doc.Objects, nil
}

func (m *mistFetcher) fetchObject(ctx context.Context, size int) (int64, int64, error) {
	up, down, _, err := m.fetchOverRelay(ctx, "/obj/"+strconv.Itoa(size), false, nil, m.firstByteHook(size))
	if err != nil {
		return up, down, err
	}
	if down != int64(size) {
		return up, down, fmt.Errorf("object size mismatch: got %d want %d", down, size)
	}
	return up, down, nil
}

// fetchObjectProgress is fetchObject with per-chunk delivery reporting
// for B10 option 1 stall detection. The report fires on body bytes only
// (headers do not count as progress: a stalled stream delivers no body).
func (m *mistFetcher) fetchObjectProgress(ctx context.Context, size int, report func(int64)) (int64, int64, error) {
	up, down, _, err := m.fetchOverRelay(ctx, "/obj/"+strconv.Itoa(size), false, report, m.firstByteHook(size))
	if err != nil {
		return up, down, err
	}
	if down != int64(size) {
		return up, down, fmt.Errorf("object size mismatch: got %d want %d", down, size)
	}
	return up, down, nil
}

// progressReader reports each chunk size passing through it. It counts
// bytes the bufio reader yields, including bytes already buffered, so
// every body byte is reported exactly once. first, when non-nil, fires
// exactly once on the first chunk with n > 0 (V7-A first-byte latency);
// a read sequence that never delivers a byte never fires it.
type progressReader struct {
	r      io.Reader
	report func(int64)
	first  func()
	fired  bool
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		if p.report != nil {
			p.report(int64(n))
		}
		if !p.fired && p.first != nil {
			p.fired = true
			p.first()
		}
	}
	return n, err
}

// ---- Direct fetcher: plain net/http to the lab object server ----

type countConn struct {
	net.Conn
	written *int64
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	*c.written += int64(n)
	return n, err
}

type directFetcher struct {
	base string // e.g. http://10.200.1.2:18080
}

func (d *directFetcher) get(ctx context.Context, path string) (up int64, resp *http.Response, err error) {
	var written int64
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var dnet net.Dialer
			c, err := dnet.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &countConn{Conn: c, written: &written}, nil
		},
	}
	cli := &http.Client{Transport: tr, Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err = cli.Do(req)
	if err != nil {
		return 0, nil, err
	}
	return written, resp, nil
}

func (d *directFetcher) fetchPage(ctx context.Context, path string) ([]int, error) {
	_, resp, err := d.get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("page status %d", resp.StatusCode)
	}
	var doc struct {
		Objects []int `json:"objects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse page: %w", err)
	}
	return doc.Objects, nil
}

func (d *directFetcher) fetchObject(ctx context.Context, size int) (int64, int64, error) {
	up, resp, err := d.get(ctx, "/obj/"+strconv.Itoa(size))
	if err != nil {
		return up, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return up, 0, fmt.Errorf("object status %d", resp.StatusCode)
	}
	down, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return up, down, fmt.Errorf("read body: %w", err)
	}
	if down != int64(size) {
		return up, down, fmt.Errorf("object size mismatch: got %d want %d", down, size)
	}
	return up, down, nil
}

// ---- Session drivers ----

type sessionResult struct {
	SessionID      string    `json:"session_id"`
	Class          string    `json:"class"`
	Arm            string    `json:"arm"`
	BuildCommit    string    `json:"build_commit"`
	ProfileVersion uint64    `json:"profile_version"`
	ProfileHash    string    `json:"profile_hash"`
	UpBytes        int64     `json:"up_bytes"`
	DownBytes      int64     `json:"down_bytes"`
	Objects        int       `json:"objects"`
	StartedAt      time.Time `json:"started_at"`
	EndedAt        time.Time `json:"ended_at"`
	Failure        string    `json:"failure,omitempty"`
	// W-1 (Mist arm only; omitted on the direct arm): the
	// server-visible address for joining against the server's
	// per-address events, and the session PMTU report from the
	// tee-fed tracker.
	UDPLocal            string `json:"udp_local,omitempty"`
	PMTUTargetIP        int    `json:"pmtu_target_ip,omitempty"`
	PMTUStackEnforcedIP int    `json:"pmtu_stack_enforced_target_ip,omitempty"`
	PMTUValidatedIP     int    `json:"pmtu_validated_ip,omitempty"`
	PMTUPeerCapIP       int    `json:"pmtu_peer_cap_ip,omitempty"`
	PMTUPeerCapKnown    bool   `json:"pmtu_peer_cap_known,omitempty"`
	PMTUDone            bool   `json:"pmtu_done,omitempty"`
	// B10 option 1 (stall-recovery runs only; omitted otherwise):
	// how many generation reconnects happened, and whether any stall
	// was detected at all.
	StallReconnects int  `json:"stall_reconnects,omitempty"`
	StallDetected   bool `json:"stall_detected,omitempty"`
	// B10 option 1, class A only (omitted otherwise): how many object
	// fetches restarted because of a stall (counted per attempt, not
	// per distinct object: one object bumped twice counts twice), and
	// how many generations the run used (1 + successful reconnects,
	// set only when a stall was detected).
	StallObjectsRetried int `json:"stall_objects_retried,omitempty"`
	StallGenerations    int `json:"stall_generations,omitempty"`
	// T-2 (page-period separate timeout, class A only; omitted
	// otherwise): how many generation reconnects were triggered while
	// the detector was in page mode (a page-mode bump refetches the
	// whole page and never counts in stall_objects_retried). Object
	// mode bumps = stall_reconnects - stall_page_bumps. Only
	// successful (dialed) bumps count, same as stall_reconnects.
	StallPageBumps int `json:"stall_page_bumps,omitempty"`
}

// runClassA fetches the page list concurrently (<=4 in flight) and then
// waits out the window from session start.
func runClassA(ctx context.Context, f fetcher, pagePath string, window time.Duration, start time.Time) (up, down int64, n int, err error) {
	objects, err := f.fetchPage(ctx, pagePath)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("fetch page: %w", err)
	}
	sem := make(chan struct{}, 4)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	for _, size := range objects {
		wg.Add(1)
		go func(size int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			uctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			u, d, ferr := f.fetchObject(uctx, size)
			mu.Lock()
			up += u
			down += d
			n++
			if ferr != nil && firstErr == nil {
				firstErr = ferr
			}
			mu.Unlock()
		}(size)
	}
	wg.Wait()
	if firstErr != nil {
		return up, down, n, firstErr
	}
	if remain := time.Until(start.Add(window)); remain > 0 {
		time.Sleep(remain)
	}
	return up, down, n, nil
}

// runClassB fetches the 12 fixed objects sequentially, no idle between.
func runClassB(ctx context.Context, f fetcher) (up, down int64, n int, err error) {
	for _, size := range bObjects {
		uctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		u, d, ferr := f.fetchObject(uctx, size)
		cancel()
		up += u
		down += d
		n++
		if ferr != nil {
			return up, down, n, ferr
		}
	}
	return up, down, n, nil
}

// ---- B10 option 1: stall-detecting class-B driver (Mist arm only) ----
//
// A blackholed generation delivers zero body bytes while its connection
// context stays alive, so the plain class-B driver only dies at the 60s
// per-object timeout. This driver watches body-byte progress with a
// realquic.StallDetector: on zero progress for stallTimeout it closes
// the old generation (closing the connection is also what unblocks the
// in-flight read promptly), backs off, dials a fresh generation,
// re-AUTHs, and retries the same object index. Completed objects are
// never refetched; an in-flight object restarts from byte 0 — in-flight
// responses are NOT recovered (Q4 known gap), and this driver must not
// be described as byte-range resume.
//
// Scope discipline: this driver is flag-gated (-stall-recover) and
// class-B-only. Class A (4 concurrent fetches) needs connection-level
// progress aggregation, which is follow-up work, not smuggled in here.
// The dial block below deliberately mirrors main()'s Mist dial block
// instead of refactoring it: the default path is frozen by Stage C and
// must not change because of this driver. The summary reports the final
// generation's profile/PMTU state; per-generation qlog/events files get
// a .gen<N> suffix (generation 0 keeps the exact requested path).

type mistSession struct {
	pc        net.PacketConn
	cli       *realquic.Client
	tracker   *realquic.PMTUTracker
	fetcher   *mistFetcher
	udpLocal  string
	eventsOut string
}

func (s *mistSession) close() {
	if s == nil {
		return
	}
	if s.cli != nil {
		_ = s.cli.Close()
		if s.eventsOut != "" {
			data, merr := json.Marshal(s.cli.ShapingEvents())
			if merr != nil {
				log.Printf("labclient: marshal events: %v", merr)
			} else if werr := os.WriteFile(s.eventsOut, data, 0o644); werr != nil {
				log.Printf("labclient: write events-out: %v", werr)
			} else {
				log.Printf("labclient: wrote events-out=%s events=%d", s.eventsOut, len(s.cli.ShapingEvents()))
			}
		}
		s.cli = nil
	}
	if s.pc != nil {
		_ = s.pc.Close()
		s.pc = nil
	}
}

// suffixedPath returns path unchanged for generation 0 and path.gen<N>
// for later generations (empty path stays empty).
func suffixedPath(path string, gen int) string {
	if path == "" || gen == 0 {
		return path
	}
	return path + ".gen" + strconv.Itoa(gen)
}

func dialMistSession(serverAddr, objectAddr string, key []byte, qlogPath, eventsOut string, gen int) (*mistSession, error) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	remote, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("resolve server: %w", err)
	}
	s, err := dialMistSessionOnConn(pc, remote, objectAddr, key, qlogPath, eventsOut, gen)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return s, nil
}

// dialMistSessionOnConn is dialMistSession over an already-open packet
// connection (production passes a UDP socket; tests pass a MemPair end).
// It owns pc on success (closed by mistSession.close) and leaves it open
// on failure for the caller to close.
func dialMistSessionOnConn(pc net.PacketConn, remote net.Addr, objectAddr string, key []byte, qlogPath, eventsOut string, gen int) (*mistSession, error) {
	s := &mistSession{pc: pc, udpLocal: visibleAddr(pc, remote), eventsOut: suffixedPath(eventsOut, gen)}
	ipv6 := false
	if udpRemote, ok := remote.(*net.UDPAddr); ok {
		ipv6 = udpRemote.IP != nil && udpRemote.IP.To4() == nil
	}
	s.tracker = realquic.NewPMTUTracker(ipv6, 0, 0)
	var trace qlogwriter.Trace
	if qp := suffixedPath(qlogPath, gen); qp != "" {
		qf, ferr := os.Create(qp)
		if ferr != nil {
			return nil, fmt.Errorf("create qlog: %w", ferr)
		}
		fileSeq := qlogwriter.NewFileSeq(qf)
		go fileSeq.Run()
		trace = realquic.NewTeeTrace(fileSeq, realquic.NewPMTUQlogTrace(s.tracker))
	} else {
		trace = realquic.NewTeeTrace(nil, realquic.NewPMTUQlogTrace(s.tracker))
	}
	dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cli, err := realquic.DialPacketConnWithPMTUTrace(dctx, pc, remote, key, trace)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	s.cli = cli
	actx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	status, _, _, err := cli.Auth(actx)
	cancel()
	if err != nil {
		_ = cli.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	if status != 200 {
		_ = cli.Close()
		return nil, fmt.Errorf("auth status %d", status)
	}
	s.fetcher = &mistFetcher{cli: cli, target: objectAddr}
	return s, nil
}

// visibleAddr is serverVisibleAddr for real UDP sockets and the raw
// local address otherwise (MemPair ends have no route to probe).
func visibleAddr(pc net.PacketConn, remote net.Addr) string {
	if udpPC, ok := pc.(*net.UDPConn); ok {
		if udpRemote, ok := remote.(*net.UDPAddr); ok {
			return serverVisibleAddr(udpPC, udpRemote)
		}
	}
	return pc.LocalAddr().String()
}

type fetchOutcome struct {
	up, down int64
	err      error
}

type recoverableSummary struct {
	up, down            int64
	n                   int
	stallReconnect      int
	stallDetected       bool
	stallObjectsRetried int
	stallGenerations    int
	stallPageBumps      int
	profileVersion      uint64
	profileHash         string
	udpLocal            string
	tracker             *realquic.PMTUTracker
}

// aObjState is one class-A object's lifecycle inside a recoverable run
// (design §2.5): pending -> in-flight -> done, or -> failed-nonstall
// (terminal). A bump reverts in-flight objects to pending; done and
// failed-nonstall objects never move again.
type aObjState int

const (
	aObjPending aObjState = iota
	aObjInFlight
	aObjDone
	aObjFailed
)

// aObjTable owns the class-A object states and the completed byte counts.
// All methods are safe for concurrent use by the fetch workers.
type aObjTable struct {
	mu       sync.Mutex
	states   []aObjState
	up       int64
	down     int64
	n        int
	firstErr error
}

// newAObjTable builds a table with every object pending.
func newAObjTable(objects []int) *aObjTable {
	return &aObjTable{states: make([]aObjState, len(objects))}
}

// claim takes the next pending object into flight and returns its index,
// or -1 when no pending object remains.
func (t *aObjTable) claim() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, s := range t.states {
		if s == aObjPending {
			t.states[i] = aObjInFlight
			return i
		}
	}
	return -1
}

// complete marks an object done and counts its bytes. Bytes are counted
// only on completion (like runClassBRecoverable): partial bytes from a
// bumped attempt are not counted, so a retried object is counted exactly
// once, at its final completion.
func (t *aObjTable) complete(idx int, up, down int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.states[idx] = aObjDone
	t.up += up
	t.down += down
	t.n++
}

// failNonStall marks an object terminally failed and records the first
// error (runClassA semantics: all objects still run to completion, the
// first error is returned at the end).
func (t *aObjTable) failNonStall(idx int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.states[idx] = aObjFailed
	if t.firstErr == nil {
		t.firstErr = err
	}
}

// bumpRequeue reverts every in-flight object in idxs to pending and
// returns how many were reverted (the stall_objects_retried increment
// for this bump, counted per attempt, not per distinct object).
func (t *aObjTable) bumpRequeue(idxs []int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, idx := range idxs {
		if t.states[idx] == aObjInFlight {
			t.states[idx] = aObjPending
			n++
		}
	}
	return n
}

// resolved reports whether no object is pending or in flight.
func (t *aObjTable) resolved() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.states {
		if s == aObjPending || s == aObjInFlight {
			return false
		}
	}
	return true
}

// snapshot returns the completed totals and first error.
func (t *aObjTable) snapshot() (up, down int64, n int, firstErr error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.up, t.down, t.n, t.firstErr
}

// aOutcome is one worker's report for one claimed object in one
// generation. bumped means the fetch failed while a bump was in progress
// (close-caused error): the object requeues instead of failing.
type aOutcome struct {
	idx    int
	up     int64
	down   int64
	err    error
	bumped bool
}

// pageOutcome is the page-fetch goroutine's report.
type pageOutcome struct {
	objects []int
	err     error
}

// resolvePageTimeout maps the -stall-page-timeout flag to the page
// phase's detector timeout: a positive value is used as-is; zero or
// negative follows -stall-timeout (single-T behavior). Never returns a
// non-positive timeout: a disabled page detector would silently never
// detect page stalls, so misconfiguration fails towards "same as
// object phase" rather than "no page detection".
func resolvePageTimeout(pageTimeout, stallTimeout time.Duration) time.Duration {
	if pageTimeout <= 0 {
		return stallTimeout
	}
	return pageTimeout
}

// runClassARecoverable drives a class-A page (concurrent object fetches,
// <=4 in flight) with connection-level stall detection and generation
// reconnects. It mirrors runClassBRecoverable's generation discipline
// (one StallDetector per generation, close-then-backoff-then-dial, cap
// per session) but aggregates progress across all in-flight streams onto
// a single detector: any stream's body bytes reset the timer, so only a
// connection-wide silence of stallTimeout trips a bump (design §2). The
// default runClassA path is untouched; this driver restates its "fetch
// page, fetch concurrently, wait out the window" skeleton because
// runClassA's fire-and-forget goroutines cannot distinguish
// close-caused errors from real failures or requeue objects.
// Completed objects are never refetched; an in-flight object restarts
// from byte 0 on a new generation — in-flight responses are NOT
// recovered (Q4 known gap), and this driver must not be described as
// byte-range resume.
//
// T-2 (page-period separate timeout): the driver runs each generation
// in one of two modes. A generation that fetches the page starts in
// page mode with timeout pageTimeout (resolved via resolvePageTimeout);
// a generation after an object-mode bump starts directly in object
// mode, because the page list is cached and never refetched. The switch
// point is page success (page body delivered, object list parsed):
// the object phase starts a fresh detector with stallTimeout, so page
// phase idle never carries into object mode (re-arm, not a parameter
// change). Page-mode bumps refetch the whole page, never count in
// stall_objects_retried, but do count in stall_page_bumps and consume
// the session-wide reconnect cap shared with object-mode bumps.
// Bump log lines carry mode=page|object for attribution.
func runClassARecoverable(ctx context.Context, dial func(gen int) (*mistSession, error), pagePath string, window time.Duration, start time.Time, stallTimeout time.Duration, pageTimeout time.Duration, policy realquic.ReconnectPolicy) (sum recoverableSummary, err error) {
	// Generations used is derived at every exit: a run that detected a
	// stall used 1 + successful reconnects generations; a run with no
	// stall leaves the field zero (omitted from the summary JSON).
	defer func() {
		if sum.stallDetected {
			sum.stallGenerations = 1 + sum.stallReconnect
		}
	}()
	// T-2: resolve once; the page phase uses pageT, the object phase
	// always uses stallTimeout (T_A).
	pageT := resolvePageTimeout(pageTimeout, stallTimeout)
	sess, derr := dial(0)
	if derr != nil {
		return sum, derr
	}
	// Closure over the variable, not the first value: reconnects
	// reassign sess, and the final generation must be the one closed.
	defer func() { sess.close() }()
	gen := 0

	// bump backs off, dials the next generation, and accounts a
	// successful reconnect. The caller closes the old generation before
	// calling bump (the monitor already did) and logs the bump line.
	bump := func() error {
		if policy.Exhausted(sum.stallReconnect) {
			return fmt.Errorf("stall: reconnect cap exhausted (reconnects=%d objects_retried=%d)", sum.stallReconnect, sum.stallObjectsRetried)
		}
		delay := policy.Delay(sum.stallReconnect)
		sum.stallDetected = true
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		next, derr := dial(gen + 1)
		if derr != nil {
			return fmt.Errorf("reconnect dial: %w", derr)
		}
		sess = next
		gen++
		sum.stallReconnect++
		return nil
	}

	// --- Page phase: fetch once; a page stall bumps to a new
	// generation and refetches the page (not counted in
	// stall_objects_retried). Once the page succeeds, the object list
	// is cached for the whole run and never refetched.
	var objects []int
	for {
		det := realquic.NewStallDetector(pageT, nil)
		det.Start()
		resCh := make(chan pageOutcome, 1)
		go func(f *mistFetcher, d *realquic.StallDetector) {
			objs, ferr := f.fetchPageProgress(ctx, pagePath, d.Report)
			resCh <- pageOutcome{objects: objs, err: ferr}
		}(sess.fetcher, det)
		var res pageOutcome
		stalled := false
		ticker := time.NewTicker(250 * time.Millisecond)
	pageWait:
		for {
			select {
			case res = <-resCh:
				break pageWait
			case <-ticker.C:
				if det.Stalled() {
					stalled = true
					// Closing the generation unblocks the page
					// fetch promptly (same absolute-deadline
					// reason as runClassBRecoverable).
					sess.close()
					res = <-resCh
					break pageWait
				}
			case <-ctx.Done():
				sess.close()
				res = <-resCh
				break pageWait
			}
		}
		ticker.Stop()
		if res.err == nil {
			objects = res.objects
			break
		}
		if ctx.Err() != nil {
			return sum, ctx.Err()
		}
		if !stalled {
			return sum, fmt.Errorf("fetch page: %w", res.err)
		}
		log.Printf("labclient: stall gen=%d mode=page (idle=%v) on page fetch, reconnect %d after %v; page refetches on new generation",
			gen, det.Idle(), sum.stallReconnect+1, policy.Delay(sum.stallReconnect))
		if berr := bump(); berr != nil {
			return sum, berr
		}
		// Only a dialed bump counts as a page-mode bump (a
		// cap-exhausted or failed bump restarts nothing).
		sum.stallPageBumps++
	}

	// --- Object phase: generations of up-to-4 concurrent fetches over
	// the pending set, until every object is done or terminally failed.
	table := newAObjTable(objects)
	for !table.resolved() {
		det := realquic.NewStallDetector(stallTimeout, nil)
		det.Start()
		var genBump atomic.Bool
		var fireIdle atomic.Int64
		genDone := make(chan struct{})
		// Monitor: the single bump authority for this generation.
		// It captures this generation's session, never the variable:
		// a bump reassigns sess, and the monitor must close the old
		// generation, not the new one.
		go func(d *realquic.StallDetector, s *mistSession) {
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-genDone:
					return
				case <-ctx.Done():
					s.close()
					return
				case <-ticker.C:
					if d.Stalled() {
						fireIdle.Store(int64(d.Idle()))
						// Flag BEFORE close: workers must see the
						// flag when their close-caused error lands,
						// or a bumped object would be misfiled as a
						// non-stall failure.
						genBump.Store(true)
						s.close()
						return
					}
				}
			}
		}(det, sess)
		var wg sync.WaitGroup
		var outMu sync.Mutex
		var outcomes []aOutcome
		record := func(o aOutcome) {
			outMu.Lock()
			outcomes = append(outcomes, o)
			outMu.Unlock()
		}
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(f *mistFetcher, d *realquic.StallDetector) {
				defer wg.Done()
				for {
					if genBump.Load() {
						return
					}
					idx := table.claim()
					if idx < 0 {
						return
					}
					if genBump.Load() {
						// Claimed after the bump started: never
						// fetched, but in flight at bump time, so
						// it counts as retried.
						record(aOutcome{idx: idx, bumped: true})
						return
					}
					fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
					u, dn, ferr := f.fetchObjectProgress(fctx, objects[idx], d.Report)
					cancel()
					if ferr == nil {
						table.complete(idx, u, dn)
						record(aOutcome{idx: idx, up: u, down: dn})
						continue
					}
					if genBump.Load() {
						record(aOutcome{idx: idx, bumped: true})
						return
					}
					table.failNonStall(idx, ferr)
					record(aOutcome{idx: idx, err: ferr})
				}
			}(sess.fetcher, det)
		}
		wg.Wait()
		close(genDone)
		if ctx.Err() != nil {
			return sum, ctx.Err()
		}
		// Requeue bumped objects; a bump with nothing to requeue
		// (all objects resolved as the stall fired) is spurious and
		// must not consume a reconnect.
		var bumped []int
		for _, o := range outcomes {
			if o.bumped {
				bumped = append(bumped, o.idx)
			}
		}
		retried := table.bumpRequeue(bumped)
		if genBump.Load() && (retried > 0 || !table.resolved()) {
			log.Printf("labclient: stall gen=%d mode=object (idle=%v), reconnect %d after %v; %d objects in flight restart from byte 0",
				gen, time.Duration(fireIdle.Load()), sum.stallReconnect+1, policy.Delay(sum.stallReconnect), retried)
			if berr := bump(); berr != nil {
				return sum, berr
			}
			// Count only restarted fetches: a bump that fails
			// (cap exhausted, dial error) restarts nothing.
			sum.stallObjectsRetried += retried
			continue
		}
		// No real bump: this generation settled the remaining
		// objects (done or terminally failed). The loop condition
		// re-checks resolved(); a generation that settled nothing
		// without a bump cannot happen (every claimed object gets
		// exactly one outcome), so the loop terminates.
	}

	up, down, n, firstErr := table.snapshot()
	sum.up, sum.down, sum.n = up, down, n
	prof := sess.cli.ActiveProfile()
	sum.profileVersion = prof.Version
	sum.profileHash = profileHash12(prof)
	sum.udpLocal = sess.udpLocal
	sum.tracker = sess.tracker
	if firstErr != nil {
		// runClassA semantics: the first error is returned after all
		// objects ran to completion, without waiting out the window.
		// Stall fields still report (the deferred generations fill
		// runs on this path too).
		return sum, firstErr
	}
	// Window wait, disarmed: no detector runs here, so a sleep longer
	// than T cannot trip a spurious reconnect (design §2.3).
	if remain := time.Until(start.Add(window)); remain > 0 {
		select {
		case <-time.After(remain):
		case <-ctx.Done():
			return sum, ctx.Err()
		}
	}
	return sum, nil
}

// runClassBRecoverable drives the 12 fixed objects with stall detection
// and generation reconnects. dial builds one generation (production: a
// fresh UDP socket via dialMistSession; tests: a MemPair end). It owns
// every generation it dials and closes the final one before returning;
// the caller applies the summary to the session result.
func runClassBRecoverable(ctx context.Context, dial func(gen int) (*mistSession, error), stallTimeout time.Duration, policy realquic.ReconnectPolicy) (recoverableSummary, error) {
	var sum recoverableSummary
	sess, err := dial(0)
	if err != nil {
		return sum, err
	}
	// Closure over the variable, not the first value: reconnects
	// reassign sess, and the final generation must be the one closed.
	defer func() { sess.close() }()
	idx := 0
	for idx < len(bObjects) {
		size := bObjects[idx]
		det := realquic.NewStallDetector(stallTimeout, nil)
		det.Start()
		fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		resCh := make(chan fetchOutcome, 1)
		go func(f *mistFetcher, d *realquic.StallDetector) {
			u, dn, ferr := f.fetchObjectProgress(fctx, size, d.Report)
			resCh <- fetchOutcome{up: u, down: dn, err: ferr}
		}(sess.fetcher, det)
		var res fetchOutcome
		stalled := false
		ticker := time.NewTicker(250 * time.Millisecond)
	waitLoop:
		for {
			select {
			case res = <-resCh:
				break waitLoop
			case <-ticker.C:
				if det.Stalled() {
					stalled = true
					// Closing the generation unblocks the in-flight
					// read promptly (a bare context cancel would not:
					// the stream read deadline is absolute, not
					// cancellation-aware). The fetch goroutine then
					// reports its error on resCh.
					sess.close()
					res = <-resCh
					break waitLoop
				}
			case <-fctx.Done():
				// Per-object timeout or parent cancellation. On parent
				// cancellation the stream read deadline is absolute,
				// not cancellation-aware, so close the generation to
				// unblock the fetch goroutine promptly instead of
				// waiting out the 60s deadline.
				if ctx.Err() != nil {
					sess.close()
				}
				res = <-resCh
				break waitLoop
			}
		}
		ticker.Stop()
		cancel()
		if res.err == nil {
			sum.up += res.up
			sum.down += res.down
			sum.n++
			idx++
			continue
		}
		if stalled && !policy.Exhausted(sum.stallReconnect) {
			delay := policy.Delay(sum.stallReconnect)
			log.Printf("labclient: stall on object %d/%d (idle=%v), reconnect %d after %v; in-flight object restarts from byte 0",
				idx+1, len(bObjects), det.Idle(), sum.stallReconnect+1, delay)
			sum.stallDetected = true
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return sum, ctx.Err()
			}
			next, derr := dial(sum.stallReconnect + 1)
			if derr != nil {
				return sum, fmt.Errorf("reconnect dial: %w", derr)
			}
			sess = next
			sum.stallReconnect++
			continue // retry the same object index on the new generation
		}
		if ctx.Err() != nil {
			return sum, ctx.Err()
		}
		return sum, fmt.Errorf("object %d: %w (stall=%v reconnects=%d)", idx, res.err, stalled, sum.stallReconnect)
	}
	prof := sess.cli.ActiveProfile()
	sum.profileVersion = prof.Version
	sum.profileHash = profileHash12(prof)
	sum.udpLocal = sess.udpLocal
	sum.tracker = sess.tracker
	return sum, nil
}

// serverVisibleAddr returns the address the server will key this
// session under: the route's source IP for remote, combined with the
// real socket's port (the port the server sees). pc.LocalAddr on a
// dual-stack wildcard socket reports [::]:port, which never matches
// the server's per-address key (127.0.0.1:port on loopback, the
// client's netns address on the pilot path). A throwaway dial to
// remote learns the source IP without sending anything. On any
// failure it falls back to the raw local address rather than
// fabricating an address.
func serverVisibleAddr(pc *net.UDPConn, remote *net.UDPAddr) string {
	local := pc.LocalAddr().String()
	_, port, err := net.SplitHostPort(local)
	if err != nil {
		return local
	}
	probe, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return local
	}
	defer probe.Close()
	host, _, err := net.SplitHostPort(probe.LocalAddr().String())
	if err != nil {
		return local
	}
	return net.JoinHostPort(host, port)
}

func main() {
	serverAddr := flag.String("server", "10.200.1.2:24443", "labserver UDP address (Mist arm; never 8443/443/1443)")
	objectAddr := flag.String("object", "10.200.1.2:18080", "labobject TCP address")
	class := flag.String("class", "A", "session class: A or B")
	id := flag.String("id", "", "session id (default: generated)")
	direct := flag.Bool("direct", false, "control arm: fetch directly over net/http, no Mist")
	page := flag.String("page", "a", "class-A page id")
	qlogPath := flag.String("qlog", "", "Mist arm only: path for this session's client qlog JSON-SEQ file (empty: no qlog file)")
	eventsOut := flag.String("events-out", "", "Mist arm only: path for up-direction shaping events JSON at session end (empty: not written)")
	// V7-A F arm (first-byte latency tail): per-object first-body-byte
	// latency samples, written as a JSON array at session end. Works
	// with -stall-recover on or off (record-only, never influences
	// fetching); empty means no recording.
	firstbyteOut := flag.String("firstbyte-out", "", "Mist arm only: path for per-object first-byte latency JSON at session end (empty: not recorded)")
	// B10 option 1, Mist class A/B (see runClassBRecoverable and
	// runClassARecoverable). Class B: V7 calibrated 2026-11-02.
	// Class A: same 5s default borrowed from class B, pending V7-A
	// calibration — not claimed as A-class calibrated.
	stallRecover := flag.Bool("stall-recover", false, "Mist class A/B: detect zero-progress stalls and reconnect to a new generation")
	stallTimeout := flag.Duration("stall-timeout", 5*time.Second, "stall-recover only: zero-progress window before a reconnect (class B: V7 calibrated 2026-11-02, 3s zero-mis-trigger across 20 sessions, 5s chosen with PTO margin; class A: default borrowed from class B, pending V7-A calibration)")
	stallMaxReconnects := flag.Int("stall-max-reconnects", 3, "stall-recover only: reconnect cap per session")
	// T-2 (class A only; class B ignores it): page-period timeout.
	// 0 follows -stall-timeout (single-T behavior, the safe default).
	// Set independently only with T_page >= D_budget + page-first-byte
	// p99 + 1s and >= T_A (see t2-page-period-design.md); lab value
	// 8s holds only under the D_budget=4s premise, never copy it to a
	// different page without recomputing.
	stallPageTimeout := flag.Duration("stall-page-timeout", 0, "stall-recover class A only: zero-progress window during page fetch; 0 follows -stall-timeout; set independently only with T_page >= D_budget + page-first-byte p99 + 1s and >= -stall-timeout (see t2-page-period-design.md)")
	flag.Parse()
	if *class != "A" && *class != "B" {
		log.Fatalf("labclient: bad class %q", *class)
	}
	if *stallRecover && *direct {
		log.Fatalf("labclient: -stall-recover applies to Mist arms only (direct=%v)", *direct)
	}
	if *firstbyteOut != "" && *direct {
		log.Fatalf("labclient: -firstbyte-out applies to Mist arms only (direct=%v)", *direct)
	}
	recoverable := *stallRecover && !*direct
	if *id == "" {
		*id = fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	arm := "mist"
	if *direct {
		arm = "direct"
	}
	log.Printf("labclient buildCommit=%s class=%s arm=%s id=%s", buildCommit, *class, arm, *id)

	res := &sessionResult{
		SessionID:   *id,
		Class:       *class,
		Arm:         arm,
		BuildCommit: buildCommit,
		StartedAt:   time.Now(),
	}
	// W-1 Mist-arm observation state, filled by the Mist branch
	// below. finishMist closes the connection (so the shaping log
	// includes the close datagram) and then writes -events-out; it
	// is a no-op on the direct arm and after the first call, so both
	// the failure path (fail) and the success path can call it.
	var mistCli *realquic.Client
	var pmtuTracker *realquic.PMTUTracker
	var udpLocal string
	finishMist := func() {
		if mistCli == nil {
			return
		}
		cli := mistCli
		mistCli = nil
		_ = cli.Close()
		if *eventsOut != "" {
			data, merr := json.Marshal(cli.ShapingEvents())
			if merr != nil {
				log.Printf("labclient: marshal events: %v", merr)
			} else if werr := os.WriteFile(*eventsOut, data, 0o644); werr != nil {
				log.Printf("labclient: write events-out: %v", werr)
			} else {
				log.Printf("labclient: wrote events-out=%s events=%d", *eventsOut, len(cli.ShapingEvents()))
			}
		}
	}
	// V7-A F arm: first-byte samples are collected only when
	// -firstbyte-out is set; nil keeps every fetch path identical.
	var fbLog *firstByteLog
	if *firstbyteOut != "" {
		fbLog = &firstByteLog{}
	}
	writeFirstByte := func() {
		if fbLog == nil || *firstbyteOut == "" {
			return
		}
		data, merr := json.Marshal(fbLog.snapshot())
		if merr != nil {
			log.Printf("labclient: marshal firstbyte: %v", merr)
		} else if werr := os.WriteFile(*firstbyteOut, data, 0o644); werr != nil {
			log.Printf("labclient: write firstbyte-out: %v", werr)
		} else {
			log.Printf("labclient: wrote firstbyte-out=%s samples=%d", *firstbyteOut, len(fbLog.snapshot()))
		}
	}
	fail := func(err error) {
		finishMist()
		writeFirstByte()
		res.EndedAt = time.Now()
		res.Failure = err.Error()
		out, _ := json.Marshal(res)
		fmt.Println(string(out))
		log.Fatalf("labclient: session failed: %v", err)
	}

	var f fetcher
	if *direct {
		f = &directFetcher{base: "http://" + *objectAddr}
	} else if !recoverable {
		// Default Mist path, unchanged by the stall-recovery driver:
		// the recoverable branch below dials its own generations.
		key, err := decodeKey(os.Getenv("MIST_KEY"))
		if err != nil {
			fail(err)
		}
		pc, err := net.ListenUDP("udp", nil)
		if err != nil {
			fail(fmt.Errorf("listen udp: %w", err))
		}
		defer pc.Close()
		remote, err := net.ResolveUDPAddr("udp", *serverAddr)
		if err != nil {
			fail(fmt.Errorf("resolve server: %w", err))
		}
		udpLocal = serverVisibleAddr(pc, remote)
		// W-1: every Mist session gets its own PMTU tracker
		// (family from the server address; 1280 default initial,
		// no ceiling), fed by a tee trace alongside the qlog file
		// when -qlog is set. The tracker is observation only: it
		// never influences sends. The client qlog uses NewFileSeq
		// (no connection ID in the header) because the dial chooses
		// the destination connection ID internally; the session's
		// identity for joining is udp_local, not a connID.
		ipv6 := remote.IP != nil && remote.IP.To4() == nil
		pmtuTracker = realquic.NewPMTUTracker(ipv6, 0, 0)
		var trace qlogwriter.Trace
		if *qlogPath != "" {
			qf, ferr := os.Create(*qlogPath)
			if ferr != nil {
				fail(fmt.Errorf("create qlog: %w", ferr))
			}
			// No deferred close: the FileSeq owns the file and
			// closes it when its last producer closes; http3's
			// producer is not closed on teardown, so the file is
			// formally closed at process exit instead. Events are
			// encoded eagerly, so the content is complete either
			// way. Do NOT close early: a late event writing to a
			// closed file would only log an encode error.
			fileSeq := qlogwriter.NewFileSeq(qf)
			go fileSeq.Run()
			trace = realquic.NewTeeTrace(fileSeq, realquic.NewPMTUQlogTrace(pmtuTracker))
		} else {
			trace = realquic.NewTeeTrace(nil, realquic.NewPMTUQlogTrace(pmtuTracker))
		}
		dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cli, err := realquic.DialPacketConnWithPMTUTrace(dctx, pc, remote, key, trace)
		cancel()
		if err != nil {
			fail(fmt.Errorf("dial: %w", err))
		}
		mistCli = cli
		actx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		status, _, _, err := cli.Auth(actx)
		cancel()
		if err != nil {
			fail(fmt.Errorf("auth: %w", err))
		}
		if status != 200 {
			fail(fmt.Errorf("auth status %d", status))
		}
		prof := cli.ActiveProfile()
		res.ProfileVersion = prof.Version
		res.ProfileHash = profileHash12(prof)
		f = &mistFetcher{cli: cli, target: *objectAddr, firstByte: fbLog}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var up, down int64
	var n int
	var err error
	if recoverable {
		// The driver owns its generations (dial + re-AUTH + resume);
		// the pre-dispatch Mist dial above was skipped for this path.
		key, kerr := decodeKey(os.Getenv("MIST_KEY"))
		if kerr != nil {
			fail(kerr)
		}
		policy := realquic.ReconnectPolicy{MaxReconnects: *stallMaxReconnects}
		dial := func(gen int) (*mistSession, error) {
			sess, err := dialMistSession(*serverAddr, *objectAddr, key, *qlogPath, *eventsOut, gen)
			if err == nil && fbLog != nil {
				sess.fetcher.firstByte = fbLog
			}
			return sess, err
		}
		var rsum recoverableSummary
		var rerr error
		if *class == "A" {
			rsum, rerr = runClassARecoverable(ctx, dial, "/page/"+*page, aWindow, res.StartedAt, *stallTimeout, *stallPageTimeout, policy)
		} else {
			rsum, rerr = runClassBRecoverable(ctx, dial, *stallTimeout, policy)
		}
		up, down, n = rsum.up, rsum.down, rsum.n
		err = rerr
		res.StallReconnects = rsum.stallReconnect
		res.StallDetected = rsum.stallDetected
		res.StallObjectsRetried = rsum.stallObjectsRetried
		res.StallGenerations = rsum.stallGenerations
		res.StallPageBumps = rsum.stallPageBumps
		res.ProfileVersion = rsum.profileVersion
		res.ProfileHash = rsum.profileHash
		res.UDPLocal = rsum.udpLocal
		if rsum.tracker != nil {
			capIP, known := rsum.tracker.PeerCapIP()
			res.PMTUTargetIP = rsum.tracker.TargetIP()
			res.PMTUStackEnforcedIP = rsum.tracker.StackEnforcedTargetIP()
			res.PMTUValidatedIP = rsum.tracker.ValidatedIP()
			res.PMTUPeerCapIP = capIP
			res.PMTUPeerCapKnown = known
			res.PMTUDone = rsum.tracker.Done()
		}
	} else if *class == "A" {
		up, down, n, err = runClassA(ctx, f, "/page/"+*page, aWindow, res.StartedAt)
	} else {
		up, down, n, err = runClassB(ctx, f)
	}
	res.UpBytes, res.DownBytes, res.Objects = up, down, n
	if err != nil {
		fail(err)
	}
	if mistCli != nil {
		res.UDPLocal = udpLocal
		if pmtuTracker != nil {
			capIP, known := pmtuTracker.PeerCapIP()
			res.PMTUTargetIP = pmtuTracker.TargetIP()
			res.PMTUStackEnforcedIP = pmtuTracker.StackEnforcedTargetIP()
			res.PMTUValidatedIP = pmtuTracker.ValidatedIP()
			res.PMTUPeerCapIP = capIP
			res.PMTUPeerCapKnown = known
			res.PMTUDone = pmtuTracker.Done()
		}
	}
	finishMist()
	writeFirstByte()
	res.EndedAt = time.Now()
	out, _ := json.Marshal(res)
	fmt.Println(string(out))
	log.Printf("labclient: session ok id=%s class=%s arm=%s down=%d objects=%d", *id, *class, arm, down, n)
}
