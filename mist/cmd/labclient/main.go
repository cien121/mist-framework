// Command labclient is the pilot-only load driver for Stage 3 pilot
// Tier 1. In Mist mode it dials the lab server (DialPacketConn), runs
// AUTH, then drives the synthetic load over Connect relay streams to
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
	"time"

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
}

// fetchOverRelay performs one HTTP/1.1 GET over a fresh Connect stream.
// When wantBody is false the body is counted and discarded.
func (m *mistFetcher) fetchOverRelay(ctx context.Context, path string, wantBody bool) (up, down int64, body []byte, err error) {
	cs, err := m.cli.Connect(ctx, m.target)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("connect: %w", err)
	}
	defer cs.Close()
	req := "GET " + path + " HTTP/1.1\r\nHost: " + m.target + "\r\nConnection: close\r\n\r\n"
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
	down, err = io.CopyN(io.Discard, br, cl)
	if err != nil {
		return up, down, nil, fmt.Errorf("read body: %w", err)
	}
	return up, down, nil, nil
}

func (m *mistFetcher) fetchPage(ctx context.Context, path string) ([]int, error) {
	_, _, body, err := m.fetchOverRelay(ctx, path, true)
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

func (m *mistFetcher) fetchObject(ctx context.Context, size int) (int64, int64, error) {
	up, down, _, err := m.fetchOverRelay(ctx, "/obj/"+strconv.Itoa(size), false)
	if err != nil {
		return up, down, err
	}
	if down != int64(size) {
		return up, down, fmt.Errorf("object size mismatch: got %d want %d", down, size)
	}
	return up, down, nil
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

func main() {
	serverAddr := flag.String("server", "10.200.1.2:24443", "labserver UDP address (Mist arm; never 8443/443/1443)")
	objectAddr := flag.String("object", "10.200.1.2:18080", "labobject TCP address")
	class := flag.String("class", "A", "session class: A or B")
	id := flag.String("id", "", "session id (default: generated)")
	direct := flag.Bool("direct", false, "control arm: fetch directly over net/http, no Mist")
	page := flag.String("page", "a", "class-A page id")
	flag.Parse()
	if *class != "A" && *class != "B" {
		log.Fatalf("labclient: bad class %q", *class)
	}
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
	fail := func(err error) {
		res.EndedAt = time.Now()
		res.Failure = err.Error()
		out, _ := json.Marshal(res)
		fmt.Println(string(out))
		log.Fatalf("labclient: session failed: %v", err)
	}

	var f fetcher
	if *direct {
		f = &directFetcher{base: "http://" + *objectAddr}
	} else {
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
		dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cli, err := realquic.DialPacketConn(dctx, pc, remote, key)
		cancel()
		if err != nil {
			fail(fmt.Errorf("dial: %w", err))
		}
		defer cli.Close()
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
		f = &mistFetcher{cli: cli, target: *objectAddr}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var up, down int64
	var n int
	var err error
	if *class == "A" {
		up, down, n, err = runClassA(ctx, f, "/page/"+*page, aWindow, res.StartedAt)
	} else {
		up, down, n, err = runClassB(ctx, f)
	}
	res.UpBytes, res.DownBytes, res.Objects = up, down, n
	if err != nil {
		fail(err)
	}
	res.EndedAt = time.Now()
	out, _ := json.Marshal(res)
	fmt.Println(string(out))
	log.Printf("labclient: session ok id=%s class=%s arm=%s down=%d objects=%d", *id, *class, arm, down, n)
}
