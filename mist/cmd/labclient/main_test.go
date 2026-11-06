package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mist/realquic"
)

func TestBObjectsTotal(t *testing.T) {
	if len(bObjects) != 12 {
		t.Fatalf("bObjects=%d, want 12", len(bObjects))
	}
	sum := 0
	for _, n := range bObjects {
		if n != 262144 {
			t.Fatalf("b object=%d, want 262144", n)
		}
		sum += n
	}
	if sum != 3145728 {
		t.Fatalf("b total=%d, want 3145728", sum)
	}
}

// testObjectServer is a minimal stand-in for labobject (same wire shape:
// /obj/<n> with Content-Length, /page/<id> with an objects JSON list).
func testObjectServer(t *testing.T, page []int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/obj/", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/obj/"))
		if err != nil || n <= 0 {
			http.Error(w, "bad size", 400)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", n)), int64(n))
	})
	mux.HandleFunc("/page/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "a", "objects": page})
	})
	return httptest.NewServer(mux)
}

func TestDirectClassAandB(t *testing.T) {
	page := []int{1000, 2000, 3000}
	s := testObjectServer(t, page)
	defer s.Close()
	f := &directFetcher{base: s.URL}
	ctx := context.Background()
	up, down, n, err := runClassA(ctx, f, "/page/a", 0, time.Now())
	if err != nil {
		t.Fatalf("class A: %v", err)
	}
	if down != 6000 || n != 3 {
		t.Fatalf("class A: down=%d n=%d, want 6000/3", down, n)
	}
	if up <= 0 {
		t.Fatalf("class A: up=%d, want >0", up)
	}
	// B uses the frozen list, served here by the same stand-in.
	up, down, n, err = runClassB(ctx, f)
	if err != nil {
		t.Fatalf("class B: %v", err)
	}
	if down != 3145728 || n != 12 {
		t.Fatalf("class B: down=%d n=%d, want 3145728/12", down, n)
	}
	if up <= 0 {
		t.Fatalf("class B: up=%d, want >0", up)
	}
}

// udpLoopbackUsable probes whether this sandbox permits UDP sendmsg on
// loopback. The library itself documents that some sandboxes block it
// with EPERM and provides NewMemPair as the lab fallback; the test
// mirrors that fallback (full session still runs, no skip).
func udpLoopbackUsable() bool {
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return false
	}
	defer a.Close()
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return false
	}
	defer b.Close()
	_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := b.WriteToUDP([]byte("probe"), a.LocalAddr().(*net.UDPAddr)); err != nil {
		return false
	}
	buf := make([]byte, 16)
	_, _, err = a.ReadFromUDP(buf)
	return err == nil
}

func TestMistLoopbackClassA(t *testing.T) {
	page := []int{4096, 8192}
	obj := testObjectServer(t, page)
	defer obj.Close()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := realquic.NewServer(realquic.ServerConfig{Key: key, RotationMin: 0})
	if err != nil {
		t.Fatal(err)
	}
	var srvPC, cliPC net.PacketConn
	if udpLoopbackUsable() {
		t.Logf("transport=udp")
		srvPC, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		cliPC, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		_ = srvPC.LocalAddr()
	} else {
		t.Logf("transport=mem-pair (sandbox blocks loopback UDP)")
		cliPC, srvPC = realquic.NewMemPair()
	}
	defer srvPC.Close()
	defer cliPC.Close()
	go func() { _ = srv.ServePacketConn(srvPC) }()
	defer srv.Close()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	cli, err := realquic.DialPacketConn(ctx, cliPC, srvPC.LocalAddr(), key)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()
	status, _, _, err := cli.Auth(ctx)
	if err != nil || status != 200 {
		t.Fatalf("auth: status=%d err=%v", status, err)
	}
	if cli.ActiveProfile().Version < 1 {
		t.Fatalf("active profile version=%d", cli.ActiveProfile().Version)
	}
	// httptest listener addr is 127.0.0.1:port, reachable from the relay.
	target := obj.Listener.Addr().String()
	f := &mistFetcher{cli: cli, target: target}
	up, down, n, err := runClassA(ctx, f, "/page/a", 200*time.Millisecond, time.Now())
	if err != nil {
		t.Fatalf("mist class A: %v", err)
	}
	if down != 12288 || n != 2 {
		t.Fatalf("mist class A: down=%d n=%d, want 12288/2", down, n)
	}
	if up <= 0 {
		t.Fatalf("mist class A: up=%d, want >0", up)
	}
}

func TestProgressReaderReportsChunks(t *testing.T) {
	var got []int64
	pr := &progressReader{r: strings.NewReader("hello world"), report: func(n int64) { got = append(got, n) }}
	buf := make([]byte, 4)
	var total int
	for {
		n, err := pr.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if total != 11 {
		t.Fatalf("total=%d, want 11", total)
	}
	var sum int64
	for _, n := range got {
		if n <= 0 {
			t.Fatalf("reported non-positive chunk %d", n)
		}
		sum += n
	}
	if sum != 11 {
		t.Fatalf("reported sum=%d, want 11", sum)
	}
}

func TestProgressReaderNilReport(t *testing.T) {
	pr := &progressReader{r: strings.NewReader("abc")}
	b, err := io.ReadAll(pr)
	if err != nil || string(b) != "abc" {
		t.Fatalf("nil-report read=%q err=%v", b, err)
	}
}

func TestSuffixedPath(t *testing.T) {
	if got := suffixedPath("/tmp/x.sqlog", 0); got != "/tmp/x.sqlog" {
		t.Fatalf("gen0=%q", got)
	}
	if got := suffixedPath("/tmp/x.sqlog", 2); got != "/tmp/x.sqlog.gen2" {
		t.Fatalf("gen2=%q", got)
	}
	if got := suffixedPath("", 3); got != "" {
		t.Fatalf("empty gen3=%q", got)
	}
}

// recoverableTestDial builds a per-generation dial function over MemPair
// ends served by one in-process lab server (no real UDP: the sandbox
// blocks loopback sendmsg with EPERM). Each generation gets a fresh pair;
// the server end is served in the background until the server closes.
func recoverableTestDial(t *testing.T, srv *realquic.Server, objAddr string, key []byte) func(int) (*mistSession, error) {
	t.Helper()
	return func(gen int) (*mistSession, error) {
		cliPC, srvPC := realquic.NewMemPair()
		go func() { _ = srv.ServePacketConn(srvPC) }()
		s, err := dialMistSessionOnConn(cliPC, srvPC.LocalAddr(), objAddr, key, "", "", gen)
		if err != nil {
			_ = cliPC.Close()
			_ = srvPC.Close()
			return nil, err
		}
		return s, nil
	}
}

func recoverableTestSetup(t *testing.T, mux *http.ServeMux) (*realquic.Server, string, []byte) {
	t.Helper()
	obj := httptest.NewServer(mux)
	t.Cleanup(obj.Close)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	srv, err := realquic.NewServer(realquic.ServerConfig{Key: key, RotationMin: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, obj.Listener.Addr().String(), key
}

// plainObjHandler serves /obj/<n> in full, like labobject.
func plainObjHandler(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/obj/"))
	if err != nil || n <= 0 {
		http.Error(w, "bad size", 400)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(n))
	_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", n)), int64(n))
}

// plainObjMux serves /obj/<n> in full, like labobject.
func plainObjMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/obj/", plainObjHandler)
	return mux
}

// aTestMux serves /page/ with the given objects and /obj/ with objHandler.
func aTestMux(page []int, objHandler http.HandlerFunc) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "a", "objects": page})
	})
	mux.HandleFunc("/obj/", objHandler)
	return mux
}

func TestRecoverableClassBNoStall(t *testing.T) {
	srv, objAddr, key := recoverableTestSetup(t, plainObjMux())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassBRecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), 8*time.Second, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("recoverable no-stall: %v", err)
	}
	if sum.n != 12 || sum.down != 3145728 {
		t.Fatalf("no-stall: n=%d down=%d, want 12/3145728", sum.n, sum.down)
	}
	if sum.stallDetected || sum.stallReconnect != 0 {
		t.Fatalf("no-stall: detected=%v reconnects=%d, want false/0", sum.stallDetected, sum.stallReconnect)
	}
}

// TestRecoverableClassBStallReconnect is the end-to-end proof of B10
// option 1 without any MTU manipulation: the object server stalls the
// FIRST object mid-body (headers + 1024 bytes, then silence until the
// relay dies). The driver must detect zero progress, close the
// generation, reconnect, and finish all 12 objects exactly once.
func TestRecoverableClassBStallReconnect(t *testing.T) {
	var stalledOnce atomic.Bool
	// /obj/ stalls once, then behaves like plainObjMux.
	mux := http.NewServeMux()
	mux.HandleFunc("/obj/", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/obj/"))
		if err != nil || n <= 0 {
			http.Error(w, "bad size", 400)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		if stalledOnce.CompareAndSwap(false, true) {
			// First object only: deliver a prefix, then stall until
			// the client kills the relay (request context done).
			if f, ok := w.(http.Flusher); ok {
				_, _ = w.Write([]byte(strings.Repeat("x", 1024)))
				f.Flush()
			}
			<-r.Context().Done()
			return
		}
		_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", n)), int64(n))
	})
	srv, objAddr, key := recoverableTestSetup(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	sum, err := runClassBRecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), 500*time.Millisecond, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("recoverable stall: %v", err)
	}
	if sum.n != 12 || sum.down != 3145728 {
		t.Fatalf("stall: n=%d down=%d, want 12/3145728", sum.n, sum.down)
	}
	if !sum.stallDetected || sum.stallReconnect != 1 {
		t.Fatalf("stall: detected=%v reconnects=%d, want true/1", sum.stallDetected, sum.stallReconnect)
	}
	t.Logf("stall-recovered in %v", time.Since(start))
}

// ---- Class A recoverable driver (B10 option 1, design §7) ----
//
// Test-T note: the A end-to-end tests use T=2s, not the 500ms of the
// B stall test. Measured downlink first-delivery latency on MemPair
// runs 270-365ms typically with a tail past 500ms (server downlink
// shaper burst phase: a generation starting mid-idle-gap waits for the
// next burst), so a 500ms test-T spuriously trips on healthy small
// objects. 2s keeps ~4x margin over the observed tail while keeping
// stall tests fast. Production T=5s is unaffected (10x margin), but
// V7-A should measure the small-object first-byte latency tail to
// confirm the production margin (design T-1 input).

func TestAObjTableTransitions(t *testing.T) {
	table := newAObjTable([]int{100, 200, 300})
	if table.resolved() {
		t.Fatal("fresh table resolved")
	}
	if i := table.claim(); i != 0 {
		t.Fatalf("claim1=%d, want 0", i)
	}
	if i := table.claim(); i != 1 {
		t.Fatalf("claim2=%d, want 1", i)
	}
	table.complete(0, 10, 100)
	// A bump reverts in-flight only: done object 0 stays done.
	if n := table.bumpRequeue([]int{0, 1}); n != 1 {
		t.Fatalf("bumpRequeue=%d, want 1", n)
	}
	// A failed object is terminal: it never requeues.
	table.failNonStall(2, errors.New("boom"))
	if n := table.bumpRequeue([]int{2}); n != 0 {
		t.Fatalf("bumpRequeue failed=%d, want 0", n)
	}
	if i := table.claim(); i != 1 {
		t.Fatalf("reclaim=%d, want 1", i)
	}
	table.complete(1, 20, 200)
	if !table.resolved() {
		t.Fatal("table not resolved after all done/failed")
	}
	up, down, n, ferr := table.snapshot()
	if up != 30 || down != 300 || n != 2 {
		t.Fatalf("snapshot: up=%d down=%d n=%d, want 30/300/2", up, down, n)
	}
	if ferr == nil || ferr.Error() != "boom" {
		t.Fatalf("firstErr=%v, want boom", ferr)
	}
}

func TestRecoverableClassANoStall(t *testing.T) {
	page := []int{1024, 2048, 3072, 4096}
	srv, objAddr, key := recoverableTestSetup(t, aTestMux(page, plainObjHandler))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, time.Now(), 2*time.Second, 0, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("recoverable A no-stall: %v", err)
	}
	if sum.n != 4 || sum.down != 10240 {
		t.Fatalf("no-stall: n=%d down=%d, want 4/10240", sum.n, sum.down)
	}
	if sum.stallDetected || sum.stallReconnect != 0 || sum.stallObjectsRetried != 0 || sum.stallGenerations != 0 {
		t.Fatalf("no-stall: detected=%v reconnects=%d retried=%d generations=%d, want false/0/0/0",
			sum.stallDetected, sum.stallReconnect, sum.stallObjectsRetried, sum.stallGenerations)
	}
}

// TestRecoverableClassAStallReconnect is the class-A proof of B10 option
// 1: the object server hangs ALL generation-0 object streams with zero
// bytes (relay-level silence: every stream starves at once, which is
// what a connection-level blackhole looks like). The driver must detect
// the aggregate stall, bump the whole connection, and finish every
// object exactly once on the new generation.
func TestRecoverableClassAStallReconnect(t *testing.T) {
	page := []int{4096, 8192, 12288, 16384}
	var reqs atomic.Int32
	mux := aTestMux(page, func(w http.ResponseWriter, r *http.Request) {
		if reqs.Add(1) <= 4 {
			// Generation 0: hang with zero bytes until the client
			// kills the relay (request context done).
			<-r.Context().Done()
			return
		}
		plainObjHandler(w, r)
	})
	srv, objAddr, key := recoverableTestSetup(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, time.Now(), 2*time.Second, 0, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("recoverable A stall: %v", err)
	}
	if sum.n != 4 || sum.down != 40960 {
		t.Fatalf("stall: n=%d down=%d, want 4/40960", sum.n, sum.down)
	}
	if !sum.stallDetected || sum.stallReconnect != 1 {
		t.Fatalf("stall: detected=%v reconnects=%d, want true/1", sum.stallDetected, sum.stallReconnect)
	}
	if sum.stallObjectsRetried != 4 {
		t.Fatalf("stall: objects_retried=%d, want 4 (all in flight at bump)", sum.stallObjectsRetried)
	}
	if sum.stallGenerations != 2 {
		t.Fatalf("stall: generations=%d, want 2", sum.stallGenerations)
	}
	if reqs.Load() != 8 {
		t.Fatalf("obj requests=%d, want 8 (4 hung + 4 served)", reqs.Load())
	}
}

// trickleObjHandler serves one size as a slow trickle (10 bytes every
// 50ms) and every other size after a fixed delay, for aggregation tests.
func trickleObjHandler(t *testing.T, trickleSize int, otherDelay time.Duration) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/obj/"))
		if err != nil || n <= 0 {
			http.Error(w, "bad size", 400)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		if n == trickleSize {
			f, _ := w.(http.Flusher)
			for sent := 0; sent < n; {
				select {
				case <-r.Context().Done():
					return
				default:
				}
				step := 10
				if sent+step > n {
					step = n - sent
				}
				_, _ = w.Write([]byte(strings.Repeat("x", step)))
				if f != nil {
					f.Flush()
				}
				sent += step
				time.Sleep(50 * time.Millisecond)
			}
			return
		}
		select {
		case <-time.After(otherDelay):
		case <-r.Context().Done():
			return
		}
		_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", n)), int64(n))
	}
}

// TestRecoverableClassATrickleNoTrip is the anti-OR proof: one stream
// trickles while the other three stall for 3x T. An OR rule (any stream
// silent for T trips) would fire at T; the aggregate detector must not,
// because the trickle stream keeps delivering body bytes.
func TestRecoverableClassATrickleNoTrip(t *testing.T) {
	const trickleSize = 1000
	page := []int{trickleSize, 4096, 8192, 12288}
	srv, objAddr, key := recoverableTestSetup(t, aTestMux(page, trickleObjHandler(t, trickleSize, 3*time.Second)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, time.Now(), 2*time.Second, 0, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("trickle: %v", err)
	}
	if sum.n != 4 || sum.down != 25576 {
		t.Fatalf("trickle: n=%d down=%d, want 4/25576", sum.n, sum.down)
	}
	if sum.stallDetected || sum.stallReconnect != 0 {
		t.Fatalf("trickle: detected=%v reconnects=%d, want false/0", sum.stallDetected, sum.stallReconnect)
	}
}

// TestRecoverableClassASlowStreamNoTrip: three fast streams plus one
// slow trickle. Slow delivery is progress, not a stall: no reconnect,
// all bytes exact.
func TestRecoverableClassASlowStreamNoTrip(t *testing.T) {
	const trickleSize = 500
	page := []int{4096, 8192, trickleSize, 12288}
	srv, objAddr, key := recoverableTestSetup(t, aTestMux(page, trickleObjHandler(t, trickleSize, 0)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, time.Now(), 2*time.Second, 0, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("slow stream: %v", err)
	}
	if sum.n != 4 || sum.down != 25076 {
		t.Fatalf("slow stream: n=%d down=%d, want 4/25076", sum.n, sum.down)
	}
	if sum.stallDetected || sum.stallReconnect != 0 {
		t.Fatalf("slow stream: detected=%v reconnects=%d, want false/0", sum.stallDetected, sum.stallReconnect)
	}
}

// TestRecoverableClassACapExhaustion: every object stream hangs on every
// generation. The driver must burn the per-session cap (3) and return a
// clear stall error instead of looping forever.
func TestRecoverableClassACapExhaustion(t *testing.T) {
	page := []int{4096, 8192, 12288, 16384}
	mux := aTestMux(page, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	srv, objAddr, key := recoverableTestSetup(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, time.Now(), 2*time.Second, 0, realquic.ReconnectPolicy{})
	if err == nil {
		t.Fatal("cap exhaustion: want error, got nil")
	}
	if !strings.Contains(err.Error(), "cap exhausted") {
		t.Fatalf("cap exhaustion: err=%v, want cap-exhausted error", err)
	}
	if !sum.stallDetected || sum.stallReconnect != 3 {
		t.Fatalf("cap exhaustion: detected=%v reconnects=%d, want true/3", sum.stallDetected, sum.stallReconnect)
	}
	if sum.stallGenerations != 4 {
		t.Fatalf("cap exhaustion: generations=%d, want 4", sum.stallGenerations)
	}
	if sum.stallObjectsRetried != 12 {
		t.Fatalf("cap exhaustion: objects_retried=%d, want 12 (4 per successful bump x3)", sum.stallObjectsRetried)
	}
}

// TestRecoverableClassAWindowWaitNoTrip: everything completes fast, then
// the driver waits out a window longer than T. The disarm point is
// correct only if no spurious reconnect fires during the wait.
func TestRecoverableClassAWindowWaitNoTrip(t *testing.T) {
	page := []int{4096, 8192}
	srv, objAddr, key := recoverableTestSetup(t, aTestMux(page, plainObjHandler))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 3*time.Second, start, 2*time.Second, 0, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("window wait: %v", err)
	}
	if sum.n != 2 || sum.down != 12288 {
		t.Fatalf("window wait: n=%d down=%d, want 2/12288", sum.n, sum.down)
	}
	if sum.stallDetected || sum.stallReconnect != 0 {
		t.Fatalf("window wait: detected=%v reconnects=%d, want false/0", sum.stallDetected, sum.stallReconnect)
	}
	if elapsed := time.Since(start); elapsed < 2900*time.Millisecond {
		t.Fatalf("window wait: elapsed=%v, want >=2.9s (window honored)", elapsed)
	}
}

// TestRecoverableClassAPageStall: the page fetch itself stalls on
// generation 0. The driver must bump, refetch the page on the new
// generation, and NOT count the page refetch in stall_objects_retried.
func TestRecoverableClassAPageStall(t *testing.T) {
	page := []int{4096, 8192}
	var pageReqs atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", func(w http.ResponseWriter, r *http.Request) {
		if pageReqs.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "a", "objects": page})
	})
	mux.HandleFunc("/obj/", plainObjHandler)
	srv, objAddr, key := recoverableTestSetup(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, time.Now(), 2*time.Second, 0, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("page stall: %v", err)
	}
	if sum.n != 2 || sum.down != 12288 {
		t.Fatalf("page stall: n=%d down=%d, want 2/12288", sum.n, sum.down)
	}
	if !sum.stallDetected || sum.stallReconnect != 1 {
		t.Fatalf("page stall: detected=%v reconnects=%d, want true/1", sum.stallDetected, sum.stallReconnect)
	}
	if sum.stallObjectsRetried != 0 {
		t.Fatalf("page stall: objects_retried=%d, want 0 (page refetch is not an object retry)", sum.stallObjectsRetried)
	}
	if sum.stallGenerations != 2 {
		t.Fatalf("page stall: generations=%d, want 2", sum.stallGenerations)
	}
	if pageReqs.Load() != 2 {
		t.Fatalf("page requests=%d, want 2 (1 hung + 1 served)", pageReqs.Load())
	}
}

// TestRecoverableClassANonStallErrorNoRetry: one object answers 400.
// That is a terminal non-stall failure: the run fails with that error,
// no reconnect happens, and the bad object is fetched exactly once.
func TestRecoverableClassANonStallErrorNoRetry(t *testing.T) {
	page := []int{4096, 777, 8192}
	var badReqs atomic.Int32
	mux := aTestMux(page, func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/obj/"))
		if err != nil || n <= 0 {
			http.Error(w, "bad size", 400)
			return
		}
		if n == 777 {
			badReqs.Add(1)
			http.Error(w, "bad size", 400)
			return
		}
		plainObjHandler(w, r)
	})
	srv, objAddr, key := recoverableTestSetup(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, time.Now(), 2*time.Second, 0, realquic.ReconnectPolicy{})
	if err == nil {
		t.Fatal("non-stall error: want error, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("non-stall error: err=%v, want 400 failure", err)
	}
	if sum.stallDetected || sum.stallReconnect != 0 {
		t.Fatalf("non-stall error: detected=%v reconnects=%d, want false/0", sum.stallDetected, sum.stallReconnect)
	}
	if badReqs.Load() != 1 {
		t.Fatalf("bad object requests=%d, want 1 (no retry on non-stall failure)", badReqs.Load())
	}
	if sum.n != 2 || sum.down != 12288 {
		t.Fatalf("non-stall error: n=%d down=%d, want 2/12288 (completed objects kept)", sum.n, sum.down)
	}
}

// ---- T-2: page-period separate timeout ----
//
// resolvePageTimeout is the flag mapping: positive wins, zero or
// negative follows -stall-timeout (never disabled: a page detector
// that can never trip would silently swallow page stalls).
func TestResolvePageTimeout(t *testing.T) {
	if got := resolvePageTimeout(0, 5*time.Second); got != 5*time.Second {
		t.Fatalf("follow 0: got %v, want 5s", got)
	}
	if got := resolvePageTimeout(-time.Second, 5*time.Second); got != 5*time.Second {
		t.Fatalf("follow negative: got %v, want 5s", got)
	}
	if got := resolvePageTimeout(12*time.Second, 5*time.Second); got != 12*time.Second {
		t.Fatalf("explicit: got %v, want 12s", got)
	}
}

// TestRecoverableClassAPageTimeoutSeparate is the separation proof:
// the page hangs on generation 0 with T_page=1.5s while T_A=8s. If the
// page phase used T_A, the run would take 8s+ before the first bump;
// with T_page it completes in well under 6s. The bump must be counted
// as a page-mode bump and must not count as an object retry.
func TestRecoverableClassAPageTimeoutSeparate(t *testing.T) {
	page := []int{4096, 8192}
	var pageReqs atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", func(w http.ResponseWriter, r *http.Request) {
		if pageReqs.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "a", "objects": page})
	})
	mux.HandleFunc("/obj/", plainObjHandler)
	srv, objAddr, key := recoverableTestSetup(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, start, 8*time.Second, 1500*time.Millisecond, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("page-timeout separate: %v", err)
	}
	if sum.n != 2 || sum.down != 12288 {
		t.Fatalf("page-timeout separate: n=%d down=%d, want 2/12288", sum.n, sum.down)
	}
	if !sum.stallDetected || sum.stallReconnect != 1 {
		t.Fatalf("page-timeout separate: detected=%v reconnects=%d, want true/1", sum.stallDetected, sum.stallReconnect)
	}
	if sum.stallPageBumps != 1 {
		t.Fatalf("page-timeout separate: page_bumps=%d, want 1", sum.stallPageBumps)
	}
	if sum.stallObjectsRetried != 0 {
		t.Fatalf("page-timeout separate: objects_retried=%d, want 0", sum.stallObjectsRetried)
	}
	if sum.stallGenerations != 2 {
		t.Fatalf("page-timeout separate: generations=%d, want 2", sum.stallGenerations)
	}
	if pageReqs.Load() != 2 {
		t.Fatalf("page-timeout separate: page requests=%d, want 2", pageReqs.Load())
	}
	// Separation proof: a page phase on T_A=8s could not finish
	// before 8s + backoff + fetch; 6s bounds the whole run below it.
	if elapsed := time.Since(start); elapsed >= 6*time.Second {
		t.Fatalf("page-timeout separate: elapsed=%v, want <6s (page used T_page, not T_A=8s)", elapsed)
	}
}

// TestRecoverableClassAPageThenObjectMode is the mode-switch proof:
// generation 0 stalls in page mode (page bump, refetch), generation 1
// serves the page then stalls in object mode (object bump, no page
// refetch), generation 2 serves everything. Page requests must stay
// at 2: the object-mode bump's generation starts directly in object
// mode because the page list is cached.
func TestRecoverableClassAPageThenObjectMode(t *testing.T) {
	page := []int{4096, 8192, 12288, 16384}
	var pageReqs, objReqs atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", func(w http.ResponseWriter, r *http.Request) {
		if pageReqs.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "a", "objects": page})
	})
	mux.HandleFunc("/obj/", func(w http.ResponseWriter, r *http.Request) {
		if objReqs.Add(1) <= 4 {
			// Generation 1 objects: hang with zero bytes.
			<-r.Context().Done()
			return
		}
		plainObjHandler(w, r)
	})
	srv, objAddr, key := recoverableTestSetup(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, time.Now(), 2*time.Second, 2*time.Second, realquic.ReconnectPolicy{})
	if err != nil {
		t.Fatalf("page-then-object mode: %v", err)
	}
	if sum.n != 4 || sum.down != 40960 {
		t.Fatalf("page-then-object mode: n=%d down=%d, want 4/40960", sum.n, sum.down)
	}
	if !sum.stallDetected || sum.stallReconnect != 2 {
		t.Fatalf("page-then-object mode: detected=%v reconnects=%d, want true/2", sum.stallDetected, sum.stallReconnect)
	}
	if sum.stallPageBumps != 1 {
		t.Fatalf("page-then-object mode: page_bumps=%d, want 1 (only the gen0 bump)", sum.stallPageBumps)
	}
	if sum.stallObjectsRetried != 4 {
		t.Fatalf("page-then-object mode: objects_retried=%d, want 4 (only the object-mode bump requeues)", sum.stallObjectsRetried)
	}
	if sum.stallGenerations != 3 {
		t.Fatalf("page-then-object mode: generations=%d, want 3", sum.stallGenerations)
	}
	if pageReqs.Load() != 2 {
		t.Fatalf("page-then-object mode: page requests=%d, want 2 (gen0 hang + gen1 serve; gen2 must not refetch)", pageReqs.Load())
	}
	if objReqs.Load() != 8 {
		t.Fatalf("page-then-object mode: obj requests=%d, want 8 (4 hung + 4 served)", objReqs.Load())
	}
}

// TestRecoverableClassASharedCapPagePlusObject is the shared-cap proof:
// one page-mode bump plus object-mode stalls on every later generation.
// With a shared session cap of 3, the fourth stall exhausts the cap;
// with per-mode caps, the object-mode bumps would each get their own
// budget and the run would bump a fourth time instead of failing.
func TestRecoverableClassASharedCapPagePlusObject(t *testing.T) {
	page := []int{4096, 8192, 12288, 16384}
	var pageReqs atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", func(w http.ResponseWriter, r *http.Request) {
		if pageReqs.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "a", "objects": page})
	})
	mux.HandleFunc("/obj/", func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	srv, objAddr, key := recoverableTestSetup(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := runClassARecoverable(ctx, recoverableTestDial(t, srv, objAddr, key), "/page/a", 100*time.Millisecond, time.Now(), 2*time.Second, 2*time.Second, realquic.ReconnectPolicy{})
	if err == nil {
		t.Fatal("shared cap: want error, got nil")
	}
	if !strings.Contains(err.Error(), "cap exhausted") {
		t.Fatalf("shared cap: err=%v, want cap-exhausted error", err)
	}
	if !sum.stallDetected || sum.stallReconnect != 3 {
		t.Fatalf("shared cap: detected=%v reconnects=%d, want true/3", sum.stallDetected, sum.stallReconnect)
	}
	if sum.stallPageBumps != 1 {
		t.Fatalf("shared cap: page_bumps=%d, want 1 (only the gen0 bump)", sum.stallPageBumps)
	}
	if sum.stallGenerations != 4 {
		t.Fatalf("shared cap: generations=%d, want 4", sum.stallGenerations)
	}
	if sum.stallObjectsRetried != 8 {
		t.Fatalf("shared cap: objects_retried=%d, want 8 (4 per successful object-mode bump x2)", sum.stallObjectsRetried)
	}
}

// ---- V7-A F arm: first-byte latency recording (P-1) ----
//
// The hook fires exactly once per fetch, on the first body byte; a
// fetch that never delivers a body byte records nothing (no sample is
// ever fabricated). Recording is off when the sink is nil, which keeps
// every existing fetch path byte-identical.

func TestProgressReaderFirstHookOnce(t *testing.T) {
	var reported []int64
	firsts := 0
	pr := &progressReader{
		r:      strings.NewReader("hello world"),
		report: func(n int64) { reported = append(reported, n) },
		first:  func() { firsts++ },
	}
	buf := make([]byte, 4)
	var total int
	for {
		n, err := pr.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if total != 11 {
		t.Fatalf("total=%d, want 11", total)
	}
	if firsts != 1 {
		t.Fatalf("first firings=%d, want 1", firsts)
	}
	var sum int64
	for _, n := range reported {
		sum += n
	}
	if sum != 11 {
		t.Fatalf("reported sum=%d, want 11 (report path unchanged by first hook)", sum)
	}
}

func TestProgressReaderFirstHookNoByteNoFire(t *testing.T) {
	firsts := 0
	pr := &progressReader{r: strings.NewReader(""), first: func() { firsts++ }}
	if _, err := io.ReadAll(pr); err != nil {
		t.Fatalf("read: %v", err)
	}
	if firsts != 0 {
		t.Fatalf("first firings=%d, want 0 (zero-byte read must not fabricate)", firsts)
	}
}

func TestFirstByteRecordedMemPair(t *testing.T) {
	srv, objAddr, key := recoverableTestSetup(t, plainObjMux())
	dial := recoverableTestDial(t, srv, objAddr, key)
	sess, err := dial(0)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.close()
	fbLog := &firstByteLog{}
	sess.fetcher.firstByte = fbLog
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, _, err := sess.fetcher.fetchObject(ctx, 8192); err != nil {
		t.Fatalf("fetchObject: %v", err)
	}
	if _, _, err := sess.fetcher.fetchObjectProgress(ctx, 4096, nil); err != nil {
		t.Fatalf("fetchObjectProgress: %v", err)
	}
	// A failed fetch (400, before any body byte) records nothing.
	if _, _, err := sess.fetcher.fetchObject(ctx, 0); err == nil {
		t.Fatal("fetchObject(0): want error, got nil")
	}
	recs := fbLog.snapshot()
	if len(recs) != 2 {
		t.Fatalf("records=%d, want 2 (failed fetch must not fabricate)", len(recs))
	}
	if recs[0].Size != 8192 || recs[1].Size != 4096 {
		t.Fatalf("sizes=%d/%d, want 8192/4096", recs[0].Size, recs[1].Size)
	}
	for i, r := range recs {
		if r.FirstByteMs < 0 || r.FirstByteMs >= 60000 {
			t.Fatalf("record %d: first_byte_ms=%v, want [0, 60000)", i, r.FirstByteMs)
		}
	}
}
