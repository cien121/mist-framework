package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
