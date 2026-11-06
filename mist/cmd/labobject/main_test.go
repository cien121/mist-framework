package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestObjDeterministic(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/obj/", handleObj)
	s := httptest.NewServer(mux)
	defer s.Close()
	get := func() []byte {
		t.Helper()
		resp, err := http.Get(s.URL + "/obj/1024")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status=%d", resp.StatusCode)
		}
		if resp.ContentLength != 1024 {
			t.Fatalf("content-length=%d", resp.ContentLength)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, b := get(), get()
	if len(a) != 1024 || len(b) != 1024 {
		t.Fatalf("len=%d/%d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] || a[i] != fillByte(i) {
			t.Fatalf("byte %d differs", i)
		}
	}
}

func TestObjBounds(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/obj/", handleObj)
	s := httptest.NewServer(mux)
	defer s.Close()
	for _, path := range []string{"/obj/0", "/obj/-5", "/obj/abc", "/obj/99999999"} {
		resp, err := http.Get(s.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("%s: status=%d, want 400", path, resp.StatusCode)
		}
	}
}

func TestPageListFrozen(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", handlePage)
	s := httptest.NewServer(mux)
	defer s.Close()
	resp, err := http.Get(s.URL + "/page/a")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc pageDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID != "a" {
		t.Fatalf("id=%q", doc.ID)
	}
	if len(doc.Objects) != 15 {
		t.Fatalf("objects=%d, want 15", len(doc.Objects))
	}
	sum := 0
	for _, n := range doc.Objects {
		sum += n
	}
	if sum != 1032192 {
		t.Fatalf("page total=%d, want 1032192", sum)
	}
}

// ---- V7-A M-page arm: -page-delay knob (P-2) ----
//
// The knob delays only the /page/ body; /obj/ is untouched, and the
// default 0 keeps behavior identical to before the knob existed.

func TestPageDelayDefault(t *testing.T) {
	pageDelay = 0
	defer func() { pageDelay = 0 }()
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", handlePage)
	s := httptest.NewServer(mux)
	defer s.Close()
	start := time.Now()
	resp, err := http.Get(s.URL + "/page/a")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc pageDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Objects) != 15 {
		t.Fatalf("objects=%d, want 15", len(doc.Objects))
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("default delay too slow: %v", time.Since(start))
	}
}

func TestPageDelayApplies(t *testing.T) {
	pageDelay = 300 * time.Millisecond
	defer func() { pageDelay = 0 }()
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", handlePage)
	s := httptest.NewServer(mux)
	defer s.Close()
	start := time.Now()
	resp, err := http.Get(s.URL + "/page/a")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc pageDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed < 300*time.Millisecond {
		t.Fatalf("elapsed=%v, want >= 300ms", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("elapsed=%v, want < 10s", elapsed)
	}
	if len(doc.Objects) != 15 {
		t.Fatalf("objects=%d, want 15 (delay must not corrupt the page)", len(doc.Objects))
	}
}

func TestPageDelayCancelled(t *testing.T) {
	pageDelay = 30 * time.Second
	defer func() { pageDelay = 0 }()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	req := httptest.NewRequest(http.MethodGet, "/page/a", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	start := time.Now()
	handlePage(rec, req)
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("cancelled delay took %v, want < 5s", elapsed)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("cancelled delay wrote %d body bytes, want 0", rec.Body.Len())
	}
}

// ---- V7-A M-core phase layouts (design §2.1) ----
//
// "full" satisfies P-full (8 objects, min >= max/4); "tail" satisfies
// P-tail (3 fast + 1 slow). Any other id keeps the frozen page.

func TestPageFullVariant(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", handlePage)
	s := httptest.NewServer(mux)
	defer s.Close()
	resp, err := http.Get(s.URL + "/page/full")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc pageDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Objects) != 8 {
		t.Fatalf("full objects=%d, want 8", len(doc.Objects))
	}
	min, max, sum := doc.Objects[0], doc.Objects[0], 0
	for _, n := range doc.Objects {
		if n < min {
			min = n
		}
		if n > max {
			max = n
		}
		sum += n
	}
	if min*4 < max {
		t.Fatalf("full min=%d max=%d, want min >= max/4", min, max)
	}
	if sum != 1212416 {
		t.Fatalf("full total=%d, want 1212416", sum)
	}
}

func TestPageTailVariant(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", handlePage)
	s := httptest.NewServer(mux)
	defer s.Close()
	resp, err := http.Get(s.URL + "/page/tail")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc pageDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Objects) != 4 {
		t.Fatalf("tail objects=%d, want 4", len(doc.Objects))
	}
	for i := 0; i < 3; i++ {
		if doc.Objects[i] != 16384 {
			t.Fatalf("tail object %d=%d, want 16384", i, doc.Objects[i])
		}
	}
	if doc.Objects[3] != 262144 {
		t.Fatalf("tail slow object=%d, want 262144", doc.Objects[3])
	}
}

func TestPageUnknownIdKeepsFrozen(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/page/", handlePage)
	s := httptest.NewServer(mux)
	defer s.Close()
	resp, err := http.Get(s.URL + "/page/zzz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc pageDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Objects) != 15 {
		t.Fatalf("unknown id objects=%d, want frozen 15", len(doc.Objects))
	}
}
