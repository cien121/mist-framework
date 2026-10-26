package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
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
