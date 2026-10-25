// Signature hardening tests (client side): node-link parsing for
// ports/hop/v6, and deterministic hop-port derivation.
//
// Functional correctness only: green tests here do not say anything
// about DPI resistance.
package core

import (
	"testing"
)

const testNodeKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func testNodeURL(host string, extra string) string {
	u := "mist://0123456789abcdef0123456789abcdef@" + host + "?key=" + testNodeKey
	if extra != "" {
		u += "&" + extra
	}
	return u
}

func TestParseMistURLHopDefaults(t *testing.T) {
	cfg, err := ParseMistURL(testNodeURL("127.0.0.1:8443", "ports=8443-8474"))
	if err != nil {
		t.Fatalf("ParseMistURL: %v", err)
	}
	if !cfg.HopEnabled() || cfg.HopPortsBase != 8443 || cfg.HopPortsLast != 8474 {
		t.Fatalf("hop range = %d-%d enabled=%v", cfg.HopPortsBase, cfg.HopPortsLast, cfg.HopEnabled())
	}
	if cfg.HopIntervalSec != 30 {
		t.Fatalf("default hop interval = %d, want 30", cfg.HopIntervalSec)
	}
	if cfg.HopPortCount() != 32 {
		t.Fatalf("hop count = %d, want 32", cfg.HopPortCount())
	}
}

func TestParseMistURLNoPortsMeansNoHop(t *testing.T) {
	cfg, err := ParseMistURL(testNodeURL("127.0.0.1:8443", "sni=example.com"))
	if err != nil {
		t.Fatalf("ParseMistURL: %v", err)
	}
	if cfg.HopEnabled() {
		t.Fatal("node without ports must not enable hopping")
	}
	// A hop= parameter without ports is inert, not an error.
	cfg, err = ParseMistURL(testNodeURL("127.0.0.1:8443", "hop=30"))
	if err != nil {
		t.Fatalf("ParseMistURL: %v", err)
	}
	if cfg.HopEnabled() {
		t.Fatal("hop= without ports must not enable hopping")
	}
}

func TestParseMistURLV6Literal(t *testing.T) {
	cfg, err := ParseMistURL(testNodeURL("[2001:db8::1]:8443", "ports=8443-8474&hop=30"))
	if err != nil {
		t.Fatalf("ParseMistURL v6: %v", err)
	}
	if cfg.Server != "[2001:db8::1]:8443" {
		t.Fatalf("Server = %q, want bracketed form preserved", cfg.Server)
	}
	if !cfg.HopEnabled() {
		t.Fatal("v6 node with ports should enable hopping")
	}
}

func TestParseMistURLHopClampAndReject(t *testing.T) {
	cfg, err := ParseMistURL(testNodeURL("127.0.0.1:8443", "ports=8443-8474&hop=5"))
	if err != nil {
		t.Fatalf("ParseMistURL: %v", err)
	}
	if cfg.HopIntervalSec != 10 {
		t.Fatalf("hop=5 clamped to %d, want 10", cfg.HopIntervalSec)
	}
	cfg, err = ParseMistURL(testNodeURL("127.0.0.1:8443", "ports=8443-8474&hop=500"))
	if err != nil {
		t.Fatalf("ParseMistURL: %v", err)
	}
	if cfg.HopIntervalSec != 120 {
		t.Fatalf("hop=500 clamped to %d, want 120", cfg.HopIntervalSec)
	}
	for _, bad := range []string{
		"ports=8443", "ports=8474-8443", "ports=0-10", "ports=8443-99999",
		"ports=8443-9000", "ports=abc-def", "ports=8443-8474&hop=abc",
	} {
		if _, err := ParseMistURL(testNodeURL("127.0.0.1:8443", bad)); err == nil {
			t.Fatalf("ports/hop %q should be rejected", bad)
		}
	}
	// >256 ports rejected (8443-9000 above is 558 ports).
	if _, err := ParseMistURL(testNodeURL("127.0.0.1:8443", "ports=1000-1256")); err == nil {
		t.Fatal("257-port range should be rejected")
	}
	if _, err := ParseMistURL(testNodeURL("127.0.0.1:8443", "ports=1000-1255")); err != nil {
		t.Fatalf("256-port range should be accepted: %v", err)
	}
	// Malformed host:port rejected.
	if _, err := ParseMistURL("mist://0123456789abcdef0123456789abcdef@127.0.0.1?key=" + testNodeKey); err == nil {
		t.Fatal("missing port should be rejected")
	}
	if _, err := ParseMistURL("mist://0123456789abcdef0123456789abcdef@127.0.0.1:0?key=" + testNodeKey); err == nil {
		t.Fatal("port 0 should be rejected")
	}
	// Domain hosts still parse (resolution happens at Connect).
	if _, err := ParseMistURL(testNodeURL("example.com:8443", "")); err != nil {
		t.Fatalf("domain host should parse: %v", err)
	}
}

func TestHopPortForDeterministicAndInRange(t *testing.T) {
	var sid [16]byte
	var k [32]byte
	for i := range sid {
		sid[i] = byte(i + 3)
	}
	for i := range k {
		k[i] = byte(i + 7)
	}
	// Deterministic: same inputs always give the same port.
	a := hopPortFor(sid, k, 1000, 8443, 32)
	b := hopPortFor(sid, k, 1000, 8443, 32)
	if a != b {
		t.Fatalf("hopPortFor not deterministic: %d vs %d", a, b)
	}
	// In range across many windows, and not stuck on one port.
	seen := make(map[int]bool)
	for w := uint32(0); w < 200; w++ {
		p := hopPortFor(sid, k, w, 8443, 32)
		if p < 8443 || p > 8474 {
			t.Fatalf("window %d: port %d out of range", w, p)
		}
		seen[p] = true
	}
	if len(seen) < 2 {
		t.Fatal("hop ports never vary across windows")
	}
	// Different session keys derive different ports for the same window
	// (otherwise the derivation would not depend on key material).
	var k2 [32]byte
	for i := range k2 {
		k2[i] = byte(0xFF - i)
	}
	if hopPortFor(sid, k2, 1000, 8443, 32) == a {
		// Not a failure by itself (1/32 chance), so check across windows.
		same := 0
		for w := uint32(0); w < 32; w++ {
			if hopPortFor(sid, k2, w, 8443, 32) == hopPortFor(sid, k, w, 8443, 32) {
				same++
			}
		}
		if same > 8 {
			t.Fatalf("different keys derive identical ports too often (%d/32)", same)
		}
	}
}
