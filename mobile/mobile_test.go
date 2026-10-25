package mobile

import (
	"os"
	"testing"
)

func TestParseEgressTarget(t *testing.T) {
	cases := []struct {
		url      string
		hostPort string
		sni      string
	}{
		{"https://api.ipify.org", "api.ipify.org:443", "api.ipify.org"},
		{"https://ifconfig.me/ip", "ifconfig.me:443", "ifconfig.me"},
		{"https://example.com:8443/check?x=1", "example.com:8443", "example.com"},
		{"https://127.0.0.1/ip", "127.0.0.1:443", "127.0.0.1"},
		{"https://[2001:db8::1]/", "[2001:db8::1]:443", "2001:db8::1"},
	}
	for _, tc := range cases {
		hostPort, sni, err := parseEgressTarget(tc.url)
		if err != nil {
			t.Errorf("parseEgressTarget(%q) unexpected error: %v", tc.url, err)
			continue
		}
		if hostPort != tc.hostPort || sni != tc.sni {
			t.Errorf("parseEgressTarget(%q) = (%q, %q), want (%q, %q)",
				tc.url, hostPort, sni, tc.hostPort, tc.sni)
		}
	}
	for _, bad := range []string{"http://example.com", "https://", "://bad", "example.com", ""} {
		if _, _, err := parseEgressTarget(bad); err == nil {
			t.Errorf("parseEgressTarget(%q) expected error, got nil", bad)
		}
	}
}

func TestFetchEgressIPNotRunning(t *testing.T) {
	m := NewMobileEngine()
	if _, err := m.FetchEgressIP("https://api.ipify.org", 10); err == nil {
		t.Fatal("FetchEgressIP on a stopped engine should fail")
	}
}

func TestMobileSplitAdblockSetters(t *testing.T) {
	// Split + adblock default on; setters work stopped (stored for
	// the next Start) and running (live engine update), and the
	// direct-byte getters report 0 on a fresh engine. Start uses a
	// pipe as the TUN fd and a well-formed but unconnected mist://
	// link: Start only builds the client/engine, it never dials.
	m := NewMobileEngine()
	if m.splitEnabled != true || m.adblockEnabled != true {
		t.Fatalf("defaults = split %v adblock %v, want both true", m.splitEnabled, m.adblockEnabled)
	}
	m.SetSplitEnabled(false)
	m.SetAdblockEnabled(false)
	m.SetLocalDNS("223.5.5.5")
	if m.splitEnabled != false || m.adblockEnabled != false || m.localDNS != "223.5.5.5" {
		t.Fatalf("stopped setters not stored: split=%v adblock=%v dns=%q", m.splitEnabled, m.adblockEnabled, m.localDNS)
	}
	if m.GetDirectUploadBytes() != 0 || m.GetDirectDownloadBytes() != 0 {
		t.Fatal("direct getters on a stopped engine must be 0")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer w.Close()
	// 32 zero bytes, base64url without padding (43 chars).
	nodeURL := "mist://0123456789abcdef0123456789abcdef@127.0.0.1:8443?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=example.com"
	if err := m.Start(int(r.Fd()), nodeURL); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !m.IsRunning() {
		t.Fatal("IsRunning must be true after Start")
	}
	// Live toggles must not panic and must update stored values.
	m.SetSplitEnabled(true)
	m.SetAdblockEnabled(true)
	m.SetLocalDNS("")
	if m.splitEnabled != true || m.adblockEnabled != true || m.localDNS != "" {
		t.Fatalf("running setters not stored: split=%v adblock=%v dns=%q", m.splitEnabled, m.adblockEnabled, m.localDNS)
	}
	if m.GetDirectUploadBytes() != 0 || m.GetDirectDownloadBytes() != 0 {
		t.Fatal("direct getters on a fresh engine must be 0")
	}
	m.Stop()
	if m.IsRunning() {
		t.Fatal("IsRunning must be false after Stop")
	}
	m.Stop() // second Stop is safe
}
