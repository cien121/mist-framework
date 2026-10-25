package mobile

import "testing"

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
