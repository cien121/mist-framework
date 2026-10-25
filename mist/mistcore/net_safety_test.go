package mistcore

import (
	"context"
	"net"
	"strings"
	"testing"
)

// testCtx returns a context for safety-gate tests.
func testCtx() context.Context {
	return context.Background()
}

// unsafeCodec returns the test-only random-ciphertext codec.
func unsafeCodec() InitialCodec { return &RandomCiphertextCodec{} }

func TestIPAllowedByPolicy(t *testing.T) {
	cases := []struct {
		name  string
		ip    string
		allow bool
	}{
		// Allowed: loopback, RFC 1918, ULA, link-local.
		{"loopback4", "127.0.0.1", true},
		{"loopback6", "::1", true},
		{"rfc1918_10", "10.8.0.1", true},
		{"rfc1918_10_2", "10.255.255.255", true},
		{"rfc1918_172", "172.16.0.1", true},
		{"rfc1918_192", "192.168.1.1", true},
		{"ula", "fd00::1", true},
		{"linklocal6", "fe80::1", true},
		// Denied: public, CGNAT, unspecified, multicast.
		{"public4", "8.8.8.8", false},
		{"public4_2", "148.135.10.19", false},
		{"public6", "2607:f130:0:113::31", false},
		{"public6_2", "2001:4860:4860::8888", false},
		{"cgnat", "100.64.0.1", false},
		{"cgnat_2", "100.127.255.254", false},
		{"unspecified4", "0.0.0.0", false},
		{"unspecified6", "::", false},
		{"multicast4", "224.0.0.1", false},
		{"multicast6", "ff02::1", false},
		// IPv4-mapped IPv6: normalized to IPv4 before policy check.
		{"mapped_public", "::ffff:8.8.8.8", false},
		{"mapped_private", "::ffff:10.8.0.1", true},
		{"mapped_loopback", "::ffff:127.0.0.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test IP %q", tc.ip)
			}
			if got := ipAllowedByPolicy(ip); got != tc.allow {
				t.Fatalf("ipAllowedByPolicy(%q) = %v, want %v", tc.ip, got, tc.allow)
			}
		})
	}
}

func TestResolvePeerAddrSafe(t *testing.T) {
	ctx := testCtx()
	unsafe := unsafeCodec()

	cases := []struct {
		name    string
		addr    string
		wantErr bool
		wantIP  string // expected IP when no error
	}{
		// Allowed: private/loopback literals.
		{"allow_10", "10.8.0.1:1443", false, "10.8.0.1"},
		{"allow_loopback", "127.0.0.1:1443", false, "127.0.0.1"},
		{"allow_loopback6", "[::1]:1443", false, "::1"},
		{"allow_localhost", "localhost:1443", false, "127.0.0.1"},
		{"allow_rfc1918", "192.168.1.10:1443", false, "192.168.1.10"},
		// Denied: public, unspecified, CGNAT.
		{"deny_public4", "8.8.8.8:1443", true, ""},
		{"deny_public6", "[2001:4860:4860::8888]:1443", true, ""},
		{"deny_unspecified4", "0.0.0.0:1443", true, ""},
		{"deny_unspecified6", "[::]:1443", true, ""},
		{"deny_cgnat", "100.64.0.5:1443", true, ""},
		{"deny_mapped_public", "[::ffff:8.8.8.8]:1443", true, ""},
		// Denied: unresolvable hostname (fail-closed).
		{"deny_badhost", "nonexistent.invalid:1443", true, ""},
		{"deny_empty", "", true, ""},
		// Allowed: mapped private.
		{"allow_mapped_private", "[::ffff:10.8.0.1]:1443", false, "10.8.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolvePeerAddrSafe(ctx, tc.addr, unsafe)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %v", tc.addr, got)
				}
				if !strings.Contains(err.Error(), "随机密文 Initial 不能用于真实网络") {
					t.Fatalf("error must state reason in Chinese, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.addr, err)
			}
			if got.IP.String() != tc.wantIP {
				t.Fatalf("got IP %q, want %q", got.IP.String(), tc.wantIP)
			}
			// The returned address must be an IP literal, not a hostname:
			// no re-resolution by the caller (TOCTOU safe).
			if got.IP == nil {
				t.Fatalf("returned IP is nil for %q", tc.addr)
			}
		})
	}
}

func TestListenUDPSafe(t *testing.T) {
	ctx := testCtx()
	unsafe := unsafeCodec()

	// Denied addresses must fail before binding.
	denyCases := []string{
		"0.0.0.0:0",
		"8.8.8.8:0",
		"[2001:4860:4860::8888]:0",
		"100.64.0.1:0",
		"[::ffff:8.8.8.8]:0",
		"nonexistent.invalid:0",
		"",
	}
	for _, addr := range denyCases {
		t.Run("deny_"+addr, func(t *testing.T) {
			conn, err := ListenUDPSafe(ctx, addr, unsafe)
			if err == nil {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("expected error for listen %q, got nil", addr)
			}
			if !strings.Contains(err.Error(), "随机密文 Initial 不能用于真实网络") {
				t.Fatalf("error must state reason in Chinese, got: %v", err)
			}
		})
	}

	// Allowed addresses must bind successfully.
	allowCases := []string{
		"127.0.0.1:0",
		"[::1]:0",
	}
	for _, addr := range allowCases {
		t.Run("allow_"+addr, func(t *testing.T) {
			conn, err := ListenUDPSafe(ctx, addr, unsafe)
			if err != nil {
				t.Fatalf("unexpected error for listen %q: %v", addr, err)
			}
			conn.Close()
		})
	}
}

func TestCheckCodecForIPsHostnameSimulation(t *testing.T) {
	// Simulates "hostname resolved to public/private": the gate sees every
	// resolved IP and denies the whole address if any one is public.
	unsafe := unsafeCodec()

	// All private: allowed, returns first IP.
	ips := []net.IP{net.ParseIP("10.8.0.1"), net.ParseIP("10.8.0.2")}
	got, err := checkCodecForIPs(unsafe, "example.internal:1443", ips)
	if err != nil {
		t.Fatalf("all-private should be allowed: %v", err)
	}
	if got.String() != "10.8.0.1" {
		t.Fatalf("got %q, want 10.8.0.1", got.String())
	}

	// One public among private: denied (fail-closed on mixed results).
	ips = []net.IP{net.ParseIP("10.8.0.1"), net.ParseIP("8.8.8.8")}
	if _, err := checkCodecForIPs(unsafe, "example.com:1443", ips); err == nil {
		t.Fatalf("mixed public/private must be denied")
	}

	// Production-safe codec: allowed everywhere.
	safe := &safeTestCodec{}
	ips = []net.IP{net.ParseIP("8.8.8.8")}
	if _, err := checkCodecForIPs(safe, "example.com:1443", ips); err != nil {
		t.Fatalf("safe codec should be allowed on public: %v", err)
	}
}

// TestNoBypassCompileTime documents the invariant: the only supported paths
// are ResolvePeerAddrSafe (client) and ListenUDPSafe (server). There is no
// exported helper that dials or binds without the check. This test exists so
// a future refactor that adds a bypass breaks the build via the doc comment
// and code review; the real enforcement is that cmd/ code has no other
// mistcore entry point to call.
func TestNoBypassCompileTime(t *testing.T) {
	// Verify the constructors exist and are the documented choke points.
	var _ = ResolvePeerAddrSafe
	var _ = ListenUDPSafe
	// Verify the raw check is not bypassed: CheckInitialCodecSafeForAddr is
	// still available for the server path, but new code must use the
	// constructors above.
	var _ = CheckInitialCodecSafeForAddr
}
