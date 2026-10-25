// Initial codec safety gate: keep the test-only random-ciphertext Initial
// off public networks.
//
// Background: Phase 1 uses RandomCiphertextCodec, whose payload is random
// ciphertext inside a QUIC long header. That is a recognizable fingerprint
// for any DPI on the path, so it must never run on a real network, even by
// accident. Phase 0 will replace it with the real RFC 9001 QUIC Initial.
//
// This file implements the startup check requested in the 2026-10-23 review:
//   - if the codec is not production-safe (anything other than the future
//     Phase 0 QUICInitialCodec),
//   - and the listen/peer address is not a loopback/private address,
// then startup/config is refused with an explicit error.
//
// Fail-closed: unknown codec implementations and unresolvable/unspecified
// addresses are treated as unsafe.
package mistcore

import (
	"fmt"
	"net"
	"strings"
)

// ProductionSafeCodec is an optional marker an InitialCodec may implement.
// Phase 0's QUICInitialCodec must implement ProductionSafe() returning true.
// RandomCiphertextCodec (and any codec not implementing this interface)
// is treated as test-only and unsafe for public networks.
type ProductionSafeCodec interface {
	InitialCodec
	ProductionSafe() bool
}

// CodecProductionSafe reports whether the given InitialCodec is allowed on
// public networks. Unknown implementations (no ProductionSafe method) are
// unsafe by default.
func CodecProductionSafe(codec InitialCodec) bool {
	if ps, ok := codec.(interface{ ProductionSafe() bool }); ok {
		return ps.ProductionSafe()
	}
	return false
}

// ProductionSafe marks RandomCiphertextCodec as test-only.
// It must never be used on a public network (see CheckInitialCodecSafeForAddr).
func (c *RandomCiphertextCodec) ProductionSafe() bool { return false }

// IsPrivateOrLoopbackIP reports whether ip is a loopback, RFC 1918 / ULA
// private, or link-local address. Zone identifiers (fe80::1%eth0) are stripped
// before parsing; unparseable input returns false.
func IsPrivateOrLoopbackIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// resolveHostToIP resolves a host string to an IP without dialing.
// "localhost" maps to 127.0.0.1. IP literals (with optional zone) parse
// directly. Other names go through the resolver; resolution failure means
// the caller must treat the address as unsafe.
func resolveHostToIP(host string) net.IP {
	if host == "" {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return net.ParseIP("127.0.0.1")
	}
	// Strip zone identifier before parsing (ParseIP rejects zones).
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	// DNS name: resolve. A nil result (or error) is unsafe, not private.
	ipAddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil
	}
	return ipAddr.IP
}

// hostFromAddr extracts the host part of "host:port", "[v6]:port", or a bare
// host. Empty string means unspecified.
func hostFromAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(addr, "[]")
}

// CheckInitialCodecSafeForAddr enforces the safety gate.
//
// If codec is production-safe (per CodecProductionSafe), any address is
// allowed and nil is returned.
//
// Otherwise the codec is test-only (currently RandomCiphertextCodec) and the
// address must be a loopback or private address (127.0.0.1, 10.x, 192.168.x,
// ::1, ...). Unspecified listen addresses (0.0.0.0, ::, empty host) are
// rejected: they bind all interfaces, including public ones. Unresolvable
// hostnames are rejected as well (fail closed).
//
// The returned error names the problem in Chinese so it is actionable on a
// phone screen: 随机密文 Initial 不能用于真实网络.
func CheckInitialCodecSafeForAddr(codec InitialCodec, addr string) error {
	if CodecProductionSafe(codec) {
		return nil
	}
	host := hostFromAddr(addr)
	ip := resolveHostToIP(host)
	if ip == nil || ip.IsUnspecified() {
		return fmt.Errorf("mist: 随机密文 Initial 不能用于真实网络 (codec=%T, addr=%q): "+
			"监听/目标地址未指定或不可解析，fail closed；内测请显式绑定 127.0.0.1 或内网地址", codec, addr)
	}
	if !IsPrivateOrLoopbackIP(ip) {
		return fmt.Errorf("mist: 随机密文 Initial 不能用于真实网络 (codec=%T, addr=%q): "+
			"随机密文 Initial 是可识别的指纹，仅限内网/回环测试；公网请等待 Phase 0 真 QUIC Initial", codec, addr)
	}
	return nil
}
