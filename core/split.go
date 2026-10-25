// Split routing, DNS-leak protection and DNS-layer ad blocking.
//
// Decision mechanism (v1, domain-driven — read this before changing
// it): there is NO embedded CN CIDR table in v1, deliberately.
// The data path never guesses a country from an IP range. Instead:
//   - a domain is domestic iff it matches domesticDomainSuffixes
//     (suffix rule) or ends in .cn (see isDomesticDomain);
//   - a domestic domain's LOCAL resolution (see resolveViaLocalDNS)
//     records its answer IPs in learnedIPs (10-minute TTL, 4096 cap);
//   - an IP routes direct iff it is private/reserved/loopback, or
//     it was learned from a domestic-domain local resolution;
//   - a literal IP with no domestic-resolution record defaults to
//     the TUNNEL (fail-safe direction: slower is better than
//     leaking foreign traffic direct).
//
// A full CN CIDR table is a later enhancement, not a v1 requirement:
// the overwhelming majority of app traffic connects by domain, so
// the DNS learning path already covers it.
//
// Priority: the Android per-app rules run BEFORE the engine (traffic
// from an excluded app never enters the TUN, so the engine never
// sees it). Engine split routing only applies to traffic that did
// enter the TUN. No extra code is needed for that ordering; it is
// stated here so nobody "fixes" it by re-implementing per-app
// filtering inside the engine.
//
// Direct sockets: a direct dial is a plain Go socket created by the
// Weave process itself. Weave is excluded from its own VPN via
// VpnService.Builder.addDisallowedApplication, so the process's own
// sockets bypass the TUN by UID and cannot loop back into the
// engine. That is why no Android protect() hook is needed on the
// direct path (same reasoning as the existing Mist socket).
//
// DNS interception point: handleUDP's port-53 path, in this order:
// adblock check first (independent of SplitEnabled: with split off,
// ads are still blocked before the tunnel), then — only when split
// is on and the query domain is domestic — local resolution, else
// the existing tagged tunnel path.
//
// Out of scope for v1 (documented, not forgotten): DNS-over-TCP
// (port 53 TCP goes through the normal TCP split/tunnel decision by
// destination IP, not by domain) and DNS-over-HTTPS (port 443 TLS;
// it is ordinary TCP/TLS traffic to the resolver's IP and is
// routed by the same IP rule). Neither is intercepted at the DNS
// layer here.
package core

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// learnedIPTTL is how long a domestic-resolution IP stays direct.
const learnedIPTTL = 10 * time.Minute

// maxLearnedIPs caps the learned-IP set.
const maxLearnedIPs = 4096

// defaultLocalDNS are the domestic public resolvers used when no
// explicit local DNS is configured (SetLocalDNS with an empty
// string restores these).
var defaultLocalDNS = []string{"223.5.5.5:53", "114.114.114.114:53"}

// localDNSDialTimeout bounds one local-resolver attempt.
const localDNSDialTimeout = 3 * time.Second

// reservedCIDRs are the non-routable/reserved ranges treated as
// direct alongside Go's IsPrivate/IsLoopback/IsLinkLocal checks.
var reservedCIDRs = func() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range []string{
		"100.64.0.0/10",   // CGNAT shared address space
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved
		"2001:db8::/32",   // documentation
	} {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// isPrivateOrReservedIP reports whether ip is private, loopback,
// link-local, multicast, unspecified, or in a reserved range.
func isPrivateOrReservedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, n := range reservedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// matchSuffix reports whether domain equals entry or ends with
// "."+entry (case-insensitive; callers lowercase first).
func matchSuffix(domain, entry string) bool {
	return domain == entry || strings.HasSuffix(domain, "."+entry)
}

// isDomesticDomain reports whether a query domain is domestic: an
// exact/suffix match in domesticDomainSuffixes, or any .cn suffix.
func isDomesticDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return false
	}
	if strings.HasSuffix(d, ".cn") || d == "cn" {
		return true
	}
	for _, s := range domesticDomainSuffixes {
		if matchSuffix(d, s) {
			return true
		}
	}
	return false
}

// isAdblockDomain reports whether a query domain is a pure ad /
// unambiguous tracker domain from the conservative seed list.
func isAdblockDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return false
	}
	for _, s := range adblockDomainSuffixes {
		if matchSuffix(d, s) {
			return true
		}
	}
	return false
}

// learnIP records ip as domestic-resolved until learnedIPTTL from
// now. Expired entries are pruned first; at the cap the oldest
// entry is evicted so the set can never grow without bound.
func (e *Engine) learnIP(ip string) {
	if ip == "" {
		return
	}
	now := time.Now()
	e.learnedMu.Lock()
	defer e.learnedMu.Unlock()
	var oldest string
	var oldestExp time.Time
	for k, exp := range e.learnedIPs {
		if now.After(exp) {
			delete(e.learnedIPs, k)
			continue
		}
		if oldest == "" || exp.Before(oldestExp) {
			oldest, oldestExp = k, exp
		}
	}
	if len(e.learnedIPs) >= maxLearnedIPs && oldest != "" {
		delete(e.learnedIPs, oldest)
	}
	e.learnedIPs[ip] = now.Add(learnedIPTTL)
}

// isLearnedIP reports whether ip is a live learned domestic IP.
func (e *Engine) isLearnedIP(ip string) bool {
	e.learnedMu.Lock()
	defer e.learnedMu.Unlock()
	exp, ok := e.learnedIPs[ip]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(e.learnedIPs, ip)
		return false
	}
	return true
}

// shouldDirect reports whether traffic to dstIP (string form) must
// bypass the tunnel. Split off => never direct. Private/reserved/
// loopback => always direct. Otherwise only learned domestic IPs.
func (e *Engine) shouldDirect(dstIP string) bool {
	if !e.splitEnabled.Load() {
		return false
	}
	ip := net.ParseIP(dstIP)
	if ip == nil {
		return false
	}
	if isPrivateOrReservedIP(ip) {
		return true
	}
	return e.isLearnedIP(dstIP)
}

// parseLocalDNSServers normalizes a comma-separated server list:
// bare IPs get :53 appended (bare IPv6 is bracketed first, since an
// unbracketed "2001:...::8888:53" is unparseable as host:port);
// entries already carrying a port are used as-is. Empty input
// returns the default domestic resolvers.
func parseLocalDNSServers(servers string) []string {
	if strings.TrimSpace(servers) == "" {
		out := make([]string, len(defaultLocalDNS))
		copy(out, defaultLocalDNS)
		return out
	}
	var out []string
	for _, s := range strings.Split(servers, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			if ip.To4() == nil {
				s = "[" + s + "]:53"
			} else {
				s += ":53"
			}
		} else if !strings.Contains(s, ":") {
			s += ":53"
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return parseLocalDNSServers("")
	}
	return out
}

// localDNSServers returns the engine's current local resolvers.
func (e *Engine) localDNSServers() []string {
	e.localDNSMu.RLock()
	defer e.localDNSMu.RUnlock()
	out := make([]string, len(e.localDNS))
	copy(out, e.localDNS)
	return out
}

// SetLocalDNS replaces the local resolvers (comma-separated;
// empty restores the default domestic public DNS). Safe to call
// while the engine is running.
func (e *Engine) SetLocalDNS(servers string) {
	e.localDNSMu.Lock()
	e.localDNS = parseLocalDNSServers(servers)
	e.localDNSMu.Unlock()
}

// SetSplitEnabled atomically toggles split routing on a live engine.
func (e *Engine) SetSplitEnabled(enabled bool) { e.splitEnabled.Store(enabled) }

// SetAdblockEnabled atomically toggles DNS ad blocking on a live engine.
func (e *Engine) SetAdblockEnabled(enabled bool) { e.adblockEnabled.Store(enabled) }

// ---------------------------------------------------------------------------
// Minimal DNS question/answer parsing.
//
// Only the question section is parsed for routing decisions (QNAME,
// QTYPE). When forwarding a query to a local resolver, the ORIGINAL
// query bytes are forwarded verbatim and the response bytes are
// returned verbatim — answers are never re-encoded, so txID,
// flags and question bytes survive untouched. Answer parsing is
// used only to learn A/AAAA addresses into learnedIPs, and it
// tolerates compression pointers (answers point back at the
// question name).
// ---------------------------------------------------------------------------

var (
	errShortDNS   = errors.New("dns: packet too short")
	errBadDNSName = errors.New("dns: bad name")
)

// parseDNSQuestion parses the first question of a DNS query.
// Returns the lowercased QNAME (no trailing dot), QTYPE, and the
// offset just past the question section (for adblock responses,
// which must echo the question bytes verbatim).
func parseDNSQuestion(q []byte) (name string, qtype uint16, qEnd int, err error) {
	if len(q) < 12 {
		return "", 0, 0, errShortDNS
	}
	qd := int(binary.BigEndian.Uint16(q[4:6]))
	if qd < 1 {
		return "", 0, 0, errBadDNSName
	}
	off := 12
	var labels []string
	for {
		if off >= len(q) {
			return "", 0, 0, errBadDNSName
		}
		l := int(q[off])
		if l == 0 {
			off++
			break
		}
		// Questions do not use compression; a pointer here is
		// malformed input, not something to follow.
		if l&0xC0 != 0 {
			return "", 0, 0, errBadDNSName
		}
		if l > 63 || off+1+l > len(q) {
			return "", 0, 0, errBadDNSName
		}
		labels = append(labels, strings.ToLower(string(q[off+1:off+1+l])))
		off += 1 + l
	}
	if off+4 > len(q) {
		return "", 0, 0, errBadDNSName
	}
	qtype = binary.BigEndian.Uint16(q[off : off+2])
	return strings.Join(labels, "."), qtype, off + 4, nil
}

// skipDNSName advances past a (possibly compressed) name at off,
// following pointers with a bounded jump count. It returns the
// offset after the name in the ORIGINAL stream (after the pointer
// bytes when a pointer was used).
func skipDNSName(msg []byte, off int) (int, error) {
	jumps := 0
	for {
		if off >= len(msg) {
			return 0, errBadDNSName
		}
		l := int(msg[off])
		if l == 0 {
			return off + 1, nil
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return 0, errBadDNSName
			}
			if jumps >= 10 {
				return 0, errBadDNSName
			}
			jumps++
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
			if jumps == 1 {
				// The stream continues after the pointer itself.
				next := off + 2
				// Walk the pointed-to name for validity, then
				// return next (not the pointed offset).
				if _, err := skipDNSName(msg, ptr); err != nil {
					return 0, err
				}
				return next, nil
			}
			off = ptr
			continue
		}
		if l > 63 || off+1+l > len(msg) {
			return 0, errBadDNSName
		}
		off += 1 + l
	}
}

// learnFromDNSResponse records every A/AAAA answer address in a
// DNS response into learnedIPs. Unparseable tails are ignored:
// learning is best-effort and must never break the response path.
func (e *Engine) learnFromDNSResponse(resp []byte) {
	if len(resp) < 12 {
		return
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		next, err := skipDNSName(resp, off)
		if err != nil || next+4 > len(resp) {
			return
		}
		off = next + 4
	}
	for i := 0; i < an; i++ {
		next, err := skipDNSName(resp, off)
		if err != nil || next+10 > len(resp) {
			return
		}
		typ := binary.BigEndian.Uint16(resp[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(resp[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(resp) {
			return
		}
		switch {
		case typ == 1 && rdlen == 4:
			e.learnIP(net.IP(resp[rdata : rdata+4]).String())
		case typ == 28 && rdlen == 16:
			e.learnIP(net.IP(resp[rdata : rdata+16]).String())
		}
		off = rdata + rdlen
	}
}

// resolveViaLocalDNS forwards query bytes verbatim to the first
// local resolver that answers, and returns the response bytes
// verbatim. It uses a plain Go UDP socket (direct, never through
// the tunnel — same UID-bypass reasoning as the direct data path).
// A nil/empty answer or any error moves to the next server; if all
// fail, the caller falls back to the tunnel path.
func (e *Engine) resolveViaLocalDNS(query []byte) ([]byte, error) {
	dial := e.localDNSDial
	if dial == nil {
		dial = net.DialTimeout
	}
	var lastErr error
	for _, srv := range e.localDNSServers() {
		conn, err := dial("udp", srv, localDNSDialTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(localDNSDialTimeout))
		if _, err := conn.Write(query); err != nil {
			lastErr = err
			conn.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil || n == 0 {
			lastErr = err
			continue
		}
		return append([]byte(nil), buf[:n]...), nil
	}
	if lastErr == nil {
		lastErr = errors.New("dns: no local resolver configured")
	}
	return nil, lastErr
}

// buildAdblockResponse builds a null answer for query: it preserves
// the query ID and the question section verbatim, sets QR=1 and
// RA=1 (RCODE cleared to NOERROR), and for A returns 0.0.0.0, for
// AAAA returns ::, for any other type returns no answers. It
// returns ok=false when the query cannot be parsed.
func buildAdblockResponse(query []byte) ([]byte, bool) {
	_, qtype, qEnd, err := parseDNSQuestion(query)
	if err != nil || qEnd > len(query) {
		return nil, false
	}
	flags := binary.BigEndian.Uint16(query[2:4])
	flags |= 0x8000  // QR
	flags |= 0x0080  // RA
	flags &^= 0x000F // RCODE = NOERROR
	out := make([]byte, 0, qEnd+32)
	out = append(out, query[0], query[1]) // ID preserved
	var fb [2]byte
	binary.BigEndian.PutUint16(fb[:], flags)
	out = append(out, fb[:]...)
	// QDCOUNT preserved, ANCOUNT per type, NSCOUNT/ARCOUNT zero.
	out = append(out, query[4], query[5])
	var cnt [2]byte
	if qtype == 1 || qtype == 28 {
		binary.BigEndian.PutUint16(cnt[:], 1)
	} else {
		binary.BigEndian.PutUint16(cnt[:], 0)
	}
	out = append(out, cnt[:]...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, query[12:qEnd]...) // question verbatim
	if qtype == 1 || qtype == 28 {
		out = append(out, 0xC0, 0x0C) // NAME: pointer to question
		binary.BigEndian.PutUint16(cnt[:], qtype)
		out = append(out, cnt[:]...)
		binary.BigEndian.PutUint16(cnt[:], 1) // CLASS IN
		out = append(out, cnt[:]...)
		var ttl [4]byte
		binary.BigEndian.PutUint32(ttl[:], 60)
		out = append(out, ttl[:]...)
		if qtype == 1 {
			binary.BigEndian.PutUint16(cnt[:], 4)
			out = append(out, cnt[:]...)
			out = append(out, 0, 0, 0, 0)
		} else {
			binary.BigEndian.PutUint16(cnt[:], 16)
			out = append(out, cnt[:]...)
			out = append(out, make([]byte, 16)...)
		}
	}
	return out, true
}
