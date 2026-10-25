// Mist UDP client for the independent framework.
//
// Handshake and data path replicate the proven mist-udp-test flow:
// QUIC Initial (Phase 0) + AUTH/AUTH_OK + X25519 session keys, then
// UDPSession + send scheduler + reliability layer.
//
// Stream protocol (client contract; mirrors the TCP mux path):
//   - SYN opens a stream (SID >= 1).
//   - First STREAM payload is EncodeConnectReq(atyp, addr, port).
//   - Server replies with one status byte on the same stream:
//     0x00 = connected, 0x01 = dial failed. Payload data follows
//     immediately after the status byte (offset 1+).
//
// Datagrams (UDP relay) use UDPFrameDatagram frames whose payload is
// EncodeDatagram(atyp, addr, port, data); responses carry the original
// target as their source address.
//
// NOTE: the current production UDP server is lab echo mode (it echoes
// STREAM frames, no CONNECT/dial). The server-side UDP proxy upgrade
// (CONNECT + dial + UDP relay on the UDP data path) is a separate task;
// this client implements the contract it will speak.
package core

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"
	"mist/mistcore"
)

// MistConfig configures a Mist UDP client.
type MistConfig struct {
	Server   string // "host:port" of the Mist UDP server
	ClientID string // 32 hex chars (16 bytes)
	AuthKey  string // base64 std, 32 bytes
	SNI      string // reserved for the TLS path; unused by UDP
	// HopPortsBase/HopPortsLast define the port-hop range (inclusive),
	// from the node link's ports=<base>-<last> parameter. Zero values
	// mean no hopping: the client behaves exactly like before (single
	// port, old DCID). Hopping is driven by the node link only; there
	// is no in-band capability probe.
	HopPortsBase int
	HopPortsLast int
	// HopIntervalSec is the hop window in seconds (node link hop=).
	// Defaults to 30 when hopping is enabled; clamped to [10, 120].
	HopIntervalSec int
}

// HopEnabled reports whether port hopping is configured for this node.
func (cfg MistConfig) HopEnabled() bool {
	return cfg.HopPortsBase > 0 && cfg.HopPortsLast >= cfg.HopPortsBase
}

// HopPortCount returns the number of ports in the hop range (0 if disabled).
func (cfg MistConfig) HopPortCount() int {
	if !cfg.HopEnabled() {
		return 0
	}
	return cfg.HopPortsLast - cfg.HopPortsBase + 1
}

// ParseMistURL parses a mist:// node link:
// mist://<cidHex>@<host>:<port>?key=<base64url>&sni=<domain>[&ports=<base>-<last>&hop=<sec>]#<name>
//
// The host may be a v4 literal, a bracketed v6 literal ([2001:db8::1]),
// or a domain name. Server keeps the original "host:port" spelling
// (brackets included): ResolvePeerAddrSafe's splitHostPort already
// handles "[v6]:port", and stripping the brackets early would break
// that input contract.
func ParseMistURL(raw string) (*MistConfig, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "mist" {
		return nil, fmt.Errorf("mist: not a mist:// link")
	}
	cid := u.User.Username()
	if len(cid) != 32 {
		return nil, fmt.Errorf("mist: clientId must be 32 hex chars")
	}
	if _, err := hex.DecodeString(cid); err != nil {
		return nil, fmt.Errorf("mist: bad clientId hex: %w", err)
	}
	host := u.Host
	if host == "" {
		return nil, fmt.Errorf("mist: missing host")
	}
	// Validate host:port spelling now (fail fast on malformed links).
	// A v6 literal must parse as an IP; a domain is left for the
	// resolver at Connect time (family preference + fallback live there).
	hostPart, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("mist: bad host:port %q: %w", host, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("mist: bad port %q", portStr)
	}
	if ip := net.ParseIP(hostPart); ip != nil && ip.To16() == nil {
		return nil, fmt.Errorf("mist: bad IP literal %q", hostPart)
	}
	keyURL := u.Query().Get("key")
	if keyURL == "" {
		return nil, fmt.Errorf("mist: missing key")
	}
	// base64url -> base64 std.
	keyStd := strings.ReplaceAll(strings.ReplaceAll(keyURL, "-", "+"), "_", "/")
	switch len(keyStd) % 4 {
	case 2:
		keyStd += "=="
	case 3:
		keyStd += "="
	}
	keyBytes, err := base64.StdEncoding.DecodeString(keyStd)
	if err != nil || len(keyBytes) != 32 {
		return nil, fmt.Errorf("mist: key must be 32 bytes base64")
	}
	// Port hopping (node link ports=<base>-<last>, hop=<sec>).
	// No ports parameter = single-port mode, byte-identical to before.
	hopBase, hopLast, hopInterval := 0, 0, 0
	if portsStr := u.Query().Get("ports"); portsStr != "" {
		parts := strings.Split(portsStr, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("mist: bad ports %q, want <base>-<last>", portsStr)
		}
		base, err1 := strconv.Atoi(parts[0])
		last, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || base < 1 || last < base || last > 65535 {
			return nil, fmt.Errorf("mist: bad ports %q", portsStr)
		}
		if last-base+1 > 256 {
			return nil, fmt.Errorf("mist: ports range %q exceeds 256 ports", portsStr)
		}
		hopBase, hopLast = base, last
		hopInterval = 30
		if hopStr := u.Query().Get("hop"); hopStr != "" {
			h, err := strconv.Atoi(hopStr)
			if err != nil {
				return nil, fmt.Errorf("mist: bad hop %q", hopStr)
			}
			// Clamp to [10, 120] and log; never fail the link over it.
			if h < 10 {
				log.Printf("mist: hop %d clamped to 10", h)
				h = 10
			}
			if h > 120 {
				log.Printf("mist: hop %d clamped to 120", h)
				h = 120
			}
			hopInterval = h
		}
	}
	return &MistConfig{
		Server:         host,
		ClientID:       strings.ToLower(cid),
		AuthKey:        keyStd,
		SNI:            u.Query().Get("sni"),
		HopPortsBase:   hopBase,
		HopPortsLast:   hopLast,
		HopIntervalSec: hopInterval,
	}, nil
}

// MistUDPClient is a Mist UDP protocol client (ProtocolClient).
type MistUDPClient struct {
	cfg   MistConfig
	cid   [16]byte
	kAuth [32]byte

	mu      sync.Mutex
	conn    *net.UDPConn
	udpAddr *net.UDPAddr
	session *mistcore.UDPSession
	sched   *mistcore.UDPSendScheduler
	codec   *mistcore.QUICInitialCodec
	nextSID byte
	streams map[byte]*mistStreamConn
	dgH     DatagramHandler
	dgTH    DatagramTaggedHandler
	closed  bool
	done    chan struct{}
	wg      sync.WaitGroup
	// acksSent/ackSendErrs count ACK packets transmitted from the
	// OnAckNeeded callback (success vs seal/write failure). Exposed
	// via AckStats so a stalled return path can tell "client never
	// sent ACKs" apart from "server never processed them".
	acksSent    atomic.Uint64
	ackSendErrs atomic.Uint64
	// dgSent/dgSendErrs/dgReceived count UDP relay datagrams:
	// successfully sent, send failures, and inbound arrivals.
	// Exposed via DatagramStats so a dead DNS path can tell
	// "client never sent" apart from "server never answered".
	// Send failures are counted, never silently swallowed; the
	// returned error is unchanged.
	dgSent     atomic.Uint64
	dgSendErrs atomic.Uint64
	dgReceived atomic.Uint64
	// lastInbound records the last successful UDP read (unix nano),
	// any packet, decrypted or not. The hop fallback watch uses it:
	// no inbound at all for 3s after a hop means the new port is dead
	// (or the session is idle — the fallback is deliberately
	// fail-safe toward the known-good base port either way).
	lastInbound atomic.Int64
	// Hop state (port hopping, §2). peerAddr is the current send
	// destination; baseAddr is the handshake destination and the
	// fallback target. rotateWait maps a DCID_ROTATE packet number to
	// a channel closed when its ACK arrives. hopStopped is the sticky
	// fallback latch: once tripped, this session never hops again.
	peerAddr     *net.UDPAddr
	baseAddr     *net.UDPAddr
	hopActive    bool
	rotateWait   map[uint32]chan struct{}
	hopDegraded  atomic.Bool
	hopFallbacks atomic.Uint64
	hopStopped   atomic.Bool
	// pumpLastIter records the last readPump loop iteration (unix
	// nano). The watchdog uses it as a liveness signal: it refreshes
	// at least every 500ms even on an idle session (read deadline),
	// so a stale value means readPump died or wedged — not idleness.
	pumpLastIter atomic.Int64
	// pumpDeaths counts readPump exits and watchdog-detected stalls.
	// A nonzero count with zero traffic is the first signal that the
	// session is dead while the UI still shows "connected".
	pumpDeaths atomic.Uint64
	// pumpDead marks a watchdog episode already counted, so a dead
	// pump logs once instead of every watchdog tick.
	pumpDead atomic.Bool
	// pendingRSTs counts streams reset because their out-of-order
	// reorder buffer exceeded the cap (see maxStreamPending*).
	pendingRSTs atomic.Uint64
}

// NewMistUDPClient parses cfg and prepares (but does not connect) a client.
func NewMistUDPClient(cfg MistConfig) (*MistUDPClient, error) {
	cidBytes, err := hex.DecodeString(cfg.ClientID)
	if err != nil || len(cidBytes) != 16 {
		return nil, errors.New("mist: clientId must be 16 bytes hex")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(cfg.AuthKey)
	if err != nil || len(keyBytes) != 32 {
		return nil, errors.New("mist: authKey must be 32 bytes base64")
	}
	c := &MistUDPClient{
		cfg:     cfg,
		codec:   &mistcore.QUICInitialCodec{},
		nextSID: 1,
		streams: make(map[byte]*mistStreamConn),
		done:    make(chan struct{}),
	}
	copy(c.cid[:], cidBytes)
	copy(c.kAuth[:], keyBytes)
	return c, nil
}

// Name implements ProtocolClient.
func (c *MistUDPClient) Name() string { return "mist" }

// AckStats reports ACK packets sent from the OnAckNeeded callback
// (sent) and seal/write failures (errs). It implements AckStatser
// so Engine.Stats can surface it for return-path diagnosis.
func (c *MistUDPClient) AckStats() (sent, errs uint64) {
	return c.acksSent.Load(), c.ackSendErrs.Load()
}

// DatagramStats reports UDP relay datagram counts: successfully
// sent, send failures, and inbound datagrams received. It implements
// DatagramStatser so Engine.Stats can surface it for DNS-path
// diagnosis.
func (c *MistUDPClient) DatagramStats() (sent, sendErrs, received uint64) {
	return c.dgSent.Load(), c.dgSendErrs.Load(), c.dgReceived.Load()
}

// HealthStats reports readPump deaths (exits + watchdog-detected
// stalls) and streams reset by the reorder-buffer cap. It implements
// HealthStatser so Engine.Stats can surface it for diagnosis.
func (c *MistUDPClient) HealthStats() (readPumpDeaths, streamPendingResets uint64) {
	return c.pumpDeaths.Load(), c.pendingRSTs.Load()
}

// Connect performs the Mist UDP handshake. Safe to call repeatedly;
// subsequent calls return the existing session.
func (c *MistUDPClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.session != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	// Resolve candidates, IPv6 first. A literal node address yields
	// exactly one candidate (no family fallback, §3.5); a domain name
	// yields v6-then-v4 candidates for handshake fallback.
	candidates, err := mistcore.ResolvePeerAddrsSafe(ctx, c.cfg.Server, c.codec)
	if err != nil {
		return fmt.Errorf("mist: safety gate: %w", err)
	}
	hostPart, _, _ := net.SplitHostPort(c.cfg.Server)
	isLiteral := net.ParseIP(hostPart) != nil
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("mist: listen: %w", err)
	}
	// Large socket buffers (best-effort; the kernel caps at rmem_max /
	// wmem_max). The default ~212KB receive buffer is far below the
	// bandwidth-delay product at 223ms RTT (~900KB at 32 Mbps), so a
	// brief app stall (GC, scheduling) overflowed the kernel queue,
	// dropped bursts, and made server-side BBR back off. 1MB absorbs
	// bursts without stressing phone memory.
	_ = conn.SetReadBuffer(1 << 20)
	_ = conn.SetWriteBuffer(1 << 20)
	// Handshake over candidates in order. Each candidate gets the
	// usual retries (4 attempts x 1s read deadline); the family
	// fallback therefore happens after the first candidate's retries
	// are exhausted (<= 4s), not after a single 1s timeout. The
	// fallback fires at most once: no ping-pong between families.
	var session *mistcore.UDPSession
	var usedAddr *net.UDPAddr
	var hsErr error
	for i, cand := range candidates {
		session, hsErr = c.handshake(ctx, conn, cand)
		if hsErr == nil {
			usedAddr = cand
			break
		}
		if isLiteral || i == len(candidates)-1 {
			break
		}
		log.Printf("mist: handshake via %s failed (%v), trying next candidate", cand, hsErr)
	}
	if hsErr != nil {
		conn.Close()
		return hsErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		conn.Close()
		return errors.New("mist: client closed")
	}
	// Another goroutine may have connected first; prefer the first session.
	if c.session != nil {
		conn.Close()
		return nil
	}
	c.conn = conn
	c.udpAddr = usedAddr
	c.peerAddr = usedAddr
	c.baseAddr = usedAddr
	c.hopActive = c.cfg.HopEnabled()
	c.session = session
	c.sched = mistcore.NewUDPSendScheduler(session, mistcore.DirC2S, func(pkt []byte) error {
		// Destination is resolved per packet, not captured: a port hop
		// changes peerAddr mid-session, and the scheduler must follow.
		// readPump deliberately still ignores the source address.
		_, err := conn.WriteToUDP(pkt, c.currentPeerAddr())
		return err
	})
	// Reliability callbacks (same pattern as mist-udp-test).
	session.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		ack := mistcore.EncodeAckFrame(0, largest, ackDelay, ranges)
		pkt, err := session.SealPacketUntracked(mistcore.DirC2S, [][]byte{ack})
		if err != nil {
			c.ackSendErrs.Add(1)
			return
		}
		n, err := conn.WriteToUDP(pkt, c.currentPeerAddr())
		if err != nil || n < len(pkt) {
			c.ackSendErrs.Add(1)
			return
		}
		c.acksSent.Add(1)
	}
	session.Rel.OnRetransmit = func(frames [][]byte) error {
		c.sched.WriteRetransmitChunked(frames)
		return nil
	}
	c.sched.Start()
	c.wg.Add(4)
	go c.readPump()
	go c.tickLoop()
	go c.watchdogLoop(readPumpWatchdogTick, readPumpWatchdogStale)
	go c.hopLoop()
	return nil
}

// currentPeerAddr returns the current send destination: the hop target
// while hopping, otherwise the handshake address. Never nil after Connect.
func (c *MistUDPClient) currentPeerAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peerAddr != nil {
		return c.peerAddr
	}
	return c.udpAddr
}

// HopStats reports hop state for diagnostics: whether hopping is active
// for this session, whether a rotation ever degraded (hopped with the
// old DCID after 3 unacked DCID_ROTATE attempts), and how many times
// the session fell back to the base port.
func (c *MistUDPClient) HopStats() (active, degraded bool, fallbacks uint64) {
	c.mu.Lock()
	active = c.hopActive && !c.hopStopped.Load()
	c.mu.Unlock()
	return active, c.hopDegraded.Load(), c.hopFallbacks.Load()
}

// hopPortFor deterministically derives a hop destination port from the
// session keys and the time window (§2.3): HKDF-SHA256 with salt =
// session ID, ikm = k_c2s, info = "mist-hop/v1" + window (big-endian),
// reduced mod the range size and offset by the base port. Both sides
// could compute it, but the server is tolerant (it accepts any in-range
// port with a valid DCID + AEAD), so the value only decides where the
// client sends. Clock skew is harmless for the same reason.
func hopPortFor(sessionID [16]byte, kC2S [32]byte, window uint32, base, count int) int {
	info := make([]byte, 0, len("mist-hop/v1")+4)
	info = append(info, []byte("mist-hop/v1")...)
	var wb [4]byte
	binary.BigEndian.PutUint32(wb[:], window)
	info = append(info, wb[:]...)
	kdf := hkdf.New(sha256.New, kC2S[:], sessionID[:], info)
	var out [8]byte
	if _, err := io.ReadFull(kdf, out[:]); err != nil {
		return base
	}
	return base + int(binary.BigEndian.Uint64(out[:])%uint64(count))
}

// hopJitter returns a 0–2s jitter so clients do not all hop on the same
// second (a synchronized hop is itself an observable feature).
func hopJitter() time.Duration {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return time.Duration(binary.BigEndian.Uint16(b[:])%2000) * time.Millisecond
}

// hopLoop drives port hopping: at each window boundary (+ jitter) it
// rotates the DCID and switches the destination port. It exits when
// the client closes or when the sticky fallback latch trips.
func (c *MistUDPClient) hopLoop() {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mist: hopLoop panic (recovered): %v", r)
		}
	}()
	c.mu.Lock()
	active := c.hopActive
	c.mu.Unlock()
	if !active {
		return
	}
	intervalSec := c.cfg.HopIntervalSec
	if intervalSec <= 0 {
		intervalSec = 30
	}
	interval := int64(intervalSec)
	for {
		now := time.Now().Unix()
		nextBoundary := (now/interval + 1) * interval
		wait := time.Until(time.Unix(nextBoundary, 0).Add(hopJitter()))
		select {
		case <-c.done:
			return
		case <-time.After(wait):
		}
		if c.hopStopped.Load() {
			return
		}
		if !c.hopStep(intervalSec) {
			return
		}
	}
}

// hopStep performs one hop: send DCID_ROTATE on the old port, wait for
// its ACK (up to 3 attempts, 1s each), then switch port + DCID — or
// switch port with the old DCID and mark degraded if the rotation
// never got ACKed. Afterwards, 3s without any inbound packet falls
// back to the base port and latches hopping off for this session.
// Returns false when the session must stop hopping.
func (c *MistUDPClient) hopStep(intervalSec int) bool {
	c.mu.Lock()
	session, conn := c.session, c.conn
	c.mu.Unlock()
	if session == nil || conn == nil {
		return true
	}
	window := uint32(time.Now().Unix() / int64(intervalSec))
	newPort := hopPortFor(session.SessionID, session.KeyC2S, window,
		c.cfg.HopPortsBase, c.cfg.HopPortCount())
	var newDCID [8]byte
	if _, err := rand.Read(newDCID[:]); err != nil {
		log.Printf("mist: hop DCID random failed: %v", err)
		return true
	}
	frame := mistcore.EncodeDCIDRotateFrame(newDCID, window)
	acked := false
	for attempt := 0; attempt < 3 && !acked; attempt++ {
		pkt, pn, err := session.SealTrackedPacket(mistcore.DirC2S, [][]byte{frame})
		if err != nil {
			log.Printf("mist: hop DCID_ROTATE seal failed: %v", err)
			return true
		}
		ch := make(chan struct{})
		c.mu.Lock()
		if c.rotateWait == nil {
			c.rotateWait = make(map[uint32]chan struct{})
		}
		c.rotateWait[pn] = ch
		c.mu.Unlock()
		if _, err := conn.WriteToUDP(pkt, c.currentPeerAddr()); err != nil {
			c.removeRotateWait(pn)
			continue
		}
		acked = c.waitRotateAck(ch, time.Second)
		c.removeRotateWait(pn)
	}
	c.mu.Lock()
	if acked {
		session.RotateDCID(newDCID)
	} else {
		c.hopDegraded.Store(true)
		log.Printf("mist: hop DCID_ROTATE unacked after 3 attempts, hopping with old DCID (degraded)")
	}
	cur := c.peerAddr
	if cur == nil {
		cur = c.udpAddr
	}
	c.peerAddr = &net.UDPAddr{IP: cur.IP, Port: newPort}
	c.mu.Unlock()
	log.Printf("mist: hopped to port %d (window %d, rotate acked=%v)", newPort, window, acked)

	// Fallback watch: 3s with no inbound packet at all after the hop
	// means the new port is unreachable (or the session is idle; the
	// fallback is fail-safe toward the base port either way).
	hopTime := time.Now().UnixNano()
	select {
	case <-c.done:
		return true
	case <-time.After(3 * time.Second):
	}
	if c.lastInbound.Load() <= hopTime {
		c.mu.Lock()
		c.peerAddr = c.baseAddr
		c.mu.Unlock()
		c.hopFallbacks.Add(1)
		c.hopStopped.Store(true)
		log.Printf("mist: hop fallback to base port (no inbound for 3s after hop)")
		return false
	}
	return true
}

// waitRotateAck waits for a DCID_ROTATE ACK or a timeout.
func (c *MistUDPClient) waitRotateAck(ch chan struct{}, timeout time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	case <-c.done:
		return false
	}
}

// removeRotateWait drops a pending rotation wait without closing it
// (the waiter already gave up; a late ACK just finds nothing).
func (c *MistUDPClient) removeRotateWait(pn uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.rotateWait, pn)
}

// notifyRotateAcked closes the wait channels for newly ACKed packet
// numbers (called from the ACK dispatch path).
func (c *MistUDPClient) notifyRotateAcked(acked []uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pn := range acked {
		if ch, ok := c.rotateWait[pn]; ok {
			delete(c.rotateWait, pn)
			close(ch)
		}
	}
}

// readPumpWatchdogTick is how often the watchdog checks readPump
// liveness; readPumpWatchdogStale is how long without an iteration
// counts as stalled (readPump iterates at least every 500ms even
// when idle, so 2s is far outside normal scheduling jitter).
const (
	readPumpWatchdogTick  = time.Second
	readPumpWatchdogStale = 2 * time.Second
)

// handshake runs Initial + AUTH + AUTH_OK and returns a live session.
func (c *MistUDPClient) handshake(ctx context.Context, conn *net.UDPConn, udpAddr *net.UDPAddr) (*mistcore.UDPSession, error) {
	ephPriv, ephPub, err := mistcore.X25519Keypair()
	if err != nil {
		return nil, err
	}
	// AUTH plaintext: [VER(1)=0x02][TS(8)][EPH_PUB(32)][FEAT(1)][MODE(1)][RSVD(2)]
	authPlain := make([]byte, 45)
	authPlain[0] = 0x02
	binary.BigEndian.PutUint64(authPlain[1:9], uint64(time.Now().Unix()))
	copy(authPlain[9:41], ephPub[:])

	var response []byte
	var scid [8]byte
	for attempt := 0; attempt < 4; attempt++ {
		var nonce [24]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		if _, err := rand.Read(scid[:]); err != nil {
			return nil, err
		}
		mac := hmac.New(sha256.New, c.kAuth[:])
		mac.Write(nonce[:])
		var handshakeCID [16]byte
		copy(handshakeCID[:], mac.Sum(nil)[:16])
		ciphertext, err := mistcore.UDPSeal(&c.kAuth, nonce, authPlain, handshakeCID[:])
		if err != nil {
			return nil, err
		}
		authWire := make([]byte, 0, 16+24+len(ciphertext))
		authWire = append(authWire, handshakeCID[:]...)
		authWire = append(authWire, nonce[:]...)
		authWire = append(authWire, ciphertext...)
		var dcid [8]byte
		// F1: a fresh random DCID per attempt. The old code sent an
		// all-zero DCID, which made the Initial key globally constant
		// (RFC 9001 §5.2 derives it from the public salt + DCID) and
		// the GCM nonce (IV xor packet number 0) identical across all
		// clients. The server derives from the parsed DCID, so no
		// format change is involved and old servers accept this.
		if _, err := rand.Read(dcid[:]); err != nil {
			return nil, err
		}
		initial, err := c.codec.SealInitial(authWire, dcid, scid, 0)
		if err != nil {
			return nil, err
		}
		if _, err := conn.WriteToUDP(initial, udpAddr); err != nil {
			return nil, err
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 2048)
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil {
			response = append([]byte(nil), buf[:n]...)
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	if response == nil {
		return nil, errors.New("mist: handshake timeout")
	}
	authOKWire, respDCID, _, _, err := c.codec.OpenInitialResponse(response)
	if err != nil {
		return nil, fmt.Errorf("mist: auth_ok parse: %w", err)
	}
	if respDCID != scid {
		return nil, errors.New("mist: DCID mismatch")
	}
	if len(authOKWire) < 24+16 {
		return nil, errors.New("mist: auth_ok too short")
	}
	var okNonce [24]byte
	copy(okNonce[:], authOKWire[:24])
	okPlain, err := mistcore.UDPOpen(&c.kAuth, okNonce, authOKWire[24:], nil)
	if err != nil {
		return nil, fmt.Errorf("mist: auth_ok decrypt: %w", err)
	}
	if len(okPlain) < 48 {
		return nil, errors.New("mist: auth_ok plain too short")
	}
	var srvEphPub [32]byte
	copy(srvEphPub[:], okPlain[0:32])
	var sessionID [16]byte
	copy(sessionID[:], okPlain[32:48])
	shared, err := mistcore.X25519Shared(&ephPriv, &srvEphPub)
	if err != nil {
		return nil, err
	}
	kC2S, kS2C := mistcore.DeriveSessionKeys(ephPub, srvEphPub, shared)
	return mistcore.NewUDPSession(sessionID, kC2S, kS2C, udpAddr, c.codec), nil
}

// readPump decrypts incoming datagrams and dispatches frames.
//
// A panic here used to kill the whole app process (Go panics are
// process-fatal, and this runs under JNI): recover converts it to a
// log + counted death instead, so the session degrades to a
// diagnosable stall rather than a crash. An unexpected exit (not via
// Close) is counted in pumpDeaths: it is the first signal when the
// tunnel stops passing traffic while the UI still shows "connected".
// The watchdog (below) covers the wedged-but-not-exited case.
func (c *MistUDPClient) readPump() {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mist: readPump panic (recovered): %v", r)
		}
		select {
		case <-c.done:
			// Normal stop via Close.
		default:
			c.pumpDeaths.Add(1)
			log.Printf("mist: readPump died unexpectedly (deaths=%d)", c.pumpDeaths.Load())
		}
	}()
	buf := make([]byte, 65535)
	for {
		// Liveness heartbeat for the watchdog: refreshes at least
		// every 500ms even on an idle session (read deadline).
		c.pumpLastIter.Store(time.Now().UnixNano())
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn == nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// Non-timeout UDP error (e.g. socket closed by the
			// OS, ICMP hard error): the old code returned here
			// silently and inbound traffic stopped forever.
			// Now the exit is counted + logged above.
			return
		}
		// Any inbound packet counts for the hop fallback watch, even
		// one that later fails to decrypt.
		c.lastInbound.Store(time.Now().UnixNano())
		c.mu.Lock()
		session := c.session
		c.mu.Unlock()
		if session == nil {
			continue
		}
		frames, _, err := session.OpenPacket(mistcore.DirS2C, buf[:n])
		if err != nil {
			continue // decrypt failed; ignore
		}
		for _, f := range frames {
			c.dispatch(f)
		}
		// ACK-only: RTO scans run on the 10ms tickLoop, not per packet
		// (see UDPSession.FlushAck: per-packet CheckRTO scans cost
		// O(in-flight) each and grow quadratically with throughput).
		session.FlushAck()
	}
}

// tickLoop flushes ACKs and scans RTOs every 10ms (server does the same).
func (c *MistUDPClient) tickLoop() {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mist: tickLoop panic (recovered): %v", r)
		}
	}()
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.mu.Lock()
			session := c.session
			c.mu.Unlock()
			if session != nil {
				session.Tick()
			}
		}
	}
}

// watchdogLoop watches readPump liveness: if readPump has not
// iterated for longer than stale, it counts one death episode and
// logs. It fires once per episode (pumpDead) so a dead pump does not
// spam the log every tick, and it clears when iterations resume
// (e.g. a transient stall that recovered). It deliberately does NOT
// restart readPump: restarting would race the old pump on the same
// socket; a counted stall is for the UI layer to surface and for
// reconnect to recover from. tick/stale are parameters so tests can
// use short values; production passes readPumpWatchdogTick/Stale.
func (c *MistUDPClient) watchdogLoop(tick, stale time.Duration) {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mist: watchdog panic (recovered): %v", r)
		}
	}()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			last := c.pumpLastIter.Load()
			if last == 0 {
				continue // readPump has not started yet
			}
			if idle := time.Since(time.Unix(0, last)); idle > stale {
				if !c.pumpDead.Swap(true) {
					c.pumpDeaths.Add(1)
					log.Printf("mist: readPump stalled (no iteration for %v, deaths=%d)", idle, c.pumpDeaths.Load())
				}
			} else {
				c.pumpDead.Store(false)
			}
		}
	}
}

// dispatch routes one decoded frame.
func (c *MistUDPClient) dispatch(f mistcore.UDPFrame) {
	switch f.Type {
	case mistcore.UDPFrameAck:
		largest, ackDelay, ranges, err := mistcore.DecodeAckFrame(f.Payload)
		if err == nil {
			c.mu.Lock()
			session := c.session
			c.mu.Unlock()
			if session != nil {
				acked := session.Rel.ProcessAck(largest, ackDelay, ranges)
				if len(acked) > 0 {
					c.notifyRotateAcked(acked)
				}
			}
		}
	case mistcore.UDPFrameStream, mistcore.UDPFrameFin, mistcore.UDPFrameRst:
		c.mu.Lock()
		st := c.streams[f.SID]
		c.mu.Unlock()
		if st != nil {
			st.deliver(f)
		}
	case mistcore.UDPFrameDatagram:
		_, addr, port, data, tag, err := mistcore.DecodeDatagramTagged(f.Payload)
		if err != nil {
			return
		}
		// Count the arrival once, even if no handler is set: a
		// missing handler is itself a diagnosis ("server answered,
		// engine never routed it").
		c.dgReceived.Add(1)
		c.mu.Lock()
		h, th := c.dgH, c.dgTH
		c.mu.Unlock()
		// Tagged handler wins when set (the engine registers it);
		// otherwise the legacy handler gets every datagram.
		if th != nil {
			th(datagramSourceAddr(addr, port), tag, data)
		} else if h != nil {
			h(datagramSourceAddr(addr, port), data)
		}
	case mistcore.UDPFramePing:
		// Reply PONG (untracked: PONGs are never ACKed).
		c.mu.Lock()
		session, sched := c.session, c.sched
		conn := c.conn
		c.mu.Unlock()
		if session != nil && conn != nil {
			_ = sched // scheduler not used for untracked frames
			pong := mistcore.EncodeUDPFrame(mistcore.UDPFramePong, 0, nil)
			if pkt, err := session.SealPacketUntracked(mistcore.DirC2S, [][]byte{pong}); err == nil {
				_, _ = conn.WriteToUDP(pkt, c.currentPeerAddr())
			}
		}
	}
}

// datagramSourceAddr formats a relay response source address for the
// engine's onDatagram, which parses it with net.SplitHostPort.
// net.JoinHostPort brackets IPv6 literals; the previous
// fmt.Sprintf("%s:%d") produced unbracketed IPv6 like
// "2001:4860:4860::8888:53", which SplitHostPort rejects with
// "too many colons" — every IPv6 datagram response was dropped
// before it could reach the TUN.
func datagramSourceAddr(addr []byte, port uint16) string {
	return net.JoinHostPort(net.IP(addr).String(), fmt.Sprint(port))
}

// OnDatagram sets the handler for inbound relay datagrams.
func (c *MistUDPClient) OnDatagram(h DatagramHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dgH = h
}

// OnDatagramTagged sets the handler for inbound relay datagrams
// with their session tag. When set, dispatch calls it instead of
// the legacy handler (see dispatch).
func (c *MistUDPClient) OnDatagramTagged(h DatagramTaggedHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dgTH = h
}

// SendDatagram sends a UDP relay datagram to target ("ip:port").
// It is SendDatagramTagged with tag 0 (untagged, old wire format).
func (c *MistUDPClient) SendDatagram(target string, data []byte) error {
	return c.SendDatagramTagged(target, 0, data)
}

// SendDatagramTagged sends a UDP relay datagram to target ("ip:port")
// with a session tag tail (tag 0 = untagged). Send failures are
// counted in dgSendErrs (and successes in dgSent); the returned
// error is unchanged.
func (c *MistUDPClient) SendDatagramTagged(target string, tag uint8, data []byte) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		c.dgSendErrs.Add(1)
		return err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		c.dgSendErrs.Add(1)
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		c.dgSendErrs.Add(1)
		return fmt.Errorf("mist: datagram target must be an IP: %s", host)
	}
	var atyp byte
	var addr []byte
	if ip4 := ip.To4(); ip4 != nil {
		atyp, addr = mistcore.ATypIPv4, []byte(ip4)
	} else {
		atyp, addr = mistcore.ATypIPv6, []byte(ip.To16())
	}
	dg := mistcore.EncodeDatagramTagged(atyp, addr, uint16(port), data, tag)
	frame := mistcore.EncodeUDPFrame(mistcore.UDPFrameDatagram, 0, dg)
	c.mu.Lock()
	sched := c.sched
	c.mu.Unlock()
	if sched == nil {
		c.dgSendErrs.Add(1)
		return errors.New("mist: not connected")
	}
	if err := sched.Write([][]byte{frame}); err != nil {
		c.dgSendErrs.Add(1)
		return err
	}
	c.dgSent.Add(1)
	return nil
}

// Dial implements ProtocolClient: open a Mist stream to addr ("host:port").
func (c *MistUDPClient) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, err
	}
	var atyp byte
	var ab []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp, ab = mistcore.ATypIPv4, []byte(ip4)
		} else {
			atyp, ab = mistcore.ATypIPv6, []byte(ip.To16())
		}
	} else {
		atyp, ab = mistcore.ATypDomain, []byte(host)
	}
	connReq := mistcore.EncodeConnectReq(atyp, ab, uint16(port))

	c.mu.Lock()
	sid, ok := c.allocSIDLocked()
	if !ok {
		c.mu.Unlock()
		return nil, errors.New("mist: no free stream id")
	}
	st := newMistStreamConn(c, sid, addr)
	c.streams[sid] = st
	sched := c.sched
	c.mu.Unlock()

	// SYN + CONNECT in one batch.
	syn := mistcore.EncodeUDPFrame(mistcore.UDPFrameSyn, sid, nil)
	first := mistcore.EncodeStreamFrame(sid, 0, connReq)
	if err := sched.Write([][]byte{syn, first}); err != nil {
		c.dropStream(sid)
		return nil, err
	}
	// Wait for the 1-byte status: 0x00 = connected, 0x01 = failed.
	// The status byte is offset 0; payload data starts at offset 1.
	if err := st.waitStatus(ctx); err != nil {
		c.dropStream(sid)
		return nil, err
	}
	// CONNECT request occupies offset [0, len(connReq)).
	// Subsequent Write data must start after it, not overlap.
	st.mu.Lock()
	st.writeOff = uint64(len(connReq))
	st.mu.Unlock()
	return st, nil
}

// allocSIDLocked returns a SID not currently in use, advancing
// nextSID past any still-occupied SIDs. The SID space is 1 byte
// (1..255); blindly wrapping used to collide with leaked streams
// (a stream whose Close was never called), routing old frames to
// the new stream and corrupting it. Skipping occupied SIDs makes
// the wrap safe; with every SID genuinely busy, Dial fails instead
// of hijacking a live stream. Caller must hold c.mu.
func (c *MistUDPClient) allocSIDLocked() (byte, bool) {
	for i := 0; i < 255; i++ {
		sid := c.nextSID
		c.nextSID++
		if c.nextSID == 0 {
			c.nextSID = 1
		}
		if _, taken := c.streams[sid]; !taken {
			return sid, true
		}
	}
	return 0, false
}

// dropStream removes a stream (on dial failure).
func (c *MistUDPClient) dropStream(sid byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st, ok := c.streams[sid]; ok {
		st.markClosed(errors.New("mist: stream dropped"))
		delete(c.streams, sid)
	}
}

// Close implements ProtocolClient.
func (c *MistUDPClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.done)
	conn, sched := c.conn, c.sched
	streams := c.streams
	c.streams = make(map[byte]*mistStreamConn)
	c.mu.Unlock()
	for _, st := range streams {
		st.markClosed(errors.New("mist: client closed"))
	}
	if sched != nil {
		sched.Stop()
	}
	if conn != nil {
		conn.Close()
	}
	// Bounded wait: Stop is called from the app's teardown path
	// (which may run on the UI thread), so Close must never block
	// forever on a wedged goroutine. 5s mirrors Mobile.Stop's
	// runDone bound; a timeout is logged and Close still returns —
	// the leaked goroutine holds no socket (conn is closed above)
	// and exits on its next deadline/error check.
	waitDone := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		log.Printf("mist: client close timed out waiting for goroutines")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Stream connection (net.Conn over one Mist stream)
// ---------------------------------------------------------------------------

// mistStreamConn is one Mist stream exposed as net.Conn.
// Reads reassemble STREAM frames by offset (duplicates/out-of-order
// from retransmissions are handled); writes chunk into frames.
type mistStreamConn struct {
	c      *MistUDPClient
	sid    byte
	remote string

	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte            // contiguous bytes ready to read
	pending map[uint64][]byte // out-of-order chunks by offset
	// pendingBytes is the total bytes held in pending; pendingSince
	// is when the current gap opened (first out-of-order chunk for
	// it). Both are guarded by mu. A gap that never fills used to
	// grow pending without bound (the peer keeps sending while the
	// missing chunk's retransmit never arrives on a wedged session),
	// eating phone memory until GC starvation froze the app.
	pendingBytes int
	pendingSince time.Time
	nextRead     uint64 // next offset to deliver
	writeOff     uint64
	// writeMu serializes Write end to end: offset load, frame send,
	// offset store. It is deliberately separate from mu: mu guards the
	// read side (cond waits on it), so holding mu across a blocking
	// frame send would stall reads and data arrival. Lock order here
	// is always writeMu -> mu (brief); no path takes them in reverse,
	// and Read never takes writeMu, so no deadlock.
	writeMu sync.Mutex
	eof     bool
	closed  bool
	err     error
	readDL  time.Time
}

func newMistStreamConn(c *MistUDPClient, sid byte, remote string) *mistStreamConn {
	st := &mistStreamConn{
		c:       c,
		sid:     sid,
		remote:  remote,
		pending: make(map[uint64][]byte),
	}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// maxStreamPendingBytes caps one stream's out-of-order reorder
// buffer; maxStreamPendingAge caps how long a gap may stay open.
// Either trip resets the stream (see deliver). 16MB is deliberately
// generous: at 140 Mbps a single ~300ms RTO gap legitimately holds
// ~5MB, so a small cap would kill healthy high-speed streams on
// every loss; but an unbounded buffer on a truly wedged session is
// what ate memory until the app froze. The 5s age trip catches gaps
// whose retransmits never arrive even at low rates. Resetting (not
// silently dropping chunks) is the only safe response: dropping a
// pending chunk would leave a permanent hole in the byte stream
// (the datagram was already ACKed, so the peer will not resend it),
// corrupting everything after it; RST fails the connection fast so
// the app can retry instead.
const (
	maxStreamPendingBytes = 16 << 20
	maxStreamPendingAge   = 5 * time.Second
)

var errPendingOverflow = errors.New("mist: stream reorder buffer overflow")

// deliver routes one frame into the reorder buffer.
func (st *mistStreamConn) deliver(f mistcore.UDPFrame) {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	needReset := false
	switch f.Type {
	case mistcore.UDPFrameStream:
		if len(f.Payload) < 8 {
			st.mu.Unlock()
			return
		}
		off := binary.BigEndian.Uint64(f.Payload[:8])
		data := append([]byte(nil), f.Payload[8:]...)
		if off < st.nextRead {
			// Retransmit overlap: trim already-delivered prefix.
			skip := st.nextRead - off
			if skip >= uint64(len(data)) {
				st.mu.Unlock()
				return
			}
			data = data[skip:]
			off = st.nextRead
		}
		if off == st.nextRead {
			st.buf = append(st.buf, data...)
			st.nextRead += uint64(len(data))
			// Drain contiguous pending chunks.
			for {
				chunk, ok := st.pending[st.nextRead]
				if !ok {
					break
				}
				delete(st.pending, st.nextRead)
				st.pendingBytes -= len(chunk)
				st.buf = append(st.buf, chunk...)
				st.nextRead += uint64(len(chunk))
			}
			if len(st.pending) == 0 {
				st.pendingSince = time.Time{}
			}
		} else {
			if _, ok := st.pending[off]; !ok {
				if len(st.pending) == 0 {
					st.pendingSince = time.Now()
				}
				st.pending[off] = data
				st.pendingBytes += len(data)
				// Cap trip: fail the stream fast instead of
				// eating memory forever on a wedged session.
				if st.pendingBytes > maxStreamPendingBytes ||
					time.Since(st.pendingSince) > maxStreamPendingAge {
					st.err = errPendingOverflow
					st.closed = true
					needReset = true
				}
			}
		}
		st.cond.Broadcast()
	case mistcore.UDPFrameFin:
		st.eof = true
		st.cond.Broadcast()
	case mistcore.UDPFrameRst:
		st.err = errors.New("mist: stream reset")
		st.cond.Broadcast()
	}
	st.mu.Unlock()
	if needReset {
		st.c.resetStream(st)
	}
}

// resetStream removes a stream from the client table, counts the
// reset, and best-effort sends an RST frame (non-blocking: deliver
// runs on readPump, which must never stall on a full scheduler
// queue). Called after deliver already marked the stream closed
// under st.mu, so this only handles the client-table side.
func (c *MistUDPClient) resetStream(st *mistStreamConn) {
	c.mu.Lock()
	sched := c.sched
	if _, ok := c.streams[st.sid]; ok {
		delete(c.streams, st.sid)
	}
	c.mu.Unlock()
	c.pendingRSTs.Add(1)
	log.Printf("mist: stream %d reset (reorder buffer overflow, resets=%d)", st.sid, c.pendingRSTs.Load())
	if sched != nil {
		rst := mistcore.EncodeUDPFrame(mistcore.UDPFrameRst, st.sid, nil)
		_ = sched.TryWrite([][]byte{rst})
	}
}

// waitStatus reads the 1-byte CONNECT status with ctx timeout.
func (st *mistStreamConn) waitStatus(ctx context.Context) error {
	// 15s dial timeout, mirroring the server's dial timeout.
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = st.SetReadDeadline(deadline)
	// Clear the deadline before returning: the caller gets a fresh
	// conn, and a leftover dial deadline would kill later reads.
	defer st.SetReadDeadline(time.Time{})
	b := make([]byte, 1)
	if _, err := st.Read(b); err != nil {
		return fmt.Errorf("mist: connect status: %w", err)
	}
	if b[0] == 0x01 {
		return errors.New("mist: server dial failed")
	}
	if b[0] != 0x00 {
		return fmt.Errorf("mist: bad connect status %d", b[0])
	}
	return nil
}

// markClosed unblocks readers/writers with err.
func (st *mistStreamConn) markClosed(err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.err == nil {
		st.err = err
	}
	st.closed = true
	st.cond.Broadcast()
}

// Read implements net.Conn.
func (st *mistStreamConn) Read(b []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for len(st.buf) == 0 {
		if st.err != nil {
			return 0, st.err
		}
		if st.eof {
			return 0, errEOF
		}
		if !st.readDL.IsZero() {
			// Deadline wait: spawn a timer broadcast.
			d := time.Until(st.readDL)
			if d <= 0 {
				return 0, errTimeout
			}
			timer := time.AfterFunc(d, st.cond.Broadcast)
			st.cond.Wait()
			timer.Stop()
			if len(st.buf) == 0 && !st.eof && st.err == nil && time.Now().After(st.readDL) {
				return 0, errTimeout
			}
			continue
		}
		st.cond.Wait()
	}
	n := copy(b, st.buf)
	st.buf = append(st.buf[:0:0], st.buf[n:]...)
	return n, nil
}

// Write implements net.Conn.
//
// The whole write is serialized by writeMu: two concurrent Writes used
// to load the same writeOff, emit frames for the same offset range, and
// store back only one of the advances, permanently misaligning every
// later byte and corrupting the TLS record layer. Holding writeMu
// across offset load, frame send, and offset store closes that race;
// mu itself is still only held briefly, never across a frame send.
func (st *mistStreamConn) Write(b []byte) (int, error) {
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	st.mu.Lock()
	if st.closed || st.err != nil {
		err := st.err
		st.mu.Unlock()
		if err == nil {
			err = errClosed
		}
		return 0, err
	}
	off := st.writeOff
	st.mu.Unlock()

	// Chunk into frames that fit one datagram payload.
	const maxChunk = 1200
	sent := 0
	c := st.c
	c.mu.Lock()
	sched := c.sched
	c.mu.Unlock()
	if sched == nil {
		return 0, errors.New("mist: not connected")
	}
	for sent < len(b) {
		n := len(b) - sent
		if n > maxChunk {
			n = maxChunk
		}
		frame := mistcore.EncodeStreamFrame(st.sid, off, b[sent:sent+n])
		if err := sched.Write([][]byte{frame}); err != nil {
			return sent, err
		}
		off += uint64(n)
		sent += n
	}
	st.mu.Lock()
	st.writeOff = off
	st.mu.Unlock()
	return sent, nil
}

// Close implements net.Conn: send FIN, free the SID.
//
// It NEVER blocks: both waits the old code could hit are removed.
//   - writeMu: taken with TryLock. A Write wedged in scheduler
//     Write (full queue on a stalled session) used to hold writeMu
//     forever, so Close blocked forever — and the engine calls
//     Close while holding e.mu, wedging the whole tunnel and,
//     through the app's teardown path, the UI thread.
//     When TryLock fails the SID is still freed and readers still
//     unblocked below; only the best-effort FIN is skipped, and the
//     peer times the stream out.
//   - scheduler queue: the FIN goes through TryWrite, which drops
//     (rather than waits) when the queue is full. The local SID is
//     freed regardless of FIN delivery.
//
// Close also unblocks pending Reads with errClosed: the old code
// left a blocked Read waiting forever (closed set, but neither err
// nor eof), leaking the pumpTCP goroutine per closed connection.
func (st *mistStreamConn) Close() error {
	if !st.writeMu.TryLock() {
		// Wedged writer: free the SID and unblock readers now,
		// without waiting for the in-flight Write. The FIN is
		// best-effort and skipped; the peer times out.
		st.markClosed(errClosed)
		st.c.mu.Lock()
		delete(st.c.streams, st.sid)
		st.c.mu.Unlock()
		return nil
	}
	defer st.writeMu.Unlock()
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	if st.err == nil {
		st.err = errClosed
	}
	off := st.writeOff
	st.mu.Unlock()
	st.cond.Broadcast()
	c := st.c
	c.mu.Lock()
	sched := c.sched
	delete(c.streams, st.sid)
	c.mu.Unlock()
	if sched != nil {
		fin := mistcore.EncodeFinFrame(st.sid, off)
		_ = sched.TryWrite([][]byte{fin})
	}
	return nil
}

// CloseWrite sends FIN without closing the read side.
func (st *mistStreamConn) CloseWrite() error {
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	st.mu.Lock()
	off := st.writeOff
	st.mu.Unlock()
	c := st.c
	c.mu.Lock()
	sched := c.sched
	c.mu.Unlock()
	if sched == nil {
		return errors.New("mist: not connected")
	}
	fin := mistcore.EncodeFinFrame(st.sid, off)
	return sched.Write([][]byte{fin})
}

// LocalAddr / RemoteAddr implement net.Conn (best-effort).
func (st *mistStreamConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }
func (st *mistStreamConn) RemoteAddr() net.Addr {
	if host, port, err := net.SplitHostPort(st.remote); err == nil {
		if p, err := net.LookupPort("tcp", port); err == nil {
			return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
		}
	}
	return &net.TCPAddr{}
}

// SetDeadline implements net.Conn (read side only in MVP).
func (st *mistStreamConn) SetDeadline(t time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.readDL = t
	st.cond.Broadcast()
	return nil
}

// SetReadDeadline implements net.Conn.
func (st *mistStreamConn) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.readDL = t
	st.cond.Broadcast()
	return nil
}

// SetWriteDeadline implements net.Conn (writes are scheduler-paced;
// deadlines are accepted but not enforced in the MVP).
func (st *mistStreamConn) SetWriteDeadline(t time.Time) error { return nil }

var (
	errEOF     = io.EOF
	errTimeout = timeoutError{}
	errClosed  = errors.New("mist: stream closed")
)

// timeoutError is a net.Error for read deadlines.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
