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
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mist/mistcore"
)

// MistConfig configures a Mist UDP client.
type MistConfig struct {
	Server   string // "host:port" of the Mist UDP server
	ClientID string // 32 hex chars (16 bytes)
	AuthKey  string // base64 std, 32 bytes
	SNI      string // reserved for the TLS path; unused by UDP
}

// ParseMistURL parses a mist:// node link:
// mist://<cidHex>@<host>:<port>?key=<base64url>&sni=<domain>#<name>
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
	return &MistConfig{
		Server:   host,
		ClientID: strings.ToLower(cid),
		AuthKey:  keyStd,
		SNI:      u.Query().Get("sni"),
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

// Connect performs the Mist UDP handshake. Safe to call repeatedly;
// subsequent calls return the existing session.
func (c *MistUDPClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.session != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	udpAddr, err := mistcore.ResolvePeerAddrSafe(ctx, c.cfg.Server, c.codec)
	if err != nil {
		return fmt.Errorf("mist: safety gate: %w", err)
	}
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
	session, err := c.handshake(ctx, conn, udpAddr)
	if err != nil {
		conn.Close()
		return err
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
	c.udpAddr = udpAddr
	c.session = session
	c.sched = mistcore.NewUDPSendScheduler(session, mistcore.DirC2S, func(pkt []byte) error {
		_, err := conn.WriteToUDP(pkt, udpAddr)
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
		n, err := conn.WriteToUDP(pkt, udpAddr)
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
	c.wg.Add(2)
	go c.readPump()
	go c.tickLoop()
	return nil
}

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
func (c *MistUDPClient) readPump() {
	defer c.wg.Done()
	buf := make([]byte, 65535)
	for {
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
			return
		}
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
				session.Rel.ProcessAck(largest, ackDelay, ranges)
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
		_, addr, port, data, err := mistcore.DecodeDatagram(f.Payload)
		if err != nil {
			return
		}
		// Count the arrival once, even if no handler is set: a
		// missing handler is itself a diagnosis ("server answered,
		// engine never routed it").
		c.dgReceived.Add(1)
		c.mu.Lock()
		h := c.dgH
		c.mu.Unlock()
		if h != nil {
			h(datagramSourceAddr(addr, port), data)
		}
	case mistcore.UDPFramePing:
		// Reply PONG (untracked: PONGs are never ACKed).
		c.mu.Lock()
		session, sched := c.session, c.sched
		conn, udpAddr := c.conn, c.udpAddr
		c.mu.Unlock()
		if session != nil && conn != nil {
			_ = sched // scheduler not used for untracked frames
			pong := mistcore.EncodeUDPFrame(mistcore.UDPFramePong, 0, nil)
			if pkt, err := session.SealPacketUntracked(mistcore.DirC2S, [][]byte{pong}); err == nil {
				_, _ = conn.WriteToUDP(pkt, udpAddr)
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

// SendDatagram sends a UDP relay datagram to target ("ip:port").
// Send failures are counted in dgSendErrs (and successes in
// dgSent); the returned error is unchanged.
func (c *MistUDPClient) SendDatagram(target string, data []byte) error {
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
	dg := mistcore.EncodeDatagram(atyp, addr, uint16(port), data)
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
	c.wg.Wait()
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

	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte            // contiguous bytes ready to read
	pending  map[uint64][]byte // out-of-order chunks by offset
	nextRead uint64            // next offset to deliver
	writeOff uint64
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

// deliver routes one frame into the reorder buffer.
func (st *mistStreamConn) deliver(f mistcore.UDPFrame) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return
	}
	switch f.Type {
	case mistcore.UDPFrameStream:
		if len(f.Payload) < 8 {
			return
		}
		off := binary.BigEndian.Uint64(f.Payload[:8])
		data := append([]byte(nil), f.Payload[8:]...)
		if off < st.nextRead {
			// Retransmit overlap: trim already-delivered prefix.
			skip := st.nextRead - off
			if skip >= uint64(len(data)) {
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
				st.buf = append(st.buf, chunk...)
				st.nextRead += uint64(len(chunk))
			}
		} else {
			if _, ok := st.pending[off]; !ok {
				st.pending[off] = data
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
func (st *mistStreamConn) Close() error {
	// Serialize against in-flight Writes so the FIN offset covers all
	// data already handed to Write; otherwise FIN could overtake
	// pending frames and the peer would discard them.
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	off := st.writeOff
	st.mu.Unlock()
	c := st.c
	c.mu.Lock()
	sched := c.sched
	delete(c.streams, st.sid)
	c.mu.Unlock()
	if sched != nil {
		fin := mistcore.EncodeFinFrame(st.sid, off)
		_ = sched.Write([][]byte{fin})
	}
	st.cond.Broadcast()
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
