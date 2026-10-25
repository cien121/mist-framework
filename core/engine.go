// TUN forwarding engine: IP packets <-> proxy protocol.
//
// Dual stack (IPv4 + IPv6). All traffic goes through the tunnel in
// the MVP; split routing / direct bypass is Phase 3.
//
// TCP model: the engine terminates TCP locally. It answers the app's
// SYN with SYN-ACK (after the proxy Dial succeeds), forwards payload
// over one Mist stream per connection, and translates stream data
// back into TCP segments. In-order only on the app side: out-of-order
// or duplicate segments are ACKed but dropped (the local stack
// retransmits; TUN delivery is effectively lossless).
//
// UDP model: each app 4-tuple maps to datagrams on the shared Mist
// session. Responses are routed back by their source address, which
// the relay echoes as the original target. This covers DNS (UDP 53)
// over v4 and v6 with no special case.
package core

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// EngineConfig wires the engine.
type EngineConfig struct {
	TUN    TUNDevice
	Client ProtocolClient
	Stats  StatsCollector // optional; may be nil
}

// Engine forwards TUN packets through a ProtocolClient.
type Engine struct {
	tun    TUNDevice
	client ProtocolClient
	dg     DatagramClient // nil if the client has no datagram support
	stats  StatsCollector

	mu        sync.Mutex // guards tables + tun writes
	tunMu     sync.Mutex // serializes TUN writes
	tcp       map[FourTuple]*tcpConn
	pending   map[FourTuple]bool
	udp       map[FourTuple]*udpSession
	udpByDst  map[string]FourTuple // dstIP:dstPort -> app tuple (return routing)
	id        uint32
	upBytes   atomic.Uint64
	downBytes atomic.Uint64
	done      chan struct{}
	closed    atomic.Bool
}

type tcpConn struct {
	tuple      FourTuple
	stream     net.Conn
	appSeq     uint32 // next byte expected from the app
	ourSeq     uint32 // next byte we send to the app
	isn        uint32 // our initial sequence number (for SYN-ACK retransmits)
	synAckSent bool
	appFin     bool
	ourFin     bool
	created    time.Time
}

type udpSession struct {
	tuple   FourTuple
	lastAct time.Time
}

// NewEngine builds an engine. If client implements DatagramClient,
// the UDP path is enabled; otherwise UDP packets are dropped.
func NewEngine(cfg EngineConfig) *Engine {
	e := &Engine{
		tun:      cfg.TUN,
		client:   cfg.Client,
		stats:    cfg.Stats,
		tcp:      make(map[FourTuple]*tcpConn),
		pending:  make(map[FourTuple]bool),
		udp:      make(map[FourTuple]*udpSession),
		udpByDst: make(map[string]FourTuple),
		done:     make(chan struct{}),
	}
	if dg, ok := cfg.Client.(DatagramClient); ok {
		e.dg = dg
		dg.OnDatagram(e.onDatagram)
	}
	return e
}

// Run reads packets from the TUN until ctx is done or the TUN closes.
// It returns when the engine is closed.
func (e *Engine) Run(ctx context.Context) error {
	go e.sweeper(ctx)
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-e.done:
			return nil
		default:
		}
		n, err := e.tun.Read(buf)
		if err != nil {
			if e.closed.Load() {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case <-e.done:
				return nil
			default:
				// Transient read error: keep going.
				continue
			}
		}
		if n == 0 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		e.handlePacket(ctx, pkt)
	}
}

// Close stops the engine and releases connections.
func (e *Engine) Close() error {
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(e.done)
	e.mu.Lock()
	for _, c := range e.tcp {
		c.stream.Close()
	}
	e.tcp = make(map[FourTuple]*tcpConn)
	e.mu.Unlock()
	return e.tun.Close()
}

// Stats returns cumulative traffic counters.
func (e *Engine) Stats() Stats {
	return Stats{
		UploadBytes:   e.upBytes.Load(),
		DownloadBytes: e.downBytes.Load(),
		UpdatedAt:     time.Now(),
	}
}

// handlePacket parses one IP packet and dispatches by protocol.
func (e *Engine) handlePacket(ctx context.Context, raw []byte) {
	p, err := ParseIP(raw)
	if err != nil {
		// Fragments, ESP, non-IP: dropped in the MVP.
		return
	}
	switch p.Proto {
	case ProtoTCP:
		seg, err := ParseTCP(p.Payload)
		if err != nil {
			return
		}
		e.handleTCP(ctx, p, seg)
	case ProtoUDP:
		dg, err := ParseUDP(p.Payload)
		if err != nil {
			return
		}
		e.handleUDP(p, dg)
	default:
		// ICMP/ICMPv6 and others: dropped in the MVP.
		return
	}
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

func (e *Engine) handleTCP(ctx context.Context, p *IPPacket, seg *TCPSegment) {
	tuple := TupleOf(p, seg.SrcPort, seg.DstPort)

	e.mu.Lock()
	conn, ok := e.tcp[tuple]
	pend := e.pending[tuple]
	e.mu.Unlock()

	// RST from the app: tear down.
	if seg.Flags&TCPRst != 0 {
		e.dropTCP(tuple)
		return
	}

	// New connection: SYN without ACK.
	if seg.Flags&TCPSyn != 0 && seg.Flags&TCPAck == 0 {
		if ok {
			// Retransmitted SYN: resend SYN-ACK.
			e.sendTCPSYNACK(conn)
			return
		}
		if pend {
			return // dial already in flight; app will retransmit
		}
		e.mu.Lock()
		e.pending[tuple] = true
		e.mu.Unlock()
		go e.dialTCP(ctx, p, tuple, seg)
		return
	}
	if !ok {
		return // data for an unknown connection; drop
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if seg.Flags&TCPAck != 0 && len(seg.Payload) == 0 && seg.Flags&TCPFin == 0 {
		// Pure ACK (e.g. for our FIN): if our FIN was ACKed, clean up.
		if conn.ourFin && seg.Ack == conn.ourSeq {
			delete(e.tcp, tuple)
		}
		return
	}
	if seg.Flags&TCPFin != 0 {
		// App half-closes: ACK the FIN, propagate to the stream.
		if seg.Seq == conn.appSeq {
			conn.appSeq++ // FIN consumes one sequence number
			conn.appFin = true
			e.sendTCPUnlocked(conn, TCPAck, nil)
			if closer, ok := conn.stream.(interface{ CloseWrite() error }); ok {
				_ = closer.CloseWrite()
			}
		}
		return
	}
	if len(seg.Payload) > 0 {
		if seg.Seq != conn.appSeq {
			// Out-of-order or duplicate: ACK current expectation, drop.
			e.sendTCPUnlocked(conn, TCPAck, nil)
			return
		}
		payload := append([]byte(nil), seg.Payload...)
		conn.appSeq += uint32(len(payload))
		e.sendTCPUnlocked(conn, TCPAck, nil)
		go func() {
			if _, err := conn.stream.Write(payload); err != nil {
				e.dropTCP(tuple)
				return
			}
			e.upBytes.Add(uint64(len(payload)))
		}()
	}
}

// dialTCP opens the proxy stream, then answers the app's SYN.
func (e *Engine) dialTCP(ctx context.Context, p *IPPacket, tuple FourTuple, syn *TCPSegment) {
	defer func() {
		e.mu.Lock()
		delete(e.pending, tuple)
		e.mu.Unlock()
	}()
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	target := net.JoinHostPort(p.Dst.String(), fmt.Sprint(tuple.DstPort))
	stream, err := e.client.Dial(dctx, target)
	if err != nil {
		// Proxy dial failed: RST the app's connection attempt.
		e.sendRST(p, tuple, syn)
		return
	}
	var isnBytes [4]byte
	_, _ = rand.Read(isnBytes[:])
	isn := binary.BigEndian.Uint32(isnBytes[:])
	conn := &tcpConn{
		tuple:   tuple,
		stream:  stream,
		appSeq:  syn.Seq + 1,
		ourSeq:  isn,
		isn:     isn,
		created: time.Now(),
	}
	e.mu.Lock()
	e.tcp[tuple] = conn
	e.mu.Unlock()
	e.sendTCPSYNACK(conn)
	go e.pumpTCP(conn)
}

// pumpTCP copies stream data back to the app as TCP segments.
func (e *Engine) pumpTCP(conn *tcpConn) {
	buf := make([]byte, 8192)
	for {
		n, err := conn.stream.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			e.mu.Lock()
			if _, ok := e.tcp[conn.tuple]; !ok {
				e.mu.Unlock()
				return
			}
			seq := conn.ourSeq
			conn.ourSeq += uint32(len(data))
			seg := BuildTCP(
				addrOf(conn.tuple.DstIP), addrOf(conn.tuple.SrcIP),
				conn.tuple.DstPort, conn.tuple.SrcPort,
				seq, conn.appSeq, TCPPsh|TCPAck, data,
			)
			e.writeTUNLocked(conn.tuple, seg)
			e.mu.Unlock()
			e.downBytes.Add(uint64(len(data)))
		}
		if err != nil {
			// Stream EOF/error: FIN the app side, then clean up.
			e.mu.Lock()
			if c, ok := e.tcp[conn.tuple]; ok && !c.ourFin {
				c.ourFin = true
				e.sendTCPUnlocked(c, TCPFin|TCPAck, nil)
			}
			delete(e.tcp, conn.tuple)
			e.mu.Unlock()
			return
		}
	}
}

// sendTCPSYNACK sends SYN+ACK. Idempotent: retransmitted SYNs
// re-send the same SYN-ACK (seq=isn) without advancing ourSeq.
func (e *Engine) sendTCPSYNACK(conn *tcpConn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	seg := BuildTCP(
		addrOf(conn.tuple.DstIP), addrOf(conn.tuple.SrcIP),
		conn.tuple.DstPort, conn.tuple.SrcPort,
		conn.isn, conn.appSeq, TCPSyn|TCPAck, nil,
	)
	e.writeTUNLocked(conn.tuple, seg)
	if !conn.synAckSent {
		conn.synAckSent = true
		conn.ourSeq = conn.isn + 1
	}
}

// sendTCPUnlocked sends a segment from the proxy to the app.
// Callers hold e.mu.
func (e *Engine) sendTCPUnlocked(conn *tcpConn, flags uint8, payload []byte) {
	seg := BuildTCP(
		addrOf(conn.tuple.DstIP), addrOf(conn.tuple.SrcIP),
		conn.tuple.DstPort, conn.tuple.SrcPort,
		conn.ourSeq, conn.appSeq, flags, payload,
	)
	e.writeTUNLocked(conn.tuple, seg)
	if flags&TCPFin != 0 {
		conn.ourSeq++
	}
}

// sendRST replies RST to a failed dial (app side sees refused).
func (e *Engine) sendRST(p *IPPacket, tuple FourTuple, syn *TCPSegment) {
	seg := BuildTCP(
		p.Dst, p.Src, tuple.DstPort, tuple.SrcPort,
		0, syn.Seq+1, TCPRst|TCPAck, nil,
	)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.writeTUNLocked(tuple, seg)
}

// dropTCP closes the stream and forgets the connection.
func (e *Engine) dropTCP(tuple FourTuple) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.tcp[tuple]; ok {
		c.stream.Close()
		delete(e.tcp, tuple)
	}
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

func (e *Engine) handleUDP(p *IPPacket, dg *UDPPacket) {
	if e.dg == nil {
		return // client has no datagram support
	}
	tuple := TupleOf(p, dg.SrcPort, dg.DstPort)
	e.mu.Lock()
	if _, ok := e.udp[tuple]; !ok {
		e.udp[tuple] = &udpSession{tuple: tuple, lastAct: time.Now()}
	}
	e.udpByDst[dstKey(p.Dst.String(), dg.DstPort)] = tuple
	e.mu.Unlock()
	target := net.JoinHostPort(p.Dst.String(), fmt.Sprint(dg.DstPort))
	payload := append([]byte(nil), dg.Payload...)
	go func() {
		if err := e.dg.SendDatagram(target, payload); err != nil {
			return
		}
		e.upBytes.Add(uint64(len(payload)))
	}()
}

// onDatagram routes a relay response back to the app's TUN packet.
func (e *Engine) onDatagram(srcAddr string, data []byte) {
	host, portStr, err := net.SplitHostPort(srcAddr)
	if err != nil {
		return
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return
	}
	e.mu.Lock()
	tuple, ok := e.udpByDst[dstKey(host, uint16(port))]
	if !ok {
		e.mu.Unlock()
		return
	}
	if s, ok := e.udp[tuple]; ok {
		s.lastAct = time.Now()
	}
	e.mu.Unlock()
	srcIP := addrOf(host)
	dstIP := addrOf(tuple.SrcIP)
	udpSeg := BuildUDP(srcIP, dstIP, uint16(port), tuple.SrcPort, data)
	e.mu.Lock()
	e.writeTUNLocked(tuple, udpSeg)
	e.mu.Unlock()
	e.downBytes.Add(uint64(len(data)))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func dstKey(ip string, port uint16) string {
	return ip + ":" + fmt.Sprint(port)
}

func addrOf(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPv4zero
	}
	return ip
}

// writeTUNLocked wraps a segment in an IP packet and writes it to the
// TUN. Callers hold e.mu (tun writes are additionally serialized).
func (e *Engine) writeTUNLocked(tuple FourTuple, segment []byte) {
	var proto uint8
	if tuple.Proto == ProtoTCP {
		proto = ProtoTCP
	} else {
		proto = ProtoUDP
	}
	src := addrOf(tuple.DstIP) // proxy side: source is the remote
	dst := addrOf(tuple.SrcIP) // destination is the app
	e.id++
	pkt := BuildIP(src, dst, proto, uint16(e.id), segment)
	e.tunMu.Lock()
	_, _ = e.tun.Write(pkt)
	e.tunMu.Unlock()
}

// sweeper removes idle connections.
func (e *Engine) sweeper(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.done:
			return
		case now := <-t.C:
			e.mu.Lock()
			for tuple, c := range e.tcp {
				if now.Sub(c.created) > 10*time.Minute {
					c.stream.Close()
					delete(e.tcp, tuple)
				}
			}
			for tuple, s := range e.udp {
				if now.Sub(s.lastAct) > 2*time.Minute {
					delete(e.udp, tuple)
				}
			}
			e.mu.Unlock()
		}
	}
}

// NewEngineForMobile creates an engine for gomobile binding.
// It accepts concrete *MistUDPClient instead of ProtocolClient interface,
// so gomobile does not need to bind the interface types.
func NewEngineForMobile(tun TUNDevice, client *MistUDPClient) *Engine {
	e := &Engine{
		tun:      tun,
		client:   client,
		tcp:      make(map[FourTuple]*tcpConn),
		pending:  make(map[FourTuple]bool),
		udp:      make(map[FourTuple]*udpSession),
		udpByDst: make(map[string]FourTuple),
		done:     make(chan struct{}),
	}
	if dg, ok := interface{}(client).(DatagramClient); ok {
		e.dg = dg
		dg.OnDatagram(e.onDatagram)
	}
	return e
}
