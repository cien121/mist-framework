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
	"log"
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

	mu      sync.Mutex // guards tables + tcpConn state (not TUN writes)
	tunMu   sync.Mutex // serializes TUN writes
	tcp     map[FourTuple]*tcpConn
	pending map[FourTuple]bool
	udp     map[FourTuple]*udpSession
	// udpByDst lists app tuples per dstIP:dstPort, most recent last.
	// A single tuple per destination used to be assumed; concurrent
	// queries to the same server (e.g. two apps asking 8.8.8.8:53)
	// overwrote each other and responses went to the wrong source
	// port. The list preserves every session; DNS traffic is further
	// disambiguated by transaction ID in udpByDNS.
	udpByDst map[string][]FourTuple // dstIP:dstPort -> app tuples (return routing)
	// udpByDNS maps one DNS exchange to its app tuple, keyed by
	// destination + transaction ID (payload bytes 0-1). A relay
	// response carries only the original destination, so the
	// transaction ID is the only way to tell concurrent queries to
	// the same server apart.
	udpByDNS map[string]FourTuple // dstIP:dstPort|txID -> app tuple
	// udpSem bounds in-flight UDP send goroutines (see handleUDP).
	// Without it a wedged session piles up one blocked goroutine
	// per app datagram — thousands of stacks plus scheduler
	// pressure, which is exactly the kind of CPU/GC load that
	// starves the phone's UI thread (1.0.41 freeze). UDP is
	// loss-tolerant, so excess datagrams are dropped, not queued.
	udpSem    chan struct{}
	id        atomic.Uint32 // IP IDs; atomic so TUN writes need not hold e.mu
	upBytes   atomic.Uint64
	downBytes atomic.Uint64
	// tunWriteErrs counts failed/short TUN writes (was silently
	// swallowed before; a nonzero count is the first thing to check
	// when return traffic stalls).
	tunWriteErrs atomic.Uint64
	done         chan struct{}
	closed       atomic.Bool
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
	lastAct    time.Time // last app- or server-side activity; sweeper uses idle time, not age
	// sendQ is the FIFO queue drained by the single tcpWriter goroutine
	// for this connection. App segments used to be forwarded by one
	// goroutine per segment with no ordering: concurrent stream Writes
	// raced on the stream offset (mistStreamConn.Write loaded and
	// stored writeOff around an unlocked send), scrambling the byte
	// stream and corrupting TLS records. Queueing here serializes AND
	// orders writes; sendMu is only ever held briefly (append/signal),
	// never across a blocking stream Write, and lock order is always
	// e.mu -> sendMu, so no deadlock with pumpTCP or dropTCP.
	sendMu     sync.Mutex
	sendCond   *sync.Cond // guards sendQ/sendClosed/queuedBytes, uses sendMu
	sendQ      []tcpWriteItem
	sendClosed bool
	// queuedBytes is the total payload bytes in sendQ. The engine
	// only ACKs app data once accepted into sendQ, and sendQ is
	// capped at maxSendQueueBytes (== the 65535 window BuildTCP
	// advertises), so the app can never be led to believe more is
	// delivered than the engine can buffer. Over-cap segments are
	// dropped without ACK advance: the app retransmits instead of
	// assuming delivery while data sits queued on the phone.
	queuedBytes int
	// Download retransmit + window, all guarded by e.mu:
	peerAck     uint32        // highest contiguous ACK received from app for our data
	appWindow   uint32        // last window advertised by app (raw, unscaled)
	sendBuf     []sentSeg     // unacked download segments, in seq order
	dupAckCount int           // consecutive duplicate ACKs for sendBuf[0]
	eofSeen     bool          // server closed; FIN to app waits for sendBuf to drain
	ackCh       chan struct{} // signaled (non-blocking) when an ACK opens the window
}

// sentSeg is one download segment kept until the app ACKs it, so a
// lost TUN segment can be retransmitted instead of wedging the
// connection forever (the pre-retransmit failure: one dropped chunk,
// app RTO -> RST -> "socket error").
type sentSeg struct {
	seq    uint32
	data   []byte
	sentAt time.Time
}

// TCP hardening constants.
const (
	// maxSendQueueBytes caps one connection's upload FIFO. It equals
	// the window BuildTCP advertises, so the advertised window and
	// the buffering the engine can actually honor never diverge.
	maxSendQueueBytes = 65535
	// tcpRTO is the backstop retransmit timeout for the oldest
	// unacked download segment (fast retransmit on 3 duplicate ACKs
	// covers most losses; RTO covers the tail).
	tcpRTO = 800 * time.Millisecond
	// tcpDupAckThreshold is the duplicate-ACK count that triggers
	// fast retransmit of the oldest unacked segment.
	tcpDupAckThreshold = 3
	// tcpIdleTimeout is how long a TCP connection may sit with no
	// app- or server-side activity before the sweeper closes it.
	tcpIdleTimeout = 10 * time.Minute
)

// tcpWriteItem is one unit of work for tcpWriter: either payload bytes
// or a half-close (fin) marker, which must be sent after all queued
// data, never ahead of it.
type tcpWriteItem struct {
	payload []byte
	fin     bool
}

type udpSession struct {
	tuple   FourTuple
	lastAct time.Time
}

// maxInFlightUDPSends bounds concurrent UDP send goroutines.
const maxInFlightUDPSends = 512

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
		udpByDst: make(map[string][]FourTuple),
		udpByDNS: make(map[string]FourTuple),
		udpSem:   make(chan struct{}, maxInFlightUDPSends),
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
//
// It never blocks on a connection close: the old code held e.mu
// across every stream.Close, and a stream.Close wedged on a stalled
// session (blocked writer, full scheduler queue) held e.mu forever,
// stalling the Run loop and everything behind it. Now the table is
// snapshotted under e.mu, streams are closed without holding it,
// and the table is cleared after. New connections cannot slip in
// between snapshot and clear: dialTCP and the SYN path refuse to
// insert once closed is set (see the guards there).
func (e *Engine) Close() error {
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(e.done)
	e.mu.Lock()
	conns := make([]*tcpConn, 0, len(e.tcp))
	for _, c := range e.tcp {
		conns = append(conns, c)
	}
	e.mu.Unlock()
	for _, c := range conns {
		c.stream.Close()
		stopTCPWriterLocked(c)
	}
	e.mu.Lock()
	e.tcp = make(map[FourTuple]*tcpConn)
	e.mu.Unlock()
	return e.tun.Close()
}

// Stats returns cumulative traffic counters.
func (e *Engine) Stats() Stats {
	s := Stats{
		UploadBytes:    e.upBytes.Load(),
		DownloadBytes:  e.downBytes.Load(),
		TunWriteErrors: e.tunWriteErrs.Load(),
		UpdatedAt:      time.Now(),
	}
	if as, ok := e.client.(AckStatser); ok {
		s.AcksSent, s.AckSendErrors = as.AckStats()
	}
	if ds, ok := e.client.(DatagramStatser); ok {
		s.DatagramsSent, s.DatagramsSendErrors, s.DatagramsReceived = ds.DatagramStats()
	}
	if hs, ok := e.client.(HealthStatser); ok {
		s.ReadPumpDeaths, s.StreamPendingResets = hs.HealthStats()
	}
	return s
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
		if e.closed.Load() {
			return // engine closing: refuse new connections
		}
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
	// Deferred EOF finish runs before the unlock (LIFO): if the
	// server already closed and this segment ACKed the last
	// download segment, the deferred FIN goes out now.
	defer func() {
		if c, ok := e.tcp[tuple]; ok && c.eofSeen && len(c.sendBuf) == 0 {
			e.finishConnLocked(c, tuple)
		}
	}()
	conn.lastAct = time.Now()
	if seg.Flags&TCPAck != 0 {
		e.processAckLocked(conn, seg)
	}
	if seg.Flags&TCPAck != 0 && len(seg.Payload) == 0 && seg.Flags&TCPFin == 0 {
		// Pure ACK (e.g. for our FIN): if our FIN was ACKed, clean up.
		if conn.ourFin && seg.Ack == conn.ourSeq {
			conn.stream.Close()
			stopTCPWriterLocked(conn)
			delete(e.tcp, tuple)
		}
		return
	}
	if seg.Flags&TCPFin != 0 {
		// FIN, possibly carrying payload (close-after-write
		// coalescing: small uploads commonly send the final chunk
		// together with FIN). Data first, FIN marker behind it:
		// dropping the payload here used to make the server wait
		// forever for the rest of the body.
		if seg.Seq != conn.appSeq {
			// Out-of-order or duplicate FIN: ACK current expectation, drop.
			e.sendTCPUnlocked(conn, TCPAck, nil)
			return
		}
		if len(seg.Payload) > 0 {
			payload := append([]byte(nil), seg.Payload...)
			if !e.tryEnqueueTCPWrite(conn, tcpWriteItem{payload: payload}) {
				// Queue full: backpressure. Neither the data nor
				// the FIN is consumed; the app retransmits both.
				e.sendTCPUnlocked(conn, TCPAck, nil)
				return
			}
			conn.appSeq += uint32(len(payload))
		}
		conn.appSeq++ // FIN consumes one sequence number
		conn.appFin = true
		e.sendTCPUnlocked(conn, TCPAck, nil)
		// FIN markers always fit the queue (0 bytes) and must
		// never be dropped, or the half-close is lost.
		e.tryEnqueueTCPWrite(conn, tcpWriteItem{fin: true})
		return
	}
	if len(seg.Payload) > 0 {
		if seg.Seq != conn.appSeq {
			// Out-of-order or duplicate: ACK current expectation, drop.
			e.sendTCPUnlocked(conn, TCPAck, nil)
			return
		}
		payload := append([]byte(nil), seg.Payload...)
		if !e.tryEnqueueTCPWrite(conn, tcpWriteItem{payload: payload}) {
			// Queue full: backpressure. Do NOT advance appSeq or
			// ACK the data (the ACK below is the old expectation):
			// the app retransmits instead of believing data
			// delivered while it sits queued on the phone.
			e.sendTCPUnlocked(conn, TCPAck, nil)
			return
		}
		conn.appSeq += uint32(len(payload))
		e.sendTCPUnlocked(conn, TCPAck, nil)
	}
}

// processAckLocked folds an incoming ACK into download state.
// Caller holds e.mu. It records the advertised window, advances
// peerAck, drops acknowledged download segments, counts duplicate
// ACKs (fast retransmit at threshold), and wakes pumpTCP's window
// wait. The window is raw (unscaled): if window scaling was
// negotiated the real buffer is larger, so treating the raw value
// as the cap can only under-send, never overflow the app's buffer.
func (e *Engine) processAckLocked(conn *tcpConn, seg *TCPSegment) {
	conn.appWindow = uint32(seg.Window)
	ack := seg.Ack
	if int32(ack-conn.ourSeq) > 0 {
		// App ACKing beyond anything sent: clamp, never let peerAck
		// run past ourSeq (else the window math goes negative).
		ack = conn.ourSeq
	}
	if int32(ack-conn.peerAck) > 0 {
		conn.peerAck = ack
		conn.dupAckCount = 0
		for len(conn.sendBuf) > 0 {
			s := conn.sendBuf[0]
			if int32(s.seq+uint32(len(s.data))-ack) <= 0 {
				conn.sendBuf = conn.sendBuf[1:]
			} else {
				break
			}
		}
	} else if ack == conn.peerAck && len(conn.sendBuf) > 0 && int32(conn.ourSeq-ack) > 0 {
		// Duplicate ACK for the oldest unacked segment.
		conn.dupAckCount++
		if conn.dupAckCount >= tcpDupAckThreshold {
			conn.dupAckCount = 0
			e.retransmitLocked(conn, 0)
		}
	}
	e.signalAckWait(conn)
}

// signalAckWait wakes pumpTCP's window wait, if it is waiting. The
// send never blocks, so it is safe under e.mu.
func (e *Engine) signalAckWait(conn *tcpConn) {
	select {
	case conn.ackCh <- struct{}{}:
	default:
	}
}

// retransmitLocked resends sendBuf[idx] (0 = oldest unacked) with
// its original sequence number. Caller holds e.mu; a single TUN
// write is brief.
func (e *Engine) retransmitLocked(conn *tcpConn, idx int) {
	if idx < 0 || idx >= len(conn.sendBuf) {
		return
	}
	s := conn.sendBuf[idx]
	seg := BuildTCP(
		addrOf(conn.tuple.DstIP), addrOf(conn.tuple.SrcIP),
		conn.tuple.DstPort, conn.tuple.SrcPort,
		s.seq, conn.appSeq, TCPPsh|TCPAck, s.data,
	)
	e.writeTUNLocked(conn.tuple, seg)
	conn.sendBuf[idx].sentAt = time.Now()
}

// finishConnLocked completes a normally-ended connection: FIN to
// the app (if not already sent), Mist stream Close (freeing the
// SID — the pre-fix leak: neither pumpTCP EOF nor pure-ACK cleanup
// closed the stream, so 1-byte SIDs wrapped into leaked streams
// after 255 short connections), writer stop, table removal.
// Caller holds e.mu. Not used for abnormal teardown (RST, writer
// error, sweeper), which must not send FIN.
func (e *Engine) finishConnLocked(c *tcpConn, tuple FourTuple) {
	if !c.ourFin {
		c.ourFin = true
		e.sendTCPUnlocked(c, TCPFin|TCPAck, nil)
	}
	c.stream.Close()
	stopTCPWriterLocked(c)
	delete(e.tcp, tuple)
}

// dialTCP opens the proxy stream, then answers the app's SYN.
func (e *Engine) dialTCP(ctx context.Context, p *IPPacket, tuple FourTuple, syn *TCPSegment) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mist: dialTCP panic (recovered): %v", r)
		}
	}()
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
	appWindow := uint32(syn.Window)
	if appWindow == 0 {
		appWindow = 65535
	}
	conn := &tcpConn{
		tuple:     tuple,
		stream:    stream,
		appSeq:    syn.Seq + 1,
		ourSeq:    isn,
		isn:       isn,
		created:   time.Now(),
		lastAct:   time.Now(),
		peerAck:   isn + 1, // post-SYN-ACK state; nothing outstanding yet
		appWindow: appWindow,
		ackCh:     make(chan struct{}, 1),
	}
	conn.sendCond = sync.NewCond(&conn.sendMu)
	e.mu.Lock()
	if e.closed.Load() {
		// Engine closed while dialing: do not insert (Close's
		// snapshot already ran) — just release the stream.
		e.mu.Unlock()
		stream.Close()
		return
	}
	e.tcp[tuple] = conn
	e.mu.Unlock()
	e.sendTCPSYNACK(conn)
	go e.pumpTCP(conn)
	go e.tcpWriter(conn)
	go e.retransmitLoop(conn)
}

// tryEnqueueTCPWrite appends an item to the connection's FIFO writer
// queue if it fits the cap, reporting whether it was accepted. FIN
// markers always fit (0 bytes) and must never be dropped, or the
// half-close is lost. Over-cap payload is rejected: the caller must
// NOT advance appSeq or ACK it, so the app retransmits instead of
// believing data delivered. It never blocks on the network: only a
// brief sendMu hold for the append and signal, so callers may hold
// e.mu (lock order e.mu -> sendMu). Items for a torn-down
// connection are dropped: the stream is already closed and the app
// side is being reset.
func (e *Engine) tryEnqueueTCPWrite(conn *tcpConn, item tcpWriteItem) bool {
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()
	if conn.sendClosed {
		return false
	}
	if !item.fin && conn.queuedBytes+len(item.payload) > maxSendQueueBytes {
		return false
	}
	conn.sendQ = append(conn.sendQ, item)
	conn.queuedBytes += len(item.payload)
	conn.sendCond.Signal()
	return true
}

// tcpWriter is the single writer goroutine per TCP connection. It drains
// the FIFO queue strictly in order, so stream writes for one connection
// are never concurrent and never reordered, regardless of how fast the
// app pipelines segments. It holds sendMu only while dequeuing; the
// blocking stream Write happens with no lock held, so a slow Mist
// write stalls only this connection, never the engine Run loop or
// pumpTCP.
func (e *Engine) tcpWriter(conn *tcpConn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mist: tcpWriter panic (recovered): %v", r)
		}
	}()
	for {
		conn.sendMu.Lock()
		for len(conn.sendQ) == 0 && !conn.sendClosed {
			conn.sendCond.Wait()
		}
		if len(conn.sendQ) == 0 { // closed and drained: exit
			conn.sendMu.Unlock()
			return
		}
		item := conn.sendQ[0]
		conn.sendQ[0] = tcpWriteItem{} // release the payload reference
		conn.sendQ = conn.sendQ[1:]
		conn.queuedBytes -= len(item.payload)
		conn.sendMu.Unlock()
		if item.fin {
			if closer, ok := conn.stream.(interface{ CloseWrite() error }); ok {
				_ = closer.CloseWrite()
			}
			continue
		}
		if _, err := conn.stream.Write(item.payload); err != nil {
			e.dropTCP(conn.tuple)
			return
		}
		e.upBytes.Add(uint64(len(item.payload)))
	}
}

// stopTCPWriterLocked wakes a connection's writer so it can exit once
// the queue drains. Caller must hold e.mu (lock order e.mu -> sendMu,
// consistent with tryEnqueueTCPWrite's callers and dropTCP).
func stopTCPWriterLocked(c *tcpConn) {
	c.sendMu.Lock()
	c.sendClosed = true
	c.sendCond.Broadcast()
	c.sendMu.Unlock()
}

// maxTCPSegmentPayload caps one return segment's payload so the
// resulting IP packet stays under the TUN MTU (Weave sets 1400):
// 1200 + 20 (TCP) + 20/40 (IPv4/IPv6) <= 1260/1280. A single Read of
// up to 8192 bytes must never become one 8232-byte DF packet: the
// phone stack drops oversized DF packets, which was the 1.0.33
// return-path failure (SYN-ACKs arrived, bulk TCP data did not).
const maxTCPSegmentPayload = 1200

// pumpTCP copies stream data back to the app as TCP segments,
// chunked to maxTCPSegmentPayload with contiguous sequence numbers.
// It never reads more than the app's advertised window allows, so
// no download backlog can accumulate behind a stalled app, and it
// never holds e.mu across the whole chunk loop (the old code
// starved handleTCP for the entire 8192-byte write-out).
func (e *Engine) pumpTCP(conn *tcpConn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mist: pumpTCP panic (recovered): %v", r)
		}
	}()
	buf := make([]byte, 8192)
	for {
		// Wait for window room, then read at most what fits.
		avail := e.waitWindow(conn, buf)
		if avail == 0 {
			return // connection gone
		}
		n, err := conn.stream.Read(buf[:avail])
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			if !e.sendDownload(conn, data) {
				return // connection gone
			}
			e.downBytes.Add(uint64(len(data)))
		}
		if err != nil {
			e.onStreamEOF(conn)
			return
		}
	}
}

// waitWindow blocks until at least one byte of the app's window is
// available, returning how many bytes may be read (capped at the
// buffer), or 0 if the connection is gone. It never holds e.mu
// while waiting: handleTCP needs e.mu to process the ACKs that open
// the window. Missed wakeups are impossible: the wake signal is a
// buffered channel send plus a 50ms recheck backstop.
func (e *Engine) waitWindow(conn *tcpConn, buf []byte) int {
	for {
		e.mu.Lock()
		_, ok := e.tcp[conn.tuple]
		if !ok {
			e.mu.Unlock()
			return 0
		}
		inflight := int64(int32(conn.ourSeq - conn.peerAck))
		if inflight < 0 {
			inflight = 0
		}
		avail := int64(conn.appWindow) - inflight
		e.mu.Unlock()
		if avail > 0 {
			if avail > int64(len(buf)) {
				avail = int64(len(buf))
			}
			return int(avail)
		}
		select {
		case <-conn.ackCh:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// sendDownload chunks data into <=maxTCPSegmentPayload segments,
// reserves their sequence numbers and records them for retransmit
// under e.mu, then writes them to the TUN WITHOUT holding e.mu
// (sequence numbers and the ACK field are snapshotted first, so a
// concurrent handleTCP advance can only make the ACK field slightly
// stale, never wrong-ordered). Returns false if the connection is
// gone.
func (e *Engine) sendDownload(conn *tcpConn, data []byte) bool {
	type chunk struct {
		seq  uint32
		data []byte
	}
	var chunks []chunk
	e.mu.Lock()
	if _, ok := e.tcp[conn.tuple]; !ok {
		e.mu.Unlock()
		return false
	}
	seq := conn.ourSeq
	ack := conn.appSeq
	now := time.Now()
	for off := 0; off < len(data); {
		n := len(data) - off
		if n > maxTCPSegmentPayload {
			n = maxTCPSegmentPayload
		}
		c := data[off : off+n]
		chunks = append(chunks, chunk{seq: seq, data: c})
		conn.sendBuf = append(conn.sendBuf, sentSeg{seq: seq, data: c, sentAt: now})
		seq += uint32(n)
		off += n
	}
	conn.ourSeq = seq
	conn.lastAct = now
	e.mu.Unlock()
	for _, c := range chunks {
		seg := BuildTCP(
			addrOf(conn.tuple.DstIP), addrOf(conn.tuple.SrcIP),
			conn.tuple.DstPort, conn.tuple.SrcPort,
			c.seq, ack, TCPPsh|TCPAck, c.data,
		)
		e.writeTUNLocked(conn.tuple, seg)
	}
	return true
}

// onStreamEOF handles server-side close. If every download segment
// is already ACKed, the connection completes immediately (FIN to
// the app, stream Close freeing the SID). Otherwise the FIN waits:
// eofSeen marks the close pending, and the ACK-driven finish path
// in handleTCP sends the FIN once sendBuf drains. Sending FIN
// first would make the app close before receiving all data.
func (e *Engine) onStreamEOF(conn *tcpConn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.tcp[conn.tuple]
	if !ok {
		return
	}
	c.eofSeen = true
	if len(c.sendBuf) == 0 {
		e.finishConnLocked(c, conn.tuple)
	}
}

// retransmitLoop is the RTO backstop: if the oldest unacked segment
// ages past tcpRTO without an ACK, resend it. Fast retransmit (from
// duplicate ACKs in handleTCP) covers most losses; this covers the
// tail, where no later segment exists to generate duplicate ACKs.
// Exits when the connection leaves the table.
func (e *Engine) retransmitLoop(conn *tcpConn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mist: retransmitLoop panic (recovered): %v", r)
		}
	}()
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		e.mu.Lock()
		_, ok := e.tcp[conn.tuple]
		if !ok {
			e.mu.Unlock()
			return
		}
		if len(conn.sendBuf) > 0 && time.Since(conn.sendBuf[0].sentAt) > tcpRTO {
			e.retransmitLocked(conn, 0)
		}
		e.mu.Unlock()
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
// The stream is closed AFTER releasing e.mu: even though stream
// Close is now non-blocking, teardown must never hold the engine
// lock across a close (defense in depth against any future
// blocking close path wedging the Run loop).
func (e *Engine) dropTCP(tuple FourTuple) {
	e.mu.Lock()
	c, ok := e.tcp[tuple]
	if ok {
		delete(e.tcp, tuple)
	}
	e.mu.Unlock()
	if !ok {
		return
	}
	c.stream.Close()
	stopTCPWriterLocked(c)
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

func (e *Engine) handleUDP(p *IPPacket, dg *UDPPacket) {
	if e.dg == nil {
		return // client has no datagram support
	}
	if e.closed.Load() {
		return
	}
	// Bound in-flight send goroutines: without this a wedged
	// session piles up one blocked goroutine per app datagram
	// (chatty UDP apps retry hard), and thousands of stacks plus
	// scheduler pressure starve the phone's UI thread. UDP is
	// loss-tolerant, so excess datagrams are dropped here — the
	// app retransmits — instead of queued forever.
	select {
	case e.udpSem <- struct{}{}:
	default:
		return
	}
	tuple := TupleOf(p, dg.SrcPort, dg.DstPort)
	e.mu.Lock()
	if _, ok := e.udp[tuple]; !ok {
		e.udp[tuple] = &udpSession{tuple: tuple, lastAct: time.Now()}
	}
	dst := dstKey(p.Dst.String(), dg.DstPort)
	e.udpByDst[dst] = appendTuple(e.udpByDst[dst], tuple)
	if dg.DstPort == 53 && len(dg.Payload) >= 2 {
		txID := binary.BigEndian.Uint16(dg.Payload[:2])
		e.udpByDNS[dnsKey(p.Dst.String(), dg.DstPort, txID)] = tuple
	}
	e.mu.Unlock()
	target := net.JoinHostPort(p.Dst.String(), fmt.Sprint(dg.DstPort))
	payload := append([]byte(nil), dg.Payload...)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("mist: udp send panic (recovered): %v", r)
			}
			<-e.udpSem
		}()
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
	var tuple FourTuple
	var ok bool
	// DNS first: the transaction ID tells concurrent queries to
	// the same server apart. Anything else falls back to the most
	// recent session for this destination (the old overwrite
	// semantics), which stays correct while only one session is
	// live per destination.
	if port == 53 && len(data) >= 2 {
		txID := binary.BigEndian.Uint16(data[:2])
		if t, hit := e.udpByDNS[dnsKey(host, uint16(port), txID)]; hit {
			tuple, ok = t, true
		}
	}
	if !ok {
		if list := e.udpByDst[dstKey(host, uint16(port))]; len(list) > 0 {
			tuple, ok = list[len(list)-1], true
		}
	}
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

// dnsKey identifies one DNS exchange for return routing.
func dnsKey(ip string, port uint16, txID uint16) string {
	return dstKey(ip, port) + "|" + fmt.Sprintf("%04x", txID)
}

// appendTuple adds tuple to the per-destination list, most recent
// last, without duplicates: a repeat query from the same tuple just
// refreshes its recency.
func appendTuple(list []FourTuple, tuple FourTuple) []FourTuple {
	out := list[:0]
	for _, t := range list {
		if t != tuple {
			out = append(out, t)
		}
	}
	return append(out, tuple)
}

// removeUDPTupleLocked drops tuple from every return-routing index.
// Callers hold e.mu (currently only the sweeper).
func (e *Engine) removeUDPTupleLocked(tuple FourTuple) {
	for dst, list := range e.udpByDst {
		kept := list[:0]
		for _, t := range list {
			if t != tuple {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(e.udpByDst, dst)
		} else {
			e.udpByDst[dst] = kept
		}
	}
	for key, t := range e.udpByDNS {
		if t == tuple {
			delete(e.udpByDNS, key)
		}
	}
}

func addrOf(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPv4zero
	}
	return ip
}

// writeTUNLocked wraps a segment in an IP packet and writes it to the
// TUN. Despite the name it does NOT require e.mu: IP IDs are atomic
// and TUN writes are serialized by tunMu, so pumpTCP can write
// chunks without starving handleTCP. Write failures and short writes
// are counted (and logged, throttled) instead of silently swallowed:
// a nonzero TunWriteErrors is the first signal when return traffic
// stalls.
func (e *Engine) writeTUNLocked(tuple FourTuple, segment []byte) {
	var proto uint8
	if tuple.Proto == ProtoTCP {
		proto = ProtoTCP
	} else {
		proto = ProtoUDP
	}
	src := addrOf(tuple.DstIP) // proxy side: source is the remote
	dst := addrOf(tuple.SrcIP) // destination is the app
	id := uint16(e.id.Add(1))
	pkt := BuildIP(src, dst, proto, id, segment)
	e.tunMu.Lock()
	n, err := e.tun.Write(pkt)
	e.tunMu.Unlock()
	if err != nil || n != len(pkt) {
		c := e.tunWriteErrs.Add(1)
		if c <= 10 || c%100 == 0 {
			log.Printf("mist: tun write failed: n=%d len=%d err=%v (count=%d)", n, len(pkt), err, c)
		}
	}
}

// sweeper removes idle connections.
func (e *Engine) sweeper(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("mist: sweeper panic (recovered): %v", r)
		}
	}()
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
			var idle []*tcpConn
			for tuple, c := range e.tcp {
				// Idle-based, not age-based: a long-lived but
				// active connection (persistent app session) must
				// not be killed at 10 minutes old, while a truly
				// idle one is reaped on the same timescale.
				if now.Sub(c.lastAct) > tcpIdleTimeout {
					idle = append(idle, c)
					delete(e.tcp, tuple)
				}
			}
			for tuple, s := range e.udp {
				if now.Sub(s.lastAct) > 2*time.Minute {
					delete(e.udp, tuple)
					e.removeUDPTupleLocked(tuple)
				}
			}
			e.mu.Unlock()
			// Close outside e.mu (see dropTCP).
			for _, c := range idle {
				c.stream.Close()
				stopTCPWriterLocked(c)
			}
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
		udpByDst: make(map[string][]FourTuple),
		udpByDNS: make(map[string]FourTuple),
		udpSem:   make(chan struct{}, maxInFlightUDPSends),
		done:     make(chan struct{}),
	}
	if dg, ok := interface{}(client).(DatagramClient); ok {
		e.dg = dg
		dg.OnDatagram(e.onDatagram)
	}
	return e
}
