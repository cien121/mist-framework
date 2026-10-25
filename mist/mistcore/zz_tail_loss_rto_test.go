// Repro + regression for: server-side S2C tail loss never recovered.
//
// Production symptom (2026-10-23 lab): 100KB echo intermittently failed with
//   "timeout waiting for peer (got 101200/102400 bytes)"
// i.e. the last ~3 echo packets were lost and never retransmitted within the
// 30s client timeout.
//
// Root cause: cmd/mist-server/main.go's periodic loop (ackFlushLoop) only
// called sess.Rel.FlushAck() — it NEVER called sess.Rel.CheckRTO(). The
// OnRetransmit callback was wired correctly, but nothing ever invoked the
// RTO scan on the server, so any server->client packet loss was permanent.
// Fast retransmit can't save the tail either: it needs 3 dup ACKs, but after
// a clean tail drop no more packets arrive to generate them.
// The sandbox never caught it because the in-process harness drove
// srv.Rel.CheckRTO() manually on both ends.
//
// This test models the production server tick EXACTLY. serverTick below MUST
// be kept in sync with tickLoop in cmd/mist-server/main.go:
//   - pre-fix:  FlushAck() only            -> test FAILS (bug repro, verified 2026-10-23)
//   - post-fix: UDPSession.Tick()           -> test PASSES (regression guard)
// serverTick calls the same entry point (srv.Tick()) as production, so the
// test breaks if the two ever diverge.
//
// Scenario: server srtt seeded to 200ms (as a real 200ms-RTT session would
// have), 100KB echo where the last 3 S2C echo datagrams are dropped. Asserts
// the server's RTO fires and the tail is recovered within a reasonable time.
package mistcore

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestZZTailLossServerRTO(t *testing.T) {
	cur := time.Now()
	startTime := cur
	now := func() time.Time { return cur }
	advance := func(d time.Duration) { cur = cur.Add(d) }

	var sessionID [16]byte
	mustRand(sessionID[:])
	var kC2S, kS2C [32]byte
	mustRand(kC2S[:])
	mustRand(kS2C[:])
	codec := &QUICInitialCodec{}
	cliAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:1111")
	srvAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:2222")
	cli := NewUDPSession(sessionID, kC2S, kS2C, srvAddr, codec)
	srv := NewUDPSession(sessionID, kC2S, kS2C, cliAddr, codec)
	cli.Rel.now = now
	srv.Rel.now = now
	// Seed server RTT as a real 200ms-RTT session would have after handshakes.
	// RTO = 200ms + max(4*25ms, 200/8ms, 1ms) + 10ms = 310ms.
	srv.Rel.srtt = 200 * time.Millisecond
	srv.Rel.rttvar = 25 * time.Millisecond

	var cliToSrv, srvToCli [][]byte
	// isEcho[i] marks srvToCli[i] as an echo datagram (vs untracked ACK).
	var isEcho []bool
	srvRetrans := 0

	cli.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		d, err := cli.SealPacketUntracked(DirC2S, [][]byte{EncodeAckFrame(0, largest, ackDelay, ranges)})
		if err != nil {
			t.Fatalf("cli ack seal: %v", err)
		}
		cliToSrv = append(cliToSrv, d)
	}
	cli.Rel.OnRetransmit = func(frames [][]byte) error {
		d, err := cli.sealPacketTracked(DirC2S, frames)
		if err != nil {
			t.Fatalf("cli retransmit seal: %v", err)
		}
		cliToSrv = append(cliToSrv, d)
		return nil
	}
	srv.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		d, err := srv.SealPacketUntracked(DirS2C, [][]byte{EncodeAckFrame(0, largest, ackDelay, ranges)})
		if err != nil {
			t.Fatalf("srv ack seal: %v", err)
		}
		srvToCli = append(srvToCli, d)
		isEcho = append(isEcho, false)
	}
	srv.Rel.OnRetransmit = func(frames [][]byte) error {
		srvRetrans++
		// Chunk to fit MaxUDPPlaintext (RTO may batch several packets).
		var batch [][]byte
		batchSize := 0
		flush := func() {
			if len(batch) == 0 {
				return
			}
			d, err := srv.sealPacketTracked(DirS2C, batch)
			if err != nil {
				t.Fatalf("srv retransmit seal: %v", err)
			}
			srvToCli = append(srvToCli, d)
			isEcho = append(isEcho, true)
			batch = nil
			batchSize = 0
		}
		for _, f := range frames {
			if batchSize+len(f) > MaxUDPPlaintext && len(batch) > 0 {
				flush()
			}
			batch = append(batch, f)
			batchSize += len(f)
		}
		flush()
		t.Logf("server retransmit #%d at +%v (srtt=%v rttvar=%v rto=%v)", srvRetrans, cur.Sub(startTime), srv.Rel.srtt, srv.Rel.rttvar, srv.Rel.RTO())
		return nil
	}

	// Server frame handling mirrors handleData's echo switch.
	handleSrv := func(dgram []byte) {
		frames, _, err := srv.OpenPacket(DirC2S, dgram)
		if err != nil {
			t.Fatalf("srv open: %v", err)
		}
		for _, f := range frames {
			switch f.Type {
			case UDPFrameAck:
				largest, ackDelay, ranges, err := DecodeAckFrame(f.Payload)
				if err != nil {
					t.Fatalf("srv ack decode: %v", err)
				}
				srv.Rel.ProcessAck(largest, ackDelay, ranges)
			case UDPFrameStream:
				echo := EncodeUDPFrame(UDPFrameStream, f.SID, f.Payload)
				d, err := srv.sealPacketTracked(DirS2C, [][]byte{echo})
				if err != nil {
					t.Fatalf("srv echo seal: %v", err)
				}
				srvToCli = append(srvToCli, d)
				isEcho = append(isEcho, true)
			case UDPFrameSyn:
			}
		}
	}

	const total = 100 * 1024
	rxBuf := make([]byte, total)
	rxSeen := make([]bool, total)
	rxGot := 0
	handleCli := func(dgram []byte) {
		frames, _, err := cli.OpenPacket(DirS2C, dgram)
		if err != nil {
			t.Fatalf("cli open: %v", err)
		}
		for _, f := range frames {
			if f.Type == UDPFrameAck {
				largest, ackDelay, ranges, err := DecodeAckFrame(f.Payload)
				if err != nil {
					t.Fatalf("cli ack decode: %v", err)
				}
				cli.Rel.ProcessAck(largest, ackDelay, ranges)
				continue
			}
			if f.Type == UDPFrameStream && len(f.Payload) >= 8 {
				off := binary.BigEndian.Uint64(f.Payload[:8])
				for i, b := range f.Payload[8:] {
					idx := int(off) + i
					if !rxSeen[idx] {
						rxSeen[idx] = true
						rxGot++
					}
					rxBuf[idx] = b
				}
			}
		}
	}

	// Drains use no time advancement (batching keeps ACKs finite), exactly
	// like TestZZEchoSim's proven pattern. Only Phase 3 advances the clock.
	var echoHold [][]byte
	drainC2S := func() {
		for len(cliToSrv) > 0 {
			d := cliToSrv[0]
			cliToSrv = cliToSrv[1:]
			handleSrv(d)
		}
	}
	drainS2CHoldEcho := func() {
		for len(srvToCli) > 0 {
			d := srvToCli[0]
			srvToCli = srvToCli[1:]
			e := isEcho[0]
			isEcho = isEcho[1:]
			if e {
				echoHold = append(echoHold, d)
			} else {
				handleCli(d)
			}
		}
	}

	// Phase 1: client sends 100KB; server echoes (held back).
	cliSend := func(frames ...[]byte) {
		d, err := cli.sealPacketTracked(DirC2S, frames)
		if err != nil {
			t.Fatalf("cli seal: %v", err)
		}
		cliToSrv = append(cliToSrv, d)
	}
	cliSend(EncodeUDPFrame(UDPFrameSyn, 1, nil))
	data := make([]byte, total)
	for i := range data {
		data[i] = byte(i*31 + 7)
	}
	for o := 0; o < total; o += 1200 {
		n := 1200
		if o+n > total {
			n = total - o
		}
		cliSend(EncodeStreamFrame(1, uint64(o), data[o:o+n]))
	}
	for i := 0; i < 8; i++ {
		drainC2S()
		drainS2CHoldEcho()
	}
	// Discard background ACK leftovers; only held echoes matter now.
	cliToSrv, srvToCli, isEcho = nil, nil, nil
	t.Logf("phase 1: %d echoes held, srv sentPackets=%d", len(echoHold), len(srv.Rel.sentPackets))

	// Phase 2: deliver all echoes EXCEPT the last 3 (tail loss), then flush
	// the resulting client ACKs. Afterwards the server must hold exactly the
	// 3 dropped packets and nothing else.
	const dropTail = 3
	if len(echoHold) < dropTail+1 {
		t.Fatalf("not enough echoes held: %d", len(echoHold))
	}
	for i, d := range echoHold {
		if i >= len(echoHold)-dropTail {
			t.Logf("dropping tail echo %d/%d", i+1, len(echoHold))
			continue
		}
		handleCli(d)
	}
	echoHold = nil
	for i := 0; i < 8; i++ {
		drainC2S()
		// S2C now carries only background ACKs; deliver them.
		for len(srvToCli) > 0 {
			d := srvToCli[0]
			srvToCli = srvToCli[1:]
			if len(isEcho) > 0 {
				isEcho = isEcho[1:]
			}
			handleCli(d)
		}
	}
	cliToSrv, srvToCli, isEcho = nil, nil, nil
	t.Logf("phase 2: rxGot=%d/%d srv sentPackets=%d (want >=%d)",
		rxGot, total, len(srv.Rel.sentPackets), dropTail)
	if rxGot == total {
		t.Fatalf("tail drop did not take effect")
	}
	if n := len(srv.Rel.sentPackets); n < dropTail {
		t.Fatalf("server sentPackets=%d, want at least %d (the dropped tail)", n, dropTail)
	}

	// Phase 3: 10ms tick loop, 30s simulated. This is the only phase where
	// the clock advances, so RTO can fire.
	// serverTick calls the same UDPSession.Tick() entry point as production
	// tickLoop in cmd/mist-server/main.go; clientTick mirrors the client's
	// pump loop (also Tick() since the Tick() bundling).
	serverTick := func() {
		srv.Tick()
	}
	clientTick := func() {
		cli.Tick()
	}
	drainInstant := func() {
		for len(cliToSrv) > 0 {
			d := cliToSrv[0]
			cliToSrv = cliToSrv[1:]
			handleSrv(d)
		}
		for len(srvToCli) > 0 {
			d := srvToCli[0]
			srvToCli = srvToCli[1:]
			if len(isEcho) > 0 {
				isEcho = isEcho[1:]
			}
			handleCli(d)
		}
	}
	deadline := cur.Add(30 * time.Second)
	for rxGot < total && cur.Before(deadline) {
		advance(10 * time.Millisecond)
		serverTick()
		clientTick()
		drainInstant()
	}

	t.Logf("phase 3: rxGot=%d/%d srvRetrans=%d simElapsed=%v",
		rxGot, total, srvRetrans, cur.Sub(startTime))
	if rxGot != total {
		t.Fatalf("BUG REPRO: tail loss not recovered: got %d/%d, server retransmits=%d",
			rxGot, total, srvRetrans)
	}
	for i := range data {
		if rxBuf[i] != data[i] {
			t.Fatalf("data mismatch at byte %d", i)
		}
	}
	if srvRetrans == 0 {
		t.Fatalf("expected server RTO retransmits, got 0")
	}
	t.Logf("PASS: server RTO recovered tail loss with %d retransmit(s)", srvRetrans)
}

// Symmetric to TestZZTailLossServerRTO: drop the LAST 3 client->server
// datagrams and assert the CLIENT's RTO recovers them. This is the mirror
// image of the 2026-10-23 lab bug: it proves UDPSession.Tick() drives
// CheckRTO on the client side too, not just the server.
//
// Scenario: client sends 10 stream packets (simulated clock, 200ms RTT);
// the last 3 never reach the server. Client Tick() every 10ms must fire RTO
// (~310ms) and retransmit; the server must eventually receive all 10.
func TestZZTailLossClientRTO(t *testing.T) {
	cur := time.Now()
	startTime := cur
	now := func() time.Time { return cur }
	advance := func(d time.Duration) { cur = cur.Add(d) }

	var sessionID [16]byte
	mustRand(sessionID[:])
	var kC2S, kS2C [32]byte
	mustRand(kC2S[:])
	mustRand(kS2C[:])
	codec := &QUICInitialCodec{}
	cliAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:1111")
	srvAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:2222")
	cli := NewUDPSession(sessionID, kC2S, kS2C, srvAddr, codec)
	srv := NewUDPSession(sessionID, kC2S, kS2C, cliAddr, codec)
	cli.Rel.now = now
	srv.Rel.now = now
	// Seed client RTT as a real 200ms-RTT session would have.
	// RTO = 200ms + max(4*25ms, 200/8ms, 1ms) + 10ms = 310ms.
	cli.Rel.srtt = 200 * time.Millisecond
	cli.Rel.rttvar = 25 * time.Millisecond

	var cliToSrv, srvToCli [][]byte
	cliRetrans := 0
	srvGot := make([]bool, 10)

	cli.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		d, err := cli.SealPacketUntracked(DirC2S, [][]byte{EncodeAckFrame(0, largest, ackDelay, ranges)})
		if err != nil {
			t.Fatalf("cli ack seal: %v", err)
		}
		cliToSrv = append(cliToSrv, d)
	}
	cli.Rel.OnRetransmit = func(frames [][]byte) error {
		cliRetrans++
		t.Logf("client retransmit #%d at +%v (srtt=%v rttvar=%v rto=%v)", cliRetrans, cur.Sub(startTime), cli.Rel.srtt, cli.Rel.rttvar, cli.Rel.RTO())
		// Chunk to fit MaxUDPPlaintext (RTO may batch several packets).
		var batch [][]byte
		batchSize := 0
		flush := func() {
			if len(batch) == 0 {
				return
			}
			d, err := cli.sealPacketTracked(DirC2S, batch)
			if err != nil {
				t.Fatalf("cli retransmit seal: %v", err)
			}
			cliToSrv = append(cliToSrv, d)
			batch = nil
			batchSize = 0
		}
		for _, f := range frames {
			if batchSize+len(f) > MaxUDPPlaintext && len(batch) > 0 {
				flush()
			}
			batch = append(batch, f)
			batchSize += len(f)
		}
		flush()
		return nil
	}
	srv.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		d, err := srv.SealPacketUntracked(DirS2C, [][]byte{EncodeAckFrame(0, largest, ackDelay, ranges)})
		if err != nil {
			t.Fatalf("srv ack seal: %v", err)
		}
		srvToCli = append(srvToCli, d)
	}
	srv.Rel.OnRetransmit = func(frames [][]byte) error {
		// Server should have nothing to retransmit in this scenario.
		d, err := srv.sealPacketTracked(DirS2C, frames)
		if err != nil {
			t.Fatalf("srv retransmit seal: %v", err)
		}
		srvToCli = append(srvToCli, d)
		return nil
	}

	handleSrv := func(dgram []byte) {
		frames, _, err := srv.OpenPacket(DirC2S, dgram)
		if err != nil {
			t.Fatalf("srv open: %v", err)
		}
		for _, f := range frames {
			switch f.Type {
			case UDPFrameAck:
				largest, ackDelay, ranges, err := DecodeAckFrame(f.Payload)
				if err != nil {
					t.Fatalf("srv ack decode: %v", err)
				}
				srv.Rel.ProcessAck(largest, ackDelay, ranges)
			case UDPFrameStream:
				// Payload layout from EncodeStreamFrame: [OFFSET(8)][DATA].
				if len(f.Payload) >= 8 {
					off := binary.BigEndian.Uint64(f.Payload[:8])
					idx := int(off / 1200)
					if idx >= 0 && idx < len(srvGot) {
						srvGot[idx] = true
					}
				}
			}
		}
	}
	handleCli := func(dgram []byte) {
		frames, _, err := cli.OpenPacket(DirS2C, dgram)
		if err != nil {
			t.Fatalf("cli open: %v", err)
		}
		for _, f := range frames {
			if f.Type == UDPFrameAck {
				largest, ackDelay, ranges, err := DecodeAckFrame(f.Payload)
				if err != nil {
					t.Fatalf("cli ack decode: %v", err)
				}
				cli.Rel.ProcessAck(largest, ackDelay, ranges)
			}
		}
	}

	// Phase 1: client sends 10 stream packets. Drop the last 3 in transit.
	const nPkts = 10
	const dropTail = 3
	var c2sHold [][]byte
	for i := 0; i < nPkts; i++ {
		payload := make([]byte, 1200)
		for j := range payload {
			payload[j] = byte(i*31 + j)
		}
		d, err := cli.sealPacketTracked(DirC2S, [][]byte{EncodeStreamFrame(1, uint64(i*1200), payload)})
		if err != nil {
			t.Fatalf("cli seal: %v", err)
		}
		c2sHold = append(c2sHold, d)
	}
	for i, d := range c2sHold {
		if i >= nPkts-dropTail {
			t.Logf("dropping tail C2S packet %d/%d", i+1, nPkts)
			continue
		}
		cliToSrv = append(cliToSrv, d)
	}
	c2sHold = nil

	drainInstant := func() {
		for len(cliToSrv) > 0 {
			d := cliToSrv[0]
			cliToSrv = cliToSrv[1:]
			handleSrv(d)
		}
		for len(srvToCli) > 0 {
			d := srvToCli[0]
			srvToCli = srvToCli[1:]
			handleCli(d)
		}
	}
	drainInstant() // deliver the 7 + their ACKs
	cliToSrv, srvToCli = nil, nil

	got := 0
	for _, g := range srvGot {
		if g {
			got++
		}
	}
	t.Logf("phase 1: server got %d/%d (tail dropped)", got, nPkts)
	if got != nPkts-dropTail {
		t.Fatalf("phase 1 setup wrong: server got %d, want %d", got, nPkts-dropTail)
	}
	t.Logf("phase 1 end: client srtt=%v rttvar=%v rto=%v", cli.Rel.srtt, cli.Rel.rttvar, cli.Rel.RTO())

	// Phase 2: 10ms tick loop, 30s simulated. Client Tick() must fire RTO
	// (~310ms) and retransmit the dropped tail; server ACKs them.
	srvGotCount := func() int {
		n := 0
		for _, g := range srvGot {
			if g {
				n++
			}
		}
		return n
	}
	deadline := cur.Add(30 * time.Second)
	for srvGotCount() < nPkts && cur.Before(deadline) {
		advance(10 * time.Millisecond)
		cli.Tick()
		srv.Tick()
		drainInstant()
	}

	t.Logf("phase 2: server got %d/%d cliRetrans=%d simElapsed=%v",
		srvGotCount(), nPkts, cliRetrans, cur.Sub(startTime))
	if srvGotCount() != nPkts {
		t.Fatalf("client RTO did not recover tail loss: server got %d/%d, client retransmits=%d",
			srvGotCount(), nPkts, cliRetrans)
	}
	if cliRetrans == 0 {
		t.Fatalf("expected client RTO retransmits, got 0")
	}
	t.Logf("PASS: client RTO recovered tail loss with %d retransmit(s)", cliRetrans)
}
