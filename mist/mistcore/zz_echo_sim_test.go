// Throwaway verification for the lab echo path (client <-> server sessions
// in-process, no UDP sockets). Exercises SealPacketUntracked, server STREAM
// echo + FIN echo + ACK wiring, and client-side reassembly/FIN wait.
package mistcore

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestZZEchoSim(t *testing.T) {
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

	// In-memory "wires".
	var cliToSrv, srvToCli [][]byte
	cliRetrans, srvRetrans := 0, 0

	cli.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32, ackDelay time.Duration) {
		d, err := cli.SealPacketUntracked(DirC2S, [][]byte{EncodeAckFrame(0, largest, ackDelay, ranges)})
		if err != nil {
			t.Fatalf("cli ack seal: %v", err)
		}
		cliToSrv = append(cliToSrv, d)
		t.Logf("cli sent ACK largest=%d ranges=%v", largest, ranges)
	}
	cli.Rel.OnRetransmit = func(frames [][]byte) error {
		cliRetrans++
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
		t.Logf("srv sent ACK largest=%d ranges=%v", largest, ranges)
	}
	srv.Rel.OnRetransmit = func(frames [][]byte) error {
		srvRetrans++
		d, err := srv.sealPacketTracked(DirS2C, frames)
		if err != nil {
			t.Fatalf("srv retransmit seal: %v", err)
		}
		srvToCli = append(srvToCli, d)
		return nil
	}

	// Server frame handling: mirrors handleData's new switch.
	handleSrv := func(dgram []byte) {
		frames, _, err := srv.OpenPacket(DirC2S, dgram)
		if err != nil {
			t.Fatalf("srv open: %v", err)
		}
		for _, f := range frames {
			switch f.Type {
			case UDPFramePing:
				d, err := srv.sealPacketTracked(DirS2C, [][]byte{EncodeUDPFrame(UDPFramePong, 0, nil)})
				if err != nil {
					t.Fatalf("srv pong seal: %v", err)
				}
				srvToCli = append(srvToCli, d)
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
			case UDPFrameSyn:
			case UDPFrameFin:
				echo := EncodeUDPFrame(UDPFrameFin, f.SID, f.Payload)
				d, err := srv.sealPacketTracked(DirS2C, [][]byte{echo})
				if err != nil {
					t.Fatalf("srv fin seal: %v", err)
				}
				srvToCli = append(srvToCli, d)
			}
		}
	}
	// Client frame handling: mirrors pumpUntil + onFrame.
	var (
		rxBuf   = make([]byte, 100*1024)
		rxSeen  = make([]bool, 100*1024)
		rxGot   int
		gotFin  bool
		gotPong bool
	)
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
			if f.Type == UDPFrameFin {
				gotFin = true
			}
			if f.Type == UDPFramePong {
				gotPong = true
			}
		}
	}
	// Drain helpers: move datagrams across the "wires".
	drain := func() {
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
	cliSend := func(frames ...[]byte) {
		d, err := cli.sealPacketTracked(DirC2S, frames)
		if err != nil {
			t.Fatalf("cli seal: %v", err)
		}
		cliToSrv = append(cliToSrv, d)
	}

	// 1. SYN + data.
	cliSend(EncodeUDPFrame(UDPFrameSyn, 1, nil))
	const total = 100 * 1024
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
	// 2. Drain until all echoed (with RTO checks like pumpUntil).
	deadline := time.Now().Add(10 * time.Second)
	for rxGot < total && time.Now().Before(deadline) {
		drain()
		cli.Rel.CheckRTO()
		srv.Rel.CheckRTO()
	}
	if rxGot != total {
		t.Fatalf("echo incomplete: got %d/%d", rxGot, total)
	}
	if !bytes.Equal(rxBuf, data) {
		t.Fatalf("echo data mismatch")
	}
	// 3. No spurious retransmits on a clean in-process link.
	if cliRetrans != 0 || srvRetrans != 0 {
		t.Fatalf("unexpected retransmits: cli=%d srv=%d", cliRetrans, srvRetrans)
	}
	// 4. FIN / FIN-echo close.
	cliSend(EncodeFinFrame(1, uint64(total)))
	deadline = time.Now().Add(10 * time.Second)
	for !gotFin && time.Now().Before(deadline) {
		drain()
		cli.Rel.CheckRTO()
		srv.Rel.CheckRTO()
	}
	if !gotFin {
		t.Fatalf("no FIN echo received")
	}
	// 5. Convergence: drive the ACK flush timers deterministically.
	// In production the server runs ackFlushLoop every 10ms; here we call
	// FlushAck directly after letting the 10ms ACK timeout expire.
	// The PING/PONG round trip also exercises the untracked path.
	cliSend(EncodeUDPFrame(UDPFramePing, 0, nil))
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond) // let UDPAckTimeout (10ms) expire
		cli.Rel.FlushAck()
		srv.Rel.FlushAck()
		drain()
		cli.Rel.CheckRTO()
		srv.Rel.CheckRTO()
		if !gotPong {
			continue
		}
		if len(cli.Rel.sentPackets) == 0 && len(srv.Rel.sentPackets) == 0 {
			break
		}
	}
	if !gotPong {
		t.Fatalf("no PONG in convergence phase")
	}
	// Invariant: everything converges to zero. No lazy-ACK tail remains
	// because FlushAck drains it deterministically.
	if n := len(cli.Rel.sentPackets); n != 0 {
		for pn, sp := range cli.Rel.sentPackets {
			t.Logf("leaked cli pkt %d sent %v ago frames=%d", pn, time.Since(sp.SendTime), len(sp.Frames))
		}
		t.Fatalf("cli sentPackets leak: %d", n)
	}
	if n := len(srv.Rel.sentPackets); n != 0 {
		for pn, sp := range srv.Rel.sentPackets {
			t.Logf("leaked srv pkt %d sent %v ago frames=%d", pn, time.Since(sp.SendTime), len(sp.Frames))
		}
		t.Fatalf("srv sentPackets leak: %d", n)
	}
	if cli.Rel.BytesInFlight() != 0 {
		t.Fatalf("cli bytesInFlight leak: %d", cli.Rel.BytesInFlight())
	}
}

func mustRand(b []byte) {
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}
}
