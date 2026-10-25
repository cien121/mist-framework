package core

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// Regression tests for UDP return-path routing (the same-target
// "串线" fix). Previously the relay stamped responses only with the
// responder address (= target for connected UDP) and the server
// shared one relay conn per target, so responses for two app
// sockets talking to the SAME target IP:port were indistinguishable
// on the wire and the engine fell back to "most recent session for
// this destination": the earlier session starved while its responses
// landed on the newer socket. Now each tunnel session carries a
// frame-payload tag (see mistcore.EncodeDatagramTagged): tagged
// responses route by tag only, untagged responses (old server)
// fall back to DNS txID, then most-recent session.

func sendUDPPkt(t *testing.T, tun *mockTUN, appIP, dstIP net.IP, appPort, dstPort uint16, id uint16, payload []byte) {
	t.Helper()
	seg := BuildUDP(appIP, dstIP, appPort, dstPort, payload)
	tun.readCh <- BuildIPv4(appIP, dstIP, ProtoUDP, id, seg)
}

func waitDgSent(t *testing.T, cli *mockClient, n int) {
	t.Helper()
	waitFor(t, "datagram forward", func() bool {
		cli.mu.Lock()
		defer cli.mu.Unlock()
		return len(cli.dgSent) == n
	})
}

// dgTagsByPayload maps each forwarded payload to its session tag.
// dgSent is recorded by per-datagram send goroutines, so record
// order is NOT send order; the payload is the only reliable key.
func dgTagsByPayload(t *testing.T, cli *mockClient, n int) map[string]uint8 {
	t.Helper()
	waitDgSent(t, cli, n)
	cli.mu.Lock()
	defer cli.mu.Unlock()
	out := make(map[string]uint8, len(cli.dgSent))
	for _, r := range cli.dgSent {
		out[string(r.data)] = r.tag
	}
	return out
}

// readTUNUDP returns the app-side dst port + payload of one TUN packet.
func readTUNUDP(t *testing.T, tun *mockTUN) (uint16, []byte) {
	t.Helper()
	select {
	case out := <-tun.writeCh:
		p, err := ParseIP(out)
		if err != nil {
			t.Fatalf("parse tun udp: %v", err)
		}
		dg, err := ParseUDP(p.Payload)
		if err != nil {
			t.Fatalf("parse tun udp seg: %v", err)
		}
		return dg.DstPort, dg.Payload
	case <-time.After(3 * time.Second):
		t.Fatal("no tun udp packet")
		return 0, nil
	}
}

// tryReadTUNUDP reports whether a TUN packet arrives within d,
// without failing the test when none does (used to prove a
// misaddressed tagged response is dropped, not delivered).
func tryReadTUNUDP(tun *mockTUN, d time.Duration) (uint16, []byte, bool) {
	select {
	case out := <-tun.writeCh:
		p, err := ParseIP(out)
		if err != nil {
			return 0, nil, false
		}
		dg, err := ParseUDP(p.Payload)
		if err != nil {
			return 0, nil, false
		}
		return dg.DstPort, dg.Payload, true
	case <-time.After(d):
		return 0, nil, false
	}
}

func TestEngineUDPSingleSession(t *testing.T) {
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")
	sendUDPPkt(t, tun, appIP, dstIP, 10001, 443, 1, []byte("Q1"))
	waitDgSent(t, cli, 1)

	cli.emitDatagram("93.184.216.34:443", []byte("R1"))
	port, payload := readTUNUDP(t, tun)
	if port != 10001 || string(payload) != "R1" {
		t.Fatalf("single session misrouted: port=%d payload=%q", port, payload)
	}
}

func TestEngineUDPConcurrentSameTarget(t *testing.T) {
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")

	// Two app sockets (e.g. two QUIC connections) to the same target.
	sendUDPPkt(t, tun, appIP, dstIP, 10001, 443, 1, []byte("QA"))
	sendUDPPkt(t, tun, appIP, dstIP, 10002, 443, 2, []byte("QB"))
	tags := dgTagsByPayload(t, cli, 2)
	tagA, tagB := tags["QA"], tags["QB"]
	if tagA == 0 || tagB == 0 || tagA == tagB {
		t.Fatalf("sessions must carry distinct nonzero tags, got %v", tags)
	}

	// Responses arrive in CROSSED order, addressed by tag: the
	// second socket's response first. Tag routing (not arrival
	// order, not most-recent session) must deliver each to its
	// own socket.
	cli.emitDatagramTagged("93.184.216.34:443", tagB, []byte("RB"))
	port, payload := readTUNUDP(t, tun)
	if port != 10002 || string(payload) != "RB" {
		t.Fatalf("tagged response misrouted: port=%d payload=%q, want 10002/RB", port, payload)
	}
	cli.emitDatagramTagged("93.184.216.34:443", tagA, []byte("RA"))
	port, payload = readTUNUDP(t, tun)
	if port != 10001 || string(payload) != "RA" {
		t.Fatalf("tagged response misrouted: port=%d payload=%q, want 10001/RA", port, payload)
	}
}

func TestEngineUDPConcurrentSameTargetMany(t *testing.T) {
	// 16 sockets to one target: every socket must receive exactly
	// its own response, even when responses arrive in reverse order.
	const n = 16
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")
	ports := make([]uint16, n)
	for i := 0; i < n; i++ {
		ports[i] = uint16(11000 + i)
		sendUDPPkt(t, tun, appIP, dstIP, ports[i], 443, uint16(i+1), []byte(fmt.Sprintf("Q%d", i)))
	}
	tags := dgTagsByPayload(t, cli, n)
	seen := map[uint8]bool{}
	for i := 0; i < n; i++ {
		tag := tags[fmt.Sprintf("Q%d", i)]
		if tag == 0 || seen[tag] {
			t.Fatalf("sessions must carry distinct nonzero tags, got %v", tags)
		}
		seen[tag] = true
	}
	for i := n - 1; i >= 0; i-- {
		cli.emitDatagramTagged("93.184.216.34:443", tags[fmt.Sprintf("Q%d", i)], []byte(fmt.Sprintf("R%d", i)))
		port, payload := readTUNUDP(t, tun)
		if port != ports[i] || string(payload) != fmt.Sprintf("R%d", i) {
			t.Fatalf("socket %d misrouted: port=%d payload=%q", i, port, payload)
		}
	}
}

func TestEngineUDPTaggedUntaggedInterop(t *testing.T) {
	// Old/new frame interop on one target: a response WITHOUT a
	// tag tail falls back to the old routing (most-recent session
	// for non-DNS), a response WITH a tag tail routes by tag, and
	// a tagged response for an unknown tag is DROPPED, never
	// fallen back to another session.
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	dstIP := net.ParseIP("93.184.216.34")
	sendUDPPkt(t, tun, appIP, dstIP, 10001, 443, 1, []byte("QA"))
	sendUDPPkt(t, tun, appIP, dstIP, 10002, 443, 2, []byte("QB"))
	tags := dgTagsByPayload(t, cli, 2)

	// Untagged (old-server) response: most-recent session wins.
	cli.emitDatagram("93.184.216.34:443", []byte("R-untagged"))
	port, payload := readTUNUDP(t, tun)
	if port != 10002 || string(payload) != "R-untagged" {
		t.Fatalf("untagged fallback misrouted: port=%d payload=%q, want 10002", port, payload)
	}

	// Tagged response for a tag no session owns: dropped outright.
	var unknown uint8 = 200
	for _, tag := range tags {
		if tag == unknown {
			unknown = 201
		}
	}
	cli.emitDatagramTagged("93.184.216.34:443", unknown, []byte("R-ghost"))
	if port, payload, ok := tryReadTUNUDP(tun, 300*time.Millisecond); ok {
		t.Fatalf("unknown-tag response must be dropped, got port=%d payload=%q", port, payload)
	}

	// Tagged response for the first session still routes by tag.
	cli.emitDatagramTagged("93.184.216.34:443", tags["QA"], []byte("RA"))
	port, payload = readTUNUDP(t, tun)
	if port != 10001 || string(payload) != "RA" {
		t.Fatalf("tagged response misrouted after unknown-tag drop: port=%d payload=%q", port, payload)
	}
}

func TestEngineUDPConcurrentDifferentTargets(t *testing.T) {
	tun := newMockTUN()
	cli := &mockClient{}
	e := NewEngine(EngineConfig{TUN: tun, Client: cli})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	appIP := net.ParseIP("10.0.0.2")
	sendUDPPkt(t, tun, appIP, net.ParseIP("93.184.216.34"), 10001, 443, 1, []byte("QA"))
	waitDgSent(t, cli, 1)
	sendUDPPkt(t, tun, appIP, net.ParseIP("142.250.80.46"), 10002, 443, 2, []byte("QB"))
	waitDgSent(t, cli, 2)

	cli.emitDatagram("93.184.216.34:443", []byte("RA"))
	port, payload := readTUNUDP(t, tun)
	if port != 10001 || string(payload) != "RA" {
		t.Fatalf("different-target routing broken: port=%d payload=%q", port, payload)
	}
	cli.emitDatagram("142.250.80.46:443", []byte("RB"))
	port, payload = readTUNUDP(t, tun)
	if port != 10002 || string(payload) != "RB" {
		t.Fatalf("different-target routing broken: port=%d payload=%q", port, payload)
	}
}
