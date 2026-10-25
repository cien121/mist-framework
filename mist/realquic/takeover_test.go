package realquic

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"
)

// startTCPEchoServer starts a loopback TCP echo service and returns its
// address. It echoes raw bytes; the framed relay is the code under test,
// not the echo service.
func startTCPEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startUDPEchoServer starts a loopback UDP echo service and returns its
// address. Replies must come from this same port: the relay's session
// socket is connected to this port, and a connected UDP socket only
// accepts packets from its connected peer — replying from a fresh
// ephemeral socket (a second DialUDP) is silently dropped by the kernel,
// which is standard connected-UDP semantics, not a relay bug. So after
// the first packet arrives, the listen socket itself is connected to the
// sender (fd-level connect, as in step 3) and replies go out over it.
// This also keeps the sandbox happy: connected sends are allowed here,
// while unconnected sendmsg with a destination is blocked (step 3).
func startUDPEchoServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		connected := false
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !connected {
				raw, err := pc.SyscallConn()
				if err != nil {
					return
				}
				connErr := raw.Control(func(fd uintptr) {
					sa := &syscall.SockaddrInet4{Port: addr.Port}
					copy(sa.Addr[:], addr.IP.To4())
					_ = syscall.Connect(int(fd), sa)
				})
				if connErr != nil {
					return
				}
				connected = true
			}
			if _, err := pc.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

// readFullFromConnect reads exactly len(want) bytes from cs.
func readFullFromConnect(t *testing.T, cs *ConnectStream, want int) []byte {
	t.Helper()
	out := make([]byte, 0, want)
	tmp := make([]byte, 16*1024)
	for len(out) < want {
		n, err := cs.Read(tmp)
		if err != nil {
			t.Fatalf("connect read: %v (got %d/%d bytes)", err, len(out), want)
		}
		out = append(out, tmp[:n]...)
	}
	return out
}

func patternPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte((i * 7) % 251)
	}
	return p
}

// TestFrameFormatBoundaries proves the production frame format at the
// LEN high-byte boundaries that broke the S1 format: for every size, the
// first byte on the wire is the constant magic 0x4D, never 0x01, and the
// frame round-trips exactly.
func TestFrameFormatBoundaries(t *testing.T) {
	sizes := []int{0, 1, 255, 256, 511, 512, 1024, 4096, 32768, 65535}
	for _, n := range sizes {
		payload := patternPayload(n)
		var buf bytes.Buffer
		if err := WriteFrame(&buf, frameData, payload); err != nil {
			t.Fatalf("size %d: write: %v", n, err)
		}
		wire := buf.Bytes()
		if len(wire) != 4+n {
			t.Fatalf("size %d: wire len %d, want %d", n, len(wire), 4+n)
		}
		if wire[0] != frameMagic {
			t.Fatalf("size %d: first byte 0x%02x, want magic 0x%02x", n, wire[0], frameMagic)
		}
		if wire[0] == 0x01 {
			t.Fatalf("size %d: first byte is 0x01 (H3 HEADERS): misdispatch risk", n)
		}
		fr, err := ReadFrame(bytes.NewReader(wire))
		if err != nil {
			t.Fatalf("size %d: read: %v", n, err)
		}
		if fr.Type != frameData || !bytes.Equal(fr.Payload, payload) {
			t.Fatalf("size %d: round-trip mismatch (type 0x%02x, payload equal=%v)", n, fr.Type, bytes.Equal(fr.Payload, payload))
		}
	}
	// TYPE 0x01 is refused at write time, and a 0x01 first byte is
	// refused at parse time: neither layer can present as H3.
	if err := WriteFrame(&bytes.Buffer{}, 0x01, []byte("x")); err == nil {
		t.Fatalf("WriteFrame accepted TYPE 0x01")
	}
	badMagic := []byte{0x01, frameData, 0x00, 0x01, 'x'}
	if _, err := ReadFrame(bytes.NewReader(badMagic)); err == nil {
		t.Fatalf("ReadFrame accepted magic 0x01")
	}
	// The old S1 format's failure case, as a wire example: a 300-byte
	// payload in [LEN][TYPE] form starts with 0x01; in the production
	// format the same payload starts with the magic byte.
	var buf bytes.Buffer
	if err := WriteFrame(&buf, frameData, patternPayload(300)); err != nil {
		t.Fatal(err)
	}
	if buf.Bytes()[0] != frameMagic {
		t.Fatalf("300-byte frame first byte 0x%02x, want magic", buf.Bytes()[0])
	}
}

// TestTakeoverRegressionInterleaved is the step-4 (c) regression: on one
// connection, H3 AUTH, then custom CONNECT, then H3, then custom UDP,
// then H3 again — proving control flow, SETTINGS and QPACK survive custom
// streams interleaved between H3 requests.
func TestTakeoverRegressionInterleaved(t *testing.T) {
	env := setupEnv(t)
	t.Logf("transport=%s", env.transport)

	// (1) H3 AUTH.
	st, _, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("AUTH: status=%d err=%v, want 200", st, err)
	}
	// (2) Custom CONNECT to a real loopback TCP service, bidirectional.
	cs, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	msg := []byte("connect-via-takeover")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("CONNECT echo %q, want %q", got, msg)
	}
	_ = cs.Close()
	// (3) H3 again on the same connection.
	st, body, _, err := env.cli.Get(env.ctx(t), "/")
	if err != nil || st != http.StatusOK || string(body) != "realquic lab site\n" {
		t.Fatalf("GET / after CONNECT: status=%d body=%q err=%v", st, body, err)
	}
	// (4) Custom UDP via datagrams.
	sid, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.cli.RegisterUDP(env.ctx(t), sid, startUDPEchoServer(t)); err != nil {
		t.Fatalf("RegisterUDP: %v", err)
	}
	udpMsg := []byte("udp-via-datagram")
	if err := env.cli.SendDatagram(sid, udpMsg); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}
	gotSID, gotPayload, err := env.cli.ReceiveDatagram(env.ctx(t))
	if err != nil {
		t.Fatalf("ReceiveDatagram: %v", err)
	}
	if gotSID != sid || !bytes.Equal(gotPayload, udpMsg) {
		t.Fatalf("UDP echo sid match=%v payload=%q, want %q", gotSID == sid, gotPayload, udpMsg)
	}
	// (5) H3 once more: connection and H3 state intact.
	st, body, _, err = env.cli.Get(env.ctx(t), "/")
	if err != nil || st != http.StatusOK || string(body) != "realquic lab site\n" {
		t.Fatalf("GET / after UDP: status=%d body=%q err=%v", st, body, err)
	}
	t.Logf("interleaved regression PASS on transport=%s", env.transport)
}

// TestConnectSizeBoundaries drives real CONNECT relay traffic at the LEN
// high-byte boundaries through the live Peek dispatch: a misdispatch at
// any size would cancel the stream and fail the echo.
func TestConnectSizeBoundaries(t *testing.T) {
	env := setupEnv(t)
	st, _, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("AUTH: status=%d err=%v", st, err)
	}
	cs, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	defer cs.Close()
	for _, n := range []int{255, 256, 511, 512, 5000} {
		payload := patternPayload(n)
		if _, err := cs.Write(payload); err != nil {
			t.Fatalf("size %d: write: %v", n, err)
		}
		if got := readFullFromConnect(t, cs, n); !bytes.Equal(got, payload) {
			t.Fatalf("size %d: echo mismatch", n)
		}
		t.Logf("size %d: echo OK", n)
	}
	// Chunking: 70000 bytes exceeds one DATA frame and one uint16 frame
	// only via chunking (maxDataChunk); it must still round-trip exactly.
	big := patternPayload(70000)
	if _, err := cs.Write(big); err != nil {
		t.Fatalf("70000-byte write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(big)); !bytes.Equal(got, big) {
		t.Fatalf("70000-byte echo mismatch")
	}
	t.Logf("70000-byte chunked echo OK")
	// Connection still serves H3 after the stream closes.
	_ = cs.Close()
	st, body, _, err := env.cli.Get(env.ctx(t), "/")
	if err != nil || st != http.StatusOK || string(body) != "realquic lab site\n" {
		t.Fatalf("GET / after CONNECT: status=%d body=%q err=%v", st, body, err)
	}
}

// TestConnectDialFailure proves a failed dial is reported as CONNECT_ERR
// (client error), not a hang and not a connection teardown.
func TestConnectDialFailure(t *testing.T) {
	env := setupEnv(t)
	st, _, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("AUTH: status=%d err=%v", st, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close() // definitely-closed loopback port
	if _, err := env.cli.Connect(env.ctx(t), closed); err == nil {
		t.Fatalf("CONNECT to closed port succeeded, want error")
	} else {
		t.Logf("CONNECT to closed port failed as expected: %v", err)
	}
	// Connection survives the failed dial.
	st, body, _, err := env.cli.Get(env.ctx(t), "/")
	if err != nil || st != http.StatusOK || string(body) != "realquic lab site\n" {
		t.Fatalf("GET / after failed CONNECT: status=%d body=%q err=%v", st, body, err)
	}
}

// TestUDPDatagramRelayUnknownDropped proves the §3 no-fallback invariant
// on datagrams: an unknown session's datagram is dropped (counted, no
// response), and the registered session keeps relaying afterwards.
func TestUDPDatagramRelayUnknownDropped(t *testing.T) {
	env := setupEnv(t)
	st, _, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("AUTH: status=%d err=%v", st, err)
	}
	sid, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.cli.RegisterUDP(env.ctx(t), sid, startUDPEchoServer(t)); err != nil {
		t.Fatalf("RegisterUDP: %v", err)
	}
	hello := []byte("udp-hello")
	if err := env.cli.SendDatagram(sid, hello); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}
	gotSID, got, err := env.cli.ReceiveDatagram(env.ctx(t))
	if err != nil || gotSID != sid || !bytes.Equal(got, hello) {
		t.Fatalf("UDP echo: sid match=%v payload=%q err=%v", gotSID == sid, got, err)
	}
	// Unknown session: dropped, never answered, never routed to sid.
	unknown, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	before := env.srv.DroppedDatagrams()
	if err := env.cli.SendDatagram(unknown, []byte("not-for-you")); err != nil {
		t.Fatalf("SendDatagram unknown: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for env.srv.DroppedDatagrams() <= before && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if env.srv.DroppedDatagrams() <= before {
		t.Fatalf("unknown datagram was not counted as dropped (before=%d now=%d)", before, env.srv.DroppedDatagrams())
	}
	short, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, _, err := env.cli.ReceiveDatagram(short); err == nil {
		t.Fatalf("unknown session datagram produced a response, want none")
	} else {
		t.Logf("unknown datagram: no response (err=%v), dropped=%d", err, env.srv.DroppedDatagrams())
	}
	// Registered session still relays after the drop.
	again := []byte("udp-after-drop")
	if err := env.cli.SendDatagram(sid, again); err != nil {
		t.Fatalf("SendDatagram after drop: %v", err)
	}
	gotSID, got, err = env.cli.ReceiveDatagram(env.ctx(t))
	if err != nil || gotSID != sid || !bytes.Equal(got, again) {
		t.Fatalf("UDP echo after drop: sid match=%v payload=%q err=%v", gotSID == sid, got, err)
	}
}

// TestCustomStreamRequiresAuth proves custom streams are refused before
// AUTH without killing the connection: a later AUTH + CONNECT works.
func TestCustomStreamRequiresAuth(t *testing.T) {
	env := setupEnv(t)
	// No AUTH yet: CONNECT must fail.
	if _, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t)); err == nil {
		t.Fatalf("CONNECT before AUTH succeeded, want refusal")
	} else {
		t.Logf("CONNECT before AUTH refused as expected: %v", err)
	}
	// The connection itself survives the refusal.
	st, _, _, err := env.cli.Auth(env.ctx(t))
	if err != nil || st != http.StatusOK {
		t.Fatalf("AUTH after refusal: status=%d err=%v", st, err)
	}
	cs, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT after AUTH: %v", err)
	}
	defer cs.Close()
	msg := []byte("post-auth-connect")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); !bytes.Equal(got, msg) {
		t.Fatalf("CONNECT echo %q, want %q", got, msg)
	}
}
