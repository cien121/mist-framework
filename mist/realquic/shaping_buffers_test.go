package realquic

import (
	"net"
	"syscall"
	"testing"
)

// Stage C B3 regression test: the shaping wrapper must pass quic-go's
// buffer-size requests through to the underlying socket, otherwise
// wrapConn logs "Not a *net.UDPConn?" and never enlarges the buffers.
// quic-go v0.64.1 probes both directions separately (SetReadBuffer in
// sys_conn_buffers.go, SetWriteBuffer in generated
// sys_conn_buffers_write.go), so both methods must exist.
var (
	_ interface{ SetReadBuffer(int) error }  = (*shapingPacketConn)(nil)
	_ interface{ SetWriteBuffer(int) error } = (*shapingPacketConn)(nil)
)

// sockBuf reads a socket option from the underlying UDP socket directly.
// (The lab tree reads it via the wrapper's SyscallConn passthrough;
// main does not have that method yet, so the regression test reads the
// raw socket instead. The assertion is identical: a Set*Buffer call made
// through the wrapper must land on the real socket.)
func sockBuf(t *testing.T, pc net.PacketConn, opt int) int {
	t.Helper()
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		t.Fatalf("not a *net.UDPConn: %T", pc)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if raw == nil {
		t.Fatalf("SyscallConn returned nil RawConn")
	}
	var got int
	if err := raw.Control(func(fd uintptr) {
		var cerr error
		got, cerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt)
		if cerr != nil {
			t.Errorf("GetsockoptInt: %v", cerr)
		}
	}); err != nil {
		t.Fatalf("RawConn.Control: %v", err)
	}
	return got
}

func TestShapingConnSetReadBufferPassthrough(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	wrapped := newSingleShapingConn(pc, "up", BootstrapProfile())
	// Modest size: below the usual rmem_max so the kernel accepts it
	// rather than silently capping below the request. Linux reports
	// back twice the requested SO_RCVBUF, so the observed value must
	// be at least what was requested.
	const want = 64 << 10
	if err := wrapped.SetReadBuffer(want); err != nil {
		t.Fatalf("SetReadBuffer: %v", err)
	}
	if got := sockBuf(t, pc, syscall.SO_RCVBUF); got < want {
		t.Fatalf("SO_RCVBUF = %d, want >= %d", got, want)
	}
}

func TestShapingConnSetWriteBufferPassthrough(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	wrapped := newSingleShapingConn(pc, "up", BootstrapProfile())
	const want = 64 << 10
	if err := wrapped.SetWriteBuffer(want); err != nil {
		t.Fatalf("SetWriteBuffer: %v", err)
	}
	if got := sockBuf(t, pc, syscall.SO_SNDBUF); got < want {
		t.Fatalf("SO_SNDBUF = %d, want >= %d", got, want)
	}
}

func TestShapingConnSetBuffersNoInner(t *testing.T) {
	a, _ := NewMemPair()
	defer a.Close()
	wrapped := newSingleShapingConn(a, "up", BootstrapProfile())
	// The in-memory pair implements neither method: the wrapper must
	// fail closed with an error, never panic and never claim success.
	// quic-go's wrapConn only logs a buffer-size error as a warning,
	// so this reproduces today's warning for non-socket inners.
	if err := wrapped.SetReadBuffer(64 << 10); err == nil {
		t.Fatalf("expected error for inner connection without SetReadBuffer, got nil")
	}
	if err := wrapped.SetWriteBuffer(64 << 10); err == nil {
		t.Fatalf("expected error for inner connection without SetWriteBuffer, got nil")
	}
}
