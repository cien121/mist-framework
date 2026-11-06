package realquic

import (
	"net"
	"testing"
)

// W-1 deviation 4 regression test: the shaping wrapper must expose the
// underlying socket's RawConn, otherwise quic-go's wrapConn sees
// DF=false and never starts the PMTU discoverer.
func TestShapingConnSyscallPassthrough(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	wrapped := newSingleShapingConn(pc, "up", BootstrapProfile())
	raw, err := wrapped.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn on UDP-backed wrapper: %v", err)
	}
	if raw == nil {
		t.Fatalf("SyscallConn returned nil RawConn")
	}
	// Prove it is a live RawConn for the same socket, not a stub.
	if err := raw.Control(func(fd uintptr) {}); err != nil {
		t.Fatalf("RawConn.Control: %v", err)
	}
}

func TestShapingConnSyscallNoInner(t *testing.T) {
	a, _ := NewMemPair()
	defer a.Close()
	wrapped := newSingleShapingConn(a, "up", BootstrapProfile())
	// Deliberately (nil, nil): quic-go's wrapConn treats a SyscallConn
	// error as fatal to dial, while a nil RawConn is only dereferenced
	// when LocalAddr is a *net.UDPAddr, which a mem pair never reports.
	raw, err := wrapped.SyscallConn()
	if err != nil {
		t.Fatalf("expected (nil, nil) for inner connection without SyscallConn, got error %v", err)
	}
	if raw != nil {
		t.Fatalf("expected nil RawConn for inner connection without SyscallConn")
	}
}
