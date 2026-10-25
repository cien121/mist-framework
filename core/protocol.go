// Package core defines the independent proxy framework interfaces.
// No Xray dependency. Mist and Hy2 are plugins.
package core

import (
	"context"
	"io"
	"net"
	"time"
)

// ProtocolClient is the unified interface for proxy protocols.
// Each protocol (Mist, Hy2) implements this.
type ProtocolClient interface {
	// Name returns the protocol name: "mist", "hy2", etc.
	Name() string

	// Dial establishes a connection to the target through the proxy.
	// addr is "host:port".
	Dial(ctx context.Context, addr string) (net.Conn, error)

	// Close releases all resources.
	Close() error
}

// PacketConn is a UDP-like packet connection for TUN forwarding.
type PacketConn interface {
	io.ReadWriteCloser
	// ReadPacket reads one IP packet.
	ReadPacket() ([]byte, error)
	// WritePacket writes one IP packet.
	WritePacket([]byte) error
}

// TUNDevice abstracts the Android TUN interface.
// Implemented by Kotlin via gomobile.
type TUNDevice interface {
	// Read reads one IP packet from TUN.
	Read([]byte) (int, error)
	// Write writes one IP packet to TUN.
	Write([]byte) (int, error)
	// Close closes the TUN device.
	Close() error
}

// Stats collects traffic statistics.
type Stats struct {
	UploadBytes         uint64
	DownloadBytes       uint64
	UploadRate          uint64 // bytes/sec
	DownloadRate        uint64 // bytes/sec
	TunWriteErrors      uint64 // failed/short TUN writes (return-path health)
	AcksSent            uint64 // ACK packets transmitted by the client
	AckSendErrors       uint64 // ACK seal/write failures on the client
	DatagramsSent       uint64 // UDP relay datagrams sent successfully
	DatagramsSendErrors uint64 // UDP relay datagram send failures
	DatagramsReceived   uint64 // UDP relay datagrams received
	ReadPumpDeaths      uint64 // readPump exits + watchdog stalls (session-dead signal)
	StreamPendingResets uint64 // streams reset by the reorder-buffer cap
	UpdatedAt           time.Time
}

// StatsCollector receives traffic updates.
type StatsCollector interface {
	// Report uploads traffic stats.
	Report(s Stats)
}

// AckStatser is an optional ProtocolClient extension reporting ACK
// transmission counts (used by the engine to surface them in Stats).
type AckStatser interface {
	AckStats() (sent, errs uint64)
}

// DatagramStatser is an optional ProtocolClient extension reporting
// UDP relay datagram counts (used by the engine to surface them in
// Stats).
type DatagramStatser interface {
	DatagramStats() (sent, sendErrs, received uint64)
}

// HealthStatser is an optional ProtocolClient extension reporting
// session-liveness counts (used by the engine to surface them in
// Stats). A nonzero ReadPumpDeaths with zero traffic is the signal
// that the session died while the UI still shows "connected".
type HealthStatser interface {
	HealthStats() (readPumpDeaths, streamPendingResets uint64)
}

// DatagramClient is an optional ProtocolClient extension for
// connectionless UDP relay (used by the engine's UDP path).
// SendDatagram sends payload to target ("ip:port"); inbound relay
// datagrams arrive via the handler set by OnDatagram, with srcAddr
// set to the original target ("ip:port").
type DatagramClient interface {
	SendDatagram(target string, data []byte) error
	OnDatagram(h DatagramHandler)
}

// DatagramHandler receives relay datagrams (see DatagramClient).
type DatagramHandler func(srcAddr string, data []byte)
