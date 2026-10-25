// Mobile bindings for Android (gomobile bind).
//
// This file is the only gomobile entry point for the independent
// framework. It wraps core.Engine + core.MistUDPClient behind a small API that
// uses only gomobile-supported types (no context.Context, no
// unexported types in signatures, no interfaces):
//
//	MobileEngine:  NewMobileEngine() -> Start(tunFd, nodeURL) / Stop()
//	              GetUploadBytes() / GetDownloadBytes() (polling)
//	Ping:         Ping(nodeURL, timeoutSec) -> handshake ms (static)
//
// Java mapping (gomobile lowerCamelCase rules; verify against the
// generated sources after the first bind):
//
//	Kotlin: MobileEngine()             // Go NewMobileEngine()
//	Kotlin: eng.start(fd, nodeURL)     // Go Start; throws on error
//	Kotlin: eng.stop()                 // Go Stop
//	Kotlin: eng.getUploadBytes()       // Go GetUploadBytes
//	Kotlin: Mobile.ping(url, 5)        // Go Ping; throws on error
//
// TUN fd ownership: Kotlin passes the fd from ParcelFileDescriptor
// .detachFd(). Go takes ownership via os.NewFile; core.Engine.Close()
// (called from Stop) closes it. Kotlin must NOT close it afterwards.
//
// Routing-loop stopgap: the Go process's own UDP socket to the Mist
// server must not be routed back into the TUN. core.MistUDPClient dials
// with net.ListenUDP and has no Android protect() hook, so the
// Kotlin side excludes the app itself with
// VpnService.Builder.addDisallowedApplication (see android/README).
// The proper fix — a ProtectHandler callback plumbed into the dial
// path — is future work and needs changes to mist_udp.go/mistcore,
// which are intentionally untouched here.
package mobile

import (
	"context"
	"errors"
	"github.com/cien121/mist-framework/core"
	"os"
	"sync"
	"time"
)

// Note: StatsListener interface removed for gomobile compatibility.
// gomobile cannot bind interface types. Kotlin polls GetUploadBytes/
// GetDownloadBytes instead of receiving callbacks.

// fdTUN adapts an Android TUN file descriptor to core.TUNDevice.
type fdTUN struct {
	f *os.File
}

func (t *fdTUN) Read(b []byte) (int, error) { return t.f.Read(b) }

// Write loops until the whole packet is written: a partial TUN write
// would corrupt the packet stream.
func (t *fdTUN) Write(b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := t.f.Write(b[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, errors.New("mist: tun write returned 0")
		}
	}
	return total, nil
}

func (t *fdTUN) Close() error { return t.f.Close() }

// MobileEngine is the gomobile handle for one running tunnel.
type MobileEngine struct {
	mu      sync.Mutex
	engine  *core.Engine
	client  *core.MistUDPClient
	cancel  context.CancelFunc
	runDone chan struct{}
	running bool
}

// NewMobileEngine creates a stopped engine handle.
func NewMobileEngine() *MobileEngine { return &MobileEngine{} }

// Start builds a Mist client from a mist:// node link, wraps tunFd as
// the TUN device, and starts the forwarding engine. tunFd ownership
// moves to Go (see package doc). Returns an error if already running
// or if the node link is invalid.
func (m *MobileEngine) Start(tunFd int, nodeURL string) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("mist: engine already running")
	}
	cfg, err := core.ParseMistURL(nodeURL)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	client, err := core.NewMistUDPClient(*cfg)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	tun := &fdTUN{f: os.NewFile(uintptr(tunFd), "tun")}
	// Use core.NewEngineForMobile (concrete *core.MistUDPClient) instead of
	// NewEngine (ProtocolClient interface) to keep gomobile from
	// trying to bind the interface types.
	engine := core.NewEngineForMobile(tun, client)
	ctx, cancel := context.WithCancel(context.Background())
	m.engine = engine
	m.client = client
	m.cancel = cancel
	m.runDone = make(chan struct{})
	m.running = true
	m.mu.Unlock()

	go func() {
		defer close(m.runDone)
		_ = engine.Run(ctx)
	}()
	return nil
}

// Stop cancels the engine, closes the TUN fd and the Mist client, and
// waits (max 5s) for the engine goroutine to exit. Safe to call when
// not running.
func (m *MobileEngine) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	engine, client, cancel, runDone := m.engine, m.client, m.cancel, m.runDone
	m.engine, m.client, m.cancel = nil, nil, nil
	m.running = false
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if engine != nil {
		_ = engine.Close() // also closes the TUN fd
	}
	if client != nil {
		_ = client.Close()
	}
	if runDone != nil {
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
		}
	}
}

// IsRunning reports whether the engine is up.
func (m *MobileEngine) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// GetUploadBytes returns cumulative bytes sent through the tunnel.
func (m *MobileEngine) GetUploadBytes() int64 {
	m.mu.Lock()
	e := m.engine
	m.mu.Unlock()
	if e == nil {
		return 0
	}
	return int64(e.Stats().UploadBytes)
}

// GetDownloadBytes returns cumulative bytes received through the tunnel.
func (m *MobileEngine) GetDownloadBytes() int64 {
	m.mu.Lock()
	e := m.engine
	m.mu.Unlock()
	if e == nil {
		return 0
	}
	return int64(e.Stats().DownloadBytes)
}

// Ping measures real Mist UDP handshake latency for a mist:// node link.
// It parses the link, performs one QUIC Initial + AUTH handshake, and
// closes the client, returning round-trip milliseconds. This is a true
// handshake round-trip, not a TCP ping: the Mist server listens on UDP
// only, so a TCP connect to the Mist port would always fail.
// timeoutSec caps the whole attempt (0 or negative = 5s default,
// capped at 30s). On failure it returns 0 and the error (surfaced as
// a Java exception by the gomobile binding).
func Ping(nodeURL string, timeoutSec int) (int64, error) {
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	if timeoutSec > 30 {
		timeoutSec = 30
	}
	cfg, err := core.ParseMistURL(nodeURL)
	if err != nil {
		return 0, err
	}
	client, err := core.NewMistUDPClient(*cfg)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	start := time.Now()
	if err := client.Connect(ctx); err != nil {
		_ = client.Close()
		return 0, err
	}
	elapsed := time.Since(start)
	_ = client.Close()
	return elapsed.Milliseconds(), nil
}
