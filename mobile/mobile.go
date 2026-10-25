// Mobile bindings for Android (gomobile bind).
//
// This file is the only gomobile entry point for the independent
// framework. It wraps core.Engine + core.MistUDPClient behind a small API that
// uses only gomobile-supported types (no context.Context, no
// unexported types in signatures, no interfaces):
//
//	MobileEngine:  NewMobileEngine() -> Start(tunFd, nodeURL) / Stop()
//	              GetUploadBytes() / GetDownloadBytes() (polling)
//	              FetchEgressIP(checkURL, timeoutSec) -> egress IP body
//	              GetTunWriteErrors() / GetAcksSent() / GetAckSendErrors()
//	              GetDatagramsSent() / GetDatagramsSendErrors()
//	              GetDatagramsReceived() (diagnostics polling)
//	              SetSplitEnabled() / SetAdblockEnabled() / SetLocalDNS()
//	              (split + adblock default on; live toggles apply to a
//	              running engine atomically)
//	              GetDirectUploadBytes() / GetDirectDownloadBytes()
//	Ping:         Ping(nodeURL, timeoutSec) -> handshake ms (static)
//
// Java mapping (gomobile lowerCamelCase rules; verify against the
// generated sources after the first bind):
//
//	Kotlin: MobileEngine()             // Go NewMobileEngine()
//	Kotlin: eng.start(fd, nodeURL)     // Go Start; throws on error
//	Kotlin: eng.stop()                 // Go Stop
//	Kotlin: eng.getUploadBytes()       // Go GetUploadBytes
//	Kotlin: eng.fetchEgressIP(url, 10) // Go FetchEgressIP; throws on error
//	Kotlin: eng.getTunWriteErrors()    // Go GetTunWriteErrors
//	Kotlin: eng.getAcksSent()          // Go GetAcksSent
//	Kotlin: eng.getAckSendErrors()     // Go GetAckSendErrors
//	Kotlin: eng.getDatagramsSent()     // Go GetDatagramsSent
//	Kotlin: eng.getDatagramsSendErrors() // Go GetDatagramsSendErrors
//	Kotlin: eng.getDatagramsReceived() // Go GetDatagramsReceived
//	Kotlin: eng.setSplitEnabled(true)  // Go SetSplitEnabled
//	Kotlin: eng.setAdblockEnabled(true) // Go SetAdblockEnabled
//	Kotlin: eng.setLocalDNS("223.5.5.5") // Go SetLocalDNS
//	Kotlin: eng.getDirectUploadBytes() // Go GetDirectUploadBytes
//	Kotlin: eng.getDirectDownloadBytes() // Go GetDirectDownloadBytes
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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cien121/mist-framework/core"
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
	// Split/adblock defaults: both on. Start passes them to the
	// engine as EngineConfig; the setters below update both the
	// stored value (for a later Start) and a live engine.
	splitEnabled   bool
	adblockEnabled bool
	localDNS       string // comma-separated; "" = default domestic public DNS
}

// NewMobileEngine creates a stopped engine handle with split
// routing and DNS ad blocking both enabled by default.
func NewMobileEngine() *MobileEngine {
	return &MobileEngine{splitEnabled: true, adblockEnabled: true}
}

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
	// Use core.NewEngineForMobileWithConfig (concrete
	// *core.MistUDPClient) instead of NewEngine (ProtocolClient
	// interface) to keep gomobile from trying to bind the
	// interface types. Split + adblock default on (see
	// NewMobileEngine); SetSplitEnabled/SetAdblockEnabled/
	// SetLocalDNS called before Start are honored here, and
	// afterwards they update the live engine atomically.
	engine := core.NewEngineForMobileWithConfig(tun, client, core.EngineConfig{
		SplitEnabled:   m.splitEnabled,
		AdblockEnabled: m.adblockEnabled,
		LocalDNS:       m.localDNS,
	})
	ctx, cancel := context.WithCancel(context.Background())
	m.engine = engine
	m.client = client
	m.cancel = cancel
	m.runDone = make(chan struct{})
	m.running = true
	m.mu.Unlock()

	go func() {
		defer close(m.runDone)
		defer func() {
			if r := recover(); r != nil {
				// A panic in the engine loop used to kill the
				// whole app process through JNI; log it instead
				// so the session degrades to a diagnosable stall
				// (readPump/watchdog counts surface it) rather
				// than a crash. Stop's 5s bound still applies.
				log.Printf("mist: engine Run panic (recovered): %v", r)
			}
		}()
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

// SetSplitEnabled toggles split routing (domestic/private direct,
// rest via tunnel). It updates the stored default and, when the
// engine is running, the live engine atomically.
func (m *MobileEngine) SetSplitEnabled(enabled bool) {
	m.mu.Lock()
	m.splitEnabled = enabled
	e := m.engine
	m.mu.Unlock()
	if e != nil {
		e.SetSplitEnabled(enabled)
	}
}

// SetAdblockEnabled toggles DNS-layer ad blocking. It updates the
// stored default and, when the engine is running, the live engine
// atomically. Ad blocking is independent of split routing: with
// split off, ads are still blocked before the tunnel.
func (m *MobileEngine) SetAdblockEnabled(enabled bool) {
	m.mu.Lock()
	m.adblockEnabled = enabled
	e := m.engine
	m.mu.Unlock()
	if e != nil {
		e.SetAdblockEnabled(enabled)
	}
}

// SetLocalDNS replaces the local resolvers used for domestic DNS
// (comma-separated IPs/hosts; empty restores the default domestic
// public DNS). It updates the stored value and, when the engine is
// running, the live engine atomically.
func (m *MobileEngine) SetLocalDNS(servers string) {
	m.mu.Lock()
	m.localDNS = servers
	e := m.engine
	m.mu.Unlock()
	if e != nil {
		e.SetLocalDNS(servers)
	}
}

// GetDirectUploadBytes returns cumulative bytes sent on direct
// (non-tunnel) paths: direct TCP dials and direct UDP.
func (m *MobileEngine) GetDirectUploadBytes() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.DirectUploadBytes)
	}
	return 0
}

// GetDirectDownloadBytes returns cumulative bytes received on
// direct (non-tunnel) paths.
func (m *MobileEngine) GetDirectDownloadBytes() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.DirectDownloadBytes)
	}
	return 0
}

// engineStats returns the engine's current Stats, or false when the
// engine is not running. Shared by the diagnostic getters below.
func (m *MobileEngine) engineStats() (core.Stats, bool) {
	m.mu.Lock()
	e := m.engine
	m.mu.Unlock()
	if e == nil {
		return core.Stats{}, false
	}
	return e.Stats(), true
}

// GetTunWriteErrors returns cumulative failed/short TUN writes.
// A nonzero value while download bytes move means the engine
// received data but could not hand it to the app.
func (m *MobileEngine) GetTunWriteErrors() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.TunWriteErrors)
	}
	return 0
}

// GetAcksSent returns cumulative ACK packets transmitted by the client.
func (m *MobileEngine) GetAcksSent() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.AcksSent)
	}
	return 0
}

// GetAckSendErrors returns cumulative ACK seal/write failures.
func (m *MobileEngine) GetAckSendErrors() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.AckSendErrors)
	}
	return 0
}

// GetDatagramsSent returns cumulative UDP relay datagrams sent.
func (m *MobileEngine) GetDatagramsSent() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.DatagramsSent)
	}
	return 0
}

// GetDatagramsSendErrors returns cumulative UDP relay datagram
// send failures.
func (m *MobileEngine) GetDatagramsSendErrors() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.DatagramsSendErrors)
	}
	return 0
}

// GetDatagramsReceived returns cumulative UDP relay datagrams received.
func (m *MobileEngine) GetDatagramsReceived() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.DatagramsReceived)
	}
	return 0
}

// GetReadPumpDeaths returns cumulative readPump exits +
// watchdog-detected stalls. Nonzero with zero traffic means the
// session is dead even though the UI still shows "connected".
func (m *MobileEngine) GetReadPumpDeaths() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.ReadPumpDeaths)
	}
	return 0
}

// GetStreamPendingResets returns cumulative streams reset because
// their out-of-order reorder buffer exceeded the cap.
func (m *MobileEngine) GetStreamPendingResets() int64 {
	if s, ok := m.engineStats(); ok {
		return int64(s.StreamPendingResets)
	}
	return 0
}

// FetchEgressIP fetches checkURL (https) through the running tunnel's
// Mist client and returns the response body, e.g. the egress IP as
// seen by the check service. It dials a fresh Mist stream (not the
// TUN) and performs TLS + HTTP GET over it, so it proves the egress
// path independently of the tunnel's DNS path and of the old
// SOCKS-based exit check. The engine must be running; otherwise it
// returns an error. The check URL is supplied by the caller (no
// single service is hardcoded). timeoutSec caps the whole request
// (<=0 = 10s default, capped at 30s). Only https URLs are accepted
// and redirects are not followed.
func (m *MobileEngine) FetchEgressIP(checkURL string, timeoutSec int) (string, error) {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	if timeoutSec > 30 {
		timeoutSec = 30
	}
	hostPort, sniHost, err := parseEgressTarget(checkURL)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	client := m.client
	running := m.running
	m.mu.Unlock()
	if !running || client == nil {
		return "", errors.New("mist: engine not running")
	}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := client.Dial(ctx, hostPort)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{ServerName: sniHost})
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tc, nil
		},
		// Plain HTTP/1.1 over the Mist stream: no HTTP/2
		// negotiation surprises on a custom dialer, no proxy.
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := hc.Get(checkURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mist: egress check status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// parseEgressTarget splits an https check URL into the Mist dial
// target (host:port, default 443) and the TLS SNI host. It rejects
// non-https URLs and URLs without a host.
func parseEgressTarget(checkURL string) (hostPort, sniHost string, err error) {
	u, err := url.Parse(checkURL)
	if err != nil {
		return "", "", err
	}
	if u.Scheme != "https" {
		return "", "", fmt.Errorf("mist: egress URL must be https: %s", checkURL)
	}
	host := u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("mist: egress URL missing host: %s", checkURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port), host, nil
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
