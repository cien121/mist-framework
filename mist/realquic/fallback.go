package realquic

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// Step-5 fallback client (REALQUIC-DESIGN.md Q8).
//
// Leg preference is fixed: QUIC first, TCP leg only on failure. The
// switch is never user-visible and never requires a new node:
//
//   - QUIC dial failure (timeout included) -> full AUTH on the TCP leg
//     (there is no session yet to resume, so a fresh AUTH is correct).
//   - An established QUIC session whose transport dies -> RESUME on
//     the TCP leg with the session params from the QUIC AUTH, no fresh
//     K_auth token. The server's session table is shared across legs
//     (Server.TCPServer), which is what makes resume possible.
//   - An AUTH failure (wrong key, replayed token: server answers 404
//     on QUIC, visitor response on TCP) never triggers a leg switch:
//     the other leg would fail identically, and switching would only
//     burn another token attempt.
//
// Thresholds, labelled honestly: the QUIC dial timeout here is a
// laboratory test value (DialDualConfig.QUICDialTimeout, tests use
// 2s), NOT a design number — design D4 leaves UDP timeout / loss-rate
// thresholds [待定]. What step 5 implements is dial-timeout fallback
// plus transport-death detection (the QUIC connection's context), not
// a continuous loss-rate monitor: a loss-rate trigger needs the
// heartbeat design that belongs with later steps, and inventing one
// here would be a number without a measurement behind it. That gap is
// recorded in doc.go as an open item.

// DialDualConfig configures the fallback client.
type DialDualConfig struct {
	Key []byte
	// QUICDialTimeout bounds the QUIC dial attempt before falling back
	// to TCP. Lab test value only, not a design threshold (see above).
	QUICDialTimeout time.Duration
}

// DualClient holds one active leg at a time. leg is "quic" or "tcp".
type DualClient struct {
	key     []byte
	tcpAddr string

	mu      sync.Mutex
	quic    *Client
	tcp     *TCPClient
	leg     string
	session *sessionParams
}

// DialDual dials the QUIC leg first (bounded by cfg.QUICDialTimeout),
// AUTHs on it, and falls back to a full TCP-leg AUTH only on transport
// failure. An AUTH rejection (non-200) is returned as an error with no
// fallback, for the reason given above.
func DialDual(ctx context.Context, quicPC net.PacketConn, quicAddr net.Addr, tcpAddr string, cfg DialDualConfig) (*DualClient, error) {
	timeout := cfg.QUICDialTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	cli, err := DialPacketConn(qctx, quicPC, quicAddr, cfg.Key)
	cancel()
	if err == nil {
		status, _, _, aerr := cli.Auth(ctx)
		if aerr == nil && status == http.StatusOK {
			return &DualClient{key: cfg.Key, tcpAddr: tcpAddr, quic: cli, leg: "quic", session: cli.sessionSnapshot()}, nil
		}
		if aerr == nil {
			// AUTH rejection (e.g. 404): the key/token is wrong, the
			// other leg would reject it too. No fallback.
			_ = cli.Close()
			return nil, errors.New("realquic: QUIC AUTH rejected, no leg fallback for auth failures")
		}
		// Transport error during AUTH: fall through to TCP.
		_ = cli.Close()
	}
	tcp, err := DialTCP(ctx, tcpAddr, cfg.Key)
	if err != nil {
		return nil, err
	}
	if err := tcp.Auth(ctx); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	d := &DualClient{key: cfg.Key, tcpAddr: tcpAddr, tcp: tcp, leg: "tcp"}
	d.mu.Lock()
	d.session = tcp.session
	d.mu.Unlock()
	return d, nil
}

// Leg reports the active leg: "quic" or "tcp".
func (d *DualClient) Leg() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.leg
}

// Connect opens a CONNECT relay on the active leg.
func (d *DualClient) Connect(ctx context.Context, target string) (*ConnectStream, error) {
	d.mu.Lock()
	leg, quic, tcp := d.leg, d.quic, d.tcp
	d.mu.Unlock()
	switch leg {
	case "quic":
		return quic.Connect(ctx, target)
	case "tcp":
		return tcp.Connect(ctx, target)
	default:
		return nil, errors.New("realquic: dual client has no active leg")
	}
}

// SwitchToTCPResume moves an established session to the TCP leg via
// RESUME (no fresh K_auth token). It is used when the QUIC transport
// has died; the caller may also call it explicitly (the design's
// "explicit blocking signal" trigger, in lab form).
func (d *DualClient) SwitchToTCPResume(ctx context.Context) error {
	d.mu.Lock()
	session := d.session
	oldQuic := d.quic
	d.mu.Unlock()
	if session == nil || !session.hasResume {
		return errors.New("realquic: no resumable session for TCP switch")
	}
	tcp, err := DialTCP(ctx, d.tcpAddr, d.key)
	if err != nil {
		return err
	}
	if err := tcp.Resume(session); err != nil {
		_ = tcp.Close()
		return err
	}
	d.mu.Lock()
	d.tcp = tcp
	d.leg = "tcp"
	d.mu.Unlock()
	if oldQuic != nil {
		_ = oldQuic.Close()
	}
	return nil
}

// ReconnectIfNeeded checks whether the QUIC leg has died and, if so,
// resumes the session on the TCP leg. It returns true if a switch
// happened, false if the QUIC leg is still alive (or already on TCP).
func (d *DualClient) ReconnectIfNeeded(ctx context.Context) (bool, error) {
	d.mu.Lock()
	leg, quic := d.leg, d.quic
	d.mu.Unlock()
	if leg != "quic" || quic == nil || !quic.transportDead() {
		return false, nil
	}
	if err := d.SwitchToTCPResume(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// Close closes the active leg.
func (d *DualClient) Close() error {
	d.mu.Lock()
	quic, tcp := d.quic, d.tcp
	d.mu.Unlock()
	if quic != nil {
		_ = quic.Close()
	}
	if tcp != nil {
		return tcp.Close()
	}
	return nil
}
