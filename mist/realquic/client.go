package realquic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/curve25519"
)

// Client is a lab client over one shared QUIC connection. It speaks pure
// HTTP/3 in this step; no stream is taken over.
type Client struct {
	key        []byte
	authHeader string
	authPath   string
	qconn      *quic.Conn
	h3         *http3.ClientConn
}

// DialPacketConn dials over pc to remoteAddr (net.PacketConn abstraction).
// TLS verification is skipped: this is lab code talking to an in-memory
// test certificate for "realquic.test". It must never be used against a
// production endpoint.
func DialPacketConn(ctx context.Context, pc net.PacketConn, remoteAddr net.Addr, key []byte) (*Client, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // lab only: in-memory test certificate
		NextProtos:         []string{"h3"},
		ServerName:         testServerName,
	}
	qconn, err := quic.Dial(ctx, pc, remoteAddr, tlsConf, &quic.Config{})
	if err != nil {
		return nil, err
	}
	return &Client{
		key:        key,
		authHeader: DefaultAuthHeader,
		authPath:   DefaultAuthPath,
		qconn:      qconn,
		h3:         (&http3.Transport{}).NewClientConn(qconn),
	}, nil
}

// Close closes the underlying QUIC connection.
func (c *Client) Close() error {
	return c.qconn.CloseWithError(0, "done")
}

// freshToken builds a one-use AUTH token with a fresh nonce and a fresh
// client ephemeral keypair.
func (c *Client) freshToken() (string, error) {
	var priv, pub [32]byte
	var nonce16 [16]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce16[:]); err != nil {
		return "", err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return MakeToken(c.key, pub, time.Now(), nonce16), nil
}

// Request performs one HTTP/3 request on the shared connection and returns
// status, body and round-trip time. token, when non-empty, is sent as the
// AUTH header value.
func (c *Client) Request(ctx context.Context, method, path, token string) (int, []byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, method, "https://"+testServerName+path, nil)
	if err != nil {
		return 0, nil, 0, err
	}
	if token != "" {
		req.Header.Set(c.authHeader, token)
	}
	start := time.Now()
	resp, err := c.h3.RoundTrip(req)
	if err != nil {
		return 0, nil, time.Since(start), err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, time.Since(start), err
}

// Auth sends a fresh-token AUTH request and returns status, body, latency.
func (c *Client) Auth(ctx context.Context) (int, []byte, time.Duration, error) {
	token, err := c.freshToken()
	if err != nil {
		return 0, nil, 0, err
	}
	return c.Request(ctx, http.MethodPost, c.authPath, token)
}

// Get performs a plain visitor GET (no AUTH) on the shared connection.
func (c *Client) Get(ctx context.Context, path string) (int, []byte, time.Duration, error) {
	return c.Request(ctx, http.MethodGet, path, "")
}
