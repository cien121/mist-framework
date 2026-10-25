package realquic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/curve25519"
)

// Client is a lab client over one shared QUIC connection. It speaks
// HTTP/3, and in this step also taken-over custom streams (CONNECT,
// UDP registration) and RFC 9221 datagrams on the same connection.
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
	// EnableDatagrams negotiates RFC 9221 datagrams for the UDP relay;
	// it does not change the H3 behaviour of the connection.
	qconn, err := quic.Dial(ctx, pc, remoteAddr, tlsConf, &quic.Config{EnableDatagrams: true})
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

// --- Step 4: taken-over streams and datagrams (path S) ---

// NewSessionID generates a fresh random 16-byte UDP session ID.
func NewSessionID() ([16]byte, error) {
	var sid [16]byte
	_, err := rand.Read(sid[:])
	return sid, err
}

// Connect opens a custom stream, sends a CONNECT frame for target
// ("host:port"), and waits for CONNECT_OK. The returned stream relays
// framed DATA in both directions; its lifecycle is the dial's lifecycle.
// Only meaningful after a successful AUTH on this connection (the server
// cancels custom streams on unauthenticated connections).
func (c *Client) Connect(ctx context.Context, target string) (*ConnectStream, error) {
	str, err := c.qconn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	applyReadDeadline(str, ctx)
	payload, err := encodeTarget(target)
	if err != nil {
		_ = str.Close()
		return nil, err
	}
	if err := WriteFrame(str, frameConnect, payload); err != nil {
		_ = str.Close()
		return nil, err
	}
	for {
		fr, err := ReadFrame(str)
		if err != nil {
			_ = str.Close()
			return nil, err
		}
		switch fr.Type {
		case frameConnectOK:
			clearReadDeadline(str)
			return &ConnectStream{str: str}, nil
		case frameConnectErr:
			_ = str.Close()
			return nil, errors.New("realquic: connect refused: " + string(fr.Payload))
		default:
			_ = str.Close()
			return nil, errors.New("realquic: unexpected frame on CONNECT stream")
		}
	}
}

// RegisterUDP registers a UDP relay session on this connection: datagrams
// tagged with sid are forwarded to target, and replies come back tagged
// with the same sid. The registration stream closes after the
// acknowledgement; the session persists on the server until the
// connection closes.
func (c *Client) RegisterUDP(ctx context.Context, sid [16]byte, target string) error {
	str, err := c.qconn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer str.Close()
	applyReadDeadline(str, ctx)
	payload, err := encodeUDPRegistration(sid, target)
	if err != nil {
		return err
	}
	if err := WriteFrame(str, frameRegisterUDP, payload); err != nil {
		return err
	}
	fr, err := ReadFrame(str)
	if err != nil {
		return err
	}
	switch fr.Type {
	case frameRegisterOK:
		return nil
	case frameRegisterErr:
		return errors.New("realquic: UDP registration refused: " + string(fr.Payload))
	default:
		return errors.New("realquic: unexpected frame on REGISTER stream")
	}
}

// SendDatagram sends one UDP-relay datagram tagged with sid. Delivery is
// not guaranteed (RFC 9221 datagrams are not retransmitted).
func (c *Client) SendDatagram(sid [16]byte, payload []byte) error {
	return c.qconn.SendDatagram(encodeDatagram(sid, payload))
}

// ReceiveDatagram receives one UDP-relay datagram and splits it into its
// session ID and payload. Unknown sessions never produce a datagram here:
// the server drops them instead of routing them anywhere.
func (c *Client) ReceiveDatagram(ctx context.Context) ([16]byte, []byte, error) {
	data, err := c.qconn.ReceiveDatagram(ctx)
	if err != nil {
		return [16]byte{}, nil, err
	}
	return decodeDatagram(data)
}

func applyReadDeadline(str *quic.Stream, ctx context.Context) {
	if dl, ok := ctx.Deadline(); ok {
		_ = str.SetReadDeadline(dl)
	}
}

func clearReadDeadline(str *quic.Stream) {
	_ = str.SetReadDeadline(time.Time{})
}

// ConnectStream is one CONNECT relay: Write sends framed DATA, Read
// returns relayed DATA bytes (buffering a frame's leftover across calls).
// Close closes the write side; the read side ends when the server closes
// the stream (e.g. the TCP target closed).
type ConnectStream struct {
	str *quic.Stream

	mu  sync.Mutex
	buf []byte
}

// Write sends p as one or more DATA frames, chunked to maxDataChunk.
func (cs *ConnectStream) Write(p []byte) (int, error) {
	total := len(p)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for len(p) > 0 {
		n := len(p)
		if n > maxDataChunk {
			n = maxDataChunk
		}
		if err := WriteFrame(cs.str, frameData, p[:n]); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return total, nil
}

// Read returns buffered DATA bytes, or the next DATA frame's payload.
// A non-DATA frame or stream end terminates the read side.
func (cs *ConnectStream) Read(p []byte) (int, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for len(cs.buf) == 0 {
		fr, err := ReadFrame(cs.str)
		if err != nil {
			return 0, err
		}
		if fr.Type != frameData {
			return 0, io.EOF
		}
		cs.buf = fr.Payload
	}
	n := copy(p, cs.buf)
	cs.buf = cs.buf[n:]
	return n, nil
}

// Close closes the write side of the stream.
func (cs *ConnectStream) Close() error {
	return cs.str.Close()
}
