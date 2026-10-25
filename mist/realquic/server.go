package realquic

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/curve25519"
)

// ServerConfig configures the lab server. Key is the test K_auth; it must
// be supplied by the caller (tests generate a fresh random key per run).
// AuthHeader/AuthPath are deployment configuration, not protocol constants.
type ServerConfig struct {
	Key        []byte
	AuthHeader string
	AuthPath   string
	Window     time.Duration
	// Site, if nil, is the default static test site.
	Site http.Handler
}

// Server is a Mode A lab server: a real QUIC + HTTP/3 site whose AUTH
// request is one ordinary HTTP/3 request. It serves pure HTTP/3 only;
// stream takeover is explicitly not done in this step.
type Server struct {
	verify     *verifier
	authHeader string
	authPath   string
	site       http.Handler
	ephPub     [32]byte
	h3         *http3.Server
}

// defaultSite is the static test site content. It intentionally has no
// /auth route: a visitor (or a failed AUTH) requesting the AUTH path gets
// the site's own 404, exactly as an ordinary request to an unknown path.
func defaultSite() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("realquic lab site\n"))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found\n"))
	})
}

// authSuccess is the AUTH success body. server_eph_pub is the server's
// ephemeral X25519 public key (base64). profile is an explicit placeholder:
// the Q6 profile envelope is P1 work and is deferred, not silently omitted.
type authSuccess struct {
	ServerEphPub string      `json:"server_eph_pub"`
	Profile      interface{} `json:"profile"`
	ProfileNote  string      `json:"profile_note"`
}

// NewServer builds a server; it generates the server ephemeral keypair and
// the in-memory test certificate lazily at Serve time. No files are read.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Key) == 0 {
		return nil, errors.New("realquic: test K_auth key is required")
	}
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	s := &Server{
		verify:     newVerifier(cfg.Key, cfg.Window),
		authHeader: cfg.AuthHeader,
		authPath:   cfg.AuthPath,
		ephPub:     pub,
	}
	if s.authHeader == "" {
		s.authHeader = DefaultAuthHeader
	}
	if s.authPath == "" {
		s.authPath = DefaultAuthPath
	}
	s.site = cfg.Site
	if s.site == nil {
		s.site = defaultSite()
	}
	return s, nil
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == s.authPath {
		// One code path for every outcome: verify (constant-time HMAC,
		// window, nonce cache) and, on any failure, fall through to the
		// site handler. Nothing here logs the token, and no failure
		// produces a distinctive status, body, or teardown.
		if s.verify.Verify(r.Header.Get(s.authHeader), time.Now()) {
			body, _ := json.Marshal(authSuccess{
				ServerEphPub: base64.StdEncoding.EncodeToString(s.ephPub[:]),
				Profile:      nil,
				ProfileNote:  "P1 Q6 deferred: profile envelope not in this step",
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
	}
	s.site.ServeHTTP(w, r)
}

// ServePacketConn serves the server over pc (net.PacketConn abstraction:
// real UDP where available, in-memory pair otherwise). It blocks until the
// server is closed or pc is closed. The certificate is generated in memory
// at this point; ALPN is "h3" only.
func (s *Server) ServePacketConn(pc net.PacketConn) error {
	cert, err := generateTestCertificate()
	if err != nil {
		return err
	}
	s.h3 = &http3.Server{
		Handler: http.HandlerFunc(s.handler),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
		},
	}
	return s.h3.Serve(pc)
}

// Close stops the HTTP/3 server. It does not close the PacketConn, which
// remains owned by the caller (matching http3.Server.Serve semantics).
func (s *Server) Close() error {
	if s.h3 == nil {
		return nil
	}
	return s.h3.Close()
}
