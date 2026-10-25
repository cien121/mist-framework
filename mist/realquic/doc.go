// Package realquic is the step-5 Real-QUIC transport for Mist
// (REALQUIC-DESIGN.md, phase 1, Q1/Q2/Q7/Q8).
//
// It runs a real quic-go (official github.com/quic-go/quic-go) stack with
// ALPN "h3" only. The server is itself an HTTP/3 site (Mode A lab form):
// AUTH is one ordinary HTTP/3 request whose opaque token travels in a
// header, and every failure mode (bad HMAC, expired timestamp, replayed
// nonce, no AUTH at all) falls through to the same site handler a plain
// visitor would hit — same status, same body, no distinctive error, no
// connection teardown.
//
// Step 4 adds path-S stream takeover (design Q2.2/D9): the server's
// AcceptStream loop peeks one byte per stream — 0x01 (H3 HEADERS) goes to
// the H3 stack, anything else goes to the custom-frame handler; control
// and QPACK unidirectional streams never enter the dispatch. Custom
// streams carry production frames (see frame.go):
// [MAGIC(1)=0x4D][TYPE(1)][LEN(2) BE][PAYLOAD], where the magic byte is
// constant and never 0x01 at any payload length — the S1 spike's
// [LEN][TYPE] format misrouted 256-511 byte payloads, whose LEN high byte
// is 0x01, and is not used here. CONNECT streams dial a TCP target and
// relay framed DATA both ways; UDP relay uses RFC 9221 datagrams tagged
// with a 16-byte session ID, and datagrams for unknown sessions are
// dropped, never routed to another session. Custom streams and datagrams
// are served only after a successful AUTH on the same connection.
//
// Step 5 adds, on top of step 4 (REALQUIC-DESIGN.md, phase 1, Q2.2/Q7/Q8):
// session keys (X25519 + HKDF per direction, XChaCha20-Poly1305 AEAD
// over frame and datagram payloads, session codec installed atomically
// with AUTH), multi-listener fallback coverage (one server over many
// PacketConns sharing one handler), and the TCP leg (uTLS Chrome-mimic
// TLS 1.3, same K_auth model, same CONNECT semantics, visitor fallback,
// RESUME-based leg switching without a fresh AUTH). See session.go,
// tcp.go and fallback.go.
//
// Scope limits of this step, by design:
//   - No profile envelope (Q6 is phase 2): the AUTH success body carries
//     the server ephemeral public key plus an explicit placeholder noting
//     the profile envelope is deferred to P1.
//   - No port hopping (default off), no up/down split (deferred), no
//     shaping, no measurement matrix (M2 timing in step 2 is preliminary
//     evidence only; the full M2 matrix — probe types x ports x address
//     families — is a later step; step 5 proves the shared-handler
//     coverage that matrix will probe).
//   - Open items carried forward, not silently closed:
//     (a) the server ephemeral pair is per-server-instance, not
//     per-connection; per-connection rotation is a follow-up.
//     (b) session records do not expire in this lab step; production
//     needs a TTL and a size cap.
//     (c) fallback triggers implemented are QUIC dial timeout (lab
//     test value, not a design number — D4 thresholds remain [待定])
//     and transport-death detection; a continuous loss-rate monitor
//     is not in this step.
//     (d) the TCP-leg visitor response is a single static HTTP/1.1
//     rendering of the site handler; production would serve the site
//     as a real HTTP server on the same TLS listener.
//   - Certificates are generated in memory at startup for the reserved test
//     name "realquic.test". No certificate or key files are ever written,
//     and no production domain, address, or key material is referenced.
//   - K_auth is always a caller-supplied test key (tests generate a fresh
//     random key per run). This package never reads production key files.
//
// Transport is abstracted as net.PacketConn on both ends (quic.Listen /
// quic.Dial semantics), so the same code runs over real UDP where
// loopback UDP is allowed and over the in-memory PacketConn pair in this
// package where it is not. Standard unconnected ListenAddr/DialAddr form
// was not verifiable in the step-3 sandbox (seccomp blocks sendmsg with a
// destination address); tests here honestly report their transport, and
// that form remains a pre-M1/M2 gate in another environment.
package realquic
