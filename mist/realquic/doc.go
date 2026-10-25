// Package realquic is the step-2 transport skeleton for Mist Real-QUIC
// (REALQUIC-DESIGN.md, phase 1, Q1/Q2/Q7 only).
//
// It runs a real quic-go (official github.com/quic-go/quic-go) stack with
// ALPN "h3" only, in pure HTTP/3 mode: no stream takeover happens in this
// step (takeover is step 3+). The server is itself an HTTP/3 site (Mode A
// lab form): AUTH is one ordinary HTTP/3 request whose opaque token travels
// in a header, and every failure mode (bad HMAC, expired timestamp, replayed
// nonce, no AUTH at all) falls through to the same site handler a plain
// visitor would hit — same status, same body, no distinctive error, no
// connection teardown.
//
// Scope limits of this step, by design:
//   - No session keys, no profile envelope (Q6 is phase 2): the AUTH success
//     body carries the server ephemeral public key plus an explicit
//     placeholder noting the profile envelope is deferred to P1.
//   - No port hopping (default off), no up/down split (deferred), no
//     shaping, no measurement matrix (M2 timing here is preliminary
//     evidence only; the full M2 matrix is a later step).
//   - Certificates are generated in memory at startup for the reserved test
//     name "realquic.test". No certificate or key files are ever written,
//     and no production domain, address, or key material is referenced.
//   - K_auth is always a caller-supplied test key (tests generate a fresh
//     random key per run). This package never reads production key files.
//
// Transport is abstracted as net.PacketConn on both ends (quic.Listen /
// quic.Dial semantics via http3.Server.Serve and quic.Dial), so the same
// code runs over real UDP where loopback UDP is allowed and over the
// in-memory PacketConn pair in this package where it is not.
package realquic
