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
// P1 step A adds the Q6 server-issued profile mechanism (see
// profile.go, and the AUTH/push/receipt paths in server.go, client.go
// and tcp.go): the AUTH success body on both legs carries the server's
// issued profile envelope; the client stores profiles per server
// (version-gated, no key material), starts from bootstrap on first
// contact and from the server profile on later sessions; the server
// rotates versions on a randomly picked delay inside a deployment
// configured interval and can push the current profile to an
// authenticated connection over a sealed custom stream, which the
// client applies from the next window; a well-formed receipt whose
// version differs from the connection's issued version downgrades the
// connection to an ordinary HTTP/3 visitor (same H3 service, same
// pre-AUTH custom-stream refusal, no distinctive error). No separate
// envelope signature is added: authenticity rests on the Mode A
// authenticated connection carrying the AUTH body.
//
// P1 step A explicitly does NOT execute (carried, stored, validated,
// not applied — see profile.go header): the hopping window range
// (hopping stays default-off), the downstream stagger delay range, and
// the split-connection reuse caps (the split itself is P2); the Q3
// shaping engine that will consume the shaping/steady fields; and
// in-session pushes on the TCP leg (one CONNECT per connection, no
// server-initiated control stream there yet). Downgrade is
// receipt-driven only: absence of a receipt never downgrades, a
// malformed receipt is ignored, and a receipt for any version ever
// issued to the connection is compliant (receipts are asynchronous, so
// judging an in-flight receipt against a just-moved latest version
// would false-positive); only a version never issued to the connection
// downgrades, and the downgrade is sticky until a fresh AUTH.
//
// P1 step B wires the Q3 shaping parameters into real sends, handshake
// first flight only, both directions (see shaping.go for the window
// definition, the tail rule, and the honest API gaps): the client Dial
// and the server listeners hand the QUIC stack a pacing/counting
// PacketConn wrapper only — never the raw connection — so quantity
// (per-direction budgets) and timing (CSPRNG-jittered pacing gaps) are
// enforced at actual datagram sends, and length is shaped through AUTH
// request/response body padding (quic-go's public API has no handshake
// PADDING-frame injection point, and this step does not fork it or use
// its internals; datagram-tail garbage padding is not used, as it would
// corrupt QUIC parsing). Budget exhaustion transitions the window to
// the profile's steady slot (provisional values, P2 baseline pending)
// instead of ever sending bare. A pushed profile queues on the shaper
// and takes effect at the next window boundary; AUTH success is the
// client window boundary and a re-AUTH is the server one. The TCP leg
// is not shaped by this engine (no PacketConn/datagram layer there),
// and hopping, stagger, and reuse caps remain carried-not-executed.
//
// Scope limits of this step, by design:
//   - No port hopping (default off), no up/down split (deferred), no
//     steady-state shaping beyond the tail transition, no measurement matrix (M2 timing in step 2 is preliminary
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
//
// True-QUIC round (design ~/workspace/mist-protocol/nextround/
// truequic-design.md §3–§8, work-tree only, unpushed): mechanism
// implementations on top of the wiring above, not a rewrite of it.
//   - §3 stack: quic-go pinned at v0.64.1 (stack.go; go.mod pin
//     enforced by test). The in-stack blackhole fix stays fork
//     pre-research and is NOT in this round. Parrot parameter sets
//     are tracked in ParrotRegistry (register / retire / select);
//     the QUIC leg uses Go standard TLS (no parrot), the TCP leg uses
//     utls HelloChrome_Auto. Parrot follow-up cadence is undecided
//     (U19); retirement is explicit, with no numeric threshold.
//   - §4 identity: ECH applicability is data (ech.go), not a claim:
//     the stack path carries ECH, but Mist end-to-end ECH is
//     UNVERIFIED, so SNI is not treated as hidden (U17). The client
//     refuses Mist-semantics calls before AUTH (requireSession in
//     client.go and the TCP leg's Connect gate): the first Mist
//     request goes out only after the AUTH response (D11
//     conservative rule). The decoy fallback is real same-stack
//     HTTP/3 content, never a forward to a third-party target, and
//     its per-connection byte cap is sampled uniformly from an
//     operator-configured interval (decoy.go; unset means off in
//     this lab server, decoy content itself is a deployment detail,
//     U24). No new identifier is introduced into any visible
//     surface: association identifiers are the existing session and
//     connection IDs, recomputed nowhere here.
//   - §5 shaping/rotation: shapingPacketConn counts the final
//     datagram length actually written, padding included, so a
//     padded datagram is never "padded but uncounted" at the Mist
//     layer (the stack's internal congestion window is stack state
//     and is not claimed to be counted here); small datagrams at or
//     below AckLenMax never take an idle gap (see shaping.go).
//     Server.IssueProfile is the server-instruction value-rotation
//     API (version-only RotateProfile does not rotate parameters);
//     first-connection bootstrap exposure is counted per server in
//     ProfileStore (observation only — the downgrade rule is
//     undecided, U18, so no behaviour keys off the count). Rotation
//     cadence, learning time and block-deployment time are likewise
//     undecided (U18).
//   - §6 split: the stagger mechanism, per-leg PMTU generations, and
//     server-enforced reuse caps already exist (split.go,
//     split_pmtu.go); this round changes none of their semantics.
//     The stagger interval stays operator configuration ([0,0]
//     means off, as before): forcing a stagger would decide the
//     D3 upper bound (U8), which stays undecided, and would break
//     the existing split tests that run with [0,0]. Reuse caps stay
//     fixed profile values enforced server-side; a randomised
//     interval cap is a design direction, not a decided change, and
//     is not implemented here. The TCP leg's dial-timeout /
//     transport-death fallback exists; its continuous loss-rate
//     trigger stays undecided (U9, D4).
//   - §7 size/PMTU: v3 §3 is carried, not rewritten. The fine-grained
//     size residual (50–100 byte bands distinguishable at roughly
//     0.94–0.96 against a TCP-1500 comparator) is a known structural
//     residual: TCP-1500 is no longer a legal fine-grained ruler
//     (D-α evolution), the size baseline must be a matching QUIC
//     comparator (real H3 browsing, G1), and that baseline does not
//     exist yet (U1 blocks numeric targets, not mechanism work).
//     Tail padding stays gated off by default (SizePolicy): the
//     TailPadder mechanism exists but is not wired into a send path
//     in this round, because with no G1 baseline there is no verdict
//     its exception clause could be judged against.
//   - §8 generation/blackhole: stall detection stays at the Mist
//     layer (stall.go, connection-level aggregate semantics) and
//     recovery stays a new generation, never QUIC connection
//     migration (migration as a recovery optimisation is undecided,
//     U23, and is not a recovery path here). T_A = 8s and the T-2
//     page-period semantics (T_page derivation, page/object mode
//     switch on page success, page bumps counted separately) are
//     inherited unchanged. In-transit objects are re-fetched from
//     byte zero on a bump, never resumed (Q4 gap unchanged).
//   - Wiring order (U22): the main-branch SyscallConn wiring had NOT
//     landed when this round started, so this round builds on the
//     work tree's existing shapingPacketConn.SyscallConn pass-through
//     and does not assume the remote branch has it. Whether that
//     wiring ships separately is not this round's decision.
//   - Language rule for this round: mechanism work is fingerprint
//     reduction only. Nothing here claims indistinguishability, and
//     no threshold in this round is a measured target: U1–U25
//     (except U3, closed by prior confirmation) remain undecided
//     and are left [待定] wherever the design leaves them so.
package realquic
