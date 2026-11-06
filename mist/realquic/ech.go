package realquic

import "errors"

// True-QUIC round (design §4, Q11; open item U17): ECH-for-QUIC
// applicability, recorded as data rather than as a comment that can
// drift. The design rule is: SNI is NOT hidden by default. A QUIC
// Initial's keys derive from public values, so a passive observer can
// decrypt the Initial; writing "QUIC is encrypted, therefore SNI is
// invisible" is forbidden.
//
// What is established about the stack path (from the parent agent's
// startup check, adopted here, not re-derived):
//
//   - ECH is standardised (RFC 9849).
//   - Go 1.26's standard library tls exposes
//     EncryptedClientHelloConfigList.
//   - The pinned quic-go v0.64.1 production code handles ECH (sni.go
//     findSNIAndECH, crypto_stream.go ECH splitting), and its tests
//     build ECH-carrying ClientHello messages via tls.QUICClient.
//
// That proves the stack path can carry ECH bytes. It does NOT prove
// Mist end-to-end ECH works: the client-facing server key, the DNS
// HTTPS ech record, the backend split, and the accept/retry behaviour
// are all unverified in a Mist deployment. Until that verification
// exists, VerifiedEndToEnd stays false and SNIHidden stays false.
// RecordVerification flips it only on non-empty evidence naming the
// verification that actually ran; an empty evidence string is refused
// rather than recorded, because an evidence-free "verified" would be
// exactly the presupposition the design forbids.

// ECHApplicability records whether ECH hides SNI for a Mist QUIC
// deployment. StackCarriesECH says the stack path can carry ECH;
// VerifiedEndToEnd says a Mist deployment's ECH handshake accept path
// has actually been verified. The two must not be conflated.
type ECHApplicability struct {
	StackCarriesECH  bool
	VerifiedEndToEnd bool
	// Evidence names the verification behind VerifiedEndToEnd, when
	// set. Empty while unverified.
	Evidence string
}

// DefaultECHApplicability is the only constructor a deployment starts
// from: the stack carries ECH, end-to-end is unverified, SNI is not
// hidden.
func DefaultECHApplicability() ECHApplicability {
	return ECHApplicability{StackCarriesECH: true, VerifiedEndToEnd: false}
}

// SNIHidden reports whether SNI may be treated as hidden. It is true
// only after end-to-end verification, never from stack capability
// alone.
func (e ECHApplicability) SNIHidden() bool { return e.VerifiedEndToEnd }

// RecordVerification returns the applicability with end-to-end
// verification recorded, or an error (leaving the receiver unchanged)
// when the evidence string is empty.
func (e ECHApplicability) RecordVerification(evidence string) (ECHApplicability, error) {
	if evidence == "" {
		return e, errors.New("realquic: ECH verification requires non-empty evidence")
	}
	e.VerifiedEndToEnd = true
	e.Evidence = evidence
	return e, nil
}
