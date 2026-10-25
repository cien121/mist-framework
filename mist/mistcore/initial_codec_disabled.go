// RandomCiphertextCodec is RETIRED (Phase 0 complete).
//
// The type is kept so old references compile, but every method fails:
// random-ciphertext Initial packets are no longer emitted or parsed.
// Use QUICInitialCodec (real QUIC Initial, RFC 9000/9001) instead.
package mistcore

import "errors"

// errCodecDisabled is returned by every RandomCiphertextCodec method in
// builds without the mist_unsafe_initial tag.
var errCodecDisabled = errors.New("mist: RandomCiphertextCodec 已废弃（Phase 0 完成），请用 QUICInitialCodec")

// RandomCiphertextCodec is the Phase 1 simplified Initial codec.
// In this build it is an inert stub: all methods return errCodecDisabled.
type RandomCiphertextCodec struct{}

// SealInitial is disabled in builds without mist_unsafe_initial.
func (c *RandomCiphertextCodec) SealInitial(authPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error) {
	return nil, errCodecDisabled
}

// OpenInitial is disabled in builds without mist_unsafe_initial.
func (c *RandomCiphertextCodec) OpenInitial(packet []byte) ([]byte, [8]byte, [8]byte, uint32, error) {
	return nil, [8]byte{}, [8]byte{}, 0, errCodecDisabled
}

// SealInitialResponse is disabled in builds without mist_unsafe_initial.
func (c *RandomCiphertextCodec) SealInitialResponse(authOKPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error) {
	return nil, errCodecDisabled
}

// OpenInitialResponse is disabled in builds without mist_unsafe_initial.
func (c *RandomCiphertextCodec) OpenInitialResponse(packet []byte) ([]byte, [8]byte, [8]byte, uint32, error) {
	return nil, [8]byte{}, [8]byte{}, 0, errCodecDisabled
}
