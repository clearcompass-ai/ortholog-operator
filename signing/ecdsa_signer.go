// ECDSA signer — operator-native inter-service signing.
//
// Delegates to the SDK's crypto/signatures.SignEntry primitive so that
// every byte emitted by this signer is verifiable by the SDK's
// crypto/signatures.VerifyEntry. The SDK calls stdlib ecdsa.Sign /
// ecdsa.Verify internally, so the curve is determined by the
// *ecdsa.PrivateKey the caller provides. P-256 is the default.
package signing

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdksig "github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// ECDSASigner wraps a stdlib *ecdsa.PrivateKey for operator self-signing.
//
// Concurrent safe: the private key is immutable after construction,
// and sdksig.SignEntry is a pure function.
type ECDSASigner struct {
	key       *ecdsa.PrivateKey
	signerDID string
}

// NewECDSASigner constructs a signer from a stdlib ECDSA private key
// and the DID whose key this is.
//
// Validation:
//   - key must be non-nil.
//   - signerDID must be non-empty.
//
// Curve validation is deferred to the SDK's SignEntry / VerifyEntry.
// Any curve the Go stdlib supports (P-224, P-256, P-384, P-521) will
// work end-to-end. Operator deployments should standardize on P-256
// unless there's a specific reason to deviate.
func NewECDSASigner(key *ecdsa.PrivateKey, signerDID string) (*ECDSASigner, error) {
	if key == nil {
		return nil, fmt.Errorf("signing: nil private key")
	}
	if signerDID == "" {
		return nil, fmt.Errorf("signing: signerDID required")
	}
	return &ECDSASigner{key: key, signerDID: signerDID}, nil
}

// Sign implements Signer. Computes sha256(signingPayload) and delegates
// to the SDK's crypto/signatures.SignEntry. Returns 64-byte raw R||S
// and the envelope.SigAlgoECDSA algorithm ID.
func (s *ECDSASigner) Sign(signingPayload []byte) ([]byte, uint16, error) {
	digest := hashSigningPayload(signingPayload)
	sig, err := sdksig.SignEntry(digest, s.key)
	if err != nil {
		return nil, 0, fmt.Errorf("signing: SignEntry: %w", err)
	}
	return sig, envelope.SigAlgoECDSA, nil
}

// SignerDID implements Signer.
func (s *ECDSASigner) SignerDID() string { return s.signerDID }
