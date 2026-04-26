// Package signing provides the operator's self-signing primitives for
// operator-authored commentary entries (anchors, commitments, shard
// genesis) and any other inter-service entry production path.
//
// Contract:
//   - Log entries are signed with envelope.SigAlgoECDSA (raw 64-byte
//     secp256k1 R||S, low-S normalized).
//   - The hash signed is sha256(envelope.SigningPayload(entry)).
//   - The SDK's crypto/signatures.SignEntry produces the wire-compatible
//     signature; the SDK's VerifyEntry accepts it.
//
// Web3 entity signing paths (did:pkh wallet sigs, EIP-191, EIP-712)
// live in the SDK's crypto/signatures package and are wired by the
// submission handler's VerifierRegistry, NOT by this package. This
// package is the operator's self-signing surface only.
package signing

import (
	"crypto/sha256"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// Signer produces signatures over entry SigningPayload bytes.
// Implementations must be safe for concurrent use by multiple goroutines
// (all three publishers — anchor, commitment, shard — run in parallel).
type Signer interface {
	// Sign returns signature bytes and the algorithm ID for the
	// resulting envelope.Signature. The algorithm MUST be one of the
	// registered constants in envelope/signature_algo.go.
	//
	// Implementations compute sha256(signingPayload) internally before
	// the cryptographic sign — this is the SDK's entry-hash convention.
	Sign(signingPayload []byte) (sig []byte, algoID uint16, err error)

	// SignerDID returns the DID whose key produced the signature. MUST
	// match Header.SignerDID of entries signed with this Signer (SDK
	// enforces ErrPrimarySignerMismatch otherwise).
	SignerDID() string
}

// BuildSigned wraps the v6 three-step flow into one call:
//
//  1. envelope.NewUnsignedEntry(header, payload)    — validate header
//  2. signer.Sign(envelope.SigningPayload(unsigned)) — produce sig
//  3. envelope.NewEntry(header, payload, []{sig})    — final entry
//
// All three operator publishers (anchor, commitment, shard genesis)
// use this helper. No direct calls to envelope.NewEntry from publisher
// code — BuildSigned is the single self-signing path.
func BuildSigned(
	header envelope.ControlHeader,
	payload []byte,
	signer Signer,
) (*envelope.Entry, error) {
	unsigned, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		return nil, err
	}
	sig, algoID, err := signer.Sign(envelope.SigningPayload(unsigned))
	if err != nil {
		return nil, err
	}
	return envelope.NewEntry(header, payload, []envelope.Signature{{
		SignerDID: signer.SignerDID(),
		AlgoID:    algoID,
		Bytes:     sig,
	}})
}

// hashSigningPayload is the canonical entry-signing digest. Operator
// signers compute this identically to the SDK's verifier
// (crypto/signatures.VerifyEntry accepts sha256(SigningPayload) as its
// hash argument).
func hashSigningPayload(signingPayload []byte) [32]byte {
	return sha256.Sum256(signingPayload)
}
