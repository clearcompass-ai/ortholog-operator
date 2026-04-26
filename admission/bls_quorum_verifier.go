/*
FILE PATH: admission/bls_quorum_verifier.go

BLS quorum verification at admission time per Wave 1 v3 §S1.

Scope (Wave 1 v3, intentionally narrow): this verifier fires ONLY for
entries whose payload embeds a cosigned tree head — anchor entries
authored by peer operators, witness-attestation commentary, cross-log
proof entries. Plain submissions that do not carry an embedded
checkpoint skip this stage entirely; the v7.75 commitment-entry
surface (pre-grant-commitment-v1, escrow-split-commitment-v1) does
not embed tree heads and therefore never triggers S1.

The verifier wraps the SDK's witness.VerifyTreeHead primitive, which
in turn invokes signatures.VerifyWitnessCosignatures. SDK mutation
gates muEnableWitnessQuorumCount, muEnableUniqueSigners, and
muEnableWitnessKeyMembership fire inside the SDK call; the operator's
job is purely to invoke the primitive and map its errors to the
admission-layer's ErrWitnessQuorumInsufficient.

Detection vs. verification (separation of concerns):

  - EntryEmbedsTreeHead reports whether an entry's schema is one
    the operator knows carries a cosigned tree head. Currently a
    closed-set predicate that returns false for every schema; future
    commits add specific schema_id matches as the operator's
    cross-log proof and peer-anchor surfaces grow. As long as the
    predicate returns false, this verifier is dead code and Wave 1
    ships with the admission pipeline correctly skipping S1 — which
    is the intended behavior for the entry surface v7.75 introduces.

  - ExtractEmbeddedTreeHead parses the embedded head from the
    payload. Schema-specific. Stubbed for the same reason as the
    detector.

  - VerifyEmbeddedTreeHead is the actual cryptographic check. Real
    and complete — it would fire correctly the moment the detector
    matches a real schema.

Active witness key set: loaded from operator config at startup via
the WitnessKeySet interface (config-backed implementations live in
cmd/operator/main.go wiring, not here). Refresh on signal is the
operator wiring's responsibility — this verifier reads a fresh
snapshot on every Verify call so updates propagate without restart.
*/
package admission

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	sdkwitness "github.com/clearcompass-ai/ortholog-sdk/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrWitnessQuorumInsufficient is returned when an entry carrying
// an embedded cosigned tree head fails to meet the active witness
// set's quorum threshold. The HTTP layer maps this to 401.
//
// Wraps the SDK's witness.ErrInsufficientWitnesses,
// witness.ErrNoSignatures, and witness.ErrEmptyWitnessSet via the
// %w verb so callers can errors.Is on either the operator-side
// sentinel or the underlying SDK cause.
var ErrWitnessQuorumInsufficient = errors.New(
	"admission: witness quorum insufficient")

// ErrWitnessKeySetUnavailable is returned when the active witness
// key set provider returns an error. The HTTP layer maps this to
// 503 — the entry is structurally valid but the operator cannot
// presently verify it.
var ErrWitnessKeySetUnavailable = errors.New(
	"admission: witness key set unavailable")

// ─────────────────────────────────────────────────────────────────────
// Witness key set provider
// ─────────────────────────────────────────────────────────────────────

// WitnessKeySet provides the active witness public keys and quorum
// threshold to the BLS quorum verifier. Implementations are config-
// backed (operator startup loads from YAML) or remote-DID-backed
// (resolver fetches the current set from a witness coordinator).
//
// Active is called on every Verify invocation; implementations
// should cache aggressively. The contract is "give me the snapshot
// to use for THIS verification" — staleness handling lives in the
// implementation.
//
// Returns:
//
//   - keys:    the active witness public keys (BLS or ECDSA)
//   - quorumK: the K threshold for the K-of-N quorum
//   - err:     non-nil only on config / resolver failure; an empty
//              key set is still a successful return that the
//              verifier rejects with ErrWitnessQuorumInsufficient
//              wrapping the SDK's ErrEmptyWitnessSet.
type WitnessKeySet interface {
	Active() (keys []types.WitnessPublicKey, quorumK int, err error)
}

// ─────────────────────────────────────────────────────────────────────
// Verifier
// ─────────────────────────────────────────────────────────────────────

// BLSQuorumVerifier verifies cosigned tree heads embedded in
// admission-time entry payloads. Constructed once at operator
// startup and shared across the admission handler's request pool;
// safe for concurrent use as long as the WitnessKeySet
// implementation is.
type BLSQuorumVerifier struct {
	keySet      WitnessKeySet
	blsVerifier signatures.BLSVerifier
}

// NewBLSQuorumVerifier constructs a verifier with the supplied
// witness key set provider and BLS verifier. blsVerifier may be
// nil if the deployment expects only ECDSA cosignatures —
// signatures.VerifyWitnessCosignatures dispatches on the head's
// SchemeTag and only invokes blsVerifier for BLS-tagged heads.
func NewBLSQuorumVerifier(
	keySet WitnessKeySet,
	blsVerifier signatures.BLSVerifier,
) *BLSQuorumVerifier {
	return &BLSQuorumVerifier{
		keySet:      keySet,
		blsVerifier: blsVerifier,
	}
}

// VerifyEmbeddedTreeHead is the cryptographic check: load the
// active witness set and invoke the SDK's witness.VerifyTreeHead.
// Maps any quorum-related SDK error to ErrWitnessQuorumInsufficient
// so the admission layer can route a single status code without
// branching on the SDK error vocabulary.
//
// Mutation gates honored via the SDK call:
//
//   - muEnableWitnessQuorumCount  (witness/verify_mutation_switches.go)
//   - muEnableUniqueSigners       (signatures/witness_verify.go)
//   - muEnableWitnessKeyMembership (signatures/witness_verify.go)
//
// Wave 1 v3 §S1 does NOT require the operator to honor these
// directly — the SDK call is the binding layer.
func (v *BLSQuorumVerifier) VerifyEmbeddedTreeHead(
	head types.CosignedTreeHead,
) error {
	if v == nil {
		return errors.New("admission: nil BLSQuorumVerifier")
	}
	if v.keySet == nil {
		return fmt.Errorf("%w: nil key set provider",
			ErrWitnessKeySetUnavailable)
	}

	keys, quorumK, err := v.keySet.Active()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWitnessKeySetUnavailable, err)
	}

	_, verifyErr := sdkwitness.VerifyTreeHead(head, keys, quorumK, v.blsVerifier)
	if verifyErr == nil {
		return nil
	}

	// Map every quorum-class SDK error to a single admission-layer
	// sentinel. The HTTP layer renders this as 401; operators
	// inspecting the wrapped chain via errors.Unwrap can still
	// see the specific SDK cause for diagnostics.
	switch {
	case errors.Is(verifyErr, sdkwitness.ErrInsufficientWitnesses),
		errors.Is(verifyErr, sdkwitness.ErrNoSignatures),
		errors.Is(verifyErr, sdkwitness.ErrEmptyWitnessSet):
		return fmt.Errorf("%w: %v", ErrWitnessQuorumInsufficient, verifyErr)
	default:
		// A non-quorum SDK failure (config bug, malformed head,
		// signature math failure) surfaces unchanged. The HTTP
		// layer treats these as 401 the same way — a failed
		// quorum-class assertion is functionally equivalent to a
		// failed cryptographic check at the trust boundary —
		// but log lines preserve the distinction.
		return fmt.Errorf("admission: witness verify: %w", verifyErr)
	}
}

// VerifyEntry is the convenience wrapper the admission handler
// calls per request. It checks whether the entry embeds a tree
// head; if not, it returns nil unchanged (passthrough). If it
// does, ExtractEmbeddedTreeHead parses the head and
// VerifyEmbeddedTreeHead checks it.
//
// Decoupling the detector from the verifier means future commits
// can grow EntryEmbedsTreeHead's closed-set match without
// touching the cryptographic path, and conversely a new
// signature scheme on the verifier side does not have to know
// about every embedding schema.
func (v *BLSQuorumVerifier) VerifyEntry(entry *envelope.Entry) error {
	if entry == nil {
		return nil
	}
	if !EntryEmbedsTreeHead(entry) {
		return nil
	}
	head, ok, extractErr := ExtractEmbeddedTreeHead(entry)
	if extractErr != nil {
		return fmt.Errorf("admission: extract embedded tree head: %w", extractErr)
	}
	if !ok {
		// Detector matched but extractor did not — the schema is
		// known to embed a head but the payload was malformed in
		// a way the extractor surfaces as "not present" rather
		// than a parse error. Treat as quorum failure: the
		// cryptographic guarantee the embedding promises is not
		// available, so admission must reject.
		return fmt.Errorf("%w: schema declares embedded tree head but payload had none",
			ErrWitnessQuorumInsufficient)
	}
	return v.VerifyEmbeddedTreeHead(head)
}

// ─────────────────────────────────────────────────────────────────────
// Schema-specific detection + extraction (extension points)
// ─────────────────────────────────────────────────────────────────────

// EntryEmbedsTreeHead reports whether an entry's payload schema is
// one the operator knows to carry a cosigned tree head. Currently
// a closed-set predicate that returns false for every schema; the
// v7.75 commitment-entry surface introduced in Wave 1 (pre-grant-
// commitment-v1, escrow-split-commitment-v1) does NOT embed tree
// heads, so S1 verification is correctly a no-op for those entries.
//
// Future commits add matches for:
//
//   - Cross-log proof entries (when a domain network adds a schema
//     for them)
//   - Peer-authored anchor entries (when the operator starts
//     accepting external anchors)
//   - Witness-attestation commentary (operator-owned schema)
//
// Each addition is a trivial schema_id match against the entry's
// SchemaRef-resolved manifest or a known-DID match on the signer
// for operator-owned schemas. The closed-set discipline ensures
// the operator never invokes S1 on payloads it does not own —
// the Domain/Protocol Separation Principle remains intact.
func EntryEmbedsTreeHead(entry *envelope.Entry) bool {
	if entry == nil {
		return false
	}
	// Closed-set passthrough. No schemas yet.
	return false
}

// ExtractEmbeddedTreeHead parses a cosigned tree head from the
// entry's DomainPayload. Returns (zero, false, nil) when the
// schema is unrecognized — the typical case for Wave 1 because
// EntryEmbedsTreeHead also returns false for every schema. Wired
// alongside detector additions in future commits.
//
// Errors are reserved for genuine parse failures on payloads whose
// schema IS recognized as carrying a tree head — schema mismatch
// or wire-format corruption. Unrecognized schemas are not errors;
// they are passthroughs at the detector layer.
func ExtractEmbeddedTreeHead(entry *envelope.Entry) (types.CosignedTreeHead, bool, error) {
	if entry == nil {
		return types.CosignedTreeHead{}, false, nil
	}
	// Closed-set passthrough — extractor is symmetric with
	// EntryEmbedsTreeHead. No schemas yet.
	return types.CosignedTreeHead{}, false, nil
}
