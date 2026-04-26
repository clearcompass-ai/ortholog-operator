/*
FILE PATH: api/submission.go

Entry submission endpoint — the complete 13-step admission pipeline.
Fail-fast: first failure terminates with appropriate HTTP status.

KEY ARCHITECTURAL DECISIONS:
  - Sequential pipeline: order matters (sig before size, size before enqueue).
  - SDK-D5 contract established HERE: signature verified before persistence.
  - Decision 50: Log_Time assigned at step 9, never in canonical bytes.
  - Decision 51: Evidence_Pointers cap checked at step 7.
  - Atomic persist+enqueue: single Postgres tx prevents orphaned entries.
  - Live difficulty: reads from DifficultyController per-request, not snapshot.
  - Protocol version validated at step 1 (preamble check).
  - Canonical hash via envelope.EntryIdentity (SDK v0.3.0 single source of truth).
  - Duplicate hash mapped to HTTP 409 (not generic 500).

SDK v0.3.0 HARDENING:
  - Step 3a (NEW): entry.Validate() re-applies NewEntry's write-time invariants
    after Deserialize. Deserialize is a pure parser — it does not re-run
    ValidateDestination, DID non-emptiness, ASCII conformance, or size caps.
    An attacker who wire-forges an entry with empty Destination bypasses
    NewEntry's gate; Validate() closes that gap at admission.
  - Step 3b (NEW): destination binding enforcement. An entry signed for
    exchange A must not be accepted at exchange B. The signature verifies
    (the canonical bytes that were signed commit to A), but the attacker's
    goal is replay at B, and B rejects because entry.Destination != LogDID.
    This is the runtime defense that the cryptographic binding enables.
  - Step 3c (NEW): late-replay freshness. exchange/policy.CheckFreshness
    rejects entries whose EventTime is too far in the past — protects
    against captured-but-never-ingested signed entries being replayed
    days later.
  - Step 5 (UPDATED): stamp hash via envelope.EntryIdentity(entry) and
    epoch via sdkadmission.CurrentEpoch (handles pre-1970 clock edge).
  - Step 8 (UPDATED): canonical hash via envelope.EntryIdentity(entry) —
    the single authoritative entry-hash primitive.

v7.75 WAVE 1 ADMISSION PACKAGE:
  - Step 3a-NFC (NEW): admission.CheckNFC asserts NFC normalization
    on every DID-shaped header field (SignerDID, Destination,
    DelegateDID when non-nil, AuthoritySet keys). Defensive only —
    the operator never normalizes on the caller's behalf, per the
    SDK Decision 52 caller-normalizes contract. Rejects with HTTP 422.
  - Step 4 (REFACTORED): admission.VerifyEntrySignature wraps the
    SDK signatures.VerifyEntry primitive. The Phase 2 nil-resolver
    passthrough is preserved internally to the wrapper, so this
    file no longer branches on resolver presence.

  - DIDResolver: nil = Phase 2 wire format trust model.
    set = Phase 4 full DID→pubkey→VerifyEntry. Future migration can replace
    this with did.DefaultVerifierRegistry.VerifyEntry (see did/verifier_registry.go).

DEPENDENCY SHAPE:

	SubmissionDeps groups dependencies by cohesion:
	  - StorageDeps:     persistence (DB + EntryStore + EntryWriter)
	  - AdmissionConfig: stamp verification policy (DiffController + epoch params)
	  - IdentityDeps:    credentials + DID resolution
	Crosscutting fields (LogDID, Logger, MaxEntrySize, Queue) live at the top.

INVARIANTS:
  - Past step 3a-NFC: all entries have NFC-normalized DID-shaped fields.
  - Past step 3b: all entries are bound to THIS log's LogDID.
  - Past step 4: all entries have verified signatures (SDK-D5).
  - Log_Time is monotonically non-decreasing within single-operator deployment.
  - Sequence numbers are gapless (Postgres sequence).
*/
package api

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/ortholog-operator/admission"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) DID Resolution Interface (Phase 4 signature verification)
// ─────────────────────────────────────────────────────────────────────────────

// DIDResolver resolves a signer DID to its current secp256k1 public key.
// Phase 4 SDK provides the concrete implementation (did/resolver.go).
//
// nil = Phase 2 trust model (wire format integrity only).
// set = Phase 4 full verification (DID → pubkey → sdk VerifyEntry).
//
// Structurally compatible with admission.DIDResolver — the operator's
// admission package defines the same single-method interface, and Go
// auto-converts at the call site to admission.VerifyEntrySignature.
//
// Future migration: replace this with did.VerifierRegistry, whose
// VerifyEntry method enforces destination binding automatically and
// dispatches across DID methods (web/key/pkh).
type DIDResolver interface {
	ResolvePublicKey(ctx context.Context, did string) (*ecdsa.PublicKey, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) Submission Dependencies — grouped by cohesion
// ─────────────────────────────────────────────────────────────────────────────

// StorageDeps groups persistence dependencies for the submission handler.
type StorageDeps struct {
	DB          *pgxpool.Pool
	EntryStore  *store.EntryStore
	EntryWriter tessera.EntryWriter
}

// AdmissionConfig groups parameters that govern admission proof verification.
//
//	DiffController        — provides current difficulty and hash function policy.
//	EpochWindowSeconds    — size of one epoch in seconds (e.g., 3600 = 1 hour).
//	                        MUST be positive; zero will panic at handler creation.
//	EpochAcceptanceWindow — tolerance in epochs around current. A value of 0
//	                        DISABLES epoch checking entirely.
type AdmissionConfig struct {
	DiffController        *middleware.DifficultyController
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
}

// IdentityDeps groups credential and DID resolution dependencies.
type IdentityDeps struct {
	CreditStore *store.CreditStore
	DIDResolver DIDResolver
}

// SubmissionDeps is the dependency surface for the POST /v1/entries handler.
type SubmissionDeps struct {
	Storage      StorageDeps
	Admission    AdmissionConfig
	Identity     IdentityDeps
	Queue        *builder.Queue
	LogDID       string
	MaxEntrySize int64
	Logger       *slog.Logger

	// FreshnessTolerance configures the late-replay rejection window at
	// admission time (exchange/policy.CheckFreshness). Zero defaults to
	// policy.FreshnessInteractive (5 minutes). Set to a larger tempo for
	// deliberative flows, smaller for automated/daemon-only endpoints.
	FreshnessTolerance time.Duration
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Submission Handler
// ─────────────────────────────────────────────────────────────────────────────

// NewSubmissionHandler creates the POST /v1/entries handler.
//
// Panics if AdmissionConfig.EpochWindowSeconds is non-positive — without
// a valid epoch window, the handler cannot validate Mode B admission proofs
// and the operator should refuse to start.
func NewSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
	if deps.Admission.EpochWindowSeconds <= 0 {
		panic("api: SubmissionDeps.Admission.EpochWindowSeconds must be positive")
	}
	if deps.LogDID == "" {
		panic("api: SubmissionDeps.LogDID must be non-empty (destination-binding enforcement)")
	}

	freshness := deps.FreshnessTolerance
	if freshness <= 0 {
		freshness = policy.FreshnessInteractive
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// ── Step 1: Read raw bytes + validate preamble ─────────────────
		sigOverhead := int64(512)
		raw, err := io.ReadAll(io.LimitReader(r.Body, deps.MaxEntrySize+sigOverhead))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}

		if len(raw) < 6 {
			writeError(w, http.StatusUnprocessableEntity, "entry too short for preamble")
			return
		}
		protocolVersion := binary.BigEndian.Uint16(raw[0:2])
		if protocolVersion != envelope.CurrentProtocolVersion() {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("unsupported protocol version %d (expected %d)",
					protocolVersion, envelope.CurrentProtocolVersion()))
			return
		}

		// ── Step 2: Strip signature, deserialize, validate algo ID ─────
		canonical, algoID, sigBytes, err := envelope.StripSignature(raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized,
				fmt.Sprintf("signature envelope: %s", err))
			return
		}

		entry, err := envelope.Deserialize(canonical)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("deserialize: %s", err))
			return
		}

		if err := envelope.ValidateAlgorithmID(algoID); err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		// ── Step 3a: Re-apply NewEntry's write-time invariants (NEW) ──
		// Deserialize is a pure parser — it does not re-run ValidateDestination,
		// DID non-emptiness, ASCII conformance, or size caps. An attacker who
		// wire-forges an entry with empty Destination or non-ASCII bytes
		// bypasses NewEntry's gate; Validate() closes that gap here.
		if err := entry.Validate(); err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("entry validation: %s", err))
			return
		}

		// ── Step 3a-NFC: Defensive NFC assertion (Wave 1 v7.75) ────────
		// SDK Decision 52 places NFC normalization at the caller boundary.
		// The operator asserts the caller honored that contract and rejects
		// mismatches. The operator NEVER normalizes on the caller's behalf —
		// silent normalization here would diverge the canonical-hash bytes
		// the caller signed from the bytes the operator stored.
		if err := admission.CheckNFC(entry); err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("NFC: %s", err))
			return
		}

		// ── Step 3b: Destination binding enforcement (NEW) ────────────
		// The entry's canonical hash commits to Header.Destination. A valid
		// signature proves the signer intended the entry for SOME destination;
		// this check proves that destination is US. Without it, an attacker
		// who captured a signed entry for exchange A could replay it at B —
		// the signature still verifies, but the attacker's goal (having B
		// accept the entry) is foiled because B rejects on destination mismatch.
		//
		// In Phase 4, did.VerifierRegistry.VerifyEntry performs this check
		// automatically and step 3b becomes redundant.
		if entry.Header.Destination != deps.LogDID {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("entry destination %q does not match log %q",
					entry.Header.Destination, deps.LogDID))
			return
		}

		// ── Step 3c: Late-replay freshness (NEW) ──────────────────────
		// Reject entries whose EventTime is outside the tolerance. Defends
		// against an attacker who captured a legitimately-signed entry,
		// prevented its delivery, and replayed it arbitrarily later.
		if err := policy.CheckFreshness(entry, time.Now().UTC(), freshness); err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("freshness: %s", err))
			return
		}

		// ── Step 4: Signature verification (SDK-D5) ────────────────────
		// admission.VerifyEntrySignature handles both branches:
		//   - nil resolver: Phase 2 trust model passthrough (no crypto verify).
		//   - non-nil resolver: Phase 4 DID→pubkey→signatures.VerifyEntry,
		//     with the SDK mutation-audit gates firing inside the call.
		if entry.Header.SignerDID == "" {
			// Validate() already catches this, but belt-and-braces.
			writeError(w, http.StatusUnprocessableEntity, "empty signer DID")
			return
		}
		if err := admission.VerifyEntrySignature(ctx, entry, sigBytes, deps.Identity.DIDResolver); err != nil {
			switch {
			case errors.Is(err, admission.ErrSignerDIDResolution):
				writeError(w, http.StatusUnauthorized, err.Error())
			case errors.Is(err, admission.ErrSignatureInvalid):
				writeError(w, http.StatusUnauthorized, err.Error())
			default:
				deps.Logger.Error("signature verification path failed", "error", err)
				writeError(w, http.StatusInternalServerError, "signature verification failed")
			}
			return
		}

		// ── Step 5: Entry size (SDK-D11) ───────────────────────────────
		// Validate() already enforced this via the NewEntry-equivalent size
		// check, but we keep it explicit here because the declared limit
		// is an admission-policy concern (operator may tighten below the
		// SDK ceiling).
		if int64(len(canonical)) > deps.MaxEntrySize {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("canonical bytes %d exceed max %d",
					len(canonical), deps.MaxEntrySize))
			return
		}

		// ── Step 6: Evidence_Pointers cap (Decision 51) ────────────────
		if !middleware.CheckEvidenceCap(entry) {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("Evidence_Pointers %d exceeds cap %d (non-snapshot)",
					len(entry.Header.EvidencePointers),
					middleware.MaxEvidencePointers))
			return
		}

		// ── Step 7: Admission mode ─────────────────────────────────────
		authenticated := middleware.IsAuthenticated(ctx)
		exchangeDID := middleware.ExchangeDID(ctx)

		if !authenticated {
			h := &entry.Header
			if h.AdmissionProof == nil {
				writeError(w, http.StatusForbidden,
					"unauthenticated submission requires compute stamp")
				return
			}

			apiProof := sdkadmission.ProofFromWire(h.AdmissionProof, deps.LogDID)

			// SDK v0.3.0: envelope.EntryIdentity is the canonical entry-hash
			// primitive. Byte-identical to sha256.Sum256(canonical) but binds
			// to the Tessera dedup-key vocabulary.
			canonicalHash := envelope.EntryIdentity(entry)
			currentDifficulty := deps.Admission.DiffController.CurrentDifficulty()
			hashFuncName := deps.Admission.DiffController.HashFunction()
			var hashFunc sdkadmission.HashFunc
			switch hashFuncName {
			case "argon2id":
				hashFunc = sdkadmission.HashArgon2id
			default:
				hashFunc = sdkadmission.HashSHA256
			}

			// SDK admission.CurrentEpoch handles the pre-1970 clock edge case
			// (negative Unix timestamp cast to uint64 would silently underflow).
			currentEpoch := sdkadmission.CurrentEpoch(uint64(deps.Admission.EpochWindowSeconds))
			acceptanceWindow := uint64(deps.Admission.EpochAcceptanceWindow)

			if err := sdkadmission.VerifyStamp(
				apiProof,
				canonicalHash,
				deps.LogDID,
				currentDifficulty,
				hashFunc,
				nil, // Argon2idParams: nil = SDK defaults
				currentEpoch,
				acceptanceWindow,
			); err != nil {
				writeError(w, http.StatusForbidden,
					fmt.Sprintf("stamp verification failed: %s", err))
				return
			}
		}

		// ── Step 8: Canonical hash (Tessera-aligned vocabulary) ────────
		// envelope.EntryIdentity(entry) is the Tessera dedup key — the
		// value Tessera's Entry.Identity() returns. Byte-identical to
		// sha256.Sum256(envelope.Serialize(entry)).
		canonicalHash := envelope.EntryIdentity(entry)

		// ── Step 9: Log_Time assignment (SDK-D1, Decision 50) ──────────
		logTime := time.Now().UTC()

		// ── Steps 10-12: Atomic persist + enqueue ──────────────────────
		var seq uint64
		err = store.WithReadCommittedTx(ctx, deps.Storage.DB, func(ctx context.Context, tx pgx.Tx) error {
			// Mode A credit deduction (inside transaction).
			if authenticated {
				if _, deductErr := deps.Identity.CreditStore.Deduct(ctx, tx, exchangeDID); deductErr != nil {
					return deductErr
				}
			}

			var seqErr error
			seq, seqErr = deps.Storage.EntryStore.NextSequence(ctx, tx)
			if seqErr != nil {
				return seqErr
			}

			var targetRootBytes, cosigOfBytes, schemaRefBytes []byte
			if entry.Header.TargetRoot != nil {
				targetRootBytes = store.SerializeLogPosition(*entry.Header.TargetRoot)
			}
			if entry.Header.CosignatureOf != nil {
				cosigOfBytes = store.SerializeLogPosition(*entry.Header.CosignatureOf)
			}
			if entry.Header.SchemaRef != nil {
				schemaRefBytes = store.SerializeLogPosition(*entry.Header.SchemaRef)
			}

			insertErr := deps.Storage.EntryStore.Insert(ctx, tx, store.EntryRow{
				SequenceNumber: seq,
				CanonicalHash:  canonicalHash,
				LogTime:        logTime,
				SigAlgorithmID: algoID,
				SignerDID:      entry.Header.SignerDID,
				TargetRoot:     targetRootBytes,
				CosignatureOf:  cosigOfBytes,
				SchemaRef:      schemaRefBytes,
			})
			if insertErr != nil {
				return insertErr
			}

			if deps.Storage.EntryWriter != nil {
				if writeErr := deps.Storage.EntryWriter.WriteEntry(seq, canonical, sigBytes); writeErr != nil {
					return fmt.Errorf("write entry bytes: %w", writeErr)
				}
			}

			return deps.Queue.Enqueue(ctx, tx, seq)
		})

		if err != nil {
			if errors.Is(err, store.ErrInsufficientCredits) {
				writeError(w, http.StatusPaymentRequired, "insufficient write credits")
				return
			}
			if errors.Is(err, store.ErrDuplicateEntry) {
				existingSeq, found, _ := deps.Storage.EntryStore.FetchByHash(ctx, canonicalHash)
				if found {
					writeError(w, http.StatusConflict,
						fmt.Sprintf("duplicate entry: existing sequence %d", existingSeq))
				} else {
					writeError(w, http.StatusConflict, "duplicate entry")
				}
				return
			}
			deps.Logger.Error("admission failed", "error", err)
			writeError(w, http.StatusInternalServerError, "admission failed")
			return
		}

		// ── Step 13: Success ───────────────────────────────────────────
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sequence_number": seq,
			"canonical_hash":  hex.EncodeToString(canonicalHash[:]),
			"log_time":        logTime.Format(time.RFC3339Nano),
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
