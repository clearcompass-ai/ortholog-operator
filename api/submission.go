/*
FILE PATH: api/submission.go

Entry submission endpoint — the complete 13-step admission pipeline.
Fail-fast: first failure terminates with appropriate HTTP status.

KEY ARCHITECTURAL DECISIONS:
  - Sequential pipeline: order matters (sig before size, size before enqueue).
  - SDK-D5 contract established HERE: signature verified before persistence.
  - Decision 50: Log_Time assigned at step 9, never in canonical bytes.
  - Decision 51: Evidence_Pointers cap checked at step 6.
  - Atomic persist+enqueue: single Postgres tx prevents orphaned entries.
  - Live difficulty: reads from DifficultyController per-request, not snapshot.
  - Protocol version validated at step 1 (preamble check).
  - Canonical hash via envelope.EntryIdentity (SDK v0.3.0 single source of truth).
  - Duplicate hash mapped to HTTP 409 (not generic 500).

PR 1 — VERIFIER REGISTRY ALIGNMENT:
  - Steps 3b and 4 now use did.VerifierRegistry for combined destination
    routing + cryptographic verification.
  - Step 3b looks up the registry scoped to entry.Header.Destination.
    Absent key → 403 (this operator does not admit for that exchange).
  - Step 4 calls registry.VerifyEntry(), which:
    1. Re-checks Destination match (ErrDestinationMismatch → 403).
    2. Computes the canonical hash internally.
    3. Dispatches to the DID-method-specific verifier (pkh/key/web).
    Replaces the prior custom DIDResolver + signatures.VerifyEntry block.
  - The DIDResolver interface that lived in this file is DELETED.
    All DID resolution flows through the registries' shared caching
    web resolver (wired in cmd/operator/main.go).

SDK v0.3.0 HARDENING (retained from prior rewrite):
  - Step 3a: entry.Validate() re-applies NewEntry's write-time invariants
    after Deserialize. Deserialize is a pure parser — it does not re-run
    ValidateDestination, DID non-emptiness, ASCII conformance, or size caps.
  - Step 3c: late-replay freshness via exchange/policy.CheckFreshness.
  - Step 7: stamp hash via envelope.EntryIdentity(entry) and
    epoch via admission.CurrentEpoch (handles pre-1970 clock edge).
  - Step 8: canonical hash via envelope.EntryIdentity(entry) —
    the single authoritative entry-hash primitive.

DEPENDENCY SHAPE:

	SubmissionDeps groups dependencies by cohesion:
	  - StorageDeps:     persistence (DB + EntryStore + EntryWriter)
	  - AdmissionConfig: stamp verification policy (DiffController + epoch params)
	  - IdentityDeps:    credentials + per-exchange verifier registries
	Crosscutting fields (LogDID, Logger, MaxEntrySize, Queue) live at the top.

INVARIANTS:
  - Past step 3b: entry's Destination matches a registered exchange.
  - Past step 4: entry's signature verified against its Destination-scoped
    registry's DID-method-specific verifier (SDK-D5).
  - Log_Time is monotonically non-decreasing within single-operator deployment.
  - Sequence numbers are gapless (Postgres sequence).
*/
package api

import (
	"context"
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
	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Submission Dependencies — grouped by cohesion
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

// IdentityDeps groups credential and verifier dependencies.
//
// Registries maps admitted exchange DID → VerifierRegistry scoped to that
// exchange. Each registry is constructed via did.DefaultVerifierRegistry
// at startup and wired with the pkh, key, and web verifiers. An entry's
// Destination field selects which registry validates its signature.
//
// Requires at least one entry. An operator with no admitted exchanges
// cannot admit any entries and fails fast at handler construction.
type IdentityDeps struct {
	CreditStore *store.CreditStore
	Registries  map[string]*did.VerifierRegistry
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
// 2) Submission Handler
// ─────────────────────────────────────────────────────────────────────────────

// NewSubmissionHandler creates the POST /v1/entries handler.
//
// Panics if:
//   - AdmissionConfig.EpochWindowSeconds is non-positive (Mode B stamps
//     cannot be validated without a valid epoch window).
//   - LogDID is empty (still required for Mode B stamp binding and as the
//     physical log identity threaded through Tessera / anchor publishing).
//   - Identity.Registries is empty or nil (an operator with no admitted
//     exchanges cannot admit any entries; better to fail at startup than
//     silently 403 every submission).
func NewSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
	if deps.Admission.EpochWindowSeconds <= 0 {
		panic("api: SubmissionDeps.Admission.EpochWindowSeconds must be positive")
	}
	if deps.LogDID == "" {
		panic("api: SubmissionDeps.LogDID must be non-empty (physical log identity, Mode B stamp binding)")
	}
	if len(deps.Identity.Registries) == 0 {
		panic("api: SubmissionDeps.Identity.Registries must contain at least one admitted exchange")
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

		// ── Step 3a: Re-apply NewEntry's write-time invariants ─────────
		// Deserialize is a pure parser — it does not re-run
		// ValidateDestination, DID non-emptiness, ASCII conformance, or
		// size caps. An attacker who wire-forges an entry with empty
		// Destination or non-ASCII bytes bypasses NewEntry's gate;
		// Validate() closes that gap here.
		if err := entry.Validate(); err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("entry validation: %s", err))
			return
		}

		// ── Step 3b: Destination routing via registry lookup (PR 1) ────
		// The entry declares its destination. We look up the
		// VerifierRegistry scoped to that destination. If no registry is
		// configured for this destination, this operator does not admit
		// entries for that exchange — reject 403.
		//
		// Two-gate defense: the map lookup proves we admit for this
		// destination; the registry's internal VerifyEntry re-check
		// (step 4) proves the entry's Destination field wasn't tampered
		// with relative to the hash the signer actually signed.
		registry, ok := deps.Identity.Registries[entry.Header.Destination]
		if !ok {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("entry destination %q not admitted by this operator",
					entry.Header.Destination))
			return
		}

		// ── Step 3c: Late-replay freshness ─────────────────────────────
		// Reject entries whose EventTime is outside the tolerance.
		// Defends against an attacker who captured a legitimately-signed
		// entry, prevented its delivery, and replayed it arbitrarily later.
		if err := policy.CheckFreshness(entry, time.Now().UTC(), freshness); err != nil {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("freshness: %s", err))
			return
		}

		// ── Step 4: Signature verification via registry (SDK-D5) ───────
		// registry.VerifyEntry dispatches to the DID-method-specific
		// verifier (pkh/key/web), enforcing destination binding as part
		// of its security contract.
		//
		// ErrDestinationMismatch → 403 (cross-exchange replay attempt).
		// All other failures → 401 (signature invalid, DID unresolvable,
		// algorithm unsupported for this DID method).
		if err := registry.VerifyEntry(entry, sigBytes, algoID); err != nil {
			if errors.Is(err, did.ErrDestinationMismatch) {
				writeError(w, http.StatusForbidden,
					fmt.Sprintf("destination mismatch: %s", err))
				return
			}
			writeError(w, http.StatusUnauthorized,
				fmt.Sprintf("signature verification failed: %s", err))
			return
		}

		// ── Step 5: Entry size (SDK-D11) ───────────────────────────────
		// Validate() already enforced this via the NewEntry-equivalent
		// size check, but we keep it explicit here because the declared
		// limit is an admission-policy concern (operator may tighten
		// below the SDK ceiling).
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

			apiProof := admission.ProofFromWire(h.AdmissionProof, deps.LogDID)

			// envelope.EntryIdentity is the canonical entry-hash primitive.
			// Byte-identical to sha256.Sum256(canonical) but binds to the
			// Tessera dedup-key vocabulary.
			canonicalHash := envelope.EntryIdentity(entry)
			currentDifficulty := deps.Admission.DiffController.CurrentDifficulty()
			hashFuncName := deps.Admission.DiffController.HashFunction()
			var hashFunc admission.HashFunc
			switch hashFuncName {
			case "argon2id":
				hashFunc = admission.HashArgon2id
			default:
				hashFunc = admission.HashSHA256
			}

			// admission.CurrentEpoch handles the pre-1970 clock edge case
			// (negative Unix timestamp cast to uint64 would silently underflow).
			currentEpoch := admission.CurrentEpoch(uint64(deps.Admission.EpochWindowSeconds))
			acceptanceWindow := uint64(deps.Admission.EpochAcceptanceWindow)

			if err := admission.VerifyStamp(
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
// 3) Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
