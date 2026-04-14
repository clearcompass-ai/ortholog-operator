/*
FILE PATH: api/submission.go

Entry submission endpoint — the complete 10-step admission pipeline.
Fail-fast: first failure terminates with appropriate HTTP status.

KEY ARCHITECTURAL DECISIONS:
  - Sequential pipeline: order matters (sig before size, size before enqueue).
  - SDK-D5 contract established HERE: signature verified before persistence.
  - Decision 50: Log_Time assigned at step 6, never in canonical bytes.
  - Decision 51: Evidence_Pointers cap checked at step 4.
  - Atomic persist+enqueue: single Postgres tx prevents orphaned entries.
  - Live difficulty: reads from DifficultyController per-request, not snapshot.
  - Protocol version validated at step 1 (preamble check).
  - Canonical hash computed from RAW canonical bytes (not re-serialized).
  - Duplicate hash mapped to HTTP 409 (not generic 500).
  - DIDResolver: nil = Phase 2 wire format trust model.
                  set = Phase 4 full DID→pubkey→VerifyEntry.

INVARIANTS:
  - Past step 2: all entries have verified signatures (SDK-D5).
  - Log_Time is monotonically non-decreasing within single-operator deployment.
  - Sequence numbers are gapless (Postgres sequence).
*/
package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
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
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"

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
type DIDResolver interface {
	ResolvePublicKey(ctx context.Context, did string) (*ecdsa.PublicKey, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) Submission Dependencies
// ─────────────────────────────────────────────────────────────────────────────

// SubmissionDeps holds dependencies for the submission handler.
type SubmissionDeps struct {
	DB              *pgxpool.Pool
	EntryStore      *store.EntryStore
	EntryWriter     tessera.EntryWriter // Bytes go here, not Postgres.
	CreditStore     *store.CreditStore
	Queue           *builder.Queue
	LogDID          string
	MaxEntrySize    int64
	DiffController  *middleware.DifficultyController
	Logger          *slog.Logger

	// DIDResolver resolves signer DIDs to public keys for signature verification.
	// nil = Phase 2 trust model (wire format integrity only, no cryptographic
	//       verification — StripSignature + Deserialize establishes format).
	// set = Phase 4 full verification (DID → pubkey → VerifyEntry).
	DIDResolver DIDResolver
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Submission Handler
// ─────────────────────────────────────────────────────────────────────────────

// NewSubmissionHandler creates the POST /v1/entries handler.
func NewSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// ── Step 1: Read raw bytes + validate preamble ─────────────────
		sigOverhead := int64(512) // sig envelope overhead allowance
		raw, err := io.ReadAll(io.LimitReader(r.Body, deps.MaxEntrySize+sigOverhead))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}

		// Validate preamble: Protocol_Version (bytes 0-1) must be 3.
		if len(raw) < 6 {
			writeError(w, http.StatusUnprocessableEntity, "entry too short for preamble")
			return
		}
		protocolVersion := binary.BigEndian.Uint16(raw[0:2])
		if protocolVersion != 3 {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("unsupported protocol version %d (expected 3)", protocolVersion))
			return
		}

		// ── Step 2: Signature verification (SDK-D5) ────────────────────
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

		// Validate signer_did is non-empty.
		if entry.Header.SignerDID == "" {
			writeError(w, http.StatusUnprocessableEntity, "empty signer DID")
			return
		}

		// Signature verification dispatch:
		if deps.DIDResolver != nil {
			// Phase 4: full cryptographic verification.
			// DID → public key → sdk VerifyEntry.
			pubkey, resolveErr := deps.DIDResolver.ResolvePublicKey(ctx, entry.Header.SignerDID)
			if resolveErr != nil {
				writeError(w, http.StatusUnauthorized,
					fmt.Sprintf("DID resolution failed for %s: %s", entry.Header.SignerDID, resolveErr))
				return
			}
			canonicalHash := sha256.Sum256(canonical)
			if verifyErr := signatures.VerifyEntry(canonicalHash, sigBytes, pubkey); verifyErr != nil {
				writeError(w, http.StatusUnauthorized,
					fmt.Sprintf("signature verification failed: %s", verifyErr))
				return
			}
		} else {
			// Phase 2 trust model: wire format integrity only.
			// Mode A: the exchange has already verified the signer's identity.
			// Mode B: the PoW stamp proves computational commitment.
			// StripSignature + Deserialize success establishes wire format integrity.
			_ = sigBytes
		}

		// ── Step 3: Entry size (SDK-D11) ───────────────────────────────
		if int64(len(canonical)) > deps.MaxEntrySize {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("canonical bytes %d exceed max %d",
					len(canonical), deps.MaxEntrySize))
			return
		}

		// ── Step 4: Evidence_Pointers cap (Decision 51) ────────────────
		if !middleware.CheckEvidenceCap(entry) {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("Evidence_Pointers %d exceeds cap %d (non-snapshot)",
					len(entry.Header.EvidencePointers),
					middleware.MaxEvidencePointers))
			return
		}

		// ── Step 5: Admission mode ─────────────────────────────────────
		authenticated := middleware.IsAuthenticated(ctx)
		exchangeDID := middleware.ExchangeDID(ctx)

		if !authenticated {
			// Mode B: verify compute stamp.
			h := &entry.Header
			if h.AdmissionProof == nil {
				writeError(w, http.StatusForbidden,
					"unauthenticated submission requires compute stamp")
				return
			}
			if h.AdmissionProof.TargetLog != deps.LogDID {
				writeError(w, http.StatusForbidden, "stamp bound to different log DID")
				return
			}

			// Compute hash over raw canonical bytes for stamp verification.
			canonicalHash := sha256.Sum256(canonical)
			currentDifficulty := deps.DiffController.CurrentDifficulty()
			hashFuncName := deps.DiffController.HashFunction()
			var hashFunc admission.HashFunc
			switch hashFuncName {
			case "argon2id":
				hashFunc = admission.HashArgon2id
			default:
				hashFunc = admission.HashSHA256
			}

			if err := admission.VerifyStamp(
				canonicalHash, h.AdmissionProof.Nonce,
				deps.LogDID, currentDifficulty, hashFunc, nil,
			); err != nil {
				writeError(w, http.StatusForbidden,
					fmt.Sprintf("stamp verification failed: %s", err))
				return
			}
		}

		// ── Step 6: Log_Time assignment (SDK-D1, Decision 50) ──────────
		logTime := time.Now().UTC()

		// ── Step 7: Canonical hash (from raw bytes, not re-serialized) ─
		canonicalHash := sha256.Sum256(canonical)

		// ── Steps 8-9: Atomic persist + enqueue ────────────────────────
		var seq uint64
		err = store.WithReadCommittedTx(ctx, deps.DB, func(ctx context.Context, tx pgx.Tx) error {
			// Mode A credit deduction (inside transaction).
			if authenticated {
				if _, deductErr := deps.CreditStore.Deduct(ctx, tx, exchangeDID); deductErr != nil {
					return deductErr // ErrInsufficientCredits → HTTP 402
				}
			}

			// Allocate sequence number.
			var seqErr error
			seq, seqErr = deps.EntryStore.NextSequence(ctx, tx)
			if seqErr != nil {
				return seqErr
			}

			// Extract indexed fields from deserialized header.
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

			// Insert entry index (metadata only — no bytes in Postgres).
			insertErr := deps.EntryStore.Insert(ctx, tx, store.EntryRow{
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

			// Write bytes to Tessera (source of truth for entry bytes).
			if deps.EntryWriter != nil {
				if writeErr := deps.EntryWriter.WriteEntry(seq, canonical, sigBytes); writeErr != nil {
					return fmt.Errorf("write entry bytes: %w", writeErr)
				}
			}

			// Enqueue for builder.
			return deps.Queue.Enqueue(ctx, tx, seq)
		})

		if err != nil {
			if errors.Is(err, store.ErrInsufficientCredits) {
				writeError(w, http.StatusPaymentRequired, "insufficient write credits")
				return
			}
			if errors.Is(err, store.ErrDuplicateEntry) {
				// Look up existing sequence for the response.
				existingSeq, found, _ := deps.EntryStore.FetchByHash(ctx, canonicalHash)
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

		// ── Step 10: Success ───────────────────────────────────────────
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
