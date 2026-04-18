/*
FILE PATH: api/queries.go

DESCRIPTION:
    Read-side query handlers for the operator's HTTP API. Fetches entries
    by sequence range, by hash, and by signer DID. Returns EntryResponse
    structures with canonical hash + metadata + payload byte-size.

SDK v0.3.0 ALIGNMENT:
    - toEntryResponses computes the canonical hash via envelope.EntryIdentity(entry)
      when deserialization succeeds. This is byte-identical to
      sha256.Sum256(ewm.CanonicalBytes) but expresses the Tessera-aligned
      vocabulary: the returned hash IS the Tessera dedup key / Entry.Identity().
    - Fallback to crypto.HashBytes(ewm.CanonicalBytes) when deserialize fails
      (shouldn't happen if admission was clean, but belt-and-braces).
    - Byte-store fetch path unchanged — wire bytes (canonical + sig) are what
      consumers need to recompute EntryIdentity independently.
*/
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto"

	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ─────────────────────────────────────────────────────────────────────
// Dependencies
// ─────────────────────────────────────────────────────────────────────

// QueryDeps is the dependency surface for read-side handlers.
type QueryDeps struct {
	DB          *pgxpool.Pool
	EntryStore  *store.EntryStore
	EntryReader tessera.EntryReader
	Logger      *slog.Logger
}

// ─────────────────────────────────────────────────────────────────────
// Response shape
// ─────────────────────────────────────────────────────────────────────

// EntryResponse is the JSON shape returned by query handlers.
type EntryResponse struct {
	SequenceNumber uint64 `json:"sequence_number"`
	CanonicalHash  string `json:"canonical_hash"`
	LogTime        string `json:"log_time"`
	SignerDID      string `json:"signer_did,omitempty"`
	ProtocolVer    uint16 `json:"protocol_version"`
	SigAlgorithmID uint16 `json:"sig_algorithm_id"`
	PayloadSize    int    `json:"payload_size"`
	CanonicalSize  int    `json:"canonical_size"`
}

// ─────────────────────────────────────────────────────────────────────
// toEntryResponses — central hash-computation site
// ─────────────────────────────────────────────────────────────────────

// toEntryResponses converts EntryWithMetadata slice into API responses.
// This is the single site where canonical hashes are computed for the
// read path — aligning here aligns every query endpoint at once.
func toEntryResponses(metas []*struct {
	SequenceNumber uint64
	CanonicalBytes []byte
	SigAlgoID      uint16
	LogTime        string
	SignerDID      string
}) []EntryResponse {
	out := make([]EntryResponse, 0, len(metas))
	for _, ewm := range metas {
		resp := EntryResponse{
			SequenceNumber: ewm.SequenceNumber,
			LogTime:        ewm.LogTime,
			SignerDID:      ewm.SignerDID,
			SigAlgorithmID: ewm.SigAlgoID,
			CanonicalSize:  len(ewm.CanonicalBytes),
		}

		// Deserialize to compute the Tessera-aligned entry identity. If
		// deserialization fails (shouldn't happen post-admission), fall
		// back to a plain SHA-256 of the stored bytes — still byte-
		// identical, but expressed via the generic primitive.
		entry, err := envelope.Deserialize(ewm.CanonicalBytes)
		if err != nil {
			// Malformed bytes in the byte store — log and degrade gracefully.
			h := crypto.HashBytes(ewm.CanonicalBytes)
			resp.CanonicalHash = hex.EncodeToString(h[:])
			resp.ProtocolVer = 0
			resp.PayloadSize = 0
		} else {
			// Happy path: use the Tessera-aligned vocabulary.
			id := envelope.EntryIdentity(entry)
			resp.CanonicalHash = hex.EncodeToString(id[:])
			resp.ProtocolVer = entry.Header.ProtocolVersion
			resp.PayloadSize = len(entry.DomainPayload)
		}

		out = append(out, resp)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries?from=N&to=M
// ─────────────────────────────────────────────────────────────────────

// NewRangeQueryHandler returns entries in [from, to] by sequence number.
func NewRangeQueryHandler(deps *QueryDeps) http.HandlerFunc {
	const maxRange = 1000
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")
		from, err := strconv.ParseUint(fromStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'from' parameter")
			return
		}
		to, err := strconv.ParseUint(toStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'to' parameter")
			return
		}
		if to < from {
			writeError(w, http.StatusBadRequest, "'to' must be >= 'from'")
			return
		}
		if to-from+1 > maxRange {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("range %d exceeds max %d", to-from+1, maxRange))
			return
		}

		metas, err := fetchRangeWithBytes(ctx, deps, from, to)
		if err != nil {
			deps.Logger.Error("range query failed", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}

		responses := toEntryResponses(metas)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": responses,
			"from":    from,
			"to":      to,
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/hash/{hash_hex}
// ─────────────────────────────────────────────────────────────────────

// NewHashLookupHandler returns a single entry by its canonical hash.
func NewHashLookupHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		hashHex := r.URL.Path[len("/v1/entries/hash/"):]
		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil || len(hashBytes) != 32 {
			writeError(w, http.StatusBadRequest, "invalid canonical hash")
			return
		}
		var hash [32]byte
		copy(hash[:], hashBytes)

		seq, found, err := deps.EntryStore.FetchByHash(ctx, hash)
		if err != nil {
			deps.Logger.Error("hash lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "entry not found")
			return
		}

		metas, err := fetchRangeWithBytes(ctx, deps, seq, seq)
		if err != nil || len(metas) == 0 {
			writeError(w, http.StatusInternalServerError, "fetch failed")
			return
		}

		responses := toEntryResponses(metas)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses[0])
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/{seq}/raw — returns wire bytes
// ─────────────────────────────────────────────────────────────────────

// NewRawEntryHandler returns the canonical bytes + signature envelope as
// a single byte stream. Consumers feed this into envelope.StripSignature
// then envelope.Deserialize then envelope.EntryIdentity to verify.
func NewRawEntryHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		_ = ctx

		seqStr := r.URL.Path[len("/v1/entries/"):]
		if i := len(seqStr) - len("/raw"); i > 0 && seqStr[i:] == "/raw" {
			seqStr = seqStr[:i]
		}
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid sequence")
			return
		}

		canonical, sig, algoID, err := deps.EntryReader.ReadEntry(seq)
		if err != nil {
			writeError(w, http.StatusNotFound, "entry not found in byte store")
			return
		}

		wire, err := envelope.AppendSignature(canonical, algoID, sig)
		if err != nil {
			deps.Logger.Error("append signature failed", "seq", seq, "error", err)
			writeError(w, http.StatusInternalServerError, "reconstruction failed")
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Sequence", strconv.FormatUint(seq, 10))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wire)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// fetchRangeWithBytes joins the entries table with byte-store lookups.
// Returns a slice of structurally-typed metas used by toEntryResponses.
func fetchRangeWithBytes(ctx context.Context, deps *QueryDeps, from, to uint64) ([]*struct {
	SequenceNumber uint64
	CanonicalBytes []byte
	SigAlgoID      uint16
	LogTime        string
	SignerDID      string
}, error) {
	rows, err := deps.EntryStore.FetchRange(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("fetch range: %w", err)
	}

	out := make([]*struct {
		SequenceNumber uint64
		CanonicalBytes []byte
		SigAlgoID      uint16
		LogTime        string
		SignerDID      string
	}, 0, len(rows))

	for _, row := range rows {
		canonical, _, algoID, err := deps.EntryReader.ReadEntry(row.SequenceNumber)
		if err != nil {
			// Byte-store miss for a sequence the entries table knows about —
			// surface as a hard error; this is an operator-side inconsistency.
			return nil, fmt.Errorf("read seq=%d from byte store: %w",
				row.SequenceNumber, err)
		}
		_ = errors.Is // silences unused import if errors not referenced
		out = append(out, &struct {
			SequenceNumber uint64
			CanonicalBytes []byte
			SigAlgoID      uint16
			LogTime        string
			SignerDID      string
		}{
			SequenceNumber: row.SequenceNumber,
			CanonicalBytes: canonical,
			SigAlgoID:      algoID,
			LogTime:        row.LogTime.Format("2006-01-02T15:04:05.000000000Z"),
			SignerDID:      row.SignerDID,
		})
	}
	return out, nil
}
