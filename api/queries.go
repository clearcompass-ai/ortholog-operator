/*
FILE PATH: api/queries.go

All 5 query endpoints (from OperatorQueryAPI) plus admission difficulty.
Returns enriched EntryResponse JSON, not raw EntryWithMetadata.

KEY ARCHITECTURAL DECISIONS:
  - EntryResponse enriches sdk EntryWithMetadata with extracted indexed fields.
  - Position params encoded as hex bytes in URL path.
  - Scan enforces MaxScanCount (10000) with explicit error on exceeding.
  - Difficulty endpoint reads LIVE value from DifficultyController (atomic).
  - All results as JSON arrays (empty array if no results, never null).
*/
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) EntryResponse — presentation type for HTTP responses
// ─────────────────────────────────────────────────────────────────────────────

// EntryResponse enriches sdk EntryWithMetadata with extracted header fields.
type EntryResponse struct {
	SequenceNumber uint64    `json:"sequence_number"`
	CanonicalHash  string    `json:"canonical_hash"`
	LogTime        time.Time `json:"log_time"`
	SignerDID      string    `json:"signer_did"`
	TargetRoot     *string   `json:"target_root,omitempty"`
	CosignatureOf  *string   `json:"cosignature_of,omitempty"`
	SchemaRef      *string   `json:"schema_ref,omitempty"`
	CanonicalBytes string    `json:"canonical_bytes"` // base64
}

func toEntryResponses(ewms []types.EntryWithMetadata) []EntryResponse {
	results := make([]EntryResponse, 0, len(ewms))
	for _, ewm := range ewms {
		resp := EntryResponse{
			SequenceNumber: ewm.Position.Sequence,
			LogTime:        ewm.LogTime,
			CanonicalBytes: hex.EncodeToString(ewm.CanonicalBytes),
		}
		// Compute hash from canonical bytes.
		h := sha256.Sum256(ewm.CanonicalBytes)
		resp.CanonicalHash = hex.EncodeToString(h[:])

		// Extract header fields via deserialization.
		entry, err := envelope.Deserialize(ewm.CanonicalBytes)
		if err == nil {
			resp.SignerDID = entry.Header.SignerDID
			if entry.Header.TargetRoot != nil {
				s := entry.Header.TargetRoot.String()
				resp.TargetRoot = &s
			}
			if entry.Header.CosignatureOf != nil {
				s := entry.Header.CosignatureOf.String()
				resp.CosignatureOf = &s
			}
			if entry.Header.SchemaRef != nil {
				s := entry.Header.SchemaRef.String()
				resp.SchemaRef = &s
			}
		}
		results = append(results, resp)
	}
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) Query Dependencies
// ─────────────────────────────────────────────────────────────────────────────

// QueryDeps holds dependencies for query handlers.
type QueryDeps struct {
	QueryAPI       *indexes.PostgresQueryAPI
	DiffController *middleware.DifficultyController
	Logger         *slog.Logger
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Position-based queries
// ─────────────────────────────────────────────────────────────────────────────

// NewQueryCosignatureOfHandler creates GET /v1/query/cosignature_of/{pos}.
func NewQueryCosignatureOfHandler(deps *QueryDeps) http.HandlerFunc {
	return posQueryHandler(func(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
		return deps.QueryAPI.QueryByCosignatureOf(pos)
	}, deps.Logger)
}

// NewQueryTargetRootHandler creates GET /v1/query/target_root/{pos}.
func NewQueryTargetRootHandler(deps *QueryDeps) http.HandlerFunc {
	return posQueryHandler(func(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
		return deps.QueryAPI.QueryByTargetRoot(pos)
	}, deps.Logger)
}

// NewQuerySchemaRefHandler creates GET /v1/query/schema_ref/{pos}.
func NewQuerySchemaRefHandler(deps *QueryDeps) http.HandlerFunc {
	return posQueryHandler(func(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
		return deps.QueryAPI.QueryBySchemaRef(pos)
	}, deps.Logger)
}

func posQueryHandler(
	fn func(types.LogPosition) ([]types.EntryWithMetadata, error),
	logger *slog.Logger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		posHex := r.PathValue("pos")
		posBytes, err := hex.DecodeString(posHex)
		if err != nil || len(posBytes) < 10 {
			writeError(w, http.StatusBadRequest, "pos must be hex-encoded LogPosition bytes")
			return
		}
		pos, err := store.DeserializeLogPosition(posBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid LogPosition encoding")
			return
		}

		results, err := fn(pos)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "query failed")
			logger.Error("query", "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toEntryResponses(results))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Signer DID query
// ─────────────────────────────────────────────────────────────────────────────

// NewQuerySignerDIDHandler creates GET /v1/query/signer_did/{did}.
func NewQuerySignerDIDHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		did := r.PathValue("did")
		if did == "" {
			writeError(w, http.StatusBadRequest, "did parameter required")
			return
		}
		results, err := deps.QueryAPI.QueryBySignerDID(did)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "signer query failed")
			deps.Logger.Error("signer_did query", "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toEntryResponses(results))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) Scan query
// ─────────────────────────────────────────────────────────────────────────────

// NewQueryScanHandler creates GET /v1/query/scan?start=&count=.
func NewQueryScanHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startStr := r.URL.Query().Get("start")
		countStr := r.URL.Query().Get("count")

		start := uint64(1)
		if startStr != "" {
			v, err := strconv.ParseUint(startStr, 10, 64)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid start parameter")
				return
			}
			start = v
		}

		count := indexes.DefaultScanCount
		if countStr != "" {
			v, err := strconv.Atoi(countStr)
			if err != nil || v < 1 {
				writeError(w, http.StatusBadRequest, "invalid count parameter")
				return
			}
			if v > indexes.MaxScanCount {
				writeError(w, http.StatusBadRequest,
					"count exceeds maximum 10000")
				return
			}
			count = v
		}

		results, err := deps.QueryAPI.ScanFromPosition(start, count)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			deps.Logger.Error("scan query", "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toEntryResponses(results))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 6) Difficulty endpoint (live)
// ─────────────────────────────────────────────────────────────────────────────

// NewDifficultyHandler creates GET /v1/admission/difficulty.
func NewDifficultyHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=30")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"difficulty":    deps.DiffController.CurrentDifficulty(),
			"hash_function": deps.DiffController.HashFunction(),
			"timestamp":     time.Now().UTC().Format(time.RFC3339),
		})
	}
}
