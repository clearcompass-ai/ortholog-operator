/*
FILE PATH:
    api/queries.go

DESCRIPTION:
    All 5 query endpoints returning []EntryWithMetadata JSON. Plus the
    admission difficulty endpoint for Mode B submitters.

KEY ARCHITECTURAL DECISIONS:
    - All query results as JSON arrays (empty array if no results, never null)
    - Scan endpoint enforces max 10000 per request
    - Position parameters as hex-encoded bytes in URL path

OVERVIEW:
    /cosignature_of/:pos, /target_root/:pos, /schema_ref/:pos → by position
    /signer_did/:did → by DID string
    /scan?start=&count= → sequential iteration
    /admission/difficulty → current difficulty for Mode B

KEY DEPENDENCIES:
    - store/indexes/: all 5 index implementations
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
)

// -------------------------------------------------------------------------------------------------
// 1) Query Dependencies
// -------------------------------------------------------------------------------------------------

// QueryDeps holds dependencies for query handlers.
type QueryDeps struct {
	CosigIdx    *indexes.CosignatureOfIndex
	TargetIdx   *indexes.TargetRootIndex
	SignerIdx   *indexes.SignerDIDIndex
	SchemaIdx   *indexes.SchemaRefIndex
	ScanIdx     *indexes.ScanIndex
	Difficulty  uint32
	HashFunc    string
	Logger      *slog.Logger
}

// -------------------------------------------------------------------------------------------------
// 2) Position-based queries
// -------------------------------------------------------------------------------------------------

// NewQueryCosignatureOfHandler creates GET /v1/query/cosignature_of/{pos}.
func NewQueryCosignatureOfHandler(deps *QueryDeps) http.HandlerFunc {
	return positionQueryHandler(func(posBytes []byte, r *http.Request) (any, error) {
		return deps.CosigIdx.Query(r.Context(), posBytes)
	}, deps.Logger)
}

// NewQueryTargetRootHandler creates GET /v1/query/target_root/{pos}.
func NewQueryTargetRootHandler(deps *QueryDeps) http.HandlerFunc {
	return positionQueryHandler(func(posBytes []byte, r *http.Request) (any, error) {
		return deps.TargetIdx.Query(r.Context(), posBytes)
	}, deps.Logger)
}

// NewQuerySchemaRefHandler creates GET /v1/query/schema_ref/{pos}.
func NewQuerySchemaRefHandler(deps *QueryDeps) http.HandlerFunc {
	return positionQueryHandler(func(posBytes []byte, r *http.Request) (any, error) {
		return deps.SchemaIdx.Query(r.Context(), posBytes)
	}, deps.Logger)
}

func positionQueryHandler(fn func([]byte, *http.Request) (any, error), logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		posHex := r.PathValue("pos")
		posBytes, err := hex.DecodeString(posHex)
		if err != nil || len(posBytes) == 0 {
			writeError(w, http.StatusBadRequest, "pos must be hex-encoded bytes")
			return
		}
		results, err := fn(posBytes, r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "query failed")
			logger.Error("query", "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Signer DID query
// -------------------------------------------------------------------------------------------------

// NewQuerySignerDIDHandler creates GET /v1/query/signer_did/{did}.
func NewQuerySignerDIDHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		did := r.PathValue("did")
		if did == "" {
			writeError(w, http.StatusBadRequest, "did parameter required")
			return
		}
		results, err := deps.SignerIdx.Query(r.Context(), did)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "signer query failed")
			deps.Logger.Error("signer_did query", "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Scan query
// -------------------------------------------------------------------------------------------------

// NewQueryScanHandler creates GET /v1/query/scan?start=&count=.
func NewQueryScanHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startStr := r.URL.Query().Get("start")
		countStr := r.URL.Query().Get("count")

		start := uint64(1) // Default: from beginning.
		if startStr != "" {
			v, err := strconv.ParseUint(startStr, 10, 64)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid start parameter")
				return
			}
			start = v
		}

		count := 100 // Default page size.
		if countStr != "" {
			v, err := strconv.Atoi(countStr)
			if err != nil || v < 1 {
				writeError(w, http.StatusBadRequest, "invalid count parameter")
				return
			}
			count = v
		}

		results, err := deps.ScanIdx.Scan(r.Context(), start, count)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			deps.Logger.Error("scan query", "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Difficulty endpoint
// -------------------------------------------------------------------------------------------------

// NewDifficultyHandler creates GET /v1/admission/difficulty.
func NewDifficultyHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"difficulty":    deps.Difficulty,
			"hash_function": deps.HashFunc,
			"timestamp":     time.Now().UTC().Format(time.RFC3339),
		})
	}
}
