/*
FILE PATH: api/entries_read.go

Entry fetch-by-position endpoints for remote consumers (Phase 5 verifiers,
fraud proof replay, cross-operator chain walking).

Routes:
  GET /v1/entries/{sequence}          → single EntryResponse
  GET /v1/entries/batch?start=N&count=M → []EntryResponse (max 1000)

The operator only serves its own log (Decision 47). Cross-log fetching
is the caller's concern.

KEY ARCHITECTURAL DECISIONS:
  - Single entry uses EntryFetcher interface (PostgresEntryFetcher).
  - Batch uses QueryAPI.ScanFromPosition (store/indexes/scan.go).
  - ScanFromPosition signature: (startPos uint64, count int) — no ctx param.
  - Reuses toEntryResponses from queries.go for JSON serialization.
*/
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
)

// EntryFetcher fetches a single entry by log position.
// Satisfied by store.PostgresEntryFetcher (store/entries.go).
type EntryFetcher interface {
	Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error)
}

// EntryReadDeps holds dependencies for entry read handlers.
type EntryReadDeps struct {
	Fetcher  EntryFetcher
	QueryAPI *indexes.PostgresQueryAPI
	LogDID   string
	Logger   *slog.Logger
}

const maxBatchSize = 1000

// NewEntryBySequenceHandler creates GET /v1/entries/{sequence}.
func NewEntryBySequenceHandler(deps *EntryReadDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		seqStr := r.PathValue("sequence")
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid sequence number")
			return
		}

		pos := types.LogPosition{LogDID: deps.LogDID, Sequence: seq}
		entry, err := deps.Fetcher.Fetch(pos)
		if err != nil {
			deps.Logger.Error("entry fetch", "sequence", seq, "error", err)
			writeError(w, http.StatusInternalServerError, "fetch failed")
			return
		}
		if entry == nil {
			writeError(w, http.StatusNotFound, "entry not found")
			return
		}

		responses := toEntryResponses([]types.EntryWithMetadata{*entry})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses[0])
	}
}

// NewEntryBatchHandler creates GET /v1/entries/batch?start=N&count=M.
func NewEntryBatchHandler(deps *EntryReadDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startStr := r.URL.Query().Get("start")
		countStr := r.URL.Query().Get("count")
		if startStr == "" || countStr == "" {
			writeError(w, http.StatusBadRequest, "start and count parameters required")
			return
		}

		start, err := strconv.ParseUint(startStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid start parameter")
			return
		}
		count, err := strconv.ParseUint(countStr, 10, 64)
		if err != nil || count == 0 {
			writeError(w, http.StatusBadRequest, "invalid count parameter")
			return
		}
		if count > maxBatchSize {
			count = maxBatchSize
		}

		// ScanFromPosition(startPos uint64, count int) — no context param.
		// See store/indexes/scan.go.
		entries, err := deps.QueryAPI.ScanFromPosition(start, int(count))
		if err != nil {
			deps.Logger.Error("batch entry fetch", "start", start, "count", count, "error", err)
			writeError(w, http.StatusInternalServerError, "batch fetch failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toEntryResponses(entries))
	}
}
