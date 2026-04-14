/*
FILE PATH: api/commitments.go

Derivation commitment query endpoint.
  GET /v1/commitments?seq=N → commitment whose range covers sequence N
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

type CommitmentDeps struct {
	CommitmentStore *store.CommitmentStore
	Logger          *slog.Logger
}

func NewCommitmentQueryHandler(deps *CommitmentDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		seqStr := r.URL.Query().Get("seq")
		if seqStr == "" {
			writeError(w, http.StatusBadRequest, "seq parameter required")
			return
		}
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid seq parameter")
			return
		}

		row, err := deps.CommitmentStore.QueryBySequence(r.Context(), seq)
		if err != nil {
			deps.Logger.Error("commitment query", "seq", seq, "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		if row == nil {
			writeError(w, http.StatusNotFound, "no commitment covers this sequence")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"range_start_seq": row.RangeStartSeq,
			"range_end_seq":   row.RangeEndSeq,
			"prior_smt_root":  hex.EncodeToString(row.PriorSMTRoot[:]),
			"post_smt_root":   hex.EncodeToString(row.PostSMTRoot[:]),
			"mutations_json":  json.RawMessage(row.MutationsJSON),
			"commentary_seq":  row.CommentarySeq,
			"created_at":      row.CreatedAt,
		})
	}
}
