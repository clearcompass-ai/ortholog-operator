/*
FILE PATH:
    api/tree.go

DESCRIPTION:
    Tree head distribution and Merkle proof endpoints. Serves cosigned
    tree heads, inclusion proofs, and consistency proofs via the Tessera
    proof adapter.

KEY ARCHITECTURAL DECISIONS:
    - Cache-Control + ETag on tree/head: clients poll efficiently
    - Inclusion proofs compatible with sdk verify.VerifyMerkleInclusion
    - Consistency proofs for witness append-only verification

OVERVIEW:
    GET /v1/tree/head → latest CosignedTreeHead JSON
    GET /v1/tree/inclusion/:seq → MerkleInclusionProof
    GET /v1/tree/consistency/:old/:new → ConsistencyProof

KEY DEPENDENCIES:
    - store/tree_heads.go: cosigned tree head persistence
    - tessera/proof_adapter.go: Merkle proof generation
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) Tree Head Handler
// -------------------------------------------------------------------------------------------------

// TreeDeps holds dependencies for tree handlers.
type TreeDeps struct {
	TreeHeadStore *store.TreeHeadStore
	ProofAdapter  *tessera.ProofAdapter
	Logger        *slog.Logger
}

// NewTreeHeadHandler creates GET /v1/tree/head.
func NewTreeHeadHandler(deps *TreeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		head, err := deps.TreeHeadStore.Latest(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to fetch tree head")
			deps.Logger.Error("tree head fetch", "error", err)
			return
		}
		if head == nil {
			writeError(w, http.StatusNotFound, "no cosigned tree head available")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, head.TreeSize))
		w.Header().Set("Cache-Control", "public, max-age=10")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size":    head.TreeSize,
			"root_hash":    hex.EncodeToString(head.RootHash[:]),
			"scheme_tag":   head.SchemeTag,
			"cosignatures": hex.EncodeToString(head.Cosignatures),
		})
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Inclusion Proof Handler
// -------------------------------------------------------------------------------------------------

// NewTreeInclusionHandler creates GET /v1/tree/inclusion/{seq}.
func NewTreeInclusionHandler(deps *TreeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		seqStr := r.PathValue("seq")
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid sequence number")
			return
		}

		head, err := deps.TreeHeadStore.Latest(r.Context())
		if err != nil || head == nil {
			writeError(w, http.StatusServiceUnavailable, "no tree head available")
			return
		}

		proof, err := deps.ProofAdapter.InclusionProof(seq, head.TreeSize)
		if err != nil {
			writeError(w, http.StatusNotFound, fmt.Sprintf("inclusion proof: %s", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Consistency Proof Handler
// -------------------------------------------------------------------------------------------------

// NewTreeConsistencyHandler creates GET /v1/tree/consistency/{old}/{new}.
func NewTreeConsistencyHandler(deps *TreeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		oldStr := r.PathValue("old")
		newStr := r.PathValue("new")
		oldSize, err1 := strconv.ParseUint(oldStr, 10, 64)
		newSize, err2 := strconv.ParseUint(newStr, 10, 64)
		if err1 != nil || err2 != nil {
			writeError(w, http.StatusBadRequest, "invalid tree sizes")
			return
		}
		if oldSize >= newSize {
			writeError(w, http.StatusBadRequest, "old size must be less than new size")
			return
		}

		proof, err := deps.ProofAdapter.ConsistencyProof(oldSize, newSize)
		if err != nil {
			writeError(w, http.StatusNotFound, fmt.Sprintf("consistency proof: %s", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}
