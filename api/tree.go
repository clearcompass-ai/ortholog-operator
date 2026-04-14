/*
FILE PATH: api/tree.go

Tree head distribution and Merkle proof endpoints. Serves cosigned tree heads,
inclusion proofs, and consistency proofs via the TesseraAdapter.

KEY ARCHITECTURAL DECISIONS:
  - Cache-Control: max-age=5 on tree/head (spec-compliant).
  - ETag: tree_size (monotonic) for conditional polling.
  - Inclusion proofs compatible with sdk verify.VerifyMerkleInclusion.
  - ConsistencyProver is a separate interface (not part of sdk MerkleTree).
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
)

// ConsistencyProver generates consistency proofs (concrete method on TesseraAdapter).
type ConsistencyProver interface {
	ConsistencyProof(oldSize, newSize uint64) (any, error)
}

// InclusionProver generates inclusion proofs.
type InclusionProver interface {
	InclusionProof(position, treeSize uint64) (any, error)
}

// TreeDeps holds dependencies for tree handlers.
type TreeDeps struct {
	TreeHeadStore *store.TreeHeadStore
	Inclusion     InclusionProver
	Consistency   ConsistencyProver
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
		w.Header().Set("Cache-Control", "public, max-age=5")

		// Build signatures array.
		sigs := make([]map[string]any, len(head.Signatures))
		for i, s := range head.Signatures {
			sigs[i] = map[string]any{
				"signer":    s.Signer,
				"sig_algo":  s.SigAlgo,
				"signature": hex.EncodeToString(s.Signature),
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size":  head.TreeSize,
			"root_hash":  hex.EncodeToString(head.RootHash[:]),
			"hash_algo":  head.HashAlgo,
			"signatures": sigs,
		})
	}
}

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

		if deps.Inclusion == nil {
			writeError(w, http.StatusServiceUnavailable, "inclusion proofs not available")
			return
		}

		proof, err := deps.Inclusion.InclusionProof(seq, head.TreeSize)
		if err != nil {
			writeError(w, http.StatusNotFound,
				fmt.Sprintf("inclusion proof: %s", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}

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

		if deps.Consistency == nil {
			writeError(w, http.StatusServiceUnavailable, "consistency proofs not available")
			return
		}

		proof, err := deps.Consistency.ConsistencyProof(oldSize, newSize)
		if err != nil {
			writeError(w, http.StatusNotFound,
				fmt.Sprintf("consistency proof: %s", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}
