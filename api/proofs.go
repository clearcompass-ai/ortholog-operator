/*
FILE PATH:
    api/proofs.go

DESCRIPTION:
    SMT proof endpoints. Single membership/non-membership proofs, batch
    multiproofs with SDK-D13 canonical ordering, and current root query.

KEY ARCHITECTURAL DECISIONS:
    - Proof generation uses sdk smt.Tree directly (same instance as builder)
    - Batch proof uses SDK-D13 canonical key ordering
    - Root endpoint includes latest commitment reference for auditability

OVERVIEW:
    GET /v1/smt/proof/:key → single proof (membership or non-membership)
    POST /v1/smt/batch_proof → batch proof for multiple keys
    GET /v1/smt/root → current SMT root hash

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ortholog-sdk/core/smt: proof generation
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
)

// -------------------------------------------------------------------------------------------------
// 1) SMT Proof Dependencies
// -------------------------------------------------------------------------------------------------

// SMTDeps holds dependencies for SMT proof handlers.
type SMTDeps struct {
	Tree   *smt.Tree
	Logger *slog.Logger
}

// -------------------------------------------------------------------------------------------------
// 2) Single Proof Handler
// -------------------------------------------------------------------------------------------------

// NewSMTProofHandler creates GET /v1/smt/proof/{key}.
func NewSMTProofHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keyHex := r.PathValue("key")
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil || len(keyBytes) != 32 {
			writeError(w, http.StatusBadRequest, "key must be 64 hex characters (32 bytes)")
			return
		}

		var key [32]byte
		copy(key[:], keyBytes)

		// Try membership first.
		leaf, _ := deps.Tree.GetLeaf(key)
		if leaf != nil {
			proof, err := deps.Tree.GenerateMembershipProof(key)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "proof generation failed")
				deps.Logger.Error("membership proof", "error", err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":  "membership",
				"proof": proof,
			})
			return
		}

		// Non-membership.
		proof, err := deps.Tree.GenerateNonMembershipProof(key)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "non-membership proof generation failed")
			deps.Logger.Error("non-membership proof", "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":  "non_membership",
			"proof": proof,
		})
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Batch Proof Handler
// -------------------------------------------------------------------------------------------------

// NewSMTBatchProofHandler creates POST /v1/smt/batch_proof.
func NewSMTBatchProofHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read body")
			return
		}

		var req struct {
			Keys []string `json:"keys"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if len(req.Keys) == 0 || len(req.Keys) > 1000 {
			writeError(w, http.StatusBadRequest, "keys count must be 1-1000")
			return
		}

		keys := make([][32]byte, len(req.Keys))
		for i, kHex := range req.Keys {
			kb, err := hex.DecodeString(kHex)
			if err != nil || len(kb) != 32 {
				writeError(w, http.StatusBadRequest, "each key must be 64 hex characters")
				return
			}
			copy(keys[i][:], kb)
		}

		proof, err := deps.Tree.GenerateBatchProof(keys)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "batch proof generation failed")
			deps.Logger.Error("batch proof", "error", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Root Handler
// -------------------------------------------------------------------------------------------------

// NewSMTRootHandler creates GET /v1/smt/root.
func NewSMTRootHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		root, err := deps.Tree.Root()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "root computation failed")
			deps.Logger.Error("smt root", "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"root": hex.EncodeToString(root[:]),
		})
	}
}
