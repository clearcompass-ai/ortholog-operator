/*
FILE PATH: tessera/proof_adapter.go

TesseraAdapter wraps the Tessera client and implements the operator's
MerkleAppender interface. The builder depends only on the interface.

Operator MerkleAppender methods:
  - AppendLeaf(data []byte) → (uint64, error)  [full wire bytes]
  - Head() → (TreeHead, error)

Proof methods (concrete, not in sdk MerkleTree interface):
  - RawInclusionProof(position, treeSize uint64) → (any, error)
    JSON passthrough for api/tree.go HTTP endpoints.
  - TypedInclusionProof(position, treeSize uint64) → (*types.MerkleProof, error)
    Parsed into SDK type for Phase 4 cross-log verification via
    smt.VerifyMerkleInclusion. Satisfies the Phase 4 MerkleProver interface.
  - ConsistencyProof(oldSize, newSize uint64) → (any, error)
    Used by api/tree.go and witnesses. Not needed by the builder.

KEY ARCHITECTURAL DECISIONS:
  - Builder calls only interface methods (AppendLeaf, Head).
  - RawInclusionProof returns json.RawMessage for HTTP passthrough.
  - TypedInclusionProof parses Tessera's response into types.MerkleProof
    so the Phase 4 cross-log verifier can call smt.VerifyMerkleInclusion.
  - ConsistencyProof is on the concrete type — HTTP handler takes *TesseraAdapter.
*/
package tessera

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// TesseraAdapter implements sdk smt.MerkleTree via Tessera HTTP API.
type TesseraAdapter struct {
	client     *Client
	tileReader *TileReader
	logger     *slog.Logger
}

// NewTesseraAdapter creates an adapter wrapping the Tessera client.
func NewTesseraAdapter(client *Client, tileReader *TileReader, logger *slog.Logger) *TesseraAdapter {
	return &TesseraAdapter{
		client:     client,
		tileReader: tileReader,
		logger:     logger,
	}
}

// ─── sdk smt.MerkleTree interface ──────────────────────────────────────────

// AppendLeaf appends full wire bytes to the Merkle tree. Tessera computes
// RFC6962.HashLeaf(data) internally. Returns tree position.
func (a *TesseraAdapter) AppendLeaf(data []byte) (uint64, error) {
	ctx := context.TODO()
	return a.client.AppendLeaf(ctx, data)
}

// Head returns the current Merkle tree head.
func (a *TesseraAdapter) Head() (types.TreeHead, error) {
	ctx := context.TODO()
	return a.client.TreeHead(ctx)
}

// ─── Inclusion proofs ──────────────────────────────────────────────────────

// RawInclusionProof generates a Merkle inclusion proof and returns the raw
// Tessera JSON response. Used by api/tree.go for HTTP passthrough — the
// response is serialized directly to the client without parsing.
//
// This was previously named InclusionProof. Renamed to distinguish from
// TypedInclusionProof which parses into types.MerkleProof.
func (a *TesseraAdapter) RawInclusionProof(position, treeSize uint64) (any, error) {
	if position >= treeSize {
		return nil, fmt.Errorf("tessera/proof: leaf %d >= tree size %d", position, treeSize)
	}

	ctx := context.TODO()
	url := fmt.Sprintf("%s/api/v1/proof/inclusion?index=%d&tree_size=%d",
		a.client.baseURL, position, treeSize)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: build request: %w", err)
	}

	resp, err := a.client.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("tessera/proof: HTTP %d: %s", resp.StatusCode, body)
	}

	var proof json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		return nil, fmt.Errorf("tessera/proof: decode: %w", err)
	}
	return proof, nil
}

// TypedInclusionProof generates a Merkle inclusion proof parsed into the
// SDK's types.MerkleProof. Used by Phase 4 cross-log verifier which calls
// smt.VerifyMerkleInclusion(proof, rootHash).
//
// Satisfies the Phase 4 SDK's MerkleProver interface:
//
//	type MerkleProver interface {
//	    TypedInclusionProof(position, treeSize uint64) (*types.MerkleProof, error)
//	}
//
// Note: LeafHash is left zeroed — the cross-log verifier already has the
// entry bytes and computes the leaf hash itself before calling
// VerifyMerkleInclusion. Callers must set proof.LeafHash before verification.
func (a *TesseraAdapter) TypedInclusionProof(position, treeSize uint64) (*types.MerkleProof, error) {
	raw, err := a.RawInclusionProof(position, treeSize)
	if err != nil {
		return nil, err
	}

	// raw is json.RawMessage from Tessera's /api/v1/proof/inclusion.
	jsonBytes, ok := raw.(json.RawMessage)
	if !ok {
		return nil, fmt.Errorf("tessera/proof: unexpected type %T from RawInclusionProof", raw)
	}

	// Tessera response shape:
	//   { "leaf_index": N, "hashes": ["base64hash1", ...] }
	// The hashes array contains the sibling path from leaf to root,
	// each encoded as standard base64.
	var resp struct {
		LeafIndex uint64   `json:"leaf_index"`
		Hashes    []string `json:"hashes"`
	}
	if err := json.Unmarshal(jsonBytes, &resp); err != nil {
		return nil, fmt.Errorf("tessera/proof: parse inclusion response: %w", err)
	}

	siblings := make([][32]byte, len(resp.Hashes))
	for i, h := range resp.Hashes {
		decoded, decErr := base64.StdEncoding.DecodeString(h)
		if decErr != nil {
			// Try URL-safe base64 as fallback (some Tessera versions).
			decoded, decErr = base64.RawURLEncoding.DecodeString(h)
			if decErr != nil {
				return nil, fmt.Errorf("tessera/proof: decode sibling %d: %w", i, decErr)
			}
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("tessera/proof: sibling %d is %d bytes, want 32", i, len(decoded))
		}
		copy(siblings[i][:], decoded)
	}

	return &types.MerkleProof{
		LeafPosition: resp.LeafIndex,
		Siblings:     siblings,
		TreeSize:     treeSize,
		// LeafHash zeroed — caller sets it from entry bytes before verification.
	}, nil
}

// ─── Consistency proofs ────────────────────────────────────────────────────

// ConsistencyProof generates a consistency proof between two tree sizes.
// Used by api/tree.go and witnesses. The builder never calls this.
func (a *TesseraAdapter) ConsistencyProof(oldSize, newSize uint64) (any, error) {
	if oldSize >= newSize {
		return nil, fmt.Errorf("tessera/proof: old %d >= new %d", oldSize, newSize)
	}

	ctx := context.TODO()
	url := fmt.Sprintf("%s/api/v1/proof/consistency?old=%d&new=%d",
		a.client.baseURL, oldSize, newSize)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: build request: %w", err)
	}

	resp, err := a.client.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("tessera/proof: HTTP %d: %s", resp.StatusCode, body)
	}

	var proof json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		return nil, fmt.Errorf("tessera/proof: decode: %w", err)
	}
	return proof, nil
}
