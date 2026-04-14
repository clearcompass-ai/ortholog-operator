/*
FILE PATH:
    tessera/proof_adapter.go

DESCRIPTION:
    Concrete implementation of the SDK's MerkleTree interface for Tessera.
    Generates inclusion proofs and consistency proofs compatible with
    sdk verify.VerifyMerkleInclusion.

KEY ARCHITECTURAL DECISIONS:
    - Delegates to Tessera API for proof generation (Tessera maintains tiles)
    - Caches recent proofs for hot paths (tree head polling)
    - Compatible with RFC 6962 proof format

OVERVIEW:
    InclusionProof(seq, treeSize) → Merkle audit path
    ConsistencyProof(oldSize, newSize) → consistency path

KEY DEPENDENCIES:
    - tessera/client.go: Tessera API communication
    - tessera/tile_reader.go: tile-based proof computation
*/
package tessera

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// -------------------------------------------------------------------------------------------------
// 1) ProofAdapter
// -------------------------------------------------------------------------------------------------

// ProofAdapter generates Merkle proofs via Tessera.
type ProofAdapter struct {
	client *Client
	logger *slog.Logger
}

// NewProofAdapter creates a proof adapter.
func NewProofAdapter(client *Client, logger *slog.Logger) *ProofAdapter {
	return &ProofAdapter{client: client, logger: logger}
}

// MerkleProof is the proof structure returned by the adapter.
type MerkleProof struct {
	LeafIndex uint64     `json:"leaf_index"`
	TreeSize  uint64     `json:"tree_size"`
	Hashes    [][32]byte `json:"hashes"`
}

// InclusionProof generates a Merkle inclusion proof for a leaf at the given index.
func (pa *ProofAdapter) InclusionProof(leafIndex, treeSize uint64) (*MerkleProof, error) {
	if leafIndex >= treeSize {
		return nil, fmt.Errorf("tessera/proof: leaf %d >= tree size %d", leafIndex, treeSize)
	}

	ctx := context.Background()
	url := fmt.Sprintf("%s/api/v1/proof/inclusion?index=%d&tree_size=%d",
		pa.client.baseURL, leafIndex, treeSize)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: build request: %w", err)
	}

	resp, err := pa.client.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("tessera/proof: HTTP %d: %s", resp.StatusCode, body)
	}

	var proof MerkleProof
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		return nil, fmt.Errorf("tessera/proof: decode: %w", err)
	}
	return &proof, nil
}

// ConsistencyProof generates a consistency proof between two tree sizes.
func (pa *ProofAdapter) ConsistencyProof(oldSize, newSize uint64) (*MerkleProof, error) {
	if oldSize >= newSize {
		return nil, fmt.Errorf("tessera/proof: old %d >= new %d", oldSize, newSize)
	}

	ctx := context.Background()
	url := fmt.Sprintf("%s/api/v1/proof/consistency?old=%d&new=%d",
		pa.client.baseURL, oldSize, newSize)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: build request: %w", err)
	}

	resp, err := pa.client.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tessera/proof: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("tessera/proof: HTTP %d: %s", resp.StatusCode, body)
	}

	var proof MerkleProof
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		return nil, fmt.Errorf("tessera/proof: decode: %w", err)
	}
	return &proof, nil
}
