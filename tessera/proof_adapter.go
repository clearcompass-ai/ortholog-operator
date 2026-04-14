/*
FILE PATH: tessera/proof_adapter.go

TesseraAdapter wraps the Tessera client and implements the sdk smt.MerkleTree
interface. The builder depends only on the interface — swappable backend.

SDK smt.MerkleTree methods:
  - AppendLeaf(hash [32]byte) → (uint64, error)
  - InclusionProof(position, treeSize uint64) → (*MerkleProof, error)
  - Head() → (TreeHead, error)

Additional concrete method (NOT in sdk interface):
  - ConsistencyProof(oldSize, newSize uint64) → (any, error)
    Used by api/tree.go and witnesses. Not needed by the builder.

KEY ARCHITECTURAL DECISIONS:
  - Builder calls only interface methods (AppendLeaf, InclusionProof, Head).
  - ConsistencyProof is on the concrete type — HTTP handler takes *TesseraAdapter.
  - Proof structures returned as generic types for JSON serialization.
*/
package tessera

import (
	"context"
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

// AppendLeaf appends an entry hash to the Merkle tree. Returns tree position.
func (a *TesseraAdapter) AppendLeaf(hash [32]byte) (uint64, error) {
	ctx := context.TODO()
	return a.client.AppendLeaf(ctx, hash)
}

// InclusionProof generates a Merkle inclusion proof for a leaf.
func (a *TesseraAdapter) InclusionProof(position, treeSize uint64) (any, error) {
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

// Head returns the current Merkle tree head.
func (a *TesseraAdapter) Head() (types.TreeHead, error) {
	ctx := context.TODO()
	return a.client.TreeHead(ctx)
}

// ─── Additional concrete method (NOT in sdk interface) ─────────────────────

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
