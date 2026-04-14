/*
FILE PATH:
    tessera/client.go

DESCRIPTION:
    Tessera API client. Appends leaves to the transparency log's Merkle
    tree and retrieves tree heads. This is the bridge between the operator's
    entry storage and the append-only Merkle tree.

KEY ARCHITECTURAL DECISIONS:
    - HTTP client to Tessera service (separate process/container)
    - Append is idempotent: same leaf hash → same position
    - TreeHead returns Tessera's view of the tree (may lag operator)

OVERVIEW:
    AppendLeaf: sends canonical hash to Tessera for Merkle tree inclusion.
    TreeHead: retrieves current Merkle tree head from Tessera.

KEY DEPENDENCIES:
    - net/http: HTTP client
*/
package tessera

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// -------------------------------------------------------------------------------------------------
// 1) Client
// -------------------------------------------------------------------------------------------------

// ClientConfig configures the Tessera client.
type ClientConfig struct {
	BaseURL string
	Timeout time.Duration
}

// Client communicates with the Tessera transparency log.
type Client struct {
	baseURL string
	client  *http.Client
	logger  *slog.Logger
}

// NewClient creates a Tessera client.
func NewClient(cfg ClientConfig, logger *slog.Logger) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		client:  &http.Client{Timeout: cfg.Timeout},
		logger:  logger,
	}
}

// AppendLeaf submits a leaf hash to the Merkle tree. Returns the assigned index.
func (c *Client) AppendLeaf(ctx context.Context, leafHash [32]byte) (uint64, error) {
	body, _ := json.Marshal(map[string]any{"leaf_hash": leafHash})
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/add", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("tessera/client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("tessera/client: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("tessera/client: HTTP %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Index uint64 `json:"index"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("tessera/client: decode response: %w", err)
	}
	return result.Index, nil
}

// TreeHead retrieves the current Merkle tree head from Tessera.
func (c *Client) TreeHead(ctx context.Context) (uint64, [32]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/v1/tree/head", nil)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("tessera/client: build request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("tessera/client: request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		TreeSize uint64   `json:"tree_size"`
		RootHash [32]byte `json:"root_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, [32]byte{}, fmt.Errorf("tessera/client: decode: %w", err)
	}
	return result.TreeSize, result.RootHash, nil
}
