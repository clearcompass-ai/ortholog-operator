/*
FILE PATH: tessera/client.go

Tessera low-level API client. Communicates with the Tessera transparency log
to append leaves and retrieve tree heads. Internal to the tessera package —
the builder interacts only with TesseraAdapter (proof_adapter.go).

KEY ARCHITECTURAL DECISIONS:
  - HTTP client to Tessera service (separate process/container).
  - Append is idempotent: same leaf hash → same position.
  - TreeHead returns root hash + tree size.
*/
package tessera

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

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

// AppendLeaf submits full wire bytes (canonical + sig_envelope) to the Merkle
// tree. Tessera computes RFC6962.HashLeaf(data) internally. Returns assigned index.
func (c *Client) AppendLeaf(ctx context.Context, data []byte) (uint64, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/add", bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("tessera/client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

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
func (c *Client) TreeHead(ctx context.Context) (types.TreeHead, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/v1/tree/head", nil)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("tessera/client: build request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("tessera/client: request: %w", err)
	}
	defer resp.Body.Close()

	var raw struct {
		TreeSize uint64 `json:"tree_size"`
		RootHash string `json:"root_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return types.TreeHead{}, fmt.Errorf("tessera/client: decode: %w", err)
	}

	var head types.TreeHead
	head.TreeSize = raw.TreeSize
	rootBytes, err := hex.DecodeString(raw.RootHash)
	if err == nil && len(rootBytes) == 32 {
		copy(head.RootHash[:], rootBytes)
	}
	return head, nil
}
