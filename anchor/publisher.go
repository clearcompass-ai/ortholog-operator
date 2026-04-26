/*
FILE PATH: anchor/publisher.go

Periodic anchor entry publisher. Creates commentary entries containing tree
head references, submitting them to the parent log's admission API.
Decision 44: anchors are standard entries, no special handling.

KEY ARCHITECTURAL DECISIONS:
  - Commentary entries: Target_Root=null, Authority_Path=null → zero SMT impact.
  - Destination-bound (SDK v0.3.0+): anchor entries are published to THIS log,
    so Destination = LogDID. NewEntry rejects empty destination at write time.
  - Domain Payload: source_log_did, tree_head_ref (SHA-256), tree_size, timestamp.
  - Submits to the local operator's admission pipeline via submitFn.
  - Configurable interval: default 1 hour.

SDK ALIGNMENT (v0.3.0):
  - envelope.NewEntry requires Destination (via ValidateDestination). Threading
    LogDID through PublisherConfig is the minimum invasive change to satisfy
    this while keeping the handler signature stable.
  - tree_head_ref uses stdlib crypto/sha256 (arbitrary-bytes hashing of a
    remote HTTP body). envelope.EntryIdentity would be wrong — it's reserved
    for Entry-shaped input producing Tessera dedup keys.
*/
package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// PublisherConfig configures the anchor publisher.
type PublisherConfig struct {
	OperatorDID   string
	LogDID        string // NEW (v0.3.0): destination-binding for self-published anchors.
	Interval      time.Duration
	AnchorSources []AnchorSource
}

// AnchorSource is a remote log to anchor.
type AnchorSource struct {
	LogDID      string
	EndpointURL string // Base URL with /v1/tree/head
}

// MerkleHeadProvider returns the current Merkle tree head.
type MerkleHeadProvider interface {
	Head() (types.TreeHead, error)
}

// Publisher periodically anchors remote tree heads to the local log.
type Publisher struct {
	cfg    PublisherConfig
	merkle MerkleHeadProvider
	// submitFn submits a signed entry to the local admission pipeline.
	submitFn func(entry *envelope.Entry) error
	client   *http.Client
	logger   *slog.Logger
}

// NewPublisher creates an anchor publisher. LogDID in cfg MUST be non-empty —
// the SDK's NewEntry will reject anchor commentary construction otherwise.
func NewPublisher(
	cfg PublisherConfig,
	merkle MerkleHeadProvider,
	submitFn func(entry *envelope.Entry) error,
	logger *slog.Logger,
) *Publisher {
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Hour
	}
	return &Publisher{
		cfg:      cfg,
		merkle:   merkle,
		submitFn: submitFn,
		client:   &http.Client{Timeout: 30 * time.Second},
		logger:   logger,
	}
}

// Run starts the anchor publishing loop.
func (p *Publisher) Run(ctx context.Context) {
	if len(p.cfg.AnchorSources) == 0 {
		p.logger.Info("anchor: no sources configured, exiting")
		return
	}

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.publishAll(ctx)
		}
	}
}

func (p *Publisher) publishAll(ctx context.Context) {
	for _, source := range p.cfg.AnchorSources {
		if err := p.publishOne(ctx, source); err != nil {
			p.logger.Warn("anchor: publish failed",
				"source_log", source.LogDID, "error", err)
		}
	}
}

func (p *Publisher) publishOne(ctx context.Context, source AnchorSource) error {
	// Fetch remote tree head.
	req, err := http.NewRequestWithContext(ctx, "GET", source.EndpointURL+"/v1/tree/head", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch tree head: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Build anchor payload. tree_head_ref is a plain SHA-256 of the remote
	// HTTP body — arbitrary bytes, NOT an Entry. envelope.EntryIdentity
	// would be wrong here (it's only correct for Entry-shaped input,
	// producing the Tessera dedup key). stdlib crypto/sha256 is the
	// idiomatic primitive for opaque-bytes hashing.
	treeHeadRef := sha256.Sum256(body)
	payload, _ := json.Marshal(map[string]any{
		"anchor_type":    "tree_head_ref",
		"source_log_did": source.LogDID,
		"tree_head_ref":  fmt.Sprintf("%x", treeHeadRef[:]),
		"anchored_at":    time.Now().UTC().Format(time.RFC3339),
	})

	// Build commentary entry (Decision 44: standard entry, no special handling).
	// Destination = LogDID (the anchor lands in THIS operator's log).
	entry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID:   p.cfg.OperatorDID,
		Destination: p.cfg.LogDID, // v0.3.0 destination-binding requirement.
		EventTime:   time.Now().UTC().Unix(),
		// Target_Root=nil, Authority_Path=nil → commentary.
	}, payload)
	if err != nil {
		return fmt.Errorf("build entry: %w", err)
	}

	// Submit through local admission pipeline.
	if p.submitFn != nil {
		if err := p.submitFn(entry); err != nil {
			return fmt.Errorf("submit anchor: %w", err)
		}
	}

	p.logger.Info("anchor published",
		"source_log", source.LogDID,
		"tree_head_ref", fmt.Sprintf("%x", treeHeadRef[:8]),
	)
	return nil
}

// SubmitViaHTTP creates a submitFn that POSTs signed entry bytes to a URL.
func SubmitViaHTTP(targetURL string) func(entry *envelope.Entry) error {
	client := &http.Client{Timeout: 30 * time.Second}
	return func(entry *envelope.Entry) error {
		canonical := envelope.Serialize(entry)
		// In production: sign canonical bytes, append signature envelope.
		// For now: submit raw canonical (the local operator would need to
		// accept self-submissions, or use a pre-signed path).
		resp, err := client.Post(targetURL+"/v1/entries", "application/octet-stream",
			bytes.NewReader(canonical))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
		}
		return nil
	}
}
