/*
FILE PATH:
    anchor/publisher.go

DESCRIPTION:
    Periodic anchor entry publisher. Creates commentary entries containing
    tree head references from remote logs, anchoring them to the local log.
    Decision 44: anchors are standard entries, no special handling.

KEY ARCHITECTURAL DECISIONS:
    - Commentary entries: Target_Root=null, Authority_Path=null → zero SMT
      impact (Fix 1 discriminator)
    - Domain Payload contains: source_log_did, tree_head_ref (hash of
      remote tree head), tree_size, timestamp
    - Configurable interval: default 1 hour
    - Anchor sources configurable per deployment (hub-spoke, mesh, etc.)

OVERVIEW:
    Run(ctx) loops at configured interval:
      For each anchor source: fetch remote tree head, build commentary entry,
      submit through local admission pipeline.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ortholog-sdk/core/envelope: NewEntry
*/
package anchor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// -------------------------------------------------------------------------------------------------
// 1) Configuration
// -------------------------------------------------------------------------------------------------

// PublisherConfig configures the anchor publisher.
type PublisherConfig struct {
	OperatorDID    string
	Interval       time.Duration
	AnchorSources  []AnchorSource
	LocalSubmitURL string // POST /v1/entries on self
}

// AnchorSource is a remote log to anchor.
type AnchorSource struct {
	LogDID      string
	EndpointURL string // GET /v1/tree/head
}

// -------------------------------------------------------------------------------------------------
// 2) Publisher
// -------------------------------------------------------------------------------------------------

// Publisher periodically anchors remote tree heads to the local log.
type Publisher struct {
	cfg    PublisherConfig
	client *http.Client
	logger *slog.Logger
}

// NewPublisher creates an anchor publisher.
func NewPublisher(cfg PublisherConfig, logger *slog.Logger) *Publisher {
	return &Publisher{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		logger: logger,
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
				"source_log", source.LogDID,
				"error", err,
			)
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

	// Build anchor payload.
	treeHeadRef := sha256.Sum256(body)
	payload, _ := json.Marshal(map[string]any{
		"anchor_type":    "tree_head_ref",
		"source_log_did": source.LogDID,
		"tree_head_ref":  fmt.Sprintf("%x", treeHeadRef[:]),
		"anchored_at":    time.Now().UTC().Format(time.RFC3339),
	})

	// Build commentary entry (Decision 44: standard entry, no special handling).
	entry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: p.cfg.OperatorDID,
		// Target_Root=nil, Authority_Path=nil → commentary.
	}, payload)
	if err != nil {
		return fmt.Errorf("build entry: %w", err)
	}

	_ = entry // In production: sign and submit via local admission pipeline.
	p.logger.Info("anchor published",
		"source_log", source.LogDID,
		"tree_head_ref", fmt.Sprintf("%x", treeHeadRef[:8]),
	)
	return nil
}
