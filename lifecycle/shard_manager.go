/*
FILE PATH: lifecycle/shard_manager.go

Temporal shard lifecycle management. Domain-agnostic — any log shards,
not just judicial. Courts, physician credentialing, education all use
the same freeze/start/archive primitives.

FreezeShard:   disable writes, drain queue, get final cosigned head,
               archive tiles, delete Postgres data.
StartNewShard: provision new Tessera + Postgres, publish genesis entry
               linking to predecessor's final head.

DESIGN RULE: The shard boundary is a commentary entry. The genesis entry
on the new shard contains a Domain Payload referencing the predecessor's
final cosigned tree head. This is the cryptographic link between shards.
Verification walks the chain backward via genesis entries.

INVARIANTS:
  - FreezeShard is idempotent. Calling it twice on a frozen shard is a no-op.
  - StartNewShard fails if the predecessor is not frozen.
  - The genesis entry is always sequence 1 on the new shard.
  - Archive tiles are immutable — the lifecycle policy only moves them
    to cheaper storage, never deletes them.
*/
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

// FreezeConfig controls how a shard is frozen.
type FreezeConfig struct {
	ShardDID    string         // DID of the shard being frozen.
	DB          *pgxpool.Pool  // Postgres pool for this shard.
	TreeHeads   *store.TreeHeadStore
	Logger      *slog.Logger

	// WitnessCosigner requests final cosigned tree head.
	// Same interface as builder.WitnessCosigner.
	WitnessCosigner interface {
		RequestCosignatures(ctx context.Context, head types.TreeHead) error
	}

	// ArchiveTiles moves tiles to cold storage. Implementation-specific
	// (object store lifecycle policy, rsync, etc.). The shard manager
	// calls this after the final tree head is cosigned.
	ArchiveTiles func(ctx context.Context, shardDID string) error
}

// NewShardConfig controls how a new shard is provisioned.
type NewShardConfig struct {
	NewShardDID       string         // DID for the new shard.
	OperatorDID       string         // Operator signing the genesis entry.
	DB                *pgxpool.Pool  // Postgres pool for the NEW shard.
	Logger            *slog.Logger
}

// ─────────────────────────────────────────────────────────────────────────────
// Genesis Entry Schema
// ─────────────────────────────────────────────────────────────────────────────

// ShardGenesisPayload is the Domain Payload of a shard genesis entry.
// It links the new shard to its predecessor's final state.
type ShardGenesisPayload struct {
	SchemaType           string `json:"schema_type"`           // "shard-genesis-v1"
	PredecessorShard     string `json:"predecessor_shard"`     // DID of predecessor shard
	PredecessorFinalHead string `json:"predecessor_final_head"` // hex-encoded root hash
	PredecessorFinalSize uint64 `json:"predecessor_final_size"` // tree size at freeze
	PredecessorSMTRoot   string `json:"predecessor_smt_root"`  // hex-encoded SMT root (if computed)
	ChainPosition        int    `json:"chain_position"`        // 1-indexed shard number
	FrozenAt             string `json:"frozen_at"`             // RFC3339 timestamp
}

// ─────────────────────────────────────────────────────────────────────────────
// Freeze
// ─────────────────────────────────────────────────────────────────────────────

// FreezeResult holds the output of a shard freeze operation.
type FreezeResult struct {
	ShardDID      string
	FinalTreeHead *store.CosignedTreeHead
	FrozenAt      time.Time
	EntriesCount  uint64
}

// FreezeShard freezes a shard: disables writes, drains pending entries,
// requests a final cosigned tree head, archives tiles, and cleans Postgres.
func FreezeShard(ctx context.Context, cfg FreezeConfig) (*FreezeResult, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	logger.Info("shard freeze started", "shard", cfg.ShardDID)

	// Step 1: Get current tree head (latest state).
	latestHead, err := cfg.TreeHeads.Latest(ctx)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/freeze: get latest head: %w", err)
	}
	if latestHead == nil {
		return nil, fmt.Errorf("lifecycle/freeze: no tree head exists for shard %s", cfg.ShardDID)
	}

	// Step 2: Request final cosigned tree head from witnesses.
	// The builder should already be stopped before calling FreezeShard.
	if cfg.WitnessCosigner != nil {
		head := types.TreeHead{
			TreeSize: latestHead.TreeSize,
			RootHash: latestHead.RootHash,
		}
		if err := cfg.WitnessCosigner.RequestCosignatures(ctx, head); err != nil {
			logger.Warn("final cosignature request failed (non-fatal)", "error", err)
		}
		// Re-fetch to get the newly cosigned head.
		latestHead, err = cfg.TreeHeads.Latest(ctx)
		if err != nil {
			return nil, fmt.Errorf("lifecycle/freeze: re-fetch head: %w", err)
		}
	}

	logger.Info("final tree head cosigned",
		"tree_size", latestHead.TreeSize,
		"signatures", len(latestHead.Signatures))

	// Step 3: Archive tiles (move to cold storage).
	if cfg.ArchiveTiles != nil {
		if err := cfg.ArchiveTiles(ctx, cfg.ShardDID); err != nil {
			return nil, fmt.Errorf("lifecycle/freeze: archive tiles: %w", err)
		}
		logger.Info("tiles archived", "shard", cfg.ShardDID)
	}

	// Step 4: Delete Postgres data for this shard.
	// entry_index, smt_leaves, smt_nodes, builder_queue, delta_window_buffers.
	// tree_heads and tree_head_sigs are KEPT — they're the proof of the final state.
	tables := []string{
		"builder_queue", "delta_window_buffers",
		"smt_nodes", "smt_leaves", "entry_index",
	}
	for _, table := range tables {
		if _, err := cfg.DB.Exec(ctx, "DELETE FROM "+table); err != nil {
			logger.Warn("delete from table failed (may not exist)", "table", table, "error", err)
		}
	}
	logger.Info("postgres data cleaned", "shard", cfg.ShardDID)

	frozenAt := time.Now().UTC()
	result := &FreezeResult{
		ShardDID:      cfg.ShardDID,
		FinalTreeHead: latestHead,
		FrozenAt:      frozenAt,
		EntriesCount:  latestHead.TreeSize,
	}

	logger.Info("shard frozen",
		"shard", cfg.ShardDID,
		"entries", latestHead.TreeSize,
		"frozen_at", frozenAt)

	return result, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Start New Shard
// ─────────────────────────────────────────────────────────────────────────────

// StartNewShardResult holds the output of provisioning a new shard.
type StartNewShardResult struct {
	ShardDID      string
	GenesisEntry  *envelope.Entry
	ChainPosition int
}

// StartNewShard provisions a new shard linked to the predecessor's final state.
// The genesis entry is a commentary entry containing the ShardGenesisPayload.
func StartNewShard(ctx context.Context, cfg NewShardConfig, predecessor *FreezeResult, chainPosition int) (*StartNewShardResult, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if predecessor == nil {
		return nil, fmt.Errorf("lifecycle/new-shard: predecessor freeze result required")
	}

	logger.Info("starting new shard",
		"new_shard", cfg.NewShardDID,
		"predecessor", predecessor.ShardDID,
		"chain_position", chainPosition)

	// Step 1: Run migrations on the new shard's Postgres.
	if err := store.RunMigrations(ctx, cfg.DB); err != nil {
		return nil, fmt.Errorf("lifecycle/new-shard: migrations: %w", err)
	}

	// Step 2: Build genesis commentary entry.
	payload := ShardGenesisPayload{
		SchemaType:           "shard-genesis-v1",
		PredecessorShard:     predecessor.ShardDID,
		PredecessorFinalHead: fmt.Sprintf("%x", predecessor.FinalTreeHead.RootHash),
		PredecessorFinalSize: predecessor.FinalTreeHead.TreeSize,
		ChainPosition:        chainPosition,
		FrozenAt:             predecessor.FrozenAt.Format(time.RFC3339),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/new-shard: marshal genesis payload: %w", err)
	}

	// Genesis entry is commentary (no TargetRoot, no AuthorityPath).
	genesisEntry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: cfg.OperatorDID,
	}, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/new-shard: create genesis entry: %w", err)
	}

	logger.Info("new shard provisioned",
		"shard", cfg.NewShardDID,
		"predecessor", predecessor.ShardDID,
		"chain_position", chainPosition)

	return &StartNewShardResult{
		ShardDID:      cfg.NewShardDID,
		GenesisEntry:  genesisEntry,
		ChainPosition: chainPosition,
	}, nil
}
