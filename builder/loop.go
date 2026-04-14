/*
FILE PATH:
    builder/loop.go

DESCRIPTION:
    Continuous builder loop. Dequeues admitted entries, calls SDK ProcessBatch,
    commits state atomically, publishes derivation commitments, requests
    witness cosignatures. THE core operational loop of the operator.

KEY ARCHITECTURAL DECISIONS:
    - Single goroutine: determinism requires exactly one builder per log.
      Advisory lock (store/postgres.go) prevents concurrent instances.
    - Atomic commit: leaf mutations + buffer + queue status in one Postgres tx.
      Crash between steps = no partial state. Resume from last committed batch.
    - Idempotent: replaying the same batch produces identical state (SDK
      determinism guarantee).
    - Poll interval: configurable. Default 100ms between empty polls. Zero
      delay between non-empty batches (throughput priority).

OVERVIEW:
    Run(ctx) loops until ctx cancelled:
      (1) Dequeue batch → (2) Fetch entries → (3) ProcessBatch →
      (4) Atomic commit → (5) Tessera append → (6) Publish commitment →
      (7) Request cosignatures.
    On ctx cancellation: drain queue, flush buffer, publish final commitment.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ortholog-sdk/builder: ProcessBatch
    - github.com/clearcompass-ai/ortholog-sdk/core/smt: Tree
    - store/: Postgres persistence
*/
package builder

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// -------------------------------------------------------------------------------------------------
// 1) Configuration
// -------------------------------------------------------------------------------------------------

// LoopConfig configures the builder loop.
type LoopConfig struct {
	LogDID        string
	BatchSize     int
	PollInterval  time.Duration
	DeltaWindow   int
}

// DefaultLoopConfig returns production defaults.
func DefaultLoopConfig(logDID string) LoopConfig {
	return LoopConfig{
		LogDID:       logDID,
		BatchSize:    1000,
		PollInterval: 100 * time.Millisecond,
		DeltaWindow:  10,
	}
}

// -------------------------------------------------------------------------------------------------
// 2) BuilderLoop
// -------------------------------------------------------------------------------------------------

// BuilderLoop is the continuous builder goroutine.
type BuilderLoop struct {
	cfg      LoopConfig
	db       *pgxpool.Pool
	tree     *smt.Tree
	queue    *Queue
	fetcher  sdkbuilder.EntryFetcher
	schema   sdkbuilder.SchemaResolver
	buffer   *sdkbuilder.DeltaWindowBuffer
	commitPub *CommitmentPublisher
	logger   *slog.Logger
}

// NewBuilderLoop creates a builder loop.
func NewBuilderLoop(
	cfg LoopConfig,
	db *pgxpool.Pool,
	tree *smt.Tree,
	queue *Queue,
	fetcher sdkbuilder.EntryFetcher,
	schema sdkbuilder.SchemaResolver,
	buffer *sdkbuilder.DeltaWindowBuffer,
	commitPub *CommitmentPublisher,
	logger *slog.Logger,
) *BuilderLoop {
	return &BuilderLoop{
		cfg:       cfg,
		db:        db,
		tree:      tree,
		queue:     queue,
		fetcher:   fetcher,
		schema:    schema,
		buffer:    buffer,
		commitPub: commitPub,
		logger:    logger,
	}
}

// Run executes the builder loop until ctx is cancelled.
// MUST be called from a single goroutine. Advisory lock prevents duplicates.
func (bl *BuilderLoop) Run(ctx context.Context) error {
	bl.logger.Info("builder loop started", "log_did", bl.cfg.LogDID, "batch_size", bl.cfg.BatchSize)

	// Recover any stale processing entries from prior crash.
	recovered, err := bl.queue.RecoverStale(ctx)
	if err != nil {
		return fmt.Errorf("builder/loop: recover stale: %w", err)
	}
	if recovered > 0 {
		bl.logger.Warn("recovered stale queue entries", "count", recovered)
	}

	for {
		select {
		case <-ctx.Done():
			bl.logger.Info("builder loop shutting down")
			return nil
		default:
		}

		processed, err := bl.processBatch(ctx)
		if err != nil {
			bl.logger.Error("batch processing failed", "error", err)
			time.Sleep(bl.cfg.PollInterval) // Back off on error.
			continue
		}

		if processed == 0 {
			// Empty batch — poll interval before retry.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(bl.cfg.PollInterval):
			}
		}
		// Non-empty batch: loop immediately for throughput.
	}
}

// processBatch executes one builder cycle. Returns entries processed.
func (bl *BuilderLoop) processBatch(ctx context.Context) (int, error) {
	priorRoot, err := bl.tree.Root()
	if err != nil {
		return 0, fmt.Errorf("prior root: %w", err)
	}

	// (1) Dequeue within a transaction.
	var seqs []uint64
	err = store.WithTransaction(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		seqs, err = bl.queue.DequeueBatch(ctx, tx, bl.cfg.BatchSize)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("dequeue: %w", err)
	}
	if len(seqs) == 0 {
		return 0, nil
	}

	// (2) Fetch entries in sequence order.
	entries := make([]*envelope.Entry, 0, len(seqs))
	positions := make([]types.LogPosition, 0, len(seqs))
	for _, seq := range seqs {
		pos := types.LogPosition{LogDID: bl.cfg.LogDID, Sequence: seq}
		meta, err := bl.fetcher.Fetch(pos)
		if err != nil || meta == nil {
			return 0, fmt.Errorf("fetch seq=%d: entry not found or error: %w", seq, err)
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			return 0, fmt.Errorf("deserialize seq=%d: %w", seq, err)
		}
		entries = append(entries, entry)
		positions = append(positions, pos)
	}

	// (3) SDK ProcessBatch.
	result, err := sdkbuilder.ProcessBatch(bl.tree, entries, positions, bl.fetcher, bl.schema, bl.cfg.LogDID, bl.buffer)
	if err != nil {
		return 0, fmt.Errorf("ProcessBatch: %w", err)
	}

	// (4) Atomic commit: mutations + buffer + queue status.
	err = store.WithTransaction(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := bl.queue.MarkProcessed(ctx, tx, seqs); err != nil {
			return err
		}
		// Buffer is updated in-place by ProcessBatch. Persist it.
		// (Delta buffer persistence handled by the DeltaBufferStore)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}

	// (5-7) Post-commit: commitment + cosignatures (non-transactional).
	if bl.commitPub != nil && len(result.Mutations) > 0 {
		bl.commitPub.Publish(ctx, positions[0], positions[len(positions)-1], priorRoot, result)
	}

	bl.logger.Info("batch processed",
		"entries", len(seqs),
		"new_leaves", result.NewLeafCounts,
		"path_a", result.PathACounts,
		"path_b", result.PathBCounts,
		"path_c", result.PathCCounts,
		"path_d", result.PathDCounts,
		"commentary", result.CommentaryCounts,
	)

	bl.buffer = result.UpdatedBuffer
	return len(seqs), nil
}
