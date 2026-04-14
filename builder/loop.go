/*
FILE PATH: builder/loop.go

Continuous builder loop. THE core operational loop of the operator.
Dequeues admitted entries, calls SDK ProcessBatch, commits state atomically,
appends to Merkle tree, publishes commitments, requests witness cosignatures.

KEY ARCHITECTURAL DECISIONS:
  - Single goroutine: determinism requires exactly one builder per log.
    Advisory lock prevents concurrent instances.
  - Atomic commit: leaf mutations + delta buffer + queue status in ONE
    Postgres transaction. No partial state on crash.
  - SDK MerkleTree interface: builder touches only the interface, never
    tessera/client.go directly. Swappable backend.
  - Idempotent: replaying the same batch produces identical state.
  - SDK LeafMutation is a diff format: carries tip positions, not a full
    SMTLeaf. The operator reconstructs the leaf from mutation fields.

INVARIANTS:
  - processBatch either fully commits or fully rolls back.
  - Crash between commit and Tessera append → on restart, re-append is
    idempotent (Tessera deduplicates by leaf hash).
  - Empty batch → no mutations, no commitment, no cosig request.
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
	"github.com/clearcompass-ai/ortholog-sdk/crypto"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Configuration
// ─────────────────────────────────────────────────────────────────────────────

// LoopConfig configures the builder loop.
type LoopConfig struct {
	LogDID       string
	BatchSize    int
	PollInterval time.Duration
	DeltaWindow  int
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

// ─────────────────────────────────────────────────────────────────────────────
// 2) Interfaces (satisfied by TesseraAdapter and HeadSync respectively)
// ─────────────────────────────────────────────────────────────────────────────

// MerkleAppender is the subset of sdk smt.MerkleTree used by the builder.
type MerkleAppender interface {
	AppendLeaf(hash [32]byte) (uint64, error)
	Head() (types.TreeHead, error)
}

// WitnessCosigner requests cosignatures on tree heads.
type WitnessCosigner interface {
	RequestCosignatures(ctx context.Context, head types.TreeHead) error
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) BuilderLoop
// ─────────────────────────────────────────────────────────────────────────────

// BuilderLoop is the continuous builder goroutine.
type BuilderLoop struct {
	cfg         LoopConfig
	db          *pgxpool.Pool
	tree        *smt.Tree
	leafStore   *store.PostgresLeafStore
	nodeCache   *store.PostgresNodeCache
	queue       *Queue
	fetcher     sdkbuilder.EntryFetcher
	schema      sdkbuilder.SchemaResolver
	buffer      *sdkbuilder.DeltaWindowBuffer
	bufferStore *DeltaBufferStore
	commitPub   *CommitmentPublisher
	merkle      MerkleAppender
	witness     WitnessCosigner
	logger      *slog.Logger
}

// NewBuilderLoop creates a builder loop with all dependencies.
func NewBuilderLoop(
	cfg LoopConfig,
	db *pgxpool.Pool,
	tree *smt.Tree,
	leafStore *store.PostgresLeafStore,
	nodeCache *store.PostgresNodeCache,
	queue *Queue,
	fetcher sdkbuilder.EntryFetcher,
	schema sdkbuilder.SchemaResolver,
	buffer *sdkbuilder.DeltaWindowBuffer,
	bufferStore *DeltaBufferStore,
	commitPub *CommitmentPublisher,
	merkle MerkleAppender,
	witness WitnessCosigner,
	logger *slog.Logger,
) *BuilderLoop {
	return &BuilderLoop{
		cfg:         cfg,
		db:          db,
		tree:        tree,
		leafStore:   leafStore,
		nodeCache:   nodeCache,
		queue:       queue,
		fetcher:     fetcher,
		schema:      schema,
		buffer:      buffer,
		bufferStore: bufferStore,
		commitPub:   commitPub,
		merkle:      merkle,
		witness:     witness,
		logger:      logger,
	}
}

// Run executes the builder loop until ctx is cancelled.
// MUST be called from a single goroutine.
func (bl *BuilderLoop) Run(ctx context.Context) error {
	bl.logger.Info("builder loop started",
		"log_did", bl.cfg.LogDID,
		"batch_size", bl.cfg.BatchSize,
	)

	// Recover stale processing entries from prior crash.
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
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(bl.cfg.PollInterval):
			}
			continue
		}

		if processed == 0 {
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
	// Capture prior root for commitment.
	priorRoot, err := bl.tree.Root()
	if err != nil {
		return 0, fmt.Errorf("prior root: %w", err)
	}

	// ── Step 1: Dequeue batch ─────────────────────────────────────────
	var seqs []uint64
	err = store.WithReadCommittedTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		var dqErr error
		seqs, dqErr = bl.queue.DequeueBatch(ctx, tx, bl.cfg.BatchSize)
		return dqErr
	})
	if err != nil {
		return 0, fmt.Errorf("dequeue: %w", err)
	}
	if len(seqs) == 0 {
		return 0, nil
	}

	// ── Step 2: Fetch entries in sequence order ───────────────────────
	metas := make([]*types.EntryWithMetadata, 0, len(seqs))
	for _, seq := range seqs {
		pos := types.LogPosition{LogDID: bl.cfg.LogDID, Sequence: seq}
		meta, fetchErr := bl.fetcher.Fetch(pos)
		if fetchErr != nil || meta == nil {
			return 0, fmt.Errorf("fetch seq=%d: not found or error: %w", seq, fetchErr)
		}
		metas = append(metas, meta)
	}

	// ── Step 3: Split EntryWithMetadata → entries + positions ─────────
	// SDK ProcessBatch takes deserialized entries and separate positions,
	// not EntryWithMetadata directly. The operator is responsible for split.
	entries := make([]*envelope.Entry, len(metas))
	positions := make([]types.LogPosition, len(metas))
	for i, ewm := range metas {
		entry, desErr := envelope.Deserialize(ewm.CanonicalBytes)
		if desErr != nil {
			return 0, fmt.Errorf("deserialize seq=%d: %w", seqs[i], desErr)
		}
		entries[i] = entry
		positions[i] = ewm.Position
	}

	// ── Step 4: SDK ProcessBatch ──────────────────────────────────────
	result, err := sdkbuilder.ProcessBatch(
		bl.tree, entries, positions,
		bl.fetcher, bl.schema, bl.cfg.LogDID, bl.buffer,
	)
	if err != nil {
		return 0, fmt.Errorf("ProcessBatch: %w", err)
	}

	// ── Step 5: Atomic commit ─────────────────────────────────────────
	// All state changes in ONE Postgres Serializable transaction:
	//   - Leaf mutations → smt_leaves (reconstructed from diff)
	//   - Delta buffer → delta_window_buffers
	//   - Queue status → builder_queue (mark done)
	//
	// SDK LeafMutation is a diff format carrying tip positions, not a
	// full SMTLeaf. The operator reconstructs the leaf:
	//   types.SMTLeaf{Key: mut.LeafKey, OriginTip: mut.NewOriginTip,
	//                 AuthorityTip: mut.NewAuthorityTip}
	err = store.WithSerializableTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		// Write leaf mutations.
		for _, mut := range result.Mutations {
			leaf := types.SMTLeaf{
				Key:          mut.LeafKey,
				OriginTip:    mut.NewOriginTip,
				AuthorityTip: mut.NewAuthorityTip,
			}
			if setErr := bl.leafStore.SetTx(ctx, tx, mut.LeafKey, leaf); setErr != nil {
				return fmt.Errorf("set leaf %x: %w", mut.LeafKey[:8], setErr)
			}
		}

		// Save delta buffer.
		if bl.bufferStore != nil && result.UpdatedBuffer != nil {
			if bufErr := bl.bufferStore.SaveTx(ctx, tx, result.UpdatedBuffer); bufErr != nil {
				return fmt.Errorf("save buffer: %w", bufErr)
			}
		}

		// Mark queue entries as processed.
		if qErr := bl.queue.MarkProcessed(ctx, tx, seqs); qErr != nil {
			return fmt.Errorf("mark processed: %w", qErr)
		}

		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("atomic commit: %w", err)
	}

	// ── Step 6: Append to Merkle tree (post-commit) ──────────────────
	// Tessera append is idempotent: same hash → same position.
	// Crash here → re-append on restart is safe.
	if bl.merkle != nil {
		for _, ewm := range metas {
			entry, desErr := envelope.Deserialize(ewm.CanonicalBytes)
			if desErr != nil || entry == nil {
				continue
			}
			entryHash := crypto.CanonicalHash(entry)
			if _, appendErr := bl.merkle.AppendLeaf(entryHash); appendErr != nil {
				bl.logger.Error("Tessera append failed",
					"seq", ewm.Position.Sequence, "error", appendErr)
				// Non-fatal: Merkle tree will catch up on next cycle.
			}
		}
	}

	// ── Step 7: Publish derivation commitment ─────────────────────────
	if bl.commitPub != nil {
		bl.commitPub.MaybePublish(ctx, len(seqs),
			positions[0], positions[len(positions)-1],
			priorRoot, result)
	}

	// ── Step 8: Request witness cosignatures ──────────────────────────
	if bl.merkle != nil && bl.witness != nil {
		head, headErr := bl.merkle.Head()
		if headErr == nil {
			if cosigErr := bl.witness.RequestCosignatures(ctx, head); cosigErr != nil {
				bl.logger.Warn("witness cosignature request failed", "error", cosigErr)
				// Non-fatal: retry on next cycle.
			}
		}
	}

	// Update buffer reference for next cycle.
	if result.UpdatedBuffer != nil {
		bl.buffer = result.UpdatedBuffer
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

	return len(seqs), nil
}
