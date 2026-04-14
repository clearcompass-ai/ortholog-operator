/*
Package builder — loop.go is the continuous builder loop. THE core operational
loop of the operator. Dequeues admitted entries, calls SDK ProcessBatch, commits
state atomically, appends to Merkle tree, publishes commitments, requests
witness cosignatures.

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
  - Context-aware: every Postgres call checks ctx.Done() first. Shutdown
    never produces spurious ERROR logs.

INVARIANTS:

  - processBatch either fully commits or fully rolls back.
  - Crash between commit and Tessera append → on restart, re-append is
    idempotent (Tessera deduplicates by leaf hash).
  - Empty batch → no mutations, no commitment, no cosig request.
  - Context cancellation → clean exit, no error logged.
*/
package builder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
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
// AppendLeaf takes full wire bytes (canonical + sig_envelope). Tessera
// computes RFC6962.HashLeaf(data) internally — the caller does not hash.
type MerkleAppender interface {
	AppendLeaf(data []byte) (uint64, error)
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

	// Observability counters (atomic, lock-free).
	totalBatches   atomic.Int64
	totalEntries   atomic.Int64
	totalErrors    atomic.Int64
	consecutiveErr atomic.Int32
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

// ─────────────────────────────────────────────────────────────────────────────
// 4) Run — main loop with clean shutdown and panic recovery
// ─────────────────────────────────────────────────────────────────────────────

// Run executes the builder loop until ctx is cancelled.
// MUST be called from a single goroutine.
//
// Shutdown behavior: context cancellation produces a clean INFO log and nil
// return. No ERROR logs on shutdown. Panics are recovered with a stack trace.
func (bl *BuilderLoop) Run(ctx context.Context) (retErr error) {
	// Panic recovery — builder goroutine death must be diagnosable.
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			bl.logger.Error("builder loop panic recovered",
				"panic", fmt.Sprintf("%v", r),
				"stack", string(buf[:n]),
			)
			retErr = fmt.Errorf("builder/loop: panic: %v", r)
		}
	}()

	bl.logger.Info("builder loop started",
		"log_did", bl.cfg.LogDID,
		"batch_size", bl.cfg.BatchSize,
		"poll_interval", bl.cfg.PollInterval,
	)

	// Recover stale processing entries from prior crash.
	if err := ctx.Err(); err != nil {
		return nil // Already cancelled before we started.
	}
	recovered, err := bl.queue.RecoverStale(ctx)
	if err != nil {
		if isContextError(err) {
			bl.logger.Info("builder loop stopped during recovery")
			return nil
		}
		return fmt.Errorf("builder/loop: recover stale: %w", err)
	}
	if recovered > 0 {
		bl.logger.Warn("recovered stale queue entries", "count", recovered)
	}

	for {
		// ── Check context BEFORE any work ─────────────────────────────
		if err := ctx.Err(); err != nil {
			bl.logger.Info("builder loop stopped",
				"batches", bl.totalBatches.Load(),
				"entries", bl.totalEntries.Load(),
				"errors", bl.totalErrors.Load(),
			)
			return nil
		}

		processed, err := bl.processBatch(ctx)

		if err != nil {
			// Context cancellation is not an error — it's a clean shutdown.
			if isContextError(err) {
				bl.logger.Info("builder loop stopped",
					"batches", bl.totalBatches.Load(),
					"entries", bl.totalEntries.Load(),
				)
				return nil
			}

			bl.totalErrors.Add(1)
			consecutive := bl.consecutiveErr.Add(1)

			bl.logger.Error("batch processing failed",
				"error", err,
				"consecutive_errors", consecutive,
			)

			// Back off on repeated errors to avoid tight error loops.
			backoff := bl.cfg.PollInterval * time.Duration(min(int(consecutive), 10))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}

		// Success — reset consecutive error counter.
		bl.consecutiveErr.Store(0)

		if processed > 0 {
			bl.totalBatches.Add(1)
			bl.totalEntries.Add(int64(processed))
			// Non-empty batch: loop immediately for throughput.
			continue
		}

		// Empty queue — wait before polling again.
		select {
		case <-ctx.Done():
			bl.logger.Info("builder loop stopped",
				"batches", bl.totalBatches.Load(),
				"entries", bl.totalEntries.Load(),
			)
			return nil
		case <-time.After(bl.cfg.PollInterval):
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) processBatch — one builder cycle, fully atomic
// ─────────────────────────────────────────────────────────────────────────────

// processBatch executes one builder cycle. Returns entries processed.
// Context cancellation at any step returns a context error (not logged as ERROR).
func (bl *BuilderLoop) processBatch(ctx context.Context) (int, error) {
	// Capture prior root for commitment.
	priorRoot, err := bl.tree.Root()
	if err != nil {
		return 0, fmt.Errorf("prior root: %w", err)
	}

	// ── Step 1: Dequeue batch ─────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return 0, err
	}

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
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	metas := make([]*types.EntryWithMetadata, 0, len(seqs))
	for _, seq := range seqs {
		p := types.LogPosition{LogDID: bl.cfg.LogDID, Sequence: seq}
		meta, fetchErr := bl.fetcher.Fetch(p)
		if fetchErr != nil || meta == nil {
			return 0, fmt.Errorf("fetch seq=%d: not found or error: %w", seq, fetchErr)
		}
		metas = append(metas, meta)
	}

	// ── Step 3: Split EntryWithMetadata → entries + positions ─────────
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
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	err = store.WithSerializableTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		// Write leaf mutations. SDK LeafMutation is a diff format —
		// the operator reconstructs the full leaf from tip positions.
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

	// ──────────────────────────────────────────────────────────────────
	// POST-COMMIT: Steps 6-8 are best-effort. The atomic state is safe.
	// Failures here are non-fatal — the next cycle will catch up.
	// ──────────────────────────────────────────────────────────────────

	// ── Step 6: Append to Merkle tree (post-commit) ──────────────────
	// Tessera append is idempotent: same data → same position.
	// Crash here → re-append on restart is safe.
	// Option B: full wire bytes (canonical + sig_envelope) go into the tree.
	// The inclusion proof covers both content and signature — the proof says
	// "this exact signed entry is in the log at position N."
	if bl.merkle != nil {
		for _, ewm := range metas {
			// Reconstruct wire bytes: canonical_bytes + sig_envelope.
			wireBytes := envelope.AppendSignature(
				ewm.CanonicalBytes, ewm.SignatureAlgoID, ewm.SignatureBytes)
			if _, appendErr := bl.merkle.AppendLeaf(wireBytes); appendErr != nil {
				bl.logger.Error("Tessera append failed",
					"seq", ewm.Position.Sequence, "error", appendErr)
			}
		}
	}

	// ── Step 7: Publish derivation commitment ─────────────────────────
	if bl.commitPub != nil && len(positions) > 0 {
		bl.commitPub.MaybePublish(ctx, len(seqs),
			positions[0], positions[len(positions)-1],
			priorRoot, result)
	}

	// ── Step 8: Request witness cosignatures ──────────────────────────
	if bl.merkle != nil && bl.witness != nil {
		head, headErr := bl.merkle.Head()
		if headErr == nil && head.TreeSize > 0 {
			if cosigErr := bl.witness.RequestCosignatures(ctx, head); cosigErr != nil {
				if !isContextError(cosigErr) {
					bl.logger.Warn("witness cosignature request failed", "error", cosigErr)
				}
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

// ─────────────────────────────────────────────────────────────────────────────
// 6) Observability
// ─────────────────────────────────────────────────────────────────────────────

// Stats returns current builder loop counters.
func (bl *BuilderLoop) Stats() (batches, entries, errs int64) {
	return bl.totalBatches.Load(), bl.totalEntries.Load(), bl.totalErrors.Load()
}

// ─────────────────────────────────────────────────────────────────────────────
// 7) Helpers
// ─────────────────────────────────────────────────────────────────────────────

// isContextError returns true if err is caused by context cancellation or
// deadline exceeded. Used to distinguish clean shutdown from real failures.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
