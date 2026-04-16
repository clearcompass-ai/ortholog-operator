/*
Package builder — loop.go

DESCRIPTION:

	The continuous builder loop — THE core operational loop of the operator.
	Dequeues admitted entries, calls SDK ProcessBatch, commits state atomically,
	appends entry hashes to the Merkle tree, publishes commitments, and requests
	witness cosignatures.

KEY ARCHITECTURAL DECISIONS:
  - Single goroutine: determinism requires exactly one builder per log.
    Advisory lock prevents concurrent instances.
  - Atomic commit: leaf mutations + delta buffer + queue status in ONE
    Postgres transaction. No partial state on crash.
  - Overlay SMT Store: SDK ProcessBatch runs against an in-memory overlay
    to guarantee functional purity. If batch validation fails, the overlay
    is discarded and Postgres remains completely untouched.
  - Hash-only Merkle tree (Conflict #1 resolution): Step 6 passes
    SHA-256(wire_bytes) — exactly 32 bytes — to Tessera. Full entry bytes
    stay in the operator's own storage (InMemoryEntryStore/disk).
    Tessera never sees full entry data. This preserves SDK-D11 (1MB)
    within the tlog-tiles uint16 (64KB) entry bundle constraint.
  - SDK MerkleTree interface: builder touches only the MerkleAppender
    interface, never tessera/client.go directly. Swappable backend.
  - Idempotent: replaying the same batch produces identical state.
  - Context-aware: every Postgres call checks ctx.Done() first.

OVERVIEW:

	Run loop: dequeue → fetch → split → ProcessBatch → atomic commit →
	Merkle append (hash-only) → commitment → witness cosig.

	Step 6 (Merkle append) is POST-COMMIT and best-effort. Crash between
	commit and append → re-append on restart is safe (Tessera deduplicates
	by leaf hash). The operator's atomic state is in Postgres.

KEY DEPENDENCIES:
  - github.com/clearcompass-ai/ortholog-sdk/builder: ProcessBatch, BatchResult.
  - tessera/proof_adapter.go: TesseraAdapter implements MerkleAppender.
  - store/smt_state.go: PostgresLeafStore.SetTx for atomic leaf writes.
  - store/entries.go: PostgresEntryFetcher for entry retrieval.
*/
package builder

import (
	"context"
	"crypto/sha256"
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

// -------------------------------------------------------------------------------------------------
// 1) Configuration
// -------------------------------------------------------------------------------------------------

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

// -------------------------------------------------------------------------------------------------
// 2) Interfaces
// -------------------------------------------------------------------------------------------------

// MerkleAppender is the subset of the Merkle tree interface used by the builder.
//
// AppendLeaf takes a 32-byte SHA-256 hash of the entry's wire bytes.
// The operator computes SHA-256(canonical + sig_envelope) and passes only
// the digest. Tessera stores this hash in its entry tiles and computes
// the Merkle leaf hash as H(0x00 || hash_bytes).
//
// This is the hash-only architecture (Conflict #1 resolution). Full entry
// bytes stay in the operator's own storage. Tessera never sees them.
type MerkleAppender interface {
	AppendLeaf(data []byte) (uint64, error)
	Head() (types.TreeHead, error)
}

// WitnessCosigner requests cosignatures on tree heads.
type WitnessCosigner interface {
	RequestCosignatures(ctx context.Context, head types.TreeHead) error
}

// -------------------------------------------------------------------------------------------------
// 3) BuilderLoop
// -------------------------------------------------------------------------------------------------

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

// -------------------------------------------------------------------------------------------------
// 4) Run — main loop with clean shutdown and panic recovery
// -------------------------------------------------------------------------------------------------

// Run executes the builder loop until ctx is cancelled.
// MUST be called from a single goroutine.
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
		return nil
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

			backoff := bl.cfg.PollInterval * time.Duration(min(int(consecutive), 10))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}

		bl.consecutiveErr.Store(0)

		if processed > 0 {
			bl.totalBatches.Add(1)
			bl.totalEntries.Add(int64(processed))
			continue
		}

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

// -------------------------------------------------------------------------------------------------
// 5) processBatch — one builder cycle, fully atomic
// -------------------------------------------------------------------------------------------------

func (bl *BuilderLoop) processBatch(ctx context.Context) (int, error) {
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
	// Wrap the live Postgres leaf store in an in-memory overlay.
	// This prevents mid-batch errors from mutating the database non-transactionally.
	// If ProcessBatch fails, the overlayStore is garbage collected and Postgres
	// remains completely untouched.
	overlayStore := smt.NewOverlayLeafStore(bl.leafStore)
	overlayTree := smt.NewTree(overlayStore, bl.nodeCache)

	result, err := sdkbuilder.ProcessBatch(
		overlayTree, entries, positions,
		bl.fetcher, bl.schema, bl.cfg.LogDID, bl.buffer,
	)
	if err != nil {
		return 0, fmt.Errorf("ProcessBatch: %w", err)
	}

	// ── Step 5: Atomic commit ─────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	err = store.WithSerializableTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		// Apply the successfully computed SMT mutations inside the transaction.
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

		if bl.bufferStore != nil && result.UpdatedBuffer != nil {
			if bufErr := bl.bufferStore.SaveTx(ctx, tx, result.UpdatedBuffer); bufErr != nil {
				return fmt.Errorf("save buffer: %w", bufErr)
			}
		}

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
	// ──────────────────────────────────────────────────────────────────

	// ── Step 6: Append to Merkle tree — HASH ONLY (post-commit) ──────
	//
	// Hash-only architecture (Conflict #1 resolution):
	// Compute SHA-256(wire_bytes) and send only the 32-byte hash to Tessera.
	// Full wire bytes stay in the operator's own storage (InMemoryEntryStore
	// or persistent disk store). Tessera never sees full entry data.
	//
	// Two-step verification for consumers:
	//   1. Prove hash is in Merkle tree at position N (tile-based proof).
	//   2. Prove entry data hashes to that value (SHA-256 of fetched bytes).
	//
	// Tessera append is idempotent: same hash → same position.
	// Crash here → re-append on restart is safe.
	if bl.merkle != nil {
		for _, ewm := range metas {
			wireBytes := envelope.AppendSignature(
				ewm.CanonicalBytes, ewm.SignatureAlgoID, ewm.SignatureBytes)
			entryHash := sha256.Sum256(wireBytes)
			if _, appendErr := bl.merkle.AppendLeaf(entryHash[:]); appendErr != nil {
				bl.logger.Error("Tessera append failed (hash-only)",
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

// -------------------------------------------------------------------------------------------------
// 6) Observability
// -------------------------------------------------------------------------------------------------

// Stats returns current builder loop counters.
func (bl *BuilderLoop) Stats() (batches, entries, errs int64) {
	return bl.totalBatches.Load(), bl.totalEntries.Load(), bl.totalErrors.Load()
}

// -------------------------------------------------------------------------------------------------
// 7) Helpers
// -------------------------------------------------------------------------------------------------

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
