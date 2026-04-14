/*
FILE PATH:
    builder/queue.go

DESCRIPTION:
    Postgres-backed FIFO queue for the builder loop. Entries are enqueued
    at admission (atomic with entry insert) and dequeued in strict sequence
    order for deterministic batch processing.

KEY ARCHITECTURAL DECISIONS:
    - SELECT FOR UPDATE SKIP LOCKED: allows admission to continue enqueuing
      while the builder holds a batch. No contention.
    - Strict sequence order within each batch: determinism requires entries
      processed in log order. No reordering.
    - Status enum: 0=pending, 1=processing, 2=done. Processing state
      enables crash recovery (reset to pending on startup).

OVERVIEW:
    Enqueue: INSERT INTO builder_queue (seq, status=pending). Atomic with
    entry insert in the same transaction.
    DequeueBatch: SELECT pending rows FOR UPDATE SKIP LOCKED, mark processing.
    MarkProcessed: UPDATE to done after successful builder commit.
    RecoverStale: on startup, reset any processing→pending (crash recovery).

KEY DEPENDENCIES:
    - github.com/jackc/pgx/v5: FOR UPDATE SKIP LOCKED
*/
package builder

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// -------------------------------------------------------------------------------------------------
// 1) Queue Status
// -------------------------------------------------------------------------------------------------

const (
	statusPending    int16 = 0
	statusProcessing int16 = 1
	statusDone       int16 = 2
)

// -------------------------------------------------------------------------------------------------
// 2) Queue
// -------------------------------------------------------------------------------------------------

// Queue is the Postgres-backed builder FIFO.
type Queue struct {
	db *pgxpool.Pool
}

// NewQueue creates a builder queue.
func NewQueue(db *pgxpool.Pool) *Queue {
	return &Queue{db: db}
}

// Enqueue adds a sequence number to the queue. Called within the admission transaction.
func (q *Queue) Enqueue(ctx context.Context, tx pgx.Tx, seq uint64) error {
	_, err := tx.Exec(ctx,
		"INSERT INTO builder_queue (sequence_number, status) VALUES ($1, $2)",
		seq, statusPending,
	)
	if err != nil {
		return fmt.Errorf("builder/queue: enqueue seq=%d: %w", seq, err)
	}
	return nil
}

// DequeueBatch retrieves up to maxSize pending entries in strict sequence order.
// Uses FOR UPDATE SKIP LOCKED to avoid contention with concurrent enqueues.
// Returns the sequence numbers. Entries are marked as processing.
func (q *Queue) DequeueBatch(ctx context.Context, tx pgx.Tx, maxSize int) ([]uint64, error) {
	rows, err := tx.Query(ctx, `
		SELECT sequence_number FROM builder_queue
		WHERE status = $1
		ORDER BY sequence_number ASC
		LIMIT $2
		FOR UPDATE SKIP LOCKED`,
		statusPending, maxSize,
	)
	if err != nil {
		return nil, fmt.Errorf("builder/queue: dequeue: %w", err)
	}
	defer rows.Close()

	var seqs []uint64
	for rows.Next() {
		var seq uint64
		if err := rows.Scan(&seq); err != nil {
			return nil, fmt.Errorf("builder/queue: scan: %w", err)
		}
		seqs = append(seqs, seq)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("builder/queue: rows: %w", err)
	}

	if len(seqs) == 0 {
		return nil, nil
	}

	// Mark as processing.
	_, err = tx.Exec(ctx, `
		UPDATE builder_queue SET status = $1
		WHERE sequence_number = ANY($2)`,
		statusProcessing, seqs,
	)
	if err != nil {
		return nil, fmt.Errorf("builder/queue: mark processing: %w", err)
	}

	return seqs, nil
}

// MarkProcessed marks entries as done after successful builder commit.
func (q *Queue) MarkProcessed(ctx context.Context, tx pgx.Tx, seqs []uint64) error {
	_, err := tx.Exec(ctx, `
		UPDATE builder_queue SET status = $1
		WHERE sequence_number = ANY($2)`,
		statusDone, seqs,
	)
	if err != nil {
		return fmt.Errorf("builder/queue: mark done: %w", err)
	}
	return nil
}

// RecoverStale resets any processing entries to pending. Call on startup
// to recover from crashes during batch processing.
func (q *Queue) RecoverStale(ctx context.Context) (int64, error) {
	tag, err := q.db.Exec(ctx,
		"UPDATE builder_queue SET status = $1 WHERE status = $2",
		statusPending, statusProcessing,
	)
	if err != nil {
		return 0, fmt.Errorf("builder/queue: recover stale: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PurgeProcessed removes done entries older than the retention window.
// Operational maintenance. Does not affect correctness.
func (q *Queue) PurgeProcessed(ctx context.Context) (int64, error) {
	tag, err := q.db.Exec(ctx,
		"DELETE FROM builder_queue WHERE status = $1", statusDone,
	)
	if err != nil {
		return 0, fmt.Errorf("builder/queue: purge: %w", err)
	}
	return tag.RowsAffected(), nil
}
