/*
FILE PATH: builder/queue.go

Postgres-backed FIFO queue for the builder loop. Entries are enqueued at
admission (atomic with entry insert) and dequeued in strict sequence order.

KEY ARCHITECTURAL DECISIONS:
  - SELECT FOR UPDATE SKIP LOCKED: no contention with concurrent enqueues.
  - Strict sequence order within each batch: determinism.
  - Status: 0=pending, 1=processing, 2=done.
  - processed_at timestamp set on completion.
  - RecoverStale on startup: resets processing→pending for crash recovery.

INVARIANTS:
  - Gapless sequence order within each dequeued batch.
  - No entry lost in transit: RecoverStale reclaims orphans.
*/
package builder

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	StatusPending    int16 = 0
	StatusProcessing int16 = 1
	StatusDone       int16 = 2
)

// Queue is the Postgres-backed builder FIFO.
type Queue struct {
	db *pgxpool.Pool
}

// NewQueue creates a builder queue.
func NewQueue(db *pgxpool.Pool) *Queue {
	return &Queue{db: db}
}

// Enqueue adds a sequence number to the queue. Called within the admission tx.
func (q *Queue) Enqueue(ctx context.Context, tx pgx.Tx, seq uint64) error {
	_, err := tx.Exec(ctx,
		"INSERT INTO builder_queue (sequence_number, status) VALUES ($1, $2)",
		seq, StatusPending,
	)
	if err != nil {
		return fmt.Errorf("builder/queue: enqueue seq=%d: %w", seq, err)
	}
	return nil
}

// DequeueBatch retrieves up to maxSize pending entries in strict sequence order.
// Marks them as processing. Returns nil if no pending entries.
func (q *Queue) DequeueBatch(ctx context.Context, tx pgx.Tx, maxSize int) ([]uint64, error) {
	rows, err := tx.Query(ctx, `
		SELECT sequence_number FROM builder_queue
		WHERE status = $1
		ORDER BY sequence_number ASC
		LIMIT $2
		FOR UPDATE SKIP LOCKED`,
		StatusPending, maxSize,
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
		StatusProcessing, seqs,
	)
	if err != nil {
		return nil, fmt.Errorf("builder/queue: mark processing: %w", err)
	}

	return seqs, nil
}

// MarkProcessed marks entries as done within a transaction.
func (q *Queue) MarkProcessed(ctx context.Context, tx pgx.Tx, seqs []uint64) error {
	_, err := tx.Exec(ctx, `
		UPDATE builder_queue SET status = $1, processed_at = NOW()
		WHERE sequence_number = ANY($2)`,
		StatusDone, seqs,
	)
	if err != nil {
		return fmt.Errorf("builder/queue: mark done: %w", err)
	}
	return nil
}

// RecoverStale resets any processing entries to pending on startup.
func (q *Queue) RecoverStale(ctx context.Context) (int64, error) {
	tag, err := q.db.Exec(ctx,
		"UPDATE builder_queue SET status = $1 WHERE status = $2",
		StatusPending, StatusProcessing,
	)
	if err != nil {
		return 0, fmt.Errorf("builder/queue: recover stale: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PurgeProcessed removes completed entries older than retention period.
func (q *Queue) PurgeProcessed(ctx context.Context) (int64, error) {
	tag, err := q.db.Exec(ctx,
		"DELETE FROM builder_queue WHERE status = $1 AND processed_at < NOW() - INTERVAL '7 days'",
		StatusDone,
	)
	if err != nil {
		return 0, fmt.Errorf("builder/queue: purge: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PendingCount returns the number of pending entries.
func (q *Queue) PendingCount(ctx context.Context) (int64, error) {
	var count int64
	err := q.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM builder_queue WHERE status = $1", StatusPending,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("builder/queue: pending count: %w", err)
	}
	return count, nil
}
