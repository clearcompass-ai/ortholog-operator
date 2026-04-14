/*
Package store provides Postgres persistence for the Ortholog operator.

FILE PATH: store/postgres.go

Connection pool, embedded DDL migrations, transaction manager, and advisory
locking for builder exclusivity. Single source of truth for the database schema.

KEY ARCHITECTURAL DECISIONS:
  - pgxpool for connection pooling: native Postgres wire protocol, no CGo.
  - Migrations embedded as Go constants: single-binary deployment.
  - Advisory lock prevents concurrent builder instances per log.
  - All schema changes additive (new tables/columns only).

INVARIANTS:
  - BuilderLockID ensures exactly one builder per database.
  - Migrations are idempotent and ordered.
  - WithTransaction uses Serializable for builder commits, ReadCommitted
    for admission (configurable via TxOptions parameter).
*/
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Connection Pool
// ─────────────────────────────────────────────────────────────────────────────

// Pool wraps pgxpool.Pool with operator lifecycle.
type Pool struct {
	DB  *pgxpool.Pool
	cfg PoolConfig
}

// PoolConfig configures the Postgres connection.
type PoolConfig struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// InitPool creates and validates the connection pool. Fails immediately if
// the database is unreachable — no silent degradation.
func InitPool(ctx context.Context, cfg PoolConfig) (*Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("store: invalid DSN: %w", err)
	}
	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime

	db, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("store: pool creation failed: %w", err)
	}

	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: database unreachable: %w", err)
	}

	return &Pool{DB: db, cfg: cfg}, nil
}

// Close shuts down the pool.
func (p *Pool) Close() { p.DB.Close() }

// ─────────────────────────────────────────────────────────────────────────────
// 2) Migrations — embedded DDL, executed sequentially on startup
// ─────────────────────────────────────────────────────────────────────────────

var migrations = []struct {
	version int
	stmts   []string
}{
	{0, []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version  INT PRIMARY KEY,
			applied  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}},
	{1, []string{
		`CREATE TABLE IF NOT EXISTS entry_index (
			sequence_number  BIGINT       PRIMARY KEY,
			canonical_hash   BYTEA        NOT NULL UNIQUE,
			log_time         TIMESTAMPTZ  NOT NULL,
			sig_algorithm_id SMALLINT     NOT NULL,
			signer_did       TEXT         NOT NULL CHECK (signer_did <> ''),
			target_root      BYTEA,
			cosignature_of   BYTEA,
			schema_ref       BYTEA
		)`,
	}},
	{2, []string{
		`CREATE INDEX IF NOT EXISTS idx_signer_did ON entry_index (signer_did)`,
		`CREATE INDEX IF NOT EXISTS idx_target_root ON entry_index (target_root) WHERE target_root IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_cosignature_of ON entry_index (cosignature_of) WHERE cosignature_of IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_schema_ref ON entry_index (schema_ref) WHERE schema_ref IS NOT NULL`,
	}},
	{3, []string{
		`CREATE TABLE IF NOT EXISTS smt_leaves (
			leaf_key      BYTEA    PRIMARY KEY,
			origin_tip    BYTEA    NOT NULL,
			authority_tip BYTEA    NOT NULL,
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS smt_nodes (
			path_key   BYTEA    PRIMARY KEY,
			hash       BYTEA    NOT NULL,
			depth      INT      NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}},
	{4, []string{
		`CREATE TABLE IF NOT EXISTS credits (
			exchange_did    TEXT    PRIMARY KEY,
			balance         BIGINT NOT NULL DEFAULT 0,
			total_purchased BIGINT NOT NULL DEFAULT 0,
			total_consumed  BIGINT NOT NULL DEFAULT 0,
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS tree_heads (
			tree_size    BIGINT   PRIMARY KEY,
			root_hash    BYTEA    NOT NULL,
			scheme_tag   SMALLINT NOT NULL,
			cosignatures BYTEA    NOT NULL,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS delta_window_buffers (
			leaf_key    BYTEA   PRIMARY KEY,
			tip_history BYTEA   NOT NULL,
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}},
	{5, []string{
		`CREATE TABLE IF NOT EXISTS builder_queue (
			sequence_number BIGINT      PRIMARY KEY,
			status          SMALLINT    NOT NULL DEFAULT 0,
			enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			processed_at    TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS witness_sets (
			version     SERIAL   PRIMARY KEY,
			set_hash    BYTEA    NOT NULL,
			keys_json   BYTEA    NOT NULL,
			scheme_tag  SMALLINT NOT NULL,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS equivocation_proofs (
			id         SERIAL      PRIMARY KEY,
			head_a     BYTEA       NOT NULL,
			head_b     BYTEA       NOT NULL,
			tree_size  BIGINT      NOT NULL,
			detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token       TEXT        PRIMARY KEY,
			exchange_did TEXT       NOT NULL,
			expires_at  TIMESTAMPTZ NOT NULL,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}},
	{6, []string{
		`CREATE SEQUENCE IF NOT EXISTS entry_sequence START 1 NO CYCLE`,
	}},
}

// RunMigrations executes all pending migrations. Each statement is atomic.
func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	// Ensure migration table exists (migration v0).
	for _, stmt := range migrations[0].stmts {
		if _, err := db.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("store: migration v0 failed: %w", err)
		}
	}

	for _, m := range migrations[1:] {
		applied, err := isMigrationApplied(ctx, db, m.version)
		if err != nil {
			return fmt.Errorf("store: checking migration v%d: %w", m.version, err)
		}
		if applied {
			continue
		}

		tx, err := db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("store: begin migration v%d: %w", m.version, err)
		}

		for _, stmt := range m.stmts {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("store: migration v%d stmt failed: %w", m.version, err)
			}
		}

		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", m.version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: recording migration v%d: %w", m.version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("store: commit migration v%d: %w", m.version, err)
		}
	}
	return nil
}

func isMigrationApplied(ctx context.Context, db *pgxpool.Pool, version int) (bool, error) {
	var exists bool
	err := db.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", version,
	).Scan(&exists)
	return exists, err
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Advisory Lock — builder exclusivity
// ─────────────────────────────────────────────────────────────────────────────

// BuilderLockID is the Postgres advisory lock key for builder exclusivity.
// One builder per log. Concurrent builders produce non-deterministic state.
const BuilderLockID int64 = 0x4F5254484F4C4F47 // "ORTHOLOG" in hex

// AcquireBuilderLock takes the advisory lock. Blocks if another instance holds it.
// Returns a release function. The lock is session-scoped (released on disconnect).
func AcquireBuilderLock(ctx context.Context, db *pgxpool.Pool) (release func(), err error) {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquiring connection for builder lock: %w", err)
	}
	_, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1)", BuilderLockID)
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("store: advisory lock failed: %w", err)
	}
	return func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", BuilderLockID)
		conn.Release()
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Transaction Manager
// ─────────────────────────────────────────────────────────────────────────────

// TxFunc is a function executed within a transaction.
type TxFunc func(ctx context.Context, tx pgx.Tx) error

// WithTransaction executes fn within a transaction at the given isolation level.
// Commits on success, rolls back on error.
func WithTransaction(ctx context.Context, db *pgxpool.Pool, iso pgx.TxIsoLevel, fn TxFunc) error {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}

	if err := fn(ctx, tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("store: tx error: %w (rollback also failed: %v)", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit tx: %w", err)
	}
	return nil
}

// WithSerializableTx is a convenience for Serializable isolation.
func WithSerializableTx(ctx context.Context, db *pgxpool.Pool, fn TxFunc) error {
	return WithTransaction(ctx, db, pgx.Serializable, fn)
}

// WithReadCommittedTx is a convenience for ReadCommitted isolation (admission).
func WithReadCommittedTx(ctx context.Context, db *pgxpool.Pool, fn TxFunc) error {
	return WithTransaction(ctx, db, pgx.ReadCommitted, fn)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) Errors
// ─────────────────────────────────────────────────────────────────────────────

// ErrInsufficientCredits signals balance = 0. Upstream returns HTTP 402.
var ErrInsufficientCredits = fmt.Errorf("store/credits: insufficient credits")

// ErrDuplicateEntry signals a UNIQUE constraint violation on canonical_hash.
var ErrDuplicateEntry = fmt.Errorf("store/entries: duplicate entry")
