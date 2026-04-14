/*
FILE PATH:
    store/postgres.go

DESCRIPTION:
    Postgres connection pool, embedded DDL migrations, transaction manager,
    and advisory locking for builder exclusivity. Single source of truth
    for the database schema.

KEY ARCHITECTURAL DECISIONS:
    - pgxpool for connection pooling: native Postgres wire protocol, no CGo
    - Migrations embedded as Go constants: single-binary deployment, no
      external migration tool dependency
    - Advisory lock (pg_advisory_lock) prevents concurrent builder instances
      on the same log — determinism requires exactly one builder per log
    - All schema changes are additive (new tables/columns only) to match
      the protocol's additive-only evolution guarantee

OVERVIEW:
    InitPool → RunMigrations → AcquireBuilderLock → ready.
    TransactionManager wraps pgx.Tx for atomic multi-table commits
    (builder loop commits leaf mutations + buffer + queue status atomically).

KEY DEPENDENCIES:
    - github.com/jackc/pgx/v5/pgxpool: connection pooling
*/
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// -------------------------------------------------------------------------------------------------
// 1) Connection Pool
// -------------------------------------------------------------------------------------------------

// Pool wraps pgxpool.Pool with operator-specific lifecycle.
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

	// Validate connectivity immediately. No lazy init.
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: database unreachable: %w", err)
	}

	return &Pool{DB: db, cfg: cfg}, nil
}

// Close shuts down the pool. Call during graceful shutdown.
func (p *Pool) Close() {
	p.DB.Close()
}

// -------------------------------------------------------------------------------------------------
// 2) Migrations — embedded DDL, executed sequentially on startup
// -------------------------------------------------------------------------------------------------

// migrations is the ordered list of DDL statements. Each runs in its own
// transaction. Index is the migration version number.
var migrations = []string{
	// v0: migration tracking table
	`CREATE TABLE IF NOT EXISTS schema_migrations (
		version  INT PRIMARY KEY,
		applied  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// v1: entries table — core log storage
	`CREATE TABLE IF NOT EXISTS entries (
		sequence_number  BIGINT       PRIMARY KEY,
		canonical_bytes  BYTEA        NOT NULL,
		canonical_hash   BYTEA        NOT NULL UNIQUE,
		log_time         TIMESTAMPTZ  NOT NULL,
		sig_algorithm_id SMALLINT     NOT NULL,
		sig_bytes        BYTEA        NOT NULL,
		signer_did       TEXT         NOT NULL,
		target_root      BYTEA,
		cosignature_of   BYTEA,
		schema_ref       BYTEA
	)`,

	// v2: entry indexes — all 5 query interfaces
	`CREATE INDEX IF NOT EXISTS idx_signer_did ON entries (signer_did);
	 CREATE INDEX IF NOT EXISTS idx_target_root ON entries (target_root) WHERE target_root IS NOT NULL;
	 CREATE INDEX IF NOT EXISTS idx_cosignature_of ON entries (cosignature_of) WHERE cosignature_of IS NOT NULL;
	 CREATE INDEX IF NOT EXISTS idx_schema_ref ON entries (schema_ref) WHERE schema_ref IS NOT NULL`,

	// v3: SMT state persistence
	`CREATE TABLE IF NOT EXISTS smt_leaves (
		leaf_key      BYTEA    PRIMARY KEY,
		origin_tip    BYTEA    NOT NULL,
		authority_tip BYTEA    NOT NULL,
		updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS smt_nodes (
		path_key   BYTEA    PRIMARY KEY,
		hash       BYTEA    NOT NULL,
		depth      INT      NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// v4: credits, tree heads, delta buffers
	`CREATE TABLE IF NOT EXISTS credits (
		exchange_did    TEXT    PRIMARY KEY,
		balance         BIGINT NOT NULL DEFAULT 0,
		total_purchased BIGINT NOT NULL DEFAULT 0,
		total_consumed  BIGINT NOT NULL DEFAULT 0,
		updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS tree_heads (
		tree_size    BIGINT   PRIMARY KEY,
		root_hash    BYTEA    NOT NULL,
		scheme_tag   SMALLINT NOT NULL,
		cosignatures BYTEA    NOT NULL,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS delta_window_buffers (
		leaf_key    BYTEA   PRIMARY KEY,
		tip_history BYTEA   NOT NULL,
		updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// v5: builder queue, witness sets, equivocation proofs, sessions
	`CREATE TABLE IF NOT EXISTS builder_queue (
		sequence_number BIGINT      PRIMARY KEY,
		status          SMALLINT    NOT NULL DEFAULT 0,
		enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS witness_sets (
		version     SERIAL   PRIMARY KEY,
		set_hash    BYTEA    NOT NULL,
		keys_json   BYTEA    NOT NULL,
		scheme_tag  SMALLINT NOT NULL,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS equivocation_proofs (
		id         SERIAL      PRIMARY KEY,
		head_a     BYTEA       NOT NULL,
		head_b     BYTEA       NOT NULL,
		tree_size  BIGINT      NOT NULL,
		detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS sessions (
		token       TEXT        PRIMARY KEY,
		exchange_did TEXT       NOT NULL,
		expires_at  TIMESTAMPTZ NOT NULL,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,

	// v6: sequence counter for gapless assignment
	`CREATE SEQUENCE IF NOT EXISTS entry_sequence START 1 NO CYCLE`,
}

// RunMigrations executes all pending migrations. Each migration is atomic.
// Fails on any error — no partial migration state.
func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	// Ensure migration table exists (migration v0).
	if _, err := db.Exec(ctx, migrations[0]); err != nil {
		return fmt.Errorf("store: migration v0 failed: %w", err)
	}

	for i := 1; i < len(migrations); i++ {
		applied, err := isMigrationApplied(ctx, db, i)
		if err != nil {
			return fmt.Errorf("store: checking migration v%d: %w", i, err)
		}
		if applied {
			continue
		}

		tx, err := db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("store: begin migration v%d: %w", i, err)
		}

		if _, err := tx.Exec(ctx, migrations[i]); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: migration v%d failed: %w", i, err)
		}

		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", i); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: recording migration v%d: %w", i, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("store: commit migration v%d: %w", i, err)
		}
	}
	return nil
}

func isMigrationApplied(ctx context.Context, db *pgxpool.Pool, version int) (bool, error) {
	var exists bool
	err := db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", version).Scan(&exists)
	return exists, err
}

// -------------------------------------------------------------------------------------------------
// 3) Advisory Lock — builder exclusivity
// -------------------------------------------------------------------------------------------------

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

// -------------------------------------------------------------------------------------------------
// 4) Transaction Manager
// -------------------------------------------------------------------------------------------------

// TxFunc is a function executed within a transaction.
type TxFunc func(ctx context.Context, tx pgx.Tx) error

// WithTransaction executes fn within a serializable transaction.
// Commits on success, rolls back on error. No partial commits.
func WithTransaction(ctx context.Context, db *pgxpool.Pool, fn TxFunc) error {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
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
