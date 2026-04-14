/*
FILE PATH:
    store/entries.go

DESCRIPTION:
    Entry persistence and the PostgresEntryFetcher — the concrete
    implementation of sdk builder.EntryFetcher. Every entry returned
    by Fetch has had its signature verified at admission (SDK-D5 contract).

KEY ARCHITECTURAL DECISIONS:
    - Sequence number as primary key: gapless, monotonic, determined at
      admission. The builder processes entries in this order.
    - Canonical hash stored separately from bytes: UNIQUE constraint
      prevents duplicate entries without deserialization.
    - Indexed columns (signer_did, target_root, cosignature_of, schema_ref)
      extracted at admission time — no runtime parsing for queries.
    - Log_Time stored as TIMESTAMPTZ alongside entry but NOT in canonical
      bytes (SDK-D1, Decision 50).

OVERVIEW:
    Insert: called by submission.go after admission. Atomic with queue enqueue.
    Fetch: implements builder.EntryFetcher. Returns EntryWithMetadata.
    FetchByHash: secondary lookup for deduplication checks.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ortholog-sdk/types: EntryWithMetadata, LogPosition
    - github.com/jackc/pgx/v5: Postgres driver
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Entry Storage
// -------------------------------------------------------------------------------------------------

// EntryStore handles entry persistence.
type EntryStore struct {
	db *pgxpool.Pool
}

// NewEntryStore creates an entry store.
func NewEntryStore(db *pgxpool.Pool) *EntryStore {
	return &EntryStore{db: db}
}

// EntryRow is the complete entry record for insertion.
type EntryRow struct {
	SequenceNumber uint64
	CanonicalBytes []byte
	CanonicalHash  [32]byte
	LogTime        time.Time
	SigAlgorithmID uint16
	SigBytes       []byte
	SignerDID      string
	TargetRoot     []byte // nil if null
	CosignatureOf  []byte // nil if null
	SchemaRef      []byte // nil if null
}

// Insert persists an entry. Called within the admission transaction.
// Fails on duplicate hash (UNIQUE constraint) — no silent overwrite.
func (s *EntryStore) Insert(ctx context.Context, tx pgx.Tx, row EntryRow) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO entries (
			sequence_number, canonical_bytes, canonical_hash, log_time,
			sig_algorithm_id, sig_bytes, signer_did, target_root,
			cosignature_of, schema_ref
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		row.SequenceNumber, row.CanonicalBytes, row.CanonicalHash[:],
		row.LogTime, row.SigAlgorithmID, row.SigBytes, row.SignerDID,
		row.TargetRoot, row.CosignatureOf, row.SchemaRef,
	)
	if err != nil {
		return fmt.Errorf("store/entries: insert seq=%d: %w", row.SequenceNumber, err)
	}
	return nil
}

// NextSequence atomically allocates the next gapless sequence number.
func (s *EntryStore) NextSequence(ctx context.Context, tx pgx.Tx) (uint64, error) {
	var seq uint64
	err := tx.QueryRow(ctx, "SELECT nextval('entry_sequence')").Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("store/entries: nextval: %w", err)
	}
	return seq, nil
}

// -------------------------------------------------------------------------------------------------
// 2) PostgresEntryFetcher — implements sdk builder.EntryFetcher
// -------------------------------------------------------------------------------------------------

// PostgresEntryFetcher implements builder.EntryFetcher.
// CONTRACT: all returned entries have verified signatures (SDK-D5).
// This invariant is established at admission (api/submission.go) and
// preserved by the database — entries only reach the database after
// signature verification passes.
type PostgresEntryFetcher struct {
	db     *pgxpool.Pool
	logDID string
}

// NewPostgresEntryFetcher creates a fetcher for the given log.
func NewPostgresEntryFetcher(db *pgxpool.Pool, logDID string) *PostgresEntryFetcher {
	return &PostgresEntryFetcher{db: db, logDID: logDID}
}

// Fetch retrieves an entry by LogPosition. Returns nil if not found.
// Only fetches entries on the local log (builder is local-only, Decision 47).
func (f *PostgresEntryFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	if pos.LogDID != f.logDID {
		return nil, nil // Foreign log — not found locally (Decision 47).
	}

	var (
		canonical []byte
		logTime   time.Time
		algoID    int16
		sigBytes  []byte
	)
	err := f.db.QueryRow(context.Background(), `
		SELECT canonical_bytes, log_time, sig_algorithm_id, sig_bytes
		FROM entries WHERE sequence_number = $1`,
		pos.Sequence,
	).Scan(&canonical, &logTime, &algoID, &sigBytes)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/entries: fetch seq=%d: %w", pos.Sequence, err)
	}

	return &types.EntryWithMetadata{
		CanonicalBytes: canonical,
		LogTime:        logTime,
		Position:       pos,
		SignatureAlgoID: uint16(algoID),
		SignatureBytes:  sigBytes,
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 3) FetchByHash — deduplication support
// -------------------------------------------------------------------------------------------------

// FetchByHash checks if an entry with the given canonical hash already exists.
// Used by submission.go to reject duplicate submissions before enqueuing.
func (s *EntryStore) FetchByHash(ctx context.Context, hash [32]byte) (*uint64, error) {
	var seq uint64
	err := s.db.QueryRow(ctx,
		"SELECT sequence_number FROM entries WHERE canonical_hash = $1", hash[:],
	).Scan(&seq)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/entries: fetch by hash: %w", err)
	}
	return &seq, nil
}
