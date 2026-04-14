/*
FILE PATH: store/tree_heads.go

Cosigned tree head persistence. Stores every cosigned head for
historical consistency proofs and equivocation detection.

KEY ARCHITECTURAL DECISIONS:
  - tree_size as PK: monotonically increasing, one head per size.
  - cosignatures stored as opaque BYTEA: scheme-tagged, parsed by SDK.
  - Latest() cached in memory, invalidated on new insert.
*/
package store

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TreeHeadStore manages cosigned tree head persistence.
type TreeHeadStore struct {
	db     *pgxpool.Pool
	mu     sync.RWMutex
	latest *TreeHeadRow // In-memory cache of latest head.
}

// NewTreeHeadStore creates a tree head store.
func NewTreeHeadStore(db *pgxpool.Pool) *TreeHeadStore {
	return &TreeHeadStore{db: db}
}

// TreeHeadRow is the stored representation of a cosigned tree head.
type TreeHeadRow struct {
	TreeSize     uint64
	RootHash     [32]byte
	SchemeTag    byte
	Cosignatures []byte
}

// Insert stores a new cosigned tree head. Invalidates the latest cache.
func (s *TreeHeadStore) Insert(ctx context.Context, row TreeHeadRow) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO tree_heads (tree_size, root_hash, scheme_tag, cosignatures)
		VALUES ($1, $2, $3, $4)`,
		row.TreeSize, row.RootHash[:], int16(row.SchemeTag), row.Cosignatures,
	)
	if err != nil {
		return fmt.Errorf("store/tree_heads: insert size=%d: %w", row.TreeSize, err)
	}
	s.mu.Lock()
	s.latest = &row
	s.mu.Unlock()
	return nil
}

// Latest returns the most recent cosigned tree head. Nil if none exist.
func (s *TreeHeadStore) Latest(ctx context.Context) (*TreeHeadRow, error) {
	s.mu.RLock()
	cached := s.latest
	s.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	row, err := s.fetchLatest(ctx)
	if err != nil {
		return nil, err
	}
	if row != nil {
		s.mu.Lock()
		s.latest = row
		s.mu.Unlock()
	}
	return row, nil
}

func (s *TreeHeadStore) fetchLatest(ctx context.Context) (*TreeHeadRow, error) {
	var (
		treeSize  uint64
		rootHash  []byte
		schemeTag int16
		cosigs    []byte
	)
	err := s.db.QueryRow(ctx,
		"SELECT tree_size, root_hash, scheme_tag, cosignatures FROM tree_heads ORDER BY tree_size DESC LIMIT 1",
	).Scan(&treeSize, &rootHash, &schemeTag, &cosigs)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/tree_heads: latest: %w", err)
	}

	row := &TreeHeadRow{
		TreeSize:     treeSize,
		SchemeTag:    byte(schemeTag),
		Cosignatures: cosigs,
	}
	if len(rootHash) == 32 {
		copy(row.RootHash[:], rootHash)
	}
	return row, nil
}

// GetBySize returns the tree head at a specific size.
func (s *TreeHeadStore) GetBySize(ctx context.Context, size uint64) (*TreeHeadRow, error) {
	var (
		rootHash  []byte
		schemeTag int16
		cosigs    []byte
	)
	err := s.db.QueryRow(ctx,
		"SELECT root_hash, scheme_tag, cosignatures FROM tree_heads WHERE tree_size = $1",
		size,
	).Scan(&rootHash, &schemeTag, &cosigs)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/tree_heads: get size=%d: %w", size, err)
	}

	row := &TreeHeadRow{
		TreeSize:     size,
		SchemeTag:    byte(schemeTag),
		Cosignatures: cosigs,
	}
	if len(rootHash) == 32 {
		copy(row.RootHash[:], rootHash)
	}
	return row, nil
}
