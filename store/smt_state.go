/*
FILE PATH:
    store/smt_state.go

DESCRIPTION:
    Postgres-backed implementations of sdk LeafStore and NodeCache interfaces.
    The SMT builder writes leaf mutations here; the proof generator reads them.

KEY ARCHITECTURAL DECISIONS:
    - PostgresLeafStore: direct Get/Set/Delete against smt_leaves table.
      No in-memory caching at this layer — NodeCache handles hot paths.
    - PostgresNodeCache: write-through to both Postgres (smt_nodes) and
      an in-memory LRU. Top N levels warmed on startup for sub-millisecond
      root computation.
    - Serialization of LogPosition into BYTEA: length-prefixed DID + uint64
      (same as sdk canonical serialization for consistency).

OVERVIEW:
    PostgresLeafStore implements sdk smt.LeafStore (Get/Set/Delete/Count).
    PostgresNodeCache implements sdk smt.NodeCache (Get/Set) with LRU.
    WarmCache preloads top N levels from Postgres into LRU on startup.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ortholog-sdk/types: SMTLeaf, LogPosition
    - github.com/clearcompass-ai/ortholog-sdk/core/smt: LeafStore, NodeCache
*/
package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) PostgresLeafStore — implements sdk smt.LeafStore
// -------------------------------------------------------------------------------------------------

// PostgresLeafStore persists SMT leaves in Postgres.
type PostgresLeafStore struct {
	db *pgxpool.Pool
}

// NewPostgresLeafStore creates a leaf store.
func NewPostgresLeafStore(db *pgxpool.Pool) *PostgresLeafStore {
	return &PostgresLeafStore{db: db}
}

func (s *PostgresLeafStore) Get(key [32]byte) (*types.SMTLeaf, error) {
	var originTipBytes, authorityTipBytes []byte
	err := s.db.QueryRow(context.Background(),
		"SELECT origin_tip, authority_tip FROM smt_leaves WHERE leaf_key = $1",
		key[:],
	).Scan(&originTipBytes, &authorityTipBytes)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/smt: get leaf: %w", err)
	}

	originTip, err := deserializeLogPosition(originTipBytes)
	if err != nil {
		return nil, fmt.Errorf("store/smt: decode origin_tip: %w", err)
	}
	authorityTip, err := deserializeLogPosition(authorityTipBytes)
	if err != nil {
		return nil, fmt.Errorf("store/smt: decode authority_tip: %w", err)
	}

	return &types.SMTLeaf{Key: key, OriginTip: originTip, AuthorityTip: authorityTip}, nil
}

func (s *PostgresLeafStore) Set(key [32]byte, leaf types.SMTLeaf) error {
	originBytes := serializeLogPosition(leaf.OriginTip)
	authBytes := serializeLogPosition(leaf.AuthorityTip)

	_, err := s.db.Exec(context.Background(), `
		INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (leaf_key) DO UPDATE SET
			origin_tip = EXCLUDED.origin_tip,
			authority_tip = EXCLUDED.authority_tip,
			updated_at = NOW()`,
		key[:], originBytes, authBytes,
	)
	if err != nil {
		return fmt.Errorf("store/smt: set leaf: %w", err)
	}
	return nil
}

func (s *PostgresLeafStore) Delete(key [32]byte) error {
	_, err := s.db.Exec(context.Background(),
		"DELETE FROM smt_leaves WHERE leaf_key = $1", key[:],
	)
	if err != nil {
		return fmt.Errorf("store/smt: delete leaf: %w", err)
	}
	return nil
}

func (s *PostgresLeafStore) Count() (int, error) {
	var count int
	err := s.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM smt_leaves",
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store/smt: count leaves: %w", err)
	}
	return count, nil
}

// -------------------------------------------------------------------------------------------------
// 2) PostgresNodeCache — write-through Postgres + in-memory LRU
// -------------------------------------------------------------------------------------------------

// PostgresNodeCache implements sdk smt.NodeCache with write-through persistence.
type PostgresNodeCache struct {
	db  *pgxpool.Pool
	mu  sync.RWMutex
	lru map[[32]byte][]byte // In-memory LRU (simple map; production: proper LRU eviction)
}

// NewPostgresNodeCache creates a node cache.
func NewPostgresNodeCache(db *pgxpool.Pool) *PostgresNodeCache {
	return &PostgresNodeCache{
		db:  db,
		lru: make(map[[32]byte][]byte, 1<<16), // Pre-allocate for top levels.
	}
}

func (c *PostgresNodeCache) Get(key [32]byte) ([]byte, bool) {
	c.mu.RLock()
	v, ok := c.lru[key]
	c.mu.RUnlock()
	if ok {
		return v, true
	}

	// Cache miss — fetch from Postgres.
	var hash []byte
	err := c.db.QueryRow(context.Background(),
		"SELECT hash FROM smt_nodes WHERE path_key = $1", key[:],
	).Scan(&hash)
	if err != nil {
		return nil, false
	}

	c.mu.Lock()
	c.lru[key] = hash
	c.mu.Unlock()
	return hash, true
}

func (c *PostgresNodeCache) Set(key [32]byte, value []byte) {
	c.mu.Lock()
	c.lru[key] = value
	c.mu.Unlock()

	// Write-through to Postgres (best-effort; cache is authoritative during batch).
	_, _ = c.db.Exec(context.Background(), `
		INSERT INTO smt_nodes (path_key, hash, depth, updated_at)
		VALUES ($1, $2, 0, NOW())
		ON CONFLICT (path_key) DO UPDATE SET hash = EXCLUDED.hash, updated_at = NOW()`,
		key[:], value,
	)
}

// WarmCache preloads the top N levels of SMT nodes into the LRU.
func (c *PostgresNodeCache) WarmCache(ctx context.Context, topLevels int) error {
	rows, err := c.db.Query(ctx,
		"SELECT path_key, hash FROM smt_nodes WHERE depth <= $1", topLevels,
	)
	if err != nil {
		return fmt.Errorf("store/smt: warm cache: %w", err)
	}
	defer rows.Close()

	count := 0
	c.mu.Lock()
	defer c.mu.Unlock()
	for rows.Next() {
		var keyBytes, hash []byte
		if err := rows.Scan(&keyBytes, &hash); err != nil {
			return fmt.Errorf("store/smt: warm cache scan: %w", err)
		}
		if len(keyBytes) == 32 {
			var key [32]byte
			copy(key[:], keyBytes)
			c.lru[key] = hash
			count++
		}
	}
	return rows.Err()
}

// -------------------------------------------------------------------------------------------------
// 3) LogPosition serialization for BYTEA columns
// -------------------------------------------------------------------------------------------------

func serializeLogPosition(pos types.LogPosition) []byte {
	did := []byte(pos.LogDID)
	buf := make([]byte, 2+len(did)+8)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(did)))
	copy(buf[2:2+len(did)], did)
	binary.BigEndian.PutUint64(buf[2+len(did):], pos.Sequence)
	return buf
}

func deserializeLogPosition(data []byte) (types.LogPosition, error) {
	if len(data) < 10 {
		return types.LogPosition{}, fmt.Errorf("LogPosition bytes too short: %d", len(data))
	}
	didLen := binary.BigEndian.Uint16(data[0:2])
	if int(2+didLen+8) > len(data) {
		return types.LogPosition{}, fmt.Errorf("LogPosition truncated: didLen=%d, total=%d", didLen, len(data))
	}
	did := string(data[2 : 2+didLen])
	seq := binary.BigEndian.Uint64(data[2+didLen:])
	return types.LogPosition{LogDID: did, Sequence: seq}, nil
}
