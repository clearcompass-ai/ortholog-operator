/*
FILE PATH: store/indexes/query_api.go

PostgresQueryAPI satisfies sdk log.OperatorQueryAPI. Methods are spread
across the package files — each file provides one method's SQL query.
This file holds the struct, constructor, shared row scanner, and constants.

KEY ARCHITECTURAL DECISIONS:
  - Single struct: all 5 query methods on one type for clean interface satisfaction.
  - Shared scanEntries: consistent EntryWithMetadata hydration across all queries.
  - Default pagination limit: 100. Hard max: 10000 (MaxScanCount).
  - All position parameters use serialized BYTEA (same as entries table columns).
*/
package indexes

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// MaxScanCount is the hard upper limit per scan request.
const MaxScanCount = 10000

// DefaultScanCount is the default page size when count is not specified.
const DefaultScanCount = 100

// PostgresQueryAPI implements sdk log.OperatorQueryAPI.
type PostgresQueryAPI struct {
	db     *pgxpool.Pool
	logDID string
}

// NewPostgresQueryAPI creates the query API for a log.
func NewPostgresQueryAPI(db *pgxpool.Pool, logDID string) *PostgresQueryAPI {
	return &PostgresQueryAPI{db: db, logDID: logDID}
}

// scanEntries hydrates []EntryWithMetadata from query rows.
func scanEntries(ctx context.Context, rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}, logDID string) ([]types.EntryWithMetadata, error) {
	defer rows.Close()
	var results []types.EntryWithMetadata
	for rows.Next() {
		var (
			seq       uint64
			canonical []byte
			logTime   time.Time
			algoID    int16
			sigBytes  []byte
		)
		if err := rows.Scan(&seq, &canonical, &logTime, &algoID, &sigBytes); err != nil {
			return nil, fmt.Errorf("store/indexes: scan: %w", err)
		}
		results = append(results, types.EntryWithMetadata{
			CanonicalBytes:  canonical,
			LogTime:         logTime,
			Position:        types.LogPosition{LogDID: logDID, Sequence: seq},
			SignatureAlgoID: uint16(algoID),
			SignatureBytes:  sigBytes,
		})
	}
	if results == nil {
		results = []types.EntryWithMetadata{} // Never return nil; always empty slice.
	}
	return results, rows.Err()
}
