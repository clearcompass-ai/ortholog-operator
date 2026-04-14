/*
FILE PATH: store/indexes/query_api.go

PostgresQueryAPI satisfies sdk log.OperatorQueryAPI. Methods are spread
across the package files — each file provides one method's SQL query.

DESIGN RULE: Postgres is an index. Tessera is the source of truth for
entry bytes. Always.

  - Queries hit entry_index for sequence numbers + metadata.
  - Entry bytes hydrated via EntryReader (tessera.EntryReader).
  - scanEntries: query rows → collect seqs + metadata → batch hydrate.
  - ReadEntryBatch is tile-aware: entries in the same tile = 1 read.
*/
package indexes

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// MaxScanCount is the hard upper limit per scan request.
const MaxScanCount = 10000

// DefaultScanCount is the default page size when count is not specified.
const DefaultScanCount = 100

// PostgresQueryAPI implements sdk log.OperatorQueryAPI.
// Metadata from entry_index (Postgres). Bytes from EntryReader (Tessera).
type PostgresQueryAPI struct {
	db     *pgxpool.Pool
	reader tessera.EntryReader
	logDID string
}

// NewPostgresQueryAPI creates the query API for a log.
func NewPostgresQueryAPI(db *pgxpool.Pool, reader tessera.EntryReader, logDID string) *PostgresQueryAPI {
	return &PostgresQueryAPI{db: db, reader: reader, logDID: logDID}
}

// indexMeta holds the metadata columns from entry_index.
type indexMeta struct {
	Seq    uint64
	Time   time.Time
	AlgoID uint16
}

// scanAndHydrate queries entry_index for metadata, then batch-hydrates
// bytes from EntryReader. This is the shared path for all 5 query methods.
func (q *PostgresQueryAPI) scanAndHydrate(ctx context.Context, rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}) ([]types.EntryWithMetadata, error) {
	defer rows.Close()

	// (1) Collect sequence numbers + metadata from Postgres.
	var metas []indexMeta
	for rows.Next() {
		var (
			seq    uint64
			lt     time.Time
			algoID int16
		)
		if err := rows.Scan(&seq, &lt, &algoID); err != nil {
			return nil, fmt.Errorf("store/indexes: scan: %w", err)
		}
		metas = append(metas, indexMeta{Seq: seq, Time: lt, AlgoID: uint16(algoID)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/indexes: rows: %w", err)
	}

	if len(metas) == 0 {
		return []types.EntryWithMetadata{}, nil
	}

	// (2) Batch-hydrate bytes from EntryReader (tile-aware).
	seqs := make([]uint64, len(metas))
	for i, m := range metas {
		seqs[i] = m.Seq
	}
	rawEntries, err := q.reader.ReadEntryBatch(seqs)
	if err != nil {
		return nil, fmt.Errorf("store/indexes: hydrate: %w", err)
	}

	// (3) Assemble []EntryWithMetadata.
	results := make([]types.EntryWithMetadata, len(metas))
	for i, m := range metas {
		results[i] = types.EntryWithMetadata{
			CanonicalBytes:  rawEntries[i].CanonicalBytes,
			LogTime:         m.Time,
			Position:        types.LogPosition{LogDID: q.logDID, Sequence: m.Seq},
			SignatureAlgoID: m.AlgoID,
			SignatureBytes:  rawEntries[i].SigBytes,
		}
	}
	return results, nil
}
