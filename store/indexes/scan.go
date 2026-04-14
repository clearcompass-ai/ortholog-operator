/*
FILE PATH:
    store/indexes/scan.go

DESCRIPTION:
    ScanFromPosition — sequential iteration using the entries table primary key.
    For monitoring, load accounting, mirror consistency, delta buffer reconstruction.
    Pagination via start parameter. Max 10000 per call.

KEY ARCHITECTURAL DECISIONS:
    - Uses sequence_number PK directly: no secondary index needed
    - Strict ascending order: deterministic pagination
    - Hard cap at 10000: prevents unbounded result sets
*/
package indexes

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// MaxScanCount is the hard upper limit per scan request.
const MaxScanCount = 10000

type ScanIndex struct {
	db     *pgxpool.Pool
	logDID string
}

func NewScanIndex(db *pgxpool.Pool, logDID string) *ScanIndex {
	return &ScanIndex{db: db, logDID: logDID}
}

func (idx *ScanIndex) Scan(ctx context.Context, startPos uint64, count int) ([]types.EntryWithMetadata, error) {
	if count <= 0 {
		return nil, nil
	}
	if count > MaxScanCount {
		count = MaxScanCount
	}
	rows, err := idx.db.Query(ctx, `
		SELECT sequence_number, canonical_bytes, log_time, sig_algorithm_id, sig_bytes
		FROM entries WHERE sequence_number >= $1 ORDER BY sequence_number ASC LIMIT $2`,
		startPos, count,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/scan: %w", err)
	}
	defer rows.Close()
	return scanEntries(rows, idx.logDID)
}
