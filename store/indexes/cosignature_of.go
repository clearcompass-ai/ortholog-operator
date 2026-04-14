/*
FILE PATH:
    store/indexes/cosignature_of.go

DESCRIPTION:
    QueryByCosignatureOf — certification-required per spec.
    Returns all entries whose Cosignature_Of field matches the given position.
    Primary consumer: exchange lifecycle compiling Evidence_Pointers.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ortholog-sdk/types: EntryWithMetadata, LogPosition
*/
package indexes

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// CosignatureOfIndex queries entries by Cosignature_Of.
type CosignatureOfIndex struct {
	db     *pgxpool.Pool
	logDID string
}

func NewCosignatureOfIndex(db *pgxpool.Pool, logDID string) *CosignatureOfIndex {
	return &CosignatureOfIndex{db: db, logDID: logDID}
}

func (idx *CosignatureOfIndex) Query(ctx context.Context, posBytes []byte) ([]types.EntryWithMetadata, error) {
	rows, err := idx.db.Query(ctx, `
		SELECT sequence_number, canonical_bytes, log_time, sig_algorithm_id, sig_bytes
		FROM entries WHERE cosignature_of = $1 ORDER BY sequence_number`,
		posBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/cosignature_of: %w", err)
	}
	defer rows.Close()
	return scanEntries(rows, idx.logDID)
}

// -------------------------------------------------------------------------------------------------
// Shared row scanner for all index queries
// -------------------------------------------------------------------------------------------------

func scanEntries(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}, logDID string) ([]types.EntryWithMetadata, error) {
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
			CanonicalBytes: canonical,
			LogTime:        logTime,
			Position:       types.LogPosition{LogDID: logDID, Sequence: seq},
			SignatureAlgoID: uint16(algoID),
			SignatureBytes:  sigBytes,
		})
	}
	return results, rows.Err()
}
