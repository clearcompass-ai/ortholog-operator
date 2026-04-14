/*
FILE PATH:
    store/indexes/target_root.go

DESCRIPTION:
    QueryByTargetRoot — all entries targeting a specific root entity.
*/
package indexes

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type TargetRootIndex struct {
	db     *pgxpool.Pool
	logDID string
}

func NewTargetRootIndex(db *pgxpool.Pool, logDID string) *TargetRootIndex {
	return &TargetRootIndex{db: db, logDID: logDID}
}

func (idx *TargetRootIndex) Query(ctx context.Context, posBytes []byte) ([]types.EntryWithMetadata, error) {
	rows, err := idx.db.Query(ctx, `
		SELECT sequence_number, canonical_bytes, log_time, sig_algorithm_id, sig_bytes
		FROM entries WHERE target_root = $1 ORDER BY sequence_number`,
		posBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/target_root: %w", err)
	}
	defer rows.Close()
	return scanEntries(rows, idx.logDID)
}
