/*
FILE PATH: store/indexes/target_root.go

QueryByTargetRoot — all entries targeting a specific root entity.
*/
package indexes

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// QueryByTargetRoot returns entries whose Target_Root matches pos.
func (q *PostgresQueryAPI) QueryByTargetRoot(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	ctx := context.TODO()
	posBytes := store.SerializeLogPosition(pos)
	rows, err := q.db.Query(ctx, `
		SELECT sequence_number, canonical_bytes, log_time, sig_algorithm_id, sig_bytes
		FROM entries WHERE target_root = $1 ORDER BY sequence_number ASC`,
		posBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/target_root: %w", err)
	}
	return scanEntries(ctx, rows, q.logDID)
}
