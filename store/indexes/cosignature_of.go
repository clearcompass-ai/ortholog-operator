/*
FILE PATH: store/indexes/cosignature_of.go

QueryByCosignatureOf — certification-required per governance spec.
Returns all entries whose Cosignature_Of field matches the given position.
Primary consumer: exchange lifecycle compiling Evidence_Pointers.
*/
package indexes

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// QueryByCosignatureOf returns entries whose Cosignature_Of matches pos.
func (q *PostgresQueryAPI) QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	ctx := context.TODO()
	posBytes := store.SerializeLogPosition(pos)
	rows, err := q.db.Query(ctx, `
		SELECT sequence_number, canonical_bytes, log_time, sig_algorithm_id, sig_bytes
		FROM entries WHERE cosignature_of = $1 ORDER BY sequence_number ASC`,
		posBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/cosignature_of: %w", err)
	}
	return scanEntries(ctx, rows, q.logDID)
}
