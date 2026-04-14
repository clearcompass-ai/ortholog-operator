/*
FILE PATH:
    store/indexes/schema_ref.go

DESCRIPTION:
    QueryBySchemaRef — all entries governed by a specific schema.
*/
package indexes

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type SchemaRefIndex struct {
	db     *pgxpool.Pool
	logDID string
}

func NewSchemaRefIndex(db *pgxpool.Pool, logDID string) *SchemaRefIndex {
	return &SchemaRefIndex{db: db, logDID: logDID}
}

func (idx *SchemaRefIndex) Query(ctx context.Context, posBytes []byte) ([]types.EntryWithMetadata, error) {
	rows, err := idx.db.Query(ctx, `
		SELECT sequence_number, canonical_bytes, log_time, sig_algorithm_id, sig_bytes
		FROM entries WHERE schema_ref = $1 ORDER BY sequence_number`,
		posBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/schema_ref: %w", err)
	}
	defer rows.Close()
	return scanEntries(rows, idx.logDID)
}
