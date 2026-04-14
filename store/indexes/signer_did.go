/*
FILE PATH:
    store/indexes/signer_did.go

DESCRIPTION:
    QueryBySignerDID — all entries signed by a specific DID.
    For officer audit, compliance monitoring, delegation tree reading.
*/
package indexes

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type SignerDIDIndex struct {
	db     *pgxpool.Pool
	logDID string
}

func NewSignerDIDIndex(db *pgxpool.Pool, logDID string) *SignerDIDIndex {
	return &SignerDIDIndex{db: db, logDID: logDID}
}

func (idx *SignerDIDIndex) Query(ctx context.Context, did string) ([]types.EntryWithMetadata, error) {
	rows, err := idx.db.Query(ctx, `
		SELECT sequence_number, canonical_bytes, log_time, sig_algorithm_id, sig_bytes
		FROM entries WHERE signer_did = $1 ORDER BY sequence_number`,
		did,
	)
	if err != nil {
		return nil, fmt.Errorf("store/indexes/signer_did: %w", err)
	}
	defer rows.Close()
	return scanEntries(rows, idx.logDID)
}
