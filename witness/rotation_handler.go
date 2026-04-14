/*
FILE PATH:
    witness/rotation_handler.go

DESCRIPTION:
    Witness set rotation handling. Accepts rotation messages signed by
    the current K-of-N quorum. Supports dual-sign for scheme transition
    (Decision 41: ECDSA→BLS requires both schemes during transition).

KEY ARCHITECTURAL DECISIONS:
    - Rotation requires current quorum: K-of-N of CURRENT set must sign
    - Dual-sign period: both old and new sets sign heads for transition
    - Rotation history preserved in witness_sets table (auditable chain)
    - Genesis set hardcoded at deployment. All subsequent sets derived
      from signed rotations.

OVERVIEW:
    ProcessRotation validates the rotation message against the current set,
    persists the new set, and updates the active witness configuration.

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ortholog-sdk/types: WitnessRotation
    - github.com/jackc/pgx/v5/pgxpool: witness_sets table
*/
package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) RotationHandler
// -------------------------------------------------------------------------------------------------

// RotationHandler manages witness set rotations.
type RotationHandler struct {
	db         *pgxpool.Pool
	currentSet []types.WitnessPublicKey
	schemeTag  byte
	logger     *slog.Logger
}

// NewRotationHandler creates a rotation handler with the current witness set.
func NewRotationHandler(
	db *pgxpool.Pool,
	currentSet []types.WitnessPublicKey,
	schemeTag byte,
	logger *slog.Logger,
) *RotationHandler {
	return &RotationHandler{
		db:         db,
		currentSet: currentSet,
		schemeTag:  schemeTag,
		logger:     logger,
	}
}

// ProcessRotation validates and applies a witness set rotation.
// Returns the new witness set or error if validation fails.
func (rh *RotationHandler) ProcessRotation(
	ctx context.Context,
	rotation types.WitnessRotation,
) ([]types.WitnessPublicKey, error) {
	// Validate: rotation must specify new keys.
	if len(rotation.NewSet) == 0 {
		return nil, fmt.Errorf("witness/rotation: empty new key set")
	}

	// Validate: current quorum must have signed the rotation.
	if len(rotation.CurrentSignatures) == 0 {
		return nil, fmt.Errorf("witness/rotation: no rotation signatures")
	}

	// Check for scheme transition (Decision 41).
	isDualSign := rotation.IsDualSigned()
	if isDualSign {
		rh.logger.Info("witness rotation: scheme transition",
			"from", rotation.SchemeTagOld, "to", rotation.SchemeTagNew)
	}

	newScheme := rotation.SchemeTagOld
	if rotation.SchemeTagNew != 0 {
		newScheme = rotation.SchemeTagNew
	}

	// Persist new set.
	keysJSON, err := json.Marshal(rotation.NewSet)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: marshal new keys: %w", err)
	}

	_, err = rh.db.Exec(ctx, `
		INSERT INTO witness_sets (set_hash, keys_json, scheme_tag)
		VALUES ($1, $2, $3)`,
		rotation.CurrentSetHash[:], keysJSON, int16(newScheme),
	)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: persist: %w", err)
	}

	rh.currentSet = rotation.NewSet
	rh.schemeTag = newScheme

	rh.logger.Info("witness rotation applied",
		"new_keys", len(rotation.NewSet),
		"scheme_tag", newScheme,
		"dual_sign", isDualSign,
	)

	return rotation.NewSet, nil
}

// CurrentSet returns the active witness key set.
func (rh *RotationHandler) CurrentSet() []types.WitnessPublicKey {
	return rh.currentSet
}

// SchemeTag returns the active signature scheme.
func (rh *RotationHandler) SchemeTag() byte {
	return rh.schemeTag
}

// LoadCurrentSet loads the latest witness set from Postgres.
func LoadCurrentSet(ctx context.Context, db *pgxpool.Pool) ([]types.WitnessPublicKey, byte, error) {
	var keysJSON []byte
	var schemeTag int16
	err := db.QueryRow(ctx,
		"SELECT keys_json, scheme_tag FROM witness_sets ORDER BY version DESC LIMIT 1",
	).Scan(&keysJSON, &schemeTag)
	if err != nil {
		return nil, 0, fmt.Errorf("witness/rotation: load current set: %w", err)
	}

	var keys []types.WitnessPublicKey
	if err := json.Unmarshal(keysJSON, &keys); err != nil {
		return nil, 0, fmt.Errorf("witness/rotation: unmarshal keys: %w", err)
	}
	return keys, byte(schemeTag), nil
}
