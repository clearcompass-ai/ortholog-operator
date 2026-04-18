/*
FILE PATH: lifecycle/shard_manager.go

DESCRIPTION:
    Shard management — spawns a new shard (new log DID) with a genesis
    commentary entry that carries forward the prior shard's final state.

SDK v0.3.0 ALIGNMENT:
    - envelope.NewEntry requires Destination. The genesis entry lands on
      the NEW shard, so Destination = cfg.NewShardDID.
    - EventTime set to frozen-at timestamp to anchor the shard rotation
      in wall-clock time (freshness policy uses this).

INVARIANTS:
    - NewShardDID MUST differ from PriorLogDID — rotating to the same DID
      would collapse the shard boundary.
    - PriorFrozenRoot is recorded in the genesis payload so consumers can
      cryptographically bind the new shard to the old one.
    - Genesis entry is pure commentary (no Target_Root, no Authority_Path) —
      zero SMT impact. State carries forward via replay, not by reference.
*/
package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// NewShardConfig configures a shard rotation.
type NewShardConfig struct {
	OperatorDID     string
	PriorLogDID     string
	NewShardDID     string
	PriorFrozenSeq  uint64
	PriorFrozenRoot [32]byte
	FrozenAt        time.Time
	Reason          string // "capacity", "governance", "recovery", etc.
}

// ShardRotationResult is the output of StartNewShard.
type ShardRotationResult struct {
	NewShardDID       string
	GenesisEntry      *envelope.Entry
	GenesisCanonical  []byte
	RotationTimestamp time.Time
}

// StartNewShard produces the genesis commentary entry for a new shard.
//
// The genesis entry:
//   - Is signed by the operator (SignerDID = OperatorDID).
//   - Is bound to the NEW shard (Destination = NewShardDID).
//   - Carries the prior shard's final root + sequence in its payload.
//   - Is pure commentary — zero SMT impact on either shard.
//   - EventTime anchors the rotation to wall-clock time for freshness.
//
// Caller is responsible for persisting GenesisEntry to the NEW shard's
// storage and announcing the new DID via out-of-band discovery.
func StartNewShard(cfg NewShardConfig) (*ShardRotationResult, error) {
	if err := validateShardConfig(cfg); err != nil {
		return nil, err
	}

	frozenAt := cfg.FrozenAt
	if frozenAt.IsZero() {
		frozenAt = time.Now().UTC()
	}

	payloadMap := map[string]any{
		"rotation_type":     "shard_spawn",
		"prior_log_did":     cfg.PriorLogDID,
		"prior_frozen_seq":  cfg.PriorFrozenSeq,
		"prior_frozen_root": fmt.Sprintf("%x", cfg.PriorFrozenRoot[:]),
		"frozen_at":         frozenAt.Format(time.RFC3339Nano),
		"reason":            cfg.Reason,
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/shard: marshal genesis payload: %w", err)
	}

	genesisEntry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID:   cfg.OperatorDID,
		Destination: cfg.NewShardDID,   // SDK v0.3.0: required field.
		EventTime:   frozenAt.Unix(),   // Binds rotation to wall-clock time.
		// Target_Root=nil, Authority_Path=nil → commentary.
	}, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/shard: build genesis entry: %w", err)
	}

	return &ShardRotationResult{
		NewShardDID:       cfg.NewShardDID,
		GenesisEntry:      genesisEntry,
		GenesisCanonical:  envelope.Serialize(genesisEntry),
		RotationTimestamp: frozenAt,
	}, nil
}

// validateShardConfig checks the rotation invariants before entry construction.
// Fail-loud: all error paths return sentinel-wrapped errors for dispatch.
func validateShardConfig(cfg NewShardConfig) error {
	if cfg.OperatorDID == "" {
		return errors.New("lifecycle/shard: OperatorDID required")
	}
	if cfg.PriorLogDID == "" {
		return errors.New("lifecycle/shard: PriorLogDID required")
	}
	if cfg.NewShardDID == "" {
		return errors.New("lifecycle/shard: NewShardDID required")
	}
	if cfg.NewShardDID == cfg.PriorLogDID {
		return fmt.Errorf("lifecycle/shard: NewShardDID %q must differ from PriorLogDID",
			cfg.NewShardDID)
	}
	return nil
}
