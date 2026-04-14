/*
FILE PATH:
    builder/commitment_publisher.go

DESCRIPTION:
    Publishes SMT derivation commitments as commentary entries on the log.
    Commentary: Target_Root=null, Authority_Path=null → zero SMT impact
    (Fix 1 discriminator). Operator DID signs.

KEY ARCHITECTURAL DECISIONS:
    - Commentary entry: no SMT leaf created or modified
    - Commitment in Domain Payload: serialized SMTDerivationCommitment
    - Frequency configurable: default every batch (production: 1000 entries or 1hr)

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ortholog-sdk/builder: GenerateBatchCommitment
    - github.com/clearcompass-ai/ortholog-sdk/core/envelope: NewEntry
*/
package builder

import (
	"context"
	"encoding/json"
	"log/slog"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// CommitmentPublisher publishes derivation commitments.
type CommitmentPublisher struct {
	operatorDID string
	logger      *slog.Logger
	// In production: submits back through the admission pipeline.
	// Here: logs the commitment for integration with the submission flow.
}

// NewCommitmentPublisher creates a commitment publisher.
func NewCommitmentPublisher(operatorDID string, logger *slog.Logger) *CommitmentPublisher {
	return &CommitmentPublisher{operatorDID: operatorDID, logger: logger}
}

// Publish generates and logs a derivation commitment for a processed batch.
func (cp *CommitmentPublisher) Publish(
	ctx context.Context,
	rangeStart, rangeEnd types.LogPosition,
	priorRoot [32]byte,
	result *sdkbuilder.BatchResult,
) {
	commitment := sdkbuilder.GenerateBatchCommitment(rangeStart, rangeEnd, priorRoot, result)

	// Serialize commitment as Domain Payload.
	payload, err := json.Marshal(commitment)
	if err != nil {
		cp.logger.Error("commitment serialization failed", "error", err)
		return
	}

	// Build commentary entry: Target_Root=null, Authority_Path=null.
	entry, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: cp.operatorDID,
		// All structural fields null → commentary (Fix 1).
	}, payload)
	if err != nil {
		cp.logger.Error("commitment entry creation failed", "error", err)
		return
	}

	_ = entry // In production: submit through operator's own admission pipeline.
	cp.logger.Info("derivation commitment published",
		"range_start", rangeStart.String(),
		"range_end", rangeEnd.String(),
		"mutations", commitment.MutationCount,
	)
}
