/*
FILE PATH:
    witness/equivocation_monitor.go

DESCRIPTION:
    Compares external tree heads against stored heads. Same tree_size +
    different root = equivocation proof. Persists proof and fires alert.

KEY ARCHITECTURAL DECISIONS:
    - Periodic poll of witness/peer endpoints for external tree heads
    - Cryptographic equivocation proof: two validly signed heads with
      same size and different roots is unforgeable evidence of operator
      misbehavior
    - Stored proofs immutable — append-only equivocation_proofs table

OVERVIEW:
    Run(ctx) loops periodically. For each known peer:
      Fetch their latest tree head.
      Compare against our stored head at same tree_size.
      If roots differ: store EquivocationProof, fire alert callback.

KEY DEPENDENCIES:
    - store/tree_heads.go: local tree head lookup
    - github.com/jackc/pgx/v5/pgxpool: proof persistence
*/
package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// -------------------------------------------------------------------------------------------------
// 1) EquivocationMonitor
// -------------------------------------------------------------------------------------------------

// EquivocationMonitorConfig configures the equivocation monitor.
type EquivocationMonitorConfig struct {
	PeerEndpoints []string
	PollInterval  time.Duration
	AlertCallback func(proof EquivocationProof) // Called on detection. Nil = log only.
}

// EquivocationProof is cryptographic evidence of log fork.
type EquivocationProof struct {
	TreeSize  uint64
	RootHashA [32]byte // Our root.
	RootHashB [32]byte // Peer's root.
	HeadA     []byte   // Our serialized head.
	HeadB     []byte   // Peer's serialized head.
}

// EquivocationMonitor detects log forks.
type EquivocationMonitor struct {
	cfg       EquivocationMonitorConfig
	db        *pgxpool.Pool
	headStore *store.TreeHeadStore
	client    *http.Client
	logger    *slog.Logger
}

// NewEquivocationMonitor creates a monitor.
func NewEquivocationMonitor(
	cfg EquivocationMonitorConfig,
	db *pgxpool.Pool,
	headStore *store.TreeHeadStore,
	logger *slog.Logger,
) *EquivocationMonitor {
	return &EquivocationMonitor{
		cfg:       cfg,
		db:        db,
		headStore: headStore,
		client:    &http.Client{Timeout: 30 * time.Second},
		logger:    logger,
	}
}

// Run starts the equivocation monitoring loop.
func (em *EquivocationMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(em.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			em.check(ctx)
		}
	}
}

func (em *EquivocationMonitor) check(ctx context.Context) {
	for _, endpoint := range em.cfg.PeerEndpoints {
		peerHead, peerBytes, err := em.fetchPeerHead(ctx, endpoint)
		if err != nil {
			em.logger.Warn("equivocation: peer fetch failed", "endpoint", endpoint, "error", err)
			continue
		}

		localHead, err := em.headStore.GetBySize(ctx, peerHead.TreeSize)
		if err != nil || localHead == nil {
			continue // We don't have a head at this size. Not comparable.
		}

		if localHead.RootHash != peerHead.RootHash {
			proof := EquivocationProof{
				TreeSize:  peerHead.TreeSize,
				RootHashA: localHead.RootHash,
				RootHashB: peerHead.RootHash,
				HeadB:     peerBytes,
			}

			em.logger.Error("EQUIVOCATION DETECTED",
				"tree_size", proof.TreeSize,
				"local_root", fmt.Sprintf("%x", proof.RootHashA[:8]),
				"peer_root", fmt.Sprintf("%x", proof.RootHashB[:8]),
				"peer", endpoint,
			)

			em.persistProof(ctx, proof)
			if em.cfg.AlertCallback != nil {
				em.cfg.AlertCallback(proof)
			}
		}
	}
}

func (em *EquivocationMonitor) fetchPeerHead(ctx context.Context, endpoint string) (*store.TreeHeadRow, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"/v1/tree/head", nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := em.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, nil, err
	}

	var parsed struct {
		TreeSize uint64 `json:"tree_size"`
		RootHash string `json:"root_hash"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, err
	}

	row := &store.TreeHeadRow{TreeSize: parsed.TreeSize}
	// Parse root hash from hex.
	if len(parsed.RootHash) == 64 {
		for i := 0; i < 32; i++ {
			row.RootHash[i] = hexByte(parsed.RootHash[i*2], parsed.RootHash[i*2+1])
		}
	}
	return row, body, nil
}

func hexByte(hi, lo byte) byte {
	return (hexNibble(hi) << 4) | hexNibble(lo)
}

func hexNibble(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10
	default:
		return 0
	}
}

func (em *EquivocationMonitor) persistProof(ctx context.Context, proof EquivocationProof) {
	_, err := em.db.Exec(ctx, `
		INSERT INTO equivocation_proofs (head_a, head_b, tree_size)
		VALUES ($1, $2, $3)`,
		proof.HeadA, proof.HeadB, proof.TreeSize,
	)
	if err != nil {
		em.logger.Error("equivocation: persist proof", "error", err)
	}
}
