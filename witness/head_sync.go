/*
FILE PATH: witness/head_sync.go

Requests K-of-N cosignatures from witnesses after each builder cycle.
Implements builder.WitnessCosigner interface.

KEY ARCHITECTURAL DECISIONS:
  - Parallel requests with per-witness timeout (30s default).
  - First-K strategy: once K valid sigs collected, cancel remaining.
  - Assembled CosignedTreeHead persisted to tree_heads table.
  - Failure to reach K → log warning, non-fatal. Never blocks builder.
*/
package witness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
)

// HeadSyncConfig configures witness cosignature collection.
type HeadSyncConfig struct {
	WitnessEndpoints  []string
	QuorumK           int
	PerWitnessTimeout time.Duration
	SchemeTag         byte
}

// HeadSync manages tree head cosignature collection.
// Implements builder.WitnessCosigner.
type HeadSync struct {
	cfg    HeadSyncConfig
	client *http.Client
	store  *store.TreeHeadStore
	logger *slog.Logger
}

// NewHeadSync creates a head sync manager.
func NewHeadSync(cfg HeadSyncConfig, treeStore *store.TreeHeadStore, logger *slog.Logger) *HeadSync {
	return &HeadSync{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.PerWitnessTimeout},
		store:  treeStore,
		logger: logger,
	}
}

// RequestCosignatures implements builder.WitnessCosigner.
// Requests K-of-N cosignatures and persists the cosigned tree head.
func (hs *HeadSync) RequestCosignatures(ctx context.Context, head types.TreeHead) error {
	if len(hs.cfg.WitnessEndpoints) == 0 {
		return nil // No witnesses configured.
	}
	if len(hs.cfg.WitnessEndpoints) < hs.cfg.QuorumK {
		return fmt.Errorf("witness/head_sync: %d endpoints < quorum %d",
			len(hs.cfg.WitnessEndpoints), hs.cfg.QuorumK)
	}

	type sigResult struct {
		sig types.WitnessSignature
		err error
	}

	results := make(chan sigResult, len(hs.cfg.WitnessEndpoints))
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, endpoint := range hs.cfg.WitnessEndpoints {
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			sig, err := hs.requestSingle(reqCtx, ep, head)
			select {
			case results <- sigResult{sig: sig, err: err}:
			case <-reqCtx.Done():
			}
		}(endpoint)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var sigs []types.WitnessSignature
	for res := range results {
		if res.err != nil {
			hs.logger.Warn("witness cosign failed", "error", res.err)
			continue
		}
		sigs = append(sigs, res.sig)
		if len(sigs) >= hs.cfg.QuorumK {
			cancel() // Cancel remaining requests.
			break
		}
	}

	if len(sigs) < hs.cfg.QuorumK {
		return fmt.Errorf("witness/head_sync: got %d sigs, need %d",
			len(sigs), hs.cfg.QuorumK)
	}

	// Persist cosigned head.
	cosigBytes, _ := json.Marshal(sigs)
	if err := hs.store.Insert(ctx, store.TreeHeadRow{
		TreeSize:     head.TreeSize,
		RootHash:     head.RootHash,
		SchemeTag:    hs.cfg.SchemeTag,
		Cosignatures: cosigBytes,
	}); err != nil {
		return fmt.Errorf("witness/head_sync: persist: %w", err)
	}

	hs.logger.Info("cosigned tree head",
		"tree_size", head.TreeSize, "signatures", len(sigs))
	return nil
}

func (hs *HeadSync) requestSingle(ctx context.Context, endpoint string, head types.TreeHead) (types.WitnessSignature, error) {
	body, _ := json.Marshal(map[string]any{
		"tree_size": head.TreeSize,
		"root_hash": fmt.Sprintf("%x", head.RootHash),
	})

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint+"/v1/cosign", bytes.NewReader(body))
	if err != nil {
		return types.WitnessSignature{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hs.client.Do(req)
	if err != nil {
		return types.WitnessSignature{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return types.WitnessSignature{}, fmt.Errorf("witness returned %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return types.WitnessSignature{}, err
	}

	var sig types.WitnessSignature
	if err := json.Unmarshal(respBody, &sig); err != nil {
		return types.WitnessSignature{}, fmt.Errorf("unmarshal witness sig: %w", err)
	}
	return sig, nil
}
