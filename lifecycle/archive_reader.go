/*
FILE PATH: lifecycle/archive_reader.go

Reads entries from archived (frozen) shards. Resolves shard from sequence
range, fetches tiles from archive endpoints (cold storage), extracts
entries, and returns EntryWithMetadata — same interface as the live operator.

DESIGN RULE: The caller does not know or care if an entry is live or
archived. ArchiveReader and PostgresEntryFetcher both return
types.EntryWithMetadata. They're interchangeable behind the
builder.EntryFetcher interface.

TILE FORMAT (Option B):
  Tessera entry tiles store full wire bytes (canonical + sig_envelope)
  as submitted via AppendLeaf. Each entry is length-prefixed in the tile
  bundle (c2sp.org/tlog-tiles format). To recover canonical + sig:
  envelope.StripSignature(wireBytes).
*/
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ─────────────────────────────────────────────────────────────────────────────
// Shard Metadata
// ─────────────────────────────────────────────────────────────────────────────

// ShardMeta describes an archived shard's location and range.
type ShardMeta struct {
	ShardDID        string `json:"shard_did"`
	SequenceStart   uint64 `json:"sequence_start"`
	SequenceEnd     uint64 `json:"sequence_end"`
	ArchiveEndpoint string `json:"archive_endpoint"`
	FinalRootHash   string `json:"final_root_hash"`
	FinalTreeSize   uint64 `json:"final_tree_size"`
	ChainPosition   int    `json:"chain_position"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Archive Reader
// ─────────────────────────────────────────────────────────────────────────────

// ArchiveReader fetches entries from archived shards.
// Implements the same Fetch signature as builder.EntryFetcher.
type ArchiveReader struct {
	mu     sync.RWMutex
	shards map[string]ShardMeta
	client *http.Client
}

// NewArchiveReader creates an archive reader from a shard index.
func NewArchiveReader(shards []ShardMeta) *ArchiveReader {
	index := make(map[string]ShardMeta, len(shards))
	for _, s := range shards {
		index[s.ShardDID] = s
	}
	return &ArchiveReader{
		shards: index,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// LoadShardIndex loads the shard index from a local JSON file or HTTP URL.
func LoadShardIndex(ctx context.Context, source string) ([]ShardMeta, error) {
	var data []byte
	var err error

	if len(source) > 4 && (source[:4] == "http") {
		req, reqErr := http.NewRequestWithContext(ctx, "GET", source, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			return nil, doErr
		}
		defer resp.Body.Close()
		data, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	} else {
		data, err = os.ReadFile(source)
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle/archive: read shard index %q: %w", source, err)
	}

	var shards []ShardMeta
	if err := json.Unmarshal(data, &shards); err != nil {
		return nil, fmt.Errorf("lifecycle/archive: parse shard index: %w", err)
	}
	return shards, nil
}

// AddShard adds or updates a shard in the index. Thread-safe.
func (r *ArchiveReader) AddShard(meta ShardMeta) {
	r.mu.Lock()
	r.shards[meta.ShardDID] = meta
	r.mu.Unlock()
}

// Fetch retrieves an entry from an archived shard by its log position.
// Returns the same types.EntryWithMetadata as the live operator's Fetch.
//
// Option B: Tessera tiles contain full wire bytes (canonical + sig_envelope).
// envelope.StripSignature recovers canonical, algoID, and sigBytes.
func (r *ArchiveReader) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	shard, err := r.resolveShard(pos)
	if err != nil {
		return nil, err
	}

	tileIndex := pos.Sequence / tessera.EntriesPerTile
	offset := pos.Sequence % tessera.EntriesPerTile

	tileURL := fmt.Sprintf("%s/tile/0/%d", shard.ArchiveEndpoint, tileIndex)
	tileData, err := r.fetchTile(tileURL)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/archive: fetch tile %d from %s: %w",
			tileIndex, shard.ShardDID, err)
	}

	// Extract raw entry data from tile bundle (c2sp.org/tlog-tiles format).
	wireBytes, err := tessera.ParseEntryBundle(tileData, offset)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/archive: extract entry seq=%d: %w", pos.Sequence, err)
	}

	// Option B: tile data = full wire bytes. StripSignature splits them.
	canonical, algoID, sigBytes, err := envelope.StripSignature(wireBytes)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/archive: strip signature seq=%d: %w", pos.Sequence, err)
	}

	return &types.EntryWithMetadata{
		Position:        pos,
		CanonicalBytes:  canonical,
		SignatureAlgoID: algoID,
		SignatureBytes:  sigBytes,
	}, nil
}

// FetchBatch retrieves multiple entries.
func (r *ArchiveReader) FetchBatch(positions []types.LogPosition) ([]*types.EntryWithMetadata, error) {
	results := make([]*types.EntryWithMetadata, len(positions))
	for i, pos := range positions {
		ewm, err := r.Fetch(pos)
		if err != nil {
			return nil, fmt.Errorf("lifecycle/archive: batch fetch pos %d: %w", i, err)
		}
		results[i] = ewm
	}
	return results, nil
}

// ShardFor returns the shard metadata for a given position, or nil if not found.
func (r *ArchiveReader) ShardFor(pos types.LogPosition) *ShardMeta {
	shard, err := r.resolveShard(pos)
	if err != nil {
		return nil
	}
	return shard
}

// Shards returns all known shard metadata.
func (r *ArchiveReader) Shards() []ShardMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ShardMeta, 0, len(r.shards))
	for _, s := range r.shards {
		result = append(result, s)
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal
// ─────────────────────────────────────────────────────────────────────────────

func (r *ArchiveReader) resolveShard(pos types.LogPosition) (*ShardMeta, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if shard, ok := r.shards[pos.LogDID]; ok {
		return &shard, nil
	}

	for _, shard := range r.shards {
		if pos.Sequence >= shard.SequenceStart && pos.Sequence <= shard.SequenceEnd {
			return &shard, nil
		}
	}

	return nil, fmt.Errorf("lifecycle/archive: no shard found for %s@%d", pos.LogDID, pos.Sequence)
}

func (r *ArchiveReader) fetchTile(url string) ([]byte, error) {
	resp, err := r.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tile fetch returned %d", resp.StatusCode)
	}

	// Entry tiles: 256 entries × ~1KB avg = ~256KB typical. Cap at 64 MB.
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
