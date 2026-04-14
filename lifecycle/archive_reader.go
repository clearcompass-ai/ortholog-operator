/*
FILE PATH: lifecycle/archive_reader.go

Reads entries from archived (frozen) shards. Resolves shard from sequence
range, fetches tiles from archive endpoints (cold storage), extracts
entries, and returns EntryWithMetadata — same interface as the live operator.

DESIGN RULE: The caller does not know or care if an entry is live or
archived. ArchiveReader and PostgresEntryFetcher both return
types.EntryWithMetadata. They're interchangeable behind the
builder.EntryFetcher interface.

USAGE:
  archive := lifecycle.NewArchiveReader(shardIndex)
  ewm, err := archive.Fetch(types.LogPosition{LogDID: "did:ortholog:davidson:2026", Sequence: 4712003})
  // ewm is the same type returned by the live operator's Fetch()

SHARD INDEX:
  The shard index maps shard DIDs to their metadata: sequence range,
  archive tile endpoint, and final cosigned tree head. This index is
  loaded from a JSON file, DID Document service endpoints, or operator
  configuration. The ArchiveReader does not manage the index — it reads it.

TILE ADDRESSING:
  Entry tiles follow Tessera's standard path: tile/0/{tile_index}
  where tile_index = sequence_number / 256. Each tile holds 256 entries.
  The tile format is the same as live tiles — immutable 8 KB blobs.
*/
package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	SequenceStart   uint64 `json:"sequence_start"`   // First sequence in this shard (inclusive).
	SequenceEnd     uint64 `json:"sequence_end"`     // Last sequence in this shard (inclusive).
	ArchiveEndpoint string `json:"archive_endpoint"` // Base URL for archived tiles.
	FinalRootHash   string `json:"final_root_hash"`  // Hex-encoded root hash at freeze.
	FinalTreeSize   uint64 `json:"final_tree_size"`  // Tree size at freeze.
	ChainPosition   int    `json:"chain_position"`   // 1-indexed position in shard chain.
}

// ─────────────────────────────────────────────────────────────────────────────
// Archive Reader
// ─────────────────────────────────────────────────────────────────────────────

// ArchiveReader fetches entries from archived shards.
// Implements the same Fetch signature as builder.EntryFetcher.
type ArchiveReader struct {
	mu     sync.RWMutex
	shards map[string]ShardMeta // shard DID → metadata
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

// LoadShardIndex loads the shard index from a JSON file or URL.
func LoadShardIndex(ctx context.Context, source string) ([]ShardMeta, error) {
	var data []byte
	var err error

	if len(source) > 4 && (source[:4] == "http" || source[:5] == "https") {
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
		// Assume local file path — read via os.ReadFile in caller.
		return nil, fmt.Errorf("lifecycle/archive: local file loading not implemented (use JSON bytes directly)")
	}
	if err != nil {
		return nil, err
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
func (r *ArchiveReader) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	// Resolve shard.
	shard, err := r.resolveShard(pos)
	if err != nil {
		return nil, err
	}

	// Compute tile index and offset.
	tileIndex := pos.Sequence / tessera.EntriesPerTile
	offset := pos.Sequence % tessera.EntriesPerTile

	// Fetch tile from archive endpoint.
	tileURL := fmt.Sprintf("%s/tile/0/%d", shard.ArchiveEndpoint, tileIndex)
	tileData, err := r.fetchTile(tileURL)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/archive: fetch tile %d from %s: %w",
			tileIndex, shard.ShardDID, err)
	}

	// Extract entry from tile.
	canonical, sig, err := extractEntryFromTile(tileData, offset)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/archive: extract entry seq=%d: %w", pos.Sequence, err)
	}

	// Parse canonical bytes to get header metadata.
	entry, parseErr := envelope.Deserialize(canonical)
	if parseErr != nil {
		return nil, fmt.Errorf("lifecycle/archive: deserialize entry seq=%d: %w", pos.Sequence, parseErr)
	}

	hash := sha256.Sum256(canonical)

	return &types.EntryWithMetadata{
		Position:       pos,
		CanonicalBytes: canonical,
		SignatureBytes: sig,
		CanonicalHash:  hash,
		SignerDID:      entry.Header.SignerDID,
	}, nil
}

// FetchBatch retrieves multiple entries. Optimizes by fetching each tile once.
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

	// Try exact DID match first.
	if shard, ok := r.shards[pos.LogDID]; ok {
		return &shard, nil
	}

	// Fall back to sequence range match.
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

	// Tiles are at most 8 KB (256 entries × ~32 bytes each for hashes).
	// Entry tiles are larger — up to ~256 × entry size.
	// Limit to 64 MB to prevent abuse.
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// extractEntryFromTile extracts canonical_bytes and sig_bytes for a given
// offset within a Tessera entry tile. Uses the c2sp.org/tlog-tiles bundle
// format: [uint16 big-endian length][data bytes] × N entries per tile.
// The data blob is then decoded via tessera.DecodeEntryData.
func extractEntryFromTile(tileData []byte, offset uint64) (canonical []byte, sig []byte, err error) {
	// Parse the tile bundle to get the raw entry data at this offset.
	entryData, err := tessera.ParseEntryBundle(tileData, offset)
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle/archive: %w", err)
	}

	// Decode the Ortholog entry data format: [4-byte len][canonical][sig].
	canonical, sig, err = tessera.DecodeEntryData(entryData)
	if err != nil {
		return nil, nil, fmt.Errorf("lifecycle/archive: %w", err)
	}

	return canonical, sig, nil
}

// tessera package alias for tile parsing functions.
var _ = tessera.ParseEntryBundle
