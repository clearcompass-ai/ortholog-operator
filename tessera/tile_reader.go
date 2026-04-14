/*
FILE PATH: tessera/tile_reader.go

Tile-based storage backend for Merkle tree data. Read-through LRU cache
minimizes backend calls. Tiles are immutable once written (append-only tree).

KEY ARCHITECTURAL DECISIONS:
  - Backend interface: swappable for GCS/S3/local.
  - LRU with access-counter eviction (not random).
  - Tile path convention: "tiles/{level}/{offset}" (Tessera standard).
  - No write path: Tessera manages writes. Operator only reads.
*/
package tessera

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// TileBackend reads Merkle tree tiles from a storage backend.
type TileBackend interface {
	ReadTile(ctx context.Context, level, offset uint64) ([]byte, error)
}

// TileReader wraps a TileBackend with an in-memory LRU cache.
type TileReader struct {
	backend TileBackend
	mu      sync.RWMutex
	cache   map[string]tileEntry
	counter int64
	maxSize int
}

type tileEntry struct {
	data   []byte
	access int64
}

// NewTileReader creates a cached tile reader.
func NewTileReader(backend TileBackend, cacheSize int) *TileReader {
	if cacheSize < 100 {
		cacheSize = 10000
	}
	return &TileReader{
		backend: backend,
		cache:   make(map[string]tileEntry, cacheSize),
		maxSize: cacheSize,
	}
}

// ReadTile reads a tile with cache. Tiles are immutable → cache indefinitely.
func (tr *TileReader) ReadTile(ctx context.Context, level, offset uint64) ([]byte, error) {
	key := fmt.Sprintf("%d/%d", level, offset)

	tr.mu.RLock()
	entry, ok := tr.cache[key]
	tr.mu.RUnlock()
	if ok {
		tr.mu.Lock()
		tr.counter++
		entry.access = tr.counter
		tr.cache[key] = entry
		tr.mu.Unlock()
		return entry.data, nil
	}

	data, err := tr.backend.ReadTile(ctx, level, offset)
	if err != nil {
		return nil, err
	}

	tr.mu.Lock()
	if len(tr.cache) >= tr.maxSize {
		tr.evictLRU()
	}
	tr.counter++
	tr.cache[key] = tileEntry{data: data, access: tr.counter}
	tr.mu.Unlock()

	return data, nil
}

// evictLRU removes the least recently accessed 25% of entries. Caller holds mu.
func (tr *TileReader) evictLRU() {
	target := tr.maxSize * 3 / 4
	if len(tr.cache) <= target {
		return
	}
	type kv struct {
		key    string
		access int64
	}
	entries := make([]kv, 0, len(tr.cache))
	for k, v := range tr.cache {
		entries = append(entries, kv{key: k, access: v.access})
	}
	// Sort by access ascending.
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].access < entries[i].access {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	toRemove := len(tr.cache) - target
	for i := 0; i < toRemove && i < len(entries); i++ {
		delete(tr.cache, entries[i].key)
	}
}

// ─── HTTP Tile Backend ─────────────────────────────────────────────────────

// HTTPTileBackend reads tiles from an HTTP endpoint (GCS/S3 public URLs).
type HTTPTileBackend struct {
	baseURL string
	client  *http.Client
}

// NewHTTPTileBackend creates an HTTP tile backend.
func NewHTTPTileBackend(baseURL string) *HTTPTileBackend {
	return &HTTPTileBackend{
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

func (b *HTTPTileBackend) ReadTile(ctx context.Context, level, offset uint64) ([]byte, error) {
	url := fmt.Sprintf("%s/tiles/%d/%d", b.baseURL, level, offset)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("tessera/tile: build request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tessera/tile: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tessera/tile: HTTP %d for %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("tessera/tile: read: %w", err)
	}
	return data, nil
}
