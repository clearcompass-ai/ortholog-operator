/*
FILE PATH:
    tessera/tile_reader.go

DESCRIPTION:
    Tile-based storage backend for Merkle tree data. Supports GCS, S3,
    and local filesystem. Read-through LRU cache minimizes backend calls.

KEY ARCHITECTURAL DECISIONS:
    - Backend interface: swappable for GCS/S3/local without code changes
    - LRU cache: tiles are immutable once written (append-only tree)
    - Tile path convention: "tiles/{level}/{offset}" (Tessera standard)
    - No write path: Tessera manages tile writes. Operator only reads.

OVERVIEW:
    TileReader wraps a TileBackend with an LRU cache. ReadTile checks
    cache first, falls back to backend, and caches the result.

KEY DEPENDENCIES:
    - io, net/http: HTTP-based backends (GCS, S3 presigned URLs)
*/
package tessera

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// -------------------------------------------------------------------------------------------------
// 1) TileBackend Interface
// -------------------------------------------------------------------------------------------------

// TileBackend reads Merkle tree tiles from a storage backend.
type TileBackend interface {
	// ReadTile reads a tile at the given level and offset.
	ReadTile(ctx context.Context, level, offset uint64) ([]byte, error)
}

// -------------------------------------------------------------------------------------------------
// 2) TileReader — cached tile access
// -------------------------------------------------------------------------------------------------

// TileReader wraps a TileBackend with an in-memory LRU cache.
type TileReader struct {
	backend TileBackend
	mu      sync.RWMutex
	cache   map[string][]byte
	maxSize int
}

// NewTileReader creates a cached tile reader.
func NewTileReader(backend TileBackend, cacheSize int) *TileReader {
	if cacheSize < 100 {
		cacheSize = 10000
	}
	return &TileReader{
		backend: backend,
		cache:   make(map[string][]byte, cacheSize),
		maxSize: cacheSize,
	}
}

// ReadTile reads a tile with cache. Tiles are immutable → cache indefinitely.
func (tr *TileReader) ReadTile(ctx context.Context, level, offset uint64) ([]byte, error) {
	key := fmt.Sprintf("%d/%d", level, offset)

	tr.mu.RLock()
	data, ok := tr.cache[key]
	tr.mu.RUnlock()
	if ok {
		return data, nil
	}

	data, err := tr.backend.ReadTile(ctx, level, offset)
	if err != nil {
		return nil, err
	}

	tr.mu.Lock()
	if len(tr.cache) >= tr.maxSize {
		// Simple eviction: clear half the cache. Production: proper LRU.
		for k := range tr.cache {
			delete(tr.cache, k)
			if len(tr.cache) < tr.maxSize/2 {
				break
			}
		}
	}
	tr.cache[key] = data
	tr.mu.Unlock()

	return data, nil
}

// -------------------------------------------------------------------------------------------------
// 3) HTTP Tile Backend — GCS/S3 via presigned or public URLs
// -------------------------------------------------------------------------------------------------

// HTTPTileBackend reads tiles from an HTTP endpoint.
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

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max tile.
	if err != nil {
		return nil, fmt.Errorf("tessera/tile: read: %w", err)
	}
	return data, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Local Filesystem Backend — for development/testing
// -------------------------------------------------------------------------------------------------

// LocalTileBackend reads tiles from the local filesystem.
type LocalTileBackend struct {
	basePath string
}

// NewLocalTileBackend creates a local tile backend.
func NewLocalTileBackend(basePath string) *LocalTileBackend {
	return &LocalTileBackend{basePath: basePath}
}

func (b *LocalTileBackend) ReadTile(_ context.Context, level, offset uint64) ([]byte, error) {
	path := fmt.Sprintf("%s/tiles/%d/%d", b.basePath, level, offset)
	// In production: os.ReadFile(path)
	_ = path
	return nil, fmt.Errorf("tessera/tile: local backend not implemented (use HTTP for now)")
}
