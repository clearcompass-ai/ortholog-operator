/*
FILE PATH: tessera/entry_reader.go

Entry byte storage interface. Postgres is an index. Tessera is the source
of truth for entry bytes. Always.

The EntryReader/EntryWriter interfaces decouple byte storage from the index.
Production: TesseraAdapter reads/writes entry tiles (8 KB immutable files).
Tests: InMemoryEntryStore stores bytes in a map.

KEY ARCHITECTURAL DECISIONS:
  - EntryReader is the ONLY source of canonical_bytes and sig_bytes.
  - Postgres entry_index stores ONLY queryable metadata (~50 bytes/row).
  - ReadEntryBatch is tile-aware: entries in the same tile = 1 read.
  - WriteEntry is called at admission time (submission.go step 9).
  - Entry tiles are immutable after write — cache indefinitely.
*/
package tessera

import (
	"fmt"
	"sync"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Interfaces
// ─────────────────────────────────────────────────────────────────────────────

// RawEntry holds the raw bytes for a single log entry.
type RawEntry struct {
	CanonicalBytes []byte
	SigBytes       []byte
}

// EntryReader reads raw entry bytes from tile storage.
// This is the ONLY source of entry bytes in the system.
type EntryReader interface {
	ReadEntry(seq uint64) (RawEntry, error)
	ReadEntryBatch(seqs []uint64) ([]RawEntry, error)
}

// EntryWriter stores raw entry bytes. Called at admission time.
type EntryWriter interface {
	WriteEntry(seq uint64, canonical []byte, sig []byte) error
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) TesseraEntryReader — production implementation (reads entry tiles)
// ─────────────────────────────────────────────────────────────────────────────

// TesseraEntryReader reads entry bytes from Tessera entry tiles.
// Each tile holds 256 entries. Tiles are immutable and LRU-cached.
type TesseraEntryReader struct {
	tileReader *TileReader
}

// NewTesseraEntryReader creates an entry reader backed by Tessera tiles.
func NewTesseraEntryReader(tileReader *TileReader) *TesseraEntryReader {
	return &TesseraEntryReader{tileReader: tileReader}
}

// ReadEntry reads a single entry's bytes from the entry tile at seq's position.
func (r *TesseraEntryReader) ReadEntry(seq uint64) (RawEntry, error) {
	batch, err := r.ReadEntryBatch([]uint64{seq})
	if err != nil {
		return RawEntry{}, err
	}
	if len(batch) == 0 {
		return RawEntry{}, fmt.Errorf("tessera/entry_reader: seq %d not found in tile", seq)
	}
	return batch[0], nil
}

// ReadEntryBatch reads multiple entries, grouping by tile for efficiency.
// Entries in the same tile (within 256 of each other) cost 1 tile read.
func (r *TesseraEntryReader) ReadEntryBatch(seqs []uint64) ([]RawEntry, error) {
	// TODO: implement tile-aware batch read.
	// For now, delegate to single reads (TileReader LRU handles caching).
	results := make([]RawEntry, len(seqs))
	for i, seq := range seqs {
		entry, err := r.readSingle(seq)
		if err != nil {
			return nil, fmt.Errorf("tessera/entry_reader: seq %d: %w", seq, err)
		}
		results[i] = entry
	}
	return results, nil
}

func (r *TesseraEntryReader) readSingle(seq uint64) (RawEntry, error) {
	// Entry tiles live at tile level 0, offset = seq / 256.
	// Within the tile, the entry is at position seq % 256.
	// The tile format packs canonical_bytes + sig_bytes per entry.
	//
	// This is a placeholder — the real implementation depends on
	// Tessera's entry tile format. The interface is stable.
	return RawEntry{}, fmt.Errorf("tessera/entry_reader: tile read not yet wired to Tessera backend")
}

// WriteEntry stores entry bytes in Tessera. Called at admission time.
// Tessera manages the tile packing — we just submit the entry.
func (r *TesseraEntryReader) WriteEntry(seq uint64, canonical []byte, sig []byte) error {
	// TODO: wire to Tessera entry submission API.
	// The TesseraClient.AppendLeaf path already handles this in production.
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) InMemoryEntryStore — test implementation
// ─────────────────────────────────────────────────────────────────────────────

// InMemoryEntryStore stores entry bytes in memory. Thread-safe.
// Implements both EntryReader and EntryWriter.
// Used by all tests — proves the rule: Postgres has no bytes.
type InMemoryEntryStore struct {
	mu      sync.RWMutex
	entries map[uint64]RawEntry
}

// NewInMemoryEntryStore creates an empty in-memory entry store.
func NewInMemoryEntryStore() *InMemoryEntryStore {
	return &InMemoryEntryStore{entries: make(map[uint64]RawEntry)}
}

// WriteEntry stores bytes in memory.
func (s *InMemoryEntryStore) WriteEntry(seq uint64, canonical []byte, sig []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[seq] = RawEntry{
		CanonicalBytes: append([]byte(nil), canonical...),
		SigBytes:       append([]byte(nil), sig...),
	}
	return nil
}

// ReadEntry retrieves bytes from memory.
func (s *InMemoryEntryStore) ReadEntry(seq uint64) (RawEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[seq]
	if !ok {
		return RawEntry{}, fmt.Errorf("entry_reader: seq %d not found", seq)
	}
	return e, nil
}

// ReadEntryBatch retrieves multiple entries from memory.
func (s *InMemoryEntryStore) ReadEntryBatch(seqs []uint64) ([]RawEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([]RawEntry, len(seqs))
	for i, seq := range seqs {
		e, ok := s.entries[seq]
		if !ok {
			return nil, fmt.Errorf("entry_reader: seq %d not found in batch", seq)
		}
		results[i] = e
	}
	return results, nil
}

// Len returns the number of stored entries.
func (s *InMemoryEntryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
