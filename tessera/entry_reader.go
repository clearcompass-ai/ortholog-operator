/*
FILE PATH:
    tessera/entry_reader.go

DESCRIPTION:
    Entry byte storage interface. Postgres is an index. The EntryReader is the
    source of truth for entry bytes. Always.

    With hash-only Tessera tiles (Conflict #1 resolution), entry data tiles
    contain 32-byte SHA-256 hashes — NOT full entry bytes. Full entry bytes
    are stored separately by the EntryWriter at admission time and served
    by the EntryReader. The TesseraEntryReader (tile-based) is removed because
    tiles no longer carry full entry data.

    Production: DiskEntryStore or GCS-backed store (future Phase 3+).
    Tests + Local Dev: InMemoryEntryStore — thread-safe in-process map.

KEY ARCHITECTURAL DECISIONS:
    - Hash-only tiles: Tessera stores SHA-256(wire_bytes) = 32 bytes per entry.
      Full wire bytes (canonical + sig_envelope) live in the operator's own
      storage via EntryWriter. This preserves SDK-D11 (1MB) within the
      tlog-tiles uint16 (64KB) spec constraint.
    - EntryReader is the ONLY source of canonical_bytes and sig_bytes.
    - Postgres entry_index stores ONLY queryable metadata (~50 bytes/row).
    - WriteEntry is called at admission time (submission.go step 9).
    - Entry encoding: [4-byte big-endian canonical_len][canonical_bytes][sig_bytes].
      This encoding is internal to the operator. The SDK wire format
      (envelope.AppendSignature) is a different concern.
    - ReadEntryBatch groups reads for efficiency (tile-aware grouping removed
      since bytes are no longer in tiles; kept for interface consistency).

OVERVIEW:
    WriteEntry(seq, canonical, sig) → encode → store in backing map/disk.
    ReadEntry(seq) → fetch from backing store → decode → RawEntry.
    ReadEntryBatch(seqs) → batch fetch → decode each → []RawEntry.

KEY DEPENDENCIES:
    - store/entries.go: PostgresEntryFetcher calls ReadEntry/ReadEntryBatch.
    - store/indexes/query_api.go: scanAndHydrate calls ReadEntryBatch.
    - api/submission.go: Calls WriteEntry at step 9 (atomic persist).
*/
package tessera

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// EntriesPerTile is the number of entries packed into a single Tessera tile.
// Retained as a constant for shard lifecycle and archive reader calculations.
const EntriesPerTile = 256

// -------------------------------------------------------------------------------------------------
// 2) Interfaces
// -------------------------------------------------------------------------------------------------

// RawEntry holds the raw bytes for a single log entry.
type RawEntry struct {
	CanonicalBytes []byte
	SigBytes       []byte
}

// EntryReader reads raw entry bytes from the operator's byte storage.
// This is the ONLY source of entry bytes in the system.
// Postgres stores index metadata only — zero bytes.
type EntryReader interface {
	ReadEntry(seq uint64) (RawEntry, error)
	ReadEntryBatch(seqs []uint64) ([]RawEntry, error)
}

// EntryWriter stores raw entry bytes. Called at admission time.
type EntryWriter interface {
	WriteEntry(seq uint64, canonical []byte, sig []byte) error
}

// -------------------------------------------------------------------------------------------------
// 3) Entry Data Encoding
// -------------------------------------------------------------------------------------------------

// EncodeEntryData packs canonical_bytes and sig_bytes into a single blob:
//
//	[4-byte big-endian canonical_len][canonical_bytes][sig_bytes]
//
// This encoding is internal to the operator's byte storage. Tessera tiles
// do NOT use this format — they store only 32-byte SHA-256 hashes.
func EncodeEntryData(canonical, sig []byte) []byte {
	buf := make([]byte, 4+len(canonical)+len(sig))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(canonical)))
	copy(buf[4:4+len(canonical)], canonical)
	copy(buf[4+len(canonical):], sig)
	return buf
}

// DecodeEntryData unpacks an encoded entry data blob back into
// canonical_bytes and sig_bytes.
func DecodeEntryData(data []byte) (canonical []byte, sig []byte, err error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("tessera/entry_reader: data too short (%d bytes)", len(data))
	}
	canonicalLen := binary.BigEndian.Uint32(data[:4])
	if uint32(len(data)-4) < canonicalLen {
		return nil, nil, fmt.Errorf("tessera/entry_reader: canonical_len %d exceeds data (%d bytes)",
			canonicalLen, len(data)-4)
	}
	canonical = data[4 : 4+canonicalLen]
	sig = data[4+canonicalLen:]
	return canonical, sig, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Tile Bundle Parsing (c2sp.org/tlog-tiles format — for archive reader)
// -------------------------------------------------------------------------------------------------

// ParseEntryBundle extracts the raw data blob for entry at `offset` within
// a Tessera entry tile. The tile format is:
//
//	[uint16 big-endian length][data bytes] × N
//
// With hash-only tiles, each entry is exactly 32 bytes (SHA-256 hash).
// This function is used by lifecycle/archive_reader.go for frozen shards
// and by proof_adapter.go for hash extraction during proof computation.
//
// Returns the data bytes for the entry at the given offset (0-indexed).
func ParseEntryBundle(tileData []byte, offset uint64) ([]byte, error) {
	pos := 0
	for i := uint64(0); i <= offset; i++ {
		if pos+2 > len(tileData) {
			return nil, fmt.Errorf("tessera/entry_reader: tile truncated at entry %d (need length prefix at byte %d, tile is %d bytes)",
				i, pos, len(tileData))
		}
		entryLen := int(binary.BigEndian.Uint16(tileData[pos : pos+2]))
		pos += 2
		if pos+entryLen > len(tileData) {
			return nil, fmt.Errorf("tessera/entry_reader: tile truncated at entry %d (need %d bytes at offset %d, tile is %d bytes)",
				i, entryLen, pos, len(tileData))
		}
		if i == offset {
			return tileData[pos : pos+entryLen], nil
		}
		pos += entryLen
	}
	return nil, fmt.Errorf("tessera/entry_reader: offset %d not found in tile", offset)
}

// -------------------------------------------------------------------------------------------------
// 5) InMemoryEntryStore — test + local dev implementation
// -------------------------------------------------------------------------------------------------

// InMemoryEntryStore stores entry bytes in memory. Thread-safe.
// Implements both EntryReader and EntryWriter.
//
// Used by all tests and local dev — proves the design rule: Postgres has no bytes.
// In production, this would be replaced with a DiskEntryStore or GCS-backed store.
//
// NOTE: With hash-only Tessera tiles, this is also the byte store for the
// read-write operator (not just tests). Admission writes bytes here at step 9.
// The builder reads bytes here for ProcessBatch (via PostgresEntryFetcher).
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
	if len(canonical) == 0 {
		return fmt.Errorf("tessera/entry_reader: WriteEntry seq=%d: empty canonical bytes", seq)
	}
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
		return RawEntry{}, fmt.Errorf("tessera/entry_reader: seq %d not found in byte store", seq)
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
			return nil, fmt.Errorf("tessera/entry_reader: seq %d not found in batch", seq)
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
