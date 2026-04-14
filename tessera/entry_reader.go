/*
FILE PATH: tessera/entry_reader.go

Entry byte storage interface. Postgres is an index. Tessera is the source
of truth for entry bytes. Always.

The EntryReader/EntryWriter interfaces decouple byte storage from the index.
Production: TesseraEntryReader reads/writes entry tiles.
Tests: InMemoryEntryStore stores bytes in a map.

TESSERA TILE FORMAT (c2sp.org/tlog-tiles):
  Entry bundles pack entries sequentially:
    [uint16 big-endian length][data bytes] × N entries per tile
  Each tile holds up to 256 entries. Tiles are immutable after write.

ORTHOLOG ENTRY DATA:
  Tessera stores one "data" blob per entry. Ortholog encodes two fields
  (canonical_bytes + sig_bytes) into this blob using a length prefix:
    [4-byte big-endian canonical_len][canonical_bytes][sig_bytes]
  This encoding is internal to the operator. The SDK wire format
  (envelope.AppendSignature) is a different concern.

KEY ARCHITECTURAL DECISIONS:
  - EntryReader is the ONLY source of canonical_bytes and sig_bytes.
  - Postgres entry_index stores ONLY queryable metadata (~50 bytes/row).
  - ReadEntryBatch is tile-aware: entries in the same tile = 1 read.
  - WriteEntry is called at admission time (submission.go step 9).
  - Entry tiles are immutable after write — cache indefinitely.
*/
package tessera

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
)

// EntriesPerTile is the number of entries packed into a single entry tile.
// This matches Tessera's default bundle size.
const EntriesPerTile = 256

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
// 2) Entry Data Encoding
// ─────────────────────────────────────────────────────────────────────────────

// EncodeEntryData packs canonical_bytes and sig_bytes into a single blob
// suitable for Tessera storage:
//
//	[4-byte big-endian canonical_len][canonical_bytes][sig_bytes]
func EncodeEntryData(canonical, sig []byte) []byte {
	buf := make([]byte, 4+len(canonical)+len(sig))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(canonical)))
	copy(buf[4:4+len(canonical)], canonical)
	copy(buf[4+len(canonical):], sig)
	return buf
}

// DecodeEntryData unpacks a Tessera entry data blob back into
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

// ─────────────────────────────────────────────────────────────────────────────
// 3) Tile Bundle Parsing (c2sp.org/tlog-tiles format)
// ─────────────────────────────────────────────────────────────────────────────

// ParseEntryBundle extracts the raw data blob for entry at `offset` within
// a Tessera entry tile. The tile format is:
//
//	[uint16 big-endian length][data bytes] × N
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

// ─────────────────────────────────────────────────────────────────────────────
// 4) TesseraEntryReader — production implementation (reads entry tiles)
// ─────────────────────────────────────────────────────────────────────────────

// TesseraEntryReader reads entry bytes from Tessera entry tiles.
// Each tile holds up to 256 entries. Tiles are immutable and LRU-cached.
type TesseraEntryReader struct {
	tileReader *TileReader
}

// NewTesseraEntryReader creates an entry reader backed by Tessera tiles.
func NewTesseraEntryReader(tileReader *TileReader) *TesseraEntryReader {
	return &TesseraEntryReader{tileReader: tileReader}
}

// ReadEntry reads a single entry's bytes from the entry tile at seq's position.
func (r *TesseraEntryReader) ReadEntry(seq uint64) (RawEntry, error) {
	tileIndex := seq / EntriesPerTile
	offset := seq % EntriesPerTile

	tileData, err := r.tileReader.ReadTile(context.Background(), 0, tileIndex)
	if err != nil {
		return RawEntry{}, fmt.Errorf("tessera/entry_reader: read tile %d: %w", tileIndex, err)
	}

	entryData, err := ParseEntryBundle(tileData, offset)
	if err != nil {
		return RawEntry{}, fmt.Errorf("tessera/entry_reader: seq %d: %w", seq, err)
	}

	canonical, sig, err := DecodeEntryData(entryData)
	if err != nil {
		return RawEntry{}, fmt.Errorf("tessera/entry_reader: seq %d: %w", seq, err)
	}

	return RawEntry{CanonicalBytes: canonical, SigBytes: sig}, nil
}

// ReadEntryBatch reads multiple entries, grouping by tile for efficiency.
// Entries in the same tile (within 256 of each other) cost 1 tile read.
func (r *TesseraEntryReader) ReadEntryBatch(seqs []uint64) ([]RawEntry, error) {
	results := make([]RawEntry, len(seqs))

	// Group sequences by tile index.
	type tileReq struct {
		resultIdx int
		offset    uint64
	}
	tileGroups := make(map[uint64][]tileReq)
	for i, seq := range seqs {
		tileIdx := seq / EntriesPerTile
		offset := seq % EntriesPerTile
		tileGroups[tileIdx] = append(tileGroups[tileIdx], tileReq{resultIdx: i, offset: offset})
	}

	// Fetch each tile once, extract all needed entries.
	for tileIdx, reqs := range tileGroups {
		tileData, err := r.tileReader.ReadTile(context.Background(), 0, tileIdx)
		if err != nil {
			return nil, fmt.Errorf("tessera/entry_reader: read tile %d: %w", tileIdx, err)
		}

		for _, req := range reqs {
			entryData, err := ParseEntryBundle(tileData, req.offset)
			if err != nil {
				return nil, fmt.Errorf("tessera/entry_reader: seq %d: %w",
					tileIdx*EntriesPerTile+req.offset, err)
			}

			canonical, sig, err := DecodeEntryData(entryData)
			if err != nil {
				return nil, fmt.Errorf("tessera/entry_reader: seq %d decode: %w",
					tileIdx*EntriesPerTile+req.offset, err)
			}

			results[req.resultIdx] = RawEntry{CanonicalBytes: canonical, SigBytes: sig}
		}
	}

	return results, nil
}

// WriteEntry stores entry bytes via Tessera. Called at admission time.
// Tessera manages the tile packing — we encode canonical+sig into a single
// data blob and submit it. The tile bundle format is handled by Tessera's
// MarshalBundleData (uint16 length prefix + data).
func (r *TesseraEntryReader) WriteEntry(seq uint64, canonical []byte, sig []byte) error {
	// In production, this calls Tessera's Add/Append API with:
	//   tessera.NewEntry(EncodeEntryData(canonical, sig))
	// The TesseraClient.AppendLeaf path handles this.
	// Tessera assigns the index and packs into tiles.
	//
	// For now, this is a no-op — the InMemoryEntryStore is used in tests,
	// and production wiring goes through TesseraClient.AppendLeaf which
	// bypasses WriteEntry entirely (Tessera controls tile layout).
	_ = seq
	_ = canonical
	_ = sig
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) InMemoryEntryStore — test implementation
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
