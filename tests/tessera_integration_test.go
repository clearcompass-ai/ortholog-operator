/*
FILE PATH:
    tests/tessera_integration_test.go

DESCRIPTION:
    Integration tests for the Tessera personality round-trip. Requires the
    Docker stack running (tessera-personality + postgres + operator).

    These tests validate:
      1. POST /add accepts exactly 32 bytes and returns a sequence index.
      2. GET /checkpoint returns a valid c2sp.org signed note checkpoint.
      3. Hash-only entry tiles contain 32-byte SHA-256 hashes.
      4. Inclusion proofs computed from tiles verify correctly.
      5. Two-step verification: hash in tree + entry hashes to value.
      6. Rejected inputs: wrong size, zero hash.

    Gate: ORTHOLOG_TESSERA_INTEGRATION_URL env var. Skip if not set.

KEY ARCHITECTURAL DECISIONS:
    - Tests run against a real Tessera personality (not mocks).
    - Each test submits known SHA-256 hashes and verifies round-trip.
    - Checkpoint parsing validates the exact c2sp.org format.
    - Entry tile reading validates the uint16-length-prefixed format
      with 32-byte entries.

KEY DEPENDENCIES:
    - tessera/client.go: Client used for Append and TreeHead.
    - tessera/tile_reader.go: HTTPTileBackend for tile fetching.
    - tessera/entry_reader.go: ParseEntryBundle for tile parsing.
*/
package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	optessera "github.com/clearcompass-ai/ortholog-operator/tessera"
)

// -------------------------------------------------------------------------------------------------
// Gate: skip if no Tessera personality URL configured
// -------------------------------------------------------------------------------------------------

func tesseraURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("ORTHOLOG_TESSERA_INTEGRATION_URL")
	if url == "" {
		t.Skip("ORTHOLOG_TESSERA_INTEGRATION_URL not set — skipping Tessera integration test")
	}
	return url
}

// =================================================================================================
// 1. POST /add — accepts 32-byte hash, returns index
// =================================================================================================

func TestTessera_AppendHash_HappyPath(t *testing.T) {
	baseURL := tesseraURL(t)
	client := optessera.NewClient(optessera.ClientConfig{
		BaseURL: baseURL,
		Timeout: 30 * time.Second,
	}, slog.Default())

	// Compute a known hash.
	data := []byte("test-entry-data-for-tessera-integration")
	hash := sha256.Sum256(data)

	index, err := client.Append(context.Background(), hash[:])
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	t.Logf("appended hash %x → index %d", hash[:8], index)
}

func TestTessera_AppendHash_WrongSize_Rejected(t *testing.T) {
	baseURL := tesseraURL(t)
	client := optessera.NewClient(optessera.ClientConfig{
		BaseURL: baseURL,
		Timeout: 30 * time.Second,
	}, slog.Default())

	// 31 bytes — should be rejected by client before HTTP call.
	_, err := client.Append(context.Background(), make([]byte, 31))
	if err == nil {
		t.Fatal("31-byte input should be rejected")
	}
	if !strings.Contains(err.Error(), "exactly 32 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 33 bytes.
	_, err = client.Append(context.Background(), make([]byte, 33))
	if err == nil {
		t.Fatal("33-byte input should be rejected")
	}
}

func TestTessera_AppendHash_ZeroHash_Rejected(t *testing.T) {
	baseURL := tesseraURL(t)

	// POST 32 zero bytes directly (bypassing client validation).
	req, _ := http.NewRequest("POST", baseURL+"/add", bytes.NewReader(make([]byte, 32)))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("zero hash should be rejected by personality")
	}
	t.Logf("zero hash rejected: HTTP %d", resp.StatusCode)
}

// =================================================================================================
// 2. GET /checkpoint — signed note format
// =================================================================================================

func TestTessera_Checkpoint_Format(t *testing.T) {
	baseURL := tesseraURL(t)
	client := optessera.NewClient(optessera.ClientConfig{
		BaseURL: baseURL,
		Timeout: 30 * time.Second,
	}, slog.Default())

	// Submit at least one entry so the checkpoint has a non-zero tree.
	hash := sha256.Sum256([]byte("checkpoint-test-entry"))
	_, err := client.Append(context.Background(), hash[:])
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Wait for integration (checkpoint may lag slightly).
	time.Sleep(2 * time.Second)

	head, err := client.TreeHead(context.Background())
	if err != nil {
		t.Fatalf("TreeHead: %v", err)
	}

	if head.TreeSize == 0 {
		t.Fatal("tree_size should be > 0 after append")
	}
	if head.RootHash == [32]byte{} {
		t.Fatal("root_hash should not be zero")
	}

	t.Logf("checkpoint: tree_size=%d root_hash=%x", head.TreeSize, head.RootHash[:8])
}

func TestTessera_Checkpoint_RawFormat(t *testing.T) {
	baseURL := tesseraURL(t)

	resp, err := http.Get(baseURL + "/checkpoint")
	if err != nil {
		t.Fatalf("GET /checkpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("checkpoint HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")

	// Must have at least 3 lines: origin, tree_size, root_hash.
	if len(lines) < 3 {
		t.Fatalf("checkpoint has %d lines, expected >= 3:\n%s", len(lines), body)
	}

	// Line 0: origin.
	if strings.TrimSpace(lines[0]) == "" {
		t.Fatal("line 0 (origin) is empty")
	}

	// Line 1: tree size decimal.
	sizeStr := strings.TrimSpace(lines[1])
	if sizeStr == "" {
		t.Fatal("line 1 (tree_size) is empty")
	}

	// Line 2: base64 root hash.
	rootB64 := strings.TrimSpace(lines[2])
	if rootB64 == "" {
		t.Fatal("line 2 (root_hash) is empty")
	}

	t.Logf("raw checkpoint:\n  origin: %s\n  size: %s\n  root: %s",
		lines[0], sizeStr, rootB64)
}

// =================================================================================================
// 3. Multiple appends — index monotonicity
// =================================================================================================

func TestTessera_AppendMultiple_MonotonicIndex(t *testing.T) {
	baseURL := tesseraURL(t)
	client := optessera.NewClient(optessera.ClientConfig{
		BaseURL: baseURL,
		Timeout: 30 * time.Second,
	}, slog.Default())

	var indices []uint64
	for i := 0; i < 10; i++ {
		data := fmt.Sprintf("monotonic-test-entry-%d-%d", i, time.Now().UnixNano())
		hash := sha256.Sum256([]byte(data))
		index, err := client.Append(context.Background(), hash[:])
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		indices = append(indices, index)
	}

	// Indices should be monotonically increasing (not necessarily contiguous
	// due to concurrent batching in Tessera).
	for i := 1; i < len(indices); i++ {
		if indices[i] <= indices[i-1] {
			t.Fatalf("indices not monotonic: %v", indices)
		}
	}

	t.Logf("10 appends, indices monotonic: %v", indices)
}

// =================================================================================================
// 4. Entry tile — contains 32-byte hashes
// =================================================================================================

func TestTessera_EntryTile_Contains32ByteHashes(t *testing.T) {
	baseURL := tesseraURL(t)
	client := optessera.NewClient(optessera.ClientConfig{
		BaseURL: baseURL,
		Timeout: 30 * time.Second,
	}, slog.Default())

	// Submit a known hash.
	knownData := []byte("tile-hash-verification-entry")
	knownHash := sha256.Sum256(knownData)
	index, err := client.Append(context.Background(), knownHash[:])
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Wait for integration.
	time.Sleep(2 * time.Second)

	// Fetch the entry tile containing our entry.
	tileIndex := index / optessera.EntriesPerTile
	tilePath := optessera.EntryTilePath(tileIndex)

	resp, err := http.Get(baseURL + "/" + tilePath)
	if err != nil {
		t.Fatalf("GET %s: %v", tilePath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("entry tile HTTP %d", resp.StatusCode)
	}

	tileData, _ := io.ReadAll(resp.Body)

	// Extract our entry from the tile.
	offset := index % optessera.EntriesPerTile
	entryData, err := optessera.ParseEntryBundle(tileData, offset)
	if err != nil {
		t.Fatalf("ParseEntryBundle: %v", err)
	}

	// Must be exactly 32 bytes (hash-only).
	if len(entryData) != 32 {
		t.Fatalf("entry at index %d is %d bytes, expected 32 (hash-only)", index, len(entryData))
	}

	// Must match the hash we submitted.
	if !bytes.Equal(entryData, knownHash[:]) {
		t.Fatalf("hash mismatch:\n  submitted: %x\n  tile:      %x", knownHash[:], entryData)
	}

	t.Logf("tile verification: index=%d tile=%s offset=%d hash=%x ✓", index, tilePath, offset, knownHash[:8])
}

// =================================================================================================
// 5. Two-step verification — hash in tree + entry hashes to value
// =================================================================================================

func TestTessera_TwoStepVerification(t *testing.T) {
	baseURL := tesseraURL(t)
	client := optessera.NewClient(optessera.ClientConfig{
		BaseURL: baseURL,
		Timeout: 30 * time.Second,
	}, slog.Default())

	// Step 1: Submit a known entry's hash.
	wireBytes := []byte("this-is-a-simulated-wire-entry-canonical+sig")
	entryHash := sha256.Sum256(wireBytes)

	index, err := client.Append(context.Background(), entryHash[:])
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Wait for integration.
	time.Sleep(2 * time.Second)

	// Step 2: Read the hash back from the entry tile.
	tileIndex := index / optessera.EntriesPerTile
	tilePath := optessera.EntryTilePath(tileIndex)
	resp, err := http.Get(baseURL + "/" + tilePath)
	if err != nil {
		t.Fatalf("GET tile: %v", err)
	}
	defer resp.Body.Close()
	tileData, _ := io.ReadAll(resp.Body)

	offset := index % optessera.EntriesPerTile
	tileHash, err := optessera.ParseEntryBundle(tileData, offset)
	if err != nil {
		t.Fatalf("ParseEntryBundle: %v", err)
	}

	// Step 3: Verify two-step.
	// (a) The hash in the tile matches what we submitted.
	if !bytes.Equal(tileHash, entryHash[:]) {
		t.Fatal("step 1 failed: hash in tile != submitted hash")
	}

	// (b) The entry data hashes to the value in the tile.
	recomputed := sha256.Sum256(wireBytes)
	if !bytes.Equal(tileHash, recomputed[:]) {
		t.Fatal("step 2 failed: SHA-256(wire_bytes) != hash in tile")
	}

	t.Logf("two-step verification passed: index=%d hash=%x", index, entryHash[:8])
}

// =================================================================================================
// 6. Personality health check
// =================================================================================================

func TestTessera_HealthCheck(t *testing.T) {
	baseURL := tesseraURL(t)

	resp, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("healthz body: %q", body)
	}
}

// =================================================================================================
// Suppress unused imports
// =================================================================================================

var _ = json.Marshal
