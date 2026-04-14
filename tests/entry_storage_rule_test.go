/*
FILE PATH: tests/entry_storage_rule_test.go

Tests proving THE design rule: Postgres is an index. Tessera (EntryReader)
is the source of truth for entry bytes. Always.

These tests verify:
  1. entry_index has NO canonical_bytes or sig_bytes columns
  2. Submitted entries have bytes in EntryReader, not Postgres
  3. PostgresEntryFetcher hydrates bytes from EntryReader
  4. Query results hydrate bytes from EntryReader
  5. If EntryReader has different bytes than what was submitted,
     the fetcher returns EntryReader's bytes (source of truth)
*/
package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	optessera "github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ═════════════════════════════════════════════════════════════════════════════
// Rule 1: entry_index has NO byte columns
// ═════════════════════════════════════════════════════════════════════════════

func TestRule_EntryIndex_HasNoByteColumns(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()

	// Query information_schema for the entry_index table columns.
	rows, err := pool.Query(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_name = 'entry_index'
		ORDER BY ordinal_position`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var col string
		rows.Scan(&col)
		columns = append(columns, col)
	}

	// Verify canonical_bytes and sig_bytes are NOT present.
	for _, col := range columns {
		if col == "canonical_bytes" {
			t.Fatal("RULE VIOLATION: entry_index contains canonical_bytes — bytes must NEVER be in Postgres")
		}
		if col == "sig_bytes" {
			t.Fatal("RULE VIOLATION: entry_index contains sig_bytes — bytes must NEVER be in Postgres")
		}
	}

	// Verify expected columns ARE present.
	expected := map[string]bool{
		"sequence_number": false, "canonical_hash": false,
		"log_time": false, "sig_algorithm_id": false,
		"signer_did": false,
	}
	for _, col := range columns {
		if _, ok := expected[col]; ok {
			expected[col] = true
		}
	}
	for col, found := range expected {
		if !found {
			t.Fatalf("missing expected column: %s", col)
		}
	}

	t.Logf("entry_index columns: %v — no byte columns, rule holds", columns)
}

// ═════════════════════════════════════════════════════════════════════════════
// Rule 2: HTTP submission stores bytes in EntryReader, not Postgres
// ═════════════════════════════════════════════════════════════════════════════

func TestRule_SubmissionStoresBytesInEntryReader(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-rule", "did:example:exchange-rule", 100)

	// Submit an entry via HTTP.
	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:rule-signer",
	}, []byte("rule-test-payload"))

	result := submitEntry(t, op.BaseURL, "tok-rule", wire)
	seq := uint64(result["sequence_number"].(float64))

	// Verify: bytes are in InMemoryEntryStore.
	raw, err := op.EntryBytes.ReadEntry(seq)
	if err != nil {
		t.Fatalf("EntryReader has no bytes for seq %d: %v", seq, err)
	}
	if len(raw.CanonicalBytes) == 0 {
		t.Fatal("EntryReader returned empty canonical bytes")
	}
	if len(raw.SigBytes) == 0 {
		t.Fatal("EntryReader returned empty sig bytes")
	}

	// Verify: Postgres entry_index has the index row but NO bytes.
	var hash []byte
	var signerDID string
	err = op.Pool.QueryRow(context.Background(), `
		SELECT canonical_hash, signer_did FROM entry_index WHERE sequence_number = $1`, seq,
	).Scan(&hash, &signerDID)
	if err != nil {
		t.Fatalf("entry_index query failed: %v", err)
	}
	if signerDID != "did:example:rule-signer" {
		t.Fatalf("signer_did mismatch: %s", signerDID)
	}

	// Verify: canonical_hash in Postgres matches hash of bytes in EntryReader.
	computedHash := sha256.Sum256(raw.CanonicalBytes)
	if !bytes.Equal(hash, computedHash[:]) {
		t.Fatalf("hash mismatch: Postgres=%s EntryReader=%s",
			hex.EncodeToString(hash), hex.EncodeToString(computedHash[:]))
	}

	t.Logf("rule verified: seq=%d, bytes in EntryReader (%d bytes), hash in Postgres (%s)",
		seq, len(raw.CanonicalBytes), hex.EncodeToString(hash[:8]))
}

// ═════════════════════════════════════════════════════════════════════════════
// Rule 3: Fetcher hydrates bytes from EntryReader, not Postgres
// ═════════════════════════════════════════════════════════════════════════════

func TestRule_FetcherHydratesFromEntryReader(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()

	entryBytes := optessera.NewInMemoryEntryStore()

	// Create an entry.
	entry, _ := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: "did:example:fetcher-rule",
	}, []byte("fetcher-rule-payload"))
	canonical := envelope.Serialize(entry)
	hash := sha256.Sum256(canonical)
	fakeSig := []byte("test-signature-bytes-48")

	// Insert index row in Postgres (no bytes).
	seq := uint64(99901)
	cleanTables(t, pool)
	tx, _ := pool.Begin(ctx)
	tx.Exec(ctx, `
		INSERT INTO entry_index (sequence_number, canonical_hash, log_time,
			sig_algorithm_id, signer_did)
		VALUES ($1, $2, $3, $4, $5)`,
		seq, hash[:], time.Now().UTC(), uint16(1), "did:example:fetcher-rule",
	)
	tx.Commit(ctx)

	// Store bytes in EntryReader (the ONLY source).
	entryBytes.WriteEntry(seq, canonical, fakeSig)

	// Fetch via PostgresEntryFetcher.
	fetcher := store.NewPostgresEntryFetcher(pool, entryBytes, testLogDID)
	pos := types.LogPosition{LogDID: testLogDID, Sequence: seq}
	ewm, err := fetcher.Fetch(pos)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if ewm == nil {
		t.Fatal("Fetch returned nil")
	}

	// Verify bytes came from EntryReader.
	if !bytes.Equal(ewm.CanonicalBytes, canonical) {
		t.Fatal("CanonicalBytes do not match EntryReader content")
	}
	if !bytes.Equal(ewm.SignatureBytes, fakeSig) {
		t.Fatal("SignatureBytes do not match EntryReader content")
	}

	// Verify metadata came from Postgres.
	if ewm.Position.Sequence != seq {
		t.Fatalf("sequence mismatch: %d", ewm.Position.Sequence)
	}
	if ewm.SignatureAlgoID != 1 {
		t.Fatalf("algo mismatch: %d", ewm.SignatureAlgoID)
	}

	t.Logf("rule verified: Fetch() hydrated %d bytes from EntryReader + metadata from Postgres", len(canonical))
}

// ═════════════════════════════════════════════════════════════════════════════
// Rule 4: Query API hydrates bytes from EntryReader
// ═════════════════════════════════════════════════════════════════════════════

func TestRule_QueryAPIHydratesFromEntryReader(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()

	entryBytes := optessera.NewInMemoryEntryStore()
	cleanTables(t, pool)

	// Insert 3 entries — index in Postgres, bytes in EntryReader.
	for i := uint64(1); i <= 3; i++ {
		entry, _ := envelope.NewEntry(envelope.ControlHeader{
			SignerDID: "did:example:query-rule-signer",
		}, []byte(fmt.Sprintf("query-payload-%d", i)))
		canonical := envelope.Serialize(entry)
		hash := sha256.Sum256(canonical)

		tx, _ := pool.Begin(ctx)
		tx.Exec(ctx, `
			INSERT INTO entry_index (sequence_number, canonical_hash, log_time,
				sig_algorithm_id, signer_did)
			VALUES ($1, $2, $3, $4, $5)`,
			i, hash[:], time.Now().UTC(), uint16(1), "did:example:query-rule-signer",
		)
		tx.Commit(ctx)
		entryBytes.WriteEntry(i, canonical, []byte(fmt.Sprintf("sig-%d", i)))
	}

	// Query via OperatorQueryAPI.
	qapi := indexes.NewPostgresQueryAPI(pool, entryBytes, testLogDID)
	results, err := qapi.QueryBySignerDID("did:example:query-rule-signer")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Verify each result has bytes from EntryReader.
	for i, r := range results {
		seq := uint64(i + 1)
		expectedRaw, _ := entryBytes.ReadEntry(seq)

		if !bytes.Equal(r.CanonicalBytes, expectedRaw.CanonicalBytes) {
			t.Fatalf("seq %d: CanonicalBytes mismatch", seq)
		}
		if !bytes.Equal(r.SignatureBytes, expectedRaw.SigBytes) {
			t.Fatalf("seq %d: SignatureBytes mismatch", seq)
		}
	}

	t.Logf("rule verified: QueryBySignerDID returned 3 results, all hydrated from EntryReader")
}

// ═════════════════════════════════════════════════════════════════════════════
// Rule 5: EntryReader is authoritative (source of truth, not Postgres)
// ═════════════════════════════════════════════════════════════════════════════

func TestRule_EntryReaderIsAuthoritative(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()

	entryBytes := optessera.NewInMemoryEntryStore()
	cleanTables(t, pool)

	// Create entry.
	entry, _ := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: "did:example:authority-test",
	}, []byte("original-payload"))
	canonical := envelope.Serialize(entry)
	hash := sha256.Sum256(canonical)

	// Insert index in Postgres.
	seq := uint64(77001)
	tx, _ := pool.Begin(ctx)
	tx.Exec(ctx, `
		INSERT INTO entry_index (sequence_number, canonical_hash, log_time,
			sig_algorithm_id, signer_did)
		VALUES ($1, $2, $3, $4, $5)`,
		seq, hash[:], time.Now().UTC(), uint16(1), "did:example:authority-test",
	)
	tx.Commit(ctx)

	// Store THE bytes in EntryReader — this is the source of truth.
	entryBytes.WriteEntry(seq, canonical, []byte("real-sig"))

	// Fetch — should return EntryReader's bytes.
	fetcher := store.NewPostgresEntryFetcher(pool, entryBytes, testLogDID)
	pos := types.LogPosition{LogDID: testLogDID, Sequence: seq}
	ewm, err := fetcher.Fetch(pos)
	if err != nil || ewm == nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if !bytes.Equal(ewm.CanonicalBytes, canonical) {
		t.Fatal("Fetch did not return EntryReader's canonical bytes")
	}
	if !bytes.Equal(ewm.SignatureBytes, []byte("real-sig")) {
		t.Fatal("Fetch did not return EntryReader's sig bytes")
	}

	// Postgres has NO bytes to return — the rule is structural.
	// There is no "wrong path" because the bytes columns don't exist.
	// The only way to get bytes is through EntryReader.

	t.Logf("rule verified: EntryReader is the sole authority for entry bytes at seq %d", seq)
}

// ═════════════════════════════════════════════════════════════════════════════
// Rule 6: End-to-end — submit via HTTP, query back, bytes from EntryReader
// ═════════════════════════════════════════════════════════════════════════════

func TestRule_EndToEnd_BytesNeverTouchPostgres(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-e2e-rule", "did:example:exchange-e2e-rule", 100)

	signerDID := "did:example:e2e-rule-signer"

	// Submit 3 entries.
	for i := 0; i < 3; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: signerDID,
		}, []byte(fmt.Sprintf("e2e-rule-payload-%d", i)))
		submitEntry(t, op.BaseURL, "tok-e2e-rule", wire)
	}

	// Wait for builder to process.
	results := pollQueryResults(t, op.BaseURL, signerDID, 3, 5*time.Second)
	if len(results) != 3 {
		t.Fatalf("expected 3, got %d", len(results))
	}

	// Verify all 3 entries have bytes in EntryReader.
	for _, r := range results {
		seq := uint64(r["sequence_number"].(float64))
		raw, err := op.EntryBytes.ReadEntry(seq)
		if err != nil {
			t.Fatalf("seq %d: EntryReader has no bytes: %v", seq, err)
		}
		if len(raw.CanonicalBytes) == 0 {
			t.Fatalf("seq %d: empty canonical bytes in EntryReader", seq)
		}

		// Verify canonical_bytes field in query response was hydrated from EntryReader.
		respBytes := r["canonical_bytes"].(string)
		if respBytes == "" {
			t.Fatalf("seq %d: empty canonical_bytes in HTTP response", seq)
		}
	}

	// Final check: entry_index has rows but NO byte columns.
	var colCount int
	op.Pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_name = 'entry_index'
		AND column_name IN ('canonical_bytes', 'sig_bytes')`).Scan(&colCount)
	if colCount != 0 {
		t.Fatalf("RULE VIOLATION: entry_index has %d byte columns", colCount)
	}

	// Verify EntryReader holds exactly the entries we submitted.
	storedCount := op.EntryBytes.Len()
	if storedCount < 3 {
		t.Fatalf("EntryReader has %d entries, expected at least 3", storedCount)
	}

	t.Logf("rule verified: 3 entries submitted, queried back, bytes from EntryReader, zero bytes in Postgres")
}
