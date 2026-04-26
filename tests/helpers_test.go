/*
FILE PATH: tests/helpers_test.go

Shared test infrastructure for the operator integration suite.

Provides:
  - In-memory SDK harness (testHarness) that wraps the SDK builder with
    convenience methods for SMT state inspection.
  - Mock fetcher and schema resolver implementing the SDK builder contracts.
  - Postgres connection/migration helpers gated by ORTHOLOG_TEST_DSN.
  - Bulk entry generation for determinism and scale tests.
  - SDK v0.1.0 admission helpers — buildStampParams, verifyStampForTest —
    that wrap the post-Wave-1.5 GenerateStamp(StampParams) and
    VerifyStamp(8-arg) APIs so test code stays readable.

PR 2 — WAVE 1 CHANGES:
  - Split the conflated testLogDID into TWO distinct constants:
    testLogDID       — the operator's PHYSICAL LOG identity
    testExchangeDID  — the EXCHANGE DID this test operator admits for
    These are separate concepts with separate values. Tests that used
    the same string for both roles are structurally impossible to write
    after this change.
  - Added testHeader(destinationDID, signerDID) as the REQUIRED
    constructor for ControlHeader in this package. Omitting either
    mandatory arg is a compile-time error (not a runtime panic),
    catching the "forgot Destination" bug at development time.
  - Updated generateEntries, addRootEntity, addDelegation,
    addScopeEntity to construct headers via testHeader with
    testExchangeDID. These helpers previously used p.LogDID for the
    Destination field (implicitly conflating log and exchange).
*/
package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/store"
	optessera "github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

// testLogDID is the operator's PHYSICAL LOG identity. Used for:
//   - startTestOperator's deps.LogDID
//   - Mode B stamp's LogDID binding
//   - LogPosition.LogDID in generated positions (pos() helper)
//   - Tessera origin, Postgres advisory lock scope
//
// Distinct from testExchangeDID by construction: they hold different
// string values so any test that conflates them fails loudly.
const testLogDID = "did:ortholog:test:log"

// testExchangeDID is the EXCHANGE DID this test operator admits for. Used for:
//   - ControlHeader.Destination in every test entry (via testHeader)
//   - startTestOperator's deps.Identity.Registries map key
//   - seedSession's exchange_did column for Mode A tests
//
// In multi-exchange tests (startTestOperatorMultiExchange), this is the
// default single-exchange value; additional exchange DIDs are passed as
// explicit constants at the call site.
const testExchangeDID = "did:web:exchange.test.example"

// testEpochWindowSeconds is the epoch length used by HTTP integration tests.
// 1 hour matches the production default (ORTHOLOG_EPOCH_WINDOW_SECONDS=3600)
// and is wired into testserver_test.go's SubmissionDeps.Admission.
const testEpochWindowSeconds = 3600

// testEpochAcceptanceWindow matches the operator-side default. window=1
// accepts stamps from [current-1, current+1], tolerating clock skew.
const testEpochAcceptanceWindow = 1

// testEntryBytes is the package-level InMemoryEntryStore shared by all
// Postgres-backed query tests. Reset in cleanTables. This is the ONLY
// source of entry bytes in the test suite (Postgres stores index only).
var testEntryBytes = optessera.NewInMemoryEntryStore()

// ─────────────────────────────────────────────────────────────────────────────
// ControlHeader constructor — REQUIRED for all test entry construction
// ─────────────────────────────────────────────────────────────────────────────

// testHeader is the REQUIRED constructor for ControlHeader in this test
// package. Two mandatory positional arguments — destination exchange DID
// and signer DID — correspond to the two fields that NewEntry validates
// as non-empty. Omission is a compile error (missing argument), not a
// runtime panic later in the pipeline.
//
// Usage:
//
//	h := testHeader(testExchangeDID, "did:example:alice")
//	h.AuthorityPath = sameSigner()
//	h.TargetRoot    = ptrTo(pos(1))
//	entry := makeEntry(t, h, payload)
//
// For normal single-exchange tests, pass testExchangeDID. For tests that
// deliberately construct entries with mismatched destinations (for
// cross-exchange rejection tests), pass an explicit string that isn't
// in the operator's admitted-exchanges set.
//
// DO NOT use envelope.ControlHeader{} literals elsewhere in this
// package. CI hygiene (PR 3) grep-bans direct literals outside
// helpers_test.go and destination_binding_test.go.
func testHeader(destinationDID, signerDID string) envelope.ControlHeader {
	if destinationDID == "" {
		panic("testHeader: destinationDID required — pass testExchangeDID for normal tests")
	}
	if signerDID == "" {
		panic("testHeader: signerDID required")
	}
	return envelope.ControlHeader{
		SignerDID:   signerDID,
		Destination: destinationDID,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Position helpers
// ─────────────────────────────────────────────────────────────────────────────

func pos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: testLogDID, Sequence: seq}
}

func foreignPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: "did:ortholog:foreign", Sequence: seq}
}

func ptrTo[T any](v T) *T { return &v }

// ─────────────────────────────────────────────────────────────────────────────
// Authority path helpers
// ─────────────────────────────────────────────────────────────────────────────

func sameSigner() *envelope.AuthorityPath {
	v := envelope.AuthoritySameSigner
	return &v
}

func delegation() *envelope.AuthorityPath {
	v := envelope.AuthorityDelegation
	return &v
}

func scopeAuth() *envelope.AuthorityPath {
	v := envelope.AuthorityScopeAuthority
	return &v
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry construction helpers
// ─────────────────────────────────────────────────────────────────────────────

func makeEntry(t *testing.T, h envelope.ControlHeader, payload []byte) *envelope.Entry {
	t.Helper()
	entry, err := envelope.NewEntry(h, payload)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	return entry
}

func canonicalHashBytes(entry *envelope.Entry) [32]byte {
	return envelope.EntryIdentity(entry)
}

// ─────────────────────────────────────────────────────────────────────────────
// SDK admission helpers (post-Wave-1.5 API)
// ─────────────────────────────────────────────────────────────────────────────

// currentTestEpoch returns the epoch index the operator's verifier will
// compute for "now" given testEpochWindowSeconds. Test fixtures must use
// this exact value, otherwise VerifyStamp rejects the stamp as out-of-window.
func currentTestEpoch() uint64 {
	return uint64(time.Now().UTC().Unix() / int64(testEpochWindowSeconds))
}

// buildStampParams constructs the StampParams struct that GenerateStamp
// expects. Keeps test call sites readable instead of repeating six fields.
//
// Caller is responsible for the entry hash, log DID, and difficulty.
// Hash function defaults to SHA-256 (operator default) and Argon2id params
// to nil. Submitter commit is left absent (Mode B without rate-limit binding).
func buildStampParams(entryHash [32]byte, logDID string, difficulty uint32) admission.StampParams {
	return admission.StampParams{
		EntryHash:  entryHash,
		LogDID:     logDID,
		Difficulty: difficulty,
		HashFunc:   admission.HashSHA256,
		Epoch:      currentTestEpoch(),
	}
}

// verifyStampForTest constructs a types.AdmissionProof from the StampParams
// + nonce and runs VerifyStamp with the test epoch and acceptance window.
// Returns the verification error (or nil on success).
//
// This is the canonical test-side equivalent of the operator's Step 7
// admission verification — uses ProofFromWire's API form, the same hash
// function, and the same epoch/window the operator uses at runtime.
func verifyStampForTest(p admission.StampParams, nonce uint64, expectedLog string, minDifficulty uint32) error {
	apiProof := &types.AdmissionProof{
		Mode:            types.AdmissionModeB,
		Nonce:           nonce,
		TargetLog:       p.LogDID,
		Difficulty:      p.Difficulty,
		Epoch:           p.Epoch,
		SubmitterCommit: p.SubmitterCommit,
	}
	return admission.VerifyStamp(
		apiProof,
		p.EntryHash,
		expectedLog,
		minDifficulty,
		p.HashFunc,
		p.Argon2idParams,
		currentTestEpoch(),
		uint64(testEpochAcceptanceWindow),
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// String helpers
// ─────────────────────────────────────────────────────────────────────────────

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 4)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func didForUser(i int) string {
	return "did:example:user" + itoa(i)
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock fetcher
// ─────────────────────────────────────────────────────────────────────────────

type mockFetcher struct {
	mu      sync.RWMutex
	entries map[types.LogPosition]*types.EntryWithMetadata
}

func newMockFetcher() *mockFetcher {
	return &mockFetcher{entries: make(map[types.LogPosition]*types.EntryWithMetadata)}
}

func (f *mockFetcher) Fetch(p types.LogPosition) (*types.EntryWithMetadata, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.entries[p], nil
}

func (f *mockFetcher) storeEntry(p types.LogPosition, entry *envelope.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[p] = &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry),
		LogTime:        time.Now(),
		Position:       p,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock schema resolver
// ─────────────────────────────────────────────────────────────────────────────

type mockSchemaResolver struct {
	commutative bool
}

func (r *mockSchemaResolver) Resolve(ref types.LogPosition, fetcher builder.EntryFetcher) (*builder.SchemaResolution, error) {
	return &builder.SchemaResolution{
		IsCommutative:   r.commutative,
		DeltaWindowSize: 10,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory test harness (wraps SDK builder with convenience methods)
// ─────────────────────────────────────────────────────────────────────────────

type testHarness struct {
	tree    *smt.Tree
	fetcher *mockFetcher
	schema  builder.SchemaResolver
	buffer  *builder.DeltaWindowBuffer
}

func newHarness() *testHarness {
	return &testHarness{
		tree:    smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache()),
		fetcher: newMockFetcher(),
		buffer:  builder.NewDeltaWindowBuffer(10),
	}
}

// addRootEntity creates a root entity leaf in the SMT and stores the entry.
//
// The entry lives at position p (pos() assigns testLogDID) but its
// Destination is testExchangeDID. This separation is deliberate: p is
// the physical location, Destination is the exchange binding.
func (h *testHarness) addRootEntity(t *testing.T, p types.LogPosition, signerDID string) *envelope.Entry {
	t.Helper()
	hdr := testHeader(testExchangeDID, signerDID)
	hdr.AuthorityPath = sameSigner()
	entry := makeEntry(t, hdr, nil)
	h.fetcher.storeEntry(p, entry)
	key := smt.DeriveKey(p)
	leaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}
	if err := h.tree.SetLeaf(key, leaf); err != nil {
		t.Fatal(err)
	}
	return entry
}

// addDelegation creates a delegation entry and leaf.
func (h *testHarness) addDelegation(t *testing.T, delegPos types.LogPosition, signerDID, delegateDID string) *envelope.Entry {
	t.Helper()
	hdr := testHeader(testExchangeDID, signerDID)
	hdr.AuthorityPath = sameSigner()
	hdr.DelegateDID = &delegateDID
	entry := makeEntry(t, hdr, nil)
	h.fetcher.storeEntry(delegPos, entry)
	key := smt.DeriveKey(delegPos)
	_ = h.tree.SetLeaf(key, types.SMTLeaf{Key: key, OriginTip: delegPos, AuthorityTip: delegPos})
	return entry
}

// addScopeEntity creates a scope entity with an authority set.
func (h *testHarness) addScopeEntity(t *testing.T, p types.LogPosition, signerDID string, authSet map[string]struct{}) *envelope.Entry {
	t.Helper()
	hdr := testHeader(testExchangeDID, signerDID)
	hdr.AuthorityPath = sameSigner()
	hdr.AuthoritySet = authSet
	entry := makeEntry(t, hdr, nil)
	h.fetcher.storeEntry(p, entry)
	key := smt.DeriveKey(p)
	_ = h.tree.SetLeaf(key, types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p})
	return entry
}

// process runs a single entry through ProcessBatch.
func (h *testHarness) process(t *testing.T, entry *envelope.Entry, p types.LogPosition) *builder.BatchResult {
	t.Helper()
	h.fetcher.storeEntry(p, entry)
	result, err := builder.ProcessBatch(
		h.tree, []*envelope.Entry{entry}, []types.LogPosition{p},
		h.fetcher, h.schema, testLogDID, h.buffer,
	)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	return result
}

// processBatch runs multiple entries through ProcessBatch.
func (h *testHarness) processBatch(t *testing.T, entries []*envelope.Entry, positions []types.LogPosition) *builder.BatchResult {
	t.Helper()
	for i, entry := range entries {
		h.fetcher.storeEntry(positions[i], entry)
	}
	result, err := builder.ProcessBatch(
		h.tree, entries, positions,
		h.fetcher, h.schema, testLogDID, h.buffer,
	)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	return result
}

func (h *testHarness) leafOriginTip(t *testing.T, p types.LogPosition) types.LogPosition {
	t.Helper()
	leaf, err := h.tree.GetLeaf(smt.DeriveKey(p))
	if err != nil || leaf == nil {
		t.Fatalf("leaf not found for %s", p)
	}
	return leaf.OriginTip
}

func (h *testHarness) leafAuthorityTip(t *testing.T, p types.LogPosition) types.LogPosition {
	t.Helper()
	leaf, err := h.tree.GetLeaf(smt.DeriveKey(p))
	if err != nil || leaf == nil {
		t.Fatalf("leaf not found for %s", p)
	}
	return leaf.AuthorityTip
}

func (h *testHarness) leafExists(t *testing.T, p types.LogPosition) bool {
	t.Helper()
	leaf, err := h.tree.GetLeaf(smt.DeriveKey(p))
	return err == nil && leaf != nil
}

func (h *testHarness) root(t *testing.T) [32]byte {
	t.Helper()
	r, err := h.tree.Root()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ─────────────────────────────────────────────────────────────────────────────
// Bulk entry generation
// ─────────────────────────────────────────────────────────────────────────────

// generateEntries produces n test entries with sequential positions.
//
// Every entry is bound to testExchangeDID (the test operator's admitted
// exchange). Positions are issued via pos(), which tags them with
// testLogDID (the physical log identity). The two DIDs are distinct by
// construction.
func generateEntries(n int) ([]*envelope.Entry, []types.LogPosition) {
	entries := make([]*envelope.Entry, n)
	positions := make([]types.LogPosition, n)
	for i := 0; i < n; i++ {
		hdr := testHeader(testExchangeDID, didForUser(i/10))
		if i%5 == 0 {
			v := envelope.AuthoritySameSigner
			hdr.AuthorityPath = &v
		}
		entry, err := envelope.NewEntry(hdr, []byte{byte(i)})
		if err != nil {
			panic(fmt.Sprintf("generateEntries[%d]: NewEntry failed: %v", i, err))
		}
		entries[i] = entry
		positions[i] = pos(uint64(i + 1))
	}
	return entries, positions
}

// runSDKBuilder runs ProcessBatch against a fresh in-memory tree.
func runSDKBuilder(t *testing.T, entries []*envelope.Entry, positions []types.LogPosition) *builder.BatchResult {
	t.Helper()
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	f := newMockFetcher()
	for i, e := range entries {
		f.storeEntry(positions[i], e)
	}
	result, err := builder.ProcessBatch(tree, entries, positions, f, nil, testLogDID, builder.NewDeltaWindowBuffer(10))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Postgres helpers (for integration tests requiring a real database)
// ─────────────────────────────────────────────────────────────────────────────

// skipIfNoPostgres checks for ORTHOLOG_TEST_DSN. Returns a pool or skips the test.
// Cleans all tables for isolation.
func skipIfNoPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := connectPostgres(t)
	cleanTables(t, pool)
	t.Cleanup(func() {
		cleanTables(t, pool)
		pool.Close()
	})
	return pool
}

// connectPostgres returns a pool WITHOUT cleaning tables.
// Use for tests that depend on data from a prior test (e.g., QueryIndex after BulkInsert).
func connectPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ORTHOLOG_TEST_DSN")
	if dsn == "" {
		t.Skip("ORTHOLOG_TEST_DSN not set — skipping Postgres integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping test database: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("run migrations: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func cleanTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	tables := []string{
		"builder_queue", "tree_head_sigs", "entry_index", "smt_leaves", "smt_nodes",
		"credits", "tree_heads", "delta_window_buffers",
		"witness_sets", "equivocation_proofs", "sessions",
	}
	for _, table := range tables {
		if _, err := pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			// Table might not exist yet; ignore.
		}
	}
	// Reset sequence.
	_, _ = pool.Exec(ctx, "ALTER SEQUENCE entry_sequence RESTART WITH 1")

	// Reset package-level entry byte store.
	testEntryBytes = optessera.NewInMemoryEntryStore()
}

// insertTestEntry directly inserts an entry into Postgres for query testing.
func insertTestEntry(t *testing.T, pool *pgxpool.Pool, seq uint64, entry *envelope.Entry, logDID string) {
	t.Helper()
	ctx := context.Background()
	hash := envelope.EntryIdentity(entry)
	canonical := envelope.Serialize(entry)
	logTime := time.Now().UTC()

	var targetRoot, cosigOf, schemaRef []byte
	if entry.Header.TargetRoot != nil {
		targetRoot = store.SerializeLogPosition(*entry.Header.TargetRoot)
	}
	if entry.Header.CosignatureOf != nil {
		cosigOf = store.SerializeLogPosition(*entry.Header.CosignatureOf)
	}
	if entry.Header.SchemaRef != nil {
		schemaRef = store.SerializeLogPosition(*entry.Header.SchemaRef)
	}

	// Index in Postgres (no bytes).
	_, err := pool.Exec(ctx, `
		INSERT INTO entry_index (sequence_number, canonical_hash, log_time,
			sig_algorithm_id, signer_did, target_root, cosignature_of, schema_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		seq, hash[:], logTime,
		uint16(1), entry.Header.SignerDID,
		targetRoot, cosigOf, schemaRef,
	)
	if err != nil {
		t.Fatalf("insert test entry seq=%d: %v", seq, err)
	}

	// Bytes in testEntryBytes (the ONLY source of entry bytes).
	if err := testEntryBytes.WriteEntry(seq, canonical, []byte("test-sig")); err != nil {
		t.Fatalf("write entry bytes seq=%d: %v", seq, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON payload helpers
// ─────────────────────────────────────────────────────────────────────────────

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Suppress unused import warnings
// ─────────────────────────────────────────────────────────────────────────────

var _ = fmt.Sprintf
