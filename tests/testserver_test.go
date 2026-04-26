/*
FILE PATH:

	tests/testserver_test.go

DESCRIPTION:

	Wires up a complete operator HTTP server for integration testing.
	Real Postgres, real middleware chain, real builder loop.

KEY ARCHITECTURAL DECISIONS:
  - Postgres is an index. Entry bytes live in EntryReader.
    InMemoryEntryStore satisfies both EntryReader and EntryWriter.
  - MerkleAppender and WitnessCosigner use in-process stubs.
  - stubMerkleAppender.AppendLeaf accepts 32-byte SHA-256 hashes
    (hash-only architecture). The builder computes the hash in loop.go
    step 6 and passes only the digest.
  - SubmissionDeps uses the cohesive sub-struct shape (StorageDeps +
    AdmissionConfig + IdentityDeps).

PR 2 — WAVE 1 CHANGES:
  - Construct did.VerifierRegistry scoped to testExchangeDID at startup,
    wire it into SubmissionDeps.Identity.Registries. Replaces the
    Phase-2-trust-model nil DIDResolver.
  - panicResolver guards against unintended did:web resolution: the test
    suite uses did:example:* signers which don't correspond to any DID
    method; the resolver should never be invoked. A panic surfaces
    unexpected code paths immediately.
  - startTestOperatorMultiExchange variant accepts a caller-supplied set
    of admitted exchanges. Used by Wave 3's multi-exchange admission
    tests. Single-exchange tests continue to use startTestOperator.

OVERVIEW:

	startTestOperator creates: Postgres pool → clean tables → stores →
	builder loop → HTTP server on random port. Returns testOperator with
	all dependencies accessible for test assertions.

KEY DEPENDENCIES:
  - All api/ handlers wired with real Postgres stores.
  - builder/loop.go runs in background goroutine.
  - tessera/entry_reader.go InMemoryEntryStore for byte storage.
  - did.DefaultVerifierRegistry for per-exchange signature routing.
*/
package tests

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/api"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	opbuilder "github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	optessera "github.com/clearcompass-ai/ortholog-operator/tessera"
)

// -------------------------------------------------------------------------------------------------
// Test operator instance
// -------------------------------------------------------------------------------------------------

type testOperator struct {
	BaseURL     string
	Pool        *pgxpool.Pool
	Queue       *opbuilder.Queue
	CreditStore *store.CreditStore
	EntryStore  *store.EntryStore
	EntryBytes  *optessera.InMemoryEntryStore
	cancel      context.CancelFunc
}

// startTestOperator creates a test operator admitting exactly one
// exchange: testExchangeDID. This is the default for single-exchange
// tests (the majority).
//
// For tests that exercise multi-exchange admission or cross-exchange
// rejection, use startTestOperatorMultiExchange.
func startTestOperator(t *testing.T) *testOperator {
	t.Helper()
	return startTestOperatorMultiExchange(t, []string{testExchangeDID})
}

// startTestOperatorMultiExchange creates a test operator admitting the
// given set of exchange DIDs. Each DID gets its own VerifierRegistry.
//
// Callers provide the full list; an empty list triggers the handler
// construction panic in NewSubmissionHandler (as intended — an operator
// with no admitted exchanges cannot admit any entries).
func startTestOperatorMultiExchange(t *testing.T, admittedExchanges []string) *testOperator {
	t.Helper()

	dsn := os.Getenv("ORTHOLOG_TEST_DSN")
	if dsn == "" {
		t.Skip("ORTHOLOG_TEST_DSN not set — skipping HTTP integration test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// ── Postgres ───────────────────────────────────────────────────────
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		cancel()
		t.Fatalf("migrations: %v", err)
	}
	cleanTables(t, pool)

	// ── Entry byte store ───────────────────────────────────────────────
	entryBytes := optessera.NewInMemoryEntryStore()

	// ── Stores ─────────────────────────────────────────────────────────
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	queue := opbuilder.NewQueue(pool)
	treeHeadStore := store.NewTreeHeadStore(pool)
	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeCache(pool, 10000)
	tree := smt.NewTree(leafStore, nodeCache)
	fetcher := store.NewPostgresEntryFetcher(pool, entryBytes, testLogDID)
	commitmentStore := store.NewCommitmentStore(pool)

	// ── Delta buffer ───────────────────────────────────────────────────
	bufferStore := opbuilder.NewDeltaBufferStore(pool, 10, logger)
	deltaBuffer, _ := bufferStore.Load(ctx)
	if deltaBuffer == nil {
		deltaBuffer = sdkbuilder.NewDeltaWindowBuffer(10)
	}

	// ── Stubs ──────────────────────────────────────────────────────────
	merkle := &stubMerkleAppender{mt: smt.NewStubMerkleTree()}
	witnessCosigner := &stubWitnessCosigner{}

	// ── Commitment publisher ───────────────────────────────────────────
	commitPub := opbuilder.NewCommitmentPublisher(
		testLogDID,
		testLogDID,
		opbuilder.CommitmentPublisherConfig{IntervalEntries: 100000, IntervalTime: 24 * time.Hour},
		func(e *envelope.Entry) error { return nil },
		logger,
	)

	// ── Builder loop ───────────────────────────────────────────────────
	loopCfg := opbuilder.DefaultLoopConfig(testLogDID)
	loopCfg.PollInterval = 50 * time.Millisecond
	loopCfg.BatchSize = 100

	builderLoop := opbuilder.NewBuilderLoop(
		loopCfg, pool, tree, leafStore, nodeCache,
		queue, fetcher, nil, deltaBuffer, bufferStore, commitPub,
		merkle, witnessCosigner, logger,
	)
	go builderLoop.Run(ctx)

	// ── Difficulty controller ──────────────────────────────────────────
	diffController := middleware.NewDifficultyController(
		queue, middleware.DefaultDifficultyConfig(), logger,
	)

	// ── Per-exchange VerifierRegistries ────────────────────────────────
	//
	// Each admitted exchange gets its own VerifierRegistry scoped to
	// that exchange's DID. The registries share a panicResolver — tests
	// use did:example:* or did:key signers, neither of which invokes the
	// web resolver. If a panic fires, a test is doing something
	// unexpected and we want the trace immediately.
	registries := make(map[string]*did.VerifierRegistry, len(admittedExchanges))
	for _, exchangeDID := range admittedExchanges {
		registries[exchangeDID] = did.DefaultVerifierRegistry(exchangeDID, panicResolver{})
	}

	// ── HTTP handlers ──────────────────────────────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(pool, entryBytes, testLogDID)

	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			DB:          pool,
			EntryStore:  entryStore,
			EntryWriter: entryBytes,
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    testEpochWindowSeconds,
			EpochAcceptanceWindow: testEpochAcceptanceWindow,
		},
		Identity: api.IdentityDeps{
			CreditStore: creditStore,
			Registries:  registries,
		},
		Queue:        queue,
		LogDID:       testLogDID,
		MaxEntrySize: 1 << 20,
		Logger:       logger,
	}

	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore, Inclusion: merkle,
		Consistency: merkle, Logger: logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	queryDeps := &api.QueryDeps{
		QueryAPI: queryAPI, DiffController: diffController, Logger: logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher: fetcher, QueryAPI: queryAPI,
		LogDID: testLogDID, Logger: logger,
	}
	commitDeps := &api.CommitmentDeps{
		CommitmentStore: commitmentStore, Logger: logger,
	}

	handlers := api.Handlers{
		Submission:      api.NewSubmissionHandler(submissionDeps),
		TreeHead:        api.NewTreeHeadHandler(treeDeps),
		TreeInclusion:   api.NewTreeInclusionHandler(treeDeps),
		TreeConsistency: api.NewTreeConsistencyHandler(treeDeps),
		SMTProof:        api.NewSMTProofHandler(smtDeps),
		SMTBatchProof:   api.NewSMTBatchProofHandler(smtDeps),
		SMTRoot:         api.NewSMTRootHandler(smtDeps),
		CosignatureOf:   api.NewQueryCosignatureOfHandler(queryDeps),
		TargetRoot:      api.NewQueryTargetRootHandler(queryDeps),
		SignerDID:       api.NewQuerySignerDIDHandler(queryDeps),
		SchemaRef:       api.NewQuerySchemaRefHandler(queryDeps),
		Scan:            api.NewQueryScanHandler(queryDeps),
		Difficulty:      api.NewDifficultyHandler(queryDeps),
		WitnessCosign:   nil,
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryBatch:      api.NewEntryBatchHandler(entryReadDeps),
		SMTLeaf:         api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:    api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery: api.NewCommitmentQueryHandler(commitDeps),
	}

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = "127.0.0.1:0"
	server := api.NewServer(serverCfg, pool, handlers, logger)

	// ── Start on random port ───────────────────────────────────────────
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		pool.Close()
		t.Fatalf("listen: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())

	go server.Serve(ln)

	op := &testOperator{
		BaseURL: baseURL, Pool: pool, Queue: queue,
		CreditStore: creditStore, EntryStore: entryStore,
		EntryBytes: entryBytes, cancel: cancel,
	}

	t.Cleanup(func() {
		cancel()
		_ = server.Shutdown(context.Background())
		cleanTables(t, pool)
		pool.Close()
	})

	// Wait for readiness.
	for i := 0; i < 50; i++ {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return op
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("test operator did not become ready in 2.5s")
	return nil
}

// seedSession inserts a valid session token + credits.
func (op *testOperator) seedSession(t *testing.T, token, exchangeDID string, credits int64) {
	t.Helper()
	ctx := context.Background()
	_, err := op.Pool.Exec(ctx,
		`INSERT INTO sessions (token, exchange_did, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (token) DO NOTHING`,
		token, exchangeDID, time.Now().UTC().Add(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if credits > 0 {
		if _, err := op.CreditStore.BulkPurchase(ctx, exchangeDID, credits); err != nil {
			t.Fatalf("seed credits: %v", err)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// panicResolver — guard against unintended did:web resolution
// -------------------------------------------------------------------------------------------------

// panicResolver is a did.DIDResolver that panics on any Resolve call.
// Used in test VerifierRegistry construction because the test suite
// uses did:example:* and did:key signers — neither invokes the web
// resolver. A panic surfaces unexpected code paths immediately.
//
// If a future test deliberately uses did:web signers, pass a real
// did.DIDResolver (likely did.CachingResolver wrapping a fixture-backed
// resolver) to startTestOperatorMultiExchange's registry construction.
type panicResolver struct{}

func (panicResolver) Resolve(didStr string) (*did.DIDDocument, error) {
	panic(fmt.Sprintf("panicResolver: unexpected resolve of %q — tests shouldn't invoke web resolution", didStr))
}

// -------------------------------------------------------------------------------------------------
// Stubs
// -------------------------------------------------------------------------------------------------

// stubMerkleAppender implements MerkleAppender for tests.
//
// Hash-only architecture: AppendLeaf receives 32-byte SHA-256 hashes from
// builder/loop.go step 6. The stub passes the hash directly to the
// StubMerkleTree (which further hashes it for the Merkle leaf as
// H(0x00 || data), matching RFC 6962).
type stubMerkleAppender struct {
	mt *smt.StubMerkleTree
}

func (s *stubMerkleAppender) AppendLeaf(data []byte) (uint64, error) {
	return s.mt.AppendLeaf(data)
}

func (s *stubMerkleAppender) Head() (types.TreeHead, error) {
	return s.mt.Head()
}

func (s *stubMerkleAppender) RawInclusionProof(position, treeSize uint64) (any, error) {
	return s.mt.InclusionProof(position, treeSize)
}

func (s *stubMerkleAppender) ConsistencyProof(oldSize, newSize uint64) (any, error) {
	return map[string]any{"old_size": oldSize, "new_size": newSize}, nil
}

type stubWitnessCosigner struct{}

func (s *stubWitnessCosigner) RequestCosignatures(_ context.Context, _ types.TreeHead) error {
	return nil
}

// -------------------------------------------------------------------------------------------------
// Lightweight test-server adapter for destination_binding_test.go
// -------------------------------------------------------------------------------------------------

type testServer struct {
	URL string
	op  *testOperator // kept for lifetime ownership; teardown is via t.Cleanup.
}

// Close is a no-op. startTestOperator registers a t.Cleanup that
// cancels the context, shuts down the HTTP server, cleans tables,
// and closes the pool. This method exists only to satisfy the
// `defer srv.Close()` idiom used by destination_binding_test.go.
func (s *testServer) Close() {}

// newTestServer returns a lightweight test-server handle for tests that
// only need a running HTTP endpoint bound to testLogDID — no credit
// seeding, no session tokens, no queue introspection.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	op := startTestOperator(t)
	return &testServer{URL: op.BaseURL, op: op}
}

// Suppress unused imports.
var _ = sha256.Sum256
