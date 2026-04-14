/*
FILE PATH: tests/testserver_test.go

Wires up a complete operator HTTP server for integration testing.
Real Postgres, real middleware chain, real builder loop.

DESIGN RULE: Postgres is an index. Entry bytes live in EntryReader.
InMemoryEntryStore satisfies both EntryReader and EntryWriter.
MerkleAppender and WitnessCosigner use in-process stubs.
*/
package tests

import (
	"context"
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
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/api"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	opbuilder "github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	optessera "github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test operator instance
// ─────────────────────────────────────────────────────────────────────────────

type testOperator struct {
	BaseURL     string
	Pool        *pgxpool.Pool
	Queue       *opbuilder.Queue
	CreditStore *store.CreditStore
	EntryStore  *store.EntryStore
	EntryBytes  *optessera.InMemoryEntryStore // Bytes live here, not Postgres.
	cancel      context.CancelFunc
}

// startTestOperator creates a fully-wired operator HTTP server on a random
// port backed by real Postgres and a running builder loop.
// Entry bytes go to InMemoryEntryStore (not Postgres).
func startTestOperator(t *testing.T) *testOperator {
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

	// ── Entry byte store (source of truth for bytes) ────────────────────
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

	// ── Delta buffer ───────────────────────────────────────────────────
	bufferStore := opbuilder.NewDeltaBufferStore(pool, 10, logger)
	deltaBuffer, _ := bufferStore.Load(ctx)
	if deltaBuffer == nil {
		deltaBuffer = sdkbuilder.NewDeltaWindowBuffer(10)
	}

	// ── Stubs ──────────────────────────────────────────────────────────
	merkle := &stubMerkleAppender{mt: smt.NewStubMerkleTree()}
	witnessCosigner := &stubWitnessCosigner{}

	// ── Commitment publisher (no-op for HTTP tests) ────────────────────
	commitPub := opbuilder.NewCommitmentPublisher(
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

	// ── HTTP handlers ──────────────────────────────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(pool, entryBytes, testLogDID)

	submissionDeps := &api.SubmissionDeps{
		DB: pool, EntryStore: entryStore, EntryWriter: entryBytes,
		CreditStore: creditStore,
		Queue: queue, LogDID: testLogDID, MaxEntrySize: 1 << 20,
		DiffController: diffController, Logger: logger,
	}
	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore, Inclusion: merkle,
		Consistency: merkle, Logger: logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	queryDeps := &api.QueryDeps{
		QueryAPI: queryAPI, DiffController: diffController, Logger: logger,
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

// ─────────────────────────────────────────────────────────────────────────────
// Stubs (satisfy real interfaces, not Go interface mocks)
// ─────────────────────────────────────────────────────────────────────────────

type stubMerkleAppender struct {
	mt *smt.StubMerkleTree
}

func (s *stubMerkleAppender) AppendLeaf(hash [32]byte) (uint64, error) {
	return s.mt.AppendLeaf(hash)
}

func (s *stubMerkleAppender) Head() (types.TreeHead, error) {
	return s.mt.Head()
}

func (s *stubMerkleAppender) InclusionProof(position, treeSize uint64) (any, error) {
	return s.mt.InclusionProof(position, treeSize)
}

func (s *stubMerkleAppender) ConsistencyProof(oldSize, newSize uint64) (any, error) {
	return map[string]any{"old_size": oldSize, "new_size": newSize}, nil
}

type stubWitnessCosigner struct{}

func (s *stubWitnessCosigner) RequestCosignatures(_ context.Context, _ types.TreeHead) error {
	return nil
}
