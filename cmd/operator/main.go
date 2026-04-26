/*
FILE PATH: cmd/operator/main.go

DESCRIPTION:

	Operator binary entry point. Wires config → Postgres → stores → byte
	store → Tessera personality → builder deps → HTTP handlers → goroutines.
	Runs the admission HTTP server, builder loop, and (optional) anchor
	publisher under a shared cancellable context.

PR 1 WIRING CHANGES:

	Per-exchange VerifierRegistry construction. cfg.AdmittedExchanges
	drives the map; each DID gets its own registry via
	did.DefaultVerifierRegistry, sharing a did.CachingResolver-wrapped
	WebDIDResolver across all registries for connection/cache efficiency.
	The previous nil DIDResolver field in IdentityDeps is replaced with
	the registry map.

SDK v0.3.0 WIRING (retained):
 1. anchor.PublisherConfig requires LogDID — threaded from cfg.LogDID.
 2. builder.NewCommitmentPublisher is (operatorDID, logDID, cfg, submitFn,
    logger) — both DIDs passed explicitly.
 3. api.SubmissionDeps has FreshnessTolerance (defaults to
    policy.FreshnessInteractive = 5 min if zero). Explicit here for
    auditability.

OPERATOR INTERNAL SIGNATURES:
  - tessera.NewClient(ClientConfig{BaseURL, Timeout}, logger) → *Client.
  - tessera.NewTesseraAdapter(client, tileReader, logger) → MerkleAppender.
  - tessera.NewInMemoryEntryStore() → *InMemoryEntryStore.
  - store.NewPostgresNodeCache(pool, cacheSize) → *PostgresNodeCache.
  - builder.NewDeltaBufferStore(pool, windowSize, logger) → *DeltaBufferStore.
  - bufferStore.Load(ctx) → (*sdkbuilder.DeltaWindowBuffer, error).
  - middleware.NewDifficultyController(queue, cfg, logger) → queue first.
  - middleware.DefaultDifficultyConfig() → ready-to-use preset.
  - did.NewWebDIDResolver(*http.Client) → *WebDIDResolver.
  - did.NewCachingResolver(DIDResolver, ttl) → *CachingResolver.
  - did.DefaultVerifierRegistry(destinationDID, resolver) → *VerifierRegistry.

INVARIANTS:
  - cfg.LogDID MUST be non-empty (physical log identity; Mode B stamp
    binding; Tessera origin; Postgres lock scope; anchor publishing).
  - cfg.AdmittedExchanges MUST be non-empty. Each DID must pass
    envelope.ValidateDestination (non-empty, no whitespace padding,
    within MaxDestinationDIDLen). The operator fails fast otherwise.
  - cfg.OperatorDID defaults to cfg.LogDID for single-exchange
    deployments where the operator IS the exchange.
  - ByteStore here is NewInMemoryEntryStore() — bytes are lost on
    restart. Production deployments MUST replace this with a
    persistent implementation of tessera.EntryReader + EntryWriter.
*/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/ortholog-operator/anchor"
	"github.com/clearcompass-ai/ortholog-operator/api"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

// ─────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────

type Config struct {
	ServerAddr            string
	DatabaseURL           string
	LogDID                string   // Physical log identity. Mode B stamp binding; Tessera origin; Postgres lock; anchor publishing.
	OperatorDID           string   // Signer DID for operator-authored commentary (commitments, anchors).
	AdmittedExchanges     []string // Exchange DIDs this operator admits entries for. Each gets its own VerifierRegistry.
	WebResolverTimeout    time.Duration
	WebResolverCacheTTL   time.Duration
	MaxEntrySize          int64
	BatchSize             int
	PollInterval          time.Duration
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
	AnchorInterval        time.Duration
	AnchorSources         []anchor.AnchorSource
	TesseraBaseURL        string
	TileCacheSize         int
	SMTNodeCacheSize      int
	DeltaWindow           int
	WitnessEndpoints      []string
	WitnessQuorumK        int
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		ServerAddr:            envOr("OPERATOR_ADDR", ":8080"),
		DatabaseURL:           os.Getenv("OPERATOR_DATABASE_URL"),
		LogDID:                os.Getenv("OPERATOR_LOG_DID"),
		OperatorDID:           os.Getenv("OPERATOR_DID"),
		AdmittedExchanges:     parseCSV(os.Getenv("OPERATOR_ADMITTED_EXCHANGES")),
		WebResolverTimeout:    15 * time.Second,
		WebResolverCacheTTL:   5 * time.Minute,
		MaxEntrySize:          1 << 20, // 1 MB, matches SDK-D11.
		BatchSize:             1000,
		PollInterval:          100 * time.Millisecond,
		EpochWindowSeconds:    3600, // 1h — matches testEpochWindowSeconds.
		EpochAcceptanceWindow: 1,
		AnchorInterval:        1 * time.Hour,
		TesseraBaseURL:        envOr("OPERATOR_TESSERA_URL", "http://localhost:8081"),
		TileCacheSize:         10_000,
		SMTNodeCacheSize:      100_000,
		DeltaWindow:           10,
		WitnessQuorumK:        1,
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("OPERATOR_DATABASE_URL required")
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("OPERATOR_LOG_DID required (physical log identity)")
	}
	if cfg.OperatorDID == "" {
		cfg.OperatorDID = cfg.LogDID
	}
	if len(cfg.AdmittedExchanges) == 0 {
		return nil, fmt.Errorf("OPERATOR_ADMITTED_EXCHANGES required (comma-separated exchange DIDs)")
	}
	for _, d := range cfg.AdmittedExchanges {
		if err := envelope.ValidateDestination(d); err != nil {
			return nil, fmt.Errorf("invalid admitted exchange %q: %w", d, err)
		}
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseCSV splits a comma-separated string, trims whitespace from each
// element, and drops empty elements. Returns nil for empty input.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config", "error", err)
		os.Exit(1)
	}

	// Fail-fast sanity check on LogDID before we touch Postgres.
	if valErr := envelope.ValidateDestination(cfg.LogDID); valErr != nil {
		logger.Error("invalid OPERATOR_LOG_DID", "error", valErr)
		os.Exit(1)
	}

	logger.Info("operator starting",
		"log_did", cfg.LogDID,
		"operator_did", cfg.OperatorDID,
		"admitted_exchanges", cfg.AdmittedExchanges,
		"addr", cfg.ServerAddr,
		"tessera_url", cfg.TesseraBaseURL,
		"sdk_version", "v0.3.0-tessera",
	)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Postgres ──────────────────────────────────────────────────────
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("pgxpool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := store.RunMigrations(ctx, pool); err != nil {
		logger.Error("migrations", "error", err)
		os.Exit(1)
	}

	// ── Stores ────────────────────────────────────────────────────────
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	commitStore := store.NewCommitmentStore(pool)
	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeCache(pool, cfg.SMTNodeCacheSize)

	// ── Byte store ────────────────────────────────────────────────────
	//
	// WARNING: InMemoryEntryStore is the ONLY implementation shipped today.
	// It holds entry bytes in a sync.RWMutex-guarded map; everything is
	// lost on process exit. For production, build a persistent
	// EntryReader/EntryWriter (disk, S3, GCS) and substitute it here.
	//
	// Single process contains both byte writer (admission path) and byte
	// reader (builder fetcher, query API). Crossing process boundaries
	// would require a shared backing store.
	byteStore := tessera.NewInMemoryEntryStore()
	logger.Warn("byte store is InMemoryEntryStore — bytes are lost on restart. Wire a persistent backend for production.")

	// ── Tessera personality ───────────────────────────────────────────
	//
	// Client talks HTTP to the personality (/add for appends, /checkpoint
	// for tree head). TileReader fetches immutable tiles for on-demand
	// proof computation. Adapter implements MerkleAppender + the proof
	// interfaces server.go needs for tree endpoints.
	tileBackend := tessera.NewHTTPTileBackend(cfg.TesseraBaseURL)
	tileReader := tessera.NewTileReader(tileBackend, cfg.TileCacheSize)
	tesseraClient := tessera.NewClient(tessera.ClientConfig{
		BaseURL: cfg.TesseraBaseURL,
		Timeout: 30 * time.Second,
	}, logger)
	tesseraAdapter := tessera.NewTesseraAdapter(tesseraClient, tileReader, logger)

	// ── DID resolution + per-exchange verifier registries (PR 1) ──────
	//
	// Shared web resolver backs every admitted exchange's registry.
	// CachingResolver wraps it so DID documents aren't re-fetched on
	// every signature verification under sustained load. did:key and
	// did:pkh are pure-parse methods and don't use this resolver.
	//
	// One did.VerifierRegistry is constructed per admitted exchange.
	// Each registry is scoped to its exchange DID and returns
	// did.ErrDestinationMismatch at VerifyEntry time if an entry's
	// Destination doesn't match — the runtime enforcement of
	// destination binding.
	webResolver := did.NewWebDIDResolver(&http.Client{Timeout: cfg.WebResolverTimeout})
	cachingResolver := did.NewCachingResolver(webResolver, cfg.WebResolverCacheTTL)

	registries := make(map[string]*did.VerifierRegistry, len(cfg.AdmittedExchanges))
	for _, exchangeDID := range cfg.AdmittedExchanges {
		registries[exchangeDID] = did.DefaultVerifierRegistry(exchangeDID, cachingResolver)
		logger.Info("admitted exchange registered", "destination", exchangeDID)
	}

	// ── Builder dependencies ──────────────────────────────────────────
	fetcher := store.NewPostgresEntryFetcher(pool, byteStore, cfg.LogDID)
	bufferStore := builder.NewDeltaBufferStore(pool, cfg.DeltaWindow, logger)
	queue := builder.NewQueue(pool)
	tree := smt.NewTree(leafStore, nodeCache)

	// Load buffer from persistence (cold start = strict OCC per SDK-D9).
	// Load returns a fresh *DeltaWindowBuffer — we do NOT pass our own in.
	buffer, loadErr := bufferStore.Load(ctx)
	if loadErr != nil {
		logger.Warn("delta buffer load — starting cold", "error", loadErr)
		buffer = sdkbuilder.NewDeltaWindowBuffer(cfg.DeltaWindow)
	}

	// ── Commitment publisher (v0.3.0: LogDID threaded) ────────────────
	commitPub := builder.NewCommitmentPublisher(
		cfg.OperatorDID,
		cfg.LogDID,
		builder.CommitmentPublisherConfig{
			IntervalEntries: 1000,
			IntervalTime:    1 * time.Hour,
		},
		anchor.SubmitViaHTTP(fmt.Sprintf("http://localhost%s", cfg.ServerAddr)),
		logger,
	).WithCommitmentStore(commitStore)

	// ── Difficulty controller (queue-depth-driven) ────────────────────
	//
	// DefaultDifficultyConfig() is the ready-made production preset:
	//   Initial=16, Min=8, Max=24, Low=100, High=10000, Interval=30s, SHA-256.
	// NewDifficultyController takes (queue, cfg, logger) — queue first.
	diffController := middleware.NewDifficultyController(
		queue, middleware.DefaultDifficultyConfig(), logger,
	)

	// ── Witness cosigner (optional) ───────────────────────────────────
	//
	// Left nil for now. The operator's witness/ package today implements
	// the witness-as-server side (serve.go, head_sync.go) — the
	// witness-as-client requester (one operator asking N peer witnesses
	// to cosign its checkpoints) is a separate subsystem not yet wired.
	// BuilderLoop tolerates a nil cosigner: the cosignature step is
	// skipped and self-signed checkpoints are published unwitnessed.
	//
	// TODO: wire a real requester when multi-witness deployments go live.
	// At that point cfg.WitnessEndpoints + cfg.WitnessQuorumK become live.
	var cosigner builder.WitnessCosigner = nil

	// ── Builder loop ──────────────────────────────────────────────────
	loopCfg := builder.DefaultLoopConfig(cfg.LogDID)
	loopCfg.BatchSize = cfg.BatchSize
	loopCfg.PollInterval = cfg.PollInterval
	loopCfg.DeltaWindow = cfg.DeltaWindow

	bl := builder.NewBuilderLoop(
		loopCfg, pool, tree, leafStore, nodeCache,
		queue, fetcher,
		nil, // schema resolver — nil is valid; SDK builder tolerates it.
		buffer, bufferStore,
		commitPub,
		tesseraAdapter, // MerkleAppender
		cosigner,
		logger,
	)

	// ── Anchor publisher (v0.3.0: LogDID threaded) ────────────────────
	anchorPub := anchor.NewPublisher(
		anchor.PublisherConfig{
			OperatorDID:   cfg.OperatorDID,
			LogDID:        cfg.LogDID,
			Interval:      cfg.AnchorInterval,
			AnchorSources: cfg.AnchorSources,
		},
		tesseraAdapter,
		anchor.SubmitViaHTTP(fmt.Sprintf("http://localhost%s", cfg.ServerAddr)),
		logger,
	)

	// ── Submission handler (v0.3.0: 13-step pipeline) ─────────────────
	submitHandler := api.NewSubmissionHandler(&api.SubmissionDeps{
		Storage: api.StorageDeps{
			DB:          pool,
			EntryStore:  entryStore,
			EntryWriter: byteStore, // same store the fetcher reads from.
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    cfg.EpochWindowSeconds,
			EpochAcceptanceWindow: cfg.EpochAcceptanceWindow,
		},
		Identity: api.IdentityDeps{
			CreditStore: creditStore,
			Registries:  registries,
		},
		Queue:              queue,
		LogDID:             cfg.LogDID,
		MaxEntrySize:       cfg.MaxEntrySize,
		Logger:             logger,
		FreshnessTolerance: policy.FreshnessInteractive, // 5-min window.
	})

	// ── Shared stores for read handlers ───────────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(pool, byteStore, cfg.LogDID)
	treeHeadStore := store.NewTreeHeadStore(pool)

	// ── Handler struct for api.Server ─────────────────────────────────
	queryDeps := &api.QueryDeps{
		EntryStore:     entryStore,
		QueryAPI:       queryAPI,
		DiffController: diffController,
		Logger:         logger,
	}
	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore,
		Inclusion:     tesseraAdapter,
		Consistency:   tesseraAdapter,
		Logger:        logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher:  fetcher,
		QueryAPI: queryAPI,
		LogDID:   cfg.LogDID,
		Logger:   logger,
	}
	commitDeps := &api.CommitmentDeps{CommitmentStore: commitStore, Logger: logger}

	handlers := api.Handlers{
		Submission:      submitHandler,
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
		WitnessCosign:   nil, // TODO: wire witness.NewCosignServer when this operator is also a witness.
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryBatch:      api.NewEntryBatchHandler(entryReadDeps),
		SMTLeaf:         api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:    api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery: api.NewCommitmentQueryHandler(commitDeps),
	}

	// ── HTTP server ───────────────────────────────────────────────────
	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr
	serverCfg.MaxEntrySize = cfg.MaxEntrySize
	server := api.NewServer(serverCfg, pool, handlers, logger)

	// ── Goroutines ────────────────────────────────────────────────────
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil {
			logger.Error("http server", "error", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := bl.Run(ctx); err != nil {
			logger.Error("builder loop exited with error", "error", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		diffController.Run(ctx, 30*time.Second)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		anchorPub.Run(ctx)
	}()

	// ── Shutdown ──────────────────────────────────────────────────────
	<-ctx.Done()
	logger.Info("shutdown initiated")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown", "error", err)
	}

	wg.Wait()

	b, e, errs := bl.Stats()
	logger.Info("operator stopped",
		"batches", b, "entries", e, "errors", errs,
	)
}
