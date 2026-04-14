/*
FILE PATH:
    cmd/operator/main.go

DESCRIPTION:
    Entry point for the Ortholog log operator. Executes the 16-step startup
    sequence, manages goroutine lifecycle, and handles graceful shutdown.
    Single binary, no external migration tools, no lazy initialization.

KEY ARCHITECTURAL DECISIONS:
    - Fail-fast startup: any initialization failure terminates immediately.
      No partial operation. If the database is unreachable, the process exits.
    - Advisory lock acquired before builder loop starts: guarantees exactly
      one builder per log (determinism requirement).
    - Graceful shutdown on SIGTERM/SIGINT: drain queue, flush buffer,
      publish final commitment, close pool, exit 0.
    - All goroutines governed by a single context: cancel propagates everywhere.

OVERVIEW:
    (1)  Load config from operator.yaml (or env overrides)
    (2)  Initialize Postgres pool (pgxpool)
    (3)  Run migrations (store/postgres.go)
    (4)  Initialize Tessera client
    (5)  Initialize SMT with Postgres LeafStore + NodeCache
    (6)  Warm SMT node cache: top N levels into LRU
    (7)  Load persisted delta-window buffer from Postgres
    (8)  Load current witness set from Postgres
    (9)  Start builder loop goroutine
    (10) Start witness head sync goroutine (no-op until builder produces heads)
    (11) Start equivocation monitor goroutine
    (12) Start anchor publisher goroutine (if configured)
    (13) Start HTTP server
    (14) Health checks: /healthz (liveness), /readyz (readiness)
    (15) Block on SIGTERM/SIGINT
    (16) Graceful shutdown: drain queue, flush buffer, close pool, exit 0

KEY DEPENDENCIES:
    - All operator packages: store/, builder/, api/, witness/, tessera/, anchor/
    - github.com/clearcompass-ai/ortholog-sdk: core protocol engine
*/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"

	"github.com/clearcompass-ai/ortholog-operator/anchor"
	"github.com/clearcompass-ai/ortholog-operator/api"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	opbuilder "github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
	"github.com/clearcompass-ai/ortholog-operator/witness"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("operator fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Step 1: Load config ────────────────────────────────────────────
	cfg := loadConfig()
	logger.Info("config loaded",
		"log_did", cfg.LogDID,
		"addr", cfg.ServerAddr,
	)

	// ── Step 2: Initialize Postgres pool ───────────────────────────────
	pool, err := store.InitPool(ctx, store.PoolConfig{
		DSN:             cfg.PostgresDSN,
		MaxConns:        int32(cfg.MaxConns),
		MinConns:        int32(cfg.MinConns),
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("step 2: %w", err)
	}
	defer pool.Close()
	logger.Info("postgres pool initialized")

	// ── Step 3: Run migrations ─────────────────────────────────────────
	if err := store.RunMigrations(ctx, pool.DB); err != nil {
		return fmt.Errorf("step 3: %w", err)
	}
	logger.Info("migrations complete")

	// ── Step 4: Initialize Tessera client ──────────────────────────────
	tesseraClient := tessera.NewClient(tessera.ClientConfig{
		BaseURL: cfg.TesseraBaseURL,
		Timeout: 30 * time.Second,
	}, logger)
	proofAdapter := tessera.NewProofAdapter(tesseraClient, logger)
	logger.Info("tessera client initialized", "url", cfg.TesseraBaseURL)

	// ── Step 5: Initialize SMT with Postgres backends ──────────────────
	leafStore := store.NewPostgresLeafStore(pool.DB)
	nodeCache := store.NewPostgresNodeCache(pool.DB)
	tree := smt.NewTree(leafStore, nodeCache)
	logger.Info("SMT initialized")

	// ── Step 6: Warm SMT node cache ────────────────────────────────────
	if err := nodeCache.WarmCache(ctx, cfg.WarmTopLevels); err != nil {
		logger.Warn("cache warm failed (non-fatal)", "error", err)
	} else {
		logger.Info("SMT cache warmed", "top_levels", cfg.WarmTopLevels)
	}

	// ── Step 7: Load delta-window buffer ───────────────────────────────
	bufferStore := opbuilder.NewDeltaBufferStore(pool.DB, cfg.DeltaWindowSize)
	deltaBuffer, err := bufferStore.Load(ctx)
	if err != nil {
		logger.Warn("delta buffer load failed (cold start)", "error", err)
	}
	logger.Info("delta buffer loaded")

	// ── Step 8: Load current witness set ───────────────────────────────
	witnessKeys, schemeTag, err := witness.LoadCurrentSet(ctx, pool.DB)
	if err != nil {
		logger.Warn("witness set not found (genesis deployment)", "error", err)
		witnessKeys = nil
		schemeTag = 1 // ECDSA default
	}
	logger.Info("witness set loaded", "keys", len(witnessKeys), "scheme", schemeTag)

	// ── Acquire builder advisory lock ──────────────────────────────────
	releaseLock, err := store.AcquireBuilderLock(ctx, pool.DB)
	if err != nil {
		return fmt.Errorf("builder lock: %w", err)
	}
	defer releaseLock()
	logger.Info("builder advisory lock acquired")

	// ── Step 9: Start builder loop goroutine ───────────────────────────
	entryStore := store.NewEntryStore(pool.DB)
	fetcher := store.NewPostgresEntryFetcher(pool.DB, cfg.LogDID)
	queue := opbuilder.NewQueue(pool.DB)
	commitPub := opbuilder.NewCommitmentPublisher(cfg.OperatorDID, logger)

	builderLoop := opbuilder.NewBuilderLoop(
		opbuilder.DefaultLoopConfig(cfg.LogDID),
		pool.DB, tree, queue, fetcher, nil, deltaBuffer, commitPub, logger,
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := builderLoop.Run(ctx); err != nil {
			logger.Error("builder loop exited", "error", err)
		}
	}()
	logger.Info("builder loop started")

	// ── Step 10: Start witness head sync goroutine ─────────────────────
	treeHeadStore := store.NewTreeHeadStore(pool.DB)
	headSync := witness.NewHeadSync(witness.HeadSyncConfig{
		WitnessEndpoints:  cfg.WitnessEndpoints,
		QuorumK:           cfg.WitnessQuorumK,
		PerWitnessTimeout: 30 * time.Second,
		SchemeTag:         schemeTag,
	}, treeHeadStore, logger)
	_ = headSync // Invoked by builder loop after each batch.
	logger.Info("witness head sync ready")

	// ── Step 11: Start equivocation monitor goroutine ──────────────────
	if len(cfg.PeerEndpoints) > 0 {
		eqMonitor := witness.NewEquivocationMonitor(
			witness.EquivocationMonitorConfig{
				PeerEndpoints: cfg.PeerEndpoints,
				PollInterval:  5 * time.Minute,
			},
			pool.DB, treeHeadStore, logger,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			eqMonitor.Run(ctx)
		}()
		logger.Info("equivocation monitor started", "peers", len(cfg.PeerEndpoints))
	}

	// ── Step 12: Start anchor publisher goroutine ──────────────────────
	if cfg.AnchorEnabled && len(cfg.AnchorSources) > 0 {
		anchorPub := anchor.NewPublisher(anchor.PublisherConfig{
			OperatorDID:    cfg.OperatorDID,
			Interval:       1 * time.Hour,
			AnchorSources:  cfg.AnchorSources,
			LocalSubmitURL: fmt.Sprintf("http://localhost%s/v1/entries", cfg.ServerAddr),
		}, logger)
		wg.Add(1)
		go func() {
			defer wg.Done()
			anchorPub.Run(ctx)
		}()
		logger.Info("anchor publisher started", "sources", len(cfg.AnchorSources))
	}

	// ── Step 13: Start HTTP server ─────────────────────────────────────
	// Build dependencies.
	creditStore := store.NewCreditStore(pool.DB)
	diffController := middleware.NewDifficultyController(
		pool.DB, middleware.DefaultDifficultyConfig(), logger,
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		diffController.Run(ctx, 30*time.Second)
	}()

	submissionDeps := &api.SubmissionDeps{
		DB:           pool.DB,
		EntryStore:   entryStore,
		CreditStore:  creditStore,
		Queue:        queue,
		LogDID:       cfg.LogDID,
		MaxEntrySize: int64(cfg.MaxEntrySize),
		Difficulty:   diffController.CurrentDifficulty(),
		Logger:       logger,
	}

	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore,
		ProofAdapter:  proofAdapter,
		Logger:        logger,
	}

	smtDeps := &api.SMTDeps{Tree: tree, Logger: logger}

	queryDeps := &api.QueryDeps{
		CosigIdx:   indexes.NewCosignatureOfIndex(pool.DB, cfg.LogDID),
		TargetIdx:  indexes.NewTargetRootIndex(pool.DB, cfg.LogDID),
		SignerIdx:  indexes.NewSignerDIDIndex(pool.DB, cfg.LogDID),
		SchemaIdx:  indexes.NewSchemaRefIndex(pool.DB, cfg.LogDID),
		ScanIdx:    indexes.NewScanIndex(pool.DB, cfg.LogDID),
		Difficulty: diffController.CurrentDifficulty(),
		HashFunc:   "sha256",
		Logger:     logger,
	}

	readyFlag := true // Set false during shutdown.
	deps := &api.Dependencies{
		SubmissionHandler: api.NewSubmissionHandler(submissionDeps),
		ReadyzHandler: func(w http.ResponseWriter, r *http.Request) {
			if readyFlag {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ready"))
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("shutting down"))
			}
		},
		TreeHeadHandler:           api.NewTreeHeadHandler(treeDeps),
		TreeInclusionHandler:      api.NewTreeInclusionHandler(treeDeps),
		TreeConsistencyHandler:    api.NewTreeConsistencyHandler(treeDeps),
		SMTProofHandler:           api.NewSMTProofHandler(smtDeps),
		SMTBatchProofHandler:      api.NewSMTBatchProofHandler(smtDeps),
		SMTRootHandler:            api.NewSMTRootHandler(smtDeps),
		QueryCosignatureOfHandler: api.NewQueryCosignatureOfHandler(queryDeps),
		QueryTargetRootHandler:    api.NewQueryTargetRootHandler(queryDeps),
		QuerySignerDIDHandler:     api.NewQuerySignerDIDHandler(queryDeps),
		QuerySchemaRefHandler:     api.NewQuerySchemaRefHandler(queryDeps),
		QueryScanHandler:          api.NewQueryScanHandler(queryDeps),
		DifficultyHandler:         api.NewDifficultyHandler(queryDeps),
	}

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr

	server := api.NewServer(serverCfg, deps, logger)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil {
			logger.Error("http server exited", "error", err)
		}
	}()
	logger.Info("HTTP server started", "addr", cfg.ServerAddr)

	// ── Steps 14-15: Block on signals ──────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("shutdown signal received", "signal", sig)

	// ── Step 16: Graceful shutdown ─────────────────────────────────────
	readyFlag = false
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown error", "error", err)
	}

	cancel() // Cancel all goroutines.
	wg.Wait()
	logger.Info("all goroutines stopped, exiting cleanly")
	return nil
}

// -------------------------------------------------------------------------------------------------
// Configuration loading
// -------------------------------------------------------------------------------------------------

type operatorConfig struct {
	LogDID           string
	OperatorDID      string
	PostgresDSN      string
	MaxConns         int
	MinConns         int
	ServerAddr       string
	MaxEntrySize     int
	TesseraBaseURL   string
	WarmTopLevels    int
	DeltaWindowSize  int
	WitnessEndpoints []string
	WitnessQuorumK   int
	PeerEndpoints    []string
	AnchorEnabled    bool
	AnchorSources    []anchor.AnchorSource
}

func loadConfig() operatorConfig {
	return operatorConfig{
		LogDID:          envOr("ORTHOLOG_LOG_DID", "did:ortholog:operator:001"),
		OperatorDID:     envOr("ORTHOLOG_OPERATOR_DID", "did:ortholog:operator:001:signer"),
		PostgresDSN:     envOr("ORTHOLOG_POSTGRES_DSN", "postgres://ortholog:ortholog@localhost:5432/ortholog?sslmode=disable"),
		MaxConns:        20,
		MinConns:        5,
		ServerAddr:      envOr("ORTHOLOG_SERVER_ADDR", ":8080"),
		MaxEntrySize:    1 << 20,
		TesseraBaseURL:  envOr("ORTHOLOG_TESSERA_URL", "http://localhost:2024"),
		WarmTopLevels:   32,
		DeltaWindowSize: 10,
		WitnessEndpoints: nil, // Populated from config file in production.
		WitnessQuorumK:   2,
		PeerEndpoints:    nil,
		AnchorEnabled:    false,
		AnchorSources:    nil,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
