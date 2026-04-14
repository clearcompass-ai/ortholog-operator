/*
FILE PATH: cmd/operator/main.go

Entry point for the Ortholog log operator (read-write mode).
Executes the startup sequence, manages goroutine lifecycle, handles shutdown.

KEY ARCHITECTURAL DECISIONS:
  - Pools.Write for builder, submission, queue (primary).
  - Pools.Read for all GET queries (replica, falls back to primary).
  - Advisory lock before builder start: exactly one builder per log.
  - Graceful shutdown: SIGTERM → drain → exit 0.
  - TesseraAdapter implements sdk MerkleTree; injected into builder loop.
  - InMemoryEntryStore for entry bytes (production: TesseraEntryReader).
  - DIDResolver: nil until Phase 4 DID resolution is deployed.
  - WitnessCosign: nil until witness key is configured.
*/
package main

import (
	"context"
	"fmt"
	"log/slog"
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
	logger.Info("config loaded", "log_did", cfg.LogDID, "addr", cfg.ServerAddr)

	// ── Step 2: Initialize Postgres pools (write + read) ───────────────
	pools, err := store.InitPools(ctx, store.PoolConfig{
		DSN:             cfg.PostgresDSN,
		MaxConns:        int32(cfg.MaxConns),
		MinConns:        int32(cfg.MinConns),
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
	}, cfg.ReplicaDSN)
	if err != nil {
		return fmt.Errorf("step 2: %w", err)
	}
	defer pools.Close()
	if cfg.ReplicaDSN != "" {
		logger.Info("postgres pools initialized (primary + replica)")
	} else {
		logger.Info("postgres pool initialized (single instance)")
	}

	// ── Step 3: Run migrations (on primary only) ────────────────────────
	if err := store.RunMigrations(ctx, pools.Write); err != nil {
		return fmt.Errorf("step 3: %w", err)
	}
	logger.Info("migrations complete")

	// ── Step 4: Initialize Tessera client ──────────────────────────────
	tesseraClient := tessera.NewClient(tessera.ClientConfig{
		BaseURL: cfg.TesseraBaseURL,
		Timeout: 30 * time.Second,
	}, logger)
	tileBackend := tessera.NewHTTPTileBackend(cfg.TesseraBaseURL)
	tileReader := tessera.NewTileReader(tileBackend, cfg.TileCacheSize)
	logger.Info("tessera client initialized", "url", cfg.TesseraBaseURL)

	// ── Step 5: Initialize TesseraAdapter (sdk MerkleTree interface) ───
	tesseraAdapter := tessera.NewTesseraAdapter(tesseraClient, tileReader, logger)

	// ── Entry byte store (source of truth for entry bytes) ─────────────
	// Production: TesseraEntryReader reads from entry tiles.
	// For now: InMemoryEntryStore (same as tests — swap when Tessera
	// entry tile format is wired).
	entryBytes := tessera.NewInMemoryEntryStore()

	// ── Step 6: Initialize SMT with Postgres backends ──────────────────
	leafStore := store.NewPostgresLeafStore(pools.Write)
	nodeCache := store.NewPostgresNodeCache(pools.Write, cfg.SMTCacheSize)
	tree := smt.NewTree(leafStore, nodeCache)
	logger.Info("SMT initialized")

	// ── Step 7: Warm SMT node cache ────────────────────────────────────
	if err := nodeCache.WarmCache(ctx, cfg.WarmTopLevels); err != nil {
		logger.Warn("cache warm failed (non-fatal)", "error", err)
	} else {
		logger.Info("SMT cache warmed", "top_levels", cfg.WarmTopLevels)
	}

	// ── Step 8: Load delta-window buffer ───────────────────────────────
	bufferStore := opbuilder.NewDeltaBufferStore(pools.Write, cfg.DeltaWindowSize, logger)
	deltaBuffer, err := bufferStore.Load(ctx)
	if err != nil {
		logger.Warn("delta buffer load failed (cold start)", "error", err)
	}
	logger.Info("delta buffer loaded")

	// ── Step 9: Load current witness set ───────────────────────────────
	witnessKeys, schemeTag, err := witness.LoadCurrentSet(ctx, pools.Read)
	if err != nil {
		logger.Warn("witness set not found (genesis deployment)", "error", err)
		witnessKeys = nil
		schemeTag = 1
	}
	logger.Info("witness set loaded", "keys", len(witnessKeys), "scheme", schemeTag)

	// ── Acquire builder advisory lock (on primary) ─────────────────────
	releaseLock, err := store.AcquireBuilderLock(ctx, pools.Write)
	if err != nil {
		return fmt.Errorf("builder lock: %w", err)
	}
	defer releaseLock()
	logger.Info("builder advisory lock acquired")

	// ── Step 10: Start builder loop goroutine ──────────────────────────
	entryStore := store.NewEntryStore(pools.Write)
	fetcher := store.NewPostgresEntryFetcher(pools.Read, entryBytes, cfg.LogDID)
	queue := opbuilder.NewQueue(pools.Write)
	treeHeadStore := store.NewTreeHeadStore(pools.Read)

	headSync := witness.NewHeadSync(witness.HeadSyncConfig{
		WitnessEndpoints:  cfg.WitnessEndpoints,
		QuorumK:           cfg.WitnessQuorumK,
		PerWitnessTimeout: 30 * time.Second,
		SchemeTag:         schemeTag,
	}, treeHeadStore, logger)

	commitPub := opbuilder.NewCommitmentPublisher(
		cfg.OperatorDID,
		opbuilder.CommitmentPublisherConfig{
			IntervalEntries: cfg.CommitmentInterval,
			IntervalTime:    cfg.CommitmentMaxAge,
		},
		nil, logger,
	)

	builderLoop := opbuilder.NewBuilderLoop(
		opbuilder.DefaultLoopConfig(cfg.LogDID),
		pools.Write, tree, leafStore, nodeCache,
		queue, fetcher, nil, deltaBuffer, bufferStore, commitPub,
		tesseraAdapter, headSync, logger,
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

	// ── Step 11: Start equivocation monitor goroutine ──────────────────
	if len(cfg.PeerEndpoints) > 0 {
		eqMonitor := witness.NewEquivocationMonitor(
			witness.EquivocationMonitorConfig{
				PeerEndpoints: cfg.PeerEndpoints,
				PollInterval:  5 * time.Minute,
			},
			pools.Write, treeHeadStore, logger,
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
		anchorPub := anchor.NewPublisher(
			anchor.PublisherConfig{
				OperatorDID:   cfg.OperatorDID,
				Interval:      1 * time.Hour,
				AnchorSources: cfg.AnchorSources,
			},
			tesseraAdapter,
			anchor.SubmitViaHTTP(fmt.Sprintf("http://localhost%s", cfg.ServerAddr)),
			logger,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			anchorPub.Run(ctx)
		}()
		logger.Info("anchor publisher started", "sources", len(cfg.AnchorSources))
	}

	// ── Step 13: Start difficulty controller goroutine ──────────────────
	creditStore := store.NewCreditStore(pools.Write)
	diffController := middleware.NewDifficultyController(
		queue, middleware.DifficultyConfig{
			InitialDifficulty: uint32(cfg.InitialDifficulty),
			MinDifficulty:     uint32(cfg.MinDifficulty),
			MaxDifficulty:     uint32(cfg.MaxDifficulty),
			LowThreshold:      int64(cfg.LowThreshold),
			HighThreshold:     int64(cfg.HighThreshold),
			HashFunction:      cfg.HashFunction,
		}, logger,
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		diffController.Run(ctx, 30*time.Second)
	}()

	// ── Step 14: Start HTTP server ─────────────────────────────────────
	// Queries use Read pool. Submission uses Write pool.
	queryAPI := indexes.NewPostgresQueryAPI(pools.Read, entryBytes, cfg.LogDID)

	submissionDeps := &api.SubmissionDeps{
		DB:             pools.Write,
		EntryStore:     entryStore,
		EntryWriter:    entryBytes,
		CreditStore:    creditStore,
		Queue:          queue,
		LogDID:         cfg.LogDID,
		MaxEntrySize:   int64(cfg.MaxEntrySize),
		DiffController: diffController,
		Logger:         logger,

		// Phase 4: replace with did.NewResolver(httpClient) when DID
		// resolution infrastructure is deployed. nil = Phase 2 trust model.
		DIDResolver: nil,
	}

	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore,
		Inclusion:     tesseraAdapter,
		Consistency:   tesseraAdapter,
		Logger:        logger,
	}

	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}

	queryDeps := &api.QueryDeps{
		QueryAPI:       queryAPI,
		DiffController: diffController,
		Logger:         logger,
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

		// Witness cosign endpoint: nil until witness key is configured.
		// When this operator serves as a witness for peer logs:
		//   witnessKey := loadWitnessKey(cfg)
		//   handlers.WitnessCosign = witness.NewCosignHandler(witness.ServeConfig{
		//       WitnessKey: witnessKey,
		//       Logger:     logger,
		//   })
		WitnessCosign: nil,
	}

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr
	serverCfg.MaxEntrySize = int64(cfg.MaxEntrySize)

	server := api.NewServer(serverCfg, pools.Write, handlers, logger)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil {
			logger.Error("http server exited", "error", err)
		}
	}()
	logger.Info("HTTP server started", "addr", cfg.ServerAddr)

	// ── Steps 15-16: Block on signals + graceful shutdown ──────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("shutdown signal received", "signal", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown error", "error", err)
	}

	cancel()
	wg.Wait()
	logger.Info("all goroutines stopped, exiting cleanly")
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

type operatorConfig struct {
	LogDID             string
	OperatorDID        string
	PostgresDSN        string
	ReplicaDSN         string // optional — GET queries use this if set
	MaxConns           int
	MinConns           int
	ServerAddr         string
	MaxEntrySize       int
	TesseraBaseURL     string
	TileCacheSize      int
	WarmTopLevels      int
	SMTCacheSize       int
	DeltaWindowSize    int
	CommitmentInterval int
	CommitmentMaxAge   time.Duration
	WitnessEndpoints   []string
	WitnessQuorumK     int
	PeerEndpoints      []string
	AnchorEnabled      bool
	AnchorSources      []anchor.AnchorSource
	InitialDifficulty  int
	MinDifficulty      int
	MaxDifficulty      int
	LowThreshold       int
	HighThreshold      int
	HashFunction       string
}

func loadConfig() operatorConfig {
	return operatorConfig{
		LogDID:             envOr("ORTHOLOG_LOG_DID", "did:ortholog:operator:001"),
		OperatorDID:        envOr("ORTHOLOG_OPERATOR_DID", "did:ortholog:operator:001:signer"),
		PostgresDSN:        envOr("ORTHOLOG_POSTGRES_DSN", "postgres://ortholog:ortholog@localhost:5432/ortholog?sslmode=disable"),
		ReplicaDSN:         envOr("ORTHOLOG_REPLICA_DSN", ""),
		MaxConns:           20,
		MinConns:           5,
		ServerAddr:         envOr("ORTHOLOG_SERVER_ADDR", ":8080"),
		MaxEntrySize:       1 << 20,
		TesseraBaseURL:     envOr("ORTHOLOG_TESSERA_URL", "http://localhost:2024"),
		TileCacheSize:      10000,
		WarmTopLevels:      32,
		SMTCacheSize:       100000,
		DeltaWindowSize:    10,
		CommitmentInterval: 1000,
		CommitmentMaxAge:   1 * time.Hour,
		WitnessEndpoints:   nil,
		WitnessQuorumK:     2,
		PeerEndpoints:      nil,
		AnchorEnabled:      false,
		AnchorSources:      nil,
		InitialDifficulty:  16,
		MinDifficulty:      8,
		MaxDifficulty:      24,
		LowThreshold:       100,
		HighThreshold:      10000,
		HashFunction:       "sha256",
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
