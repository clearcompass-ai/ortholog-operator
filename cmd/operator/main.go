/*
FILE PATH: cmd/operator/main.go

Entry point for the Ortholog log operator (read-write mode).

CHANGES:
  - SchemaResolver: schema.NewCachingResolver() from SDK (one line, no wrapper)
  - submitFn: anchor.SubmitViaHTTP (correction #6)
  - CommitmentStore: created + wired via WithCommitmentStore
  - 5 new handlers: EntryBySequence, EntryBatch, SMTLeaf, SMTLeafBatch, CommitmentQuery
  - SubmissionDeps refactored into sub-structs (StorageDeps + AdmissionConfig + IdentityDeps)
  - Epoch config (EpochWindowSeconds + EpochAcceptanceWindow) for SDK-2 stamp validation
*/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"

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

	// ── Step 2: Initialize Postgres pools ──────────────────────────────
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

	// ── Step 3: Run migrations ─────────────────────────────────────────
	if err := store.RunMigrations(ctx, pools.Write); err != nil {
		return fmt.Errorf("step 3: %w", err)
	}
	logger.Info("migrations complete")

	// ── Step 4-5: Tessera ──────────────────────────────────────────────
	tesseraClient := tessera.NewClient(tessera.ClientConfig{
		BaseURL: cfg.TesseraBaseURL,
		Timeout: 30 * time.Second,
	}, logger)
	tileBackend := tessera.NewHTTPTileBackend(cfg.TesseraBaseURL)
	tileReader := tessera.NewTileReader(tileBackend, cfg.TileCacheSize)
	tesseraAdapter := tessera.NewTesseraAdapter(tesseraClient, tileReader, logger)
	entryBytes := tessera.NewInMemoryEntryStore()

	// ── Step 6-7: SMT ──────────────────────────────────────────────────
	leafStore := store.NewPostgresLeafStore(pools.Write)
	nodeCache := store.NewPostgresNodeCache(pools.Write, cfg.SMTCacheSize)
	tree := smt.NewTree(leafStore, nodeCache)
	if err := nodeCache.WarmCache(ctx, cfg.WarmTopLevels); err != nil {
		logger.Warn("cache warm failed (non-fatal)", "error", err)
	} else {
		logger.Info("SMT cache warmed", "top_levels", cfg.WarmTopLevels)
	}

	// ── Step 8: Delta buffer ───────────────────────────────────────────
	bufferStore := opbuilder.NewDeltaBufferStore(pools.Write, cfg.DeltaWindowSize, logger)
	deltaBuffer, err := bufferStore.Load(ctx)
	if err != nil {
		logger.Warn("delta buffer load failed (cold start)", "error", err)
	}
	logger.Info("delta buffer loaded")

	// ── Step 9: Witness set ────────────────────────────────────────────
	witnessKeys, schemeTag, err := witness.LoadCurrentSet(ctx, pools.Read)
	if err != nil {
		logger.Warn("witness set not found (genesis deployment)", "error", err)
		witnessKeys = nil
		schemeTag = 1
	}
	logger.Info("witness set loaded", "keys", len(witnessKeys), "scheme", schemeTag)

	// ── Builder advisory lock ──────────────────────────────────────────
	releaseLock, err := store.AcquireBuilderLock(ctx, pools.Write)
	if err != nil {
		return fmt.Errorf("builder lock: %w", err)
	}
	defer releaseLock()
	logger.Info("builder advisory lock acquired")

	// ── Step 10: Builder loop ──────────────────────────────────────────
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

	commitmentStore := store.NewCommitmentStore(pools.Write)
	schemaResolver := schema.NewCachingResolver()
	submitFn := anchor.SubmitViaHTTP(fmt.Sprintf("http://localhost%s", cfg.ServerAddr))

	commitPub := opbuilder.NewCommitmentPublisher(
		cfg.OperatorDID,
		opbuilder.CommitmentPublisherConfig{
			IntervalEntries: cfg.CommitmentInterval,
			IntervalTime:    cfg.CommitmentMaxAge,
		},
		submitFn,
		logger,
	).WithCommitmentStore(commitmentStore)

	builderLoop := opbuilder.NewBuilderLoop(
		opbuilder.DefaultLoopConfig(cfg.LogDID),
		pools.Write, tree, leafStore, nodeCache,
		queue, fetcher, schemaResolver, deltaBuffer, bufferStore, commitPub,
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

	// ── Step 11: Equivocation monitor ──────────────────────────────────
	if len(cfg.PeerEndpoints) > 0 {
		eqMonitor := witness.NewEquivocationMonitor(
			witness.EquivocationMonitorConfig{
				PeerEndpoints: cfg.PeerEndpoints,
				PollInterval:  5 * time.Minute,
			}, pools.Write, treeHeadStore, logger)
		wg.Add(1)
		go func() { defer wg.Done(); eqMonitor.Run(ctx) }()
		logger.Info("equivocation monitor started", "peers", len(cfg.PeerEndpoints))
	}

	// ── Step 12: Anchor publisher ──────────────────────────────────────
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
		go func() { defer wg.Done(); anchorPub.Run(ctx) }()
		logger.Info("anchor publisher started", "sources", len(cfg.AnchorSources))
	}

	// ── Step 13: Difficulty controller ──────────────────────────────────
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
	go func() { defer wg.Done(); diffController.Run(ctx, 30*time.Second) }()

	// ── Step 14: HTTP server ───────────────────────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(pools.Read, entryBytes, cfg.LogDID)

	// Build SubmissionDeps using the cohesive sub-structs.
	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			DB:          pools.Write,
			EntryStore:  entryStore,
			EntryWriter: entryBytes,
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    cfg.EpochWindowSeconds,
			EpochAcceptanceWindow: cfg.EpochAcceptanceWindow,
		},
		Identity: api.IdentityDeps{
			CreditStore: creditStore,
			DIDResolver: nil,
		},
		Queue:        queue,
		LogDID:       cfg.LogDID,
		MaxEntrySize: int64(cfg.MaxEntrySize),
		Logger:       logger,
	}

	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore, Inclusion: tesseraAdapter,
		Consistency: tesseraAdapter, Logger: logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	queryDeps := &api.QueryDeps{
		QueryAPI: queryAPI, DiffController: diffController, Logger: logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher: fetcher, QueryAPI: queryAPI,
		LogDID: cfg.LogDID, Logger: logger,
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

	// ── Steps 15-16: Signals + shutdown ────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("shutdown signal received", "signal", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	cancel()
	wg.Wait()
	logger.Info("all goroutines stopped, exiting cleanly")
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

type operatorConfig struct {
	LogDID                string
	OperatorDID           string
	PostgresDSN           string
	ReplicaDSN            string
	MaxConns              int
	MinConns              int
	ServerAddr            string
	MaxEntrySize          int
	TesseraBaseURL        string
	TileCacheSize         int
	WarmTopLevels         int
	SMTCacheSize          int
	DeltaWindowSize       int
	CommitmentInterval    int
	CommitmentMaxAge      time.Duration
	WitnessEndpoints      []string
	WitnessQuorumK        int
	PeerEndpoints         []string
	AnchorEnabled         bool
	AnchorSources         []anchor.AnchorSource
	InitialDifficulty     int
	MinDifficulty         int
	MaxDifficulty         int
	LowThreshold          int
	HighThreshold         int
	HashFunction          string
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
}

func loadConfig() operatorConfig {
	return operatorConfig{
		LogDID:                envOr("ORTHOLOG_LOG_DID", "did:ortholog:operator:001"),
		OperatorDID:           envOr("ORTHOLOG_OPERATOR_DID", "did:ortholog:operator:001:signer"),
		PostgresDSN:           envOr("ORTHOLOG_POSTGRES_DSN", "postgres://ortholog:ortholog@localhost:5432/ortholog?sslmode=disable"),
		ReplicaDSN:            envOr("ORTHOLOG_REPLICA_DSN", ""),
		MaxConns:              20,
		MinConns:              5,
		ServerAddr:            envOr("ORTHOLOG_SERVER_ADDR", ":8080"),
		MaxEntrySize:          1 << 20,
		TesseraBaseURL:        envOr("ORTHOLOG_TESSERA_URL", "http://localhost:2024"),
		TileCacheSize:         10000,
		WarmTopLevels:         32,
		SMTCacheSize:          100000,
		DeltaWindowSize:       10,
		CommitmentInterval:    1000,
		CommitmentMaxAge:      1 * time.Hour,
		WitnessEndpoints:      nil,
		WitnessQuorumK:        2,
		PeerEndpoints:         nil,
		AnchorEnabled:         false,
		AnchorSources:         nil,
		InitialDifficulty:     16,
		MinDifficulty:         8,
		MaxDifficulty:         24,
		LowThreshold:          100,
		HighThreshold:         10000,
		HashFunction:          "sha256",
		EpochWindowSeconds:    envIntOr("ORTHOLOG_EPOCH_WINDOW_SECONDS", 3600),
		EpochAcceptanceWindow: envIntOr("ORTHOLOG_EPOCH_ACCEPTANCE_WINDOW", 1),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
