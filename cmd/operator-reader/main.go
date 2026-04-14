/*
FILE PATH: cmd/operator-reader/main.go

Read-only Ortholog log operator. Serves all GET endpoints.
Does NOT run the builder loop, accept submissions, or write anything.

CHANGES:
  - 5 new read handlers: EntryBySequence, EntryBatch, SMTLeaf, SMTLeafBatch, CommitmentQuery
  - CommitmentStore created on read pool
  - No shard wiring (deferred post Phase 6)
  - No SchemaResolver (reader doesn't run builder loop)
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

	"github.com/clearcompass-ai/ortholog-operator/api"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("operator-reader fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := loadConfig()
	logger.Info("config loaded (read-only mode)", "log_did", cfg.LogDID, "addr", cfg.ServerAddr)

	// ── Postgres read pool ─────────────────────────────────────────────
	dsn := cfg.ReplicaDSN
	if dsn == "" {
		dsn = cfg.PostgresDSN
	}
	pool, err := store.InitPool(ctx, store.PoolConfig{
		DSN:             dsn,
		MaxConns:        int32(cfg.MaxConns),
		MinConns:        int32(cfg.MinConns),
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("postgres pool: %w", err)
	}
	defer pool.Close()
	logger.Info("postgres read pool initialized", "replica", cfg.ReplicaDSN != "")

	// ── Tessera ────────────────────────────────────────────────────────
	tileBackend := tessera.NewHTTPTileBackend(cfg.TesseraBaseURL)
	tileReader := tessera.NewTileReader(tileBackend, cfg.TileCacheSize)
	entryReader := tessera.NewTesseraEntryReader(tileReader)
	tesseraClient := tessera.NewClient(tessera.ClientConfig{
		BaseURL: cfg.TesseraBaseURL,
		Timeout: 30 * time.Second,
	}, logger)
	tesseraAdapter := tessera.NewTesseraAdapter(tesseraClient, tileReader, logger)
	logger.Info("tessera initialized", "url", cfg.TesseraBaseURL)

	// ── SMT (read-only) ────────────────────────────────────────────────
	leafStore := store.NewPostgresLeafStore(pool.DB)
	nodeCache := store.NewPostgresNodeCache(pool.DB, cfg.SMTCacheSize)
	tree := smt.NewTree(leafStore, nodeCache)
	if err := nodeCache.WarmCache(ctx, cfg.WarmTopLevels); err != nil {
		logger.Warn("cache warm failed (non-fatal)", "error", err)
	}

	// ── Stores ─────────────────────────────────────────────────────────
	treeHeadStore := store.NewTreeHeadStore(pool.DB)
	commitmentStore := store.NewCommitmentStore(pool.DB)
	fetcher := store.NewPostgresEntryFetcher(pool.DB, entryReader, cfg.LogDID)

	// ── Difficulty (static) ────────────────────────────────────────────
	diffController := middleware.NewDifficultyController(
		nil,
		middleware.DifficultyConfig{
			InitialDifficulty: uint32(cfg.InitialDifficulty),
			MinDifficulty:     uint32(cfg.MinDifficulty),
			MaxDifficulty:     uint32(cfg.MaxDifficulty),
			HashFunction:      cfg.HashFunction,
		}, logger,
	)

	// ── Query API ──────────────────────────────────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(pool.DB, entryReader, cfg.LogDID)

	// ── HTTP handlers ──────────────────────────────────────────────────
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
		Submission:      nil, // No POST /v1/entries in read-only mode.
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
	server := api.NewServer(serverCfg, pool.DB, handlers, logger)

	// ── Start + shutdown ───────────────────────────────────────────────
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil {
			logger.Error("http server exited", "error", err)
		}
	}()
	logger.Info("HTTP server started (read-only)", "addr", cfg.ServerAddr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("shutdown signal received", "signal", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	cancel()
	wg.Wait()
	logger.Info("operator-reader stopped cleanly")
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

type readerConfig struct {
	LogDID            string
	PostgresDSN       string
	ReplicaDSN        string
	MaxConns          int
	MinConns          int
	ServerAddr        string
	TesseraBaseURL    string
	TileCacheSize     int
	WarmTopLevels     int
	SMTCacheSize      int
	InitialDifficulty int
	MinDifficulty     int
	MaxDifficulty     int
	HashFunction      string
}

func loadConfig() readerConfig {
	return readerConfig{
		LogDID:            envOr("ORTHOLOG_LOG_DID", "did:ortholog:operator:001"),
		PostgresDSN:       envOr("ORTHOLOG_POSTGRES_DSN", "postgres://ortholog:ortholog@localhost:5432/ortholog?sslmode=disable"),
		ReplicaDSN:        envOr("ORTHOLOG_REPLICA_DSN", ""),
		MaxConns:          20,
		MinConns:          5,
		ServerAddr:        envOr("ORTHOLOG_SERVER_ADDR", ":8081"),
		TesseraBaseURL:    envOr("ORTHOLOG_TESSERA_URL", "http://localhost:2024"),
		TileCacheSize:     10000,
		WarmTopLevels:     32,
		SMTCacheSize:      100000,
		InitialDifficulty: 16,
		MinDifficulty:     8,
		MaxDifficulty:     24,
		HashFunction:      "sha256",
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
