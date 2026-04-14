/*
FILE PATH: cmd/operator-reader/main.go

Read-only Ortholog log operator. Serves all GET endpoints.
Does NOT run the builder loop, accept submissions, or write anything.

Deploy N instances behind a load balancer. Stateless — any instance
serves any request. Connects to a Postgres read replica and Tessera
tile storage (URL). Infrastructure behind that URL (CDN, nginx,
object store) is a deployment decision, not operator code.

USE CASES:
  - Horizontal read scaling for query-heavy workloads.
  - Public API instances serving court record lookups.
  - Monitoring service endpoints.
  - Cross-network verification responders.

WHAT'S MISSING vs cmd/operator/main.go:
  - No builder loop (no advisory lock, no queue, no delta buffer).
  - No POST /v1/entries (no submission handler, no credit store).
  - No anchor publisher, no equivocation monitor.
  - No write pool — connects to replica_dsn only.
  - Difficulty served from config (static, not queue-adaptive).
  - No witness cosign endpoint (read-only instances don't sign).
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

	// ── Load config ────────────────────────────────────────────────────
	cfg := loadConfig()
	logger.Info("config loaded (read-only mode)", "log_did", cfg.LogDID, "addr", cfg.ServerAddr)

	// ── Initialize Postgres read pool ──────────────────────────────────
	// Connects to replica_dsn if set, otherwise primary dsn.
	// Read-only — never writes.
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

	// ── Tessera tile reader ────────────────────────────────────────────
	tileBackend := tessera.NewHTTPTileBackend(cfg.TesseraBaseURL)
	tileReader := tessera.NewTileReader(tileBackend, cfg.TileCacheSize)
	logger.Info("tessera tile reader initialized", "url", cfg.TesseraBaseURL)

	// ── Entry byte reader ──────────────────────────────────────────────
	entryReader := tessera.NewTesseraEntryReader(tileReader)

	// ── Tessera adapter (for proof endpoints) ──────────────────────────
	tesseraClient := tessera.NewClient(tessera.ClientConfig{
		BaseURL: cfg.TesseraBaseURL,
		Timeout: 30 * time.Second,
	}, logger)
	tesseraAdapter := tessera.NewTesseraAdapter(tesseraClient, tileReader, logger)

	// ── SMT (read-only — for proof endpoints) ──────────────────────────
	leafStore := store.NewPostgresLeafStore(pool.DB)
	nodeCache := store.NewPostgresNodeCache(pool.DB, cfg.SMTCacheSize)
	tree := smt.NewTree(leafStore, nodeCache)

	// ── Warm SMT cache ─────────────────────────────────────────────────
	if err := nodeCache.WarmCache(ctx, cfg.WarmTopLevels); err != nil {
		logger.Warn("cache warm failed (non-fatal)", "error", err)
	}

	// ── Stores (read-only) ─────────────────────────────────────────────
	treeHeadStore := store.NewTreeHeadStore(pool.DB)

	// ── Difficulty (static from config — no queue to poll) ─────────────
	diffController := middleware.NewDifficultyController(
		nil, // No queue — static difficulty from config.
		middleware.DifficultyConfig{
			InitialDifficulty: uint32(cfg.InitialDifficulty),
			MinDifficulty:     uint32(cfg.MinDifficulty),
			MaxDifficulty:     uint32(cfg.MaxDifficulty),
			HashFunction:      cfg.HashFunction,
		}, logger,
	)
	// NOTE: diffController.Run() is NOT started. CurrentDifficulty()
	// returns InitialDifficulty. The primary operator serves the
	// dynamic difficulty. Read-only instances serve the configured default.

	// ── Query API (read pool + entry reader) ───────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(pool.DB, entryReader, cfg.LogDID)

	// ── HTTP handlers (GET only — no submission handler) ───────────────
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
		WitnessCosign:   nil, // Read-only instances never serve as witnesses.
	}

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr

	server := api.NewServer(serverCfg, pool.DB, handlers, logger)

	// ── Start HTTP server ──────────────────────────────────────────────
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil {
			logger.Error("http server exited", "error", err)
		}
	}()
	logger.Info("HTTP server started (read-only)", "addr", cfg.ServerAddr)

	// ── Block on signals + shutdown ────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("shutdown signal received", "signal", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown error", "error", err)
	}

	cancel()
	wg.Wait()
	logger.Info("operator-reader stopped cleanly")
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration (subset of full operator config — no builder/submission fields)
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
