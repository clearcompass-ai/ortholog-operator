/*
FILE PATH: cmd/operator/main.go

DESCRIPTION:
    Operator binary entry point. Wires config → stores → subsystems → HTTP
    server, then runs the builder loop, anchor publisher, commitment
    publisher, and witness cosigner as cooperating goroutines under a
    shared context.

SDK v0.3.0 WIRING CHANGES:
    1. anchor.PublisherConfig now requires LogDID — threaded from cfg.LogDID.
    2. builder.NewCommitmentPublisher signature changed: (operatorDID,
       logDID, ...) — both DIDs passed explicitly.
    3. api.SubmissionDeps now has FreshnessTolerance (defaults to
       policy.FreshnessInteractive=5min if left zero). Explicit here for
       auditability.
    4. Phase 4 DID verifier registry scaffolded behind a nil check —
       when consumers are ready, swap the nil for
       did.DefaultVerifierRegistry(cfg.LogDID, resolver).

INVARIANTS:
    - cfg.LogDID MUST be non-empty: submission handler panics at
      construction otherwise (destination-binding enforcement gate).
    - cfg.OperatorDID SHOULD differ from cfg.LogDID but may collapse in
      single-exchange deployments where the operator IS the exchange.
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

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"

	"github.com/clearcompass-ai/ortholog-operator/anchor"
	"github.com/clearcompass-ai/ortholog-operator/api"
	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	"github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
	"github.com/clearcompass-ai/ortholog-operator/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────

type Config struct {
	ServerAddr            string
	DatabaseURL           string
	LogDID                string // Destination for self-published entries (anchors, commitments).
	OperatorDID           string // Signer DID for operator-authored commentary.
	MaxEntrySize          int64
	BatchSize             int
	PollInterval          time.Duration
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
	AnchorInterval        time.Duration
	AnchorSources         []anchor.AnchorSource
	TesseraStorageRoot    string
	WitnessEndpoints      []string
	WitnessQuorumK        int
	ByteStoreRoot         string
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		ServerAddr:            envOr("OPERATOR_ADDR", ":8080"),
		DatabaseURL:           os.Getenv("OPERATOR_DATABASE_URL"),
		LogDID:                os.Getenv("OPERATOR_LOG_DID"),
		OperatorDID:           os.Getenv("OPERATOR_DID"),
		MaxEntrySize:          1 << 20,
		BatchSize:              1000,
		PollInterval:           100 * time.Millisecond,
		EpochWindowSeconds:    3600,
		EpochAcceptanceWindow: 1,
		AnchorInterval:         1 * time.Hour,
		TesseraStorageRoot:     envOr("OPERATOR_TESSERA_ROOT", "/var/lib/operator/tessera"),
		WitnessQuorumK:         1,
		ByteStoreRoot:          envOr("OPERATOR_BYTESTORE_ROOT", "/var/lib/operator/bytestore"),
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("OPERATOR_DATABASE_URL required")
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("OPERATOR_LOG_DID required (destination-binding)")
	}
	if cfg.OperatorDID == "" {
		cfg.OperatorDID = cfg.LogDID // Default to single-exchange deployment.
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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

	// Fail-fast sanity check on the LogDID before we touch Postgres.
	if valErr := envelope.ValidateDestination(cfg.LogDID); valErr != nil {
		logger.Error("invalid OPERATOR_LOG_DID", "error", valErr)
		os.Exit(1)
	}

	logger.Info("operator starting",
		"log_did", cfg.LogDID,
		"operator_did", cfg.OperatorDID,
		"addr", cfg.ServerAddr,
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

	// ── Stores ────────────────────────────────────────────────────────
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	commitStore := store.NewCommitmentStore(pool)
	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeCache(pool)

	// ── Byte store + Tessera ──────────────────────────────────────────
	byteStore, err := tessera.NewFSByteStore(cfg.ByteStoreRoot)
	if err != nil {
		logger.Error("byte store", "error", err)
		os.Exit(1)
	}

	tesseraClient, err := tessera.NewClient(ctx, cfg.TesseraStorageRoot, cfg.LogDID, logger)
	if err != nil {
		logger.Error("tessera", "error", err)
		os.Exit(1)
	}
	defer tesseraClient.Close()

	// ── Builder dependencies ──────────────────────────────────────────
	fetcher := store.NewPostgresEntryFetcher(pool, byteStore, cfg.LogDID)
	schema := builder.NewInMemorySchemaResolver() // Replace with SDK schema resolver when ready.
	buffer := sdkbuilder.NewDeltaWindowBuffer(10)
	bufferStore := builder.NewDeltaBufferStore(pool)
	queue := builder.NewQueue(pool)
	tree := smt.NewTree(leafStore, nodeCache)

	// Restore buffer from persistence (cold start = strict OCC per SDK-D9).
	if loadErr := bufferStore.Load(ctx, buffer); loadErr != nil {
		logger.Warn("delta buffer load — starting cold", "error", loadErr)
	}

	// ── Commitment publisher — LogDID threaded (v0.3.0) ───────────────
	commitPub := builder.NewCommitmentPublisher(
		cfg.OperatorDID,
		cfg.LogDID, // NEW: destination-binding for self-published commentary.
		builder.CommitmentPublisherConfig{
			IntervalEntries: 1000,
			IntervalTime:    1 * time.Hour,
		},
		anchor.SubmitViaHTTP(fmt.Sprintf("http://localhost%s", cfg.ServerAddr)),
		logger,
	).WithCommitmentStore(commitStore)

	// ── Admission controller ──────────────────────────────────────────
	diffController := middleware.NewDifficultyController(
		middleware.DifficultyConfig{
			MinDifficulty:   8,
			MaxDifficulty:   24,
			TargetQueueSize: 500,
		}, logger,
	)

	// ── Witness cosigner ──────────────────────────────────────────────
	var cosigner builder.WitnessCosigner
	if len(cfg.WitnessEndpoints) > 0 {
		cosigner = witness.NewRequester(cfg.WitnessEndpoints, cfg.WitnessQuorumK, logger)
	}

	// ── Builder loop ──────────────────────────────────────────────────
	loopCfg := builder.DefaultLoopConfig(cfg.LogDID)
	loopCfg.BatchSize = cfg.BatchSize
	loopCfg.PollInterval = cfg.PollInterval

	bl := builder.NewBuilderLoop(
		loopCfg, pool, tree, leafStore, nodeCache,
		queue, fetcher, schema, buffer, bufferStore,
		commitPub, tesseraClient, cosigner, logger,
	)

	// ── Anchor publisher — LogDID threaded (v0.3.0) ───────────────────
	anchorPub := anchor.NewPublisher(
		anchor.PublisherConfig{
			OperatorDID:   cfg.OperatorDID,
			LogDID:        cfg.LogDID, // NEW: destination-binding.
			Interval:      cfg.AnchorInterval,
			AnchorSources: cfg.AnchorSources,
		},
		tesseraClient,
		anchor.SubmitViaHTTP(fmt.Sprintf("http://localhost%s", cfg.ServerAddr)),
		logger,
	)

	// ── Submission handler — FreshnessTolerance explicit (v0.3.0) ─────
	submitHandler := api.NewSubmissionHandler(&api.SubmissionDeps{
		Storage: api.StorageDeps{
			DB:          pool,
			EntryStore:  entryStore,
			EntryWriter: tesseraClient, // satisfies tessera.EntryWriter via byteStore
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    cfg.EpochWindowSeconds,
			EpochAcceptanceWindow: cfg.EpochAcceptanceWindow,
		},
		Identity: api.IdentityDeps{
			CreditStore: creditStore,
			DIDResolver: nil, // Phase 4: swap for did.DefaultVerifierRegistry wrapper.
		},
		Queue:              queue,
		LogDID:             cfg.LogDID,
		MaxEntrySize:       cfg.MaxEntrySize,
		Logger:             logger,
		FreshnessTolerance: policy.FreshnessInteractive, // 5-min late-replay window.
	})

	// ── Query handlers ────────────────────────────────────────────────
	queryDeps := &api.QueryDeps{
		DB:          pool,
		EntryStore:  entryStore,
		EntryReader: tesseraClient,
		Logger:      logger,
	}

	// ── HTTP router ───────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/entries", submitHandler)
	mux.HandleFunc("GET /v1/entries", api.NewRangeQueryHandler(queryDeps))
	mux.HandleFunc("GET /v1/entries/hash/", api.NewHashLookupHandler(queryDeps))
	mux.HandleFunc("GET /v1/entries/", api.NewRawEntryHandler(queryDeps))
	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","log_did":"` + cfg.LogDID + `"}`))
	})

	srv := &http.Server{Addr: cfg.ServerAddr, Handler: mux}

	// ── Run goroutines ────────────────────────────────────────────────
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("HTTP server listening", "addr", cfg.ServerAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
		anchorPub.Run(ctx)
	}()

	// ── Shutdown ──────────────────────────────────────────────────────
	<-ctx.Done()
	logger.Info("shutdown initiated")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown", "error", err)
	}

	wg.Wait()

	b, e, errs := bl.Stats()
	logger.Info("operator stopped",
		"batches", b, "entries", e, "errors", errs,
	)
}
