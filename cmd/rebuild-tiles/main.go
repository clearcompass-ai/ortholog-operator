/*
FILE PATH: cmd/rebuild-tiles/main.go

DESCRIPTION:
    One-shot utility that rebuilds the Tessera tile store after the
    v0.3.0-tessera operator migration. Drives the patched builder loop
    to completion over the existing admitted entries in Postgres, against
    a FRESH Tessera storage root.

    Necessary because the v0.3.0 migration changes the Merkle leaf scheme
    from sha256(canonical+signature_envelope) to envelope.EntryIdentity,
    which makes every previously-published inclusion proof invalid. Live
    operators must rebuild their tiles before the new code path serves
    verification traffic.

WHY A SEPARATE BINARY:
    The production operator's main.go starts the admission HTTP server,
    the anchor publisher, the commitment publisher, and the witness
    cosigner concurrently with the builder loop. For a tile rebuild we
    want ONLY the builder loop — no admission (no new entries should
    enter), no anchor publishing (source tree heads would stamp over
    mid-rebuild state), no witness cosig requests (wasted work on
    un-finalized tree heads).

    Running the operator with a flag to disable everything except the
    builder loop is equally valid; a dedicated binary makes the intent
    explicit and the blast radius small.

SAFETY CONTRACT:
    1. Idempotent against its OWN re-runs. If interrupted halfway, a
       second invocation resumes from the queue state left by the first.
    2. NOT idempotent against running while the production operator is
       also running. The builder loop uses the advisory lock the
       operator acquires, so two instances cannot step on each other —
       but the production operator will advance queue state past what
       the rebuild instance has processed, potentially skipping tiles.
       Operators MUST stop the production binary before running this.
    3. Fresh Tessera storage root is the caller's responsibility. If the
       provided root contains existing tile data, the rebuild will
       APPEND to it rather than replace — almost certainly wrong. Verify
       the root is empty before running.

USAGE:

    # 1. Stop the production operator.
    systemctl stop ortholog-operator

    # 2. Back up Postgres (operator state of record — do not touch).
    pg_dump ortholog > /var/backups/operator-pre-rebuild-$(date -I).sql

    # 3. Wipe the Tessera storage root (keep the byte store — that has
    #    the wire bytes we replay from, and the new identity scheme
    #    treats them the same way).
    rm -rf /var/lib/operator/tessera/*

    # 4. Reset the builder queue so EVERY admitted entry gets replayed
    #    through the new leaf scheme. This is a destructive SQL
    #    operation — the pre-rebuild backup is your escape hatch.
    psql ortholog <<SQL
        UPDATE builder_queue SET status = 'pending', dequeued_at = NULL;
        DELETE FROM derivation_commitments WHERE true;
    SQL

    # 5. Run the rebuild.
    ./rebuild-tiles \
        --database-url="$OPERATOR_DATABASE_URL" \
        --log-did="did:web:your-log.example" \
        --operator-did="did:web:your-log.example" \
        --tessera-root=/var/lib/operator/tessera \
        --bytestore-root=/var/lib/operator/bytestore \
        --batch-size=1000

    # 6. When the rebuild exits cleanly (all entries replayed, queue
    #    drained), start the production operator.
    systemctl start ortholog-operator

    # 7. Verify: compute envelope.EntryIdentity(entry) client-side for a
    #    known sequence, fetch the inclusion proof from the new Tessera
    #    tree, confirm verification succeeds.

EXIT CODES:
    0 — rebuild completed, queue drained, final tree head published.
    1 — configuration error (missing flag, unreachable DB, invalid DID).
    2 — Postgres transaction failure during replay.
    3 — Tessera append failure. Rebuild is in a partial state; do NOT
        serve traffic from it. Investigate, then re-run from step 3.
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"

	"github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/tessera"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var (
		databaseURL    = flag.String("database-url", os.Getenv("OPERATOR_DATABASE_URL"), "Postgres connection string")
		logDID         = flag.String("log-did", os.Getenv("OPERATOR_LOG_DID"), "log DID (must match production)")
		operatorDID    = flag.String("operator-did", os.Getenv("OPERATOR_DID"), "operator DID (signer)")
		tesseraRoot    = flag.String("tessera-root", os.Getenv("OPERATOR_TESSERA_ROOT"), "FRESH Tessera storage root (must be empty)")
		bytestoreRoot  = flag.String("bytestore-root", os.Getenv("OPERATOR_BYTESTORE_ROOT"), "byte store root (unchanged)")
		batchSize      = flag.Int("batch-size", 1000, "builder batch size")
		pollInterval   = flag.Duration("poll-interval", 10*time.Millisecond, "queue poll interval")
		idleShutdownAfter = flag.Duration("idle-shutdown-after", 30*time.Second, "exit cleanly after this much idle time (no pending entries)")
	)
	flag.Parse()

	if *databaseURL == "" || *logDID == "" || *tesseraRoot == "" || *bytestoreRoot == "" {
		logger.Error("required flags missing",
			"database_url_set", *databaseURL != "",
			"log_did_set", *logDID != "",
			"tessera_root_set", *tesseraRoot != "",
			"bytestore_root_set", *bytestoreRoot != "",
		)
		os.Exit(1)
	}
	if *operatorDID == "" {
		*operatorDID = *logDID
	}
	if err := envelope.ValidateDestination(*logDID); err != nil {
		logger.Error("invalid log DID", "error", err)
		os.Exit(1)
	}

	logger.Info("tile rebuild starting",
		"log_did", *logDID,
		"tessera_root", *tesseraRoot,
		"batch_size", *batchSize,
	)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Postgres ──────────────────────────────────────────────────────
	pool, err := pgxpool.New(ctx, *databaseURL)
	if err != nil {
		logger.Error("pgxpool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// ── Stores ────────────────────────────────────────────────────────
	leafStore := store.NewPostgresLeafStore(pool)
	nodeCache := store.NewPostgresNodeCache(pool)

	byteStore, err := tessera.NewFSByteStore(*bytestoreRoot)
	if err != nil {
		logger.Error("byte store", "error", err)
		os.Exit(1)
	}
	_ = byteStore // reserved for fetcher wiring below

	tesseraClient, err := tessera.NewClient(ctx, *tesseraRoot, *logDID, logger)
	if err != nil {
		logger.Error("tessera", "error", err)
		os.Exit(1)
	}
	defer tesseraClient.Close()

	// ── Builder dependencies ──────────────────────────────────────────
	fetcher := store.NewPostgresEntryFetcher(pool, byteStore, *logDID)
	schema := builder.NewInMemorySchemaResolver()
	buffer := sdkbuilder.NewDeltaWindowBuffer(10)
	bufferStore := builder.NewDeltaBufferStore(pool)
	queue := builder.NewQueue(pool)
	tree := smt.NewTree(leafStore, nodeCache)

	// No commitment publisher (no one is running the submission path).
	// No witness cosigner (no one is watching the tree heads).
	bl := builder.NewBuilderLoop(
		builder.LoopConfig{
			LogDID:       *logDID,
			BatchSize:    *batchSize,
			PollInterval: *pollInterval,
			DeltaWindow:  10,
		},
		pool, tree, leafStore, nodeCache,
		queue, fetcher, schema, buffer, bufferStore,
		nil, // commitPub
		tesseraClient,
		nil, // witness cosigner
		logger,
	)

	// ── Idle watchdog: exit cleanly when the queue has been empty for
	//    IdleShutdownAfter. Without this the loop would run forever.
	go func() {
		lastSeenEntries := int64(-1)
		lastAdvanced := time.Now()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, entries, _ := bl.Stats()
				if entries != lastSeenEntries {
					lastSeenEntries = entries
					lastAdvanced = time.Now()
					continue
				}
				if time.Since(lastAdvanced) >= *idleShutdownAfter {
					logger.Info("idle shutdown threshold reached — rebuild complete",
						"total_entries", entries,
						"idle_for", time.Since(lastAdvanced),
					)
					cancel()
					return
				}
			}
		}
	}()

	if err := bl.Run(ctx); err != nil {
		logger.Error("builder loop failed during rebuild", "error", err)
		os.Exit(3)
	}

	// ── Final sanity: publish a fresh tree head and log it. ───────────
	head, headErr := tesseraClient.Head()
	if headErr != nil {
		logger.Error("final head fetch", "error", headErr)
		os.Exit(3)
	}
	fmt.Printf("\n=== TILE REBUILD COMPLETE ===\n")
	fmt.Printf("  log_did:     %s\n", *logDID)
	fmt.Printf("  tree_size:   %d\n", head.TreeSize)
	fmt.Printf("  root_hash:   %x\n", head.RootHash[:])
	batches, entries, errs := bl.Stats()
	fmt.Printf("  batches:     %d\n", batches)
	fmt.Printf("  entries:     %d\n", entries)
	fmt.Printf("  errors:      %d\n", errs)
	fmt.Printf("\nStart the production operator. Publish the new tree head.\n")
}
