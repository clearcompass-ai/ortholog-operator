/*
FILE PATH:
    tessera-personality/main.go

DESCRIPTION:
    Dedicated Ortholog Tessera personality binary. Accepts SHA-256 entry hashes
    (32 bytes) via POST /add, delegates Merkle tree computation to the Tessera
    library, and serves the c2sp.org/tlog-tiles static read API automatically.

KEY ARCHITECTURAL DECISIONS:
    - Hash-only entries: 32 bytes per leaf. Preserves SDK-D11 1MB limit without
      violating the tlog-tiles uint16 (64KB) entry bundle constraint.
    - Ed25519 checkpoint signing: required by c2sp.org/tlog-tiles spec.
    - POSIX driver for local dev, GCP driver for production.
    - Tessera handles tile layout, checkpoint production, integration batching,
      and the static read API (/checkpoint, /tile/{L}/{N}, /tile/entries/{N}).

KEY DEPENDENCIES:
    - github.com/transparency-dev/tessera
    - github.com/transparency-dev/tessera/storage/posix
    - golang.org/x/mod/sumdb/note
*/
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

const (
	hashEntrySize  = 32
	maxRequestBody = 256
)

// -------------------------------------------------------------------------------------------------
// 2) Flags
// -------------------------------------------------------------------------------------------------

var (
	flagStorageDir = flag.String("storage_dir", "/data", "POSIX storage directory")
	flagListen     = flag.String("listen", ":8081", "HTTP listen address")
	flagPrivKey    = flag.String("private_key", "", "Path to note signer private key file. Empty = generate ephemeral.")
)

// -------------------------------------------------------------------------------------------------
// 3) Main
// -------------------------------------------------------------------------------------------------

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("tessera-personality fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx := context.Background()

	// -------------------------------------------------------------------------------------------------
	// 3a) Initialize POSIX storage driver
	// -------------------------------------------------------------------------------------------------

	driver, err := posix.New(ctx, posix.Config{Path: *flagStorageDir})
	if err != nil {
		return fmt.Errorf("posix driver: %w", err)
	}
	logger.Info("storage initialized", "backend", "posix", "dir", *flagStorageDir)

	// -------------------------------------------------------------------------------------------------
	// 3b) Ed25519 signing key for checkpoint
	// -------------------------------------------------------------------------------------------------

	signer := getSignerOrGenerate(logger)

	// -------------------------------------------------------------------------------------------------
	// 3c) Create Tessera Appender
	// -------------------------------------------------------------------------------------------------

	appender, shutdown, _, err := tessera.NewAppender(ctx, driver,
		tessera.NewAppendOptions().
			WithCheckpointSigner(signer).
			WithCheckpointInterval(time.Second).
			WithBatching(256, time.Second))
	if err != nil {
		return fmt.Errorf("tessera appender: %w", err)
	}
	logger.Info("tessera appender created")

	// -------------------------------------------------------------------------------------------------
	// 3d) HTTP server
	// -------------------------------------------------------------------------------------------------

	mux := http.NewServeMux()

	// POST /add — accepts exactly 32 bytes (SHA-256 hash), returns assigned index.
	mux.HandleFunc("POST /add", newAddHandler(appender, logger))

	// Health check.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Serve Tessera's tlog-tiles read API from the POSIX storage directory.
	// Tessera writes files in the exact c2sp.org/tlog-tiles layout.
	fs := http.FileServer(http.Dir(*flagStorageDir))
	mux.Handle("GET /checkpoint", addCacheHeaders("no-cache", fs))
	mux.Handle("GET /tile/", addCacheHeaders("max-age=31536000, immutable", fs))
	logger.Info("serving tlog-tiles read API from filesystem", "dir", *flagStorageDir)

	server := &http.Server{
		Addr:         *flagListen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("HTTP server starting", "addr", *flagListen)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// -------------------------------------------------------------------------------------------------
	// 3e) Signal handling + graceful shutdown
	// -------------------------------------------------------------------------------------------------

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig)
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	if err := shutdown(shutdownCtx); err != nil {
		logger.Warn("tessera shutdown", "error", err)
	}

	logger.Info("tessera-personality stopped cleanly")
	return nil
}

// -------------------------------------------------------------------------------------------------
// 4) POST /add Handler
// -------------------------------------------------------------------------------------------------

func newAddHandler(appender *tessera.Appender, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "failed to read request body")
			return
		}

		if len(body) != hashEntrySize {
			writeJSONError(w, http.StatusBadRequest,
				fmt.Sprintf("body must be exactly %d bytes (SHA-256 hash), got %d", hashEntrySize, len(body)))
			return
		}

		// Validate non-zero hash.
		allZero := true
		for _, b := range body {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			writeJSONError(w, http.StatusBadRequest, "zero hash rejected")
			return
		}

		// Submit to Tessera. Returns tessera.Index with .Index field (uint64).
		idx, err := appender.Add(r.Context(), tessera.NewEntry(body))()
		if err != nil {
			logger.Error("tessera add failed", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "sequencing failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]uint64{"index": idx.Index})
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Signer — load from file or generate ephemeral
// -------------------------------------------------------------------------------------------------

// getSignerOrGenerate loads a note.Signer from a private key file,
// or generates an ephemeral Ed25519 keypair for local dev.
//
// Key format follows golang.org/x/mod/sumdb/note:
//   Private: "PRIVATE+KEY+<name>+<hash>+<keydata>"
//   Public:  "<name>+<hash>+<keydata>"
func getSignerOrGenerate(logger *slog.Logger) note.Signer {
	if *flagPrivKey != "" {
		keyData, err := os.ReadFile(*flagPrivKey)
		if err != nil {
			logger.Error("failed to read private key file", "path", *flagPrivKey, "error", err)
			os.Exit(1)
		}
		signer, err := note.NewSigner(string(keyData))
		if err != nil {
			logger.Error("failed to create signer from key file", "path", *flagPrivKey, "error", err)
			os.Exit(1)
		}
		logger.Info("loaded signer from file", "path", *flagPrivKey, "name", signer.Name())
		return signer
	}

	// Local dev: generate ephemeral keypair.
	skey, vkey, err := note.GenerateKey(rand.Reader, "ortholog-local-dev")
	if err != nil {
		logger.Error("failed to generate ephemeral key", "error", err)
		os.Exit(1)
	}

	signer, err := note.NewSigner(skey)
	if err != nil {
		logger.Error("failed to create signer from generated key", "error", err)
		os.Exit(1)
	}

	logger.Warn("generated ephemeral Ed25519 key — NOT for production",
		"verifier_key", vkey,
		"signer_name", signer.Name())

	return signer
}

// -------------------------------------------------------------------------------------------------
// 6) Helpers
// -------------------------------------------------------------------------------------------------

func addCacheHeaders(value string, fs http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", value)
		fs.ServeHTTP(w, r)
	}
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
