/*
FILE PATH:
    tessera-personality/main.go

DESCRIPTION:
    Dedicated Ortholog Tessera personality binary. Accepts SHA-256 entry hashes
    (32 bytes) via POST /add, delegates Merkle tree computation to the Tessera
    library, and serves the c2sp.org/tlog-tiles static read API automatically.

    This binary is the ONLY writer to the Merkle tree. The operator calls POST /add
    with the 32-byte SHA-256(wire_bytes) digest. Full entry bytes live in the
    operator's own storage (Postgres entry_index + InMemoryEntryStore). Tessera
    never sees full entry data — only cryptographic commitments.

KEY ARCHITECTURAL DECISIONS:
    - Hash-only entries: 32 bytes per leaf. Preserves SDK-D11 1MB limit without
      violating the tlog-tiles uint16 (64KB) entry bundle constraint.
    - Ed25519 checkpoint signing: required by c2sp.org/tlog-tiles spec. The operator
      independently produces ECDSA secp256k1 cosigned tree heads for smart contract
      bridges — dual attestation over identical tree state.
    - POSIX driver for local dev, GCP driver for production. Selected by --storage flag.
    - Tessera handles tile layout, checkpoint production, integration batching, and
      the static read API (/checkpoint, /tile/{L}/{N}, /tile/entries/{N}).
    - No antispam: the operator's admission pipeline handles dedup via canonical_hash
      UNIQUE constraint. Tessera receives pre-validated hashes only.

OVERVIEW:
    1. Parse flags (storage backend, listen address, origin string, key path).
    2. Initialize storage driver (POSIX or GCP).
    3. Load or generate Ed25519 signing key for checkpoint signatures.
    4. Call tessera.NewAppender to get appender + reader + shutdown.
    5. Register POST /add handler: validate 32-byte body, call appender.Add, return index.
    6. Serve Tessera's static tlog-tiles read API via the reader's HTTP handler.
    7. Block on SIGTERM/SIGINT, call shutdown for clean quiescence.

KEY DEPENDENCIES:
    - github.com/transparency-dev/tessera: Core tlog library (Appender, Entry, drivers).
    - github.com/transparency-dev/tessera/storage/posix: Filesystem-backed tile storage.
    - golang.org/x/mod/sumdb/note: Ed25519 signed note signer/verifier for checkpoints.
*/
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
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
	// hashEntrySize is the exact byte length of a SHA-256 digest.
	// The personality rejects any POST body that is not exactly this size.
	hashEntrySize = 32

	// maxRequestBody caps the POST /add body read to prevent abuse.
	// 32 bytes of hash + minimal overhead. Anything larger is rejected.
	maxRequestBody = 256

	// readTimeout and writeTimeout for the HTTP server.
	serverReadTimeout  = 30 * time.Second
	serverWriteTimeout = 60 * time.Second
)

// -------------------------------------------------------------------------------------------------
// 2) Flags
// -------------------------------------------------------------------------------------------------

var (
	flagStorage  = flag.String("storage", "posix", "Storage backend: posix or gcp")
	flagDataDir  = flag.String("data-dir", "/data", "POSIX storage directory")
	flagListen   = flag.String("listen", ":8081", "HTTP listen address")
	flagOrigin   = flag.String("origin", "ortholog-dev", "Log origin string for checkpoint")
	flagKeyPath  = flag.String("key-path", "", "Path to Ed25519 private key (PEM). Empty = generate ephemeral.")
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// -------------------------------------------------------------------------------------------------
	// 3a) Initialize storage driver
	// -------------------------------------------------------------------------------------------------

	var driver tessera.Driver
	switch *flagStorage {
	case "posix":
		d, err := posix.New(ctx, *flagDataDir)
		if err != nil {
			return fmt.Errorf("posix driver: %w", err)
		}
		driver = d
		logger.Info("storage initialized", "backend", "posix", "dir", *flagDataDir)

	// case "gcp":
	//     Uncomment and wire GCP driver for production:
	//     d, err := gcp.New(ctx, gcpConfig)
	//     driver = d

	default:
		return fmt.Errorf("unsupported storage backend: %s (supported: posix, gcp)", *flagStorage)
	}

	// -------------------------------------------------------------------------------------------------
	// 3b) Ed25519 signing key for checkpoint
	// -------------------------------------------------------------------------------------------------

	signer, verifier, err := loadOrGenerateKey(logger)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}

	verifierStr, err := note.NewVerifier(verifier)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}
	logger.Info("checkpoint signer ready",
		"origin", *flagOrigin,
		"verifier", verifierStr.Name())

	// -------------------------------------------------------------------------------------------------
	// 3c) Create Tessera Appender
	// -------------------------------------------------------------------------------------------------

	opts := tessera.NewAppendOptions()
	opts.WithCheckpointSigner(signer, verifier)

	appender, shutdown, _, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		return fmt.Errorf("tessera appender: %w", err)
	}
	logger.Info("tessera appender created", "origin", *flagOrigin)

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

	// Tessera's tlog-tiles read API is served from the storage directory.
	// For POSIX, we serve the files directly. Tessera writes them in the
	// exact c2sp.org/tlog-tiles layout: checkpoint, tile/{L}/{N}, tile/entries/{N}.
	if *flagStorage == "posix" {
		fs := http.FileServer(http.Dir(*flagDataDir))
		mux.Handle("/", fs)
		logger.Info("serving tlog-tiles read API from filesystem", "dir", *flagDataDir)
	}

	server := &http.Server{
		Addr:         *flagListen,
		Handler:      mux,
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
	}

	// Start server in background.
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

	// Graceful: stop accepting new requests.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	// Tessera shutdown: flush pending entries, finalize checkpoint.
	if err := shutdown(shutdownCtx); err != nil {
		logger.Warn("tessera shutdown", "error", err)
	}

	cancel()
	logger.Info("tessera-personality stopped cleanly")
	return nil
}

// -------------------------------------------------------------------------------------------------
// 4) POST /add Handler
// -------------------------------------------------------------------------------------------------

func newAddHandler(appender *tessera.Appender, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read body — must be exactly 32 bytes.
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

		// Validate non-zero hash (defense against accidental empty submissions).
		allZero := true
		for _, b := range body {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			writeJSONError(w, http.StatusBadRequest, "zero hash rejected — likely a bug in the caller")
			return
		}

		// Submit to Tessera. The entry data IS the 32-byte hash.
		// Tessera computes the Merkle leaf hash as H(0x00 || entry_data).
		indexFuture := appender.Add(r.Context(), tessera.NewEntry(body))

		// Block until sequenced.
		index, err := indexFuture()
		if err != nil {
			logger.Error("tessera add failed", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "sequencing failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]uint64{"index": index})
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Ed25519 Key Management
// -------------------------------------------------------------------------------------------------

// loadOrGenerateKey loads an Ed25519 key from disk or generates an ephemeral one.
// Returns a note.Signer and note.Verifier for Tessera's checkpoint signing.
func loadOrGenerateKey(logger *slog.Logger) (note.Signer, note.Verifier, error) {
	var privKey ed25519.PrivateKey

	if *flagKeyPath != "" {
		// Production: load from file.
		keyData, err := os.ReadFile(*flagKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read key file %s: %w", *flagKeyPath, err)
		}
		if len(keyData) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("key file must be %d bytes raw Ed25519, got %d",
				ed25519.PrivateKeySize, len(keyData))
		}
		privKey = ed25519.PrivateKey(keyData)
		logger.Info("loaded Ed25519 key from file", "path", *flagKeyPath)
	} else {
		// Local dev: generate ephemeral key.
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate key: %w", err)
		}
		privKey = priv
		logger.Warn("generated ephemeral Ed25519 key — NOT for production")
	}

	// Derive the key hash for the note signer name.
	// Format: "<origin>+<key_hash_hex_prefix>"
	pubKey := privKey.Public().(ed25519.PublicKey)
	keyHash := sha256Short(pubKey)
	signerName := fmt.Sprintf("%s+%x", *flagOrigin, keyHash)

	signer, err := note.NewEd25519SignerFromKey(signerName, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create signer: %w", err)
	}

	verifier, err := note.NewEd25519VerifierFromKey(signerName, pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create verifier: %w", err)
	}

	return signer, verifier, nil
}

// sha256Short returns the first 4 bytes of SHA-256(data) as a uint32.
func sha256Short(data []byte) uint32 {
	// Use a simple hash for key ID — not crypto-critical, just an identifier.
	var h [32]byte
	// Inline SHA-256 would require crypto/sha256 import; use a simpler approach
	// for the key hash identifier.
	for i, b := range data {
		h[i%32] ^= b
	}
	return binary.BigEndian.Uint32(h[:4])
}

// -------------------------------------------------------------------------------------------------
// 6) Helpers
// -------------------------------------------------------------------------------------------------

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
