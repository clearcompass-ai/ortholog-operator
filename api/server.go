/*
FILE PATH: api/server.go

HTTP server initialization and route registration. All Ortholog operator
endpoints under /v1/. Health checks at /healthz and /readyz.

KEY ARCHITECTURAL DECISIONS:
  - net/http standard library: no framework dependency.
  - Middleware chain: size_limit → auth → handler (for submission).
  - All handlers receive dependencies via closure (no globals).
  - Readiness flag is atomic for thread-safe shutdown signaling.
*/
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) Server Configuration
// ─────────────────────────────────────────────────────────────────────────────

// ServerConfig configures the HTTP server.
type ServerConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	MaxEntrySize    int64
}

// DefaultServerConfig returns production defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:            ":8080",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    60 * time.Second,
		ShutdownTimeout: 30 * time.Second,
		MaxEntrySize:    1 << 20, // 1MB
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) Server
// ─────────────────────────────────────────────────────────────────────────────

// Server is the operator HTTP server.
type Server struct {
	httpServer *http.Server
	ready      atomic.Bool
	logger     *slog.Logger
}

// Handlers holds all registered handler functions.
type Handlers struct {
	Submission     http.HandlerFunc
	TreeHead       http.HandlerFunc
	TreeInclusion  http.HandlerFunc
	TreeConsistency http.HandlerFunc
	SMTProof       http.HandlerFunc
	SMTBatchProof  http.HandlerFunc
	SMTRoot        http.HandlerFunc
	CosignatureOf  http.HandlerFunc
	TargetRoot     http.HandlerFunc
	SignerDID      http.HandlerFunc
	SchemaRef      http.HandlerFunc
	Scan           http.HandlerFunc
	Difficulty     http.HandlerFunc
}

// NewServer creates the HTTP server with all routes and middleware applied.
func NewServer(
	cfg ServerConfig,
	db *pgxpool.Pool,
	handlers Handlers,
	logger *slog.Logger,
) *Server {
	s := &Server{logger: logger}
	s.ready.Store(true)

	mux := http.NewServeMux()

	// ── Health checks ──────────────────────────────────────────────────
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.ready.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("shutting down"))
		}
	})

	// ── Submission — with full middleware chain ─────────────────────────
	// Chain: SizeLimit → Auth → submission handler.
	// Auth sets context values; submission reads them.
	submissionChain := middleware.SizeLimit(
		cfg.MaxEntrySize+1024, // sig overhead
		middleware.Auth(db, handlers.Submission),
	)
	mux.Handle("POST /v1/entries", submissionChain)

	// ── Tree head + proofs (read-only, no auth required) ───────────────
	mux.HandleFunc("GET /v1/tree/head", handlers.TreeHead)
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", handlers.TreeInclusion)
	mux.HandleFunc("GET /v1/tree/consistency/{old}/{new}", handlers.TreeConsistency)

	// ── SMT proofs (read-only) ─────────────────────────────────────────
	mux.HandleFunc("GET /v1/smt/proof/{key}", handlers.SMTProof)
	mux.HandleFunc("POST /v1/smt/batch_proof", handlers.SMTBatchProof)
	mux.HandleFunc("GET /v1/smt/root", handlers.SMTRoot)

	// ── Query endpoints (read-only) ────────────────────────────────────
	mux.HandleFunc("GET /v1/query/cosignature_of/{pos}", handlers.CosignatureOf)
	mux.HandleFunc("GET /v1/query/target_root/{pos}", handlers.TargetRoot)
	mux.HandleFunc("GET /v1/query/signer_did/{did}", handlers.SignerDID)
	mux.HandleFunc("GET /v1/query/schema_ref/{pos}", handlers.SchemaRef)
	mux.HandleFunc("GET /v1/query/scan", handlers.Scan)

	// ── Admission info (read-only) ─────────────────────────────────────
	mux.HandleFunc("GET /v1/admission/difficulty", handlers.Difficulty)

	s.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		BaseContext:  func(_ net.Listener) context.Context { return context.Background() },
	}

	return s
}

// ListenAndServe starts the HTTP server. Blocks until error or shutdown.
func (s *Server) ListenAndServe() error {
	s.logger.Info("HTTP server starting", "addr", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.ready.Store(false)
	s.logger.Info("HTTP server shutting down")
	return s.httpServer.Shutdown(ctx)
}
