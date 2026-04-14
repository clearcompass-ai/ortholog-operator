/*
FILE PATH:
    api/server.go

DESCRIPTION:
    HTTP server initialization and route registration. All Ortholog operator
    endpoints under /v1/. Health checks at /healthz and /readyz.

KEY ARCHITECTURAL DECISIONS:
    - net/http standard library: no framework dependency. Production-grade
      with proper timeouts and graceful shutdown.
    - All handlers receive dependencies via closure (no globals)
    - Middleware chain: size_limit → auth → evidence_cap → handler

KEY DEPENDENCIES:
    - net/http: HTTP server
    - api/submission.go, tree.go, proofs.go, queries.go: route handlers
    - api/middleware/: request preprocessing
*/
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// -------------------------------------------------------------------------------------------------
// 1) Server Configuration
// -------------------------------------------------------------------------------------------------

// ServerConfig configures the HTTP server.
type ServerConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	MaxEntrySize    int64 // SDK-D11 default 1MB
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

// -------------------------------------------------------------------------------------------------
// 2) Server
// -------------------------------------------------------------------------------------------------

// Server is the operator HTTP server.
type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
}

// NewServer creates the HTTP server with all routes registered.
func NewServer(cfg ServerConfig, deps *Dependencies, logger *slog.Logger) *Server {
	mux := http.NewServeMux()

	// Health checks.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", deps.ReadyzHandler)

	// Submission.
	mux.HandleFunc("POST /v1/entries", deps.SubmissionHandler)

	// Tree head + proofs.
	mux.HandleFunc("GET /v1/tree/head", deps.TreeHeadHandler)
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", deps.TreeInclusionHandler)
	mux.HandleFunc("GET /v1/tree/consistency/{old}/{new}", deps.TreeConsistencyHandler)

	// SMT proofs.
	mux.HandleFunc("GET /v1/smt/proof/{key}", deps.SMTProofHandler)
	mux.HandleFunc("POST /v1/smt/batch_proof", deps.SMTBatchProofHandler)
	mux.HandleFunc("GET /v1/smt/root", deps.SMTRootHandler)

	// Query endpoints.
	mux.HandleFunc("GET /v1/query/cosignature_of/{pos}", deps.QueryCosignatureOfHandler)
	mux.HandleFunc("GET /v1/query/target_root/{pos}", deps.QueryTargetRootHandler)
	mux.HandleFunc("GET /v1/query/signer_did/{did}", deps.QuerySignerDIDHandler)
	mux.HandleFunc("GET /v1/query/schema_ref/{pos}", deps.QuerySchemaRefHandler)
	mux.HandleFunc("GET /v1/query/scan", deps.QueryScanHandler)

	// Admission info.
	mux.HandleFunc("GET /v1/admission/difficulty", deps.DifficultyHandler)

	return &Server{
		httpServer: &http.Server{
			Addr:         cfg.Addr,
			Handler:      mux,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			BaseContext:  func(_ net.Listener) context.Context { return context.Background() },
		},
		logger: logger,
	}
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
	s.logger.Info("HTTP server shutting down")
	return s.httpServer.Shutdown(ctx)
}

// -------------------------------------------------------------------------------------------------
// 3) Dependencies — injected into all handlers
// -------------------------------------------------------------------------------------------------

// Dependencies holds all handler dependencies. Populated by cmd/operator/main.go.
type Dependencies struct {
	SubmissionHandler          http.HandlerFunc
	ReadyzHandler              http.HandlerFunc
	TreeHeadHandler            http.HandlerFunc
	TreeInclusionHandler       http.HandlerFunc
	TreeConsistencyHandler     http.HandlerFunc
	SMTProofHandler            http.HandlerFunc
	SMTBatchProofHandler       http.HandlerFunc
	SMTRootHandler             http.HandlerFunc
	QueryCosignatureOfHandler  http.HandlerFunc
	QueryTargetRootHandler     http.HandlerFunc
	QuerySignerDIDHandler      http.HandlerFunc
	QuerySchemaRefHandler      http.HandlerFunc
	QueryScanHandler           http.HandlerFunc
	DifficultyHandler          http.HandlerFunc
}
