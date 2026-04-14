/*
FILE PATH:
    api/middleware/rate_limit.go

DESCRIPTION:
    DifficultyController manages the dynamic difficulty for Mode B
    admission stamps. Adjusts based on queue depth — more entries waiting
    means higher difficulty. Matches Phase 5 DifficultyProvider interface.

KEY ARCHITECTURAL DECISIONS:
    - Queue-depth-based: direct signal of load pressure
    - Floor/ceiling: minimum 8 bits (always some work), maximum 24 bits
    - Adjustment interval: recomputed every 30 seconds
    - Thread-safe: atomic reads for serving difficulty endpoint

OVERVIEW:
    Background goroutine periodically checks queue depth.
    Low depth → decrease difficulty. High depth → increase.
    GET /v1/admission/difficulty serves current parameters.

KEY DEPENDENCIES:
    - github.com/jackc/pgx/v5/pgxpool: queue depth query
*/
package middleware

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// -------------------------------------------------------------------------------------------------
// 1) DifficultyController
// -------------------------------------------------------------------------------------------------

// DifficultyController dynamically adjusts Mode B stamp difficulty.
type DifficultyController struct {
	db             *pgxpool.Pool
	difficulty     atomic.Uint32
	minDifficulty  uint32
	maxDifficulty  uint32
	lowThreshold   int64 // Queue depth below this → decrease
	highThreshold  int64 // Queue depth above this → increase
	logger         *slog.Logger
}

// DifficultyConfig configures the difficulty controller.
type DifficultyConfig struct {
	InitialDifficulty uint32
	MinDifficulty     uint32
	MaxDifficulty     uint32
	LowThreshold      int64
	HighThreshold      int64
	AdjustInterval    time.Duration
}

// DefaultDifficultyConfig returns production defaults.
func DefaultDifficultyConfig() DifficultyConfig {
	return DifficultyConfig{
		InitialDifficulty: 16,
		MinDifficulty:     8,
		MaxDifficulty:     24,
		LowThreshold:      100,
		HighThreshold:     10000,
		AdjustInterval:    30 * time.Second,
	}
}

// NewDifficultyController creates a difficulty controller.
func NewDifficultyController(db *pgxpool.Pool, cfg DifficultyConfig, logger *slog.Logger) *DifficultyController {
	dc := &DifficultyController{
		db:            db,
		minDifficulty: cfg.MinDifficulty,
		maxDifficulty: cfg.MaxDifficulty,
		lowThreshold:  cfg.LowThreshold,
		highThreshold: cfg.HighThreshold,
		logger:        logger,
	}
	dc.difficulty.Store(cfg.InitialDifficulty)
	return dc
}

// CurrentDifficulty returns the current difficulty. Thread-safe.
func (dc *DifficultyController) CurrentDifficulty() uint32 {
	return dc.difficulty.Load()
}

// Run starts the adjustment loop. Blocks until ctx cancelled.
func (dc *DifficultyController) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dc.adjust(ctx)
		}
	}
}

func (dc *DifficultyController) adjust(ctx context.Context) {
	var depth int64
	err := dc.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM builder_queue WHERE status = 0",
	).Scan(&depth)
	if err != nil {
		dc.logger.Error("difficulty: queue depth query", "error", err)
		return
	}

	current := dc.difficulty.Load()
	var next uint32
	switch {
	case depth < dc.lowThreshold && current > dc.minDifficulty:
		next = current - 1
	case depth > dc.highThreshold && current < dc.maxDifficulty:
		next = current + 1
	default:
		return // No change.
	}

	dc.difficulty.Store(next)
	dc.logger.Info("difficulty adjusted", "from", current, "to", next, "queue_depth", depth)
}
