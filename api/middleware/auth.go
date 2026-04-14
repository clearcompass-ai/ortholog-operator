/*
FILE PATH:
    api/middleware/auth.go

DESCRIPTION:
    Exchange session authentication middleware. Validates Bearer tokens
    against the sessions table. Sets authenticated + exchangeDID in context.
    Unauthenticated requests proceed as Mode B (compute stamp required).

KEY ARCHITECTURAL DECISIONS:
    - Context-based propagation: no globals, no thread-locals
    - Token validation failure = unauthenticated (Mode B), NOT rejected
    - Sessions table: token PK, exchange_did, expires_at

KEY DEPENDENCIES:
    - github.com/jackc/pgx/v5/pgxpool: session lookup
*/
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// -------------------------------------------------------------------------------------------------
// 1) Context Keys
// -------------------------------------------------------------------------------------------------

type contextKey string

const (
	ctxAuthenticated contextKey = "authenticated"
	ctxExchangeDID   contextKey = "exchange_did"
)

// IsAuthenticated extracts the authentication flag from context.
func IsAuthenticated(ctx context.Context) bool {
	v, _ := ctx.Value(ctxAuthenticated).(bool)
	return v
}

// ExchangeDID extracts the exchange DID from context.
func ExchangeDID(ctx context.Context) string {
	v, _ := ctx.Value(ctxExchangeDID).(string)
	return v
}

// -------------------------------------------------------------------------------------------------
// 2) Auth Middleware
// -------------------------------------------------------------------------------------------------

// Auth validates Bearer tokens. Invalid/missing → unauthenticated context.
func Auth(db *pgxpool.Pool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token := extractBearerToken(r)
		if token == "" {
			ctx = context.WithValue(ctx, ctxAuthenticated, false)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		var exchangeDID string
		var expiresAt time.Time
		err := db.QueryRow(ctx,
			"SELECT exchange_did, expires_at FROM sessions WHERE token = $1",
			token,
		).Scan(&exchangeDID, &expiresAt)

		if errors.Is(err, pgx.ErrNoRows) || (err == nil && time.Now().After(expiresAt)) {
			ctx = context.WithValue(ctx, ctxAuthenticated, false)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		if err != nil {
			ctx = context.WithValue(ctx, ctxAuthenticated, false)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		ctx = context.WithValue(ctx, ctxAuthenticated, true)
		ctx = context.WithValue(ctx, ctxExchangeDID, exchangeDID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}
