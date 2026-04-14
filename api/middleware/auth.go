/*
FILE PATH: api/middleware/auth.go

Exchange session authentication. Validates Bearer tokens against sessions table.
Sets authenticated + exchangeDID in context.

KEY ARCHITECTURAL DECISIONS:
  - Missing token → unauthenticated (Mode B). No error.
  - Invalid/expired token → HTTP 401 (not silent fallthrough to Mode B).
  - Valid token → context carries exchangeDID + authenticated=true.
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

// Auth validates Bearer tokens. Missing token → unauthenticated (Mode B).
// Invalid/expired token → HTTP 401 (rejected, not Mode B fallthrough).
func Auth(db *pgxpool.Pool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token := extractBearerToken(r)
		if token == "" {
			// No token: proceed as unauthenticated (Mode B).
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

		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, `{"error":"invalid session token"}`, http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, `{"error":"session lookup failed"}`, http.StatusInternalServerError)
			return
		}
		if time.Now().After(expiresAt) {
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
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
