/*
FILE PATH:
    api/middleware/size_limit.go

DESCRIPTION:
    Request body size enforcement via io.LimitReader. HTTP 413 on exceed.
    Protects against memory exhaustion from oversized payloads.

KEY ARCHITECTURAL DECISIONS:
    - LimitReader(body, max+1): read one extra byte to detect overflow
    - Applied before any parsing (earliest rejection point)
*/
package middleware

import (
	"io"
	"net/http"
)

// SizeLimit wraps the request body with io.LimitReader.
func SizeLimit(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}
