# FILE PATH: tessera-personality/Dockerfile
#
# Multi-stage build for the Ortholog Tessera personality.
# Produces a minimal Alpine image with the personality binary.
# The binary accepts 32-byte SHA-256 hashes and delegates Merkle
# tree computation to the embedded Tessera library.

FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy the entire operator repo (personality imports tessera as a dependency
# added to the operator's go.mod — no separate Go module).
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /tessera-personality ./tessera-personality

# ---

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata wget

WORKDIR /
COPY --from=builder /tessera-personality /tessera-personality

# Default data directory for POSIX tile storage.
RUN mkdir -p /data

EXPOSE 8081

ENTRYPOINT ["/tessera-personality"]
CMD ["--storage=posix", "--data-dir=/data", "--listen=:8081", "--origin=ortholog-local-dev"]
