FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /tessera-personality ./tessera-personality

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata wget

WORKDIR /
COPY --from=builder /tessera-personality /tessera-personality

RUN mkdir -p /data

EXPOSE 8081

ENTRYPOINT ["/tessera-personality"]
CMD ["--storage_dir=/data", "--listen=:8081"]
