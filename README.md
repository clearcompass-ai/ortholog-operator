# Ortholog Operator

Log operator infrastructure for the Ortholog decentralized credentialing protocol. Receives signed entries, runs the four-path builder algorithm via the SDK, persists state to Postgres, distributes cosigned tree heads to witnesses, and serves query/proof endpoints to clients.

Separate deployable from the SDK. Kubernetes target. Single binary.

## Architecture

```
                  ┌─────────────┐
                  │   Clients   │
                  └──────┬──────┘
                         │ POST /v1/entries
                         ▼
               ┌───────────────────┐
               │  Admission (10    │
               │  sequential steps)│
               └────────┬──────────┘
                        │ atomic: INSERT entry + ENQUEUE
                        ▼
               ┌───────────────────┐       ┌──────────────┐
               │   Builder Loop    │──────▶│   Tessera    │
               │  (single goroutine│       │  Merkle Tree │
               │   advisory lock)  │       └──────────────┘
               └────────┬──────────┘
                        │ SDK ProcessBatch
                        ▼
               ┌───────────────────┐       ┌──────────────┐
               │   Postgres        │       │   Witnesses  │
               │  entries, SMT,    │       │  K-of-N      │
               │  queue, credits   │       │  cosignatures│
               └───────────────────┘       └──────────────┘
```

The operator never reimplements builder logic. It calls `sdk builder.ProcessBatch` — the same deterministic function that two independent operators processing the same log must agree on (determinism gate: `root=9fff8e35d9bb4ed4`).

## Requirements

- Go 1.22+ (tested through 1.26)
- PostgreSQL 14+
- [Trillian Tessera](https://github.com/transparency-dev/trillian-tessera) instance (Merkle tree backend)
- Ortholog SDK (`github.com/clearcompass-ai/ortholog-sdk`) at `../ortholog-sdk` (local replace in go.mod)

## Quick Start

```bash
# 1. Database
createdb ortholog
export ORTHOLOG_POSTGRES_DSN="postgres://user:pass@localhost:5432/ortholog?sslmode=disable"

# 2. Build
cd ortholog-operator
go mod tidy
go build -o operator ./cmd/operator

# 3. Run (migrations execute automatically on first start)
./operator

# 4. Verify
curl http://localhost:8080/healthz   # → "ok"
curl http://localhost:8080/readyz    # → "ready"
```

## Startup Sequence

`cmd/operator/main.go` executes 16 steps in order. Any failure at steps 1–8 terminates the process immediately — no partial operation.

| Step | Action | Failure mode |
|------|--------|-------------|
| 1 | Load config from env / operator.yaml | Fatal: missing required config |
| 2 | Initialize Postgres pool (pgxpool) | Fatal: database unreachable |
| 3 | Run embedded DDL migrations (6 versions) | Fatal: migration SQL error |
| 4 | Initialize Tessera client | Fatal: invalid URL |
| 5 | Initialize SMT with Postgres LeafStore + NodeCache | Fatal: Postgres error |
| 6 | Warm SMT node cache (top N levels into LRU) | Warn: non-fatal, cold cache |
| 7 | Load persisted delta-window buffer | Warn: cold start → strict OCC (SDK-D9) |
| 8 | Load current witness set from Postgres | Warn: genesis deployment |
| 9 | Acquire advisory lock, start builder loop goroutine | Fatal: lock contention |
| 10 | Start witness head sync (ready, invoked per batch) | — |
| 11 | Start equivocation monitor goroutine | — |
| 12 | Start anchor publisher goroutine (if configured) | — |
| 13 | Start HTTP server | Fatal: port bind |
| 14 | Health checks available (/healthz, /readyz) | — |
| 15 | Block on SIGTERM / SIGINT | — |
| 16 | Graceful shutdown: drain queue, cancel goroutines, close pool | — |

## API Reference

### Submission

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/entries` | Submit a signed entry for admission |

**Admission Pipeline** (10 sequential steps, fail-fast):

1. Read raw bytes, validate 6-byte preamble (Protocol_Version = 3)
2. Strip and verify signature (SDK-D5 — contract established here)
3. Entry size check (SDK-D11, default 1MB max)
4. Evidence_Pointers cap (Decision 51, max 10, snapshots exempt)
5. Admission mode: authenticated → Mode A credit deduction; unauthenticated → Mode B stamp verification
6. Log_Time assignment (UTC, outside canonical hash — SDK-D1, Decision 50)
7. Compute canonical hash
8. Duplicate check (canonical_hash UNIQUE constraint)
9. Atomic persist + enqueue (single Postgres transaction)
10. HTTP 202 `{ sequence_number, canonical_hash, log_time }`

**Error responses:**

| Status | Condition |
|--------|-----------|
| 401 | Signature verification failed |
| 402 | Insufficient write credits (Mode A) |
| 403 | Invalid compute stamp / wrong log DID (Mode B) |
| 409 | Duplicate entry (canonical hash exists) |
| 413 | Entry exceeds max size |
| 422 | Malformed preamble or Evidence_Pointers cap exceeded |

### Tree Head & Merkle Proofs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/tree/head` | Latest cosigned tree head (ETag + Cache-Control) |
| `GET` | `/v1/tree/inclusion/{seq}` | Merkle inclusion proof for sequence number |
| `GET` | `/v1/tree/consistency/{old}/{new}` | Consistency proof between two tree sizes |

### SMT Proofs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/smt/proof/{key}` | Membership or non-membership proof (auto-detected) |
| `POST` | `/v1/smt/batch_proof` | Batch multiproof for up to 1000 keys (SDK-D13 ordering) |
| `GET` | `/v1/smt/root` | Current SMT root hash |

### Query Endpoints

All return `[]EntryWithMetadata` JSON. Empty array if no results.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/query/cosignature_of/{pos}` | Entries whose Cosignature_Of matches position (certification-required) |
| `GET` | `/v1/query/target_root/{pos}` | Entries targeting a specific root entity |
| `GET` | `/v1/query/signer_did/{did}` | Entries signed by a specific DID |
| `GET` | `/v1/query/schema_ref/{pos}` | Entries governed by a specific schema |
| `GET` | `/v1/query/scan?start=N&count=M` | Sequential scan (default count=100, max 10000) |

### Admission Info

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/admission/difficulty` | Current Mode B difficulty + hash function |

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Liveness probe (always 200 while process runs) |
| `GET` | `/readyz` | Readiness probe (503 during shutdown) |

## Database Schema

Six migration versions, executed sequentially on first startup. All additive — no destructive migrations.

**Core tables:**

| Table | Primary Key | Purpose |
|-------|-------------|---------|
| `entries` | `sequence_number BIGINT` | Log entries with canonical bytes, hash, signature, indexed fields |
| `smt_leaves` | `leaf_key BYTEA(32)` | SMT leaf state: origin_tip + authority_tip |
| `smt_nodes` | `path_key BYTEA` | SMT internal node hashes (cache backing) |
| `builder_queue` | `sequence_number BIGINT` | FIFO queue: pending → processing → done |
| `credits` | `exchange_did TEXT` | Mode A write credit balances |
| `tree_heads` | `tree_size BIGINT` | Cosigned tree head history |
| `delta_window_buffers` | `leaf_key BYTEA` | Per-leaf OCC authority tip history |
| `witness_sets` | `version SERIAL` | Witness key set rotation history |
| `equivocation_proofs` | `id SERIAL` | Detected fork evidence (immutable) |
| `sessions` | `token TEXT` | Authenticated exchange sessions |

**Indexes:**

| Index | Column | Condition |
|-------|--------|-----------|
| `idx_signer_did` | `signer_did` | — |
| `idx_target_root` | `target_root` | `WHERE NOT NULL` |
| `idx_cosignature_of` | `cosignature_of` | `WHERE NOT NULL` |
| `idx_schema_ref` | `schema_ref` | `WHERE NOT NULL` |

## Configuration

All settings in `config/operator.yaml`. Override any value with environment variables using the pattern `ORTHOLOG_<SECTION>_<KEY>` (e.g., `ORTHOLOG_POSTGRES_DSN`).

**Critical settings:**

| Setting | Default | Description |
|---------|---------|-------------|
| `ORTHOLOG_LOG_DID` | `did:ortholog:operator:001` | This operator's log identity |
| `ORTHOLOG_POSTGRES_DSN` | localhost | Postgres connection string (inject via env) |
| `ORTHOLOG_SERVER_ADDR` | `:8080` | HTTP listen address |
| `ORTHOLOG_TESSERA_URL` | `http://localhost:2024` | Tessera Merkle tree backend |

**Builder tuning:**

| Setting | Default | Impact |
|---------|---------|--------|
| `builder.batch_size` | 1000 | Entries per builder cycle. Higher = better throughput, higher latency. |
| `builder.poll_interval` | 100ms | Delay between empty polls. Zero delay between non-empty batches. |
| `builder.delta_window_size` | 10 | OCC window depth. Higher = more commutative tolerance. |

**Admission tuning:**

| Setting | Default | Impact |
|---------|---------|--------|
| `admission.initial_difficulty` | 16 | Mode B stamp bits. Higher = more compute per submission. |
| `admission.min_difficulty` | 8 | Floor. Never below this regardless of queue depth. |
| `admission.max_difficulty` | 24 | Ceiling. ~16M hashes at 24 bits. |
| `admission.low_threshold` | 100 | Queue depth below this → decrease difficulty. |
| `admission.high_threshold` | 10000 | Queue depth above this → increase difficulty. |

## Builder Loop

The builder is a single goroutine protected by a Postgres advisory lock (`pg_advisory_lock`). Two builders on the same log would produce non-deterministic state — the lock makes this structurally impossible.

Each cycle:

1. `DequeueBatch` — `SELECT FOR UPDATE SKIP LOCKED` (no contention with concurrent submissions)
2. Fetch entries in strict sequence order via `PostgresEntryFetcher`
3. `sdk builder.ProcessBatch` — four-path algorithm, deterministic
4. Atomic commit: leaf mutations + buffer + queue status in one Postgres transaction
5. Append to Tessera Merkle tree
6. Publish derivation commitment (commentary entry)
7. Request K-of-N witness cosignatures on new tree head

**Crash recovery:** On startup, `RecoverStale` resets any `processing` queue entries back to `pending`. The builder replays from the last committed batch. Idempotent: same entries → identical state.

## Witness Infrastructure

**Head Sync:** After each builder batch, requests cosignatures from N witness endpoints in parallel. First K valid signatures assembled into a `CosignedTreeHead`, verified locally, persisted. Failure to reach quorum logs a warning and retries on the next cycle — never blocks the builder.

**Equivocation Monitor:** Periodic background goroutine. Fetches tree heads from peer operators. Same `tree_size` with different `root_hash` = cryptographic equivocation proof. Persisted to `equivocation_proofs` (immutable). Alert callback fired.

**Rotation Handler:** Accepts witness set rotations signed by the current K-of-N quorum. Dual-sign for scheme transitions (Decision 41: ECDSA → BLS requires both schemes during transition period). Full rotation history in `witness_sets` table.

## Project Structure

```
ortholog-operator/
├── cmd/operator/main.go               16-step startup + graceful shutdown
├── api/
│   ├── server.go                      HTTP routes + dependency injection
│   ├── submission.go                  10-step admission pipeline
│   ├── tree.go                        Tree head + Merkle proof endpoints
│   ├── proofs.go                      SMT proof endpoints
│   ├── queries.go                     5 query endpoints + difficulty
│   └── middleware/
│       ├── auth.go                    Bearer token session validation
│       ├── size_limit.go              Request body size enforcement
│       ├── rate_limit.go              Dynamic difficulty controller
│       └── evidence_cap.go            Decision 51 early guard
├── builder/
│   ├── loop.go                        Continuous goroutine → SDK ProcessBatch
│   ├── queue.go                       Postgres FIFO (FOR UPDATE SKIP LOCKED)
│   ├── commitment_publisher.go        Derivation commitments as commentary
│   └── delta_buffer.go                OCC buffer persistence
├── store/
│   ├── postgres.go                    Pool, migrations, advisory lock, TxManager
│   ├── entries.go                     PostgresEntryFetcher (SDK-D5 contract)
│   ├── smt_state.go                   PostgresLeafStore + PostgresNodeCache
│   ├── credits.go                     Mode A credit deduction (SELECT FOR UPDATE)
│   ├── tree_heads.go                  Cosigned tree head history
│   └── indexes/
│       ├── cosignature_of.go          Certification-required index
│       ├── target_root.go
│       ├── signer_did.go
│       ├── schema_ref.go
│       └── scan.go                    ScanFromPosition via PK, max 10000
├── witness/
│   ├── head_sync.go                   K-of-N parallel cosig collection
│   ├── equivocation_monitor.go        Fork detection
│   └── rotation_handler.go            Dual-sign scheme transition
├── tessera/
│   ├── client.go                      Tessera API: AppendLeaf, TreeHead
│   ├── proof_adapter.go              Merkle inclusion/consistency proofs
│   └── tile_reader.go                 GCS/S3/local tile backends + LRU
├── anchor/
│   └── publisher.go                   Periodic anchor entries (Decision 44)
├── config/
│   └── operator.yaml                  Full config schema
├── tests/
│   └── integration_test.go            25 tests across 10 categories
├── go.mod
└── go.sum
```

31 Go source files. 1 test file (25 tests). 4,873 lines.

## Testing

```bash
# Unit + integration tests (no Postgres required for unit-level tests)
go test ./tests/ -v -count=1

# With Postgres (full integration)
export ORTHOLOG_TEST_DSN="postgres://user:pass@localhost:5432/ortholog_test?sslmode=disable"
go test ./tests/ -v -count=1 -tags=integration
```

**25 tests across 10 categories:**

| Category | Tests | Validates |
|----------|-------|-----------|
| End-to-end submission | 3 | Commentary, root entity, query-by-signer |
| Mode A credits | 3 | Sufficient balance, zero balance, bulk purchase |
| Mode B stamps | 3 | Valid stamp, wrong log, below difficulty |
| Admission rejection | 4 | Unsigned (SDK-D5), oversized (SDK-D11), evidence cap, snapshot exempt |
| Builder determinism | 1 | Operator root == SDK-only root for 500 entries |
| Delta buffer persistence | 2 | Restart round-trip, cold start strict OCC |
| Query indexes | 5 | One per index (contract + max count enforcement) |
| Tree head distribution | 2 | Cosigned head assembly, HeadSync config validation |
| Witness rotation | 1 | Dual-sign detection (Decision 41) |
| Derivation commitment | 1 | Commitment matches batch mutations |

## Invariants

These are not guidelines. They are structural properties enforced by code.

**SDK-D5 (signature contract):** Every entry in the `entries` table has had its signature verified at admission. The builder trusts this — it never re-verifies. Established at `api/submission.go` step 2.

**Builder exclusivity:** `pg_advisory_lock` in `store/postgres.go`. Two builders on the same log is a protocol violation. The lock makes it impossible.

**Atomic persist + enqueue:** Entry insert and queue enqueue happen in one Postgres transaction (`api/submission.go` step 9). No orphaned entries. No phantom queue entries.

**Gapless sequence:** `entry_sequence` Postgres sequence with `NO CYCLE`. Builder processes entries in this order. Gaps would break determinism.

**Decision 47 (locality):** `PostgresEntryFetcher.Fetch` returns nil for foreign log DIDs. The builder only processes local entries.

**Decision 51 (evidence cap):** Enforced at both `sdk envelope.NewEntry` (Phase 1) and `api/submission.go` step 4 (Phase 2). Defense in depth.

**SDK-D9 (cold start):** Empty delta buffer = strict OCC. `builder/delta_buffer.go` Load returns empty buffer on first boot. No silent commutative tolerance without history.

## Kubernetes Deployment Notes

- **Replicas:** Exactly 1 per log DID. The advisory lock prevents concurrent builders, but running multiple replicas wastes resources on lock contention. Use a Deployment with `replicas: 1` and a `PodDisruptionBudget`.
- **Readiness probe:** `GET /readyz`. Returns 503 during shutdown drain.
- **Liveness probe:** `GET /healthz`. Returns 200 while the process runs.
- **Graceful shutdown:** `SIGTERM` → readiness fails → drain queue → flush buffer → close pool → exit 0. Set `terminationGracePeriodSeconds: 60`.
- **Secrets:** Inject `ORTHOLOG_POSTGRES_DSN` via Kubernetes Secret / SOPS. Never in operator.yaml.
- **Resource requests:** Builder loop is CPU-bound during batch processing. 500m CPU / 512Mi memory minimum. Node cache LRU grows with tree depth — monitor RSS.

## Protocol Decisions Referenced

| Decision | Enforcement point |
|----------|-------------------|
| SDK-D1 | Log_Time assignment at submission step 6 |
| SDK-D5 | Signature verification at submission step 2 |
| SDK-D7 | Schema resolver → commutative boolean (OCC mode) |
| SDK-D9 | Empty delta buffer → strict OCC |
| SDK-D11 | Entry size check at submission step 3 |
| SDK-D13 | Batch proof canonical ordering |
| Decision 41 | Witness rotation dual-sign in `witness/rotation_handler.go` |
| Decision 44 | Anchor entries as standard commentary in `anchor/publisher.go` |
| Decision 47 | Locality check in `PostgresEntryFetcher.Fetch` |
| Decision 50 | Log_Time outside canonical hash |
| Decision 51 | Evidence_Pointers cap at submission step 4 + SDK NewEntry |

## License

Proprietary. ClearCompass AI.
