# Operator → SDK v0.3.0-tessera Migration — Complete Change Set

This directory is the **final, single-shot** migration. It consolidates
PR1 (dep bump), PR2 (destination binding + Validate + freshness), PR3
(Tessera leaf switch), and PR4 (vocabulary migration).

## Summary of the SDK contract change

Every Entry now commits to its destination exchange DID in the canonical
hash. An entry signed for exchange A cannot be replayed at exchange B —
B's signature check recomputes a different hash and fails. The operator
must enforce this at admission time.

Additionally:
- `envelope.EntryIdentity(entry)` is the single Entry-hash primitive.
- `(*Entry).Validate()` re-applies NewEntry's write-time invariants.
- `exchange/policy.CheckFreshness` rejects late-replay attempts.
- `crypto.HashBytes(data)` is for generic (non-Entry) hashing.
- Tessera-personality applies RFC 6962 leaf prefix internally — operator
  sends `EntryIdentity` (unwrapped 32 bytes), NOT `EntryLeafHash`.

## Files in this directory

```
go.mod                                          # SDK dep → v0.3.0-tessera
anchor/publisher.go                             # +LogDID, crypto.HashBytes for tree head ref
builder/commitment_publisher.go                 # +logDID field + constructor arg
builder/loop.go                                 # Tessera leaf → envelope.EntryIdentity
api/submission.go                               # 13-step pipeline + Validate + destination + freshness
api/queries.go                                  # hash computation → envelope.EntryIdentity
lifecycle/shard_manager.go                      # +Destination, +EventTime on genesis
cmd/operator/main.go                            # Wires LogDID everywhere
tests/helpers_test.PATCH.go                     # helpers + testLogDID default
tests/entry_storage_rule_test.PATCH.go          # 3 migrate, 1 keep
tests/http_integration_test.PATCH.go            # 2 migrate + 3 new tests
tests/integration_test.PATCH.go                 # 3 migrate, 6 keep (test data)
tests/scale_test.PATCH.go                       # 4 migrate
tests/tessera_and_testserver_NO_CHANGE.md       # Rationale for keep-as-is
```

## Apply order

### Step 1 — drop in the complete files

```bash
cd ~/workspace/ortholog-operator

# Single-shot replacements (these are full file contents):
cp /mnt/user-data/outputs/go.mod                              ./go.mod
cp /mnt/user-data/outputs/anchor/publisher.go                 ./anchor/publisher.go
cp /mnt/user-data/outputs/builder/commitment_publisher.go     ./builder/commitment_publisher.go
cp /mnt/user-data/outputs/builder/loop.go                     ./builder/loop.go
cp /mnt/user-data/outputs/api/submission.go                   ./api/submission.go
cp /mnt/user-data/outputs/api/queries.go                      ./api/queries.go
cp /mnt/user-data/outputs/lifecycle/shard_manager.go          ./lifecycle/shard_manager.go
cp /mnt/user-data/outputs/cmd/operator/main.go                ./cmd/operator/main.go
```

### Step 2 — apply the test patches

Test files are patches, not complete replacements, because they contain
test logic the migration preserves unchanged. Each `.PATCH.go` file in
`tests/` contains precise `FIND`/`REPLACE` blocks. Apply by editing the
corresponding test file:

```bash
# Open each test file and apply the patches noted in the .PATCH.go docs.
# The find strings are verbatim from the grep output the SDK provided.
$EDITOR tests/helpers_test.go
$EDITOR tests/entry_storage_rule_test.go
$EDITOR tests/http_integration_test.go
$EDITOR tests/integration_test.go
$EDITOR tests/scale_test.go

# tests/tessera_integration_test.go — NO changes.
# tests/testserver_test.go — check var _ = sha256.Sum256 suppressor (see md).
```

### Step 3 — go mod tidy

```bash
go get github.com/clearcompass-ai/ortholog-sdk@v0.3.0-tessera
go mod tidy
```

### Step 4 — verify

```bash
go vet ./...
go test ./...
```

## What stays and what changes — the 39 sha256 sites

| File | Line | Action | Why |
|---|---|---|---|
| anchor/publisher.go | 126 | → `crypto.HashBytes(body)` | HTTP body bytes, not Entry |
| api/queries.go | 58 | → `envelope.EntryIdentity(entry)` after Deserialize | Entry-shaped |
| api/submission.go | 200 | → `envelope.EntryIdentity(entry)` | Entry-shaped |
| api/submission.go | 250 | → `envelope.EntryIdentity(entry)` | Entry-shaped (admission proof) |
| api/submission.go | 285 | → `envelope.EntryIdentity(entry)` | Entry-shaped (step 7 canonical hash) |
| builder/loop.go | 401 | → `envelope.EntryIdentity(entries[i])` | **CRITICAL** — leaf data |
| tessera/proof_adapter.go | 355 | **KEEP** | RFC 6962 interior node — primitive itself |
| tests/entry_storage_rule_test.go | 131 | KEEP or `crypto.HashBytes` | Bytes-integrity check |
| tests/entry_storage_rule_test.go | 156 | → `envelope.EntryIdentity` | Entry-shaped |
| tests/entry_storage_rule_test.go | 221 | → `envelope.EntryIdentity` | Entry-shaped |
| tests/entry_storage_rule_test.go | 276 | → `envelope.EntryIdentity` | Entry-shaped |
| tests/helpers_test.go | 107 | → `envelope.EntryIdentity(entry)` | Helper, Entry-shaped |
| tests/helpers_test.go | 460 | → `envelope.EntryIdentity(entry)` | Entry-shaped |
| tests/http_integration_test.go | 107 | → `envelope.EntryIdentity(entry)` | Entry-shaped |
| tests/http_integration_test.go | 723 | → `envelope.EntryIdentity(entry)` | Entry-shaped |
| tests/integration_test.go | 50 | → `envelope.EntryIdentity(entry)` | Entry-shaped |
| tests/integration_test.go | 62-63 | → `envelope.EntryIdentity(entry)` | Entry-shaped |
| tests/integration_test.go | 640-641 | **KEEP** | Equivocation fixture, not Entry |
| tests/integration_test.go | 675 | → `envelope.EntryIdentity` | Determinism test |
| tests/integration_test.go | 849 | **KEEP** | Anchor payload fixture |
| tests/integration_test.go | 1299 | **KEEP** | Stamp hash input fixture |
| tests/integration_test.go | 1385 | **KEEP** | Stamp hash input fixture |
| tests/integration_test.go | 1402 | **KEEP** | Stamp hash input fixture |
| tests/scale_test.go | 171 | → `envelope.EntryIdentity` | Entry-shaped |
| tests/scale_test.go | 211 | → `envelope.EntryIdentity` | Entry-shaped |
| tests/scale_test.go | 355 | → `envelope.EntryIdentity` | Entry-shaped |
| tests/scale_test.go | 389 | → `envelope.EntryIdentity` | Entry-shaped |
| tests/tessera_integration_test.go | 76 | **KEEP** | Arbitrary test bytes |
| tests/tessera_integration_test.go | 139 | **KEEP** | Arbitrary test bytes |
| tests/tessera_integration_test.go | 219 | **KEEP** | Arbitrary test bytes |
| tests/tessera_integration_test.go | 251 | **KEEP** | Arbitrary test bytes |
| tests/tessera_integration_test.go | 309 | **KEEP** | Simulated wire bytes |
| tests/tessera_integration_test.go | 342 | **KEEP** | Simulated wire bytes |
| tests/testserver_test.go | 311 | REMOVE if unused | `var _` suppressor |
| witness/serve.go | 57 | **KEEP** | Pub-key ID primitive |
| witness/serve.go | 134 | **KEEP** | WitnessCosignMessage hash — primitive |

**26 Entry-shaped migrations. 13 keep-as-is.**

## Why `EntryIdentity`, not `EntryLeafHash`

This is the single most important correctness decision in the migration.

The SDK ships two similar-sounding primitives:
- `envelope.EntryIdentity(entry)` = `SHA-256(Serialize(entry))` — the
  Tessera dedup key.
- `envelope.EntryLeafHash(entry)` = `SHA-256(0x00 || Serialize(entry))` —
  the RFC 6962 Merkle leaf hash.

The operator sends `EntryIdentity` to `bl.merkle.AppendLeaf(...)`. Tessera-
personality then wraps the data it receives with the RFC 6962 leaf prefix
(`0x00`) internally when computing the Merkle leaf hash for the tree.
Consumers verifying inclusion proofs against a Tessera-published tree
must use Tessera's leaf-hash convention, which is exactly that: the tree
root commits to `SHA-256(0x00 || EntryIdentity(entry))`.

If the operator sent `EntryLeafHash(entry)` to Tessera, the Merkle leaf
would be `SHA-256(0x00 || SHA-256(0x00 || Serialize(entry)))` — the 0x00
prefix applied twice. Inclusion proofs would then fail against every
verifier expecting standard RFC 6962 hashes over `EntryIdentity` values.

The previous operator code sent `SHA-256(canonical + signature_envelope)` —
neither identity nor leaf hash, and included the signature as part of
the tree leaf, which was incorrect (multiple valid sigs over the same
entry would give different Merkle leaves). This change fixes that.

## Breaking change: live tiles must be rebuilt

Any existing deployment that already has tiles contains the old
`SHA-256(canonical + sig)` values. Those inclusion proofs will not
verify against the new scheme. To migrate:

1. Freeze the existing Tessera state (drain admission, wait for the
   builder loop to quiesce).
2. Take a Postgres backup.
3. Wipe the Tessera storage root (keep Postgres — the authoritative log
   state lives there).
4. Replay every admitted entry through the patched builder loop. The
   deterministic contract of `ProcessBatch` + `AppendLeaf` produces
   fresh tiles containing `EntryIdentity` values.
5. Republish a fresh checkpoint. Announce the tile rebuild to consumers.

## New verification contract for consumers

```
  1. Fetch wire bytes from operator's byte store      (GET /v1/entries/{seq}/raw)
  2. canonical, algoID, sig = envelope.StripSignature(wireBytes)
  3. entry = envelope.Deserialize(canonical)
  4. identity = envelope.EntryIdentity(entry)
  5. Fetch inclusion proof for position N             (Tessera personality)
  6. Verify proof hashes `identity` → published tree head
```

Downstream verifier SDKs and reference clients must update to this flow
before the operator migration ships. Coordinate the release.

## Verification checklist (post-apply)

Run these as integration tests to prove the migration is correct:

### 1. Cross-destination rejection → 403

```go
wire := buildWireEntry(..., Destination: "did:web:OTHER-log.example", ...)
resp := POST("/v1/entries", wire)
assert resp.StatusCode == 403
```

### 2. Malformed destination → 422 (via Validate())

```go
forged := &envelope.Entry{Header: ControlHeader{Destination: "", ...}}
canonical := Serialize(forged)  // bypasses NewEntry
sig := Sign(EntryIdentity(forged))
wire := AppendSignature(canonical, algo, sig)
resp := POST("/v1/entries", wire)
assert resp.StatusCode == 422
```

### 3. Stale EventTime → 422

```go
stale := time.Now().Add(-10*time.Minute).Unix()
wire := buildWireEntry(..., EventTime: stale, ...)
resp := POST("/v1/entries", wire)
assert resp.StatusCode == 422
```

### 4. Merkle round-trip with new leaf scheme

```go
// Submit entry, fetch proof, verify inclusion.
seq, hash := submit(wire)
proof := fetchInclusionProof(seq)
identity := envelope.EntryIdentity(entryFromWire(wire))
assert verifyInclusion(proof, identity, publishedRoot)
```

### 5. Self-published entries land with Destination == LogDID

```go
// Start operator, wait for anchor publisher interval.
// Query the recent commentary entries.
entries := GET("/v1/entries?from=0&to=100")
for e := range entries where e.SignerDID == operatorDID:
    assert e.Destination == logDID  // via queryResp or re-parse
```

### 6. `go vet ./... && go test ./...` clean

The whole suite passes with no warnings, no skips.

## What's NOT in this migration

Deferred to later PRs:

1. **Phase 4 `did.VerifierRegistry` wiring** — the SDK ships
   `did.DefaultVerifierRegistry(destDID, resolver)` which does
   destination-binding + DID-method dispatch automatically. When this
   lands, the explicit step 3b in submission.go becomes redundant.
2. **SDK builders** — `builder.BuildAnchorEntry`, `builder.BuildCommentary`
   replace manual `envelope.NewEntry` at three self-published sites.
   Cleaner, but no correctness change.
3. **`smt.Tree.SetLeaves` batch commit** — replaces per-mutation
   `leafStore.SetTx` with a single atomic `SetBatch`. Performance
   optimization only.
4. **`builder.ProcessWithRetry`** — wraps `ProcessBatch` with exponential
   backoff on OCC rejection. Useful under contention.

Each of the above is safe to ship independently once the v0.3.0-tessera
core alignment (this migration) is green.

## Commit message

```
Operator v0.3.0-tessera alignment

- Bump SDK dep to v0.3.0-tessera
- Destination binding enforced at submission (step 3b → 403)
- Entry.Validate() re-applies write-time invariants (step 3a → 422)
- exchange/policy.CheckFreshness at admission (step 3c → 422)
- Tessera leaf data: envelope.EntryIdentity(entry), NOT sha256(wire)
- Self-published entries (anchor, commitment, shard genesis) carry
  Destination = LogDID (or NewShardDID for shards)
- Vocabulary migration: 26 Entry-shaped sha256 sites → envelope.EntryIdentity
- 13 non-Entry sha256 sites preserved (pub-key IDs, witness msg hash,
  RFC 6962 interior nodes, test fixtures)
- crypto.HashBytes for arbitrary byte hashing
- admission.CurrentEpoch helper (handles pre-1970 edge case)

Breaking change for consumers: live Tessera tiles contain sha256(wire)
values under the old scheme; inclusion proofs will not verify under the
new envelope.EntryIdentity scheme. Rebuild tiles by replaying entries
through the patched builder loop against fresh Tessera storage.

Tests: 3 new integration tests lock in cross-destination rejection,
malformed-destination rejection via Validate(), and late-replay
rejection via freshness policy.
```
