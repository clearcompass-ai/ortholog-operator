#!/usr/bin/env bash
# Apply six test-side fixes for SDK v0.3.0-tessera migration.
#
# EVIDENCE SUMMARY:
#   - builder.NewCommitmentPublisher went 4-arg → 5-arg in v0.3.0 (logDID
#     second). Three call sites in tests still use the old 4-arg form.
#   - crypto/sha256 imports in helpers_test.go and scale_test.go are
#     orphaned after the EntryIdentity migration.
#   - canonical locals at scale_test.go:171,211 are post-migration
#     vestigial; the surrounding INSERT statements store index-only
#     (no canonical_bytes column) so deletion is semantically correct.
#
# IDEMPOTENT: each edit is guarded by a pre-check. Re-running is safe.

set -euo pipefail

cd ~/workspace/ortholog-operator

# ─────────────────────────────────────────────────────────────────────
# Fix 1 — integration_test.go:889
# NewCommitmentPublisher("did:example:op", cfg, ...) → add "did:example:op" as 2nd arg.
# The test collapses operator DID and log DID (matches production default
# when OPERATOR_DID == OPERATOR_LOG_DID). Explicit-same beats inferred.
# ─────────────────────────────────────────────────────────────────────
FILE="tests/integration_test.go"
NEEDLE='opbuilder.NewCommitmentPublisher("did:example:op", opbuilder.CommitmentPublisherConfig'
REPLACEMENT='opbuilder.NewCommitmentPublisher("did:example:op", "did:example:op", opbuilder.CommitmentPublisherConfig'

if grep -qF "$NEEDLE" "$FILE" && ! grep -qF "$REPLACEMENT" "$FILE"; then
  perl -i -pe 's/\Qopbuilder.NewCommitmentPublisher("did:example:op", opbuilder.CommitmentPublisherConfig\E/opbuilder.NewCommitmentPublisher("did:example:op", "did:example:op", opbuilder.CommitmentPublisherConfig/g' \
    "$FILE"
  echo "✓ $FILE — added second DID arg"
else
  echo "· $FILE — already patched or needle absent"
fi

# ─────────────────────────────────────────────────────────────────────
# Fix 2 — scale_test.go:422
# Multi-line call: testLogDID,\n  <cfg>. Insert testLogDID, on a new line after.
# Using line-aware match to avoid touching any future call site that also
# passes testLogDID as first arg (e.g., if something like that exists in
# loopCfg construction — which uses DefaultLoopConfig(testLogDID), not
# NewCommitmentPublisher).
# ─────────────────────────────────────────────────────────────────────
FILE="tests/scale_test.go"
python3 <<'PYFIX'
import re, pathlib
path = pathlib.Path("tests/scale_test.go")
src = path.read_text()
# Match: opbuilder.NewCommitmentPublisher(\n\t\ttestLogDID,\n\t\topbuilder.CommitmentPublisherConfig
# Replace so testLogDID appears twice (operatorDID, logDID both = testLogDID).
# Regex anchored tightly on the exact two-line prefix seen at line 421-423.
old = ("opbuilder.NewCommitmentPublisher(\n"
       "\t\ttestLogDID,\n"
       "\t\topbuilder.CommitmentPublisherConfig")
new = ("opbuilder.NewCommitmentPublisher(\n"
       "\t\ttestLogDID,\n"
       "\t\ttestLogDID,\n"
       "\t\topbuilder.CommitmentPublisherConfig")
if new in src:
    print("· tests/scale_test.go — commitPub already patched")
elif old in src:
    path.write_text(src.replace(old, new, 1))
    print("✓ tests/scale_test.go — added logDID arg to NewCommitmentPublisher")
else:
    print("! tests/scale_test.go — NewCommitmentPublisher pattern not found as expected")
    print("  (manual review needed)")
PYFIX

# ─────────────────────────────────────────────────────────────────────
# Fix 3 — testserver_test.go:127
# Same shape as Fix 2.
# ─────────────────────────────────────────────────────────────────────
python3 <<'PYFIX'
import pathlib
path = pathlib.Path("tests/testserver_test.go")
src = path.read_text()
old = ("opbuilder.NewCommitmentPublisher(\n"
       "\t\ttestLogDID,\n"
       "\t\topbuilder.CommitmentPublisherConfig")
new = ("opbuilder.NewCommitmentPublisher(\n"
       "\t\ttestLogDID,\n"
       "\t\ttestLogDID,\n"
       "\t\topbuilder.CommitmentPublisherConfig")
if new in src:
    print("· tests/testserver_test.go — commitPub already patched")
elif old in src:
    path.write_text(src.replace(old, new, 1))
    print("✓ tests/testserver_test.go — added logDID arg to NewCommitmentPublisher")
else:
    print("! tests/testserver_test.go — NewCommitmentPublisher pattern not found")
PYFIX

# ─────────────────────────────────────────────────────────────────────
# Fix 4 & 5 — scale_test.go:171,211 — delete dead `canonical` locals.
# The surrounding INSERT statements store index-only (no canonical_bytes
# column), so the serialized bytes are not needed. Vestigial from the
# pre-v0.3.0 code that used sha256.Sum256(canonical).
# ─────────────────────────────────────────────────────────────────────
python3 <<'PYFIX'
import pathlib, re
path = pathlib.Path("tests/scale_test.go")
src = path.read_text()
# Exact line (tabs + trailing newline): "\t\t\tcanonical := envelope.Serialize(entry)\n"
# Appears twice in scale_test.go. Remove both occurrences.
target = "\t\t\tcanonical := envelope.Serialize(entry)\n"
count = src.count(target)
if count == 0:
    print("· tests/scale_test.go — dead canonical lines already removed")
elif count in (1, 2):
    src = src.replace(target, "")
    path.write_text(src)
    print(f"✓ tests/scale_test.go — removed {count} dead `canonical` line(s)")
else:
    print(f"! tests/scale_test.go — unexpected count of `canonical` lines: {count}")
PYFIX

# ─────────────────────────────────────────────────────────────────────
# Fix 6 — remove orphaned `crypto/sha256` imports in helpers_test.go and
# scale_test.go. Post-migration, sha256.Sum256 is replaced everywhere by
# envelope.EntryIdentity. Confirmed via source review: no function body
# in either file still references sha256.*.
# ─────────────────────────────────────────────────────────────────────
python3 <<'PYFIX'
import pathlib
for target in ("tests/helpers_test.go", "tests/scale_test.go"):
    path = pathlib.Path(target)
    src = path.read_text()
    # Defensive: bail if sha256. is actually used anywhere in function bodies.
    # (The import line contains "sha256" too, so search for usage patterns.)
    body = src
    # Strip the import block to search only code.
    import_end = body.find(")", body.find("import ("))
    if import_end > 0:
        code = body[import_end+1:]
        if "sha256." in code:
            print(f"! {target} — sha256 still used in code, refusing to remove import")
            continue
    needle = '\t"crypto/sha256"\n'
    if needle in src:
        path.write_text(src.replace(needle, "", 1))
        print(f"✓ {target} — removed orphaned crypto/sha256 import")
    else:
        print(f"· {target} — crypto/sha256 import already absent")
PYFIX

# ─────────────────────────────────────────────────────────────────────
# Verify
# ─────────────────────────────────────────────────────────────────────
echo
echo "══ Post-patch verification ══"
echo
echo "— go build ./... —"
go build ./... 2>&1 || true
echo
echo "— go vet ./... —"
go vet ./... 2>&1 || true
echo
echo "— compile test package without running —"
go test -count=1 -run 'TestDoesNotExist_Sentinel_ZZZ' ./tests/... 2>&1 | head -20 || true