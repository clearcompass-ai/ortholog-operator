#!/usr/bin/env bash
#
# operator-v6-audit.sh — evidence gathering for operator v6 migration
#
# Answers three questions with type-resolved precision:
#   1. Every callsite to envelope.NewEntry (what breaks against v6 SDK)
#   2. Every callsite to envelope.NewUnsignedEntry + SigningPayload (v6-correct code)
#   3. Signing infrastructure in operator (signers, key loading, crypto.Signer impls)
#   4. Where Publisher is instantiated (what we'll need to update)
#
# Run from operator root:
#   cd ~/workspace/ortholog-operator
#   bash operator-v6-audit.sh

set -eu

if [ ! -f go.mod ]; then
    echo "ERROR: run from operator repo root (go.mod not found)" >&2
    exit 1
fi

OUT=/tmp/operator-v6-audit
mkdir -p "$OUT"

echo "================================================================"
echo "OPERATOR V6 MIGRATION — EVIDENCE GATHERING"
echo "================================================================"
echo

# --------------------------------------------------------------------
# Q1: Compile errors — the definitive "what's broken" list
# --------------------------------------------------------------------

echo "=== 1. Current compile errors (definitive breakage list) ==="
echo

go build ./... 2>&1 | tee "$OUT/build-errors.txt" || true
echo

ERROR_COUNT=$(grep -c 'error\|wrong' "$OUT/build-errors.txt" 2>/dev/null || echo 0)
echo "  → $ERROR_COUNT error lines captured in $OUT/build-errors.txt"
echo

# --------------------------------------------------------------------
# Q2: Every envelope.NewEntry callsite (text-level — fast)
# --------------------------------------------------------------------

echo "=== 2. envelope.NewEntry callsites (text-level for breadth) ==="
echo

grep -rn 'envelope\.NewEntry(' --include='*.go' . 2>/dev/null \
    | grep -v '_test.go' \
    | tee "$OUT/newentry-callsites.txt" || echo "(none found)"
echo

NE_COUNT=$(wc -l < "$OUT/newentry-callsites.txt" 2>/dev/null | tr -d ' ' || echo 0)
echo "  → $NE_COUNT production callsites to envelope.NewEntry"
echo

# --------------------------------------------------------------------
# Q3: Every envelope.NewUnsignedEntry + SigningPayload callsite
#     (shows which code is ALREADY v6-correct)
# --------------------------------------------------------------------

echo "=== 3. v6-correct patterns (NewUnsignedEntry + SigningPayload) ==="
echo

grep -rn 'envelope\.NewUnsignedEntry\|envelope\.SigningPayload' --include='*.go' . 2>/dev/null \
    | tee "$OUT/v6-correct.txt" || echo "(none found — operator has NO v6-compliant signing)"
echo

V6_COUNT=$(wc -l < "$OUT/v6-correct.txt" 2>/dev/null | tr -d ' ' || echo 0)
echo "  → $V6_COUNT existing v6-correct signing sites"
echo

# --------------------------------------------------------------------
# Q4: Signing infrastructure — what exists to sign with
# --------------------------------------------------------------------

echo "=== 4. Signing infrastructure in operator ==="
echo

echo "--- 4a. Signer interfaces / types ---"
grep -rn 'type.*Signer[^s]\|interface.*Sign\b' --include='*.go' . 2>/dev/null \
    | grep -v '_test.go' \
    | tee "$OUT/signer-types.txt" || echo "(none)"
echo

echo "--- 4b. Private key handling ---"
grep -rn 'PrivateKey\|ecdsa\.GenerateKey\|ed25519\.Generate\|LoadKey\|ReadKey' --include='*.go' . 2>/dev/null \
    | grep -v '_test.go' \
    | head -30 \
    | tee "$OUT/private-keys.txt" || echo "(none)"
echo

echo "--- 4c. crypto/ecdsa and crypto/ed25519 imports ---"
grep -rln '"crypto/ecdsa"\|"crypto/ed25519"\|"crypto/rsa"' --include='*.go' . 2>/dev/null \
    | grep -v '_test.go' \
    | tee "$OUT/crypto-imports.txt" || echo "(none)"
echo

# --------------------------------------------------------------------
# Q5: Publisher wiring — where is anchor.Publisher instantiated?
# --------------------------------------------------------------------

echo "=== 5. anchor.Publisher instantiation (what we need to update) ==="
echo

echo "--- 5a. NewPublisher callsites ---"
grep -rn 'anchor\.NewPublisher\|NewPublisher(' --include='*.go' . 2>/dev/null \
    | grep -v '_test.go' \
    | tee "$OUT/publisher-instantiation.txt" || echo "(none — publisher may not be wired)"
echo

echo "--- 5b. PublisherConfig construction ---"
grep -rn 'anchor\.PublisherConfig\|PublisherConfig{' --include='*.go' . 2>/dev/null \
    | grep -v '_test.go' \
    | tee "$OUT/publisher-config.txt" || echo "(none)"
echo

# --------------------------------------------------------------------
# Q6: key file presence in deployment
# --------------------------------------------------------------------

echo "=== 6. Key files in deployment ==="
echo

find . -name '*.pem' -o -name '*.key' -o -name '*.priv' 2>/dev/null \
    | grep -v node_modules \
    | tee "$OUT/key-files.txt" || echo "(no key files found)"
echo

# --------------------------------------------------------------------
# Q7: What does cmd/operator/main.go actually do?
# --------------------------------------------------------------------

echo "=== 7. cmd/operator/main.go signing-related logic ==="
echo

if [ -f cmd/operator/main.go ]; then
    echo "--- File exists. Extracting relevant sections: ---"
    echo
    echo "## Imports:"
    sed -n '/^import/,/^)/p' cmd/operator/main.go | head -30
    echo
    echo "## Signing/key-related lines:"
    grep -n 'Sign\|Key\|PrivateKey\|Publisher\|Anchor' cmd/operator/main.go | head -40
    echo
else
    echo "cmd/operator/main.go not found"
fi

# --------------------------------------------------------------------
# Q8: Signer usage in SDK (reference for how operator should implement)
# --------------------------------------------------------------------

echo "=== 8. SDK's own signer conventions (for reference) ==="
echo

SDK_ROOT=~/workspace/ortholog-sdk
if [ -d "$SDK_ROOT" ]; then
    echo "--- SDK signer type definitions ---"
    grep -rn 'type.*Signer\b\|type Sign\b' "$SDK_ROOT" --include='*.go' 2>/dev/null \
        | grep -v '_test.go' \
        | head -20 \
        | tee "$OUT/sdk-signer-types.txt"
    echo

    echo "--- SDK test helpers for entry construction (buildTestEntry pattern) ---"
    grep -rn 'buildTestEntry\|NewUnsignedEntry\|SigningPayload' "$SDK_ROOT" --include='*.go' 2>/dev/null \
        | head -20 \
        | tee "$OUT/sdk-signing-patterns.txt"
    echo
fi

# --------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------

echo "================================================================"
echo "SUMMARY"
echo "================================================================"
echo
echo "Files produced in $OUT/:"
ls -la "$OUT/"
echo
echo "Key findings:"
echo "  - Compile errors:            $ERROR_COUNT lines"
echo "  - NewEntry callsites:        $NE_COUNT"
echo "  - v6-correct sites:          $V6_COUNT"
echo
echo "Next step: paste the full output or share $OUT/ for analysis."