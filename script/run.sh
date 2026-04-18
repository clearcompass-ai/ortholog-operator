#!/usr/bin/env bash
# Apply the three AppendSignature → MustAppendSignature edits.
# Grounded in SDK evidence: core/envelope/signature_wire.go:167 and
# canonical_hash_test.go:231 (the SDK's own test usage pattern).
#
# Idempotent: re-running is safe (Must* is already the target form).

set -euo pipefail

cd "$(dirname "$0")/../../../../workspace/ortholog-operator" 2>/dev/null \
  || cd ~/workspace/ortholog-operator

# All three call sites match this pattern exactly:
#   <something> := envelope.AppendSignature(...)
#
# Rewriting to MustAppendSignature collapses to a single return, matching
# the SDK's own test style. No line renumbering, no call-site argument
# changes — the three args (canonical, algoID, sig) are identical.

perl -i -pe 's/\benvelope\.AppendSignature\b/envelope.MustAppendSignature/g' \
  tests/http_integration_test.go \
  tests/integration_test.go

echo "Applied. Verifying no old form remains:"
grep -n "envelope\.AppendSignature\b" tests/*.go || echo "  (none — clean)"
echo
echo "Confirming new form present:"
grep -n "envelope\.MustAppendSignature" tests/*.go