#!/usr/bin/env bash
# Fix missing Destination fields in tests/helpers_test.go ControlHeader
# literals — the root cause of the TestDeterminism panic.
#
# EVIDENCE:
#   Full source of helpers_test.go reviewed. Four sites construct
#   envelope.ControlHeader{} without Destination:
#     - addRootEntity   (line ~245)
#     - addDelegation   (line ~259)
#     - addScopeEntity  (line ~274)
#     - generateEntries (line ~340) — ALSO swallows NewEntry error with `_`
#
#   SDK v0.3.0-tessera's NewEntry calls ValidateDestination, which errors
#   on empty Destination. generateEntries's `, _` caused the error to be
#   silently swallowed, producing nil entries that panicked downstream in
#   envelope.Serialize.
#
# SEMANTIC CHOICE:
#   - add*() helpers: Destination = the LogPosition's LogDID. Entries
#     correctly target the log they're being stored at, including
#     foreignPos() cases.
#   - generateEntries: Destination = testLogDID (matches pos() which uses
#     testLogDID unconditionally).
#
# IDEMPOTENT. SAFE RE-RUN.

set -euo pipefail

cd ~/workspace/ortholog-operator

FILE="tests/helpers_test.go"
[[ -f "$FILE" ]] || { echo "ERROR: $FILE not found"; exit 1; }

python3 <<'PYFIX'
import pathlib
path = pathlib.Path("tests/helpers_test.go")
src = path.read_text()
original = src

# ─────────────────────────────────────────────────────────────
# Patch 1 — addRootEntity
# ─────────────────────────────────────────────────────────────
old = ("\tentry := makeEntry(t, envelope.ControlHeader{\n"
       "\t\tSignerDID:     signerDID,\n"
       "\t\tAuthorityPath: sameSigner(),\n"
       "\t}, nil)\n"
       "\th.fetcher.storeEntry(p, entry)\n"
       "\tkey := smt.DeriveKey(p)\n"
       "\tleaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}\n")
new = ("\tentry := makeEntry(t, envelope.ControlHeader{\n"
       "\t\tSignerDID:     signerDID,\n"
       "\t\tDestination:   p.LogDID,\n"
       "\t\tAuthorityPath: sameSigner(),\n"
       "\t}, nil)\n"
       "\th.fetcher.storeEntry(p, entry)\n"
       "\tkey := smt.DeriveKey(p)\n"
       "\tleaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}\n")
if new in src:
    print("· addRootEntity: already patched")
elif old in src:
    src = src.replace(old, new, 1)
    print("✓ addRootEntity: Destination added")
else:
    print("! addRootEntity: pattern not found — MANUAL REVIEW NEEDED")

# ─────────────────────────────────────────────────────────────
# Patch 2 — addDelegation
# ─────────────────────────────────────────────────────────────
old = ("\tentry := makeEntry(t, envelope.ControlHeader{\n"
       "\t\tSignerDID:     signerDID,\n"
       "\t\tAuthorityPath: sameSigner(),\n"
       "\t\tDelegateDID:   &delegateDID,\n"
       "\t}, nil)\n")
new = ("\tentry := makeEntry(t, envelope.ControlHeader{\n"
       "\t\tSignerDID:     signerDID,\n"
       "\t\tDestination:   delegPos.LogDID,\n"
       "\t\tAuthorityPath: sameSigner(),\n"
       "\t\tDelegateDID:   &delegateDID,\n"
       "\t}, nil)\n")
if new in src:
    print("· addDelegation: already patched")
elif old in src:
    src = src.replace(old, new, 1)
    print("✓ addDelegation: Destination added")
else:
    print("! addDelegation: pattern not found — MANUAL REVIEW NEEDED")

# ─────────────────────────────────────────────────────────────
# Patch 3 — addScopeEntity
# ─────────────────────────────────────────────────────────────
old = ("\tentry := makeEntry(t, envelope.ControlHeader{\n"
       "\t\tSignerDID:     signerDID,\n"
       "\t\tAuthorityPath: sameSigner(),\n"
       "\t\tAuthoritySet:  authSet,\n"
       "\t}, nil)\n")
new = ("\tentry := makeEntry(t, envelope.ControlHeader{\n"
       "\t\tSignerDID:     signerDID,\n"
       "\t\tDestination:   p.LogDID,\n"
       "\t\tAuthorityPath: sameSigner(),\n"
       "\t\tAuthoritySet:  authSet,\n"
       "\t}, nil)\n")
if new in src:
    print("· addScopeEntity: already patched")
elif old in src:
    src = src.replace(old, new, 1)
    print("✓ addScopeEntity: Destination added")
else:
    print("! addScopeEntity: pattern not found — MANUAL REVIEW NEEDED")

# ─────────────────────────────────────────────────────────────
# Patch 4 — generateEntries (adds Destination + fixes silent error)
# ─────────────────────────────────────────────────────────────
old = ("\t\tentries[i], _ = envelope.NewEntry(envelope.ControlHeader{\n"
       "\t\t\tSignerDID:     didForUser(i / 10),\n"
       "\t\t\tAuthorityPath: ap,\n"
       "\t\t}, []byte{byte(i)})\n"
       "\t\tpositions[i] = pos(uint64(i + 1))\n")
new = ("\t\tentry, err := envelope.NewEntry(envelope.ControlHeader{\n"
       "\t\t\tSignerDID:     didForUser(i / 10),\n"
       "\t\t\tDestination:   testLogDID,\n"
       "\t\t\tAuthorityPath: ap,\n"
       "\t\t}, []byte{byte(i)})\n"
       "\t\tif err != nil {\n"
       "\t\t\tpanic(fmt.Sprintf(\"generateEntries[%d]: NewEntry failed: %v\", i, err))\n"
       "\t\t}\n"
       "\t\tentries[i] = entry\n"
       "\t\tpositions[i] = pos(uint64(i + 1))\n")
if new in src:
    print("· generateEntries: already patched")
elif old in src:
    src = src.replace(old, new, 1)
    print("✓ generateEntries: Destination added + error check fixed")
else:
    print("! generateEntries: pattern not found — MANUAL REVIEW NEEDED")

# Remove the fmt suppression if generateEntries now uses fmt.Sprintf —
# it will still be used there, so the suppressor becomes redundant but
# not harmful. Leave it alone to minimize diff.

if src != original:
    path.write_text(src)
    print(f"\nWrote {path} ({len(src) - len(original):+d} bytes)")
else:
    print("\nNo changes applied.")
PYFIX

# ─────────────────────────────────────────────────────────────────────
# Defensive scan: are there other ControlHeader sites in tests/ that
# omit Destination? Flag without auto-fixing — manual review needed.
# ─────────────────────────────────────────────────────────────────────
echo
echo "══ Defensive scan: other ControlHeader sites in tests/ ══"
python3 <<'PYSCAN'
import pathlib, re

SUSPECT = []
for path in sorted(pathlib.Path("tests").glob("*.go")):
    if path.name.endswith(".bak"):
        continue
    src = path.read_text()
    # Find every `envelope.ControlHeader{` opening and its matching `}`.
    # Simple brace-counter — Go struct literals don't nest arbitrary
    # characters that would break this.
    idx = 0
    while True:
        start = src.find("envelope.ControlHeader{", idx)
        if start < 0:
            break
        # Find matching close brace.
        depth = 1
        i = start + len("envelope.ControlHeader{")
        while i < len(src) and depth > 0:
            if src[i] == '{':
                depth += 1
            elif src[i] == '}':
                depth -= 1
            i += 1
        literal = src[start:i]
        if "Destination:" not in literal:
            # Line number for grep-friendly output.
            line_no = src[:start].count('\n') + 1
            SUSPECT.append((str(path), line_no, literal.split('\n')[0]))
        idx = i

if not SUSPECT:
    print("  ✓ All ControlHeader{} literals in tests/ include Destination.")
else:
    print("  ⚠ Found ControlHeader{} without Destination:")
    for p, ln, snippet in SUSPECT:
        print(f"      {p}:{ln}  {snippet}")
    print()
    print("  These may be intentional (e.g., forged-malformed tests that")
    print("  deliberately omit Destination to exercise Validate()), OR")
    print("  they may be sites that need patching. Inspect each before")
    print("  deciding.")
PYSCAN

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
echo "— compile-only test package —"
go test -count=1 -run 'TestDoesNotExist_ZZZ_Sentinel' ./tests/... 2>&1 | head -20 || true
echo
echo "— actually run the determinism test that was panicking —"
echo "  (skipped if ORTHOLOG_TEST_DSN is required; this test is in-memory so should run)"
go test -count=1 -run 'TestDeterminism_RootMatch_1000Entries' ./tests/ -v 2>&1 | tail -30 || true