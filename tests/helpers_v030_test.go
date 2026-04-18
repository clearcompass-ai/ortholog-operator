/*
FILE PATH: tests/helpers_v030_test.go

DESCRIPTION:

	Additive helpers for the v0.3.0-tessera migration. Adds the
	testLogDID constant and a thin wrapper for entry construction that
	defaults Destination when callers leave it unset.

	This file is separate from helpers_test.go to make the migration
	additive: helpers_test.go needs small in-place edits (the
	canonicalHashBytes function body, see helpers_test.PATCH.go), but
	everything net-new lives here. Keeps diffs against the original
	helpers_test.go minimal.

	Once confidence is established, contents of this file can be folded
	into helpers_test.go by hand.

KEY ARCHITECTURAL DECISIONS:
  - testLogDID is the canonical DID the test server is configured with.
    Every helper that builds an Entry defaults to this value. Tests that
    want to exercise cross-destination behavior pass an explicit
    Destination in the ControlHeader.
  - makeV030Entry is the successor to makeEntry. It runs envelope.NewEntry
    (not a struct literal), so it exercises the same gate that production
    callers hit. Tests that deliberately forge malformed entries bypass
    this helper and hand-construct via struct literal.
  - No global state. Every helper takes *testing.T for failure reporting.
*/
package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────

// testLogDID is the DID the test operator is bound to. Every test helper
// that constructs an Entry defaults Destination to this value so existing
// fixtures keep working without a per-test edit.
//
// Tests that exercise cross-destination behavior set an explicit
// Destination on the ControlHeader, which the helper respects.
//
// MUST match the value the test server's config passes into
// api.SubmissionDeps.LogDID, or every default-Destination entry will
// fail step 3b's destination check with 403 Forbidden.
// testLogDID is defined in helpers_test.go at package scope. We reuse that
// value (did:ortholog:test:integration) as both the log destination and
// the operator DID for self-published entries in v0.3.0 fixtures.
const testOperatorDID = testLogDID

// ─────────────────────────────────────────────────────────────────────
// Entry construction helpers
// ─────────────────────────────────────────────────────────────────────

// makeV030Entry constructs an Entry via envelope.NewEntry, defaulting
// hdr.Destination to testLogDID when the caller leaves it empty. This
// is the v0.3.0 successor to the legacy makeEntry helper.
//
// Use this in new tests. Existing tests using makeEntry are patched
// in-place via helpers_test.PATCH.go (which adds the same default
// injection directly to makeEntry's body).
//
// Fails the test on NewEntry error — helpers that silently return nil
// create observability gaps in downstream failures.
func makeV030Entry(
	t *testing.T,
	hdr envelope.ControlHeader,
	payload []byte,
) *envelope.Entry {
	t.Helper()
	if hdr.Destination == "" {
		hdr.Destination = testLogDID
	}
	entry, err := envelope.NewEntry(hdr, payload)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	return entry
}

// makeForeignEntry is a convenience wrapper building an Entry bound to
// a foreign exchange DID. Used by cross-destination rejection tests.
//
// Equivalent to makeV030Entry with hdr.Destination overridden — kept as
// a named helper so test intent (i.e., "this entry is deliberately
// targeting the wrong exchange") is obvious from the call site.
func makeForeignEntry(
	t *testing.T,
	hdr envelope.ControlHeader,
	payload []byte,
) *envelope.Entry {
	t.Helper()
	const foreignLogDID = "did:web:other-log.example"
	hdr.Destination = foreignLogDID
	entry, err := envelope.NewEntry(hdr, payload)
	if err != nil {
		t.Fatalf("NewEntry (foreign destination): %v", err)
	}
	return entry
}

// ─────────────────────────────────────────────────────────────────────
// Compile-time sanity checks
// ─────────────────────────────────────────────────────────────────────

// These var declarations exercise the SDK's primary Entry-hashing
// primitives at compile time. If the SDK ever renames or removes one of
// these, the test suite breaks at build time — making the API drift
// obvious before any test run.
var (
	_ = envelope.EntryIdentity   // Tessera dedup key (preferred vocabulary)
	_ = envelope.EntryLeafHash   // RFC 6962 leaf hash (consumer-side only)
	_ = envelope.Serialize       // canonical bytes
	_ = envelope.Deserialize     // canonical parser
	_ = envelope.StripSignature  // wire → canonical+sig split
	_ = envelope.AppendSignature // canonical+sig → wire
	_ = envelope.ValidateDestination
)
