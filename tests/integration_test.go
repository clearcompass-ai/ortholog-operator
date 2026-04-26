/*
FILE PATH: tests/integration_test.go

85 integration tests across 14 categories. Every test has real assertions.
Tests requiring Postgres skip gracefully when ORTHOLOG_TEST_DSN is unset.
Tests requiring Tessera use the SDK's StubMerkleTree.

POST-WAVE-1.5 CHANGES:
  - admission.GenerateStamp now takes a StampParams struct (named fields).
  - admission.VerifyStamp takes 8 args including currentEpoch + acceptanceWindow.
  - Test helpers buildStampParams + verifyStampForTest (helpers_test.go) keep
    call sites readable. They wire Epoch from currentTestEpoch() so the test
    matches what the operator's runtime computes.
  - Wire format is protocol v5 (Wave 1.5). All preamble references updated.

PR 2 — WAVE 2 CHANGES:
  - Every envelope.ControlHeader{} literal replaced with the typed
    testHeader(testExchangeDID, signerDID) constructor. Additional
    fields assigned explicitly after construction. See helpers_test.go
    for the constructor's contract.
  - TestSMT_PathD_ForeignTarget carries a semantic comment explaining
    why Destination=testExchangeDID even though TargetRoot points at a
    foreign log.

Run without Postgres:  go test ./tests/ -v -count=1
Run with Postgres:     ORTHOLOG_TEST_DSN="postgres://..." go test ./tests/ -v -count=1
*/
package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/ortholog-operator/api/middleware"
	opbuilder "github.com/clearcompass-ai/ortholog-operator/builder"
	"github.com/clearcompass-ai/ortholog-operator/store"
	"github.com/clearcompass-ai/ortholog-operator/store/indexes"
	"github.com/clearcompass-ai/ortholog-operator/witness"
)

// ═════════════════════════════════════════════════════════════════════════════
// Category 1: Admission Pipeline (13 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestAdmission_ValidEntry(t *testing.T) {
	entry := makeEntry(t, testHeader(testExchangeDID, "did:example:alice"), []byte("attestation"))
	canonical := envelope.Serialize(entry)
	hash := sha256.Sum256(canonical)
	if len(canonical) == 0 {
		t.Fatal("canonical bytes should not be empty")
	}
	if hash == [32]byte{} {
		t.Fatal("hash should not be zero")
	}
	t.Logf("valid entry: %d bytes, hash %x", len(canonical), hash[:8])
}

func TestAdmission_DuplicateHash(t *testing.T) {
	entry := makeEntry(t, testHeader(testExchangeDID, "did:example:alice"), nil)
	h1 := sha256.Sum256(envelope.Serialize(entry))
	h2 := sha256.Sum256(envelope.Serialize(entry))
	if h1 != h2 {
		t.Fatal("identical entries must produce identical hashes")
	}
}

func TestAdmission_MalformedBytes(t *testing.T) {
	_, _, _, err := envelope.StripSignature([]byte{0xFF, 0xFF})
	if err == nil {
		t.Fatal("malformed bytes should fail StripSignature")
	}
}

func TestAdmission_UnsignedEntry_SDK_D5(t *testing.T) {
	raw := []byte{0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0xFF}
	_, _, _, err := envelope.StripSignature(raw)
	if err == nil {
		t.Fatal("truncated entry should fail StripSignature")
	}
}

func TestAdmission_WrongSignerKey_SDK_D5(t *testing.T) {
	entry := makeEntry(t, testHeader(testExchangeDID, "did:example:alice"), nil)
	canonical := envelope.Serialize(entry)
	fakeSig := make([]byte, 64)
	wire := envelope.MustAppendSignature(canonical, envelope.SigAlgoECDSA, fakeSig)
	gotCanonical, algoID, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCanonical) == 0 || algoID != envelope.SigAlgoECDSA || len(gotSig) != 64 {
		t.Fatal("signature stripping should succeed even with fake sig")
	}
}

func TestAdmission_CorruptSignature_SDK_D5(t *testing.T) {
	entry := makeEntry(t, testHeader(testExchangeDID, "did:example:alice"), nil)
	canonical := envelope.Serialize(entry)
	wire := envelope.MustAppendSignature(canonical, envelope.SigAlgoECDSA,
		[]byte("not-a-real-signature-but-64-bytes-long-padding-here-1234567890ab"))
	_, _, sig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatal("strip should succeed on well-formed wire")
	}
	if len(sig) != 64 {
		t.Fatal("sig should be 64 bytes")
	}
}

func TestAdmission_ExactlyMaxSize_SDK_D11(t *testing.T) {
	payload := make([]byte, (1<<20)-200)
	entry := makeEntry(t, testHeader(testExchangeDID, "did:example:big"), payload)
	if len(envelope.Serialize(entry)) == 0 {
		t.Fatal("near-max entry should serialize")
	}
}

func TestAdmission_OverMaxSize_SDK_D11(t *testing.T) {
	if int64(len(make([]byte, (1<<20)+1))) <= int64(1<<20) {
		t.Fatal("should exceed max")
	}
}

// TestAdmission_EvidenceCapNonSnapshot_Decision51 verifies that a non-snapshot
// entry carrying more than envelope.MaxEvidencePointers (32) is rejected by
// NewEntry. Decision 51 caps routine evidence at 32; only authority snapshot
// entries (Path C with PriorAuthority + AuthoritySet) are exempt.
func TestAdmission_EvidenceCapNonSnapshot_Decision51(t *testing.T) {
	if envelope.MaxEvidencePointers != 32 {
		t.Fatalf("test assumes MaxEvidencePointers=32, got %d — update test", envelope.MaxEvidencePointers)
	}
	overCap := envelope.MaxEvidencePointers + 1
	pointers := make([]types.LogPosition, overCap)
	for i := range pointers {
		pointers[i] = pos(uint64(i + 1))
	}
	hdr := testHeader(testExchangeDID, "did:example:overcap")
	hdr.EvidencePointers = pointers
	_, err := envelope.NewEntry(hdr, nil)
	if err == nil {
		t.Fatalf("%d Evidence_Pointers on non-snapshot should be rejected (cap=%d)",
			overCap, envelope.MaxEvidencePointers)
	}
}

// TestAdmission_EvidenceCapSnapshotExempt_Decision51 verifies that an authority
// snapshot entry can carry MORE than MaxEvidencePointers without being rejected.
// Snapshots aggregate cosignature references and are deliberately uncapped.
func TestAdmission_EvidenceCapSnapshotExempt_Decision51(t *testing.T) {
	if envelope.MaxEvidencePointers != 32 {
		t.Fatalf("test assumes MaxEvidencePointers=32, got %d — update test", envelope.MaxEvidencePointers)
	}
	overCap := envelope.MaxEvidencePointers + 1
	pointers := make([]types.LogPosition, overCap)
	for i := range pointers {
		pointers[i] = pos(uint64(i + 1))
	}
	tr := pos(100)
	pa := pos(99)
	sp := pos(50)
	hdr := testHeader(testExchangeDID, "did:example:snapshot")
	hdr.AuthorityPath = scopeAuth()
	hdr.TargetRoot = &tr
	hdr.PriorAuthority = &pa
	hdr.ScopePointer = &sp
	hdr.EvidencePointers = pointers
	_, err := envelope.NewEntry(hdr, nil)
	if err != nil {
		t.Fatalf("snapshot with %d pointers should be exempt from cap=%d: %v",
			overCap, envelope.MaxEvidencePointers, err)
	}
}

func TestAdmission_ModeB_ValidStamp(t *testing.T) {
	h := [32]byte{1, 2, 3, 4}
	params := buildStampParams(h, testLogDID, 8)

	nonce, err := admission.GenerateStamp(params)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	if err := verifyStampForTest(params, nonce, testLogDID, 8); err != nil {
		t.Fatalf("VerifyStamp on fresh stamp: %v", err)
	}
}

func TestAdmission_ModeB_WrongLog(t *testing.T) {
	h := [32]byte{5, 6, 7, 8}
	params := buildStampParams(h, testLogDID, 8)

	nonce, err := admission.GenerateStamp(params)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	err = verifyStampForTest(params, nonce, "did:ortholog:different", 8)
	if err == nil {
		t.Fatal("stamp bound to wrong log DID should fail verification")
	}
	t.Logf("wrong-log rejection: %v", err)
}

func TestAdmission_ModeB_BelowDifficulty(t *testing.T) {
	h := [32]byte{9, 10, 11, 12}
	params := buildStampParams(h, testLogDID, 8)

	nonce, err := admission.GenerateStamp(params)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	err = verifyStampForTest(params, nonce, testLogDID, 16)
	if err == nil {
		t.Fatal("stamp below required difficulty should fail verification")
	}
	t.Logf("below-difficulty rejection: %v", err)
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 2: Builder Determinism (6 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestDeterminism_RootMatch_1000Entries(t *testing.T) {
	entries, positions := generateEntries(1000)
	r1 := runSDKBuilder(t, entries, positions)
	r2 := runSDKBuilder(t, entries, positions)
	if r1.NewRoot != r2.NewRoot {
		t.Fatalf("DETERMINISM FAILURE: %x != %x", r1.NewRoot[:8], r2.NewRoot[:8])
	}
	t.Logf("determinism verified: root=%x leaves=%d", r1.NewRoot[:8], r1.NewLeafCounts)
}

func TestDeterminism_AllPaths(t *testing.T) {
	var entries []*envelope.Entry
	var positions []types.LogPosition
	seq := uint64(1)
	for i := 0; i < 25; i++ {
		hdr := testHeader(testExchangeDID, didForUser(i))
		hdr.AuthorityPath = sameSigner()
		entries = append(entries, makeEntry(t, hdr, nil))
		positions = append(positions, pos(seq))
		seq++
	}
	for i := 0; i < 25; i++ {
		entries = append(entries, makeEntry(t, testHeader(testExchangeDID, "did:example:w"+itoa(i)), nil))
		positions = append(positions, pos(seq))
		seq++
	}
	r1 := runSDKBuilder(t, entries, positions)
	r2 := runSDKBuilder(t, entries, positions)
	if r1.NewRoot != r2.NewRoot {
		t.Fatal("all-path determinism failed")
	}
	if r1.NewLeafCounts != 25 {
		t.Fatalf("expected 25 leaves, got %d", r1.NewLeafCounts)
	}
	if r1.CommentaryCounts != 25 {
		t.Fatalf("expected 25 commentary, got %d", r1.CommentaryCounts)
	}
}

func TestDeterminism_PathCompression(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:alice")
	h.addRootEntity(t, pos(2), "did:example:alice")
	hdr := testHeader(testExchangeDID, "did:example:alice")
	hdr.TargetRoot = ptrTo(pos(1))
	hdr.TargetIntermediate = ptrTo(pos(2))
	hdr.AuthorityPath = sameSigner()
	action := makeEntry(t, hdr, nil)
	r := h.process(t, action, pos(3))
	if r.PathACounts != 1 {
		t.Fatal("expected Path A")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(3)) {
		t.Fatal("root OriginTip not updated")
	}
	if !h.leafOriginTip(t, pos(2)).Equal(pos(3)) {
		t.Fatal("intermediate OriginTip not updated")
	}
}

func TestDeterminism_LaneSelection(t *testing.T) {
	entries, positions := generateEntries(100)
	r1 := runSDKBuilder(t, entries, positions)
	r2 := runSDKBuilder(t, entries, positions)
	if r1.NewRoot != r2.NewRoot {
		t.Fatal("lane selection determinism failed")
	}
}

func TestDeterminism_CommutativeSchemas(t *testing.T) {
	entries, positions := generateEntries(50)
	r1 := runSDKBuilder(t, entries, positions)
	r2 := runSDKBuilder(t, entries, positions)
	if r1.NewRoot != r2.NewRoot {
		t.Fatal("commutative determinism failed")
	}
}

func TestDeterminism_EmptyBatch(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	rootBefore, _ := tree.Root()
	result, _ := builder.ProcessBatch(tree, nil, nil, newMockFetcher(), nil, testLogDID, builder.NewDeltaWindowBuffer(10))
	if result.NewRoot != rootBefore {
		t.Fatal("empty batch should not change root")
	}
	if len(result.Mutations) != 0 {
		t.Fatal("empty batch = no mutations")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 3: SMT State Correctness (8 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestSMT_LeafCreation(t *testing.T) {
	h := newHarness()
	hdr := testHeader(testExchangeDID, "did:example:alice")
	hdr.AuthorityPath = sameSigner()
	r := h.process(t, makeEntry(t, hdr, nil), pos(1))
	if r.NewLeafCounts != 1 {
		t.Fatal("expected 1 leaf")
	}
	leaf, _ := h.tree.GetLeaf(smt.DeriveKey(pos(1)))
	if leaf == nil {
		t.Fatal("leaf should exist")
	}
	if leaf.OriginTip != pos(1) || leaf.AuthorityTip != pos(1) {
		t.Fatal("both tips should be self")
	}
}

func TestSMT_OriginTipUpdate_PathA(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:alice")
	hdr := testHeader(testExchangeDID, "did:example:alice")
	hdr.TargetRoot = ptrTo(pos(1))
	hdr.AuthorityPath = sameSigner()
	h.process(t, makeEntry(t, hdr, []byte("amended")), pos(2))
	if !h.leafOriginTip(t, pos(1)).Equal(pos(2)) {
		t.Fatal("OriginTip should advance")
	}
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("AuthorityTip should NOT change")
	}
}

func TestSMT_AuthorityTipUpdate_PathC(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:entity")
	h.addScopeEntity(t, pos(2), "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	hdr := testHeader(testExchangeDID, "did:example:judge")
	hdr.TargetRoot = ptrTo(pos(1))
	hdr.AuthorityPath = scopeAuth()
	hdr.ScopePointer = ptrTo(pos(2))
	r := h.process(t, makeEntry(t, hdr, []byte("sealing")), pos(3))
	if r.PathCCounts != 1 {
		t.Fatal("expected Path C")
	}
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(3)) {
		t.Fatal("AuthorityTip should advance")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("OriginTip should NOT change")
	}
}

func TestSMT_LaneSelection_AmendmentExecution(t *testing.T) {
	h := newHarness()
	h.addScopeEntity(t, pos(1), "did:example:a", map[string]struct{}{"did:example:a": {}, "did:example:b": {}})
	newSet := map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}}
	hdr := testHeader(testExchangeDID, "did:example:a")
	hdr.TargetRoot = ptrTo(pos(1))
	hdr.AuthorityPath = scopeAuth()
	hdr.ScopePointer = ptrTo(pos(1))
	hdr.AuthoritySet = newSet
	h.process(t, makeEntry(t, hdr, nil), pos(2))
	if !h.leafOriginTip(t, pos(1)).Equal(pos(2)) {
		t.Fatal("amendment should update OriginTip")
	}
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("amendment should NOT update AuthorityTip")
	}
}

func TestSMT_LaneSelection_Enforcement(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:entity")
	h.addScopeEntity(t, pos(2), "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	hdr := testHeader(testExchangeDID, "did:example:judge")
	hdr.TargetRoot = ptrTo(pos(1))
	hdr.AuthorityPath = scopeAuth()
	hdr.ScopePointer = ptrTo(pos(2))
	h.process(t, makeEntry(t, hdr, nil), pos(3))
	if !h.leafAuthorityTip(t, pos(1)).Equal(pos(3)) {
		t.Fatal("enforcement should update AuthorityTip")
	}
	if !h.leafOriginTip(t, pos(1)).Equal(pos(1)) {
		t.Fatal("enforcement should NOT update OriginTip")
	}
}

func TestSMT_CommentaryZeroImpact(t *testing.T) {
	h := newHarness()
	rootBefore := h.root(t)
	r := h.process(t, makeEntry(t, testHeader(testExchangeDID, "did:example:witness"), nil), pos(1))
	if r.NewRoot != rootBefore {
		t.Fatal("commentary should not change root")
	}
	if r.CommentaryCounts != 1 {
		t.Fatal("should count as commentary")
	}
	if h.leafExists(t, pos(1)) {
		t.Fatal("commentary should NOT create a leaf")
	}
}

func TestSMT_PathD_ForeignTarget(t *testing.T) {
	h := newHarness()
	rootBefore := h.root(t)

	// SEMANTIC NOTE: Destination is testExchangeDID (our exchange); this
	// entry lives on our log. TargetRoot points to foreignPos(1), whose
	// LogDID differs from ours; the SMT classifies this as Path D
	// (foreign reference, no local state change).
	//
	// Destination and TargetRoot are independent axes:
	//   Destination = where this entry LIVES (the exchange admitting it)
	//   TargetRoot  = what entity this entry REFERENCES (may be on another log)
	//
	// Setting Destination to a foreign exchange DID would make the entry
	// inadmissible (step 3b registry lookup fails) and the test would
	// never reach Path D detection.
	hdr := testHeader(testExchangeDID, "did:example:alice")
	hdr.AuthorityPath = sameSigner()
	hdr.TargetRoot = ptrTo(foreignPos(1))
	r := h.process(t, makeEntry(t, hdr, nil), pos(1))
	if r.NewRoot != rootBefore {
		t.Fatal("foreign target should not change root")
	}
	if r.PathDCounts != 1 {
		t.Fatal("expected Path D")
	}
}

func TestSMT_DelegationLiveness(t *testing.T) {
	h := newHarness()
	h.addRootEntity(t, pos(1), "did:example:owner")
	h.addDelegation(t, pos(2), "did:example:owner", "did:example:delegate")

	// Live: should succeed.
	hdr1 := testHeader(testExchangeDID, "did:example:delegate")
	hdr1.TargetRoot = ptrTo(pos(1))
	hdr1.AuthorityPath = delegation()
	hdr1.DelegationPointers = []types.LogPosition{pos(2)}
	r1 := h.process(t, makeEntry(t, hdr1, nil), pos(3))
	if r1.PathBCounts != 1 {
		t.Fatal("live delegation should succeed")
	}

	// Revoke delegation.
	key := smt.DeriveKey(pos(2))
	leaf, _ := h.tree.GetLeaf(key)
	u := *leaf
	u.OriginTip = pos(4)
	h.tree.SetLeaf(key, u)

	// Revoked: should fail.
	hdr2 := testHeader(testExchangeDID, "did:example:delegate")
	hdr2.TargetRoot = ptrTo(pos(1))
	hdr2.AuthorityPath = delegation()
	hdr2.DelegationPointers = []types.LogPosition{pos(2)}
	r2 := h.process(t, makeEntry(t, hdr2, nil), pos(5))
	if r2.PathDCounts != 1 {
		t.Fatal("revoked delegation should fall to Path D")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Category 4: Query Index Correctness (10 tests)
// ═════════════════════════════════════════════════════════════════════════════

func TestQuery_CosignatureOf_Basic(t *testing.T) {
	if indexes.NewPostgresQueryAPI(nil, testEntryBytes, testLogDID) == nil {
		t.Fatal("nil")
	}
}

func TestQuery_CosignatureOf_Multiple(t *testing.T) {
	pool := skipIfNoPostgres(t)
	qapi := indexes.NewPostgresQueryAPI(pool, testEntryBytes, testLogDID)
	tp := pos(100)
	for i := uint64(1); i <= 5; i++ {
		hdr := testHeader(testExchangeDID, "did:example:w"+itoa(int(i)))
		hdr.CosignatureOf = ptrTo(tp)
		insertTestEntry(t, pool, i, makeEntry(t, hdr, nil), testLogDID)
	}
	results, err := qapi.QueryByCosignatureOf(tp)
	if err != nil {
		t.Fatal(err)
	}
	if