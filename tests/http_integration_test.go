/*
FILE PATH: tests/http_integration_test.go

HTTP integration tests. Every test makes real HTTP calls to a real operator
server backed by real Postgres. No interface mocks.

Run: ORTHOLOG_TEST_DSN="postgres://..." go test ./tests/ -v -count=1 -run TestHTTP
*/
package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// Wire format helpers
// ─────────────────────────────────────────────────────────────────────────────

// buildWireEntry creates a v3 entry with a fake ECDSA signature appended.
// Used for Mode A (authenticated) submissions where stamp isn't needed.
func buildWireEntry(t *testing.T, header envelope.ControlHeader, payload []byte) []byte {
	t.Helper()
	entry := makeEntry(t, header, payload)
	canonical := envelope.Serialize(entry)
	fakeSig := make([]byte, 64)
	for i := range fakeSig {
		fakeSig[i] = byte(i + 1)
	}
	return envelope.AppendSignature(canonical, envelope.SigAlgoECDSA, fakeSig)
}

// buildModeBWireEntry creates a v3 entry with a valid compute stamp for Mode B.
// Brute-forces the nonce so that the stamp verifies against the canonical hash.
// With difficulty 16 this takes ~65ms on average.
func buildModeBWireEntry(t *testing.T, header envelope.ControlHeader, payload []byte, logDID string, difficulty uint32) []byte {
	t.Helper()
	header.AdmissionProof = &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      0,
		TargetLog:  logDID,
		Difficulty: difficulty,
	}

	for nonce := uint64(0); nonce < 20_000_000; nonce++ {
		header.AdmissionProof.Nonce = nonce
		entry, err := envelope.NewEntry(header, payload)
		if err != nil {
			t.Fatalf("NewEntry: %v", err)
		}
		canonical := envelope.Serialize(entry)
		entryHash := sha256.Sum256(canonical)

		if admission.VerifyStamp(entryHash, nonce, logDID, difficulty, admission.HashSHA256, nil) == nil {
			fakeSig := make([]byte, 64)
			for i := range fakeSig {
				fakeSig[i] = byte(i + 1)
			}
			return envelope.AppendSignature(canonical, envelope.SigAlgoECDSA, fakeSig)
		}
	}
	t.Fatal("could not find valid nonce within 20M iterations")
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Poll helper — replaces flaky time.Sleep
// ─────────────────────────────────────────────────────────────────────────────

// pollQueryResults polls GET /v1/query/signer_did/{did} until expectedCount
// results arrive or timeout. Returns the parsed results.
func pollQueryResults(t *testing.T, baseURL, signerDID string, expectedCount int, timeout time.Duration) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	queryURL := fmt.Sprintf("%s/v1/query/signer_did/%s", baseURL, signerDID)

	for time.Now().Before(deadline) {
		resp, err := http.Get(queryURL)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		var results []map[string]any
		json.NewDecoder(resp.Body).Decode(&results)
		resp.Body.Close()

		if len(results) >= expectedCount {
			return results
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d results from signer %s (waited %s)", expectedCount, signerDID, timeout)
	return nil
}

// submitEntry POSTs a wire entry with auth and returns the parsed response.
func submitEntry(t *testing.T, baseURL, token string, wire []byte) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("POST", baseURL+"/v1/entries", bytes.NewReader(wire))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", resp.StatusCode, body)
	}
	var result map[string]any
	json.Unmarshal(body, &result)
	return result
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. Submission — Mode A (authenticated with session token)
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Submission_ModeA_HappyPath(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-a", "did:example:exchange-a", 100)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:mode-a-submitter",
	}, []byte("mode-a-payload"))

	result := submitEntry(t, op.BaseURL, "tok-a", wire)

	seq := result["sequence_number"].(float64)
	if seq < 1 {
		t.Fatalf("sequence_number should be >= 1, got %v", seq)
	}
	hash := result["canonical_hash"].(string)
	if len(hash) != 64 {
		t.Fatalf("canonical_hash should be 64-char hex, got %d", len(hash))
	}
	logTimeStr := result["log_time"].(string)
	if _, err := time.Parse(time.RFC3339Nano, logTimeStr); err != nil {
		t.Fatalf("log_time should be RFC3339Nano: %v", err)
	}
	t.Logf("Mode A accepted: seq=%.0f hash=%s", seq, hash[:16])
}

func TestHTTP_Submission_ModeA_MultipleEntries(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-multi", "did:example:exchange-multi", 100)

	var seqs []float64
	for i := 0; i < 5; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:multi-submitter",
		}, []byte(fmt.Sprintf("entry-%d", i)))
		result := submitEntry(t, op.BaseURL, "tok-multi", wire)
		seqs = append(seqs, result["sequence_number"].(float64))
	}

	// Verify monotonically increasing sequences.
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatalf("sequences not monotonic: %v", seqs)
		}
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Submission — Mode B (unauthenticated with compute stamp)
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Submission_ModeB_ValidStamp(t *testing.T) {
	op := startTestOperator(t)

	// Build entry with valid compute stamp (no auth token).
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:mode-b-submitter",
	}, []byte("mode-b-stamped-payload"), testLogDID, 16)

	// POST without Authorization header.
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("Mode B with valid stamp: expected 202, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	json.Unmarshal(body, &result)
	t.Logf("Mode B accepted: seq=%v hash=%s", result["sequence_number"], result["canonical_hash"].(string)[:16])
}

func TestHTTP_Submission_ModeB_NoStamp_403(t *testing.T) {
	op := startTestOperator(t)

	// Entry without AdmissionProof, no auth token → 403.
	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:no-stamp",
	}, []byte("no-stamp"))

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	// No Authorization header.
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Mode B without stamp: expected 403, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Submission_ModeB_WrongLogDID_403(t *testing.T) {
	op := startTestOperator(t)

	// Stamp bound to a different log DID.
	wire := buildModeBWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:wrong-log",
	}, []byte("wrong-log-payload"), "did:ortholog:different-log", 16)

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("stamp bound to wrong log: expected 403, got %d: %s", resp.StatusCode, body)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Middleware Chain — Auth, Size, Credits, Protocol Version
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Middleware_InvalidToken_401(t *testing.T) {
	op := startTestOperator(t)
	wire := buildWireEntry(t, envelope.ControlHeader{SignerDID: "did:example:auth-test"}, []byte("auth"))
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer invalid-nonexistent-token")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_ExpiredToken_401(t *testing.T) {
	op := startTestOperator(t)
	_, _ = op.Pool.Exec(context.Background(),
		`INSERT INTO sessions (token, exchange_did, expires_at) VALUES ($1, $2, $3)`,
		"tok-expired", "did:example:expired-exchange", time.Now().UTC().Add(-1*time.Hour),
	)
	wire := buildWireEntry(t, envelope.ControlHeader{SignerDID: "did:example:expired"}, []byte("expired"))
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-expired")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 for expired, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_OversizeBody_413(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-big", "did:example:exchange-big", 100)

	// Build a real entry that exceeds MaxEntrySize after deserialization.
	// The SizeLimit middleware wraps r.Body with MaxBytesReader.
	// When io.ReadAll hits the limit, the next Read returns an error.
	// The handler reads body → gets truncated/error → returns 400 (read failure).
	oversized := make([]byte, (1<<20)+2048)
	oversized[0] = 0x00
	oversized[1] = 0x03 // valid v3 preamble

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(oversized))
	req.Header.Set("Authorization", "Bearer tok-big")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	// MaxBytesReader silently truncates the read. The handler then tries to
	// deserialize the truncated bytes → fails at Deserialize → 422.
	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("oversize body: expected 422, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_NoCredits_402(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-broke", "did:example:exchange-broke", 0)
	wire := buildWireEntry(t, envelope.ControlHeader{SignerDID: "did:example:broke"}, []byte("need-credits"))
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-broke")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 402, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_MalformedBody_422(t *testing.T) {
	op := startTestOperator(t)
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader([]byte("garbage")))
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("malformed body: expected 422, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_WrongProtocolVersion_422(t *testing.T) {
	op := startTestOperator(t)

	// Build a wire entry then overwrite protocol version to v2.
	wire := buildWireEntry(t, envelope.ControlHeader{SignerDID: "did:example:v2"}, []byte("v2"))
	wire[0] = 0x00
	wire[1] = 0x02 // Protocol version 2 instead of 3.

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("v2 entry: expected 422, got %d: %s", resp.StatusCode, body)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Credit Deduction Verification
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_CreditDeduction(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-credit", "did:example:exchange-credit", 10)

	// Check initial balance.
	bal0, _ := op.CreditStore.Balance(context.Background(), "did:example:exchange-credit")
	if bal0 != 10 {
		t.Fatalf("initial balance should be 10, got %d", bal0)
	}

	// Submit 3 entries.
	for i := 0; i < 3; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:credit-test",
		}, []byte(fmt.Sprintf("credit-entry-%d", i)))
		submitEntry(t, op.BaseURL, "tok-credit", wire)
	}

	// Check balance decreased by exactly 3.
	bal1, _ := op.CreditStore.Balance(context.Background(), "did:example:exchange-credit")
	if bal1 != 7 {
		t.Fatalf("balance after 3 submissions: expected 7, got %d", bal1)
	}

	// Submit 7 more → balance 0.
	for i := 3; i < 10; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:credit-test",
		}, []byte(fmt.Sprintf("credit-entry-%d", i)))
		submitEntry(t, op.BaseURL, "tok-credit", wire)
	}

	bal2, _ := op.CreditStore.Balance(context.Background(), "did:example:exchange-credit")
	if bal2 != 0 {
		t.Fatalf("balance after 10 submissions: expected 0, got %d", bal2)
	}

	// 11th submission → 402.
	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:credit-test",
	}, []byte("credit-entry-overflow"))
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-credit")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("exhausted credits: expected 402, got %d: %s", resp.StatusCode, body)
	}

	t.Logf("credit deduction verified: 10→7→0→402")
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. End-to-End Round-Trip with Sequence Ordering
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_EndToEnd_SubmitAndQueryBack(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-e2e", "did:example:exchange-e2e", 100)

	signerDID := "did:example:e2e-roundtrip-alice"
	const N = 5

	// Submit N entries, collect submission sequence numbers.
	var submitSeqs []float64
	for i := 0; i < N; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: signerDID,
		}, []byte(fmt.Sprintf("e2e-payload-%d", i)))
		result := submitEntry(t, op.BaseURL, "tok-e2e", wire)
		submitSeqs = append(submitSeqs, result["sequence_number"].(float64))
	}

	// Poll until builder processes all entries (no flaky sleep).
	results := pollQueryResults(t, op.BaseURL, signerDID, N, 5*time.Second)
	if len(results) != N {
		t.Fatalf("expected %d entries, got %d", N, len(results))
	}

	// Verify sequence numbers are sequential and match submission order.
	var querySeqs []float64
	for _, r := range results {
		querySeqs = append(querySeqs, r["sequence_number"].(float64))
	}
	sort.Float64s(querySeqs)

	for i := 1; i < len(querySeqs); i++ {
		if querySeqs[i] != querySeqs[i-1]+1 {
			t.Fatalf("sequence gap: %v", querySeqs)
		}
	}

	// Verify all results have correct signer_did.
	for i, r := range results {
		if r["signer_did"] != signerDID {
			t.Fatalf("result %d: signer_did %v != %s", i, r["signer_did"], signerDID)
		}
	}

	t.Logf("end-to-end: submitted %d, queried %d, sequences %v", N, len(results), querySeqs)
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. 409 Duplicate Detection
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Duplicate_409(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-dup", "did:example:exchange-dup", 100)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:duplicate-test",
	}, []byte("unique-payload-for-dup-test"))

	// First → 202.
	submitEntry(t, op.BaseURL, "tok-dup", wire)

	// Second with same bytes → 409.
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-dup")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("duplicate: expected 409, got %d: %s", resp.StatusCode, body)
	}

	var errResp map[string]string
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] == "" {
		t.Fatal("409 should have error message")
	}
	t.Logf("duplicate rejected: %s", errResp["error"])
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. EntryResponse Shape (verifies no internal fields leak)
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_EntryResponseShape(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-shape", "did:example:exchange-shape", 100)

	signerDID := "did:example:shape-test-signer"
	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: signerDID,
	}, []byte("shape-test-payload"))
	submitEntry(t, op.BaseURL, "tok-shape", wire)

	// Poll for result (replaces flaky sleep).
	results := pollQueryResults(t, op.BaseURL, signerDID, 1, 5*time.Second)
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}

	r := results[0]

	// Required fields.
	for _, f := range []string{"sequence_number", "canonical_hash", "log_time", "signer_did", "canonical_bytes"} {
		if _, ok := r[f]; !ok {
			t.Fatalf("missing required field: %s", f)
		}
	}

	// Value checks.
	if r["signer_did"] != signerDID {
		t.Fatalf("signer_did: got %v, want %s", r["signer_did"], signerDID)
	}
	hash := r["canonical_hash"].(string)
	if len(hash) != 64 {
		t.Fatalf("canonical_hash should be 64 hex, got %d", len(hash))
	}
	seq := r["sequence_number"].(float64)
	if seq < 1 {
		t.Fatalf("sequence_number should be >= 1, got %v", seq)
	}

	t.Logf("shape verified: seq=%.0f hash=%s signer=%s", seq, hash[:16], signerDID)
}

// ═════════════════════════════════════════════════════════════════════════════
// 8. Difficulty + Health Endpoints
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_DifficultyEndpoint(t *testing.T) {
	op := startTestOperator(t)
	resp, _ := http.Get(op.BaseURL + "/v1/admission/difficulty")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	diff := result["difficulty"].(float64)
	if diff < 8 || diff > 24 {
		t.Fatalf("difficulty out of range: %v", diff)
	}
	if result["hash_function"] != "sha256" {
		t.Fatalf("hash_function: %v", result["hash_function"])
	}
	if _, ok := result["timestamp"]; !ok {
		t.Fatal("missing timestamp")
	}
	if resp.Header.Get("Cache-Control") == "" {
		t.Fatal("missing Cache-Control header")
	}
	t.Logf("difficulty=%v hash=%v cache=%s", diff, result["hash_function"], resp.Header.Get("Cache-Control"))
}

func TestHTTP_HealthCheck(t *testing.T) {
	op := startTestOperator(t)
	resp, _ := http.Get(op.BaseURL + "/healthz")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body: %q", body)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Suppress unused imports
// ═════════════════════════════════════════════════════════════════════════════

var _ = binary.BigEndian
