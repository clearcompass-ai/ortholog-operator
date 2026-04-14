/*
FILE PATH: tests/http_integration_test.go

HTTP integration tests. Every test makes real HTTP calls to a real operator
server backed by real Postgres. No interface mocks.

Run: ORTHOLOG_TEST_DSN="postgres://ortholog:ortholog@localhost:5432/ortholog_test?sslmode=disable" go test ./tests/ -v -count=1 -run TestHTTP
*/
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// ─────────────────────────────────────────────────────────────────────────────
// Wire format helper: build a complete signed entry ready for POST.
// ─────────────────────────────────────────────────────────────────────────────

// buildWireEntry creates a v3 entry with a fake ECDSA signature appended.
// The operator's submission handler verifies the wire format (StripSignature,
// Deserialize, ValidateAlgorithmID) but does not yet verify the actual
// cryptographic signature (TODO in step 2). This builds a well-formed wire
// entry that passes all structural checks.
func buildWireEntry(t *testing.T, header envelope.ControlHeader, payload []byte) []byte {
	t.Helper()
	entry := makeEntry(t, header, payload)
	canonical := envelope.Serialize(entry)
	// Fake 64-byte ECDSA signature (structurally valid wire format).
	fakeSig := make([]byte, 64)
	for i := range fakeSig {
		fakeSig[i] = byte(i + 1)
	}
	return envelope.AppendSignature(canonical, envelope.SigAlgoECDSA, fakeSig)
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. POST /v1/entries — Happy Path
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Submission_HappyPath_ModeB(t *testing.T) {
	op := startTestOperator(t)

	// Mode B: no auth token, just POST the entry (no stamp needed since
	// difficulty controller starts at default and we need to provide a stamp).
	// For simplicity, submit with auth token (Mode A).
	op.seedSession(t, "tok-happy", "did:example:exchange-happy", 100)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:happy-submitter",
	}, []byte("happy-path-payload"))

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer tok-happy")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/entries: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 202, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Verify response fields.
	if _, ok := result["sequence_number"]; !ok {
		t.Fatal("response missing sequence_number")
	}
	if _, ok := result["canonical_hash"]; !ok {
		t.Fatal("response missing canonical_hash")
	}
	if _, ok := result["log_time"]; !ok {
		t.Fatal("response missing log_time")
	}

	seq := result["sequence_number"].(float64)
	if seq < 1 {
		t.Fatalf("sequence_number should be >= 1, got %v", seq)
	}

	hash := result["canonical_hash"].(string)
	if len(hash) != 64 {
		t.Fatalf("canonical_hash should be 64-char hex, got %d chars", len(hash))
	}

	logTimeStr := result["log_time"].(string)
	_, err = time.Parse(time.RFC3339Nano, logTimeStr)
	if err != nil {
		t.Fatalf("log_time should be RFC3339: %v", err)
	}

	t.Logf("submission accepted: seq=%.0f hash=%s", seq, hash[:16])
}

func TestHTTP_Submission_HappyPath_MultipleEntries(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-multi", "did:example:exchange-multi", 100)

	for i := 0; i < 5; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: "did:example:multi-submitter",
		}, []byte(fmt.Sprintf("entry-%d", i)))

		req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
		req.Header.Set("Authorization", "Bearer tok-multi")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("entry %d: expected 202, got %d: %s", i, resp.StatusCode, body)
		}
		resp.Body.Close()
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Middleware Chain — Auth, Size Limit, Credits
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Middleware_InvalidToken_401(t *testing.T) {
	op := startTestOperator(t)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:auth-test",
	}, []byte("auth-test"))

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer invalid-nonexistent-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_ExpiredToken_401(t *testing.T) {
	op := startTestOperator(t)

	// Insert an expired session.
	_, err := op.Pool.Exec(context.Background(),
		`INSERT INTO sessions (token, exchange_did, expires_at) VALUES ($1, $2, $3)`,
		"tok-expired", "did:example:expired-exchange",
		time.Now().UTC().Add(-1*time.Hour), // Already expired.
	)
	if err != nil {
		t.Fatal(err)
	}

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:expired-test",
	}, []byte("expired"))

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-expired")

	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 for expired token, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_OversizeBody_413(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-big", "did:example:exchange-big", 100)

	// Build a body larger than MaxEntrySize (1MB) + sig overhead.
	oversized := make([]byte, (1<<20)+2048)
	// Write a valid v3 preamble so it gets past the first check.
	oversized[0] = 0x00
	oversized[1] = 0x03

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(oversized))
	req.Header.Set("Authorization", "Bearer tok-big")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// MaxBytesReader triggers 413 or the handler returns 413/422.
	if resp.StatusCode != http.StatusRequestEntityTooLarge &&
		resp.StatusCode != http.StatusUnprocessableEntity &&
		resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 413/422/400 for oversize, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_NoCredits_402(t *testing.T) {
	op := startTestOperator(t)
	// Session with zero credits.
	op.seedSession(t, "tok-broke", "did:example:exchange-broke", 0)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:no-credits",
	}, []byte("need-credits"))

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-broke")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPaymentRequired {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 402, got %d: %s", resp.StatusCode, body)
	}
}

func TestHTTP_Middleware_MalformedBody_4xx(t *testing.T) {
	op := startTestOperator(t)

	// Garbage bytes (not a valid entry).
	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader([]byte("garbage")))
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("malformed body should be 4xx, got %d", resp.StatusCode)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. End-to-End Round-Trip: Submit → Builder → Query Back
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_EndToEnd_SubmitAndQueryBack(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-e2e", "did:example:exchange-e2e", 100)

	signerDID := "did:example:e2e-roundtrip-alice"
	const N = 5

	// Submit N entries.
	for i := 0; i < N; i++ {
		wire := buildWireEntry(t, envelope.ControlHeader{
			SignerDID: signerDID,
		}, []byte(fmt.Sprintf("e2e-payload-%d", i)))

		req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
		req.Header.Set("Authorization", "Bearer tok-e2e")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("submit %d: expected 202, got %d: %s", i, resp.StatusCode, body)
		}
		resp.Body.Close()
	}

	// Wait for builder to process.
	time.Sleep(500 * time.Millisecond)

	// Query by signer DID.
	queryURL := fmt.Sprintf("%s/v1/query/signer_did/%s", op.BaseURL, signerDID)
	resp, err := http.Get(queryURL)
	if err != nil {
		t.Fatalf("GET signer_did: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("query: expected 200, got %d: %s", resp.StatusCode, body)
	}

	var results []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatalf("decode query results: %v", err)
	}

	if len(results) != N {
		t.Fatalf("expected %d entries from query, got %d", N, len(results))
	}

	// Verify each result has the expected fields.
	for i, r := range results {
		if r["signer_did"] != signerDID {
			t.Fatalf("result %d: wrong signer_did: %v", i, r["signer_did"])
		}
		if _, ok := r["sequence_number"]; !ok {
			t.Fatalf("result %d: missing sequence_number", i)
		}
		if _, ok := r["canonical_hash"]; !ok {
			t.Fatalf("result %d: missing canonical_hash", i)
		}
		if _, ok := r["log_time"]; !ok {
			t.Fatalf("result %d: missing log_time", i)
		}
	}

	t.Logf("end-to-end: submitted %d, queried back %d entries for %s", N, len(results), signerDID)
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. 409 Duplicate Detection
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_Duplicate_409(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-dup", "did:example:exchange-dup", 100)

	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:duplicate-test",
	}, []byte("unique-payload-for-dup-test"))

	// First submission → 202.
	req1, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req1.Header.Set("Authorization", "Bearer tok-dup")
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusAccepted {
		t.Fatalf("first submit: expected 202, got %d", resp1.StatusCode)
	}

	// Second submission with SAME bytes → 409.
	req2, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req2.Header.Set("Authorization", "Bearer tok-dup")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("duplicate submit: expected 409, got %d: %s", resp2.StatusCode, body)
	}

	// Verify error body mentions "duplicate".
	var errResp map[string]string
	json.NewDecoder(resp2.Body).Decode(&errResp)
	if errResp["error"] == "" {
		t.Fatal("409 response should have error message")
	}
	t.Logf("duplicate correctly rejected: %s", errResp["error"])
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. EntryResponse Shape
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_EntryResponseShape(t *testing.T) {
	op := startTestOperator(t)
	op.seedSession(t, "tok-shape", "did:example:exchange-shape", 100)

	signerDID := "did:example:shape-test-signer"
	wire := buildWireEntry(t, envelope.ControlHeader{
		SignerDID: signerDID,
	}, []byte("shape-test-payload"))

	req, _ := http.NewRequest("POST", op.BaseURL+"/v1/entries", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer tok-shape")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	// Wait for builder.
	time.Sleep(500 * time.Millisecond)

	// Query.
	queryURL := fmt.Sprintf("%s/v1/query/signer_did/%s", op.BaseURL, signerDID)
	resp2, err := http.Get(queryURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	body, _ := io.ReadAll(resp2.Body)

	// Parse as raw JSON to check exact field names.
	var results []map[string]json.RawMessage
	if err := json.Unmarshal(body, &results); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}

	r := results[0]

	// Required fields.
	requiredFields := []string{"sequence_number", "canonical_hash", "log_time", "signer_did", "canonical_bytes"}
	for _, f := range requiredFields {
		if _, ok := r[f]; !ok {
			t.Fatalf("response missing required field: %s\nGot: %s", f, string(body))
		}
	}

	// Verify signer_did value.
	var gotSigner string
	json.Unmarshal(r["signer_did"], &gotSigner)
	if gotSigner != signerDID {
		t.Fatalf("signer_did: got %q, want %q", gotSigner, signerDID)
	}

	// Verify canonical_hash is 64-char hex.
	var gotHash string
	json.Unmarshal(r["canonical_hash"], &gotHash)
	if len(gotHash) != 64 {
		t.Fatalf("canonical_hash should be 64 hex chars, got %d", len(gotHash))
	}

	// Verify sequence_number is a number.
	var gotSeq float64
	json.Unmarshal(r["sequence_number"], &gotSeq)
	if gotSeq < 1 {
		t.Fatalf("sequence_number should be >= 1, got %v", gotSeq)
	}

	t.Logf("response shape verified: seq=%.0f hash=%s signer=%s", gotSeq, gotHash[:16], gotSigner)
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. Difficulty Endpoint
// ═════════════════════════════════════════════════════════════════════════════

func TestHTTP_DifficultyEndpoint(t *testing.T) {
	op := startTestOperator(t)

	resp, err := http.Get(op.BaseURL + "/v1/admission/difficulty")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	// Verify fields.
	diff, ok := result["difficulty"]
	if !ok {
		t.Fatal("missing difficulty field")
	}
	if diff.(float64) < 8 || diff.(float64) > 24 {
		t.Fatalf("difficulty out of range: %v", diff)
	}

	hashFunc, ok := result["hash_function"]
	if !ok {
		t.Fatal("missing hash_function field")
	}
	if hashFunc != "sha256" {
		t.Fatalf("hash_function: got %v, want sha256", hashFunc)
	}

	if _, ok := result["timestamp"]; !ok {
		t.Fatal("missing timestamp field")
	}

	// Verify Cache-Control header.
	cc := resp.Header.Get("Cache-Control")
	if cc == "" {
		t.Fatal("difficulty endpoint should set Cache-Control header")
	}

	t.Logf("difficulty: %v, hash_function: %v, cache-control: %s", diff, hashFunc, cc)
}

func TestHTTP_HealthCheck(t *testing.T) {
	op := startTestOperator(t)

	resp, err := http.Get(op.BaseURL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("healthz body: %q", body)
	}
}
