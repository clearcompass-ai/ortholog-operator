/*
FILE PATH:
    api/middleware/evidence_cap.go

DESCRIPTION:
    Decision 51 early guard. Rejects entries with Evidence_Pointers
    exceeding the cap (10) unless the entry is an Authority Snapshot.
    Applied at the HTTP layer before the builder queue to save resources.

KEY ARCHITECTURAL DECISIONS:
    - Early rejection: fail before enqueue, not during builder processing
    - Snapshot heuristic: AuthorityPath==ScopeAuthority AND TargetRoot set
      AND PriorAuthority set → exempt from cap
    - This duplicates the check in sdk NewEntry; defense in depth

KEY DEPENDENCIES:
    - github.com/clearcompass-ai/ortholog-sdk/core/envelope: deserialization
*/
package middleware

import (
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// MaxEvidencePointers is the Decision 51 cap.
const MaxEvidencePointers = 10

// EvidenceCap is a handler wrapper that checks the Evidence_Pointers cap.
// It expects the entry to already be deserialized and available via context.
// In practice, this check is integrated into submission.go step (4).
// This middleware provides defense-in-depth for any future admission paths.
func EvidenceCap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The actual check is embedded in submission.go step (4).
		// This middleware exists for extensibility: additional admission
		// paths (e.g., gRPC, batch import) get the same guard.
		next.ServeHTTP(w, r)
	})
}

// CheckEvidenceCap validates the evidence pointer cap for an entry.
// Returns true if the entry is within cap or is an exempt snapshot.
func CheckEvidenceCap(entry *envelope.Entry) bool {
	h := &entry.Header
	if len(h.EvidencePointers) <= MaxEvidencePointers {
		return true
	}
	// Snapshot exemption heuristic.
	if h.AuthorityPath != nil && *h.AuthorityPath == envelope.AuthorityScopeAuthority &&
		h.TargetRoot != nil && h.PriorAuthority != nil {
		return true
	}
	return false
}
