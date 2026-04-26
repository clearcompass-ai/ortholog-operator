# Ortholog Operator — make targets
#
# Wave 1 v3 §CI1 introduces the audit-v775 target. Other targets
# below are conventional helpers for build / test / lint cadence.
#
# All targets use POSIX sh and are intended to run in CI without
# relying on developer tooling. The audit target works whether the
# SDK is vendored (vendor/github.com/clearcompass-ai/ortholog-sdk/)
# or resolved from the Go module cache (go env GOMODCACHE).

GO          ?= go
SDK_MODULE  := github.com/clearcompass-ai/ortholog-sdk

.PHONY: build test test-short audit-v775 vet tidy clean help

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Compile every package
	$(GO) build ./...

test: ## Run all tests (integration tests skip without ORTHOLOG_TEST_DSN)
	$(GO) test ./...

test-short: ## Run only unit tests (skip integration via -short)
	$(GO) test -short ./...

vet: ## go vet across all packages
	$(GO) vet ./...

tidy: ## go mod tidy + verify
	$(GO) mod tidy
	$(GO) mod verify

clean: ## Remove build artifacts
	rm -rf ./bin ./coverage.out

# ─────────────────────────────────────────────────────────────────────
# Wave 1 v3 §CI1 — SDK mutation-gate audit
# ─────────────────────────────────────────────────────────────────────

# audit-v775 ensures NO muEnable* gate has been flipped to false in
# the SDK that this operator depends on. The discipline lives at
# ADR-005 §6: every muEnable constant is a load-bearing security
# gate, and any value other than `true` in committed code is a
# regression.
#
# Resolution order:
#   1. If ./vendor/<sdk> exists, scan there (operator is vendoring).
#   2. Otherwise, ask `go list -m` for the module cache directory
#      and scan there (default Go module mode).
#
# Either path produces an absolute directory we can grep. A non-zero
# exit status on `grep` means matches were found, which is the
# failure condition we want to surface to CI.
audit-v775: ## Wave 1 §CI1 — fail if SDK ships any muEnable*=false
	@set -e; \
	VENDOR_DIR="vendor/$(SDK_MODULE)"; \
	if [ -d "$$VENDOR_DIR" ]; then \
		SDK_PATH="$$VENDOR_DIR"; \
	else \
		SDK_PATH=$$($(GO) list -m -f '{{.Dir}}' $(SDK_MODULE)); \
	fi; \
	if [ -z "$$SDK_PATH" ] || [ ! -d "$$SDK_PATH" ]; then \
		echo "audit-v775: cannot locate SDK source at $$SDK_PATH"; \
		exit 2; \
	fi; \
	echo "audit-v775: scanning $$SDK_PATH"; \
	if grep -rn 'muEnable.*=\s*false' --include='*.go' "$$SDK_PATH"; then \
		echo ""; \
		echo "FAIL: SDK ships disabled mutation gates (above)."; \
		echo "Every muEnable* constant must be true in committed code."; \
		echo "See ADR-005 §6 for the mutation-audit discipline."; \
		exit 1; \
	fi; \
	echo "audit-v775: PASS — no disabled mutation gates"
