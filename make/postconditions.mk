# =========================
# Post-Conditions Makefile (Go)
# Uses tools pinned in tools/go.mod (no @version here)
# =========================

MAKEFLAGS += --no-print-directory
SHELL := bash

GOFLAGS ?=
TEST_PKGS ?= ./...
COVER_OUT ?= coverage.out
COVER_FLOOR ?= 80
GOCYCLO_MAX ?= 12

# Run tools through the tools module
GO_RUN_TOOLS = GOMOD=$(CURDIR)/tools/go.mod go run

# In CI, disallow go.mod/go.sum edits during steps
ifdef CI
GOFLAGS += -mod=readonly
endif

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN{FS=":.*##";print "\nTargets:"} /^[a-zA-Z0-9_.-]+:.*?##/ {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# --- Formatting (non-mutating) ---
.PHONY: fmt
fmt: ## Verify gofmt -s (non-mutating)
	@changed="$$(gofmt -s -l .)"; \
	if [ -n "$$changed" ]; then \
	  echo "Files need formatting:"; echo "$$changed" | sed 's/^/  /'; \
	  echo "Run: make fmt-fix"; exit 1; \
	fi

.PHONY: fmt-fix
fmt-fix: ## Apply gofmt -s (local use)
	@gofmt -s -w .

# --- Static analysis and security ---
.PHONY: vet
vet: ## go vet
	@go vet $(GOFLAGS) $(TEST_PKGS)

.PHONY: staticcheck
staticcheck: ## staticcheck (expanded analyzer)
	@$(GO_RUN_TOOLS) honnef.co/go/tools/cmd/staticcheck $(TEST_PKGS)

.PHONY: vuln
vuln: ## govulncheck (module + packages)
	@$(GO_RUN_TOOLS) golang.org/x/vuln/cmd/govulncheck@v1.1.3 $(TEST_PKGS)

# --- Lint (with duplicate/complexity/unused gates) ---
GOLANGCI := $(GO_RUN_TOOLS) github.com/golangci/golangci-lint/cmd/golangci-lint@v1.63.4

.PHONY: lint
lint: ## Full golangci-lint run (uses .golangci.yml if present)
	@$(GOLANGCI) run --sort-results $(if $(CI),--timeout=10m)

.PHONY: sanity
sanity: ## Quick gates: duplicates, complexity, unused, constants
	@$(GOLANGCI) run \
	  -E dupl -E gocyclo -E goconst -E unparam -E ineffassign -E nestif \
	  --max-issues-per-linter=0 --max-same-issues=0 \
	  --issues-exit-code=1 \
	  --sort-results \
	  --out-format=colored-line-number \
	  --timeout=5m
	@echo "Reminder: enforce gocyclo min-complexity in .golangci.yml (target $(GOCYCLO_MAX))"

.PHONY: sanity-file
sanity-file: ## Quick gates for specific files (usage: make sanity-file FILES="./cmd/validate/image.go ./internal/validate/vsa/")
	@test -n "$(FILES)" || { echo "Usage: make sanity-file FILES='./path/to/file.go ./path/to/package/'"; exit 1; }
	@$(GOLANGCI) run \
	  -E dupl -E gocyclo -E goconst -E unparam -E ineffassign -E nestif \
	  --max-issues-per-linter=0 --max-same-issues=0 \
	  --issues-exit-code=1 \
	  --sort-results \
	  --out-format=colored-line-number \
	  --timeout=5m \
	  $(FILES)
	@echo "Reminder: enforce gocyclo min-complexity in .golangci.yml (target $(GOCYCLO_MAX))"

.PHONY: deep-sanity
deep-sanity: staticcheck lint ## staticcheck + full golangci run

# --- Tests & Coverage ---
.PHONY: test
test: ## Run tests with race + coverage
	@go test $(GOFLAGS) -race -covermode=atomic -coverprofile=$(COVER_OUT) $(TEST_PKGS)

.PHONY: cover-merge
cover-merge: ## Merge coverage-*.out -> $(COVER_OUT)
	@set -euo pipefail; \
	files=($$(ls -1 coverage-*.out 2>/dev/null || true)); \
	if [ $${#files[@]} -eq 0 ]; then \
	  echo "No coverage-*.out files found; keeping $(COVER_OUT)"; \
	else \
	  echo "Merging: $${files[*]}"; \
	  $(GO_RUN_TOOLS) github.com/wadey/gocovmerge $${files[*]} > $(COVER_OUT); \
	fi

.PHONY: cover-check
cover-check: ## Enforce total coverage floor ($(COVER_FLOOR)%)
	@set -euo pipefail; \
	test -f "$(COVER_OUT)" || { echo "Missing $(COVER_OUT) — run 'make test' first"; exit 1; }; \
	pct=$$(go tool cover -func=$(COVER_OUT) | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
	echo "Total coverage: $$pct% (floor $(COVER_FLOOR)%)"; \
	awk -v p="$$pct" -v f="$(COVER_FLOOR)" 'BEGIN{exit (p+0 >= f+0)?0:1}'

# --- Public API compatibility (optional but recommended for libraries) ---
# apidiff target removed due to dependency issues

# --- Convenience bundles ---
.PHONY: analysis
analysis: fmt vet staticcheck vuln sanity ## Non-mutating quality gates

.PHONY: ci
ci: test analysis cover-check ## Full CI suite (non-mutating)

# --- Optional perf smoke (won't fail CI, adjust package path as needed) ---
.PHONY: bench-smoke
bench-smoke: ## Run quick benchmarks (ignored failures)
	@go test $(GOFLAGS) -run=^$$ -bench=. -benchmem ./... || true

# --- Default goal ---
.DEFAULT_GOAL := ci

# --- Sanity summary (JSON + jq) ---------------------------------------------

SANITY_JSON ?= .sanity.json

.PHONY: sanity-json
sanity-json: ## Run sanity linters and write JSON to $(SANITY_JSON)
	@$(GOLANGCI) run \
	  -E dupl -E gocyclo -E goconst -E unparam -E ineffassign -E nestif \
	  --out-format json \
	  --max-issues-per-linter=0 --max-same-issues=0 \
	  --issues-exit-code=0 \
	  > $(SANITY_JSON)
	@echo "Wrote $(SANITY_JSON)"

.PHONY: sanity-file-json
sanity-file-json: ## Run sanity linters on specific files and write JSON to $(SANITY_JSON) (usage: make sanity-file-json FILES="./cmd/validate/image.go")
	@test -n "$(FILES)" || { echo "Usage: make sanity-file-json FILES='./path/to/file.go ./path/to/package/'"; exit 1; }
	@$(GOLANGCI) run \
	  -E dupl -E gocyclo -E goconst -E unparam -E ineffassign -E nestif \
	  --out-format json \
	  --max-issues-per-linter=0 --max-same-issues=0 \
	  --issues-exit-code=0 \
	  $(FILES) > $(SANITY_JSON)
	@echo "Wrote $(SANITY_JSON)"

.PHONY: sanity-summary
sanity-summary: sanity-json ## Summarize sanity issues (grouped & worst offenders)
	@command -v jq >/dev/null || { echo "jq is required"; exit 1; }
	@echo "== Issues by linter =="; \
	jq -r '.Issues | group_by(.FromLinter) | map({linter: .[0].FromLinter, count: length}) | sort_by(-.count) | (["linter","count"], (.[] | [ .linter, (.count|tostring) ]) ) | @tsv' $(SANITY_JSON) | column -t
	@echo; echo "== Top files by issue count (top 10) =="; \
	jq -r '.Issues | group_by(.Pos.Filename) | map({file: .[0].Pos.Filename, count: length}) | sort_by(-.count)[0:10] | (["file","count"], (.[] | [ .file, (.count|tostring) ])) | @tsv' $(SANITY_JSON) | column -t
	@echo; echo "== Worst cyclomatic complexity (top 10) =="; \
	jq -r '.Issues | map(select(.FromLinter=="gocyclo")) | map({file: .Pos.Filename, line: .Pos.Line, text: .Text, n: ( .Text | capture("(?<n>[0-9]+)"; "m")? | .n // "0") | tonumber}) | sort_by(-.n)[0:10] | (["complexity","file:line","message"], (.[] | [ ( .n|tostring ), ( .file + ":" + (.line|tostring) ), .text ])) | @tsv' $(SANITY_JSON) | column -t
	@echo; echo "== Duplicate code (dupl) hot-spots (top 10) =="; \
	jq -r '.Issues | map(select(.FromLinter=="dupl")) | group_by(.Pos.Filename) | map({file: .[0].Pos.Filename, count: length}) | sort_by(-.count)[0:10] | (["file","dupl_issues"], (.[] | [ .file, (.count|tostring) ])) | @tsv' $(SANITY_JSON) | column -t

.PHONY: sanity-file-summary
sanity-file-summary: sanity-file-json ## Summarize sanity issues for specific files (usage: make sanity-file-summary FILES="./cmd/validate/image.go")
	@command -v jq >/dev/null || { echo "jq is required"; exit 1; }
	@echo "== Issues by linter =="; \
	jq -r '.Issues | group_by(.FromLinter) | map({linter: .[0].FromLinter, count: length}) | sort_by(-.count) | (["linter","count"], (.[] | [ .linter, (.count|tostring) ]) ) | @tsv' $(SANITY_JSON) | column -t
	@echo; echo "== Top files by issue count (top 10) =="; \
	jq -r '.Issues | group_by(.Pos.Filename) | map({file: .[0].Pos.Filename, count: length}) | sort_by(-.count)[0:10] | (["file","count"], (.[] | [ .file, (.count|tostring) ])) | @tsv' $(SANITY_JSON) | column -t
	@echo; echo "== Worst cyclomatic complexity (top 10) =="; \
	jq -r '.Issues | map(select(.FromLinter=="gocyclo")) | map({file: .Pos.Filename, line: .Pos.Line, text: .Text, n: ( .Text | capture("(?<n>[0-9]+)"; "m")? | .n // "0") | tonumber}) | sort_by(-.n)[0:10] | (["complexity","file:line","message"], (.[] | [ ( .n|tostring ), ( .file + ":" + (.line|tostring) ), .text ])) | @tsv' $(SANITY_JSON) | column -t
	@echo; echo "== Duplicate code (dupl) hot-spots (top 10) =="; \
	jq -r '.Issues | map(select(.FromLinter=="dupl")) | group_by(.Pos.Filename) | map({file: .[0].Pos.Filename, count: length}) | sort_by(-.count)[0:10] | (["file","dupl_issues"], (.[] | [ .file, (.count|tostring) ])) | @tsv' $(SANITY_JSON) | column -t

# Path to your installed CLI
FFR ?= $(HOME)/go/bin/find-func-refs

.PHONY: ffr
ffr:
	@test -x "$(FFR)" || { echo "find-func-refs not found at $(FFR)"; exit 1; }
	@test -n "$(FILE)" || { echo "Usage: make ffr FILE=./path/to/file.go"; exit 1; }
	@echo "Checking unused funcs in $(FILE)"
	@$(FFR) -file "$(FILE)" -root . -snippet

# Use the current makefile for recursive calls
THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

.PHONY: sanity-plus
sanity-plus: ## Run sanity checks + unused function scan
	@$(MAKE) -f $(THIS_MAKEFILE) sanity
	@$(MAKE) -f $(THIS_MAKEFILE) ffr FILE="$(FILE)"
