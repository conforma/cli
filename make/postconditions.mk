# =========================
# Post-Conditions Makefile (Go)
# Tools are pinned in tools/go.mod (no @versions here)
# =========================

MAKEFLAGS += --no-print-directory
SHELL := bash

GOFLAGS ?=
TEST_PKGS ?= ./...
COVER_OUT ?= coverage.out
COVER_FLOOR ?= 80
GOCYCLO_MAX ?= 12         # cyclomatic complexity budget for gocyclo
COGNIT_MAX  ?= 20         # cognitive complexity budget for gocognit

# Run tools through the tools module (do NOT cd tools/)
GO_RUN_TOOLS = go run -modfile tools/go.mod
GOLANGCI := $(GO_RUN_TOOLS) github.com/golangci/golangci-lint/cmd/golangci-lint

# Source lists for tools that need explicit files (not ./...)
GO_SOURCES := $(shell git ls-files '*.go' ':!:**/*.pb.go')
# If your repo includes generated dirs, exclude them above (add more :!: patterns as needed)

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

# --- Static analysis and security (single-tool runners) ---
.PHONY: vet
vet: ## go vet
	@go vet $(GOFLAGS) $(TEST_PKGS)

.PHONY: staticcheck
staticcheck: ## staticcheck (expanded analyzer)
	@$(GO_RUN_TOOLS) honnef.co/go/tools/cmd/staticcheck $(TEST_PKGS)

.PHONY: revive
revive: ## revive (style linter)
	@$(GO_RUN_TOOLS) github.com/mgechev/revive $(TEST_PKGS)

.PHONY: gosimple
gosimple: ## gosimple (simplification suggestions)
	@$(GO_RUN_TOOLS) honnef.co/go/tools/cmd/gosimple $(TEST_PKGS)

.PHONY: errcheck
errcheck: ## errcheck (error handling)
	@$(GO_RUN_TOOLS) github.com/kisielk/errcheck $(TEST_PKGS)

.PHONY: vuln
vuln: ## govulncheck (module + packages)
	@$(GO_RUN_TOOLS) golang.org/x/vuln/cmd/govulncheck $(TEST_PKGS)

# --- Extra "Go patterns" linters (standalone CLIs) ---------------------------
# NOTE: These are optional deeper checks. Many overlap with golangci-lint linters used in sanity.
# We keep them separate so day-to-day iteration stays fast; run them in pre-PR or locally as needed.

.PHONY: gocyclo
gocyclo: ## gocyclo (cyclomatic complexity) - fails if > GOCYCLO_MAX
	@$(GO_RUN_TOOLS) github.com/fzipp/gocyclo/cmd/gocyclo -over $(GOCYCLO_MAX) $(GO_SOURCES)

.PHONY: nestif
nestif: ## nestif (nested if statements)
	@$(GO_RUN_TOOLS) github.com/nakabonne/nestif/cmd/nestif .

.PHONY: dupl
dupl: ## dupl (duplicate code detection)
	@$(GO_RUN_TOOLS) github.com/mibk/dupl .

.PHONY: goconst
goconst: ## goconst (repeated string/number literals) - using golangci-lint
	@$(GO_RUN_TOOLS) github.com/golangci/golangci-lint/cmd/golangci-lint run --disable-all --enable=goconst ./...

.PHONY: misspell
misspell: ## misspell (spelling checker; errors only)
	@$(GO_RUN_TOOLS) github.com/client9/misspell/cmd/misspell -error -locale US $(GO_SOURCES)

.PHONY: unparam
unparam: ## unparam (unused parameters)
	@$(GO_RUN_TOOLS) mvdan.cc/unparam $(TEST_PKGS)

.PHONY: ineffassign
ineffassign: ## ineffassign (ineffective assignments)
	@$(GO_RUN_TOOLS) github.com/gordonklaus/ineffassign .

.PHONY: gosec
gosec: ## gosec (security issues)
	@$(GO_RUN_TOOLS) github.com/securecodewarrior/gosec/v2/cmd/gosec ./...

.PHONY: gocritic
gocritic: ## gocritic (style and performance issues)
	@$(GO_RUN_TOOLS) github.com/go-critic/go-critic/cmd/gocritic check ./...

.PHONY: gocognit
gocognit: ## gocognit (cognitive complexity) - fails if > COGNIT_MAX
	@$(GO_RUN_TOOLS) github.com/uudashr/gocognit/cmd/gocognit -over $(COGNIT_MAX) $(GO_SOURCES)

.PHONY: funlen
funlen: ## funlen (function length)
	@$(GO_RUN_TOOLS) github.com/ultraware/funlen/cmd/funlen ./...

.PHONY: gofumpt
gofumpt: ## gofumpt (stricter gofmt; non-mutating)
	@$(GO_RUN_TOOLS) mvdan.cc/gofumpt -l $(GO_SOURCES)

# --- Lint (keeps using .golangci.yml exactly as-is) --------------------------
.PHONY: lint
lint: ## Full golangci-lint run (uses .golangci.yml)
	@$(GOLANGCI) run --sort-results $(if $(CI),--timeout=10m)

# --------- Sanity: checks & reports (isolated from .golangci.yml) ------------

# Public knobs:
#   FILES=""                     # optional: files/dirs to scope the run
#   SANITY_JSON=.sanity.json     # where JSON lands for report-sanity
#   SANITY_BUILD_TAGS=...        # build tags for sanity runs
#   SANITY_NO_CONFIG=1           # 1 = ignore .golangci.yml (default), 0 = use it
SANITY_JSON ?= .sanity.json
SANITY_BUILD_TAGS ?= acceptance,generative,integration,unit
SANITY_NO_CONFIG ?= 1

SANITY_LINTERS = -E dupl -E gocyclo -E goconst -E unparam -E ineffassign -E nestif
SANITY_BASE    = --max-issues-per-linter=0 --max-same-issues=0 --sort-results --timeout=5m --build-tags=$(SANITY_BUILD_TAGS)
SANITY_CFG_FLAGS =
ifeq ($(SANITY_NO_CONFIG),1)
  SANITY_CFG_FLAGS = --no-config --disable-all
endif

# 1) CHECK: human-friendly output, fails on issues.
.PHONY: check-sanity
check-sanity: ## Run sanity checks (FILES=... optional). Ignores .golangci.yml by default.
	@$(GOLANGCI) run $(SANITY_CFG_FLAGS) $(SANITY_LINTERS) $(SANITY_BASE) --issues-exit-code=1 \
	  --out-format=colored-line-number $(if $(FILES),$(FILES),)
	@echo "Target complexity budget (gocyclo): $(GOCYCLO_MAX)"

# 2) REPORT: summarized output, never fails; uses JSON internally.
.PHONY: report-sanity
report-sanity: ## Summarize sanity issues (FILES=... optional). Ignores .golangci.yml by default.
	@$(GOLANGCI) run $(SANITY_CFG_FLAGS) $(SANITY_LINTERS) $(SANITY_BASE) --issues-exit-code=0 \
	  --out-format json $(if $(FILES),$(FILES),) > $(SANITY_JSON)
	@command -v jq >/dev/null || { echo "jq is required for report-sanity"; exit 1; }
	@echo "== Issues by linter =="; \
	jq -r '.Issues | group_by(.FromLinter) | map({linter: .[0].FromLinter, count: length}) | sort_by(-.count) | (["linter","count"], (.[] | [ .linter, (.count|tostring) ])) | @tsv' $(SANITY_JSON) | column -t
	@echo; echo "== Top files by issue count (top 10) =="; \
	jq -r '.Issues | group_by(.Pos.Filename) | map({file: .[0].Pos.Filename, count: length}) | sort_by(-.count)[0:10] | (["file","count"], (.[] | [ .file, (.count|tostring) ])) | @tsv' $(SANITY_JSON) | column -t
	@echo; echo "== Worst cyclomatic complexity (top 10) =="; \
	jq -r '.Issues | map(select(.FromLinter=="gocyclo")) | map({file: .Pos.Filename, line: .Pos.Line, text: .Text, n: ( .Text | capture("(?<n>[0-9]+)"; "m")? | .n // "0") | tonumber}) | sort_by(-.n)[0:10] | (["complexity","file:line","message"], (.[] | [ ( .n|tostring ), ( .file + ":" + (.line|tostring) ), .text ])) | @tsv' $(SANITY_JSON) | column -t
	@echo; echo "== Duplicate code (dupl) hot-spots (top 10) =="; \
	jq -r '.Issues | map(select(.FromLinter=="dupl")) | group_by(.Pos.Filename) | map({file: .[0].Pos.Filename, count: length}) | sort_by(-.count)[0:10] | (["file","dupl_issues"], (.[] | [ .file, (.count|tostring) ])) | @tsv' $(SANITY_JSON) | column -t

# Compatibility aliases (old names keep working)
.PHONY: sanity sanity-file sanity-json sanity-file-json sanity-summary sanity-file-summary
sanity:
	@echo "[alias] sanity → check-sanity"; \
	$(MAKE) check-sanity FILES="$(FILES)"
sanity-file:
	@echo "[alias] sanity-file → check-sanity (FILES=...)"; \
	$(MAKE) check-sanity FILES="$(FILES)"
sanity-json:
	@echo "[alias] sanity-json → report-sanity (JSON saved to $(SANITY_JSON))"; \
	$(MAKE) report-sanity FILES="$(FILES)"
sanity-file-json:
	@echo "[alias] sanity-file-json → report-sanity (FILES=...)"; \
	$(MAKE) report-sanity FILES="$(FILES)"
sanity-summary:
	@echo "[alias] sanity-summary → report-sanity"; \
	$(MAKE) report-sanity FILES="$(FILES)"
sanity-file-summary:
	@echo "[alias] sanity-file-summary → report-sanity (FILES=...)"; \
	$(MAKE) report-sanity FILES="$(FILES)"

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

# --- find-func-refs (repo-wide) ---
FFR ?= $(HOME)/go/bin/find-func-refs

.PHONY: ffr
ffr: ## Repo-wide unused function scan (via find-func-refs -all)
	@test -x "$(FFR)" || { echo "find-func-refs not found at $(FFR)"; exit 1; }
	@echo "Checking unused funcs (repo-wide)"
	@$(FFR) -all -root . -snippet || true

# --- Aggregate "Go patterns" suite -------------------------------------------
.PHONY: go-patterns-lint
go-patterns-lint: ## Extra Go pattern checks (run locally / pre-PR; slower than sanity)
go-patterns-lint: revive gocyclo nestif dupl goconst misspell unparam ineffassign gosec gocritic gocognit funlen gofumpt

# --- Stage bundles -----------------------------------------------------------
.PHONY: quick
quick: fmt check-sanity ## Small/local changes: fast guard

.PHONY: refactor
refactor: fmt check-sanity ffr ## Structural changes: add unused scan

.PHONY: behavior
behavior: fmt check-sanity analysis test cover-check ## Behavior change: full quality + tests + coverage

.PHONY: prepr
prepr: analysis test cover-check report-sanity go-patterns-lint ## Pre-PR stabilization (adds deeper Go patterns)

# --- CI / default ------------------------------------------------------------
.PHONY: analysis
analysis: fmt vet staticcheck revive gosimple errcheck vuln check-sanity ## Non-mutating quality gates

.PHONY: ci
ci: test analysis cover-check ## Full CI suite (non-mutating)

# --- Optional perf smoke (won't fail CI) ---
.PHONY: bench-smoke
bench-smoke: ## Run quick benchmarks (ignored failures)
	@go test $(GOFLAGS) -run=^$$ -bench=. -benchmem ./... || true

.DEFAULT_GOAL := ci
