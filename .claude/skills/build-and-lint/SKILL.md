---
name: build-and-lint
description: >
  Build and lint the Conforma CLI. Use when users ask "how to build", "make build",
  "lint errors", "lint fix", "golangci-lint", "make generate", "generated files",
  "go mod tidy", or need help with the build process and code quality checks.
---

# Build and Lint the Conforma CLI

Run build, lint, and code generation steps, then report results.

## Step 1: Build the binary

```bash
make build
```

This produces `dist/ec_<os>_<arch>` for the current platform. Verify the binary exists:

```bash
ls -la dist/ec_*
```

For a debug build with debugger symbols:

```bash
DEBUG_BUILD=1 make build
```

## Step 2: Run code generation

```bash
make generate
git diff --exit-code
```

If there are changes, stage and commit them. CI will fail if generated code is out of sync.

## Step 3: Run lint

```bash
make lint
```

Zero warnings are enforced. If lint fails, try auto-fix:

```bash
make lint-fix
```

Report what was auto-fixed vs what needs manual attention.

To lint a specific package:

```bash
go run -modfile tools/go.mod github.com/golangci/golangci-lint/v2/cmd/golangci-lint run ./internal/evaluator/...
```

## Step 4: Check module tidiness

Identify which modules have changes:

```bash
git diff --name-only origin/main...HEAD | grep -E '^(acceptance/|tools/)' || echo "root module only"
```

Run `go mod tidy` in each affected module:

```bash
# Root module
go mod tidy && git diff --exit-code go.mod go.sum

# If acceptance/ files changed
(cd acceptance && go mod tidy && git diff --exit-code go.mod go.sum)

# If tools/ files changed
(cd tools && go mod tidy && git diff --exit-code go.mod go.sum)

# If tools/kubectl/ files changed
(cd tools/kubectl && go mod tidy && git diff --exit-code go.mod go.sum)
```

## Step 5: Report

Summarize:

| Check | Status | Notes |
|-------|--------|-------|
| Build | pass/fail | |
| Generated code | pass/fail | |
| Lint | pass/fail | |
| Module tidiness | pass/fail | |

List any items that need attention.
