---
name: run-tests
description: >
  Run Conforma CLI tests. Use when users ask "how to run tests", "run unit tests",
  "run acceptance tests", "make test", "test tags", "test timeout", "run a single
  test", or need help with test execution and environment setup.
---

# Run Conforma CLI Tests

Determine which tests to run, execute them, and report results.

## Step 1: Determine test scope

Check what files changed to decide which tests are needed:

```bash
git diff --name-only origin/main...HEAD
```

- Changes in `internal/`, `cmd/`, `pkg/` → run unit + integration tests
- Changes in `features/`, `acceptance/` → run acceptance tests
- Changes in `tools/` → run `make tools-ci`

## Step 2: Run unit and integration tests

```bash
make test
```

This runs unit (10s timeout), integration (15s), and generative (30s) tests. If a specific test is needed:

```bash
go test -tags=unit ./internal/evaluator -run TestName
```

Report any failures with the test name and error message.

## Step 3: Run acceptance tests (if needed)

Full suite (~20 min):

```bash
make acceptance
```

Single feature or scenario:

```bash
make feature_validate_image
make scenario_inline_policy
```

Focused tests (tag scenarios with `@focus`):

```bash
make focus-acceptance
```

## Step 4: Debug acceptance test options

These require `go test` directly, not `make`:

```bash
# Keep test containers running after failure
(cd acceptance && go test . -args -persist)

# Reattach to persisted containers
(cd acceptance && go test . -args -restore)

# Run with specific tags
(cd acceptance && go test . -args -tags=@focus)

# Update snapshot files
UPDATE_SNAPS=true make acceptance
```

## Step 5: Verify macOS setup (if acceptance tests fail on macOS)

```bash
./hack/macos/setup-podman-machine.sh
```

Check `/etc/hosts` has required entries:

```text
127.0.0.1 apiserver.localhost
127.0.0.1 rekor.localhost
```

## Step 6: Report results

Summarize:
- Which test suites ran and their pass/fail status
- Any failing test names with error messages
- Whether snapshot updates are needed
- Environment issues encountered (Podman, DNS, etc.)
