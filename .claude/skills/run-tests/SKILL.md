---
name: run-tests
description: >
  Run Conforma CLI tests. Use when users ask "how to run tests", "run unit tests",
  "run acceptance tests", "make test", "test tags", "test timeout", "run a single
  test", "ginkgo", or need help with test execution and environment setup.
---

# Run Conforma CLI Tests

## Quick Start

```bash
make test          # unit + integration + generative tests
make acceptance    # all acceptance tests (Cucumber/Gherkin, ~20min)
make ci            # full CI: test + lint-fix + acceptance + tools-ci
```

## Test Tags and Timeouts

| Tag | Timeout | What it covers |
|-----|---------|----------------|
| `unit` | 10s | Isolated function tests, mocked dependencies |
| `integration` | 15s | Tests with real OPA engine |
| `generative` | 30s | Property-based/fuzz tests |
| `acceptance` | 20m | End-to-end Cucumber scenarios with Testcontainers |

## Running Specific Tests

```bash
# Single test by name
go test -tags=unit ./internal/evaluator -run TestName

# Single acceptance feature
make feature_validate_image

# Single acceptance scenario (replace spaces with underscores)
make scenario_inline_policy

# Focused acceptance tests (tag scenarios with @focus)
make focus-acceptance
```

## Acceptance Test Options

Note: `-persist`/`-restore` require `go test` directly (not `make`), and use `./acceptance` not `./...`:

```bash
# Keep test containers running after failure for debugging
cd acceptance && go test ./acceptance -args -persist

# Reattach to persisted containers
cd acceptance && go test ./acceptance -args -restore

# Run with specific tags
cd acceptance && go test ./acceptance -args -tags=@focus

# Update snapshot files
UPDATE_SNAPS=true make acceptance
```

## macOS Setup for Acceptance Tests

Acceptance tests need Podman with a properly configured machine:

```bash
./hack/macos/setup-podman-machine.sh   # 4 CPUs, 8GB RAM
./hack/macos/run-acceptance-tests.sh
```

Also add to `/etc/hosts`:
```
127.0.0.1 apiserver.localhost
127.0.0.1 rekor.localhost
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `UPDATE_SNAPS=true` | Update acceptance test snapshots |
| `E2E_INSTRUMENTATION=true` | Build coverage-instrumented binary |
| `EC_DEBUG=1` | Preserve `ec-work-*` temp directories |

## Multi-Module Note

This repo has 3 independent Go modules: root, `acceptance/`, and `tools/`. Run `go test` from the correct module root. `make test` handles the root module; `make acceptance` handles the acceptance module.
