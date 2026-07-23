---
name: build-and-lint
description: >
  Build and lint the Conforma CLI. Use when users ask "how to build", "make build",
  "lint errors", "lint fix", "golangci-lint", "make generate", "generated files",
  "go mod tidy", or need help with the build process and code quality checks.
---

# Build and Lint

## Build

```bash
make build                    # builds dist/ec_<os>_<arch> for current platform
make dist                     # builds for all supported platforms
DEBUG_BUILD=1 make build      # includes debugger symbols
```

## Lint

```bash
make lint                     # golangci-lint + addlicense + tekton-lint (0 warnings enforced)
make lint-fix                 # auto-fix lint issues
make tekton-lint              # lint Tekton task YAML only
```

Single-file verification:
```bash
golangci-lint run internal/evaluator/evaluator.go
gofmt -l internal/evaluator/evaluator.go
```

## Code Generation

```bash
make generate
```

CI checks that `make generate` produces no uncommitted changes. If CI fails with "File was modified in build", run `make generate` locally and commit the results.

## Multi-Module Project

Three independent Go modules — run `go mod tidy` in the correct one:

| Module | Path | What it covers |
|--------|------|----------------|
| Root | `go.mod` | CLI source code |
| Acceptance | `acceptance/go.mod` | Acceptance tests |
| Tools | `tools/go.mod` | Development tool dependencies |

Adding a dependency to the wrong module causes build failures.

## Container Images

```bash
make build-image              # build container image
make push-image               # push to default registry
make task-bundle              # push Tekton Task bundle
make dev                      # push ec + task bundle to kind cluster
```
