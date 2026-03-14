# Enterprise Contract CLI - Agent Instructions

The `ec` CLI verifies artifacts and evaluates software supply chain policies using OPA/Rego rules.

## Quick Reference

### Build & Test
```bash
make build              # Build ec binary (dist/ec)
make test               # Run all tests
make acceptance         # Run acceptance tests (20m timeout)
make lint-fix           # Fix linting issues
make ci                 # Full CI suite
```

### Code Quality (Required)
```bash
make sanity             # Run sanity checks - MUST PASS before PR
make sanity-report      # Generate detailed quality report
make sanity-file FILES="./path/to/file.go"  # Check specific files
```

### Before Submitting Code
1. `make sanity` - Must pass (complexity, duplication, unused params)
2. `make test` - Must pass
3. Follow [docs/PRINCIPLES.md](docs/PRINCIPLES.md)
4. Review checklist in [docs/REVIEW.md](docs/REVIEW.md)

## Documentation Map

| Topic | Location |
|-------|----------|
| Architecture overview | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Engineering principles | [docs/PRINCIPLES.md](docs/PRINCIPLES.md) |
| Code style rules | [docs/CODE_STYLE.md](docs/CODE_STYLE.md) |
| PR review checklist | [docs/REVIEW.md](docs/REVIEW.md) |
| Package filtering | [docs/design-docs/package-filtering.md](docs/design-docs/package-filtering.md) |
| Rule filtering | [docs/design-docs/rule-filtering.md](docs/design-docs/rule-filtering.md) |
| VSA architecture | [docs/design-docs/vsa-architecture.md](docs/design-docs/vsa-architecture.md) |
| Tech debt tracker | [docs/quality/tech-debt-tracker.md](docs/quality/tech-debt-tracker.md) |

## Key Constraints

1. **Complexity budgets are enforced** - `make sanity` fails if exceeded
2. **Simplicity over abstraction** - See [PRINCIPLES.md](docs/PRINCIPLES.md)
3. **Match existing patterns** - Don't "improve" surrounding code
4. **Parse at boundaries** - Validate input, trust internal data

## Project Structure

```
cmd/           # CLI commands (validate, fetch, inspect, track, etc.)
internal/      # Private packages
├── evaluator/ # Policy evaluation engine (filters.go, conftest_evaluator.go)
├── validate/  # Validation logic
│   └── vsa/   # VSA subsystem (9 layers)
├── policy/    # Policy management
├── attestation/ # In-toto attestations, SLSA provenance
└── ...
acceptance/    # Cucumber acceptance tests
features/      # Gherkin feature files
```

## Testing

| Type | Command | Timeout |
|------|---------|---------|
| Unit | `go test -tags=unit ./...` | 10s |
| Integration | `go test -tags=integration ./...` | 15s |
| Acceptance | `make acceptance` | 20m |
| Single scenario | `make scenario_<name>` | - |

## Common Issues

**DNS resolution in tests** - Add to `/etc/hosts`:
```
127.0.0.1 apiserver.localhost
127.0.0.1 rekor.localhost
```

**Go checksum mismatch:**
```bash
go env -w GOPROXY='https://proxy.golang.org,direct'
```

## When Stuck

If code quality checks fail:
1. Simplify the implementation
2. Extract focused helper functions
3. Use early returns to reduce nesting
4. Do NOT add flags or config to work around limits

For architecture questions, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
For detailed design docs, see [docs/design-docs/](docs/design-docs/).
