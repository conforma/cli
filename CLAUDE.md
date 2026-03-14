# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Mandatory Workflow

**Before writing any code**, read the relevant docs:
- [docs/PRINCIPLES.md](docs/PRINCIPLES.md) - Engineering principles (simplicity, no over-engineering)
- [docs/CODE_STYLE.md](docs/CODE_STYLE.md) - What NOT to do
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Layer dependencies

**Before submitting any code**:
1. Run `make sanity` - MUST PASS (complexity, duplication checks)
2. Run `make test` - MUST PASS
3. If sanity fails: simplify the code, do NOT add workarounds

**Key constraints**:
- Do NOT over-engineer. Prefer 3 similar lines over a premature abstraction.
- Do NOT add features that weren't requested.
- Do NOT "improve" surrounding code while making changes.
- Match existing patterns in the codebase.

## Quick Commands

```bash
make build          # Build
make test           # Run tests
make sanity         # Code quality checks (REQUIRED)
make sanity-report  # Detailed quality report
make lint-fix       # Fix linting issues
```

## Documentation

| Topic | Location |
|-------|----------|
| Full agent instructions | [AGENTS.md](AGENTS.md) |
| Architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Principles | [docs/PRINCIPLES.md](docs/PRINCIPLES.md) |
| Code style | [docs/CODE_STYLE.md](docs/CODE_STYLE.md) |
| Review checklist | [docs/REVIEW.md](docs/REVIEW.md) |
| Design docs | [docs/design-docs/](docs/design-docs/) |

## When Sanity Checks Fail

If `make sanity` fails:
1. **Cyclomatic complexity too high** → Split the function, use early returns
2. **Duplicate code** → Extract shared helper (only if 3+ uses)
3. **Nested ifs** → Use guard clauses, early returns
4. **Unused params** → Remove them

Do NOT increase complexity budgets or add config flags to bypass checks.
