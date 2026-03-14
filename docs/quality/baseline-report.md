# Baseline Quality Report

**Generated:** 2026-03-14

## Summary

| Linter | Issues | Description |
|--------|--------|-------------|
| nestif | 32 | Deeply nested if statements |
| dupl | 28 | Duplicate code blocks |
| goconst | 17 | Repeated string literals |
| unparam | 11 | Unused function parameters |
| gocyclo | 2 | Cyclomatic complexity > 30 |
| **Total** | **90** | |

## Critical: High Complexity Functions

| Function | File | Complexity | Target |
|----------|------|------------|--------|
| `validateImageCmd` | cmd/validate/image.go:56 | 52 | 12 |
| `Evaluate` | internal/evaluator/conftest_evaluator.go:414 | 40 | 12 |

## Top Problem Files

| File | Issues |
|------|--------|
| internal/validate/vsa/rekor_retriever.go | 6 |
| internal/evaluator/conftest_evaluator.go | 5 |
| internal/evaluator/filters.go | 5 |
| cmd/validate/image.go | 4 |

## Duplicate Code Hotspots

| File | Issues |
|------|--------|
| internal/output/output_test.go | 4 |
| internal/http/retry_test.go | 3 |
| internal/policy/source/git_config_test.go | 3 |

## Current Budgets

| Metric | Limit | Target | Timeline |
|--------|-------|--------|----------|
| Cyclomatic complexity | 55 | 12 | TBD |

## Notes

- Most duplication is in test files
- Two functions significantly exceed complexity targets
- Initial budget set high to accommodate existing code
