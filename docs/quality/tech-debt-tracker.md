# Technical Debt Tracker

## Complexity Violations

Functions exceeding complexity budgets that are grandfathered until fixed:

| File | Function | Current | Target | Issue |
|------|----------|---------|--------|-------|
| cmd/validate/image.go:56 | validateImageCmd | 52 | 12 | - |
| internal/evaluator/conftest_evaluator.go:414 | Evaluate | 40 | 12 | - |

## Ratchet Schedule

| Date | Action | GOCYCLO_MAX |
|------|--------|-------------|
| 2026-03-14 | Baseline | 55 |
| TBD | Phase 1 | 45 |
| TBD | Phase 2 | 30 |
| TBD | Phase 3 | 15 |
| TBD | Target | 12 |

## Known Issues

| Category | Description | Priority | Issue |
|----------|-------------|----------|-------|
| Complexity | validateImageCmd needs refactoring | Medium | - |
| Complexity | Evaluate method needs refactoring | Medium | - |
| Duplication | Test file duplication | Low | - |
