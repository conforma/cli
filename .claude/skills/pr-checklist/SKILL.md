---
name: pr-checklist
description: >
  Definition of done checklist for Conforma CLI pull requests. Use when users ask
  "is this PR ready", "definition of done", "PR checklist", "before merging",
  "review checklist", or when preparing a PR for review.
---

# PR Definition of Done for Conforma CLI

## Before Submitting

- [ ] `make ci` passes (test + lint-fix + acceptance + tools-ci)
- [ ] `make generate` produces no uncommitted changes
- [ ] `go mod tidy` run in the correct module (root, acceptance/, or tools/)
- [ ] Acceptance test snapshots updated if behavior changed (`UPDATE_SNAPS=true make acceptance`)

## Commit Messages

Use conventional commits with Jira key:
```
feat(EC-1234): add support for new attestation format
fix(EC-5678): handle empty predicate in bundle path
```

## PR Description

Follow the template (`.github/pull_request_template.md`):
- **What:** What is this change doing?
- **Why:** Context and background
- **Tickets:** Link to Jira issue

## Code Quality

- [ ] No hardcoded values that should be configurable
- [ ] New code has appropriate test coverage (unit and/or acceptance)
- [ ] Build tags (`//go:build unit`) on all new test files
- [ ] No new lint warnings (`make lint` enforces 0 warnings)

## Multi-Module Awareness

If you changed dependencies:
- Root module: `go mod tidy` in repo root
- Acceptance tests: `cd acceptance && go mod tidy`
- Tools: `cd tools && go mod tidy`
