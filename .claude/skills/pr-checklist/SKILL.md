---
name: pr-checklist
description: >
  Verify a Conforma CLI pull request is ready for review. Use when users ask
  "is this PR ready", "definition of done", "PR checklist", "before merging",
  "review checklist", or when preparing a PR for review.
---

# Verify PR Readiness for Conforma CLI

Run through each step below, report pass/fail for each, and summarize what remains.

## Step 1: Check for uncommitted generated code

```bash
make generate
git diff --exit-code
```

If there are uncommitted changes after `make generate`, flag them and stage the results.

## Step 2: Check module tidiness

List all modules and run `go mod tidy` in each, then check for drift:

```bash
git ls-files go.mod '*/go.mod'
```

```bash
go mod tidy && git diff --exit-code go.mod go.sum
(cd acceptance && go mod tidy && git diff --exit-code go.mod go.sum)
(cd tools && go mod tidy && git diff --exit-code go.mod go.sum)
(cd tools/kubectl && go mod tidy && git diff --exit-code go.mod go.sum)
```

## Step 3: Run lint

```bash
make lint
```

Zero warnings required. If there are failures, run `make lint-fix` and report what was auto-fixed vs what needs manual attention.

## Step 4: Run tests

```bash
make test
```

If acceptance-relevant code changed (features/, acceptance/, CLI commands), also run:

```bash
make acceptance
```

If behavior changed, check whether snapshots need updating:

```bash
git diff features/__snapshots__/
```

If snapshots are stale, update them with `UPDATE_SNAPS=true make acceptance` and report which snapshots changed.

## Step 5: Verify build tags on new test files

Find any new test files in the diff and verify each starts with a build tag (`//go:build unit`, `integration`, or `generative`):

```bash
git diff --name-only --diff-filter=A origin/main...HEAD | grep '_test\.go$'
```

Read the first line of each new test file and flag any missing build tags.

## Step 6: Check PR description

If a PR already exists for this branch, fetch its description and verify it covers:

- **What:** What the change does
- **Why:** Context and background
- **Tickets:** Link to Jira issue

Compare against the template in `.github/pull_request_template.md`.

## Step 7: Report

Produce a summary table:

| Check | Status | Notes |
|-------|--------|-------|
| Generated code | pass/fail | |
| Module tidiness | pass/fail | |
| Lint | pass/fail | |
| Tests | pass/fail | |
| Build tags | pass/fail | |
| PR description | pass/fail/skip | |

List any items that need attention before the PR is ready for review.
