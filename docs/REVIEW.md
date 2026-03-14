# PR Review Checklist

## Automated Checks (Must Pass)

Before review, ensure:
- [ ] `make sanity` passes
- [ ] `make test` passes
- [ ] `make lint` passes

## Complexity Review

Run `make sanity-report` and check:

- [ ] No new functions with cyclomatic complexity > 55 (current limit)
- [ ] No new functions longer than 60 lines
- [ ] No nesting deeper than 4 levels

If limits are exceeded, request simplification before approval.

## Simplicity Review

- [ ] Does this change do only what was requested?
- [ ] Are there any "while I'm here" improvements? (Should be separate PR)
- [ ] Any new abstractions? Are there 3+ use cases justifying them?
- [ ] Any new configuration options? Are they necessary?
- [ ] Any new packages? Is the justification documented?

## Pattern Consistency

- [ ] Does the code match existing patterns in the same package?
- [ ] Are error handling patterns consistent with surrounding code?
- [ ] Are naming conventions followed?

## Architecture Compliance

- [ ] Does the change respect layer boundaries? (See ARCHITECTURE.md)
- [ ] No imports from higher layers to lower layers?
- [ ] Cross-cutting concerns go through proper interfaces?

## Test Quality

- [ ] Tests cover the changed behavior
- [ ] Tests are not just for coverage (they test meaningful scenarios)
- [ ] No commented-out tests
- [ ] Test names describe the scenario

## Documentation

- [ ] If behavior changed, are docs updated?
- [ ] If new feature, is it documented?
- [ ] No excessive comments explaining obvious code
