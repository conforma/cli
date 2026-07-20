# Rule Filtering Design

## Why Two PolicyResolvers

`ECPolicyResolver` handles the full Conforma evaluation path including pipeline intention
filtering — rules declare what pipeline type they apply to (build, release, production) via
metadata, and the resolver matches against the configured intention. This is the default for
`ec validate`.

`IncludeExcludePolicyResolver` skips pipeline intention filtering entirely. It exists for
`ec test` (conftest-compatible mode) where pipeline intentions don't apply. Use this resolver
when evaluating policies outside the Conforma pipeline context.

## Filtering Happens Twice

Pre-evaluation filtering selects which *packages* to load into OPA. Post-evaluation filtering
decides which *results* to keep. Both use the same `PolicyResolver` instance so decisions are
consistent. This two-pass design exists because OPA evaluates all rules in a loaded package —
you can't selectively run individual rules within a package, only control which packages load.

## Scoring Determines Precedence

When include and exclude criteria conflict, the more-specific pattern wins via scoring.
The scoring rules are documented in the `LegacyScore` function docstring in `filters.go`.
The key insight: terms (+100pts) and specific rules (+100pts) always override collection-level
(10pts) or wildcard (1pt) patterns. This lets operators exclude a broad category while
including specific exceptions, or vice versa.

## Adding a New Filter

Follow the pattern in `IncludeExcludePolicyResolver`: embed `basePolicyResolver`, implement
`processPackage` with your filtering logic, and delegate to `baseResolvePolicy`. The
`basePolicyResolver` provides the shared scoring and package inclusion logic.

Key files: `filters.go` (all filtering logic), `conftest_evaluator.go` (integration point).
