# Engineering Principles

These principles guide all code contributions, whether from humans or agents.

## Simplicity First

1. **Prefer 3 similar lines over a premature abstraction.**
   - Don't create helpers for one-time operations
   - Don't extract functions until you have 3+ call sites
   - Duplication is cheaper than the wrong abstraction

2. **Don't add features that weren't requested.**
   - No "while I'm here" improvements
   - No speculative configurability
   - No defensive coding for impossible scenarios

3. **Match existing patterns.**
   - Copy the style of surrounding code
   - Don't "improve" code you didn't need to change
   - Consistency beats local optimization

## Boundaries and Validation

4. **Parse at boundaries, trust internally.**
   - Validate external input (user input, API responses, file contents)
   - Don't re-validate data that's already been parsed
   - Use typed structures after validation

5. **No YOLO data probing.**
   - Don't guess at data shapes
   - Use typed SDKs or explicit schemas
   - Fail fast on unexpected structures

## Code Organization

6. **Flat is better than nested.**
   - Early returns over nested conditionals
   - Guard clauses at function start
   - Maximum 3 levels of nesting

7. **Small functions with clear purposes.**
   - Functions should do one thing
   - If you can't name it clearly, it's doing too much
   - Target: under 50 lines per function

8. **Explicit over implicit.**
   - Name things clearly, even if verbose
   - Avoid magic values
   - Document non-obvious behavior

## Error Handling

9. **Handle errors where you can act on them.**
   - Don't wrap errors just to wrap them
   - Add context only when it helps debugging
   - Let errors bubble up if you can't handle them

10. **Fail fast, fail loud.**
    - Return errors, don't log and continue
    - Panics are acceptable for programmer errors
    - Never swallow errors silently
