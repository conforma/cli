---
name: write-tests
description: >
  Write tests for the Conforma CLI. Use when users ask "add a test", "write a test",
  "new test case", "how to test", "test pattern", "build tags", "snapshot testing",
  "acceptance test", "cucumber", or need guidance on the test framework.
---

# Write Tests for Conforma CLI

## Unit Tests

Every test file starts with a build tag:
```go
//go:build unit

package mypackage

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestMyFunction(t *testing.T) {
    result := MyFunction("input")
    assert.Equal(t, "expected", result)
}
```

Use `testify/assert` for assertions and `testify/mock` for mocking. Timeout: 10s.

Run: `go test -tags=unit ./internal/mypackage -run TestMyFunction`

## Integration Tests

Same pattern but with `//go:build integration` tag. These tests use the real OPA engine. Timeout: 15s.

```go
//go:build integration

package evaluator

func TestEvaluatorWithRealOPA(t *testing.T) {
    // test with actual OPA evaluation, no mocks
}
```

## Snapshot Testing

Use `go-snaps` for snapshot assertions:
```go
import "github.com/gkampitakis/go-snaps/snaps"

func TestOutput(t *testing.T) {
    result := GenerateOutput()
    snaps.MatchJSON(t, result)  // or snaps.MatchSnapshot(t, result)
}
```

Update snapshots: `UPDATE_SNAPS=true go test -tags=unit ./...`

## Acceptance Tests (Cucumber/Gherkin)

Feature files live in `features/`. Step definitions in `acceptance/`.

**Feature file** (`features/my_feature.feature`):
```gherkin
Feature: My feature
  Scenario: it works
    Given a known good image
    When ec validates the image
    Then the exit status is 0
```

**Step definitions** are Go functions in `acceptance/` subdirectories, registered via Godog. The test framework uses:
- `framework.NewFramework()` for test setup
- Testcontainers for infrastructure (registry, API server, Rekor)
- WireMock for HTTP stubs
- Context values for state passing between steps (no global state)

Run: `make scenario_it_works`

## Test File Naming

Follow existing patterns:
- `*_test.go` with appropriate build tag
- Unit tests alongside source: `evaluator.go` → `evaluator_test.go`
- Separate test files per concern: `evaluator_unit_core_test.go`, `evaluator_unit_data_test.go`

## Table-Driven Tests

Preferred pattern for multiple cases:
```go
cases := []struct {
    name      string
    input     string
    expected  string
    expectErr string
}{
    {name: "valid input", input: "good", expected: "result"},
    {name: "invalid input", input: "bad", expectErr: "error message"},
}

for _, c := range cases {
    t.Run(c.name, func(t *testing.T) {
        result, err := MyFunc(c.input)
        if c.expectErr != "" {
            assert.ErrorContains(t, err, c.expectErr)
            return
        }
        assert.NoError(t, err)
        assert.Equal(t, c.expected, result)
    })
}
```
