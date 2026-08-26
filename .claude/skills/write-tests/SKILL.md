---
name: write-tests
description: >
  Write tests for the Conforma CLI. Use when users ask "add a test", "write a test",
  "new test case", "how to test", "test pattern", "build tags", "snapshot testing",
  "acceptance test", "cucumber", or need guidance on the test framework.
---

# Write a Test for the Conforma CLI

Determine the test type, create the file with correct conventions, write the test, and verify it passes.

## Step 1: Determine test type

Check what is being tested:

- **Unit test** (`//go:build unit`, 10s timeout): isolated function, mocked dependencies
- **Integration test** (`//go:build integration`, 15s timeout): real OPA engine, no mocks
- **Acceptance test** (Cucumber/Gherkin, 20m timeout): end-to-end CLI behavior

## Step 2: Create the test file

### For unit or integration tests

Create a `_test.go` file alongside the source. Every test file must start with a build tag:

```go
//go:build unit

package mypackage

import (
    "testing"
    "github.com/stretchr/testify/assert"
)
```

Follow existing naming patterns in the package:
- `evaluator.go` → `evaluator_test.go`
- Multiple test files per concern: `evaluator_unit_core_test.go`, `evaluator_unit_data_test.go`

### For acceptance tests

Create or modify a `.feature` file in `features/`:

```gherkin
Feature: My feature
  Scenario: it works
    Given a known good image
    When ec validates the image
    Then the exit status is 0
```

Step definitions go in `acceptance/` subdirectories, registered via `AddStepsTo(sc *godog.ScenarioContext)` functions. State is passed between steps via `context.Context` values — no global state.

## Step 3: Write the test

Use table-driven tests for multiple cases:

```go
func TestMyFunction(t *testing.T) {
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
}
```

For snapshot testing, use `go-snaps`:

```go
import "github.com/gkampitakis/go-snaps/snaps"

func TestOutput(t *testing.T) {
    result := GenerateOutput()
    snaps.MatchJSON(t, result)
}
```

## Step 4: Run the test and verify

```bash
# Unit test
go test -tags=unit ./internal/mypackage -run TestMyFunction

# Integration test
go test -tags=integration ./internal/mypackage -run TestMyFunction

# Acceptance scenario
make scenario_it_works
```

Verify:
- Test passes
- Build tag is present on first line
- Test uses `testify/assert` for assertions
- No global state in acceptance tests

## Step 5: Report

Summarize:
- Test file created/modified and its location
- Test type and build tag used
- Pass/fail result
- Any snapshot files created or updated
