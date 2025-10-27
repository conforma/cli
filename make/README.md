# Make Targets for Change Validation

This directory contains Makefile targets designed to help validate code changes and ensure code quality throughout the development process.

## 🎯 Sanity Checks

### Basic Sanity Check
```bash
make sanity -f make/postconditions.mk
```
Runs comprehensive linting and static analysis using `golangci-lint` to catch:
- Code style issues
- Potential bugs
- Performance problems
- Security vulnerabilities
- Complexity issues

### Enhanced Sanity Check
```bash
make sanity-plus -f make/postconditions.mk
```
Runs the basic sanity check **plus** unused function detection using `find-func-refs`:
- All benefits of `make sanity`
- **Additional**: Detects unused functions in specific files
- **Shows**: Function usage across the entire codebase
- **Requires**: `find-func-refs` tool installed (`go install github.com/konflux-ci/enterprise-contract/tools/find-func-refs@latest`)

**Example Output:**
```
=== github.com/conforma/cli/cmd/validate.containsOutput ===
/Users/jstuart/Documents/repos/ec-cli/cmd/validate/image.go:420:12  [github.com/conforma/cli/cmd/validate]
    if containsOutput(data.output, "attestation") {

=== github.com/conforma/cli/cmd/validate.validateImageCmd ===
/Users/jstuart/Documents/repos/ec-cli/cmd/validate/validate.go:35:25  [github.com/conforma/cli/cmd/validate]
    ValidateCmd.AddCommand(validateImageCmd(image.ValidateImage))
```

### Target Specific Files

#### Using Make Targets (Recommended)
```bash
# Target a specific file
make sanity-file FILES="./cmd/validate/image.go" -f make/postconditions.mk

# Target multiple files
make sanity-file FILES="./cmd/validate/image.go ./internal/validate/vsa/" -f make/postconditions.mk

# Target a specific package
make sanity-file FILES="./cmd/validate/" -f make/postconditions.mk

# Generate JSON output for specific files
make sanity-file-json FILES="./cmd/validate/image.go" -f make/postconditions.mk

# Generate summary for specific files
make sanity-file-summary FILES="./cmd/validate/image.go" -f make/postconditions.mk
```

#### Using Make with File Arguments (Alternative)
```bash
# Target a specific file
make sanity -f make/postconditions.mk -- ./cmd/validate/image.go

# Target multiple files
make sanity -f make/postconditions.mk -- ./cmd/validate/image.go ./internal/validate/vsa/

# Target a specific package
make sanity -f make/postconditions.mk -- ./cmd/validate/

# Exclude benchmark files (common pattern)
make sanity -f make/postconditions.mk -- $(find . -name "*.go" -not -path "./benchmark/*")
```

### Enhanced Sanity Reporting

#### JSON Output
```bash
make sanity-json -f make/postconditions.mk
```
Generates a JSON file (`.sanity.json`) with detailed linting results for programmatic analysis.

#### Summary Report
```bash
make sanity-summary -f make/postconditions.mk
```
Provides a human-readable summary showing:
- Issues by linter type
- Top files with most issues
- Worst cyclomatic complexity functions
- Duplicate code hotspots

## 🎯 File-Specific Validation

### Direct golangci-lint Usage
For more control over file targeting, you can use `golangci-lint` directly:

```bash
# Target specific files
golangci-lint run ./cmd/validate/image.go ./internal/validate/vsa/rekor_retriever.go

# Target with specific linters
golangci-lint run -E gocyclo,dupl,nestif ./cmd/validate/image.go

# Target with complexity threshold
golangci-lint run -E gocyclo --gocyclo.min-complexity=15 ./cmd/validate/

# Exclude specific files
golangci-lint run --skip-files=".*_test.go" ./cmd/validate/
```

### Package-Specific Testing
```bash
# Test specific package
go test ./cmd/validate -v

# Test with coverage for specific package
go test -coverprofile=coverage.out ./cmd/validate
go tool cover -html=coverage.out

# Test specific file (if it has tests)
go test ./cmd/validate -run TestValidateImage
```

### Build-Specific Files
```bash
# Build specific package
go build ./cmd/validate

# Build and check specific file
go build -o /tmp/test-build ./cmd/validate
```

### Format Specific Files
```bash
# Format specific files
go fmt ./cmd/validate/image.go ./internal/validate/vsa/rekor_retriever.go

# Check formatting without fixing
gofmt -l ./cmd/validate/image.go
```

### Find Unused Functions
```bash
# Check for unused functions in a specific file
make ffr FILE=./cmd/validate/image.go -f make/postconditions.mk

# This requires find-func-refs to be installed:
# go install github.com/konflux-ci/enterprise-contract/tools/find-func-refs@latest
```

## 🧪 Testing

### Unit Tests
```bash
make test
```
Runs all unit tests with coverage reporting. Essential after refactoring to ensure functionality is preserved.

### Test Specific Package
```bash
go test ./cmd/validate -v
go test ./internal/validate/vsa -v
```
Run tests for specific packages to validate changes in targeted areas.

### Test with Coverage
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```
Generate and view detailed coverage reports.

## 🔨 Build Validation

### Compile Check
```bash
go build ./...
```
Ensures all packages compile without errors. Run this after any code changes.

### Format Check
```bash
go fmt ./...
```
Automatically formats code according to Go standards.

### Import Organization
```bash
goimports -w .
```
Organizes imports according to Go conventions (requires `goimports` to be installed).

## 🔍 Advanced Validation

### Race Detection
```bash
go test -race ./...
```
Detects race conditions in concurrent code.

### Memory Profiling
```bash
go test -memprofile=mem.prof ./...
go tool pprof mem.prof
```
Analyze memory usage patterns.

### Benchmarking
```bash
go test -bench=./... -benchmem
```
Performance testing to ensure refactoring doesn't degrade performance.

## 📋 Recommended Workflow

### For Small Changes
1. **Make your changes**
2. **Run basic validation:**
   ```bash
   go build ./...
   make sanity -f make/postconditions.mk
   ```
3. **Run tests:**
   ```bash
   make test
   ```

### For File-Specific Changes
1. **Make your changes to specific files**
2. **Validate only changed files:**
   ```bash
   # Example: You changed cmd/validate/image.go
   go build ./cmd/validate
   make sanity -f make/postconditions.mk -- ./cmd/validate/image.go
   ```
3. **Run relevant tests:**
   ```bash
   go test ./cmd/validate -v
   ```

### For Large Refactoring
1. **Make your changes**
2. **Compile check:**
   ```bash
   go build ./...
   ```
3. **Static analysis:**
   ```bash
   make sanity -f make/postconditions.mk
   make sanity-summary -f make/postconditions.mk
   ```
4. **Run tests:**
   ```bash
   make test
   ```
5. **Check coverage:**
   ```bash
   go test -coverprofile=coverage.out ./...
   go tool cover -html=coverage.out
   ```
6. **Performance check:**
   ```bash
   go test -bench=./... -benchmem
   ```

### For CI/CD Integration
```bash
# Complete validation pipeline
go build ./... && \
make sanity -f make/postconditions.mk && \
make test && \
go test -race ./...
```

## 🎯 Understanding Sanity Check Results

### Common Issue Types

#### `gocyclo` - Cyclomatic Complexity
- **Issue**: Functions with too many decision points
- **Fix**: Extract helper functions, reduce nesting
- **Threshold**: > 12 complexity

#### `dupl` - Duplicate Code
- **Issue**: Repeated code blocks
- **Fix**: Extract common functions, use helper methods
- **Threshold**: > 50% similarity

#### `nestif` - Nested If Statements
- **Issue**: Deeply nested conditional logic
- **Fix**: Early returns, guard clauses, extract functions
- **Threshold**: > 4 nesting levels

#### `goconst` - String Constants
- **Issue**: Repeated string literals
- **Fix**: Extract to constants
- **Threshold**: > 2 occurrences

#### `revive` - Code Style
- **Issue**: Naming conventions, early returns
- **Fix**: Follow Go naming conventions, improve control flow
- **Threshold**: Various style rules

#### `unparam` - Unused Parameters
- **Issue**: Function parameters that are never used
- **Fix**: Remove unused parameters or use them
- **Threshold**: Any unused parameter

#### `ineffassign` - Ineffectual Assignment
- **Issue**: Assignments that don't affect the program
- **Fix**: Remove or fix the assignment
- **Threshold**: Any ineffectual assignment

## 🚀 Quick Reference

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `make sanity` | Basic linting | After any code change |
| `make sanity-plus` | Enhanced linting + unused functions | Before major refactoring |
| `make sanity-file FILES="..."` | File-specific linting | After changing specific files |
| `make sanity-summary` | Detailed analysis | Before committing |
| `make sanity-file-summary FILES="..."` | File-specific analysis | Before committing specific changes |
| `make test` | Run all tests | After refactoring |
| `go build ./...` | Compile check | Before any other validation |
| `go fmt ./...` | Format code | Before committing |
| `go test -race ./...` | Race detection | For concurrent code |
| `go test -bench ./...` | Performance | After optimization |

## 💡 Practical Examples

### Example 1: Refactoring a Single File
```bash
# You're refactoring cmd/validate/image.go
go build ./cmd/validate
make sanity-file FILES="./cmd/validate/image.go" -f make/postconditions.mk
make sanity-file-summary FILES="./cmd/validate/image.go" -f make/postconditions.mk
go test ./cmd/validate -v
```

### Example 1b: Major Refactoring with Unused Function Detection
```bash
# You're doing major refactoring and want to find unused functions
make sanity-plus -f make/postconditions.mk
# This runs both sanity checks AND finds unused functions in the file
```

### Example 2: Working on a Package
```bash
# You're working on the VSA package
go build ./internal/validate/vsa
make sanity-file FILES="./internal/validate/vsa/" -f make/postconditions.mk
make sanity-file-summary FILES="./internal/validate/vsa/" -f make/postconditions.mk
go test ./internal/validate/vsa -v
```

### Example 3: Excluding Test Files
```bash
# Check only production code, skip tests
golangci-lint run --skip-files=".*_test.go" ./cmd/validate/
```

### Example 4: Focus on Specific Issues
```bash
# Only check for complexity issues
golangci-lint run -E gocyclo ./cmd/validate/image.go

# Only check for duplicate code
golangci-lint run -E dupl ./internal/validate/vsa/
```

### Example 5: CI/CD Pipeline
```bash
# Complete validation for specific files
go build ./cmd/validate && \
make sanity -f make/postconditions.mk -- ./cmd/validate/ && \
go test ./cmd/validate -v
```

## 🔧 Troubleshooting

### Common Issues

#### "File is not properly formatted (gci)"
```bash
goimports -w .
```

#### "Cyclomatic complexity is high"
- Extract helper functions
- Reduce nesting with early returns
- Split large functions

#### "Duplicate code detected"
- Extract common functionality
- Use helper functions
- Consider generics for type-safe duplication

#### "Unused parameter"
- Remove the parameter if not needed
- Use the parameter if it should be used
- Add `_` prefix if intentionally unused

## 📊 Quality Metrics

The sanity checks help maintain:
- **Maintainability**: Low complexity, clear structure
- **Readability**: Consistent style, good naming
- **Reliability**: No race conditions, proper error handling
- **Performance**: Efficient algorithms, no memory leaks
- **Security**: No vulnerabilities, proper input validation

## 🎯 Best Practices

1. **Run sanity checks frequently** during development
2. **Fix issues immediately** rather than accumulating them
3. **Use the summary report** to prioritize high-impact fixes
4. **Combine with tests** to ensure functionality is preserved
5. **Profile performance** for critical code paths
6. **Check race conditions** for concurrent code

---

*This README is part of the enterprise-contract CLI development workflow. For questions or improvements, please refer to the project documentation.*
