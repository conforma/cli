# Code Style Guide

## Complexity Budgets

These limits are enforced by `make sanity`:

| Metric | Current Limit | Target | Action if Exceeded |
|--------|---------------|--------|-------------------|
| Cyclomatic complexity | 55 | 12 | Split function, extract helpers |
| Nesting depth | 4 levels | 4 | Use guard clauses, early returns |

**Note:** Current limit is set high to accommodate existing code. Will ratchet down over time.

## What NOT to Do

### Don't Over-Abstract

```go
// BAD: Abstraction for a single use case
type ImageValidator interface {
    Validate(ctx context.Context, image string) error
}

type defaultImageValidator struct {
    client *http.Client
    cache  *cache.Cache
    config ValidatorConfig
}

// GOOD: Direct implementation
func validateImage(ctx context.Context, image string) error {
    // Implementation here
}
```

### Don't Add Unnecessary Configuration

```go
// BAD: Config for things that never change
type EvaluatorConfig struct {
    MaxRetries     int
    RetryBackoff   time.Duration
    EnableCaching  bool
    CacheTTL       time.Duration
    LogLevel       string
    // ... 20 more fields
}

// GOOD: Hardcode sensible defaults, extract only what varies
const maxRetries = 3
const retryBackoff = time.Second
```

### Don't Preemptively Handle Errors

```go
// BAD: Handling errors that can't happen
func processData(data []byte) error {
    if data == nil {
        return errors.New("data cannot be nil") // Caller already validated
    }
    if len(data) == 0 {
        return errors.New("data cannot be empty") // Already checked upstream
    }
    // ...
}

// GOOD: Trust validated input
func processData(data []byte) error {
    // Process directly - input was validated at boundary
}
```

### Don't Add Comments for Obvious Code

```go
// BAD
// validateImage validates the image
func validateImage(image string) error {
    // Check if image is empty
    if image == "" {
        // Return an error
        return errors.New("image required")
    }
}

// GOOD
func validateImage(image string) error {
    if image == "" {
        return errors.New("image required")
    }
}
```

## What TO Do

### Use Early Returns

```go
// GOOD: Guard clauses reduce nesting
func processItem(item *Item) error {
    if item == nil {
        return errNilItem
    }
    if item.Status != StatusActive {
        return nil // Nothing to do
    }
    if item.ExpiresAt.Before(time.Now()) {
        return errExpired
    }

    // Main logic at lowest nesting level
    return item.Process()
}
```

### Keep Functions Focused

```go
// GOOD: Each function does one thing
func validateAndProcess(ctx context.Context, input Input) (*Result, error) {
    if err := validate(input); err != nil {
        return nil, err
    }
    return process(ctx, input)
}

func validate(input Input) error {
    // Only validation logic
}

func process(ctx context.Context, input Input) (*Result, error) {
    // Only processing logic
}
```

### Match Existing Patterns

When modifying existing code:
1. Look at how similar functions are structured
2. Follow the same error handling pattern
3. Use the same naming conventions
4. Don't refactor surrounding code

## Go Style Reference

For general Go style guidelines, follow the [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md).
