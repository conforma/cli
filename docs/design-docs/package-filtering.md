# Pluggable Rule Filtering System

## Overview
The Enterprise Contract CLI uses a flexible rule filtering system that allows you to filter Rego rules based on various criteria before evaluation. The system is designed to be extensible and composable, making it easy to add new filtering criteria.

## Architecture

### Core Components
- **`PolicyResolver` interface**: Provides comprehensive policy resolution capabilities for both pre and post-evaluation filtering
- **`PostEvaluationFilter` interface**: Handles post-evaluation filtering and result categorization
- **`UnifiedPostEvaluationFilter`**: Implements unified filtering logic using the same PolicyResolver
- **Individual filter implementations**: Each filter implements the `RuleFilter` interface (legacy support)

### Current Filters
- **`PipelineIntentionFilter`**: Filters rules based on `pipeline_intention` metadata
- **`IncludeListFilter`**: Filters rules based on include/exclude configuration (collections, packages, rules)

## Interface Definitions

```go
// PolicyResolver provides comprehensive policy resolution capabilities.
// It handles both pre-evaluation filtering (namespace selection) and
// post-evaluation filtering (result inclusion/exclusion).
type PolicyResolver interface {
    // ResolvePolicy determines which packages and rules should be included
    // based on the current policy configuration.
    ResolvePolicy(rules policyRules, target string) PolicyResolutionResult
    
    // Includes returns the include criteria used by this policy resolver
    Includes() *Criteria
    
    // Excludes returns the exclude criteria used by this policy resolver
    Excludes() *Criteria
}

// PostEvaluationFilter decides whether individual results (warnings, failures,
// exceptions, skipped, successes) should be included in the final output.
type PostEvaluationFilter interface {
    // FilterResults processes all result types and returns the filtered results
    // along with updated missing includes tracking.
    FilterResults(
        results []Result,
        rules policyRules,
        target string,
        missingIncludes map[string]bool,
        effectiveTime time.Time,
    ) ([]Result, map[string]bool)

    // CategorizeResults takes filtered results and categorizes them by type
    // (warnings, failures, exceptions, skipped) with appropriate severity logic.
    CategorizeResults(
        filteredResults []Result,
        originalResult Outcome,
        effectiveTime time.Time,
    ) (warnings []Result, failures []Result, exceptions []Result, skipped []Result)
}

// RuleFilter decides whether an entire package (namespace) should be
// included in the evaluation set (legacy interface for backward compatibility).
type RuleFilter interface {
    Include(pkg string, rules []rule.Info) bool
}
```

## Current Implementation

### PolicyResolver Types

The system provides two main PolicyResolver implementations:

#### ECPolicyResolver
Uses the full Enterprise Contract policy resolution logic including pipeline intention filtering:

```go
type ECPolicyResolver struct {
    basePolicyResolver
    pipelineIntentions []string
    source             ecc.Source
    config             ConfigProvider
}

func NewECPolicyResolver(source ecc.Source, p ConfigProvider) PolicyResolver {
    intentions := extractStringArrayFromRuleData(source, "pipeline_intention")
    return &ECPolicyResolver{
        basePolicyResolver: basePolicyResolver{
            include: extractIncludeCriteria(source, p),
            exclude: extractExcludeCriteria(source, p),
        },
        pipelineIntentions: intentions,
        source:             source,
        config:             p,
    }
}
```

#### IncludeExcludePolicyResolver
Uses only include/exclude criteria without pipeline intention filtering:

```go
type IncludeExcludePolicyResolver struct {
    basePolicyResolver
}

func NewIncludeExcludePolicyResolver(source ecc.Source, p ConfigProvider) PolicyResolver {
    return &IncludeExcludePolicyResolver{
        basePolicyResolver: basePolicyResolver{
            include: extractIncludeCriteria(source, p),
            exclude: extractExcludeCriteria(source, p),
        },
    }
}
```

### Integration with Conftest Evaluator

The filtering is integrated into the `Evaluate` method in `conftest_evaluator.go`:

```go
func (c conftestEvaluator) Evaluate(ctx context.Context, target EvaluationTarget) ([]Outcome, error) {
    // ... existing code ...

    // Use unified policy resolution for pre-evaluation filtering
    var filteredNamespaces []string
    if c.policyResolver != nil {
        // Use the same PolicyResolver for both pre-evaluation and post-evaluation filtering
        // This ensures consistent logic and eliminates duplication
        policyResolution := c.policyResolver.ResolvePolicy(allRules, target.Target)

        // Extract included package names for conftest evaluation
        for pkg := range policyResolution.IncludedPackages {
            filteredNamespaces = append(filteredNamespaces, pkg)
        }
    }

    // ... conftest runner setup ...

    // Use unified post-evaluation filter for consistent filtering logic
    unifiedFilter := NewUnifiedPostEvaluationFilter(c.policyResolver)

    // Collect all results for processing
    allResults := []Result{}
    allResults = append(allResults, result.Warnings...)
    allResults = append(allResults, result.Failures...)
    allResults = append(allResults, result.Exceptions...)
    allResults = append(allResults, result.Skipped...)

    // Filter results using the unified filter
    filteredResults, updatedMissingIncludes := unifiedFilter.FilterResults(
        allResults, allRules, target.Target, missingIncludes, effectiveTime)

    // Categorize results using the unified filter
    warnings, failures, exceptions, skipped := unifiedFilter.CategorizeResults(
        filteredResults, result, effectiveTime)

    // ... rest of evaluation logic ...
}
```

## Policy Resolution Process

### Phase 1: Pipeline Intention Filtering (ECPolicyResolver only)
- When `pipeline_intention` is set in ruleData: only include packages with rules that have matching pipeline_intention metadata
- When `pipeline_intention` is NOT set in ruleData: only include packages with rules that have NO pipeline_intention metadata (general-purpose rules)

### Phase 2: Rule-by-Rule Evaluation
- Evaluate each rule in the package and determine if it should be included or excluded
- Apply include/exclude criteria with scoring system
- Handle term-based filtering for fine-grained control

### Phase 3: Package-Level Determination
- If ANY rule in the package is included → Package is included
- If NO rules are included but SOME rules are excluded → Package is excluded
- If NO rules are included and NO rules are excluded → Package is not explicitly categorized

## Scoring System

The system uses a sophisticated scoring mechanism for include/exclude decisions:

```go
func LegacyScore(matcher string) int {
    score := 0
    
    // Collection scoring
    if strings.HasPrefix(matcher, "@") {
        score += 10
        return score
    }
    
    // Wildcard scoring
    if matcher == "*" {
        score += 1
        return score
    }
    
    // Package and rule scoring
    parts := strings.Split(matcher, ".")
    for i, part := range parts {
        if part == "*" {
            score += 1
        } else {
            score += 10 * (len(parts) - i) // More specific parts score higher
        }
    }
    
    // Term scoring (adds 100 points)
    if strings.Contains(matcher, ":") {
        score += 100
    }
    
    return score
}
```

## Term-Based Filtering

The system supports fine-grained filtering using terms:

```go
// Example: tasks.required_untrusted_task_found:clamav-scan
// This pattern scores 210 points (10 for package + 100 for rule + 100 for term)
// and can override general patterns like "tasks.*" (10 points)
```

## How to Add a New Filter

### Step 1: Define the Filter Structure
Create a new struct that implements the `RuleFilter` interface:

```go
type MyCustomFilter struct {
    targetValues []string
}

func NewMyCustomFilter(targetValues []string) RuleFilter {
    return &MyCustomFilter{
        targetValues: targetValues,
    }
}
```

### Step 2: Implement the Filtering Logic
Implement the `Include` method:

```go
func (f *MyCustomFilter) Include(pkg string, rules []rule.Info) bool {
    // If no target values are configured, include all packages
    if len(f.targetValues) == 0 {
        return true
    }

    // Include packages with rules that have matching values
    for _, rule := range rules {
        for _, ruleValue := range rule.YourField {
            for _, targetValue := range f.targetValues {
                if ruleValue == targetValue {
                    log.Debugf("Including package %s: rule has matching value %s", pkg, targetValue)
                    return true
                }
            }
        }
    }
    
    log.Debugf("Excluding package %s: no rules match target values %v", pkg, f.targetValues)
    return false
}
```

### Step 3: Update PolicyResolver (if needed)
If you need to integrate with the new PolicyResolver system, you would need to modify the policy resolution logic in the appropriate resolver.

## Usage Examples

### Single Filter (Legacy)
```go
pipelineFilter := NewPipelineIntentionFilter([]string{"release", "production"})
filteredNamespaces := filterNamespaces(rules, pipelineFilter)
```

### PolicyResolver (Current)
```go
// Use ECPolicyResolver for full policy resolution
resolver := NewECPolicyResolver(source, config)
policyResolution := resolver.ResolvePolicy(rules, target)

// Use IncludeExcludePolicyResolver for include/exclude only
resolver := NewIncludeExcludePolicyResolver(source, config)
policyResolution := resolver.ResolvePolicy(rules, target)
```

## File Organization

The filtering system is organized in the following files:

- `internal/evaluator/conftest_evaluator.go`: Main evaluator logic and the `Evaluate` method
- `internal/evaluator/filters.go`: All filtering-related code including:
  - `PolicyResolver` interface and implementations
  - `PostEvaluationFilter` interface and implementations
  - `RuleFilter` interface (legacy)
  - `PipelineIntentionFilter` implementation
  - `IncludeListFilter` implementation
  - `NamespaceFilter` implementation
  - `filterNamespaces()` function (legacy)
  - Helper functions for extracting configuration
  - Scoring and matching logic

## Best Practices

### 1. Use PolicyResolver for New Code
- Prefer `PolicyResolver` over legacy `RuleFilter` for new implementations
- Use `ECPolicyResolver` when you need pipeline intention filtering
- Use `IncludeExcludePolicyResolver` when you only need include/exclude logic

### 2. Unified Filtering Logic
- The system now uses unified filtering logic for both pre and post-evaluation
- This ensures consistency and eliminates duplication
- All filtering decisions are made using the same PolicyResolver

### 3. Term-Based Filtering
- Use terms for fine-grained control over rule inclusion/exclusion
- Terms add significant scoring weight and can override general patterns
- Consider term-based filtering for complex policy requirements

### 4. Performance
- Keep filtering logic efficient for large rule sets
- Consider early termination when possible
- Use appropriate data structures for lookups

## Migration from Old System

The old `filterNamespacesByPipelineIntention` method has been refactored to use the new PolicyResolver system while maintaining backward compatibility. The new system provides:

1. **Unified Logic**: Same PolicyResolver used for both pre and post-evaluation filtering
2. **Enhanced Capabilities**: Better support for complex filtering scenarios
3. **Backward Compatibility**: Legacy interfaces still supported
4. **Extensibility**: Easy to add new filtering criteria

This extensible design makes it easy to add new filtering criteria without modifying existing code, following the Open/Closed Principle. 