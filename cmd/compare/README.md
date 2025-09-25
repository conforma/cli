# Policy Config Equivalence Checker

The `ec compare` command determines if two Enterprise Contract Policy specs would produce the same evaluation result for a given image at a specific time, without actually running policy evaluation.

## Overview

This tool implements a sophisticated equivalence checker that normalizes and compares policy configurations to determine if they are functionally equivalent. It handles various complexities including:

- **Source Normalization**: Groups sources by identical policy/data URI sets
- **Digest Stripping**: Ignores digests in policy/data URLs for comparison
- **RuleData Canonicalization**: Compares JSON data with deterministic key sorting
- **Deterministic Merging**: Merges RuleData in content-based order, not input order
- **Volatile Config Filtering**: Considers time-based and image-based temporary configurations
- **Matcher Normalization**: Handles `pkg.*` → `pkg` conversion and deduplication
- **Global Configuration Merging**: Incorporates deprecated global config into all sources
- **Comprehensive Error Handling**: Proper error propagation with descriptive context

## Usage

```bash
ec compare <policy1> <policy2> [flags]
```

### Flags

- `--effective-time`: Effective time for policy evaluation (RFC3339 format, 'now', or 'attestation')
- `--image-digest`: Image digest for volatile config matching
- `--image-ref`: Image reference for volatile config matching  
- `--image-url`: Image URL for volatile config matching
- `--output`: Output format (text, json)

## Use Cases

### 1. Policy Version Comparison

Compare policies with different versions or digests to ensure they're functionally equivalent:

```bash
# Compare policy with tag vs digest
ec compare policy-with-tag.yaml policy-with-digest.yaml

# Example: These are equivalent
# policy1: oci::quay.io/enterprise-contract/ec-release-policy:latest
# policy2: oci::quay.io/enterprise-contract/ec-release-policy:latest@sha256:abc123...
```

### 2. Configuration Validation

Validate that policy changes don't alter the effective configuration:

```bash
# Before and after a policy update
ec compare old-policy.yaml new-policy.yaml

# Compare with specific effective time
ec compare policy1.yaml policy2.yaml --effective-time "2024-01-01T00:00:00Z"
```

### 3. Environment Consistency

Ensure policies across different environments are equivalent:

```bash
# Compare dev vs prod policies
ec compare dev-policy.yaml prod-policy.yaml

# Compare with JSON output for automation
ec compare policy1.yaml policy2.yaml --output json
```

### 4. Volatile Config Testing

Test how volatile (temporary) configurations affect equivalence:

```bash
# Compare with image-specific volatile configs
ec compare policy1.yaml policy2.yaml \
  --image-digest "sha256:abc123" \
  --image-ref "registry.example.com/image:latest"

# Test at specific time when volatile configs are active
ec compare policy1.yaml policy2.yaml \
  --effective-time "2024-06-15T12:00:00Z" \
  --image-digest "sha256:def456"
```

### 5. CI/CD Integration

Use in automated pipelines to validate policy changes:

```bash
# In CI pipeline - fail if policies are not equivalent
if ! ec compare current-policy.yaml updated-policy.yaml --output json | jq -r '.equivalent' | grep -q true; then
  echo "Policy changes detected - manual review required"
  exit 1
fi
```

### 6. Policy Migration Validation

Validate policy migrations maintain equivalence:

```bash
# Compare old format vs new format
ec compare legacy-policy.yaml modern-policy.yaml

# Compare with attestation time
ec compare policy1.yaml policy2.yaml --effective-time "attestation"
```

## How Equivalence is Determined

The equivalence checker performs a multi-step normalization and comparison process with **deterministic behavior** to ensure consistent results. Here's the detailed technical breakdown:

### 1. Source Bucketization

Sources are grouped into "buckets" based on their **normalized** policy and data URI sets. The key insight is that sources with identical policy/data combinations are treated as a single unit.

#### Digest Stripping Process

**Before normalization:**
```yaml
sources:
  - name: "Source A"
    policy: ["oci::quay.io/enterprise-contract/ec-release-policy:latest"]
    data: ["oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest"]
  - name: "Source B" 
    policy: ["oci::quay.io/enterprise-contract/ec-release-policy:latest@sha256:40a767fc4df3aa5bacd9fc8d16435b3bbb3edfe5db2e6b3c17d396f4ba38d711"]
    data: ["oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest@sha256:abc123def456"]
```

**After digest stripping:**
```yaml
# Both sources become:
policy: ["oci::quay.io/enterprise-contract/ec-release-policy:latest"]
data: ["oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest"]
```

**Result:** These sources are placed in the same bucket because their normalized URI sets are identical.

#### Bucket Key Generation

The bucket key is generated as: `"policy_uris|data_uris"`

```go
// Example bucket keys:
"oci::registry.com/policy:latest|oci::registry.com/data:latest"
"oci::registry.com/policy:v1.0|oci::registry.com/data:v1.0,oci::registry.com/other:latest"
```

### 2. RuleData Canonicalization and Comparison

RuleData JSON is processed to ensure consistent comparison regardless of key order or formatting.

#### Canonicalization Process

**Input RuleData:**
```yaml
# Source 1
ruleData: {"allowed_registry_prefixes": ["registry.redhat.io/", "registry.access.redhat.com/"], "timeout": 30}

# Source 2  
ruleData: {"timeout": 30, "allowed_registry_prefixes": ["registry.access.redhat.com/", "registry.redhat.io/"]}
```

**Canonical JSON (deterministic key sorting at all levels):**
```json
{
  "allowed_registry_prefixes": ["registry.access.redhat.com/", "registry.redhat.io/"],
  "timeout": 30
}
```

**Technical Implementation:**
- Uses `marshalCanonical()` which recursively sorts map keys at every level
- Ensures deterministic JSON output regardless of input key order
- Handles nested objects, arrays, and scalar values consistently
- Produces identical byte sequences for equivalent data structures

**Result:** Both RuleData objects produce the same canonical JSON, so they're considered equivalent.

#### Merging Process

When multiple sources have RuleData, they are merged in **deterministic order** based on the canonical JSON hash of each source's RuleData:

```yaml
# Source 1 RuleData
{"timeout": 30, "retries": 3}

# Source 2 RuleData  
{"timeout": 30, "max_size": "1GB"}

# Deterministic merge order (based on canonical JSON hash)
# Source with smaller hash is processed first
# Merged Result
{"max_size": "1GB", "retries": 3, "timeout": 30}
```

**Key Point**: The merge order is **content-based**, not input order-based. This ensures that equivalent policies with different source orderings produce identical merged results.

### 3. Matcher Normalization

Include and exclude matchers undergo several normalization steps:

#### Step 1: Global Configuration Merging

Deprecated global configuration is merged into every source:

```yaml
# Global config (deprecated)
spec:
  configuration:
    include: ["@redhat"]
    exclude: ["cve"]

# Source config
sources:
  - config:
      include: ["@slsa3"]
      exclude: ["hermetic"]

# After merging (every source gets):
include: ["@redhat", "@slsa3"]
exclude: ["cve", "hermetic"]
```

#### Step 2: Volatile Config Processing

Volatile configurations are filtered based on current time and image information:

```yaml
volatileConfig:
  include:
    - value: "temporary_rule"
      effectiveOn: "2024-01-01T00:00:00Z"
      effectiveUntil: "2024-12-31T23:59:59Z"
      imageDigest: "sha256:abc123"
  exclude:
    - value: "hermetic"
      effectiveOn: "2024-06-01T00:00:00Z"
      imageRef: "registry.redhat.io/ubi8/ubi:latest"
```

**Filtering Logic:**
```go
// For each volatile matcher, check:
if matcher.EffectiveOn != "" && now.Before(effectiveOn) {
    return false // Not yet active
}
if matcher.EffectiveUntil != "" && now.After(effectiveUntil) {
    return false // Expired
}
if matcher.ImageDigest != "" && matcher.ImageDigest != providedDigest {
    return false // Image doesn't match
}
// ... similar checks for ImageRef and ImageUrl
```

**Example with current time `2024-06-15T12:00:00Z` and image `sha256:abc123`:**
- `temporary_rule` → **ACTIVE** (time and image match)
- `hermetic` → **INACTIVE** (time matches but image doesn't)

#### Step 3: Matcher Normalization

Final normalization of include/exclude lists:

```yaml
# Before normalization
include: ["pkg.*", "other", "pkg.rule", "pkg.*", "duplicate"]
exclude: ["cve", "hermetic", "cve"]

# After normalization
include: ["other", "pkg", "pkg.rule"]  # pkg.* → pkg, deduplicated, sorted
exclude: ["cve", "hermetic"]           # deduplicated, sorted
```

**Normalization Rules:**
1. **Wildcard Conversion**: `pkg.*` → `pkg`
2. **Deduplication**: Remove duplicate entries
3. **Sorting**: Alphabetical order for consistent comparison

### 4. Final Comparison Process

For each bucket, the following are compared:

```go
type PolicyBucket struct {
    PolicyURIs []string              // Normalized policy URIs (digests stripped)
    DataURIs   []string              // Normalized data URIs (digests stripped)  
    RuleData   map[string]interface{} // Canonicalized JSON
    Include    []string              // Normalized include matchers
    Exclude    []string              // Normalized exclude matchers
}
```

**Comparison Logic:**
```go
// Two policies are equivalent if:
// 1. Same number of buckets
// 2. For each bucket in policy1, there's a matching bucket in policy2
// 3. Matching buckets have identical:
//    - PolicyURIs (ignoring order)
//    - DataURIs (ignoring order)  
//    - RuleData (canonical JSON comparison)
//    - Include (normalized matchers)
//    - Exclude (normalized matchers)
```

### 5. Complete Example

**Policy 1:**
```yaml
sources:
  - name: "Release Policies"
    policy: ["oci::quay.io/enterprise-contract/ec-release-policy:latest"]
    data: ["oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest"]
    ruleData: {"timeout": 30, "retries": 3}
    config:
      include: ["@slsa3", "pkg.*"]
      exclude: ["cve"]
    volatileConfig:
      exclude:
        - value: "hermetic"
          effectiveOn: "2024-01-01T00:00:00Z"
          imageDigest: "sha256:abc123"
```

**Policy 2:**
```yaml
sources:
  - name: "Release Policies"  
    policy: ["oci::quay.io/enterprise-contract/ec-release-policy:latest@sha256:40a767fc4df3aa5bacd9fc8d16435b3bbb3edfe5db2e6b3c17d396f4ba38d711"]
    data: ["oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest@sha256:def456"]
    ruleData: {"retries": 3, "timeout": 30}
    config:
      include: ["pkg", "@slsa3"]
      exclude: ["cve"]
    volatileConfig:
      exclude:
        - value: "hermetic"
          effectiveOn: "2024-01-01T00:00:00Z"
          imageDigest: "sha256:abc123"
```

**Normalized Bucket (both policies):**
```go
PolicyBucket{
    PolicyURIs: ["oci::quay.io/enterprise-contract/ec-release-policy:latest"],
    DataURIs:   ["oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest"],
    RuleData:   {"retries": 3, "timeout": 30}, // Canonicalized
    Include:    ["@slsa3", "pkg"],             // pkg.* → pkg, sorted
    Exclude:    ["cve", "hermetic"],           // volatile config active
}
```

**Result:** ✅ **EQUIVALENT** - All normalized components match exactly.

## Examples

### Basic Comparison

```bash
$ ec compare policy1.yaml policy2.yaml
✅ Policies are equivalent
Effective time: 2024-01-15T12:00:00Z
```

### JSON Output

```bash
$ ec compare policy1.yaml policy2.yaml --output json
{
  "equivalent": true,
  "effective_time": "2024-01-15T12:00:00Z",
  "policy1": "policy1.yaml",
  "policy2": "policy2.yaml",
  "image_info": {
    "digest": "sha256:abc123",
    "ref": "registry.example.com/image:latest",
    "url": ""
  }
}
```

### Non-Equivalent Policies

```bash
$ ec compare policy1.yaml policy2.yaml
❌ Policies are not equivalent
Effective time: 2024-01-15T12:00:00Z
```

## Error Handling

The equivalence checker now provides comprehensive error handling with detailed context:

### Error Propagation
- **No Silent Failures**: All errors are properly propagated with descriptive messages
- **Context Preservation**: Error messages include operation context (e.g., "failed to hash rule data")
- **Error Wrapping**: Original errors are wrapped with additional context using `fmt.Errorf`

### Common Error Scenarios
```bash
# JSON parsing errors
❌ failed to unmarshal rule data: invalid character '}' looking for beginning of object

# Canonicalization errors  
❌ failed to marshal canonical JSON: unsupported type: chan int

# Merge errors
❌ failed to merge rule data: conflicting data types for key 'timeout'
```

## Technical Improvements

### Deterministic Behavior
The equivalence checker has been enhanced to ensure **deterministic behavior** in all operations:

- **Canonical JSON Encoding**: Uses `marshalCanonical()` for deterministic JSON output with sorted keys at all levels
- **Deterministic Merging**: RuleData sources are merged in content-based order (canonical JSON hash) rather than input order
- **Consistent Hashing**: Equivalent data structures always produce identical hashes regardless of key order
- **Order Independence**: Different source orderings produce identical results

### Error Handling Improvements
- **No Silent Failures**: All errors are properly propagated with descriptive context
- **Error Wrapping**: Original errors are wrapped with operation context using `fmt.Errorf`
- **Comprehensive Coverage**: Error handling covers JSON parsing, canonicalization, and merging operations

## Limitations

- **No Policy Evaluation**: This tool only compares configurations, not actual evaluation results
- **No Collection Expansion**: `@collection` references are not expanded
- **No Specificity Scoring**: All matchers are treated equally
- **No Policy Fetching**: Policies must be available as local files
