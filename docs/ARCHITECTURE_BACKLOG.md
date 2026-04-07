# Architecture Improvement Backlog

This document catalogs identified architectural issues, technical debt, and improvement opportunities in the Conforma CLI codebase based on a comprehensive deep-dive analysis.

## Executive Summary

The codebase has a **sensible top-level modular layout** and **meaningful interfaces** around evaluation, policy, and VSA. However, significant technical debt exists across multiple dimensions:

| Category | Count | Severity |
|----------|-------|----------|
| Critical Logic/Correctness Bugs | 8 | High |
| Incomplete/Stub Code | 5 | Medium-High |
| Silent Error Handling | 12 | Medium-High |
| API/Naming Inconsistencies | 15 | Medium |
| Hardcoded Values | 25+ | Medium |
| File Size Issues (>500 LOC) | 24 | Medium |
| Dead/Unused Code | 6 | Low |
| Documentation Gaps | 10+ | Low |

---

## Priority Legend

| Priority | Meaning | Effort |
|----------|---------|--------|
| P0 | Critical - causes bugs or data loss | High |
| P1 | High - significant correctness/maintainability impact | Medium-High |
| P2 | Medium - improves developer experience | Medium |
| P3 | Low - nice to have, polish | Low |

---

## Part 1: Critical Logic and Correctness Issues

### 1.1 `EffectiveTime()` Value Receiver Bug
**Priority: P0** | **Location:** `internal/policy/policy.go`

**Problem:** `EffectiveTime()` uses a value receiver. When `effectiveTime` is nil, the method sets `p.effectiveTime` on a **copy**, so the stored `*policy` is never updated. Each call can fall back to a new `now()` if time moves, causing inconsistent behavior.

**Impact:** Policy evaluation may use different effective times for the same policy object across calls.

**Fix:** Change to pointer receiver or ensure `effectiveTime` is always initialized.

---

### 1.2 `trim()`/`trimOutput()` Logic Error
**Priority: P0** | **Location:** `internal/evaluator/conftest_evaluator.go` (lines ~90-96)

**Problem:** With multiple `depends_on` codes, results can be appended more than once. The loop does not clearly implement "drop if any dependency is reported" vs "keep unless all satisfied."

**Impact:** Results may be duplicated or incorrectly filtered.

**Fix:** Refactor to use a set-based approach for dependency checking.

---

### 1.3 Worker Count Off-by-One Error
**Priority: P0** | **Location:** `cmd/validate/image.go` (lines ~400-402)

**Problem:** Worker loop uses `for i := 0; i <= numWorkers; i++`, which starts **numWorkers + 1** workers (e.g., 6 when default is 5). This is inconsistent with `vsa.go` which uses `< numWorkers`.

**Impact:** Resource usage is higher than configured; inconsistent behavior across commands.

**Fix:** Change to `i < numWorkers`.

---

### 1.4 Result Duplication in Post-Evaluation Filters
**Priority: P1** | **Location:** `internal/evaluator/filters.go` (lines ~1010-1012, ~1138-1140)

**Problem:** `CategorizeResults` takes exceptions and skipped from `originalResult` after iterating `filteredResults`, which can duplicate rows if those slices were already represented in filtered output.

**Impact:** Reports may show duplicate entries.

**Fix:** Deduplicate results before categorization or track seen results.

---

### 1.5 `computeSuccesses()` Clock Inconsistency
**Priority: P1** | **Location:** `internal/evaluator/conftest_evaluator.go` (lines ~860-861)

**Problem:** Uses `time.Now()` inside `FilterResults` while the evaluation path uses policy `EffectiveTime()`. This causes inconsistent time reference for success vs other results.

**Impact:** Edge cases where successes disagree with failures on time-based logic.

**Fix:** Pass `EffectiveTime` through consistently.

---

### 1.6 Missing Component Items in `Evaluate`
**Priority: P1** | **Location:** `internal/evaluator/conftest_evaluator.go` (lines ~618-625)

**Problem:** Missing-includes seed only uses `defaultItems` and `digestItems`; `componentItems` from volatile config may be missing from the "must match" set.

**Impact:** Component-scoped includes may not be enforced correctly.

**Fix:** Include `componentItems` in the seed set.

---

### 1.7 Package Name Segmentation Assumption
**Priority: P1** | **Location:** `internal/evaluator/filters.go` (lines ~323-328, ~543-548)

**Problem:** Rules grouped by first dot segment of `fqName`; multi-segment package names may not match conftest namespace or `rule.Info.Package`.

**Impact:** Rules in packages like `foo.bar.baz` may not be grouped correctly.

**Fix:** Use full package path for grouping.

---

### 1.8 `ECPolicyResolver` Omits Component
**Priority: P1** | **Location:** `internal/evaluator/filters.go` (lines ~1033-1035)

**Problem:** `ResolvePolicy(rules, imageRef)` omits component; together with `baseResolvePolicy` using `include.get(target, "")`, component-scoped policy may not line up with resolution.

**Impact:** Per-component policies may not apply correctly.

**Fix:** Pass component name through the resolution chain.

---

## Part 2: Incomplete/Stub Code

### 2.1 `ExtractDigestFromImageRef` Not Implemented
**Priority: P1** | **Location:** `internal/validate/vsa/vsa.go`

**Problem:** For tag references, returns the ref unchanged; comment says digest resolution is not implemented.

**Impact:** VSA validation with tag references may not work correctly.

**Fix:** Implement proper digest resolution using registry API.

---

### 2.2 `ExtractImageDigest` TODO
**Priority: P1** | **Location:** `internal/validate/vsa/validator.go` (line ~262)

**Problem:** **TODO** comment indicates proper digest extraction logic not implemented; returns identifier as-is.

**Impact:** Policy equivalence checking may use wrong values.

**Fix:** Implement proper digest extraction.

---

### 2.3 `pinnedPolicyUrls` Never Read
**Priority: P2** | **Location:** `internal/policy/policy.go`

**Problem:** `pinnedPolicyUrls` is filled in `PreProcessPolicy` but never read—likely leftover or unfinished feature.

**Impact:** Dead code; confusing for maintainers.

**Fix:** Either complete the feature or remove the field.

---

### 2.4 Policy Cache Error Never Exposed
**Priority: P2** | **Location:** `internal/policy/cache/cache.go`

**Problem:** `PolicyCache.Set(key, value, err)` stores `err` in `cacheEntry`, but `Get` never exposes `err`—the error field is effectively dead.

**Impact:** Cache errors are silently ignored.

**Fix:** Either use the error or remove the field.

---

### 2.5 `namespaces` Flag Declared but Unused
**Priority: P2** | **Location:** `cmd/validate/input.go`

**Problem:** `namespaces` is declared but has no flag and is unused.

**Impact:** Dead code.

**Fix:** Either implement the feature or remove the field.

---

## Part 3: Silent Error Handling

### 3.1 `prepareDataDirs` Ignores Walk Errors
**Priority: P1** | **Location:** `internal/evaluator/conftest_evaluator.go` (lines ~732-735)

**Problem:** Walk errors on a data source directory are ignored with `continue`—risk of silent omission of data.

**Impact:** Policies may evaluate with incomplete data.

**Fix:** Aggregate errors and return them.

---

### 3.2 `UploadVSAEnvelope` Always Returns Nil
**Priority: P1** | **Location:** `internal/validate/vsa/storage.go`

**Problem:** After trying each backend, the function always returns `nil`; failures are only logged.

**Impact:** Callers cannot tell if every upload failed.

**Fix:** Return aggregated errors from failed uploads.

---

### 3.3 `ProcessAllVSAs` Logs and Continues
**Priority: P1** | **Location:** `internal/validate/vsa/service.go`

**Problem:** On per-component digest or VSA errors, the code logs and continues. Partial success is not clearly surfaced to callers.

**Impact:** Components can be missing from `ComponentEnvelopes` without a single aggregated error.

**Fix:** Return partial results with error aggregation.

---

### 3.4 `Criteria.get` Returns Only Defaults on Bad Ref
**Priority: P2** | **Location:** `internal/evaluator/criteria.go` (lines ~83-88)

**Problem:** Bad image ref logs debug and returns only defaults; no error to caller.

**Impact:** Silent fallback behavior.

**Fix:** Return error for invalid refs.

---

### 3.5 `extractStringArrayFromRuleData` Silent Failure
**Priority: P2** | **Location:** `internal/evaluator/filters.go` (lines ~375-377)

**Problem:** Parse failure logs debug and returns nil (same as empty).

**Impact:** Malformed rule data silently ignored.

**Fix:** Return error or distinct sentinel value.

---

### 3.6 `extractCollections` Error Log Only
**Priority: P2** | **Location:** `internal/evaluator/conftest_evaluator.go` (lines ~1139-1142)

**Problem:** Wrong metadata type logs error only, returns empty collections.

**Impact:** Rules may not be categorized correctly.

**Fix:** Consider returning error or warning to user.

---

### 3.7 `addMetadataToResults` Warns and Continues
**Priority: P2** | **Location:** `internal/evaluator/conftest_evaluator.go` (lines ~948-961)

**Problem:** Missing effective time in context or bad `effective_on` warns and continues.

**Impact:** Time-based logic silently falls back.

**Fix:** Consider stricter validation.

---

### 3.8 `conftestRunner.Run` Partial Success
**Priority: P2** | **Location:** `internal/evaluator/conftest_evaluator.go` (lines ~289-293)

**Problem:** On bad store data, sets `err` but still returns populated `result`. Callers must treat partial success + error carefully.

**Impact:** Confusing API contract.

**Fix:** Document behavior or return empty result on error.

---

### 3.9 `ValidateVSAAndComparePolicy` Missing ReasonCode
**Priority: P2** | **Location:** `internal/validate/vsa/validator.go`

**Problem:** When `ExtractPolicyFromVSA` fails, returns a failed `ValidationResult` without `ReasonCode`, unlike other branches.

**Impact:** Inconsistent error reporting.

**Fix:** Add appropriate `ReasonCode` for extraction failures.

---

### 3.10 `BuildUnifiedValidationResult` Nil Errors
**Priority: P2** | **Location:** `internal/validate/vsa/result.go`

**Problem:** Passes `nil, nil` for VSA/fallback errors into `BuildValidationError`, so structured error causes may omit underlying error text.

**Impact:** Error messages may be incomplete.

**Fix:** Preserve original error information.

---

### 3.11-3.12 `nolint:nilerr` Suppressions
**Priority: P3** | **Location:** `internal/rego/oci/oci.go` (25+ occurrences)

**Problem:** Functions return `nil, nil` on errors instead of actual errors—by design for OPA, but suppresses linter warnings extensively.

**Impact:** Hard to distinguish "no result" from "error occurred."

**Document:** This is documented but should be reconsidered for debugging.

---

## Part 4: API and Naming Inconsistencies

### 4.1 Storage vs Retrieval Backend Names
**Priority: P1** | **Location:** `internal/validate/vsa/`

**Problem:** Upload/config parsing uses `local`, while retriever creation uses `file` for the same concept.

**Impact:** Easy to misconfigure; confusing documentation.

**Fix:** Standardize on one term (recommend `file`).

---

### 4.2 Result Type Split
**Priority: P2** | **Location:** `internal/validate/vsa/`

**Problem:** Core `ValidationResult` in `vsa.go`; unified CLI shape `VSAValidationResult` in `result.go`—overlapping names and two "result" models.

**Impact:** Confusing for developers.

**Fix:** Consolidate or clearly differentiate naming.

---

### 4.3 Flag Documentation Mismatch
**Priority: P2** | **Location:** `cmd/validate/policy.go`

**Problem:** Examples use `--policy-configuration` but real flag is `--policy` / `-p`.

**Impact:** User confusion.

**Fix:** Update examples.

---

### 4.4 Error Message Mismatch
**Priority: P2** | **Location:** `cmd/validate/vsa.go` (lines ~361-362)

**Problem:** Error message refers to `--fallback-to-image-validation` which doesn't exist; behavior controlled by `--no-fallback`.

**Impact:** User confusion.

**Fix:** Update error message.

---

### 4.5 Attestor Comment vs Code Mismatch
**Priority: P3** | **Location:** `internal/validate/vsa/attest.go`

**Problem:** Comment/TODO mentions `enterprisecontract.dev` predicate type; actual constant is `https://conforma.dev/verification_summary/v1`.

**Impact:** Misleading comments.

**Fix:** Update comment.

---

### 4.6 JSON Tag Casing Inconsistency
**Priority: P2** | **Location:** `internal/validate/vsa/vsa.go` (lines ~53-68)

**Problem:** `VSASummary` uses `json:"violations"` (lowerCamelCase); `ComponentDetail` uses `json:"Name"` (PascalCase).

**Impact:** API inconsistency. **Breaking change** to fix.

**Fix:** Standardize (with versioning consideration).

---

### 4.7 Unused Flag: `--filter-type` in `input.go`
**Priority: P2** | **Location:** `cmd/validate/input.go`

**Problem:** `--filter-type` is registered but never applied to policy construction.

**Impact:** Flag does nothing; user confusion.

**Fix:** Either implement or remove.

---

### 4.8 `data.output` and `data.strict` Unused
**Priority: P2** | **Location:** `cmd/validate/policy.go`

**Problem:** These fields are never wired to flags or used; `strict: true` has no effect.

**Impact:** Dead code.

**Fix:** Either implement or remove.

---

### 4.9 Interfaces Not Used to Type Concrete Types
**Priority: P3** | **Location:** `internal/validate/vsa/interfaces.go`

**Problem:** `PredicateGenerator[T]`/`PredicateWriter[T]` are not used to type the concrete `Generator`/`Writer`; behavior is implicit.

**Impact:** Compiler doesn't enforce interface compliance.

**Fix:** Add type assertions or use interfaces explicitly.

---

### 4.10 `WithSpec` Mutates Receiver
**Priority: P2** | **Location:** `internal/policy/policy.go`

**Problem:** `WithSpec` mutates the receiver and returns the same `Policy`—not a copy; surprising if callers assume immutability.

**Impact:** Subtle bugs from shared state.

**Fix:** Document or return new instance.

---

### 4.11 `PolicyUrl` Mutates During GetPolicy
**Priority: P2** | **Location:** `internal/policy/source/source.go`

**Problem:** `PolicyUrl` mutates `Url` in place during `GetPolicy` (pinned URL from metadata). Callers must rely on that mutation.

**Impact:** Easy to misuse if a `PolicySource` is reused.

**Fix:** Return new struct or document mutation clearly.

---

### 4.12 Typo: `choosenTime`
**Priority: P3** | **Location:** `internal/policy/policy.go`

**Fix:** Rename to `chosenTime`.

---

### 4.13 Typo: `ecapsulation`
**Priority: P3** | **Location:** `internal/evaluator/conftest_evaluator.go` (line 77)

**Fix:** Rename to `encapsulation`.

---

### 4.14-4.15 Duplicate Validation Helpers
**Priority: P2** | **Location:** `internal/validate/vsa/`

**Problem:** Multiple overlapping helpers:
- `isImageDigest`/`isPureDigest` (vsa.go) vs `isValidImageDigest` (rekor_retriever.go)
- `isFilePath`/`IsFilePathLike`/`DetectIdentifierType`/`IsImageReference` overlap

**Fix:** Consolidate into single utility module.

---

## Part 5: Hardcoded Values

### 5.1 Time Constants

| Value | Location | Description |
|-------|----------|-------------|
| 90 days | `evaluator/conftest_evaluator.go` | `effectiveOnTimeout` |
| 7 days | `cmd/validate/vsa.go` | `DefaultVSAExpiration` |
| 30 min | `cmd/validate/vsa.go` | `DefaultTimeoutDuration` |
| 30s | Multiple VSA files | Rekor timeout |

### 5.2 URLs and Defaults

| Value | Location | Description |
|-------|----------|-------------|
| `https://rekor.sigstore.dev` | Multiple VSA files | Repeated 3+ times |
| `./vsa-upload` | `storage.go` | Local upload default |
| `"."` | `file_retriever.go` | File retriever default |
| GitHub/GitLab hints | `conftest_evaluator.go` ~463 | URL detection |

### 5.3 Worker/Concurrency Defaults

| Value | Location | Description |
|-------|----------|-------------|
| 5 | `cmd/validate/vsa.go`, `image.go` | Default workers |
| 8 | `rekor_retriever.go` | Rekor workers |
| 64 | `rekor_retriever.go` | Rekor worker cap |

### 5.4 File Permissions

| Value | Location | Description |
|-------|----------|-------------|
| 0755 | Multiple | Directory mode |
| 0600 | `vsa/writer.go` | Predicate JSON |
| 0644 | `vsa/attest.go` | Envelope |
| 0444 | `conftest_evaluator.go` | Data files |

### 5.5 Scoring Weights

| Value | Location | Description |
|-------|----------|-------------|
| 10/1/100 | `filters.go` | LegacyScore weights |

**Recommendation:** Extract all to a `defaults` package or configuration.

---

## Part 6: Large File Refactoring

### Large Source Files

| File | Lines | Primary Issue |
|------|-------|---------------|
| `cmd/validate/vsa.go` | 1906 | 16 structs; CLI + logic mixed |
| `internal/rego/oci/oci.go` | 1642 | All OCI rego functions |
| `internal/evaluator/conftest_evaluator.go` | 1271 | 5+ responsibilities |
| `internal/evaluator/filters.go` | 1206 | 3 filter mechanisms |
| `internal/validate/vsa/vsa.go` | 983 | Core + helpers mixed |
| `internal/policy/equivalence/equivalence.go` | 904 | Normalization + diffing |
| `internal/validate/vsa/rekor_retriever.go` | 755 | Retrieval + parsing |
| `cmd/validate/image.go` | 762 | CLI + validation mixed |
| `internal/policy/policy.go` | 686 | Policy + options + time |
| `internal/applicationsnapshot/report.go` | 421 | Multiple report formats |
| `internal/rego/sigstore/sigstore.go` | 396 | Verification functions |
| `internal/validate/vsa/storage_rekor.go` | 354 | Upload logic |
| `internal/output/output.go` | 349 | Multiple output formats |
| `internal/applicationsnapshot/input.go` | 333 | Input parsing |
| `internal/tracker/tracker.go` | 332 | Bundle tracking |
| `internal/opa/rule/rule.go` | 313 | Rule extraction |
| `internal/policy/source/source.go` | 295 | Source handling |
| `internal/validate/vsa/result.go` | 294 | Result types |
| `cmd/validate/input.go` | 286 | CLI + validation |
| `internal/validate/vsa/errors.go` | 269 | Error types |

### Test Files Over 1000 Lines

| File | Lines |
|------|-------|
| `cmd/validate/vsa_test.go` | 2681 |
| `cmd/validate/image_test.go` | 2196 |
| `internal/policy/equivalence/equivalence_test.go` | 2045 |
| `internal/evaluator/filters_test.go` | 1798 |
| `internal/rego/oci/oci_test.go` | 1781 |
| `internal/policy/policy_test.go` | 1613 |
| `internal/validate/vsa/vsa_test.go` | 1422 |
| `internal/applicationsnapshot/report_test.go` | 1370 |
| `internal/evaluation_target/.../application_snapshot_image_test.go` | 1365 |

---

## Part 7: Architecture Issues

### 7.1 `conftest_evaluator.go` Overloaded
**Location:** `internal/evaluator/conftest_evaluator.go`

**Mixed Responsibilities:**
1. Conftest integration
2. Policy download/inspect
3. Workspace and config I/O
4. Capabilities file generation
5. Pre/post filtering orchestration
6. Success synthesis
7. Metadata enrichment
8. Strict OPA capabilities
9. Rego AST helpers
10. FS glue layer

**Fix:** Extract into:
- `evaluator_setup.go` - Initialization
- `evaluator_workspace.go` - Filesystem operations
- `evaluator_results.go` - Result processing
- `evaluator_metadata.go` - Metadata enrichment

---

### 7.2 Two Parallel Pre-Filter Mechanisms
**Location:** `internal/evaluator/filters.go`

**Problem:** Package-level `RuleFilter`/`NamespaceFilter`/`FilterFactory` vs `PolicyResolver` + scoring (`ECPolicyResolver`/`IncludeExcludePolicyResolver`). Same domain (what runs) split across mechanisms.

**Fix:** Consolidate into single filtering pipeline.

---

### 7.3 Interfaces Scattered Across Files
**Location:** `internal/evaluator/`

**Problem:**
- `Evaluator` in `evaluator.go`
- `RuleFilter`, `PostEvaluationFilter`, `PolicyResolver` in `filters.go`
- `testRunner`, `ConfigProvider` in `conftest_evaluator.go`

**Fix:** Create `evaluator_interfaces.go` with all interfaces.

---

### 7.4 Two Caching Layers
**Location:** `internal/policy/`

**Problem:** `source` download cache vs `policy/cache.PolicyCache`—same URL may hit different behaviors.

**Fix:** Document relationship or consolidate.

---

### 7.5 Mixed FS Models in VSA
**Location:** `internal/validate/vsa/`

**Problem:**
- Predicate writing uses `afero`
- `UploadVSAEnvelope` reads with `os.ReadFile`
- Local storage uses `os`
- `WriteEnvelope` uses `afero.WriteFile` but `filepath.Abs`

**Fix:** Standardize on `afero` throughout or document OS-specific parts.

---

### 7.6 `orchestrator.go` Misnomer
**Location:** `internal/validate/vsa/orchestrator.go`

**Problem:** No orchestrator type or workflow object—only helper functions. Documentation oversells the file.

**Fix:** Either implement real orchestration pattern or rename.

---

### 7.7 Strong Coupling in Evaluator
**Coupled To:**
- `internal/opa`
- `internal/opa/rule`
- `internal/policy`
- `internal/policy/source`
- `internal/utils`
- `internal/tracing`
- Conftest/OPA libraries
- Conforma CRDs (`ecc`)

**Fix:** Introduce abstraction layers or adapter patterns.

---

## Part 8: Global State and Side Effects

### 8.1 Process-Wide Download Cache
**Location:** `internal/policy/source/source.go`

**Problem:** `downloadCache` and `symlinkMutexes` are global; tests use `ClearDownloadCache()`.

**Impact:** Affects isolation in concurrent/long-lived processes.

**Fix:** Make cache injectable via context.

---

### 8.2 Global HTTP Retry Config
**Location:** `cmd/root/root_cmd.go`

**Problem:** `http.SetRetryConfig` uses global mutable state.

**Fix:** Pass retry configuration through context.

---

### 8.3 `min` Function Shadows Builtin
**Location:** `internal/validate/vsa/storage_rekor.go`

**Problem:** Local `min` function shadows Go builtin.

**Fix:** Remove redundant function (Go 1.21+).

---

### 8.4 Sensitive Logging
**Location:** `internal/validate/vsa/vsa.go`

**Problem:** `verifyVSASignatureFromEnvelope` logs public key material at debug level.

**Fix:** Review for operational security policy.

---

## Part 9: TODOs and FIXMEs in Code

### Evaluator Package

| Location | Comment |
|----------|---------|
| `conftest_evaluator.go:436` | `TODO do we want to download other policies instead of erroring out?` |
| `conftest_evaluator.go:459` | `TODO: Determine if we want to check for a .git suffix as well?` |
| `conftest_evaluator.go:603` | `TODO do we want to evaluate further policies instead of erroring out?` |
| `conftest_evaluator.go:722` | `Todo: Should probably recognize other supported types of data` |

### VSA Package

| Location | Comment |
|----------|---------|
| `validator.go:262` | `TODO: Implement proper digest extraction logic` |
| `rekor_retriever.go:447` | `TODO: This is a hack to get the signature from the in-toto entry` |
| `attest.go:49` | `TODO: make this configurable` (predicate type) |

### Other Locations

| Location | Comment |
|----------|---------|
| `common_test.go:35` | `TODO: Replace mock.Anything calls with specific values` |
| `image.go:312` | `Todo: Make each fetch run concurrently` |
| `input.go:44` | `Todo: Make each fetch run concurrently` |
| `wiremock.go:284` | `TODO: reset stub state after the scenario` |
| `files.go:89` | `TODO: large files could be an issue` |
| `scans.go:89` | `TODO match by reference instead of name` |
| `sigstore.go:223` | `TODO: EffectiveTime is not actually used in this context` |

### `nolint` Suppressions Count

| File | Count |
|------|-------|
| `slsa_provenance_v1_test.go` | 35 |
| `application_snapshot_image_test.go` | 35 |
| `attestation_test.go` | 25 |
| `slsa_provenance_02_test.go` | 20 |
| `oci/oci.go` | 25 |
| Various others | 50+ |

---

## Part 10: `panic()` Usage

### Production Code (Non-Test)

| File | Count | Concern |
|------|-------|---------|
| `documentation/documentation.go` | 2 | Template errors |
| `kind/kind.go` | 3 | Kubernetes setup |
| `schema/schema.go` | 2 | Schema loading |
| `validate/image.go` | 1 | Flag registration |
| `validate/input.go` | 2 | Flag registration |
| `validate/policy.go` | 1 | Flag registration |
| `fetch_policy.go` | 1 | Flag registration |
| `inspect_policy_data.go` | 1 | Flag registration |
| `applicationsnapshot/report.go` | 1 | Template errors |
| `signature/testing_certs.go` | 3 | Cert parsing |
| `logging/logging.go` | 1 | Logger setup |
| `image/validate.go` | 1 | Internal error |
| `image/fake.go` | 1 | Test helper |

**Total: 20+ panic calls in production code**

**Recommendation:** Flag registration panics are idiomatic but should use a `must()` helper. Template/schema panics should be reconsidered.

---

## Part 11: Deprecated Code

| Location | Description |
|----------|-------------|
| `applicationsnapshot/report.go:112` | Old appstudio format |
| `applicationsnapshot/input.go:48-49` | `File`/`JSON` fields |
| `cmd/validate/image.go:511-517` | `--file`/`--json` flags |
| `evaluator/criteria.go:175` | `c.ImageDigest` usage |
| `applicationsnapshot/report_test.go:665` | hacbs output test |

---

## Part 12: Command Inconsistencies

### Policy Loading Timing

| Command | When Loaded |
|---------|-------------|
| `image` | `PreRunE` |
| `input` | `PreRunE` |
| `policy` | `PreRunE` |
| `vsa` | `RunE` (later) |

### Error Style

| Command | Pattern |
|---------|---------|
| `image` | `(allErrors error)` with `errors.Join` |
| `input` | `(allErrors error)` with `errors.Join` |
| `vsa` | Plain `error` return |

### Color Handling

| Command | Method |
|---------|--------|
| `image` | Via `WriteReport`/internal paths |
| `input` | Explicit `SetColorEnabled` in `RunE` |
| `vsa` | Explicit `SetColorEnabled` in `RunE` |

---

## Implementation Roadmap

### Phase 1: Critical Fixes (1 week)
- [ ] Fix `EffectiveTime()` value receiver bug (1.1)
- [ ] Fix worker count off-by-one (1.3)
- [ ] Fix result duplication in filters (1.4)
- [ ] Fix clock inconsistency in `computeSuccesses` (1.5)
- [ ] Standardize storage backend naming (4.1)

### Phase 2: Error Handling (1-2 weeks)
- [ ] Fix silent error in `prepareDataDirs` (3.1)
- [ ] Fix `UploadVSAEnvelope` return value (3.2)
- [ ] Fix `ProcessAllVSAs` partial failures (3.3)
- [ ] Add missing `ReasonCode` in validator (3.9)

### Phase 3: Incomplete Code (2 weeks)
- [ ] Implement `ExtractDigestFromImageRef` (2.1)
- [ ] Implement `ExtractImageDigest` (2.2)
- [ ] Remove or complete `pinnedPolicyUrls` (2.3)
- [ ] Fix flag documentation (4.3, 4.4)

### Phase 4: File Splitting (3-4 weeks)
- [ ] Split `cmd/validate/vsa.go`
- [ ] Split `internal/rego/oci/oci.go`
- [ ] Split `internal/evaluator/conftest_evaluator.go`
- [ ] Split `internal/evaluator/filters.go`

### Phase 5: Architecture (4-6 weeks)
- [ ] Consolidate filter mechanisms
- [ ] Standardize FS handling in VSA
- [ ] Extract hardcoded values to config
- [ ] Reduce global state

### Phase 6: Polish (Ongoing)
- [ ] Fix typos
- [ ] Update documentation
- [ ] Remove deprecated code
- [ ] Add ADRs
- [ ] Add package `doc.go` files

---

## Metrics to Track

| Metric | Current | Target |
|--------|---------|--------|
| Files > 1000 lines | 6 | 0 |
| Files > 500 lines | 24 | 8 |
| Test files > 1000 lines | 9 | 4 |
| Critical logic bugs | 8 | 0 |
| Silent error handlers | 12 | 0 |
| `panic()` in prod code | 20+ | 5 |
| `nolint` suppressions | 150+ | 50 |
| TODOs/FIXMEs | 15+ | 5 |
| Deprecated items | 5 | 0 |

---

## References

- [AGENTS.md](../AGENTS.md) - Project documentation
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Effective Go](https://go.dev/doc/effective_go)
- [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md)
