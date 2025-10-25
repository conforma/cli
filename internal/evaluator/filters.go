// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX‑License‑Identifier: Apache‑2.0

package evaluator

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/opa/rule"
)

// ensureNonNilSlice returns an empty slice if the input is nil, otherwise returns the input unchanged
func ensureNonNilSlice[T any](slice []T) []T {
	if slice == nil {
		return []T{}
	}
	return slice
}

//////////////////////////////////////////////////////////////////////////////
// Interfaces
//////////////////////////////////////////////////////////////////////////////

// RuleFilter decides whether an entire package (namespace) should be
// included in the evaluation set.
//
// The filtering system works at the package level - if any rule in a package
// matches the filter criteria, the entire package is included for evaluation.
// This ensures that related rules within the same package are evaluated together.
type RuleFilter interface {
	Include(pkg string, rules []rule.Info) bool
}

// FilterFactory builds a slice of filters for a given `ecc.Source`.
//
// Multiple filters can be applied simultaneously using AND logic - all filters
// must approve a package for it to be included in the evaluation set.
type FilterFactory interface {
	CreateFilters(source ecc.Source) []RuleFilter
}

// PostEvaluationFilter decides whether individual results (warnings, failures,
// exceptions, skipped, successes) should be included in the final output.
//
// This filtering happens after all rules have been executed by conftest,
// allowing for fine-grained control over which results are reported.
// It handles include/exclude criteria, severity promotion/demotion,
// effective time filtering, and success computation.
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

//////////////////////////////////////////////////////////////////////////////
// DefaultFilterFactory
//////////////////////////////////////////////////////////////////////////////

// DefaultFilterFactory creates filters based on the source configuration.
// It handles two main filtering mechanisms:
// 1. Pipeline intention filtering - based on rule metadata
// 2. Include list filtering - based on explicit package/collection names
type DefaultFilterFactory struct{}

func NewDefaultFilterFactory() FilterFactory { return &DefaultFilterFactory{} }

// CreateFilters builds a list of filters based on the source configuration.
//
// The filtering logic follows these rules:
// 1. Pipeline Intention Filtering:
//   - When pipeline_intention is set in ruleData: only include packages with rules
//     that have matching pipeline_intention metadata
//   - When pipeline_intention is NOT set in ruleData: only include packages with rules
//     that have NO pipeline_intention metadata (general-purpose rules)
//
// 2. Include List Filtering:
//   - When includes are specified: only include packages that match the include criteria
//   - Supports @collection, package names, and package.rule patterns
//
// 3. Combined Logic:
//   - All filters are applied with AND logic - a package must pass ALL filters
//   - This allows fine-grained control over which rules are evaluated
func (f *DefaultFilterFactory) CreateFilters(source ecc.Source) []RuleFilter {
	var filters []RuleFilter

	// ── 1. Pipeline‑intention ───────────────────────────────────────────────
	intentions := extractStringArrayFromRuleData(source, "pipeline_intention")
	hasIncludes := source.Config != nil && len(source.Config.Include) > 0

	// Always add PipelineIntentionFilter to handle both cases:
	// - When pipeline_intention is set: only include packages with matching pipeline_intention metadata
	// - When pipeline_intention is not set: only include packages with no pipeline_intention metadata
	filters = append(filters, NewPipelineIntentionFilter(intentions))

	// ── 2. Include list (handles @collection / pkg / pkg.rule) ─────────────
	if hasIncludes {
		filters = append(filters, NewIncludeListFilter(source.Config.Include))
	}

	return filters
}

type IncludeFilterFactory struct{}

func NewIncludeFilterFactory() FilterFactory { return &IncludeFilterFactory{} }

// CreateFilters builds a list of filters based on the source configuration.
//
// The filtering logic follows these rules:
// 1. Pipeline Intention Filtering:
//   - When pipeline_intention is set in ruleData: only include packages with rules
//     that have matching pipeline_intention metadata
//   - When pipeline_intention is NOT set in ruleData: only include packages with rules
//     that have NO pipeline_intention metadata (general-purpose rules)
//
// 2. Include List Filtering:
//   - When includes are specified: only include packages that match the include criteria
//   - Supports @collection, package names, and package.rule patterns
//
// 3. Combined Logic:
//   - All filters are applied with AND logic - a package must pass ALL filters
//   - This allows fine-grained control over which rules are evaluated
func (f *IncludeFilterFactory) CreateFilters(source ecc.Source) []RuleFilter {
	var filters []RuleFilter

	hasIncludes := source.Config != nil && len(source.Config.Include) > 0

	// ── 1. Include list (handles @collection / pkg / pkg.rule) ─────────────
	if hasIncludes {
		filters = append(filters, NewIncludeListFilter(source.Config.Include))
	}

	return filters
}

//////////////////////////////////////////////////////////////////////////////
// PipelineIntentionFilter
//////////////////////////////////////////////////////////////////////////////

// PipelineIntentionFilter filters packages based on pipeline_intention metadata.
//
// This filter ensures that only rules appropriate for the current pipeline context
// are evaluated. It works by examining the pipeline_intention metadata in each rule
// and comparing it against the configured pipeline_intention values.
//
// Behavior:
// - When targetIntentions is empty (no pipeline_intention configured):
//   - Only includes packages with rules that have NO pipeline_intention metadata
//   - This allows general-purpose rules to run in default contexts
//
// - When targetIntentions is set (pipeline_intention configured):
//   - Only includes packages with rules that have MATCHING pipeline_intention metadata
//   - This ensures only pipeline-specific rules are evaluated
//
// Examples:
// - Config: pipeline_intention: ["release"]
//   - Rule with pipeline_intention: ["release", "production"] → INCLUDED
//   - Rule with pipeline_intention: ["staging"] → EXCLUDED
//   - Rule with no pipeline_intention metadata → EXCLUDED
//
// - Config: no pipeline_intention set
//   - Rule with pipeline_intention: ["release"] → EXCLUDED
//   - Rule with no pipeline_intention metadata → INCLUDED
type PipelineIntentionFilter struct{ targetIntentions []string }

func NewPipelineIntentionFilter(target []string) RuleFilter {
	return &PipelineIntentionFilter{targetIntentions: target}
}

// Include determines whether a package should be included based on pipeline_intention metadata.
//
// The function examines all rules in the package to determine if any have appropriate
// pipeline_intention metadata for the current configuration.
func (f *PipelineIntentionFilter) Include(_ string, rules []rule.Info) bool {
	if len(f.targetIntentions) == 0 {
		// When no pipeline_intention is configured, only include packages with no pipeline_intention metadata
		// This allows general-purpose rules (like the example fail_with_data.rego) to be evaluated
		for _, r := range rules {
			if len(r.PipelineIntention) > 0 {
				return false // Exclude packages with pipeline_intention metadata
			}
		}
		return true // Include packages with no pipeline_intention metadata
	}

	// When pipeline_intention is set, only include packages that contain rules with matching pipeline_intention metadata
	// This ensures only pipeline-specific rules are evaluated
	for _, r := range rules {
		for _, ruleIntention := range r.PipelineIntention {
			for _, targetIntention := range f.targetIntentions {
				if ruleIntention == targetIntention {
					return true // Include packages with matching pipeline_intention metadata
				}
			}
		}
	}
	return false // Exclude packages with no matching pipeline_intention metadata
}

//////////////////////////////////////////////////////////////////////////////
// IncludeListFilter
//////////////////////////////////////////////////////////////////////////////

// IncludeListFilter filters packages based on explicit include criteria.
//
// This filter provides fine-grained control over which packages are evaluated
// by allowing explicit specification of packages, collections, or individual rules.
//
// Supported patterns:
// - "@collection" - includes any package with rules that belong to the specified collection
// - "package" - includes the entire package
// - "package.rule" - includes the package containing the specified rule
//
// Examples:
// - ["@security"] - includes packages with rules in the "security" collection
// - ["cve"] - includes the "cve" package
// - ["release.security_check"] - includes the "release" package (which contains the rule)
type IncludeListFilter struct{ entries []string }

func NewIncludeListFilter(entries []string) RuleFilter {
	return &IncludeListFilter{entries: entries}
}

// Include determines whether a package should be included based on the include list criteria.
//
// The function checks if the package or any of its rules match the include criteria.
// If any rule in the package matches, the entire package is included.
func (f *IncludeListFilter) Include(pkg string, rules []rule.Info) bool {
	for _, entry := range f.entries {
		switch {
		case entry == pkg:
			// Direct package match
			return true
		case strings.HasPrefix(entry, "@"):
			// Collection-based filtering
			want := strings.TrimPrefix(entry, "@")
			for _, r := range rules {
				for _, c := range r.Collections {
					if c == want {
						return true // Package contains a rule in the specified collection
					}
				}
			}
		case strings.Contains(entry, "."):
			// Rule-specific filtering (package.rule format)
			parts := strings.SplitN(entry, ".", 2)
			if len(parts) == 2 && parts[0] == pkg {
				return true // Package contains the specified rule
			}
		}
	}
	return false // No matches found
}

//////////////////////////////////////////////////////////////////////////////
// NamespaceFilter – applies all filters (logical AND)
//////////////////////////////////////////////////////////////////////////////

// NamespaceFilter applies multiple filters using AND logic.
//
// This filter combines multiple RuleFilter instances and only includes packages
// that pass ALL filters. This allows for complex filtering scenarios where
// multiple criteria must be satisfied.
//
// Example: Pipeline intention + Include list
// - Pipeline intention filter: only packages with matching pipeline_intention
// - Include list filter: only packages in the include list
// - Result: only packages that satisfy BOTH conditions
type NamespaceFilter struct{ filters []RuleFilter }

func NewNamespaceFilter(filters ...RuleFilter) *NamespaceFilter {
	return &NamespaceFilter{filters: filters}
}

// Filter applies all filters to the given rules and returns the list of packages
// that pass all filter criteria.
//
// The filtering process:
// 1. Groups rules by package (namespace)
// 2. For each package, applies all filters in sequence
// 3. Only includes packages that pass ALL filters (AND logic)
// 4. Returns the list of approved package names
//
// This ensures that only the appropriate rules are evaluated based on the
// current configuration and context.
func (nf *NamespaceFilter) Filter(rules policyRules) []string {
	// Group rules by package for efficient filtering
	grouped := make(map[string][]rule.Info)
	for fqName, r := range rules {
		pkg := strings.SplitN(fqName, ".", 2)[0]
		if pkg == "" {
			pkg = fqName // fallback
		}
		grouped[pkg] = append(grouped[pkg], r)
	}

	var out []string
	for pkg, pkgRules := range grouped {
		include := true
		// Apply all filters - package must pass ALL filters to be included
		for _, flt := range nf.filters {
			ok := flt.Include(pkg, pkgRules)

			if !ok {
				include = false
				break // No need to check other filters if this one fails
			}
		}

		if include {
			out = append(out, pkg)
		}
	}
	return out
}

//////////////////////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////////////////////

// filterNamespaces is a convenience function that creates a NamespaceFilter
// and applies it to the given rules.
func filterNamespaces(r policyRules, filters ...RuleFilter) []string {
	return NewNamespaceFilter(filters...).Filter(r)
}

// extractStringArrayFromRuleData returns a string slice for `key`.
//
// This function parses the ruleData JSON and extracts string values for the
// specified key. It handles both single string values and arrays of strings.
//
// Examples:
// - ruleData: {"pipeline_intention": "release"} → ["release"]
// - ruleData: {"pipeline_intention": ["release", "production"]} → ["release", "production"]
// - ruleData: {} → []
func extractStringArrayFromRuleData(src ecc.Source, key string) []string {
	if src.RuleData == nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(src.RuleData.Raw, &m); err != nil {
		log.Debugf("ruleData parse error: %v", err)
		return nil
	}
	switch v := m[key].(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, i := range v {
			if s, ok := i.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

//////////////////////////////////////////////////////////////////////////////
// Comprehensive Policy Resolution
//////////////////////////////////////////////////////////////////////////////

// PolicyResolver provides comprehensive policy resolution capabilities.
// It can determine which rules and packages are included/excluded based on
// the policy configuration, taking into account all criteria including
// includes, excludes, collections, pipeline intentions, and volatile config.
type PolicyResolver interface {
	// ResolvePolicy determines which rules and packages are included/excluded
	// based on the policy configuration and available rules.
	ResolvePolicy(rules policyRules, target string) PolicyResolutionResult

	// Includes returns the include criteria used by this policy resolver
	Includes() *Criteria

	// Excludes returns the exclude criteria used by this policy resolver
	Excludes() *Criteria
}

// PolicyResolutionResult contains the comprehensive results of policy resolution.
type PolicyResolutionResult struct {
	// IncludedRules contains all rule IDs that are included in the policy
	IncludedRules map[string]bool
	// ExcludedRules contains all rule IDs that are explicitly excluded
	ExcludedRules map[string]bool
	// IncludedPackages contains all package names that are included
	IncludedPackages map[string]bool
	// MissingIncludes contains include criteria that didn't match any rules
	MissingIncludes map[string]bool
	// Explanations provides reasons for why rules/packages were included/excluded
	Explanations map[string]string
}

// NewPolicyResolutionResult creates a new PolicyResolutionResult with initialized maps
func NewPolicyResolutionResult() PolicyResolutionResult {
	return PolicyResolutionResult{
		IncludedRules:    make(map[string]bool),
		ExcludedRules:    make(map[string]bool),
		IncludedPackages: make(map[string]bool),
		MissingIncludes:  make(map[string]bool),
		Explanations:     make(map[string]string),
	}
}

// basePolicyResolver contains the shared functionality between different policy resolvers
type basePolicyResolver struct {
	include *Criteria
	exclude *Criteria
}

// ECPolicyResolver implements PolicyResolver using the existing
// filtering logic and scoring system.
type ECPolicyResolver struct {
	basePolicyResolver
	pipelineIntentions []string
}

// IncludeExcludePolicyResolver implements PolicyResolver using the existing
// filtering logic and scoring system, but ignores pipeline intention filtering.
type IncludeExcludePolicyResolver struct {
	basePolicyResolver
}

// NewECPolicyResolver creates a new PolicyResolver that uses
// the existing filtering and scoring logic.
func NewECPolicyResolver(source ecc.Source, p ConfigProvider) PolicyResolver {
	include, exclude := computeIncludeExclude(source, p)
	intentions := extractStringArrayFromRuleData(source, "pipeline_intention")

	return &ECPolicyResolver{
		basePolicyResolver: basePolicyResolver{
			include: include,
			exclude: exclude,
		},
		pipelineIntentions: intentions,
	}
}

// NewIncludeExcludePolicyResolver creates a new PolicyResolver that uses
// the existing filtering and scoring logic but ignores pipeline intention filtering.
//
// Example usage:
//
//	source := ecc.Source{
//	    RuleData: &extv1.JSON{Raw: json.RawMessage(`{"pipeline_intention":["build"]}`)},
//	    Config: &ecc.SourceConfig{Include: []string{"*"}},
//	}
//	config := &simpleConfigProvider{effectiveTime: time.Now()}
//	resolver := NewIncludeExcludePolicyResolver(source, config)
//	result := resolver.ResolvePolicy(rules, "test-target")
//	// result will include all rules regardless of pipeline intention
func NewIncludeExcludePolicyResolver(source ecc.Source, p ConfigProvider) PolicyResolver {
	include, exclude := computeIncludeExclude(source, p)

	return &IncludeExcludePolicyResolver{
		basePolicyResolver: basePolicyResolver{
			include: include,
			exclude: exclude,
		},
	}
}

// ResolvePolicy determines which rules and packages are included/excluded
// based on the policy configuration and available rules.
//
// END RESULT: Returns a comprehensive PolicyResolutionResult containing:
//
// 1. Rule-Level Decisions:
//   - IncludedRules: Map of rule IDs that should be evaluated (e.g., "package.rule")
//   - ExcludedRules: Map of rule IDs that are explicitly excluded
//   - Explanations: Detailed reasons for each rule's inclusion/exclusion decision
//
// 2. Package-Level Decisions:
//   - IncludedPackages: Map of package names that contain included rules
//   - ExcludedPackages: Map of package names that contain only excluded rules
//   - Explanations: Reasons for package-level decisions
//
// 3. Missing Includes Tracking:
//   - MissingIncludes: Include criteria that didn't match any rules (for validation)
//
// This result can be used to:
// - Filter which rules are actually evaluated by conftest
// - Determine which packages should be loaded for evaluation
// - Provide detailed explanations for policy decisions
// - Validate that all include criteria were matched
// - Generate comprehensive policy reports
func (r *ECPolicyResolver) ResolvePolicy(rules policyRules, target string) PolicyResolutionResult {
	return r.baseResolvePolicy(rules, target, r.processPackage)
}

// ResolvePolicy determines which rules and packages are included/excluded
// based on the policy configuration and available rules, ignoring pipeline intention filtering.
func (r *IncludeExcludePolicyResolver) ResolvePolicy(rules policyRules, target string) PolicyResolutionResult {
	return r.baseResolvePolicy(rules, target, r.processPackage)
}

// baseResolvePolicy contains the shared logic for policy resolution
func (r *basePolicyResolver) baseResolvePolicy(rules policyRules, target string, processPackageFunc func(string, []rule.Info, string, *PolicyResolutionResult)) PolicyResolutionResult {
	result := NewPolicyResolutionResult()

	// Initialize missing includes with all include criteria
	for _, include := range r.include.get(target) {
		result.MissingIncludes[include] = true
	}

	// Group rules by package for efficient processing
	grouped := make(map[string][]rule.Info)
	for fqName, ruleInfo := range rules {
		pkg := strings.SplitN(fqName, ".", 2)[0]
		if pkg == "" {
			pkg = fqName // fallback
		}
		grouped[pkg] = append(grouped[pkg], ruleInfo)
	}

	// Process each package
	for pkg, pkgRules := range grouped {
		processPackageFunc(pkg, pkgRules, target, &result)
	}

	return result
}

// processPackage processes a single package and its rules (without pipeline intention filtering)
func (r *IncludeExcludePolicyResolver) processPackage(pkg string, pkgRules []rule.Info, target string, result *PolicyResolutionResult) {
	// Debug: Log package being processed
	log.Debugf("[processPackage] Processing package: %s with %d rules (no pipeline intention filtering)", pkg, len(pkgRules))

	// Skip Phase 1: Pipeline Intention Filtering
	// Go directly to Phase 2: Rule-by-Rule Evaluation
	// Evaluate each rule in the package and determine if it should be included or excluded
	for _, ruleInfo := range pkgRules {
		ruleID := ruleInfo.Code
		r.baseEvaluateRuleInclusion(ruleID, ruleInfo, target, result)
	}

	// Phase 3: Package-Level Determination
	// Determine package inclusion based on its rules
	r.baseDeterminePackageInclusion(pkg, pkgRules, result)
}

// Includes returns the include criteria used by this policy resolver
func (r *IncludeExcludePolicyResolver) Includes() *Criteria {
	return r.include
}

// Excludes returns the exclude criteria used by this policy resolver
func (r *IncludeExcludePolicyResolver) Excludes() *Criteria {
	return r.exclude
}

// baseEvaluateRuleInclusion contains the shared logic for evaluating rule inclusion
func (r *basePolicyResolver) baseEvaluateRuleInclusion(ruleID string, ruleInfo rule.Info, target string, result *PolicyResolutionResult) {
	// Create matchers for this rule (similar to makeMatchers in conftest_evaluator.go)
	matchers := r.createRuleMatchers(ruleID, ruleInfo)

	// Score against include criteria
	includeScore := LegacyScoreMatches(matchers, r.include.get(target), result.MissingIncludes)

	// Score against exclude criteria
	excludeScore := LegacyScoreMatches(matchers, r.exclude.get(target), make(map[string]bool))

	// Debug: Log rule scoring
	log.Debugf("[evaluateRuleInclusion] Rule: %s, includeScore: %d, excludeScore: %d, matchers: %v", ruleID, includeScore, excludeScore, matchers)

	// Determine inclusion based on scores
	if includeScore > excludeScore {
		result.IncludedRules[ruleID] = true
		result.Explanations[ruleID] = fmt.Sprintf("included (include score: %d, exclude score: %d)", includeScore, excludeScore)
		log.Debugf("[evaluateRuleInclusion] Rule: %s INCLUDED", ruleID)
	} else if excludeScore > 0 {
		result.ExcludedRules[ruleID] = true
		result.Explanations[ruleID] = fmt.Sprintf("excluded (include score: %d, exclude score: %d)", includeScore, excludeScore)
		log.Debugf("[evaluateRuleInclusion] Rule: %s EXCLUDED", ruleID)
	} else {
		// No explicit criteria, check default behavior
		if len(r.include.get(target)) == 0 || (len(r.include.get(target)) == 1 && r.include.get(target)[0] == "*") {
			result.IncludedRules[ruleID] = true
			result.Explanations[ruleID] = "included by default (no explicit includes)"
			log.Debugf("[evaluateRuleInclusion] Rule: %s INCLUDED by default", ruleID)
		} else {
			result.Explanations[ruleID] = "not explicitly included"
			log.Debugf("[evaluateRuleInclusion] Rule: %s NOT explicitly included", ruleID)
		}
	}
}

// baseDeterminePackageInclusion contains the shared logic for determining package inclusion
func (r *basePolicyResolver) baseDeterminePackageInclusion(pkg string, pkgRules []rule.Info, result *PolicyResolutionResult) {
	// Check if any rule in the package is included
	hasIncludedRules := false

	for _, ruleInfo := range pkgRules {
		ruleID := ruleInfo.Code
		if result.IncludedRules[ruleID] {
			hasIncludedRules = true
			break
		}
	}

	// Package inclusion logic:
	// - If ANY rule is included → Package is included
	// - If NO rules are included → Package is not included (regardless of excluded rules)
	if hasIncludedRules {
		result.IncludedPackages[pkg] = true
		result.Explanations[pkg] = "package contains included rules"
	}
}

// createRuleMatchers creates matchers for a rule (same logic for both resolvers).
func (r *basePolicyResolver) createRuleMatchers(ruleID string, ruleInfo rule.Info) []string {
	parts := strings.Split(ruleID, ".")
	pkg := ""
	if len(parts) >= 2 {
		pkg = parts[len(parts)-2]
	}
	rule := parts[len(parts)-1]

	var matchers []string

	if pkg != "" {
		matchers = append(matchers, pkg, fmt.Sprintf("%s.*", pkg), fmt.Sprintf("%s.%s", pkg, rule))
	}

	// Note: Terms are extracted from result metadata, not from rule.Info
	// This will be handled when processing actual results, not during rule analysis

	matchers = append(matchers, "*")

	// Add collection matchers
	for _, collection := range ruleInfo.Collections {
		matchers = append(matchers, "@"+collection)
	}

	return matchers
}

// processPackage processes a single package and its rules
// processPackage orchestrates the evaluation of a package and its rules. This function
// implements a two-phase evaluation process:
//
// Phase 1: Pipeline Intention Filtering
// - Checks if the package matches pipeline intention criteria
// - If not, the entire package is excluded and processing stops
//
// Phase 2: Rule-by-Rule Evaluation
// - Evaluates each individual rule in the package using evaluateRuleInclusion
// - Records which rules are included/excluded in the result
//
// Phase 3: Package-Level Determination
// - Uses determinePackageInclusion to decide if the package itself should be included
// - Package inclusion is based on whether it contains any included rules
//
// The relationship between evaluateRuleInclusion and determinePackageInclusion:
//   - evaluateRuleInclusion: Makes individual rule decisions based on include/exclude criteria
//   - determinePackageInclusion: Aggregates rule decisions to determine package-level inclusion
//   - This two-step process allows for fine-grained rule control while maintaining package-level
//     organization for evaluation and reporting purposes.
func (r *ECPolicyResolver) processPackage(pkg string, pkgRules []rule.Info, target string, result *PolicyResolutionResult) {
	// Debug: Log package being processed
	log.Debugf("[processPackage] Processing package: %s with %d rules", pkg, len(pkgRules))

	// Phase 1: Rule-by-Rule Evaluation with Pipeline Intention Filtering
	// Evaluate each rule in the package and determine if it should be included or excluded
	// Pipeline intention filtering now happens at the rule level, not package level
	for _, ruleInfo := range pkgRules {
		ruleID := ruleInfo.Code

		// Check if this specific rule matches pipeline intention criteria
		if !r.ruleMatchesPipelineIntention(ruleInfo) {
			log.Debugf("[processPackage] Rule %s does NOT match pipeline intention criteria", ruleID)
			result.Explanations[ruleID] = "rule does not match pipeline intention criteria"
			continue
		}

		// Rule matches pipeline intention, proceed with normal rule evaluation
		r.baseEvaluateRuleInclusion(ruleID, ruleInfo, target, result)
	}

	// Phase 2: Package-Level Determination
	// Determine package inclusion based on its rules
	r.baseDeterminePackageInclusion(pkg, pkgRules, result)
}

// determinePackageInclusion aggregates rule-level decisions to determine package-level inclusion.
// This function is called after evaluateRuleInclusion has processed all rules in the package.
//
// Package inclusion logic:
// - If ANY rule in the package is included → Package is included
// - If NO rules are included but SOME rules are excluded → Package is excluded
// - If NO rules are included and NO rules are excluded → Package is not explicitly categorized
//
// This aggregation approach ensures that:
// 1. Packages with included rules are available for evaluation
// 2. Packages with only excluded rules are clearly marked as excluded
// 3. The package-level organization is maintained for reporting and filtering purposes
//

// ruleMatchesPipelineIntention checks if a specific rule matches pipeline intention criteria
func (r *ECPolicyResolver) ruleMatchesPipelineIntention(ruleInfo rule.Info) bool {
	if len(r.pipelineIntentions) == 0 {
		// No pipeline intention specified, only include rules with no pipeline intention metadata
		return len(ruleInfo.PipelineIntention) == 0
	}

	// Pipeline intention specified, check if this rule matches
	for _, intention := range ruleInfo.PipelineIntention {
		for _, targetIntention := range r.pipelineIntentions {
			if intention == targetIntention {
				return true
			}
		}
	}
	return false
}

// Includes returns the include criteria used by this policy resolver
func (r *ECPolicyResolver) Includes() *Criteria {
	return r.include
}

// Excludes returns the exclude criteria used by this policy resolver
func (r *ECPolicyResolver) Excludes() *Criteria {
	return r.exclude
}

// GetECPolicyResolution is a convenience function that creates a PolicyResolver
// and resolves the policy for the given rules and target.
//
// This function provides a simple way to get comprehensive policy resolution results
// including all included/excluded rules and packages, with explanations.
func GetECPolicyResolution(source ecc.Source, p ConfigProvider, rules policyRules, target string) PolicyResolutionResult {
	resolver := NewECPolicyResolver(source, p)
	return resolver.ResolvePolicy(rules, target)
}

// GetIncludeExcludePolicyResolution is a convenience function that creates a PolicyResolver
// that ignores pipeline intention filtering and resolves the policy for the given rules and target.
//
// This function provides a simple way to get policy resolution results
// including all included/excluded rules and packages, with explanations, but without
// pipeline intention filtering.
func GetIncludeExcludePolicyResolution(source ecc.Source, p ConfigProvider, rules policyRules, target string) PolicyResolutionResult {
	resolver := NewIncludeExcludePolicyResolver(source, p)
	return resolver.ResolvePolicy(rules, target)
}

//////////////////////////////////////////////////////////////////////////////
// Standalone Post-Evaluation Filtering Functions
//////////////////////////////////////////////////////////////////////////////

// LegacyIsResultIncluded determines whether a result should be included based on
// include/exclude criteria and scoring logic. This is the legacy filtering function.
func LegacyIsResultIncluded(result Result, target string, missingIncludes map[string]bool, include *Criteria, exclude *Criteria) bool {
	ruleMatchers := LegacyMakeMatchers(result)
	includeScore := LegacyScoreMatches(ruleMatchers, include.get(target), missingIncludes)
	excludeScore := LegacyScoreMatches(ruleMatchers, exclude.get(target), map[string]bool{})
	return includeScore > excludeScore
}

// LegacyScoreMatches returns the combined score for every match between needles and haystack.
// 'toBePruned' contains items that will be removed (pruned) from this map if a match is found.
// This is the legacy scoring function.
func LegacyScoreMatches(needles, haystack []string, toBePruned map[string]bool) int {
	s := 0
	for _, needle := range needles {
		for _, hay := range haystack {
			if hay == needle {
				s += LegacyScore(hay)
				delete(toBePruned, hay)
			}
		}
	}
	return s
}

// LegacyScore computes and returns the specificity of the given name. The scoring guidelines are:
//  1. If the name starts with "@" the returned score is exactly 10, e.g. "@collection". No
//     further processing is done.
//  2. Add 1 if the name covers everything, i.e. "*"
//  3. Add 10 if the name specifies a package name, e.g. "pkg", "pkg.", "pkg.*", or "pkg.rule",
//     and an additional 10 based on the namespace depth of the pkg, e.g. "a.pkg.rule" adds 10
//     more, "a.b.pkg.rule" adds 20, etc
//  4. Add 100 if a term is used, e.g. "*:term", "pkg:term" or "pkg.rule:term"
//  5. Add 100 if a rule is used, e.g. "pkg.rule", "pkg.rule:term"
//
// The score is cumulative. If a name is covered by multiple items in the guidelines, they
// are added together. For example, "pkg.rule:term" scores at 210.
// This is the legacy scoring function.
func LegacyScore(name string) int {
	if strings.HasPrefix(name, "@") {
		return 10
	}
	value := 0
	shortName, term, _ := strings.Cut(name, ":")
	if term != "" {
		value += 100
	}
	nameSplit := strings.Split(shortName, ".")
	nameSplitLen := len(nameSplit)

	if nameSplitLen == 1 {
		value += scoreSingleNameMatch(shortName)
	} else if nameSplitLen > 1 {
		value += scoreMultiNameMatch(nameSplit, nameSplitLen)
	}
	return value
}

// scoreSingleNameMatch scores a single name match (no dots)
func scoreSingleNameMatch(shortName string) int {
	// When there are no dots we assume the name refers to a
	// package and any rule inside the package is matched
	if shortName == "*" {
		return 1
	}
	return 10
}

// scoreMultiNameMatch scores a multi-name match (with dots)
func scoreMultiNameMatch(nameSplit []string, nameSplitLen int) int {
	// When there is at least one dot we assume the last element
	// is the rule and everything else is the package path
	rule := nameSplit[nameSplitLen-1]
	pkg := strings.Join(nameSplit[:nameSplitLen-1], ".")

	value := 0
	if pkg == "*" {
		// E.g. "*.rule", a weird edge case
		value += 1
	} else {
		// E.g. "pkg.rule" or "path.pkg.rule"
		value += 10 * (nameSplitLen - 1)
	}

	if rule != "*" && rule != "" {
		// E.g. "pkg.rule" so a specific rule was specified
		value += 100
	}

	return value
}

// LegacyMakeMatchers returns the possible matching strings for the result.
// This is the legacy matcher function.
func LegacyMakeMatchers(result Result) []string {
	code := ExtractStringFromMetadata(result, metadataCode)
	terms := extractStringsFromMetadata(result, metadataTerm)
	parts := strings.Split(code, ".")
	pkg := ""
	if len(parts) >= 2 {
		pkg = parts[len(parts)-2]
	}
	rule := parts[len(parts)-1]

	var matchers []string

	if pkg != "" {
		matchers = append(matchers, pkg, fmt.Sprintf("%s.*", pkg), fmt.Sprintf("%s.%s", pkg, rule))
	}

	// A term can be applied to any of the package matchers above. But we don't want to apply a term
	// matcher to a matcher that already includes a term.
	var termMatchers []string
	for _, term := range terms {
		if len(term) == 0 {
			continue
		}
		for _, matcher := range matchers {
			termMatchers = append(termMatchers, fmt.Sprintf("%s:%s", matcher, term))
		}
	}
	matchers = append(matchers, termMatchers...)

	matchers = append(matchers, "*")

	matchers = append(matchers, extractCollections(result)...)

	return matchers
}

//////////////////////////////////////////////////////////////////////////////
// Comprehensive Post-Evaluation Filter Implementation
//////////////////////////////////////////////////////////////////////////////

// UnifiedPostEvaluationFilter implements the PostEvaluationFilter interface
// using the unified policy resolution approach. This filter handles all aspects
// of post-evaluation filtering including result categorization and severity logic.
type UnifiedPostEvaluationFilter struct {
	policyResolver PolicyResolver
}

// NewUnifiedPostEvaluationFilter creates a new unified post-evaluation filter
// that uses the same PolicyResolver for consistent filtering logic.
func NewUnifiedPostEvaluationFilter(policyResolver PolicyResolver) PostEvaluationFilter {
	return &UnifiedPostEvaluationFilter{
		policyResolver: policyResolver,
	}
}

// LegacyPostEvaluationFilter implements the PostEvaluationFilter interface
// using only the include/exclude criteria, matching the legacy behavior.
type LegacyPostEvaluationFilter struct {
	include *Criteria
	exclude *Criteria
}

// NewLegacyPostEvaluationFilter creates a new legacy-style post-evaluation filter.
func NewLegacyPostEvaluationFilter(source ecc.Source, p ConfigProvider) PostEvaluationFilter {
	include, exclude := computeIncludeExclude(source, p)
	return &LegacyPostEvaluationFilter{
		include: include,
		exclude: exclude,
	}
}

// FilterResults processes all result types and returns the filtered results
// along with updated missing includes tracking.
func (f *LegacyPostEvaluationFilter) FilterResults(
	results []Result,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	effectiveTime time.Time,
) ([]Result, map[string]bool) {
	// Filter results based on include/exclude criteria only (no pipeline intention)
	var filteredResults []Result
	for _, result := range results {
		// Check if this result should be included using legacy logic
		// Results without codes are handled by LegacyIsResultIncluded using wildcard matchers
		if LegacyIsResultIncluded(result, target, missingIncludes, f.include, f.exclude) {
			filteredResults = append(filteredResults, result)
		}
	}

	return filteredResults, missingIncludes
}

// CategorizeResults implements the PostEvaluationFilter interface for legacy compatibility.
// This method provides a simple categorization that preserves the original result types.
func (f *LegacyPostEvaluationFilter) CategorizeResults(
	filteredResults []Result,
	originalResult Outcome,
	effectiveTime time.Time,
) (warnings []Result, failures []Result, exceptions []Result, skipped []Result) {
	// Simple categorization - preserve original types
	for _, result := range filteredResults {
		code := ExtractStringFromMetadata(result, metadataCode)
		// Results without codes are handled by the categorization logic using wildcard matchers

		// Determine original type by checking each category
		originalType := "unknown"
		for _, originalWarning := range originalResult.Warnings {
			if ExtractStringFromMetadata(originalWarning, metadataCode) == code {
				originalType = severityWarning
				break
			}
		}
		for _, originalFailure := range originalResult.Failures {
			if ExtractStringFromMetadata(originalFailure, metadataCode) == code {
				originalType = severityFailure
				break
			}
		}

		// Apply severity logic based on original type
		switch originalType {
		case severityWarning:
			if getSeverity(result) == severityFailure {
				failures = append(failures, result)
			} else {
				warnings = append(warnings, result)
			}
		case severityFailure:
			if getSeverity(result) == severityWarning || !isResultEffective(result, effectiveTime) {
				warnings = append(warnings, result)
			} else {
				failures = append(failures, result)
			}
		default:
			// For unknown types, assume warning
			warnings = append(warnings, result)
		}
	}

	// Add exceptions and skipped as-is
	exceptions = append(exceptions, originalResult.Exceptions...)
	skipped = append(skipped, originalResult.Skipped...)

	return warnings, failures, exceptions, skipped
}

// FilterResults processes all result types and returns the filtered results
// along with updated missing includes tracking. This method handles:
// 1. Policy-based filtering using the unified PolicyResolver
// 2. Result categorization (warnings, failures, exceptions, skipped)
// 3. Severity logic and effective time filtering
// 4. Missing includes tracking
func (f *UnifiedPostEvaluationFilter) FilterResults(
	results []Result,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	effectiveTime time.Time,
) ([]Result, map[string]bool) {
	// Check if we're using an ECPolicyResolver (which handles pipeline intentions)
	// vs IncludeExcludePolicyResolver (which doesn't)
	if ecResolver, ok := f.policyResolver.(*ECPolicyResolver); ok {
		return f.filterWithECResolver(results, rules, target, missingIncludes, ecResolver)
	}

	// Fall back to legacy filtering for other policy resolvers
	return f.filterWithLegacyLogic(results, target, missingIncludes)
}

// filterWithECResolver handles filtering using ECPolicyResolver
func (f *UnifiedPostEvaluationFilter) filterWithECResolver(
	results []Result,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	ecResolver *ECPolicyResolver,
) ([]Result, map[string]bool) {
	policyResolution := ecResolver.ResolvePolicy(rules, target)

	filteredResults := f.filterResultsByPolicyResolution(results, policyResolution)
	f.updateMissingIncludesFromPolicyResolution(missingIncludes, policyResolution)

	return filteredResults, missingIncludes
}

// filterWithLegacyLogic handles filtering using legacy logic
func (f *UnifiedPostEvaluationFilter) filterWithLegacyLogic(
	results []Result,
	target string,
	missingIncludes map[string]bool,
) ([]Result, map[string]bool) {
	filteredResults := f.filterResultsWithLegacyLogic(results, target, missingIncludes)
	f.updateMissingIncludesFromResults(missingIncludes, filteredResults)

	return filteredResults, missingIncludes
}

// filterResultsByPolicyResolution filters results based on policy resolution
func (f *UnifiedPostEvaluationFilter) filterResultsByPolicyResolution(results []Result, policyResolution PolicyResolutionResult) []Result {
	var filteredResults []Result

	for _, result := range results {
		code := ExtractStringFromMetadata(result, metadataCode)
		// For results without codes, always include them (matches legacy behavior)
		if code == "" {
			filteredResults = append(filteredResults, result)
			continue
		}

		// Check if the result's rule is included based on policy resolution
		if policyResolution.IncludedRules[code] {
			filteredResults = append(filteredResults, result)
		}
	}

	return filteredResults
}

// filterResultsWithLegacyLogic filters results using legacy logic
func (f *UnifiedPostEvaluationFilter) filterResultsWithLegacyLogic(
	results []Result,
	target string,
	missingIncludes map[string]bool,
) []Result {
	var filteredResults []Result

	for _, result := range results {
		code := ExtractStringFromMetadata(result, metadataCode)
		// For results without codes, always include them (matches legacy behavior)
		// This ensures that simple Rego rules without metadata are not filtered out
		if code == "" {
			filteredResults = append(filteredResults, result)
			continue
		}

		// Use legacy filtering logic for all results
		if LegacyIsResultIncluded(result, target, missingIncludes, f.policyResolver.Includes(), f.policyResolver.Excludes()) {
			filteredResults = append(filteredResults, result)
		}
	}

	return filteredResults
}

// updateMissingIncludesFromPolicyResolution updates missing includes based on policy resolution
func (f *UnifiedPostEvaluationFilter) updateMissingIncludesFromPolicyResolution(
	missingIncludes map[string]bool,
	policyResolution PolicyResolutionResult,
) {
	for include := range missingIncludes {
		if !policyResolution.MissingIncludes[include] {
			delete(missingIncludes, include)
		}
	}
}

// updateMissingIncludesFromResults updates missing includes based on filtered results
func (f *UnifiedPostEvaluationFilter) updateMissingIncludesFromResults(
	missingIncludes map[string]bool,
	filteredResults []Result,
) {
	for include := range missingIncludes {
		if f.isIncludeMatched(include, filteredResults) {
			delete(missingIncludes, include)
		}
	}
}

// isIncludeMatched checks if an include directive was matched by any result
func (f *UnifiedPostEvaluationFilter) isIncludeMatched(include string, results []Result) bool {
	for _, result := range results {
		matchers := LegacyMakeMatchers(result)
		for _, matcher := range matchers {
			if matcher == include {
				return true
			}
		}
	}
	return false
}

// CategorizeResults takes filtered results and categorizes them by type
// (warnings, failures, exceptions, skipped) with appropriate severity logic.
func (f *UnifiedPostEvaluationFilter) CategorizeResults(
	filteredResults []Result,
	originalResult Outcome,
	effectiveTime time.Time,
) (warnings []Result, failures []Result, exceptions []Result, skipped []Result) {
	for _, filteredResult := range filteredResults {
		// Determine the original type and apply severity logic
		originalType := f.determineOriginalType(filteredResult, originalResult)

		// Apply severity logic based on original type
		switch originalType {
		case severityWarning:
			if getSeverity(filteredResult) == severityFailure {
				failures = append(failures, filteredResult)
			} else {
				warnings = append(warnings, filteredResult)
			}
		case severityFailure:
			if getSeverity(filteredResult) == severityWarning || !isResultEffective(filteredResult, effectiveTime) {
				warnings = append(warnings, filteredResult)
			} else {
				failures = append(failures, filteredResult)
			}
		case severityException:
			exceptions = append(exceptions, filteredResult)
		case severitySkipped:
			skipped = append(skipped, filteredResult)
		default:
			// For unknown types, assume it was a warning
			// Include results with or without codes (handles simple Rego rules)
			warnings = append(warnings, filteredResult)
		}
	}

	// Add exceptions and skipped as-is (they don't go through inclusion filtering)
	exceptions = append(exceptions, originalResult.Exceptions...)
	skipped = append(skipped, originalResult.Skipped...)

	// Ensure we return empty slices instead of nil slices for consistency
	return ensureNonNilSlice(warnings), ensureNonNilSlice(failures), ensureNonNilSlice(exceptions), ensureNonNilSlice(skipped)
}

// determineOriginalType determines the original type of a filtered result
// by comparing it against the original result categories.
func (f *UnifiedPostEvaluationFilter) determineOriginalType(filteredResult Result, originalResult Outcome) string {
	filteredCode := ExtractStringFromMetadata(filteredResult, metadataCode)

	// If we have a code, try to match it against original results
	if filteredCode != "" {
		if originalType := f.findOriginalTypeByCode(filteredCode, originalResult); originalType != "" {
			return originalType
		}
	}

	// For results without codes, check if they match any original results by message
	if originalType := f.findOriginalTypeByMessage(filteredResult.Message, originalResult); originalType != "" {
		return originalType
	}

	// If no message match found, check if the result has an effective_on field
	if _, hasEffectiveOn := filteredResult.Metadata[metadataEffectiveOn]; hasEffectiveOn {
		// Results with effective_on are typically failures that might be demoted to warnings
		return severityFailure
	}

	return "unknown"
}

// findOriginalTypeByCode finds the original type by matching code
func (f *UnifiedPostEvaluationFilter) findOriginalTypeByCode(code string, originalResult Outcome) string {
	// Check each category in the original result
	for _, originalWarning := range originalResult.Warnings {
		if ExtractStringFromMetadata(originalWarning, metadataCode) == code {
			return severityWarning
		}
	}
	for _, originalFailure := range originalResult.Failures {
		if ExtractStringFromMetadata(originalFailure, metadataCode) == code {
			return severityFailure
		}
	}
	for _, originalException := range originalResult.Exceptions {
		if ExtractStringFromMetadata(originalException, metadataCode) == code {
			return severityException
		}
	}
	for _, originalSkipped := range originalResult.Skipped {
		if ExtractStringFromMetadata(originalSkipped, metadataCode) == code {
			return severitySkipped
		}
	}
	return ""
}

// findOriginalTypeByMessage finds the original type by matching message
func (f *UnifiedPostEvaluationFilter) findOriginalTypeByMessage(message string, originalResult Outcome) string {
	for _, originalWarning := range originalResult.Warnings {
		if originalWarning.Message == message {
			return severityWarning
		}
	}
	for _, originalFailure := range originalResult.Failures {
		if originalFailure.Message == message {
			return severityFailure
		}
	}
	for _, originalException := range originalResult.Exceptions {
		if originalException.Message == message {
			return severityException
		}
	}
	for _, originalSkipped := range originalResult.Skipped {
		if originalSkipped.Message == message {
			return severitySkipped
		}
	}
	return ""
}
