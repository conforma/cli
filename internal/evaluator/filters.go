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

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/opa/rule"
)

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
}

// PolicyResolutionResult contains the comprehensive results of policy resolution.
type PolicyResolutionResult struct {
	// IncludedRules contains all rule IDs that are included in the policy
	IncludedRules map[string]bool
	// ExcludedRules contains all rule IDs that are explicitly excluded
	ExcludedRules map[string]bool
	// IncludedPackages contains all package names that are included
	IncludedPackages map[string]bool
	// ExcludedPackages contains all package names that are explicitly excluded
	ExcludedPackages map[string]bool
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
		ExcludedPackages: make(map[string]bool),
		MissingIncludes:  make(map[string]bool),
		Explanations:     make(map[string]string),
	}
}

// ComprehensivePolicyResolver implements PolicyResolver using the existing
// filtering logic and scoring system.
type ComprehensivePolicyResolver struct {
	include            *Criteria
	exclude            *Criteria
	pipelineIntentions []string
}

// NewComprehensivePolicyResolver creates a new PolicyResolver that uses
// the existing filtering and scoring logic.
func NewComprehensivePolicyResolver(source ecc.Source, p ConfigProvider) PolicyResolver {
	include, exclude := computeIncludeExclude(source, p)
	intentions := extractStringArrayFromRuleData(source, "pipeline_intention")

	return &ComprehensivePolicyResolver{
		include:            include,
		exclude:            exclude,
		pipelineIntentions: intentions,
	}
}

// ResolvePolicy determines which rules and packages are included/excluded
// based on the policy configuration and available rules.
func (r *ComprehensivePolicyResolver) ResolvePolicy(rules policyRules, target string) PolicyResolutionResult {
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
		r.processPackage(pkg, pkgRules, target, &result)
	}

	return result
}

// processPackage processes a single package and its rules
func (r *ComprehensivePolicyResolver) processPackage(pkg string, pkgRules []rule.Info, target string, result *PolicyResolutionResult) {
	// Check if package should be included based on pipeline intentions
	if !r.matchesPipelineIntention(pkgRules) {
		result.Explanations[pkg] = "package does not match pipeline intention criteria"
		return
	}

	// Process each rule in the package
	for _, ruleInfo := range pkgRules {
		ruleID := fmt.Sprintf("%s.%s", pkg, ruleInfo.Code)
		r.processRule(ruleID, ruleInfo, target, result)
	}

	// Determine package inclusion based on its rules
	r.determinePackageInclusion(pkg, pkgRules, target, result)
}

// processRule processes a single rule
func (r *ComprehensivePolicyResolver) processRule(ruleID string, ruleInfo rule.Info, target string, result *PolicyResolutionResult) {
	// Create matchers for this rule (similar to makeMatchers in conftest_evaluator.go)
	matchers := r.createRuleMatchers(ruleID, ruleInfo)

	// Score against include criteria
	includeScore := r.scoreMatches(matchers, r.include.get(target), result.MissingIncludes)

	// Score against exclude criteria
	excludeScore := r.scoreMatches(matchers, r.exclude.get(target), make(map[string]bool))

	// Determine inclusion based on scores
	if includeScore > excludeScore {
		result.IncludedRules[ruleID] = true
		result.Explanations[ruleID] = fmt.Sprintf("included (include score: %d, exclude score: %d)", includeScore, excludeScore)
	} else if excludeScore > 0 {
		result.ExcludedRules[ruleID] = true
		result.Explanations[ruleID] = fmt.Sprintf("excluded (include score: %d, exclude score: %d)", includeScore, excludeScore)
	} else {
		// No explicit criteria, check default behavior
		if len(r.include.get(target)) == 0 || (len(r.include.get(target)) == 1 && r.include.get(target)[0] == "*") {
			result.IncludedRules[ruleID] = true
			result.Explanations[ruleID] = "included by default (no explicit includes)"
		} else {
			result.Explanations[ruleID] = "not explicitly included"
		}
	}
}

// determinePackageInclusion determines if a package should be included based on its rules
func (r *ComprehensivePolicyResolver) determinePackageInclusion(pkg string, pkgRules []rule.Info, target string, result *PolicyResolutionResult) {
	// Check if any rule in the package is included
	hasIncludedRules := false
	hasExcludedRules := false

	for _, ruleInfo := range pkgRules {
		ruleID := fmt.Sprintf("%s.%s", pkg, ruleInfo.Code)
		if result.IncludedRules[ruleID] {
			hasIncludedRules = true
		}
		if result.ExcludedRules[ruleID] {
			hasExcludedRules = true
		}
	}

	// Package is included if it has any included rules
	if hasIncludedRules {
		result.IncludedPackages[pkg] = true
		result.Explanations[pkg] = "package has included rules"
	} else if hasExcludedRules {
		result.ExcludedPackages[pkg] = true
		result.Explanations[pkg] = "package has excluded rules"
	}
}

// matchesPipelineIntention checks if the package matches pipeline intention criteria
func (r *ComprehensivePolicyResolver) matchesPipelineIntention(pkgRules []rule.Info) bool {
	if len(r.pipelineIntentions) == 0 {
		// No pipeline intention specified, only include rules without pipeline intention metadata
		for _, rule := range pkgRules {
			if len(rule.PipelineIntention) == 0 {
				return true
			}
		}
		return false
	}

	// Pipeline intention specified, check if any rule matches
	for _, rule := range pkgRules {
		for _, intention := range rule.PipelineIntention {
			for _, targetIntention := range r.pipelineIntentions {
				if intention == targetIntention {
					return true
				}
			}
		}
	}
	return false
}

// createRuleMatchers creates matchers for a rule (similar to makeMatchers in conftest_evaluator.go)
func (r *ComprehensivePolicyResolver) createRuleMatchers(ruleID string, ruleInfo rule.Info) []string {
	parts := strings.Split(ruleID, ".")
	var pkg string
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

// scoreMatches returns the combined score for every match between needles and haystack
func (r *ComprehensivePolicyResolver) scoreMatches(needles, haystack []string, toBePruned map[string]bool) int {
	var s int
	for _, needle := range needles {
		for _, hay := range haystack {
			if hay == needle {
				s += r.score(hay)
				delete(toBePruned, hay)
			}
		}
	}
	return s
}

// score computes the specificity score for a given name (same logic as in conftest_evaluator.go)
func (r *ComprehensivePolicyResolver) score(name string) int {
	if strings.HasPrefix(name, "@") {
		return 10
	}
	var value int
	shortName, term, _ := strings.Cut(name, ":")
	if term != "" {
		value += 100
	}
	nameSplit := strings.Split(shortName, ".")
	nameSplitLen := len(nameSplit)

	if nameSplitLen == 1 {
		// When there are no dots we assume the name refers to a
		// package and any rule inside the package is matched
		if shortName == "*" {
			value += 1
		} else {
			value += 10
		}
	} else if nameSplitLen > 1 {
		// When there is at least one dot we assume the last element
		// is the rule and everything else is the package path
		rule := nameSplit[nameSplitLen-1]
		pkg := strings.Join(nameSplit[:nameSplitLen-1], ".")

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
	}
	return value
}

// GetComprehensivePolicyResolution is a convenience function that creates a PolicyResolver
// and resolves the policy for the given rules and target.
//
// This function provides a simple way to get comprehensive policy resolution results
// including all included/excluded rules and packages, with explanations.
func GetComprehensivePolicyResolution(source ecc.Source, p ConfigProvider, rules policyRules, target string) PolicyResolutionResult {
	resolver := NewComprehensivePolicyResolver(source, p)
	return resolver.ResolvePolicy(rules, target)
}
