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

//////////////////////////////////////////////////////////////////////////////
// Standalone Post-Evaluation Filtering Functions
//////////////////////////////////////////////////////////////////////////////

// IsResultIncluded determines whether a result should be included based on
// include/exclude criteria and scoring logic.
func IsResultIncluded(result Result, target string, missingIncludes map[string]bool, include *Criteria, exclude *Criteria) bool {
	ruleMatchers := MakeMatchers(result)
	includeScore := ScoreMatches(ruleMatchers, include.get(target), missingIncludes)
	excludeScore := ScoreMatches(ruleMatchers, exclude.get(target), map[string]bool{})
	return includeScore > excludeScore
}

// ScoreMatches returns the combined score for every match between needles and haystack.
// 'toBePruned' contains items that will be removed (pruned) from this map if a match is found.
func ScoreMatches(needles, haystack []string, toBePruned map[string]bool) int {
	var s int
	for _, needle := range needles {
		for _, hay := range haystack {
			if hay == needle {
				s += Score(hay)
				delete(toBePruned, hay)
			}
		}
	}
	return s
}

// Score computes and returns the specificity of the given name. The scoring guidelines are:
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
func Score(name string) int {
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

// MakeMatchers returns the possible matching strings for the result.
func MakeMatchers(result Result) []string {
	code := ExtractStringFromMetadata(result, metadataCode)
	terms := extractStringsFromMetadata(result, metadataTerm)
	parts := strings.Split(code, ".")
	var pkg string
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

// ComputeSuccesses computes success results for rules that didn't appear in warnings, failures, exceptions, or skipped.
func ComputeSuccesses(
	result Outcome,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	include *Criteria,
	exclude *Criteria,
) []Result {
	// what rules, by code, have we seen in the Conftest results, use map to
	// take advantage of hashing for quicker lookup
	seenRules := map[string]bool{}
	for _, o := range [][]Result{result.Failures, result.Warnings, result.Skipped, result.Exceptions} {
		for _, r := range o {
			if code, ok := r.Metadata[metadataCode].(string); ok {
				seenRules[code] = true
			}
		}
	}

	var successes []Result
	if l := len(rules); l > 0 {
		successes = make([]Result, 0, l)
	}

	// any rule left DID NOT get metadata added so it's a success
	// this depends on the delete in addMetadata
	for code, rule := range rules {
		if _, ok := seenRules[code]; ok {
			continue
		}

		// Ignore any successes that are not meant for the package this CheckResult represents
		if rule.Package != result.Namespace {
			continue
		}

		success := Result{
			Message: "Pass",
			Metadata: map[string]interface{}{
				metadataCode: code,
			},
		}

		if rule.Title != "" {
			success.Metadata[metadataTitle] = rule.Title
		}

		if rule.Description != "" {
			success.Metadata[metadataDescription] = rule.Description
		}

		if len(rule.Collections) > 0 {
			success.Metadata[metadataCollections] = rule.Collections
		}

		if len(rule.DependsOn) > 0 {
			success.Metadata[metadataDependsOn] = rule.DependsOn
		}

		if !IsResultIncluded(success, target, missingIncludes, include, exclude) {
			continue
		}

		if rule.EffectiveOn != "" {
			success.Metadata[metadataEffectiveOn] = rule.EffectiveOn
		}

		// Let's omit the solution text here because if the rule is passing
		// already then the user probably doesn't care about the solution.

		successes = append(successes, success)
	}

	return successes
}

//////////////////////////////////////////////////////////////////////////////
// Comprehensive Post-Evaluation Filter Implementation
//////////////////////////////////////////////////////////////////////////////

// ComprehensivePostEvaluationFilter implements the PostEvaluationFilter interface
// using the comprehensive policy resolution logic for consistent filtering behavior.
type ComprehensivePostEvaluationFilter struct {
	resolver PolicyResolver
}

// NewComprehensivePostEvaluationFilter creates a new comprehensive post-evaluation filter.
func NewComprehensivePostEvaluationFilter(source ecc.Source, p ConfigProvider) PostEvaluationFilter {
	return &ComprehensivePostEvaluationFilter{
		resolver: NewComprehensivePolicyResolver(source, p),
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
		code := ExtractStringFromMetadata(result, metadataCode)
		if code == "" {
			// Skip results without a code
			continue
		}

		// Check if this result should be included using legacy logic
		if IsResultIncluded(result, target, missingIncludes, f.include, f.exclude) {
			filteredResults = append(filteredResults, result)
		}
	}

	return filteredResults, missingIncludes
}

// FilterResults processes all result types and returns the filtered results
// along with updated missing includes tracking.
func (f *ComprehensivePostEvaluationFilter) FilterResults(
	results []Result,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	effectiveTime time.Time,
) ([]Result, map[string]bool) {
	// Get comprehensive policy resolution for this target
	resolution := f.resolver.ResolvePolicy(rules, target)

	// Filter results based on the resolution
	var filteredResults []Result
	for _, result := range results {
		code := ExtractStringFromMetadata(result, metadataCode)
		if code == "" {
			// Skip results without a code
			continue
		}

		// Check if this result should be included
		if resolution.IncludedRules[code] {
			filteredResults = append(filteredResults, result)
		}
		// Note: Excluded rules are simply not included in the results
	}

	// Update missing includes based on what was actually matched
	// Check if any included results matched each include criteria
	for include := range missingIncludes {
		matched := false
		for _, result := range filteredResults {
			// Check if this result matches the include criteria
			matchers := MakeMatchers(result)
			for _, matcher := range matchers {
				if matcher == include {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if matched {
			delete(missingIncludes, include)
		}
	}

	return filteredResults, missingIncludes
}

// MigrationHelper provides utilities for migrating between legacy and new
// post-evaluation filtering approaches.
type MigrationHelper struct {
	useLegacyFilter bool
	legacyFilter    PostEvaluationFilter
	newFilter       PostEvaluationFilter
}

// NewMigrationHelper creates a new migration helper with both legacy and new filters.
func NewMigrationHelper(source ecc.Source, p ConfigProvider, useLegacyFilter bool) *MigrationHelper {
	return &MigrationHelper{
		useLegacyFilter: useLegacyFilter,
		legacyFilter:    NewLegacyPostEvaluationFilter(source, p),
		newFilter:       NewComprehensivePostEvaluationFilter(source, p),
	}
}

// FilterResults applies the appropriate filter based on the migration configuration.
func (h *MigrationHelper) FilterResults(
	results []Result,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	effectiveTime time.Time,
) ([]Result, map[string]bool) {
	if h.useLegacyFilter {
		return h.legacyFilter.FilterResults(results, rules, target, missingIncludes, effectiveTime)
	}
	return h.newFilter.FilterResults(results, rules, target, missingIncludes, effectiveTime)
}

// GetActiveFilterType returns a string describing which filter is currently active.
func (h *MigrationHelper) GetActiveFilterType() string {
	if h.useLegacyFilter {
		return "legacy"
	}
	return "comprehensive"
}

// CompareResults runs both filters and returns the results for comparison.
// This is useful for testing and validation during migration.
func (h *MigrationHelper) CompareResults(
	results []Result,
	rules policyRules,
	target string,
	missingIncludes map[string]bool,
	effectiveTime time.Time,
) (legacyResults []Result, newResults []Result, legacyMissingIncludes map[string]bool, newMissingIncludes map[string]bool) {
	// Create copies of missing includes for each filter
	legacyMissingIncludesCopy := make(map[string]bool)
	newMissingIncludesCopy := make(map[string]bool)
	for k, v := range missingIncludes {
		legacyMissingIncludesCopy[k] = v
		newMissingIncludesCopy[k] = v
	}

	// Run both filters
	legacyResults, legacyMissingIncludes = h.legacyFilter.FilterResults(
		results, rules, target, legacyMissingIncludesCopy, effectiveTime)
	newResults, newMissingIncludes = h.newFilter.FilterResults(
		results, rules, target, newMissingIncludesCopy, effectiveTime)

	return legacyResults, newResults, legacyMissingIncludes, newMissingIncludes
}

// FeatureFlagProvider defines the interface for checking feature flags.
type FeatureFlagProvider interface {
	IsEnabled(flag string) bool
}

// DefaultFeatureFlagProvider provides a simple implementation of FeatureFlagProvider.
type DefaultFeatureFlagProvider struct {
	flags map[string]bool
}

// NewDefaultFeatureFlagProvider creates a new feature flag provider with the given flags.
func NewDefaultFeatureFlagProvider(flags map[string]bool) *DefaultFeatureFlagProvider {
	return &DefaultFeatureFlagProvider{
		flags: flags,
	}
}

// IsEnabled checks if a feature flag is enabled.
func (p *DefaultFeatureFlagProvider) IsEnabled(flag string) bool {
	return p.flags[flag]
}

// FeatureFlagMigrationHelper extends MigrationHelper with feature flag support.
type FeatureFlagMigrationHelper struct {
	*MigrationHelper
	featureFlagProvider FeatureFlagProvider
	featureFlagName     string
}

// NewFeatureFlagMigrationHelper creates a new migration helper with feature flag support.
func NewFeatureFlagMigrationHelper(
	source ecc.Source,
	p ConfigProvider,
	featureFlagProvider FeatureFlagProvider,
	featureFlagName string,
) *FeatureFlagMigrationHelper {
	// Determine which filter to use based on feature flag
	useLegacyFilter := !featureFlagProvider.IsEnabled(featureFlagName)

	return &FeatureFlagMigrationHelper{
		MigrationHelper:     NewMigrationHelper(source, p, useLegacyFilter),
		featureFlagProvider: featureFlagProvider,
		featureFlagName:     featureFlagName,
	}
}

// GetActiveFilterType returns a string describing which filter is currently active,
// including feature flag information.
func (h *FeatureFlagMigrationHelper) GetActiveFilterType() string {
	baseType := h.MigrationHelper.GetActiveFilterType()
	if h.featureFlagProvider.IsEnabled(h.featureFlagName) {
		return baseType + " (feature flag enabled)"
	}
	return baseType + " (feature flag disabled)"
}

// IsFeatureFlagEnabled returns whether the feature flag is currently enabled.
func (h *FeatureFlagMigrationHelper) IsFeatureFlagEnabled() bool {
	return h.featureFlagProvider.IsEnabled(h.featureFlagName)
}

// GetFeatureFlagName returns the name of the feature flag being used.
func (h *FeatureFlagMigrationHelper) GetFeatureFlagName() string {
	return h.featureFlagName
}
