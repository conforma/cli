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
	"slices"
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
			if slices.Contains(f.targetIntentions, ruleIntention) {
				return true // Include packages with matching pipeline_intention metadata
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
				if slices.Contains(r.Collections, want) {
					return true // Package contains a rule in the specified collection
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
