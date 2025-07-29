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
// Pipeline Intention Filter Factory
//////////////////////////////////////////////////////////////////////////////

// PipelineIntentionFilterFactory creates filters specifically for pipeline intention filtering.
//
// This factory creates a filter that:
// 1. Only evaluates packages that contain rules with pipeline_intention metadata
// 2. Only includes rules that have pipeline_intention matching the configured values
// 3. Excludes rules without pipeline_intention metadata when pipeline_intention is configured
type PipelineIntentionFilterFactory struct{}

func NewPipelineIntentionFilterFactory() FilterFactory {
	return &PipelineIntentionFilterFactory{}
}

// CreateFilters creates a pipeline intention filter based on the source configuration.
//
// Behavior:
//   - When pipeline_intention is set in ruleData: only include packages with rules
//     that have matching pipeline_intention metadata
//   - When pipeline_intention is NOT set in ruleData: only include packages with rules
//     that have NO pipeline_intention metadata (general-purpose rules)
func (f *PipelineIntentionFilterFactory) CreateFilters(source ecc.Source) []RuleFilter {
	// Extract single pipeline_intention string from policy config
	targetIntention := extractStringFromRuleData(source, "pipeline_intention")
	var targetIntentions []string
	if targetIntention != "" {
		targetIntentions = []string{targetIntention}
	}
	return []RuleFilter{NewPipelineIntentionFilter(targetIntentions)}
}

//////////////////////////////////////////////////////////////////////////////
// Pipeline Intention Filter
//////////////////////////////////////////////////////////////////////////////

// PipelineIntentionFilter filters packages based on pipeline_intention metadata.
//
// This filter ensures that only rules appropriate for the current pipeline context
// are evaluated. It works by examining the pipeline_intention metadata in each rule
// and comparing it against the configured pipeline_intention value.
//
// The relationship:
// - Policy Config: pipeline_intention is a SINGLE string (e.g., "release")
// - Rule Metadata: pipeline_intention is a LIST of strings (e.g., ["release", "production"])
//
// Behavior:
// - When targetIntention is empty (no pipeline_intention configured):
//   - Only includes packages with rules that have NO pipeline_intention metadata
//   - This allows general-purpose rules to run in default contexts
//
// - When targetIntention is set (pipeline_intention configured):
//   - Only includes packages with rules that have the target value in their pipeline_intention list
//   - This ensures only pipeline-specific rules are evaluated
//
// Examples:
// - Config: pipeline_intention: "release"
//   - Rule with pipeline_intention: ["release", "production"] → INCLUDED (contains "release")
//   - Rule with pipeline_intention: ["staging"] → EXCLUDED (doesn't contain "release")
//   - Rule with no pipeline_intention metadata → EXCLUDED
//
// - Config: no pipeline_intention set
//   - Rule with pipeline_intention: ["release"] → EXCLUDED
//   - Rule with no pipeline_intention metadata → INCLUDED
type PipelineIntentionFilter struct {
	targetIntentions []string
}

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
				log.Debugf("PipelineIntentionFilter: Excluding package with pipeline_intention metadata")
				return false // Exclude packages with pipeline_intention metadata
			}
		}
		log.Debugf("PipelineIntentionFilter: Including package with no pipeline_intention metadata")
		return true // Include packages with no pipeline_intention metadata
	}

	// When pipeline_intention is set, only include packages that contain rules with matching pipeline_intention metadata
	// This ensures only pipeline-specific rules are evaluated
	for _, r := range rules {
		for _, ruleIntention := range r.PipelineIntention {
			for _, targetIntention := range f.targetIntentions {
				if ruleIntention == targetIntention {
					log.Debugf("PipelineIntentionFilter: Including package with matching pipeline_intention: %s", targetIntention)
					return true // Include packages with matching pipeline_intention metadata
				}
			}
		}
	}
	log.Debugf("PipelineIntentionFilter: Excluding package with no matching pipeline_intention metadata")
	return false // Exclude packages with no matching pipeline_intention metadata
}

//////////////////////////////////////////////////////////////////////////////
// NamespaceFilter – applies all filters (logical AND)
//////////////////////////////////////////////////////////////////////////////

// NamespaceFilter applies multiple filters using AND logic.
//
// This filter combines multiple RuleFilter instances and only includes packages
// that pass ALL filters. This allows for complex filtering scenarios where
// multiple criteria must be satisfied.
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

// extractStringFromRuleData extracts a single string value from the ruleData JSON.
//
// This function is similar to extractStringArrayFromRuleData but extracts a single
// string value instead of an array. It's used for configuration values that are
// single strings rather than arrays.
func extractStringFromRuleData(src ecc.Source, key string) string {
	if src.RuleData == nil {
		return ""
	}

	var data map[string]interface{}
	if err := json.Unmarshal(src.RuleData.Raw, &data); err != nil {
		log.Debugf("Failed to unmarshal ruleData: %v", err)
		return ""
	}

	if value, exists := data[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
		log.Debugf("RuleData key '%s' is not a string: %T", key, value)
	}
	return ""
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
