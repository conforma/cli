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
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"fmt"
	"strings"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/opa/rule"
)

// RuleSelector provides unified filtering logic for both evaluation-time and reporting-time decisions
type RuleSelector interface {
	// PackagesToEvaluate determines which packages should be evaluated
	// Returns package names that contain at least one rule that should be evaluated
	PackagesToEvaluate(allRules map[string]rule.Info) []string

	// ShouldReport determines if a specific rule should be included in results
	// This handles post-evaluation filtering including volatile exclusions
	ShouldReport(ruleID string, imageDigest string, effectiveTime time.Time) bool

	// ExplainExclusion provides human-readable explanation for why a rule/package is excluded
	ExplainExclusion(ruleID string) string

	// GetIncludedRules returns all rule IDs that should be included for a given package
	// Used for success computation and dependency analysis
	GetIncludedRules(packageName string) []string

	// SetAllRules sets the complete rule set for analysis
	SetAllRules(allRules map[string]rule.Info)
}

// FilterConfig contains the include/exclude configuration
type FilterConfig struct {
	Include []string
	Exclude []string
}

// VolatileExclusion represents a volatile exclusion rule
type VolatileExclusion struct {
	Value          string
	ImageDigest    string
	ImageUrl       string
	EffectiveOn    time.Time
	EffectiveUntil time.Time
	Reference      string
}

// VolatileConfig contains volatile include/exclude rules
type VolatileConfig struct {
	Exclude []VolatileExclusion
}

// ImageContext contains image-specific information
type ImageContext struct {
	Digest string
	URL    string
	Time   time.Time
}

// UnifiedRuleSelector implements the RuleSelector interface using the existing scoring logic
type UnifiedRuleSelector struct {
	config         *FilterConfig
	volatileConfig *VolatileConfig
	effectiveTime  time.Time
	imageContext   *ImageContext
	allRules       map[string]rule.Info
}

// NewUnifiedRuleSelector creates a new unified rule selector
func NewUnifiedRuleSelector(source ecc.Source, policy ConfigProvider, imageContext *ImageContext) RuleSelector {
	config := &FilterConfig{
		Include: source.Config.Include,
		Exclude: source.Config.Exclude,
	}

	if len(config.Include) == 0 {
		config.Include = []string{"*"}
	}

	var volatileConfig *VolatileConfig
	if source.VolatileConfig != nil {
		volatileConfig = &VolatileConfig{
			Exclude: parseVolatileExclusions(source.VolatileConfig.Exclude, policy.EffectiveTime()),
		}
	} else {
		volatileConfig = &VolatileConfig{
			Exclude: []VolatileExclusion{},
		}
	}

	return &UnifiedRuleSelector{
		config:         config,
		volatileConfig: volatileConfig,
		effectiveTime:  policy.EffectiveTime(),
		imageContext:   imageContext,
		allRules:       make(map[string]rule.Info),
	}
}

// parseVolatileExclusions converts volatile config to internal format
func parseVolatileExclusions(volatileCriteria []ecc.VolatileCriteria, effectiveTime time.Time) []VolatileExclusion {
	var exclusions []VolatileExclusion

	for _, c := range volatileCriteria {
		from, err := time.Parse(time.RFC3339, c.EffectiveOn)
		if err != nil {
			if c.EffectiveOn != "" {
				log.Warnf("unable to parse time for criteria %q, was given %q: %v", c.Value, c.EffectiveOn, err)
			}
			from = effectiveTime
		}
		until, err := time.Parse(time.RFC3339, c.EffectiveUntil)
		if err != nil {
			if c.EffectiveUntil != "" {
				log.Warnf("unable to parse time for criteria %q, was given %q: %v", c.Value, c.EffectiveUntil, err)
			}
			until = effectiveTime
		}
		if until.Compare(effectiveTime) >= 0 && from.Compare(effectiveTime) <= 0 {
			exclusion := VolatileExclusion{
				Value:          c.Value,
				EffectiveOn:    from,
				EffectiveUntil: until,
				Reference:      c.Reference,
			}

			// DEPRECATED: use c.ImageDigest instead
			if c.ImageRef != "" {
				exclusion.ImageDigest = c.ImageRef
			} else if c.ImageUrl != "" {
				exclusion.ImageUrl = c.ImageUrl
			} else if c.ImageDigest != "" {
				exclusion.ImageDigest = c.ImageDigest
			}

			exclusions = append(exclusions, exclusion)
		}
	}

	return exclusions
}

// SetAllRules sets the complete rule set for analysis
func (s *UnifiedRuleSelector) SetAllRules(allRules map[string]rule.Info) {
	s.allRules = allRules
}

// PackagesToEvaluate determines which packages should be evaluated
func (s *UnifiedRuleSelector) PackagesToEvaluate(allRules map[string]rule.Info) []string {
	// Group rules by package
	packages := make(map[string][]rule.Info)
	for _, rule := range allRules {
		pkg := rule.Package
		packages[pkg] = append(packages[pkg], rule)
	}

	var includedPackages []string

	for pkg, rules := range packages {
		log.Debugf("Evaluating package %s with %d rules", pkg, len(rules))
		if s.packageHasIncludedRules(pkg, rules) {
			includedPackages = append(includedPackages, pkg)
			log.Debugf("Package %s included for evaluation", pkg)
		} else {
			log.Debugf("Package %s excluded from evaluation", pkg)
		}
	}

	return includedPackages
}

// packageHasIncludedRules checks if any rule in the package would be included
func (s *UnifiedRuleSelector) packageHasIncludedRules(pkg string, rules []rule.Info) bool {
	for _, rule := range rules {
		if s.ruleWouldBeIncluded(rule.Code, rule) {
			log.Debugf("Package %s has included rule: %s", pkg, rule.Code)
			return true
		}
	}
	return false
}

// ruleWouldBeIncluded determines if a rule would be included based on config (no volatile exclusions)
func (s *UnifiedRuleSelector) ruleWouldBeIncluded(ruleID string, rule rule.Info) bool {
	matchers := s.makeMatchers(ruleID, rule)

	includeScore := s.scoreMatches(matchers, s.config.Include, map[string]bool{})
	excludeScore := s.scoreMatches(matchers, s.config.Exclude, map[string]bool{})

	result := includeScore > excludeScore
	log.Debugf("Rule %s: include score=%d, exclude score=%d, included=%v", ruleID, includeScore, excludeScore, result)

	return result
}

// ShouldReport determines if a specific rule should be included in results
func (s *UnifiedRuleSelector) ShouldReport(ruleID string, imageDigest string, effectiveTime time.Time) bool {
	rule, exists := s.allRules[ruleID]
	if !exists {
		log.Debugf("Rule %s not found in rule set", ruleID)
		return false
	}

	// First check if rule would be included based on config
	if !s.ruleWouldBeIncluded(ruleID, rule) {
		log.Debugf("Rule %s excluded by config", ruleID)
		return false
	}

	// Then check volatile exclusions
	for _, exclusion := range s.volatileConfig.Exclude {
		if s.isVolatileExclusionActive(exclusion, ruleID, imageDigest, effectiveTime) {
			log.Debugf("Rule %s excluded by volatile config: %s", ruleID, exclusion.Reference)
			return false
		}
	}

	log.Debugf("Rule %s included for reporting", ruleID)
	return true
}

// isVolatileExclusionActive checks if a volatile exclusion applies
func (s *UnifiedRuleSelector) isVolatileExclusionActive(exclusion VolatileExclusion, ruleID, imageDigest string, effectiveTime time.Time) bool {
	// Check if this exclusion applies to this rule
	if exclusion.Value != ruleID {
		return false
	}

	// Check time constraints
	if !exclusion.EffectiveOn.IsZero() && effectiveTime.Before(exclusion.EffectiveOn) {
		return false
	}
	if !exclusion.EffectiveUntil.IsZero() && effectiveTime.After(exclusion.EffectiveUntil) {
		return false
	}

	// Check image constraints
	if exclusion.ImageDigest != "" && exclusion.ImageDigest != imageDigest {
		return false
	}
	if exclusion.ImageUrl != "" && exclusion.ImageUrl != s.imageContext.URL {
		return false
	}

	return true
}

// ExplainExclusion provides human-readable explanation for why a rule/package is excluded
func (s *UnifiedRuleSelector) ExplainExclusion(ruleID string) string {
	rule, exists := s.allRules[ruleID]
	if !exists {
		return fmt.Sprintf("Rule %s not found in rule set", ruleID)
	}

	// Check config-based exclusion
	if !s.ruleWouldBeIncluded(ruleID, rule) {
		matchers := s.makeMatchers(ruleID, rule)
		includeScore := s.scoreMatches(matchers, s.config.Include, map[string]bool{})
		excludeScore := s.scoreMatches(matchers, s.config.Exclude, map[string]bool{})

		if includeScore == 0 {
			return fmt.Sprintf("Rule %s excluded: no matching include criteria (include score: %d)", ruleID, includeScore)
		}
		return fmt.Sprintf("Rule %s excluded: exclude score (%d) >= include score (%d)", ruleID, excludeScore, includeScore)
	}

	// Check volatile exclusions
	for _, exclusion := range s.volatileConfig.Exclude {
		if exclusion.Value == ruleID {
			reason := fmt.Sprintf("Rule %s excluded by volatile config", ruleID)
			if exclusion.Reference != "" {
				reason += fmt.Sprintf(" (reference: %s)", exclusion.Reference)
			}
			if !exclusion.EffectiveUntil.IsZero() {
				reason += fmt.Sprintf(" until %s", exclusion.EffectiveUntil.Format(time.RFC3339))
			}
			return reason
		}
	}

	return fmt.Sprintf("Rule %s would be included", ruleID)
}

// GetIncludedRules returns all rule IDs that should be included for a given package
func (s *UnifiedRuleSelector) GetIncludedRules(packageName string) []string {
	var includedRules []string

	for ruleID, rule := range s.allRules {
		if rule.Package == packageName && s.ruleWouldBeIncluded(ruleID, rule) {
			includedRules = append(includedRules, ruleID)
		}
	}

	return includedRules
}

// makeMatchers generates all possible matching strings for a rule
func (s *UnifiedRuleSelector) makeMatchers(ruleID string, rule rule.Info) []string {
	parts := strings.Split(ruleID, ".")
	var pkg string
	if len(parts) >= 2 {
		pkg = parts[len(parts)-2]
	}
	ruleName := parts[len(parts)-1]

	var matchers []string

	if pkg != "" {
		matchers = append(matchers, pkg, fmt.Sprintf("%s.*", pkg), fmt.Sprintf("%s.%s", pkg, ruleName))
	}

	// Handle terms from rule metadata
	terms := rule.Terms
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

	// Add collections
	for _, collection := range rule.Collections {
		matchers = append(matchers, "@"+collection)
	}

	return matchers
}

// scoreMatches returns the combined score for every match between needles and haystack
func (s *UnifiedRuleSelector) scoreMatches(needles, haystack []string, toBePruned map[string]bool) int {
	var totalScore int
	for _, needle := range needles {
		for _, hay := range haystack {
			if hay == needle {
				totalScore += s.calculateScore(hay)
				delete(toBePruned, hay)
			}
		}
	}
	return totalScore
}

// calculateScore computes the specificity of the given name (reused from existing logic)
func (s *UnifiedRuleSelector) calculateScore(name string) int {
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
		if shortName == "*" {
			value += 1
		} else {
			value += 10
		}
	} else if nameSplitLen > 1 {
		rule := nameSplit[nameSplitLen-1]
		pkg := strings.Join(nameSplit[:nameSplitLen-1], ".")

		if pkg == "*" {
			value += 1
		} else {
			value += 10 * (nameSplitLen - 1)
		}

		if rule != "*" && rule != "" {
			value += 100
		}
	}
	return value
}
