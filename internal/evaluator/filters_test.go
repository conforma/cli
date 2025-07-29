// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"encoding/json"
	"testing"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/conforma/cli/internal/opa/rule"
)

//////////////////////////////////////////////////////////////////////////////
// test scaffolding
//////////////////////////////////////////////////////////////////////////////

func makeSource(ruleData string, includes []string) ecc.Source {
	s := ecc.Source{}
	if ruleData != "" {
		s.RuleData = &extv1.JSON{Raw: json.RawMessage(ruleData)}
	}
	if len(includes) > 0 {
		s.Config = &ecc.SourceConfig{Include: includes}
	}
	return s
}

// MockRuleSelector implements RuleSelector for testing
type MockRuleSelector struct {
	packagesToEvaluate []string
	shouldReport       map[string]bool
	explainExclusion   map[string]string
	includedRules      map[string][]string
	allRules           map[string]rule.Info
}

func NewMockRuleSelector() *MockRuleSelector {
	return &MockRuleSelector{
		shouldReport:     make(map[string]bool),
		explainExclusion: make(map[string]string),
		includedRules:    make(map[string][]string),
		allRules:         make(map[string]rule.Info),
	}
}

func (m *MockRuleSelector) PackagesToEvaluate(allRules map[string]rule.Info) []string {
	return m.packagesToEvaluate
}

func (m *MockRuleSelector) ShouldReport(ruleID string, imageDigest string, effectiveTime time.Time) bool {
	return m.shouldReport[ruleID]
}

func (m *MockRuleSelector) ExplainExclusion(ruleID string) string {
	return m.explainExclusion[ruleID]
}

func (m *MockRuleSelector) GetIncludedRules(packageName string) []string {
	return m.includedRules[packageName]
}

func (m *MockRuleSelector) SetAllRules(allRules map[string]rule.Info) {
	m.allRules = allRules
}

//////////////////////////////////////////////////////////////////////////////
// UnifiedFilterFactory tests
//////////////////////////////////////////////////////////////////////////////

func TestUnifiedFilterFactory(t *testing.T) {
	mockSelector := NewMockRuleSelector()
	mockSelector.packagesToEvaluate = []string{"pkg1", "pkg2"}

	factory := NewUnifiedFilterFactory(mockSelector)
	source := makeSource(`{"pipeline_intention":"release"}`, []string{"@security"})

	filters := factory.CreateFilters(source)

	assert.Len(t, filters, 1, "Should create exactly one filter")

	// Test that the filter is a UnifiedRuleFilter
	unifiedFilter, ok := filters[0].(*UnifiedRuleFilter)
	assert.True(t, ok, "Filter should be a UnifiedRuleFilter")
	assert.Equal(t, mockSelector, unifiedFilter.selector, "Filter should use the provided selector")
}

//////////////////////////////////////////////////////////////////////////////
// UnifiedRuleFilter tests
//////////////////////////////////////////////////////////////////////////////

func TestUnifiedRuleFilter(t *testing.T) {
	mockSelector := NewMockRuleSelector()
	mockSelector.packagesToEvaluate = []string{"pkg1", "pkg3"}

	filter := NewUnifiedRuleFilter(mockSelector)

	rules := []rule.Info{
		{Code: "pkg1.rule1", Package: "pkg1", ShortName: "rule1"},
		{Code: "pkg2.rule1", Package: "pkg2", ShortName: "rule1"},
		{Code: "pkg3.rule1", Package: "pkg3", ShortName: "rule1"},
	}

	// Test that only packages returned by the selector are included
	assert.True(t, filter.Include("pkg1", rules), "pkg1 should be included")
	assert.False(t, filter.Include("pkg2", rules), "pkg2 should be excluded")
	assert.True(t, filter.Include("pkg3", rules), "pkg3 should be included")
}

func TestUnifiedRuleFilterWithEmptySelector(t *testing.T) {
	mockSelector := NewMockRuleSelector()
	mockSelector.packagesToEvaluate = []string{} // Empty list

	filter := NewUnifiedRuleFilter(mockSelector)

	rules := []rule.Info{
		{Code: "pkg1.rule1", Package: "pkg1", ShortName: "rule1"},
		{Code: "pkg2.rule1", Package: "pkg2", ShortName: "rule1"},
	}

	// Test that no packages are included when selector returns empty list
	assert.False(t, filter.Include("pkg1", rules), "pkg1 should be excluded")
	assert.False(t, filter.Include("pkg2", rules), "pkg2 should be excluded")
}

//////////////////////////////////////////////////////////////////////////////
// PipelineIntentionFilterFactory tests
//////////////////////////////////////////////////////////////////////////////

func TestPipelineIntentionFilterFactory(t *testing.T) {
	tests := []struct {
		name        string
		source      ecc.Source
		wantFilters int
	}{
		{
			name:        "no config",
			source:      ecc.Source{},
			wantFilters: 1, // Always creates one filter
		},
		{
			name:        "pipeline intention only",
			source:      makeSource(`{"pipeline_intention":"release"}`, nil),
			wantFilters: 1,
		},
		{
			name:        "multiple pipeline intentions",
			source:      makeSource(`{"pipeline_intention":["release","production"]}`, nil),
			wantFilters: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			factory := NewPipelineIntentionFilterFactory()
			filters := factory.CreateFilters(tc.source)
			assert.Len(t, filters, tc.wantFilters, tc.name)

			// Test that the filter is a PipelineIntentionFilter
			pipelineFilter, ok := filters[0].(*PipelineIntentionFilter)
			assert.True(t, ok, "Filter should be a PipelineIntentionFilter")
			assert.NotNil(t, pipelineFilter, "Filter should not be nil")
		})
	}
}

//////////////////////////////////////////////////////////////////////////////
// PipelineIntentionFilter tests
//////////////////////////////////////////////////////////////////////////////

func TestPipelineIntentionFilter(t *testing.T) {
	rules := policyRules{
		"release.rule1": {PipelineIntention: []string{"release"}},
		"release.rule2": {PipelineIntention: []string{"release", "production"}},
		"dev.rule1":     {PipelineIntention: []string{"dev"}},
		"general.rule1": {}, // No pipeline_intention metadata
		"general.rule2": {}, // No pipeline_intention metadata
	}

	tests := []struct {
		name        string
		intentions  []string
		wantPkgs    []string
		description string
	}{
		{
			name:        "no intentions - only packages with no pipeline_intention metadata",
			intentions:  nil,
			wantPkgs:    []string{"general"}, // Only general has no pipeline_intention metadata
			description: "When no pipeline_intention is configured, only rules without pipeline_intention metadata are evaluated",
		},
		{
			name:        "single intention - only packages with matching pipeline_intention metadata",
			intentions:  []string{"release"},
			wantPkgs:    []string{"release"}, // Only release has matching pipeline_intention metadata
			description: "When pipeline_intention is set, only rules with matching pipeline_intention metadata are evaluated",
		},
		{
			name:        "multiple intentions - packages with any matching pipeline_intention metadata",
			intentions:  []string{"release", "dev"},
			wantPkgs:    []string{"release", "dev"}, // Both have matching pipeline_intention metadata
			description: "When multiple pipeline_intentions are set, rules with any matching metadata are evaluated",
		},
		{
			name:        "non-existent intention - no packages included",
			intentions:  []string{"staging"},
			wantPkgs:    []string{}, // No packages have matching pipeline_intention metadata
			description: "When pipeline_intention doesn't match any rules, no packages are evaluated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := NewPipelineIntentionFilter(tc.intentions)
			got := filterNamespaces(rules, filter)
			assert.ElementsMatch(t, tc.wantPkgs, got, tc.description)
		})
	}
}

func TestPipelineIntentionFilterWithRulesWithoutMetadata(t *testing.T) {
	// This test demonstrates how filtering works with rules that don't have
	// pipeline_intention metadata, like the example fail_with_data.rego rule.
	rules := policyRules{
		"main.fail_with_data": {}, // Rule without any metadata (like fail_with_data.rego)
		"release.security":    {PipelineIntention: []string{"release"}},
		"dev.validation":      {PipelineIntention: []string{"dev"}},
		"general.basic":       {}, // Another rule without metadata
	}

	tests := []struct {
		name        string
		intentions  []string
		expectedPkg []string
		description string
	}{
		{
			name:        "no pipeline_intention - only rules without metadata",
			intentions:  nil,
			expectedPkg: []string{"main", "general"}, // Only packages with rules that have no pipeline_intention metadata
			description: "When no pipeline_intention is configured, only rules without pipeline_intention metadata are evaluated",
		},
		{
			name:        "pipeline_intention set - only rules with matching metadata",
			intentions:  []string{"release"},
			expectedPkg: []string{"release"}, // Only package with matching pipeline_intention metadata
			description: "When pipeline_intention is set, only rules with matching pipeline_intention metadata are evaluated",
		},
		{
			name:        "pipeline_intention set with multiple values",
			intentions:  []string{"release", "dev"},
			expectedPkg: []string{"release", "dev"}, // Both packages have matching pipeline_intention metadata
			description: "When multiple pipeline_intentions are set, rules with any matching metadata are evaluated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := NewPipelineIntentionFilter(tc.intentions)
			got := filterNamespaces(rules, filter)
			assert.ElementsMatch(t, tc.expectedPkg, got, tc.description)
		})
	}
}

func TestPipelineIntentionFilterCorrectRelationship(t *testing.T) {
	// Test the correct relationship:
	// - Policy Config: pipeline_intention is a SINGLE string (e.g., "release")
	// - Rule Metadata: pipeline_intention is a LIST of strings (e.g., ["release", "production"])

	tests := []struct {
		name            string
		configIntention string   // Single string from policy config
		ruleIntentions  []string // List of strings from rule metadata
		expectedInclude bool
	}{
		{
			name:            "Config has 'release', rule has ['release', 'production'] - should include",
			configIntention: "release",
			ruleIntentions:  []string{"release", "production"},
			expectedInclude: true,
		},
		{
			name:            "Config has 'release', rule has ['staging'] - should exclude",
			configIntention: "release",
			ruleIntentions:  []string{"staging"},
			expectedInclude: false,
		},
		{
			name:            "Config has 'release', rule has no pipeline_intention - should exclude",
			configIntention: "release",
			ruleIntentions:  []string{},
			expectedInclude: false,
		},
		{
			name:            "Config has no pipeline_intention, rule has ['release'] - should exclude",
			configIntention: "",
			ruleIntentions:  []string{"release"},
			expectedInclude: false,
		},
		{
			name:            "Config has no pipeline_intention, rule has no pipeline_intention - should include",
			configIntention: "",
			ruleIntentions:  []string{},
			expectedInclude: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create filter with single intention from config
			var targetIntentions []string
			if tt.configIntention != "" {
				targetIntentions = []string{tt.configIntention}
			}
			filter := NewPipelineIntentionFilter(targetIntentions)

			// Create rule with list of intentions
			rules := []rule.Info{
				{
					Code:              "test.rule",
					Package:           "test",
					ShortName:         "rule",
					PipelineIntention: tt.ruleIntentions,
				},
			}

			// Test the filter
			result := filter.Include("test", rules)
			assert.Equal(t, tt.expectedInclude, result,
				"Config intention: '%s', Rule intentions: %v", tt.configIntention, tt.ruleIntentions)
		})
	}
}

//////////////////////////////////////////////////////////////////////////////
// NamespaceFilter tests
//////////////////////////////////////////////////////////////////////////////

func TestNamespaceFilter(t *testing.T) {
	rules := policyRules{
		"pkg1.rule1": {Package: "pkg1", ShortName: "rule1"},
		"pkg1.rule2": {Package: "pkg1", ShortName: "rule2"},
		"pkg2.rule1": {Package: "pkg2", ShortName: "rule1"},
		"pkg3.rule1": {Package: "pkg3", ShortName: "rule1"},
	}

	// Create mock filters
	mockFilter1 := &MockRuleFilter{includeMap: map[string]bool{"pkg1": true, "pkg2": true, "pkg3": false}}
	mockFilter2 := &MockRuleFilter{includeMap: map[string]bool{"pkg1": true, "pkg2": false, "pkg3": false}}

	namespaceFilter := NewNamespaceFilter(mockFilter1, mockFilter2)
	result := namespaceFilter.Filter(rules)

	// Only pkg1 should pass both filters (AND logic)
	assert.ElementsMatch(t, []string{"pkg1"}, result)
}

func TestNamespaceFilterWithNoFilters(t *testing.T) {
	rules := policyRules{
		"pkg1.rule1": {Package: "pkg1", ShortName: "rule1"},
		"pkg2.rule1": {Package: "pkg2", ShortName: "rule1"},
	}

	namespaceFilter := NewNamespaceFilter() // No filters
	result := namespaceFilter.Filter(rules)

	// When no filters are provided, all packages should be included
	assert.ElementsMatch(t, []string{"pkg1", "pkg2"}, result)
}

func TestNamespaceFilterWithSingleFilter(t *testing.T) {
	rules := policyRules{
		"pkg1.rule1": {Package: "pkg1", ShortName: "rule1"},
		"pkg2.rule1": {Package: "pkg2", ShortName: "rule1"},
	}

	mockFilter := &MockRuleFilter{includeMap: map[string]bool{"pkg1": true, "pkg2": false}}
	namespaceFilter := NewNamespaceFilter(mockFilter)
	result := namespaceFilter.Filter(rules)

	assert.ElementsMatch(t, []string{"pkg1"}, result)
}

// MockRuleFilter implements RuleFilter for testing
type MockRuleFilter struct {
	includeMap map[string]bool
}

func (m *MockRuleFilter) Include(pkg string, rules []rule.Info) bool {
	return m.includeMap[pkg]
}

//////////////////////////////////////////////////////////////////////////////
// Helper function tests
//////////////////////////////////////////////////////////////////////////////

func TestFilterNamespaces(t *testing.T) {
	rules := policyRules{
		"pkg1.rule1": {Package: "pkg1", ShortName: "rule1"},
		"pkg2.rule1": {Package: "pkg2", ShortName: "rule1"},
	}

	mockFilter := &MockRuleFilter{includeMap: map[string]bool{"pkg1": true, "pkg2": false}}
	result := filterNamespaces(rules, mockFilter)

	assert.ElementsMatch(t, []string{"pkg1"}, result)
}

func TestExtractStringArrayFromRuleData(t *testing.T) {
	tests := []struct {
		name     string
		ruleData string
		key      string
		expected []string
	}{
		{
			name:     "single string value",
			ruleData: `{"pipeline_intention":"release"}`,
			key:      "pipeline_intention",
			expected: []string{"release"},
		},
		{
			name:     "array of strings",
			ruleData: `{"pipeline_intention":["release","production"]}`,
			key:      "pipeline_intention",
			expected: []string{"release", "production"},
		},
		{
			name:     "non-existent key",
			ruleData: `{"other_key":"value"}`,
			key:      "pipeline_intention",
			expected: nil,
		},
		{
			name:     "empty ruleData",
			ruleData: "",
			key:      "pipeline_intention",
			expected: nil,
		},
		{
			name:     "invalid JSON",
			ruleData: `{"invalid":json}`,
			key:      "pipeline_intention",
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := ecc.Source{}
			if tc.ruleData != "" {
				source.RuleData = &extv1.JSON{Raw: json.RawMessage(tc.ruleData)}
			}

			result := extractStringArrayFromRuleData(source, tc.key)
			assert.Equal(t, tc.expected, result)
		})
	}
}
