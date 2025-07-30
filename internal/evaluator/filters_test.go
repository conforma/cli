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
	"github.com/conforma/cli/internal/policy"
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

//////////////////////////////////////////////////////////////////////////////
// FilterFactory tests
//////////////////////////////////////////////////////////////////////////////

func TestDefaultFilterFactory(t *testing.T) {
	tests := []struct {
		name        string
		source      ecc.Source
		wantFilters int
	}{
		{
			name:        "no config",
			source:      ecc.Source{},
			wantFilters: 1, // Always adds PipelineIntentionFilter
		},
		{
			name:        "pipeline intention only",
			source:      makeSource(`{"pipeline_intention":"release"}`, nil),
			wantFilters: 1,
		},
		{
			name:        "include list only",
			source:      makeSource("", []string{"@redhat", "cve"}),
			wantFilters: 2, // PipelineIntentionFilter + IncludeListFilter
		},
		{
			name:        "both pipeline_intention and include list",
			source:      makeSource(`{"pipeline_intention":"release"}`, []string{"@redhat", "cve"}),
			wantFilters: 2,
		},
		{
			name:        "no includes and no pipeline_intention - PipelineIntentionFilter still added",
			source:      makeSource("", nil),
			wantFilters: 1, // PipelineIntentionFilter is always added
		},
	}

	for _, tc := range tests {
		got := NewDefaultFilterFactory().CreateFilters(tc.source)
		assert.Len(t, got, tc.wantFilters, tc.name)
	}
}

//////////////////////////////////////////////////////////////////////////////
// IncludeListFilter – core behaviour
//////////////////////////////////////////////////////////////////////////////

func TestIncludeListFilter(t *testing.T) {
	rules := policyRules{
		"pkg.rule":    {Collections: []string{"redhat"}},
		"cve.rule":    {Collections: []string{"security"}},
		"other.rule":  {},
		"labels.rule": {Collections: []string{"security"}},
		"foo.bar":     {},
	}

	tests := []struct {
		name     string
		entries  []string
		wantPkgs []string
	}{
		{
			name:     "@redhat collection",
			entries:  []string{"@redhat"},
			wantPkgs: []string{"pkg"},
		},
		{
			name:     "explicit package",
			entries:  []string{"cve"},
			wantPkgs: []string{"cve"},
		},
		{
			name:     "package.rule entry",
			entries:  []string{"labels.rule"},
			wantPkgs: []string{"labels"},
		},
		{
			name:     "OR across entries",
			entries:  []string{"@redhat", "cve"},
			wantPkgs: []string{"pkg", "cve"},
		},
		{
			name:     "non‑existent entry",
			entries:  []string{"@none"},
			wantPkgs: []string{},
		},
	}

	for _, tc := range tests {
		got := filterNamespaces(rules, NewIncludeListFilter(tc.entries))
		assert.ElementsMatch(t, tc.wantPkgs, got, tc.name)
	}
}

//////////////////////////////////////////////////////////////////////////////
// PipelineIntentionFilter
//////////////////////////////////////////////////////////////////////////////

func TestPipelineIntentionFilter(t *testing.T) {
	rules := policyRules{
		"a.r": {PipelineIntention: []string{"release"}},
		"b.r": {PipelineIntention: []string{"dev"}},
		"c.r": {},
	}

	tests := []struct {
		name       string
		intentions []string
		wantPkgs   []string
	}{
		{
			name:       "no intentions ⇒ only packages with no pipeline_intention metadata",
			intentions: nil,
			wantPkgs:   []string{"c"}, // Only c has no pipeline_intention metadata
		},
		{
			name:       "pipeline_intention set - include packages with matching pipeline_intention metadata",
			intentions: []string{"release"},
			wantPkgs:   []string{"a"}, // Only a has matching pipeline_intention metadata
		},
		{
			name:       "pipeline_intention set with multiple values - include packages with any matching pipeline_intention metadata",
			intentions: []string{"dev", "release"},
			wantPkgs:   []string{"a", "b"}, // Both a and b have matching pipeline_intention metadata
		},
	}

	for _, tc := range tests {
		got := filterNamespaces(rules, NewPipelineIntentionFilter(tc.intentions))
		assert.ElementsMatch(t, tc.wantPkgs, got, tc.name)
	}
}

//////////////////////////////////////////////////////////////////////////////
// Complete filtering behavior tests
//////////////////////////////////////////////////////////////////////////////

func TestCompleteFilteringBehavior(t *testing.T) {
	rules := policyRules{
		"release.rule1": {PipelineIntention: []string{"release"}},
		"release.rule2": {PipelineIntention: []string{"release", "production"}},
		"dev.rule1":     {PipelineIntention: []string{"dev"}},
		"general.rule1": {}, // No pipeline_intention metadata
		"general.rule2": {}, // No pipeline_intention metadata
	}

	tests := []struct {
		name        string
		source      ecc.Source
		expectedPkg []string
	}{
		{
			name:        "no includes and no pipeline_intention - only packages with no pipeline_intention metadata",
			source:      makeSource("", nil),
			expectedPkg: []string{"general"}, // Only general has no pipeline_intention metadata
		},
		{
			name:        "pipeline_intention set - only packages with matching pipeline_intention metadata",
			source:      makeSource(`{"pipeline_intention":"release"}`, nil),
			expectedPkg: []string{"release"}, // Only release has matching pipeline_intention metadata
		},
		{
			name:        "includes set - only matching packages with no pipeline_intention metadata",
			source:      makeSource("", []string{"release", "general"}),
			expectedPkg: []string{"general"}, // Only general has no pipeline_intention metadata and matches includes
		},
		{
			name:        "both pipeline_intention and includes - AND logic",
			source:      makeSource(`{"pipeline_intention":"release"}`, []string{"release"}),
			expectedPkg: []string{"release"}, // Only release matches both conditions
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filterFactory := NewDefaultFilterFactory()
			filters := filterFactory.CreateFilters(tc.source)
			got := filterNamespaces(rules, filters...)
			assert.ElementsMatch(t, tc.expectedPkg, got, tc.name)
		})
	}
}

//////////////////////////////////////////////////////////////////////////////
// Test filtering with rules that don't have metadata
//////////////////////////////////////////////////////////////////////////////

func TestFilteringWithRulesWithoutMetadata(t *testing.T) {
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
		source      ecc.Source
		expectedPkg []string
		description string
	}{
		{
			name:        "no pipeline_intention - only rules without metadata",
			source:      makeSource("", nil),
			expectedPkg: []string{"main", "general"}, // Only packages with rules that have no pipeline_intention metadata
			description: "When no pipeline_intention is configured, only rules without pipeline_intention metadata are evaluated",
		},
		{
			name:        "pipeline_intention set - only rules with matching metadata",
			source:      makeSource(`{"pipeline_intention":"release"}`, nil),
			expectedPkg: []string{"release"}, // Only package with matching pipeline_intention metadata
			description: "When pipeline_intention is set, only rules with matching pipeline_intention metadata are evaluated",
		},
		{
			name:        "includes with no pipeline_intention - only matching rules without metadata",
			source:      makeSource("", []string{"main", "release"}),
			expectedPkg: []string{"main"}, // Only main has no pipeline_intention metadata and matches includes
			description: "When includes are set but no pipeline_intention, only rules without metadata that match includes are evaluated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filterFactory := NewDefaultFilterFactory()
			filters := filterFactory.CreateFilters(tc.source)
			got := filterNamespaces(rules, filters...)
			assert.ElementsMatch(t, tc.expectedPkg, got, tc.description)
		})
	}
}

func TestComprehensivePolicyResolver(t *testing.T) {
	// Create a mock source with policy configuration
	source := ecc.Source{
		Config: &ecc.SourceConfig{
			Include: []string{"cve", "@redhat"},
			Exclude: []string{"slsa3", "test.test_data_found"},
		},
	}

	// Create a simple config provider for testing
	configProvider := &simpleConfigProvider{
		effectiveTime: time.Now(),
	}

	// Create policy resolver
	resolver := NewComprehensivePolicyResolver(source, configProvider)

	// Create mock rules
	rules := policyRules{
		"cve.high_severity": rule.Info{
			Package:     "cve",
			Code:        "high_severity",
			Collections: []string{"redhat"},
		},
		"cve.medium_severity": rule.Info{
			Package:     "cve",
			Code:        "medium_severity",
			Collections: []string{"redhat"},
		},
		"slsa3.provenance": rule.Info{
			Package: "slsa3",
			Code:    "provenance",
		},
		"test.test_data_found": rule.Info{
			Package: "test",
			Code:    "test_data_found",
		},
		"tasks.required_tasks_found": rule.Info{
			Package:     "tasks",
			Code:        "required_tasks_found",
			Collections: []string{"redhat"},
		},
	}

	// Resolve policy
	result := resolver.ResolvePolicy(rules, "test-target")

	// Verify included rules
	assert.True(t, result.IncludedRules["cve.high_severity"], "cve.high_severity should be included")
	assert.True(t, result.IncludedRules["cve.medium_severity"], "cve.medium_severity should be included")
	assert.True(t, result.IncludedRules["tasks.required_tasks_found"], "tasks.required_tasks_found should be included")

	// Verify excluded rules
	assert.True(t, result.ExcludedRules["slsa3.provenance"], "slsa3.provenance should be excluded")
	assert.True(t, result.ExcludedRules["test.test_data_found"], "test.test_data_found should be excluded")

	// Verify included packages
	assert.True(t, result.IncludedPackages["cve"], "cve package should be included")
	assert.True(t, result.IncludedPackages["tasks"], "tasks package should be included")

	// Verify excluded packages
	assert.True(t, result.ExcludedPackages["slsa3"], "slsa3 package should be excluded")
	assert.True(t, result.ExcludedPackages["test"], "test package should be excluded")

	// Verify explanations
	assert.Contains(t, result.Explanations["cve.high_severity"], "included")
	assert.Contains(t, result.Explanations["slsa3.provenance"], "excluded")
}

// simpleConfigProvider is a simple implementation for testing
type simpleConfigProvider struct {
	effectiveTime time.Time
}

func (s *simpleConfigProvider) EffectiveTime() time.Time {
	return s.effectiveTime
}

func (s *simpleConfigProvider) SigstoreOpts() (policy.SigstoreOpts, error) {
	return policy.SigstoreOpts{}, nil
}

func (s *simpleConfigProvider) Spec() ecc.EnterpriseContractPolicySpec {
	return ecc.EnterpriseContractPolicySpec{}
}

func TestComprehensivePolicyResolver_DefaultBehavior(t *testing.T) {
	// Create a source with no explicit includes (should default to "*")
	source := ecc.Source{
		Config: &ecc.SourceConfig{
			Exclude: []string{"test.test_data_found"},
		},
	}

	configProvider := &simpleConfigProvider{
		effectiveTime: time.Now(),
	}

	resolver := NewComprehensivePolicyResolver(source, configProvider)

	rules := policyRules{
		"cve.high_severity": rule.Info{
			Package: "cve",
			Code:    "high_severity",
		},
		"test.test_data_found": rule.Info{
			Package: "test",
			Code:    "test_data_found",
		},
	}

	result := resolver.ResolvePolicy(rules, "test-target")

	// Should include everything by default except explicitly excluded
	assert.True(t, result.IncludedRules["cve.high_severity"], "cve.high_severity should be included by default")
	assert.True(t, result.ExcludedRules["test.test_data_found"], "test.test_data_found should be excluded")
}

func TestComprehensivePolicyResolver_PipelineIntention(t *testing.T) {
	// Create a source with pipeline intention
	source := ecc.Source{
		RuleData: &extv1.JSON{Raw: json.RawMessage(`{"pipeline_intention":["build"]}`)},
		Config: &ecc.SourceConfig{
			Include: []string{"*"},
		},
	}

	configProvider := &simpleConfigProvider{
		effectiveTime: time.Now(),
	}

	resolver := NewComprehensivePolicyResolver(source, configProvider)

	rules := policyRules{
		"tasks.build_task": rule.Info{
			Package:           "tasks",
			Code:              "build_task",
			PipelineIntention: []string{"build"},
		},
		"tasks.deploy_task": rule.Info{
			Package:           "tasks",
			Code:              "deploy_task",
			PipelineIntention: []string{"deploy"},
		},
		"general.security_check": rule.Info{
			Package: "general",
			Code:    "security_check",
			// No pipeline intention - should not be included
		},
	}

	result := resolver.ResolvePolicy(rules, "test-target")

	// Debug output
	t.Logf("Pipeline intentions: %v", resolver.(*ComprehensivePolicyResolver).pipelineIntentions)
	t.Logf("Included rules: %v", result.IncludedRules)
	t.Logf("Excluded rules: %v", result.ExcludedRules)
	t.Logf("Explanations: %v", result.Explanations)

	// Pipeline intention filtering works at package level
	// If any rule in a package matches the pipeline intention, the entire package is included
	assert.True(t, result.IncludedRules["tasks.build_task"], "tasks.build_task should be included")
	assert.True(t, result.IncludedRules["tasks.deploy_task"], "tasks.deploy_task should be included (same package as build_task)")
	assert.False(t, result.IncludedRules["general.security_check"], "general.security_check should not be included")

	// Check package inclusion
	assert.True(t, result.IncludedPackages["tasks"], "tasks package should be included (has included rules)")
	assert.False(t, result.IncludedPackages["general"], "general package should not be included (no included rules)")
}

func TestComprehensivePolicyResolver_Example(t *testing.T) {
	// Example: Using the comprehensive policy resolver with the policy config from the user's example

	// Create a source with the policy configuration from the user's example
	source := ecc.Source{
		Config: &ecc.SourceConfig{
			Include: []string{
				"cve",     // package example
				"@redhat", // collection example
			},
			Exclude: []string{
				"slsa3",                                  // exclude package example
				"test.test_data_found",                   // exclude a rule
				"tasks.required_tasks_found:clamav-scan", // exclude a rule with a term
			},
		},
	}

	configProvider := &simpleConfigProvider{
		effectiveTime: time.Now(),
	}

	// Create mock rules that would be found in the policy
	rules := policyRules{
		"cve.high_severity": rule.Info{
			Package:     "cve",
			Code:        "high_severity",
			Collections: []string{"redhat"},
		},
		"cve.medium_severity": rule.Info{
			Package:     "cve",
			Code:        "medium_severity",
			Collections: []string{"redhat"},
		},
		"slsa3.provenance": rule.Info{
			Package: "slsa3",
			Code:    "provenance",
		},
		"test.test_data_found": rule.Info{
			Package: "test",
			Code:    "test_data_found",
		},
		"tasks.required_tasks_found": rule.Info{
			Package:     "tasks",
			Code:        "required_tasks_found",
			Collections: []string{"redhat"},
		},
		"tasks.build_task": rule.Info{
			Package:     "tasks",
			Code:        "build_task",
			Collections: []string{"redhat"},
		},
	}

	// Use the convenience function to get comprehensive policy resolution
	result := GetComprehensivePolicyResolution(source, configProvider, rules, "test-target")

	// Verify the results
	t.Logf("=== Comprehensive Policy Resolution Results ===")
	t.Logf("Included Rules: %v", result.IncludedRules)
	t.Logf("Excluded Rules: %v", result.ExcludedRules)
	t.Logf("Included Packages: %v", result.IncludedPackages)
	t.Logf("Excluded Packages: %v", result.ExcludedPackages)
	t.Logf("Missing Includes: %v", result.MissingIncludes)
	t.Logf("Explanations: %v", result.Explanations)

	// Expected behavior based on the policy configuration:
	// - cve.high_severity: included (matches "cve" package and "@redhat" collection)
	// - cve.medium_severity: included (matches "cve" package and "@redhat" collection)
	// - slsa3.provenance: excluded (matches "slsa3" package exclusion)
	// - test.test_data_found: excluded (matches "test.test_data_found" rule exclusion)
	// - tasks.required_tasks_found: included (matches "@redhat" collection)
	// - tasks.build_task: included (matches "@redhat" collection)

	assert.True(t, result.IncludedRules["cve.high_severity"], "cve.high_severity should be included")
	assert.True(t, result.IncludedRules["cve.medium_severity"], "cve.medium_severity should be included")
	assert.True(t, result.ExcludedRules["slsa3.provenance"], "slsa3.provenance should be excluded")
	assert.True(t, result.ExcludedRules["test.test_data_found"], "test.test_data_found should be excluded")
	assert.True(t, result.IncludedRules["tasks.required_tasks_found"], "tasks.required_tasks_found should be included")
	assert.True(t, result.IncludedRules["tasks.build_task"], "tasks.build_task should be included")

	// Check package inclusion
	assert.True(t, result.IncludedPackages["cve"], "cve package should be included")
	assert.True(t, result.IncludedPackages["tasks"], "tasks package should be included")
	assert.True(t, result.ExcludedPackages["slsa3"], "slsa3 package should be excluded")
	assert.True(t, result.ExcludedPackages["test"], "test package should be excluded")
}
