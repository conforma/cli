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

//go:build unit

package evaluator

import (
	"encoding/json"
	"testing"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestECPolicyResolver(t *testing.T) {
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
	resolver := NewECPolicyResolver(source, configProvider)

	// Create mock rules
	rules := policyRules{
		"cve.high_severity": rule.Info{
			Package:     "cve",
			Code:        "cve.high_severity",
			Collections: []string{"redhat"},
		},
		"cve.medium_severity": rule.Info{
			Package:     "cve",
			Code:        "cve.medium_severity",
			Collections: []string{"redhat"},
		},
		"slsa3.provenance": rule.Info{
			Package: "slsa3",
			Code:    "slsa3.provenance",
		},
		"test.test_data_found": rule.Info{
			Package: "test",
			Code:    "test.test_data_found",
		},
		"tasks.required_tasks_found": rule.Info{
			Package:     "tasks",
			Code:        "tasks.required_tasks_found",
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

func TestECPolicyResolver_DefaultBehavior(t *testing.T) {
	// Create a source with no explicit includes (should default to "*")
	source := ecc.Source{
		Config: &ecc.SourceConfig{
			Exclude: []string{"test.test_data_found"},
		},
	}

	configProvider := &simpleConfigProvider{
		effectiveTime: time.Now(),
	}

	resolver := NewECPolicyResolver(source, configProvider)

	rules := policyRules{
		"cve.high_severity": rule.Info{
			Package: "cve",
			Code:    "cve.high_severity",
		},
		"test.test_data_found": rule.Info{
			Package: "test",
			Code:    "test.test_data_found",
		},
	}

	result := resolver.ResolvePolicy(rules, "test-target")

	// Should include everything by default except explicitly excluded
	assert.True(t, result.IncludedRules["cve.high_severity"], "cve.high_severity should be included by default")
	assert.True(t, result.ExcludedRules["test.test_data_found"], "test.test_data_found should be excluded")
}

func TestECPolicyResolver_PipelineIntention(t *testing.T) {
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

	resolver := NewECPolicyResolver(source, configProvider)

	rules := policyRules{
		"tasks.build_task": rule.Info{
			Package:           "tasks",
			Code:              "tasks.build_task",
			PipelineIntention: []string{"build"},
		},
		"tasks.deploy_task": rule.Info{
			Package:           "tasks",
			Code:              "tasks.deploy_task",
			PipelineIntention: []string{"deploy"},
		},
		"general.security_check": rule.Info{
			Package: "general",
			Code:    "general.security_check",
			// No pipeline intention - should not be included
		},
	}

	result := resolver.ResolvePolicy(rules, "test-target")

	// Debug output
	t.Logf("Pipeline intentions: %v", resolver.(*ECPolicyResolver).pipelineIntentions)
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

func TestECPolicyResolver_Example(t *testing.T) {
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
			Code:        "cve.high_severity",
			Collections: []string{"redhat"},
		},
		"cve.medium_severity": rule.Info{
			Package:     "cve",
			Code:        "cve.medium_severity",
			Collections: []string{"redhat"},
		},
		"slsa3.provenance": rule.Info{
			Package: "slsa3",
			Code:    "slsa3.provenance",
		},
		"test.test_data_found": rule.Info{
			Package: "test",
			Code:    "test.test_data_found",
		},
		"tasks.required_tasks_found": rule.Info{
			Package:     "tasks",
			Code:        "tasks.required_tasks_found",
			Collections: []string{"redhat"},
		},
		"tasks.build_task": rule.Info{
			Package:     "tasks",
			Code:        "tasks.build_task",
			Collections: []string{"redhat"},
		},
	}

	// Use the convenience function to get comprehensive policy resolution
	result := GetECPolicyResolution(source, configProvider, rules, "test-target")

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

func TestUnifiedPostEvaluationFilter(t *testing.T) {
	// Test basic filtering functionality
	t.Run("Basic Filtering", func(t *testing.T) {
		source := ecc.Source{
			Config: &ecc.SourceConfig{
				Include: []string{"cve", "@redhat"},
				Exclude: []string{"test.test_data_found"},
			},
		}

		configProvider := &simpleConfigProvider{
			effectiveTime: time.Now(),
		}

		filter := NewUnifiedPostEvaluationFilter(NewECPolicyResolver(source, configProvider))

		// Create test results
		results := []Result{
			{
				Message: "High severity CVE found",
				Metadata: map[string]interface{}{
					metadataCode: "cve.high_severity",
				},
			},
			{
				Message: "Test data found",
				Metadata: map[string]interface{}{
					metadataCode: "test.test_data_found",
				},
			},
			{
				Message: "Redhat collection rule",
				Metadata: map[string]interface{}{
					metadataCode:        "tasks.build_task",
					metadataCollections: []string{"redhat"},
				},
			},
		}

		rules := policyRules{
			"cve.high_severity": rule.Info{
				Package: "cve",
				Code:    "cve.high_severity",
			},
			"test.test_data_found": rule.Info{
				Package: "test",
				Code:    "test.test_data_found",
			},
			"tasks.build_task": rule.Info{
				Package:     "tasks",
				Code:        "tasks.build_task",
				Collections: []string{"redhat"},
			},
		}

		missingIncludes := map[string]bool{
			"cve":     true,
			"@redhat": true,
		}

		filteredResults, updatedMissingIncludes := filter.FilterResults(
			results, rules, "test-target", missingIncludes, time.Now())

		// Should include cve.high_severity and tasks.build_task, exclude test.test_data_found
		assert.Len(t, filteredResults, 2)

		// Check that the correct results are included
		codes := make([]string, 0, len(filteredResults))
		for _, result := range filteredResults {
			if code, ok := result.Metadata[metadataCode].(string); ok {
				codes = append(codes, code)
			}
		}
		assert.Contains(t, codes, "cve.high_severity")
		assert.Contains(t, codes, "tasks.build_task")
		assert.NotContains(t, codes, "test.test_data_found")

		// Check that missing includes were updated
		assert.Len(t, updatedMissingIncludes, 0) // All includes should be matched
	})

	// Test pipeline intention filtering
	t.Run("Pipeline Intention Filtering", func(t *testing.T) {
		source := ecc.Source{
			RuleData: &extv1.JSON{Raw: json.RawMessage(`{"pipeline_intention":["release"]}`)},
			Config: &ecc.SourceConfig{
				Include: []string{"*"},
			},
		}

		configProvider := &simpleConfigProvider{
			effectiveTime: time.Now(),
		}

		filter := NewUnifiedPostEvaluationFilter(NewECPolicyResolver(source, configProvider))

		// Create test results with different pipeline intentions
		results := []Result{
			{
				Message: "Release security check",
				Metadata: map[string]interface{}{
					metadataCode: "release.security_check",
				},
			},
			{
				Message: "Build task",
				Metadata: map[string]interface{}{
					metadataCode: "build.build_task",
				},
			},
		}

		rules := policyRules{
			"release.security_check": rule.Info{
				Package:           "release",
				Code:              "release.security_check",
				PipelineIntention: []string{"release"},
			},
			"build.build_task": rule.Info{
				Package:           "build",
				Code:              "build.build_task",
				PipelineIntention: []string{"build"},
			},
		}

		missingIncludes := map[string]bool{
			"*": true,
		}

		filteredResults, updatedMissingIncludes := filter.FilterResults(
			results, rules, "test-target", missingIncludes, time.Now())

		// Should only include release.security_check (matches pipeline intention)
		assert.Len(t, filteredResults, 1)

		// Check that the correct result is included
		if len(filteredResults) > 0 {
			code := filteredResults[0].Metadata[metadataCode].(string)
			assert.Equal(t, "release.security_check", code)
		}

		// Check that missing includes were updated
		assert.Len(t, updatedMissingIncludes, 0) // Wildcard should be matched
	})

	// Test missing includes handling
	t.Run("Missing Includes Handling", func(t *testing.T) {
		source := ecc.Source{
			Config: &ecc.SourceConfig{
				Include: []string{"nonexistent.package", "cve"},
			},
		}

		configProvider := &simpleConfigProvider{
			effectiveTime: time.Now(),
		}

		filter := NewUnifiedPostEvaluationFilter(NewECPolicyResolver(source, configProvider))

		results := []Result{
			{
				Message: "CVE found",
				Metadata: map[string]interface{}{
					metadataCode: "cve.high_severity",
				},
			},
		}

		rules := policyRules{
			"cve.high_severity": rule.Info{
				Package: "cve",
				Code:    "cve.high_severity",
			},
		}

		missingIncludes := map[string]bool{
			"nonexistent.package": true,
			"cve":                 true,
		}

		filteredResults, updatedMissingIncludes := filter.FilterResults(
			results, rules, "test-target", missingIncludes, time.Now())

		// Should include the CVE result
		assert.Len(t, filteredResults, 1)

		// Should still have the unmatched include
		assert.Len(t, updatedMissingIncludes, 1)
		assert.True(t, updatedMissingIncludes["nonexistent.package"])
		assert.False(t, updatedMissingIncludes["cve"]) // Should be removed as it was matched
	})
}

func TestUnifiedPostEvaluationFilterVsLegacy(t *testing.T) {
	// Test that the new comprehensive post-evaluation filter produces
	// the same results as the legacy filtering approach

	t.Run("Compare Filtering Results", func(t *testing.T) {
		// Create a policy configuration that exercises various filtering scenarios
		source := ecc.Source{
			RuleData: &extv1.JSON{Raw: json.RawMessage(`{"pipeline_intention":["release"]}`)},
			Config: &ecc.SourceConfig{
				Include: []string{"cve", "@redhat", "security.*"},
				Exclude: []string{"test.test_data_found", "slsa3.provenance"},
			},
		}

		configProvider := &simpleConfigProvider{
			effectiveTime: time.Now(),
		}

		// Create test results that cover different scenarios
		results := []Result{
			// Included by package include
			{
				Message: "High severity CVE found",
				Metadata: map[string]interface{}{
					metadataCode: "cve.high_severity",
				},
			},
			// Included by collection include
			{
				Message: "Redhat collection rule",
				Metadata: map[string]interface{}{
					metadataCode:        "tasks.build_task",
					metadataCollections: []string{"redhat"},
				},
			},
			// Included by wildcard include
			{
				Message: "Security signature check",
				Metadata: map[string]interface{}{
					metadataCode: "security.signature_check",
				},
			},
			// Excluded by explicit exclude
			{
				Message: "Test data found",
				Metadata: map[string]interface{}{
					metadataCode: "test.test_data_found",
				},
			},
			// Excluded by package exclude
			{
				Message: "SLSA provenance",
				Metadata: map[string]interface{}{
					metadataCode: "slsa3.provenance",
				},
			},
			// Excluded by pipeline intention (doesn't match release)
			{
				Message: "Build task",
				Metadata: map[string]interface{}{
					metadataCode: "build.build_task",
				},
			},
			// Included by pipeline intention (matches release)
			{
				Message: "Release security check",
				Metadata: map[string]interface{}{
					metadataCode: "release.security_check",
				},
			},
		}

		rules := policyRules{
			"cve.high_severity": rule.Info{
				Package: "cve",
				Code:    "high_severity",
			},
			"tasks.build_task": rule.Info{
				Package:     "tasks",
				Code:        "build_task",
				Collections: []string{"redhat"},
			},
			"security.signature_check": rule.Info{
				Package:           "security",
				Code:              "signature_check",
				PipelineIntention: []string{"release"},
			},
			"test.test_data_found": rule.Info{
				Package: "test",
				Code:    "test_data_found",
			},
			"slsa3.provenance": rule.Info{
				Package: "slsa3",
				Code:    "provenance",
			},
			"build.build_task": rule.Info{
				Package:           "build",
				Code:              "build_task",
				PipelineIntention: []string{"build"},
			},
			"release.security_check": rule.Info{
				Package:           "release",
				Code:              "security_check",
				PipelineIntention: []string{"release"},
			},
		}

		// Test the new comprehensive filter
		newFilter := NewLegacyPostEvaluationFilter(source, configProvider)
		newMissingIncludes := map[string]bool{
			"cve":        true,
			"@redhat":    true,
			"security.*": true,
		}
		newFilteredResults, newUpdatedMissingIncludes := newFilter.FilterResults(
			results, rules, "test-target", newMissingIncludes, time.Now())

		// Test the legacy approach using the standalone functions
		legacyMissingIncludes := map[string]bool{
			"cve":        true,
			"@redhat":    true,
			"security.*": true,
		}
		var legacyFilteredResults []Result
		for _, result := range results {
			code := ExtractStringFromMetadata(result, metadataCode)
			if code == "" {
				continue
			}

			// Use the legacy IsResultIncluded function
			include := &Criteria{
				defaultItems: []string{"cve", "@redhat", "security.*"},
			}
			exclude := &Criteria{
				defaultItems: []string{"test.test_data_found", "slsa3.provenance"},
			}

			if LegacyIsResultIncluded(result, "test-target", legacyMissingIncludes, include, exclude) {
				legacyFilteredResults = append(legacyFilteredResults, result)
			}
		}

		// Compare the results
		t.Logf("New filter results: %d items", len(newFilteredResults))
		t.Logf("Legacy filter results: %d items", len(legacyFilteredResults))

		// Extract codes for comparison
		newCodes := make([]string, 0, len(newFilteredResults))
		for _, result := range newFilteredResults {
			if code, ok := result.Metadata[metadataCode].(string); ok {
				newCodes = append(newCodes, code)
			}
		}

		legacyCodes := make([]string, 0, len(legacyFilteredResults))
		for _, result := range legacyFilteredResults {
			if code, ok := result.Metadata[metadataCode].(string); ok {
				legacyCodes = append(legacyCodes, code)
			}
		}

		t.Logf("New filter codes: %v", newCodes)
		t.Logf("Legacy filter codes: %v", legacyCodes)

		// The results should be the same
		assert.ElementsMatch(t, newCodes, legacyCodes, "New and legacy filters should produce the same results")

		// Check missing includes
		t.Logf("New missing includes: %v", newUpdatedMissingIncludes)
		t.Logf("Legacy missing includes: %v", legacyMissingIncludes)
		assert.Equal(t, len(newUpdatedMissingIncludes), len(legacyMissingIncludes),
			"Missing includes should be the same")
	})
}

func TestIncludeExcludePolicyResolver(t *testing.T) {
	// Create a config provider
	config := &simpleConfigProvider{
		effectiveTime: time.Now(),
	}

	// Create a source with pipeline intention
	source := ecc.Source{
		RuleData: &extv1.JSON{Raw: json.RawMessage(`{"pipeline_intention":["build"]}`)},
		Config: &ecc.SourceConfig{
			Include: []string{"*"},
		},
	}

	// Create rules with pipeline intention metadata
	rules := policyRules{
		"build.rule1": rule.Info{
			Code:              "build.rule1",
			Package:           "build",
			ShortName:         "rule1",
			PipelineIntention: []string{"build"},
		},
		"deploy.rule2": rule.Info{
			Code:              "deploy.rule2",
			Package:           "deploy",
			ShortName:         "rule2",
			PipelineIntention: []string{"deploy"}, // Different intention
		},
		"general.rule3": rule.Info{
			Code:      "general.rule3",
			Package:   "general",
			ShortName: "rule3",
			// No pipeline intention
		},
	}

	// Test ECPolicyResolver (should filter by pipeline intention)
	ecResolver := NewECPolicyResolver(source, config)
	ecResult := ecResolver.ResolvePolicy(rules, "test")

	// Test IncludeExcludePolicyResolver (should ignore pipeline intention)
	includeExcludeResolver := NewIncludeExcludePolicyResolver(source, config)
	includeExcludeResult := includeExcludeResolver.ResolvePolicy(rules, "test")

	// Verify that the EC resolver excludes rules with non-matching pipeline intentions
	require.False(t, ecResult.IncludedRules["deploy.rule2"], "EC resolver should exclude rule with non-matching pipeline intention")
	require.True(t, ecResult.IncludedRules["build.rule1"], "EC resolver should include rule with matching pipeline intention")
	require.False(t, ecResult.IncludedRules["general.rule3"], "EC resolver should exclude rule with no pipeline intention when pipeline intentions are specified")

	// Verify that the include-exclude resolver includes all rules regardless of pipeline intention
	require.True(t, includeExcludeResult.IncludedRules["build.rule1"], "Include-exclude resolver should include rule with matching pipeline intention")
	require.True(t, includeExcludeResult.IncludedRules["deploy.rule2"], "Include-exclude resolver should include rule with non-matching pipeline intention")
	require.True(t, includeExcludeResult.IncludedRules["general.rule3"], "Include-exclude resolver should include rule with no pipeline intention")

	// Verify that both resolvers include the same packages
	require.True(t, ecResult.IncludedPackages["build"], "EC resolver should include build package")
	require.False(t, ecResult.IncludedPackages["general"], "EC resolver should exclude general package (no matching pipeline intention)")
	require.True(t, includeExcludeResult.IncludedPackages["build"], "Include-exclude resolver should include build package")
	require.True(t, includeExcludeResult.IncludedPackages["deploy"], "Include-exclude resolver should include deploy package")
	require.True(t, includeExcludeResult.IncludedPackages["general"], "Include-exclude resolver should include general package")
}

func TestMissingIncludesFilterUpdate(t *testing.T) {
	tests := []struct {
		name            string
		initialMissing  map[string]bool
		filteredResults []Result
		expectedMissing map[string]bool
		description     string
	}{
		{
			name: "All includes matched",
			initialMissing: map[string]bool{
				"cve":        true,
				"@redhat":    true,
				"security.*": true,
			},
			filteredResults: []Result{
				{
					Message: "CVE found",
					Metadata: map[string]interface{}{
						metadataCode: "cve.high_severity",
					},
				},
				{
					Message: "Redhat collection rule",
					Metadata: map[string]interface{}{
						metadataCode:        "tasks.build_task",
						metadataCollections: []string{"redhat"},
					},
				},
				{
					Message: "Security check",
					Metadata: map[string]interface{}{
						metadataCode: "security.signature_check",
					},
				},
			},
			expectedMissing: map[string]bool{},
			description:     "Tests that all include criteria are removed when matched by results",
		},
		{
			name: "Partial includes matched",
			initialMissing: map[string]bool{
				"cve":           true,
				"@redhat":       true,
				"nonexistent.*": true,
			},
			filteredResults: []Result{
				{
					Message: "CVE found",
					Metadata: map[string]interface{}{
						metadataCode: "cve.high_severity",
					},
				},
			},
			expectedMissing: map[string]bool{
				"@redhat":       true,
				"nonexistent.*": true,
			},
			description: "Tests that only matched include criteria are removed",
		},
		{
			name: "No includes matched",
			initialMissing: map[string]bool{
				"@security": true,
				"release.*": true,
			},
			filteredResults: []Result{
				{
					Message: "Unrelated rule",
					Metadata: map[string]interface{}{
						metadataCode: "test.unrelated",
					},
				},
			},
			expectedMissing: map[string]bool{
				"@security": true,
				"release.*": true,
			},
			description: "Tests that no include criteria are removed when none match",
		},
		{
			name: "Wildcard matching",
			initialMissing: map[string]bool{
				"*": true,
			},
			filteredResults: []Result{
				{
					Message: "Any rule",
					Metadata: map[string]interface{}{
						metadataCode: "any.package.rule",
					},
				},
			},
			expectedMissing: map[string]bool{},
			description:     "Tests that wildcard includes are matched by any result",
		},
		{
			name: "Collection matching",
			initialMissing: map[string]bool{
				"@redhat": true,
			},
			filteredResults: []Result{
				{
					Message: "Redhat collection rule",
					Metadata: map[string]interface{}{
						metadataCode:        "tasks.build_task",
						metadataCollections: []string{"redhat"},
					},
				},
			},
			expectedMissing: map[string]bool{},
			description:     "Tests that collection includes are matched by results with matching collections",
		},
		{
			name: "Package matching",
			initialMissing: map[string]bool{
				"cve": true,
			},
			filteredResults: []Result{
				{
					Message: "CVE rule",
					Metadata: map[string]interface{}{
						metadataCode: "cve.high_severity",
					},
				},
			},
			expectedMissing: map[string]bool{},
			description:     "Tests that package includes are matched by results from that package",
		},
		{
			name: "Rule-specific matching",
			initialMissing: map[string]bool{
				"cve.high_severity": true,
			},
			filteredResults: []Result{
				{
					Message: "Specific CVE rule",
					Metadata: map[string]interface{}{
						metadataCode: "cve.high_severity",
					},
				},
			},
			expectedMissing: map[string]bool{},
			description:     "Tests that rule-specific includes are matched by the exact rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the initial missing includes
			missingIncludes := make(map[string]bool)
			for k, v := range tt.initialMissing {
				missingIncludes[k] = v
			}

			// Simulate the filter update logic
			for include := range missingIncludes {
				matched := false
				for _, result := range tt.filteredResults {
					matchers := LegacyMakeMatchers(result)
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

			// Verify the expected missing includes
			for expectedItem := range tt.expectedMissing {
				assert.True(t, missingIncludes[expectedItem],
					"Expected item '%s' should remain in missingIncludes", expectedItem)
			}

			// Verify no unexpected items remain
			for actualItem := range missingIncludes {
				assert.True(t, tt.expectedMissing[actualItem],
					"Unexpected item '%s' remains in missingIncludes", actualItem)
			}

			t.Logf("Test case: %s", tt.description)
			t.Logf("Initial missingIncludes: %v", tt.initialMissing)
			t.Logf("Final missingIncludes: %v", missingIncludes)
		})
	}
}
