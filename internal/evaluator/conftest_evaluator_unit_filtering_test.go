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

// This file contains unit tests related to include/exclude logic, matcher generation,
// and result filtering functionality. It includes tests for:
// - Include/exclude criteria handling (TestConftestEvaluatorIncludeExclude)
// - Matcher generation for rule matching (TestMakeMatchers)
// - Name scoring for rule prioritization (TestNameScoring)
// - Result trimming functionality (TestCheckResultsTrim)
// These tests focus on the filtering and rule matching aspects of the evaluator.

//go:build unit

package evaluator

import (
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
)

func TestConftestEvaluatorIncludeExclude(t *testing.T) {
	tests := []struct {
		name    string
		results []Outcome
		config  *ecc.EnterpriseContractPolicyConfiguration
		want    []Outcome
	}{
		{
			name: "exclude by package name",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mockTestRunner{}
			dl := mockDownloader{}
			inputs := EvaluationTarget{Inputs: []string{"inputs"}}
			ctx := setupTestContext(&r, &dl)
			r.On("Run", ctx, inputs.Inputs).Return(tt.results, Data(nil), nil)

			p, err := policy.NewOfflinePolicy(ctx, policy.Now)
			assert.NoError(t, err)

			p = p.WithSpec(ecc.EnterpriseContractPolicySpec{
				Configuration: tt.config,
			})

			sourceConfig := ecc.Source{
				Config: &ecc.SourceConfig{
					Include: tt.config.Include,
					Exclude: tt.config.Exclude,
				},
			}

			evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
				testPolicySource{},
			}, p, sourceConfig, []string{})

			assert.NoError(t, err)
			got, err := evaluator.Evaluate(ctx, inputs)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMakeMatchers(t *testing.T) {
	cases := []struct {
		name string
		code string
		term any
		want []string
	}{
		{
			name: "valid", code: "breakfast.spam", term: "eggs",
			want: []string{
				"breakfast", "breakfast.*", "breakfast.spam", "breakfast:eggs", "breakfast.*:eggs",
				"breakfast.spam:eggs", "*",
			},
		},
		{
			name: "valid without term", code: "breakfast.spam",
			want: []string{"breakfast", "breakfast.*", "breakfast.spam", "*"},
		},
		{name: "incomplete code", code: "spam", want: []string{"*"}},
		{name: "empty code", code: "", want: []string{"*"}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			result := Result{Metadata: map[string]any{}}
			if tt.code != "" {
				result.Metadata["code"] = tt.code
			}
			if tt.term != "" {
				result.Metadata["term"] = tt.term
			}
			assert.Equal(t, tt.want, LegacyMakeMatchers(result))
		})
	}
}

func TestNameScoring(t *testing.T) {
	cases := []struct {
		name  string
		score int
	}{
		{
			name:  "*",
			score: 1,
		},
		{
			name:  "pkg",
			score: 10,
		},
		{
			name:  "pkg.rule",
			score: 110,
		},
		{
			name:  "pkg:term",
			score: 110,
		},
		{
			name:  "pkg.rule:term",
			score: 210,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.score, LegacyScore(c.name))
		})
	}
}

func TestCheckResultsTrim(t *testing.T) {
	cases := []struct {
		name     string
		given    []Outcome
		expected []Outcome
	}{
		{
			name: "simple dependency",
			given: []Outcome{
				{
					Failures: []Result{
						{
							Message: "failure 1",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure1",
							},
						},
					},
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success1",
								metadataDependsOn: []string{"a.failure1"},
							},
						},
					},
				},
			},
			expected: []Outcome{
				{
					Failures: []Result{
						{
							Message: "failure 1",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure1",
							},
						},
					},
					Successes: []Result{},
				},
			},
		},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trim(&cases[i].given)
			assert.Equal(t, c.expected, c.given)
		})
	}
}

// TestIsResultIncludedWithComponentName tests the isResultIncluded method
// with the componentName parameter to ensure component-based filtering works correctly.
// This test exercises the legacy fallback path for backward compatibility.
func TestIsResultIncludedWithComponentName(t *testing.T) {
	tests := []struct {
		name          string
		result        Result
		imageRef      string
		componentName string
		include       *Criteria
		exclude       *Criteria
		expected      bool
	}{
		{
			name: "include by component name",
			result: Result{
				Metadata: map[string]any{"code": "test.check_a"},
			},
			imageRef:      "quay.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			componentName: "my-component",
			include: &Criteria{
				digestItems: map[string][]string{},
				componentItems: map[string][]string{
					"my-component": {"test.check_a"},
				},
				defaultItems: []string{},
			},
			exclude: &Criteria{
				digestItems:    map[string][]string{},
				componentItems: map[string][]string{},
				defaultItems:   []string{},
			},
			expected: true,
		},
		{
			name: "exclude by component name",
			result: Result{
				Metadata: map[string]any{"code": "test.check_b"},
			},
			imageRef:      "quay.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			componentName: "my-component",
			include: &Criteria{
				digestItems:    map[string][]string{},
				componentItems: map[string][]string{},
				defaultItems:   []string{"*"},
			},
			exclude: &Criteria{
				digestItems: map[string][]string{},
				componentItems: map[string][]string{
					"my-component": {"test.check_b"},
				},
				defaultItems: []string{},
			},
			expected: false,
		},
		{
			name: "component-specific include overrides global exclude",
			result: Result{
				Metadata: map[string]any{"code": "test.check_c"},
			},
			imageRef:      "quay.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			componentName: "my-component",
			include: &Criteria{
				digestItems: map[string][]string{},
				componentItems: map[string][]string{
					"my-component": {"test.check_c"},
				},
				defaultItems: []string{},
			},
			exclude: &Criteria{
				digestItems:    map[string][]string{},
				componentItems: map[string][]string{},
				defaultItems:   []string{"test"},
			},
			expected: true,
		},
		{
			name: "different component - not included",
			result: Result{
				Metadata: map[string]any{"code": "test.check_d"},
			},
			imageRef:      "quay.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			componentName: "other-component",
			include: &Criteria{
				digestItems: map[string][]string{},
				componentItems: map[string][]string{
					"my-component": {"test.check_d"},
				},
				defaultItems: []string{},
			},
			exclude: &Criteria{
				digestItems:    map[string][]string{},
				componentItems: map[string][]string{},
				defaultItems:   []string{},
			},
			expected: false,
		},
		{
			name: "empty component name - uses only global criteria",
			result: Result{
				Metadata: map[string]any{"code": "test.check_e"},
			},
			imageRef:      "quay.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			componentName: "",
			include: &Criteria{
				digestItems: map[string][]string{},
				componentItems: map[string][]string{
					"my-component": {"test.check_e"},
				},
				defaultItems: []string{"*"},
			},
			exclude: &Criteria{
				digestItems:    map[string][]string{},
				componentItems: map[string][]string{},
				defaultItems:   []string{},
			},
			expected: true, // Matches global "*"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := conftestEvaluator{
				include: tt.include,
				exclude: tt.exclude,
			}
			missingIncludes := map[string]bool{}
			got := evaluator.isResultIncluded(tt.result, tt.imageRef, tt.componentName, missingIncludes)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestComputeSuccessesLegacyFallback tests the computeSuccesses method with nil unifiedFilter
// to exercise the legacy fallback path that uses isResultIncluded directly.
// This ensures backward compatibility and provides coverage for the legacy code path.
func TestComputeSuccessesLegacyFallback(t *testing.T) {
	tests := []struct {
		name            string
		result          Outcome
		rules           policyRules
		imageRef        string
		componentName   string
		missingIncludes map[string]bool
		include         *Criteria
		exclude         *Criteria
		expectedCount   int
		expectedCodes   []string
	}{
		{
			name: "include success by component name - legacy path",
			result: Outcome{
				Namespace: "test",
				Failures:  []Result{},
				Warnings:  []Result{},
				Skipped:   []Result{},
			},
			rules: policyRules{
				"test.success_rule": {
					Code:      "test.success_rule",
					Package:   "test",
					ShortName: "success_rule",
					Title:     "Success Rule",
				},
			},
			imageRef:        "quay.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			componentName:   "my-component",
			missingIncludes: map[string]bool{},
			include: &Criteria{
				digestItems: map[string][]string{},
				componentItems: map[string][]string{
					"my-component": {"test.success_rule"},
				},
				defaultItems: []string{},
			},
			exclude: &Criteria{
				digestItems:    map[string][]string{},
				componentItems: map[string][]string{},
				defaultItems:   []string{},
			},
			expectedCount: 1,
			expectedCodes: []string{"test.success_rule"},
		},
		{
			name: "exclude success by component name - legacy path",
			result: Outcome{
				Namespace: "test",
				Failures:  []Result{},
				Warnings:  []Result{},
				Skipped:   []Result{},
			},
			rules: policyRules{
				"test.excluded_rule": {
					Code:      "test.excluded_rule",
					Package:   "test",
					ShortName: "excluded_rule",
					Title:     "Excluded Rule",
				},
			},
			imageRef:        "quay.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			componentName:   "my-component",
			missingIncludes: map[string]bool{},
			include: &Criteria{
				digestItems:    map[string][]string{},
				componentItems: map[string][]string{},
				defaultItems:   []string{"*"},
			},
			exclude: &Criteria{
				digestItems: map[string][]string{},
				componentItems: map[string][]string{
					"my-component": {"test.excluded_rule"},
				},
				defaultItems: []string{},
			},
			expectedCount: 0,
			expectedCodes: []string{},
		},
		{
			name: "multiple rules with mixed inclusion - legacy path",
			result: Outcome{
				Namespace: "test",
				Failures:  []Result{},
				Warnings:  []Result{},
				Skipped:   []Result{},
			},
			rules: policyRules{
				"test.included_rule": {
					Code:      "test.included_rule",
					Package:   "test",
					ShortName: "included_rule",
					Title:     "Included Rule",
				},
				"test.excluded_rule": {
					Code:      "test.excluded_rule",
					Package:   "test",
					ShortName: "excluded_rule",
					Title:     "Excluded Rule",
				},
			},
			imageRef:        "quay.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			componentName:   "my-component",
			missingIncludes: map[string]bool{},
			include: &Criteria{
				digestItems: map[string][]string{},
				componentItems: map[string][]string{
					"my-component": {"test.included_rule"},
				},
				defaultItems: []string{},
			},
			exclude: &Criteria{
				digestItems:    map[string][]string{},
				componentItems: map[string][]string{},
				defaultItems:   []string{},
			},
			expectedCount: 1,
			expectedCodes: []string{"test.included_rule"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := conftestEvaluator{
				include: tt.include,
				exclude: tt.exclude,
			}

			// Call computeSuccesses with nil unifiedFilter to exercise the legacy path
			successes := evaluator.computeSuccesses(
				tt.result,
				tt.rules,
				tt.imageRef,
				tt.componentName,
				tt.missingIncludes,
				nil, // nil unifiedFilter triggers the legacy fallback path
				time.Now(),
			)

			assert.Equal(t, tt.expectedCount, len(successes), "unexpected number of successes")

			// Verify the expected codes are present
			actualCodes := make([]string, 0, len(successes))
			for _, success := range successes {
				if code, ok := success.Metadata[metadataCode].(string); ok {
					actualCodes = append(actualCodes, code)
				}
			}
			assert.ElementsMatch(t, tt.expectedCodes, actualCodes, "unexpected success codes")
		})
	}
}
