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

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
)

// createTestOutcomeWithBreakfastAndLunch creates a test outcome with breakfast and lunch items
func createTestOutcomeWithBreakfastAndLunch() []Outcome {
	return []Outcome{
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
	}
}

// createExpectedOutcome creates an expected outcome with the given failure and warning codes
func createExpectedOutcome(failureCodes, warningCodes []string) []Outcome {
	failures := make([]Result, len(failureCodes))
	for i, code := range failureCodes {
		failures[i] = Result{Metadata: map[string]any{"code": code}}
	}

	warnings := make([]Result, len(warningCodes))
	for i, code := range warningCodes {
		warnings[i] = Result{Metadata: map[string]any{"code": code}}
	}

	return []Outcome{
		{
			Failures:   failures,
			Warnings:   warnings,
			Skipped:    []Result{},
			Exceptions: []Result{},
		},
	}
}

func TestConftestEvaluatorIncludeExclude(t *testing.T) {
	tests := []struct {
		name    string
		results []Outcome
		config  *ecc.EnterpriseContractPolicyConfiguration
		want    []Outcome
	}{
		{
			name:    "exclude by package name",
			results: createTestOutcomeWithBreakfastAndLunch(),
			config:  &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast"}},
			want:    createExpectedOutcome([]string{"lunch.spam"}, []string{"lunch.ham"}),
		},
		{
			name:    "include by package",
			results: createTestOutcomeWithBreakfastAndLunch(),
			config:  &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast"}},
			want:    createExpectedOutcome([]string{"breakfast.spam"}, []string{"breakfast.ham"}),
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
