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

// This file contains unit tests for rule metadata processing and annotation handling.
// It includes tests for:
// - Annotation data collection (TestCollectAnnotationData)
// - Rule metadata processing (TestRuleMetadata)
// - Rules without metadata handling (TestRulesWithoutMetadata)
// - Warning for rules not showing up (TestWarnRuleNotShowingUp)
// These tests focus on how the evaluator processes and handles rule metadata
// and annotations from OPA policies.

//go:build unit

package evaluator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
)

func TestCollectAnnotationData(t *testing.T) {
	module := ast.MustParseModuleWithOpts(heredoc.Doc(`
		package a.b.c
		import rego.v1

		# METADATA
		# title: Title
		# description: Description
		# custom:
		#   short_name: short
		#   collections: [A, B, C]
		#   effective_on: 2022-01-01T00:00:00Z
		#   depends_on: a.b.c
		#   pipeline_intention: [release, production]
		deny contains msg if {
			msg := "hi"
		}`), ast.ParserOptions{
		ProcessAnnotation: true,
	})

	rules := policyRules{}
	require.NoError(t, rules.collect(ast.NewAnnotationsRef(module.Annotations[0])))

	assert.Equal(t, policyRules{
		"a.b.c.short": {
			Code:              "a.b.c.short",
			Collections:       []string{"A", "B", "C"},
			DependsOn:         []string{"a.b.c"},
			Description:       "Description",
			EffectiveOn:       "2022-01-01T00:00:00Z",
			Kind:              rule.Deny,
			Package:           "a.b.c",
			PipelineIntention: []string{"release", "production"},
			ShortName:         "short",
			Title:             "Title",
			DocumentationUrl:  "https://conforma.dev/docs/policy/packages/release_c.html#c__short",
		},
	}, rules)
}

func TestRuleMetadata(t *testing.T) {
	effectiveOnTest := time.Now().Format(effectiveOnFormat)

	effectiveTimeTest := time.Now().Add(-24 * time.Hour)
	ctx := context.TODO()
	ctx = context.WithValue(ctx, effectiveTimeKey, effectiveTimeTest)

	rules := policyRules{
		"warning1": rule.Info{
			Title: "Warning1",
		},
		"failure2": rule.Info{
			Title:       "Failure2",
			Description: "Failure 2 description",
		},
		"warning2": rule.Info{
			Title:       "Warning2",
			Description: "Warning 2 description",
			EffectiveOn: "2022-01-01T00:00:00Z",
		},
		"warning3": rule.Info{
			Title:       "Warning3",
			Description: "Warning 3 description",
			EffectiveOn: effectiveOnTest,
		},
		"pipelineIntentionRule": rule.Info{
			Title:             "Pipeline Intention Rule",
			Description:       "Rule with pipeline intention",
			PipelineIntention: []string{"release", "production"},
		},
	}
	cases := []struct {
		name   string
		result Result
		rules  policyRules
		want   Result
	}{
		{
			name: "update title",
			result: Result{
				Metadata: map[string]any{
					"code":        "warning1",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
				Metadata: map[string]any{
					"code":        "warning1",
					"collections": []string{"A"},
					"title":       "Warning1",
				},
			},
		},
		{
			name: "update title and description",
			result: Result{
				Metadata: map[string]any{
					"code":        "failure2",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
				Metadata: map[string]any{
					"code":        "failure2",
					"collections": []string{"A"},
					"description": "Failure 2 description",
					"title":       "Failure2",
				},
			},
		},
		{
			name: "drop stale effectiveOn",
			result: Result{
				Metadata: map[string]any{
					"code":        "warning2",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
				Metadata: map[string]any{
					"code":        "warning2",
					"collections": []string{"A"},
					"description": "Warning 2 description",
					"title":       "Warning2",
				},
			},
		},
		{
			name: "add relevant effectiveOn",
			result: Result{
				Metadata: map[string]any{
					"code":        "warning3",
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
				Metadata: map[string]any{
					"code":         "warning3",
					"collections":  []string{"A"},
					"description":  "Warning 3 description",
					"title":        "Warning3",
					"effective_on": effectiveOnTest,
				},
			},
		},
		{
			name: "rule not found",
			result: Result{
				Metadata: map[string]any{
					"collections": []any{"A"},
				},
			},
			rules: rules,
			want: Result{
				Metadata: map[string]any{
					"collections": []any{"A"},
				},
			},
		},
		{
			name: "add pipeline intention metadata",
			result: Result{
				Metadata: map[string]any{
					"code":        "pipelineIntentionRule",
					"collections": []any{"B"},
				},
			},
			rules: rules,
			want: Result{
				Metadata: map[string]any{
					"code":        "pipelineIntentionRule",
					"collections": []string{"B"},
					"title":       "Pipeline Intention Rule",
					"description": "Rule with pipeline intention",
				},
			},
		},
	}
	for i, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			addRuleMetadata(ctx, &cases[i].result, tt.rules)
			assert.Equal(t, tt.result, tt.want)
		})
	}
}

func TestRulesWithoutMetadata(t *testing.T) {
	// Create a temporary directory for the test
	tempDir := t.TempDir()

	// Create a simple policy file without metadata
	policyContent := `package main

import rego.v1

deny contains result if {
    result := {
        "msg": "Simple deny rule",
        "severity": "failure"
    }
}

warn contains result if {
    result := {
        "msg": "Simple warn rule", 
        "severity": "warning"
    }
}`

	policyFile := filepath.Join(tempDir, "simple.rego")
	err := os.WriteFile(policyFile, []byte(policyContent), 0600)
	require.NoError(t, err)

	// Create input directory structure
	inputDir := filepath.Join(tempDir, "inputs")
	require.NoError(t, os.MkdirAll(inputDir, 0755))
	inputFile := filepath.Join(inputDir, "data.json")
	err = os.WriteFile(inputFile, []byte("{}"), 0600)
	require.NoError(t, err)

	// Create evaluator using the proper constructor
	ctx := context.Background()
	config := &mockConfigProvider{}
	config.On("EffectiveTime").Return(time.Now())
	config.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	config.On("Spec").Return(ecc.EnterpriseContractPolicySpec{})

	evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
		&source.PolicyUrl{
			Url:  tempDir,
			Kind: source.PolicyKind,
		},
	}, config, ecc.Source{}, []string{})
	require.NoError(t, err)

	// Evaluate the policy
	results, err := evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{inputDir}})

	// The evaluation should succeed
	require.NoError(t, err)
	require.NotNil(t, results)
	require.Len(t, results, 1, "Expected one result set")

	result := results[0]

	// Check that we have results (this is what the acceptance test expects)
	// The rules should always evaluate to true since they have no conditions
	totalResults := len(result.Failures) + len(result.Warnings) + len(result.Successes)
	require.Greater(t, totalResults, 0, "Expected to find at least one result from the simple.rego rules")

	// Check that we have the expected results
	require.Len(t, result.Failures, 1, "Expected 1 deny rule")
	require.Len(t, result.Warnings, 1, "Expected 1 warn rule")

	// Verify the content of the results
	expectedMessages := []string{
		"Simple deny rule",
		"Simple warn rule",
	}

	allResults := append(result.Failures, result.Warnings...)
	require.Len(t, allResults, 2, "Expected 2 total results")

	for _, expectedMsg := range expectedMessages {
		found := false
		for _, result := range allResults {
			if result.Message == expectedMsg {
				found = true
				break
			}
		}
		require.True(t, found, "Expected to find result with message: %s", expectedMsg)
	}
}

func TestWarnRuleNotShowingUp(t *testing.T) {
	// Create a temporary directory for the test
	tempDir := t.TempDir()

	// Create the warn.rego file (exact content from acceptance test)
	policyContent := `# Simplest always-warning policy
package main

import rego.v1

warn contains result if {
    result := "Has a warning"
}`

	policyFile := filepath.Join(tempDir, "warn.rego")
	err := os.WriteFile(policyFile, []byte(policyContent), 0600)
	require.NoError(t, err)

	// Create input directory structure
	inputDir := filepath.Join(tempDir, "inputs")
	require.NoError(t, os.MkdirAll(inputDir, 0755))
	inputFile := filepath.Join(inputDir, "data.json")
	err = os.WriteFile(inputFile, []byte("{}"), 0600)
	require.NoError(t, err)

	// Create evaluator using the proper constructor
	ctx := context.Background()
	config := &mockConfigProvider{}
	config.On("EffectiveTime").Return(time.Now())
	config.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	config.On("Spec").Return(ecc.EnterpriseContractPolicySpec{})

	evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
		&source.PolicyUrl{
			Url:  tempDir,
			Kind: source.PolicyKind,
		},
	}, config, ecc.Source{}, []string{})
	require.NoError(t, err)

	// Evaluate the policy
	results, err := evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{inputDir}})

	// The evaluation should succeed
	require.NoError(t, err)
	require.NotNil(t, results)
	require.Len(t, results, 1, "Expected one result set")

	result := results[0]

	// Check that we have the warning result
	require.Len(t, result.Warnings, 1, "Expected 1 warn rule from warn.rego")
	require.Equal(t, "Has a warning", result.Warnings[0].Message, "Expected warning message to match")

	// The warning should be included in the output
	totalResults := len(result.Failures) + len(result.Warnings) + len(result.Successes)
	require.Greater(t, totalResults, 0, "Expected to find at least one result from the warn.rego rules")
}
