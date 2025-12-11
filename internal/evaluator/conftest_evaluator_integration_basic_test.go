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

// This file contains integration tests for the Conftest Evaluator that test
// the complete evaluation flow with real policy sources and file systems.
// It includes tests for:
// - Basic integration functionality (TestConftestEvaluatorIntegrationBasic)
// - Integration with test data and file systems (TestConftestEvaluatorIntegrationWithTestData)
// These tests verify that the evaluator works correctly in real-world scenarios
// with actual policy files and data sources.

//go:build integration

package evaluator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
)

func TestConftestEvaluatorIntegrationBasic(t *testing.T) {
	ctx := context.Background()

	// Create a simple policy source
	policySource := &source.PolicyUrl{
		Url:  "file://testdata/policies",
		Kind: source.PolicyKind,
	}

	// Create config provider
	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Now())
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{
			{
				Policy: []string{"file://testdata/policies"},
			},
		},
	})

	// Create evaluator
	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{})
	require.NoError(t, err)
	defer evaluator.Destroy()

	// Test that evaluator is created successfully
	assert.NotNil(t, evaluator)
	assert.NotEmpty(t, evaluator.CapabilitiesPath())
}

func TestConftestEvaluatorIntegrationWithTestData(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policy")
	err := os.MkdirAll(policyDir, 0o755)
	require.NoError(t, err)

	// Create a simple policy file for testing
	policyContent := `package main

import rego.v1

deny contains result if {
	result := {
		"code": "main.test",
		"msg": "Test value found",
	}
}`
	err = os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policyContent), 0o600)
	require.NoError(t, err)

	// Create policy source
	policySource := &source.PolicyUrl{
		Url:  "file://" + policyDir,
		Kind: source.PolicyKind,
	}

	// Create config provider
	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Now())
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{
			{
				Policy: []string{"file://" + policyDir},
			},
		},
	})

	// Create evaluator
	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{})
	require.NoError(t, err)
	defer evaluator.Destroy()

	// Test evaluation with simple input
	target := EvaluationTarget{
		Inputs: []string{filepath.Join(tmpDir, "input.json")},
		Target: "test",
	}

	// Create a simple input file
	inputData := map[string]interface{}{
		"test": "value",
	}
	inputBytes, err := json.Marshal(inputData)
	require.NoError(t, err)
	err = os.WriteFile(target.Inputs[0], inputBytes, 0o600)
	require.NoError(t, err)

	// Run evaluation
	result, err := evaluator.Evaluate(ctx, target)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestConftestEvaluatorIntegrationWithComponentNames(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policy")
	err := os.MkdirAll(policyDir, 0o755)
	require.NoError(t, err)

	// Create policies that will be filtered by ComponentNames
	policyContent := `package test

import rego.v1

# METADATA
# title: Check A
# custom:
#   short_name: check_a
deny contains result if {
	result := {
		"code": "test.check_a",
		"msg": "Check A always fails"
	}
}

# METADATA
# title: Check B
# custom:
#   short_name: check_b
deny contains result if {
	result := {
		"code": "test.check_b",
		"msg": "Check B always fails"
	}
}
`
	err = os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policyContent), 0o600)
	require.NoError(t, err)

	// Create policy source
	policySource := &source.PolicyUrl{
		Url:  "file://" + policyDir,
		Kind: source.PolicyKind,
	}

	// Create config provider with ComponentNames filter
	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC))
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{
			{
				Policy: []string{"file://" + policyDir},
			},
		},
	})

	// Create evaluator with VolatileConfig that excludes check_a for comp1
	evaluator, err := NewConftestEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{
		VolatileConfig: &ecc.VolatileSourceConfig{
			Exclude: []ecc.VolatileCriteria{
				{
					Value:          "test.check_a",
					ComponentNames: []ecc.ComponentName{"comp1"},
					EffectiveOn:    "2024-01-01T00:00:00Z",
					EffectiveUntil: "2025-01-01T00:00:00Z",
				},
			},
		},
	})
	require.NoError(t, err)
	defer evaluator.Destroy()

	// Debug: Check exclude criteria
	conftestEval := evaluator.(conftestEvaluator)
	t.Logf("Exclude componentItems: %+v", conftestEval.exclude.componentItems)
	t.Logf("Exclude defaultItems: %+v", conftestEval.exclude.defaultItems)
	t.Logf("Exclude digestItems: %+v", conftestEval.exclude.digestItems)

	// Create test input
	inputData := map[string]interface{}{
		"test": "value",
	}
	inputBytes, err := json.Marshal(inputData)
	require.NoError(t, err)
	inputPath := filepath.Join(tmpDir, "input.json")
	err = os.WriteFile(inputPath, inputBytes, 0o600)
	require.NoError(t, err)

	// Test comp1 - check_a should be excluded
	target1 := EvaluationTarget{
		Inputs:        []string{inputPath},
		Target:        "quay.io/repo/img@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		ComponentName: "comp1",
	}

	result1, err := evaluator.Evaluate(ctx, target1)
	require.NoError(t, err)
	require.NotNil(t, result1)

	// Debug: Print all failures
	t.Logf("comp1 results: %d outcomes", len(result1))
	for i, outcome := range result1 {
		t.Logf("  Outcome %d: %d failures, %d successes", i, len(outcome.Failures), len(outcome.Successes))
		for _, failure := range outcome.Failures {
			t.Logf("    Failure: %s", failure.Metadata["code"])
		}
		for _, success := range outcome.Successes {
			t.Logf("    Success: %s", success.Metadata["code"])
		}
	}

	// Verify check_a is excluded, check_b is not
	hasCheckA := false
	hasCheckB := false
	for _, outcome := range result1 {
		for _, failure := range outcome.Failures {
			if codeStr, ok := failure.Metadata["code"].(string); ok {
				if codeStr == "test.check_a" {
					hasCheckA = true
				}
				if codeStr == "test.check_b" {
					hasCheckB = true
				}
			}
		}
	}
	assert.False(t, hasCheckA, "Expected check_a to be excluded for comp1")
	assert.True(t, hasCheckB, "Expected check_b to be evaluated for comp1")

	// Test comp2 - check_a should NOT be excluded
	target2 := EvaluationTarget{
		Inputs:        []string{inputPath},
		Target:        "quay.io/repo/img@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ComponentName: "comp2",
	}

	result2, err := evaluator.Evaluate(ctx, target2)
	require.NoError(t, err)
	require.NotNil(t, result2)

	// Verify both checks are evaluated for comp2
	hasCheckA2 := false
	hasCheckB2 := false
	for _, outcome := range result2 {
		for _, failure := range outcome.Failures {
			if codeStr, ok := failure.Metadata["code"].(string); ok {
				if codeStr == "test.check_a" {
					hasCheckA2 = true
				}
				if codeStr == "test.check_b" {
					hasCheckB2 = true
				}
			}
		}
	}
	assert.True(t, hasCheckA2, "Expected check_a to be evaluated for comp2")
	assert.True(t, hasCheckB2, "Expected check_b to be evaluated for comp2")

	// Test same image with different components - monorepo scenario
	sameImage := "quay.io/monorepo@sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"

	target3 := EvaluationTarget{
		Inputs:        []string{inputPath},
		Target:        sameImage,
		ComponentName: "comp1",
	}

	result3, err := evaluator.Evaluate(ctx, target3)
	require.NoError(t, err)

	hasCheckA3 := false
	for _, outcome := range result3 {
		for _, failure := range outcome.Failures {
			if codeStr, ok := failure.Metadata["code"].(string); ok && codeStr == "test.check_a" {
				hasCheckA3 = true
			}
		}
	}
	assert.False(t, hasCheckA3, "Expected check_a excluded for comp1 even with different image")

	target4 := EvaluationTarget{
		Inputs:        []string{inputPath},
		Target:        sameImage,
		ComponentName: "comp2",
	}

	result4, err := evaluator.Evaluate(ctx, target4)
	require.NoError(t, err)

	hasCheckA4 := false
	for _, outcome := range result4 {
		for _, failure := range outcome.Failures {
			if codeStr, ok := failure.Metadata["code"].(string); ok && codeStr == "test.check_a" {
				hasCheckA4 = true
			}
		}
	}
	assert.True(t, hasCheckA4, "Expected check_a evaluated for comp2 with same image")
}
