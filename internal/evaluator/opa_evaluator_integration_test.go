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

func TestOPAEvaluatorIntegrationBasic(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policy")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

	policyContent := `package main

import rego.v1

# METADATA
# title: Always deny
# custom:
#   short_name: always_deny
deny contains result if {
	result := {
		"code": "main.always_deny",
		"msg": "This always fails",
	}
}
`
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policyContent), 0o600))

	policySource := &source.PolicyUrl{
		Url:  "file://" + policyDir,
		Kind: source.PolicyKind,
	}

	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Now())
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{{
			Policy: []string{"file://" + policyDir},
		}},
	})

	evaluator, err := NewOPAEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{}, nil)
	require.NoError(t, err)
	defer evaluator.Destroy()

	assert.NotNil(t, evaluator)
	assert.NotEmpty(t, evaluator.CapabilitiesPath())
}

func TestOPAEvaluatorIntegrationWithTestData(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policy")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

	policyContent := `package main

import rego.v1

# METADATA
# title: Test deny
# custom:
#   short_name: test_deny
deny contains result if {
	result := {
		"code": "main.test_deny",
		"msg": "Test value found",
	}
}
`
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policyContent), 0o600))

	policySource := &source.PolicyUrl{
		Url:  "file://" + policyDir,
		Kind: source.PolicyKind,
	}

	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Now())
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{{
			Policy: []string{"file://" + policyDir},
		}},
	})

	evaluator, err := NewOPAEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{}, nil)
	require.NoError(t, err)
	defer evaluator.Destroy()

	inputData := map[string]any{"test": "value"}
	inputBytes, err := json.Marshal(inputData)
	require.NoError(t, err)
	inputPath := filepath.Join(tmpDir, "input.json")
	require.NoError(t, os.WriteFile(inputPath, inputBytes, 0o600))

	target := EvaluationTarget{
		Inputs: []string{inputPath},
		Target: "test-image:latest",
	}

	results, err := evaluator.Evaluate(ctx, target)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	hasFailure := false
	for _, outcome := range results {
		for _, failure := range outcome.Failures {
			if failure.Message == "Test value found" {
				hasFailure = true
			}
		}
	}
	assert.True(t, hasFailure, "Expected deny rule to produce a failure")
}

func TestOPAEvaluatorIntegrationDenyWarnException(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policy")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

	policyContent := `package main

import rego.v1

# METADATA
# title: Deny check
# custom:
#   short_name: deny_check
deny contains result if {
	input.should_deny == true
	result := {
		"code": "main.deny_check",
		"msg": "Deny triggered",
	}
}

# METADATA
# title: Warn check
# custom:
#   short_name: warn_check
warn contains result if {
	input.should_warn == true
	result := {
		"code": "main.warn_check",
		"msg": "Warning triggered",
	}
}
`
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policyContent), 0o600))

	policySource := &source.PolicyUrl{
		Url:  "file://" + policyDir,
		Kind: source.PolicyKind,
	}

	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Now())
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{{
			Policy: []string{"file://" + policyDir},
		}},
	})

	evaluator, err := NewOPAEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{}, nil)
	require.NoError(t, err)
	defer evaluator.Destroy()

	t.Run("deny and warn both triggered", func(t *testing.T) {
		inputData := map[string]any{"should_deny": true, "should_warn": true}
		inputBytes, err := json.Marshal(inputData)
		require.NoError(t, err)
		inputPath := filepath.Join(tmpDir, "input_both.json")
		require.NoError(t, os.WriteFile(inputPath, inputBytes, 0o600))

		results, err := evaluator.Evaluate(ctx, EvaluationTarget{
			Inputs: []string{inputPath},
			Target: "image:latest",
		})
		require.NoError(t, err)

		var failures, warnings int
		for _, outcome := range results {
			failures += len(outcome.Failures)
			warnings += len(outcome.Warnings)
		}
		assert.Equal(t, 1, failures, "Expected 1 deny failure")
		assert.Equal(t, 1, warnings, "Expected 1 warning")
	})

	t.Run("only warn triggered", func(t *testing.T) {
		inputData := map[string]any{"should_deny": false, "should_warn": true}
		inputBytes, err := json.Marshal(inputData)
		require.NoError(t, err)
		inputPath := filepath.Join(tmpDir, "input_warn.json")
		require.NoError(t, os.WriteFile(inputPath, inputBytes, 0o600))

		results, err := evaluator.Evaluate(ctx, EvaluationTarget{
			Inputs: []string{inputPath},
			Target: "image:latest",
		})
		require.NoError(t, err)

		var failures, warnings, successes int
		for _, outcome := range results {
			failures += len(outcome.Failures)
			warnings += len(outcome.Warnings)
			successes += len(outcome.Successes)
		}
		assert.Equal(t, 0, failures, "Expected no deny failures")
		assert.Equal(t, 1, warnings, "Expected 1 warning")
		assert.GreaterOrEqual(t, successes, 1, "Expected at least 1 success")
	})

	t.Run("nothing triggered produces successes", func(t *testing.T) {
		inputData := map[string]any{"should_deny": false, "should_warn": false}
		inputBytes, err := json.Marshal(inputData)
		require.NoError(t, err)
		inputPath := filepath.Join(tmpDir, "input_pass.json")
		require.NoError(t, os.WriteFile(inputPath, inputBytes, 0o600))

		results, err := evaluator.Evaluate(ctx, EvaluationTarget{
			Inputs: []string{inputPath},
			Target: "image:latest",
		})
		require.NoError(t, err)

		var failures, warnings, successes int
		for _, outcome := range results {
			failures += len(outcome.Failures)
			warnings += len(outcome.Warnings)
			successes += len(outcome.Successes)
		}
		assert.Equal(t, 0, failures, "Expected no failures")
		assert.Equal(t, 0, warnings, "Expected no warnings")
		assert.GreaterOrEqual(t, successes, 1, "Expected successes for passing rules")
	})
}

func TestOPAEvaluatorIntegrationWithParsedInput(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policy")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

	policyContent := `package main

import rego.v1

# METADATA
# title: Image check
# custom:
#   short_name: image_check
deny contains result if {
	input.image.ref == "bad-image:latest"
	result := {
		"code": "main.image_check",
		"msg": "Bad image detected",
	}
}
`
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policyContent), 0o600))

	policySource := &source.PolicyUrl{
		Url:  "file://" + policyDir,
		Kind: source.PolicyKind,
	}

	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Now())
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{{
			Policy: []string{"file://" + policyDir},
		}},
	})

	evaluator, err := NewOPAEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{}, nil)
	require.NoError(t, err)
	defer evaluator.Destroy()

	t.Run("parsed input triggers deny", func(t *testing.T) {
		results, err := evaluator.Evaluate(ctx, EvaluationTarget{
			ParsedInput: map[string]any{
				"image": map[string]any{"ref": "bad-image:latest"},
			},
			Target: "bad-image:latest",
		})
		require.NoError(t, err)

		hasFailure := false
		for _, outcome := range results {
			for _, f := range outcome.Failures {
				if f.Message == "Bad image detected" {
					hasFailure = true
				}
			}
		}
		assert.True(t, hasFailure, "Expected deny rule to trigger with parsed input")
	})

	t.Run("parsed input passes", func(t *testing.T) {
		results, err := evaluator.Evaluate(ctx, EvaluationTarget{
			ParsedInput: map[string]any{
				"image": map[string]any{"ref": "good-image:latest"},
			},
			Target: "good-image:latest",
		})
		require.NoError(t, err)

		var failures int
		for _, outcome := range results {
			failures += len(outcome.Failures)
		}
		assert.Equal(t, 0, failures, "Expected no failures for good image")
	})
}

func TestOPAEvaluatorIntegrationWithComponentNames(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policy")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

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
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policyContent), 0o600))

	policySource := &source.PolicyUrl{
		Url:  "file://" + policyDir,
		Kind: source.PolicyKind,
	}

	configProvider := &mockConfigProvider{}
	configProvider.On("EffectiveTime").Return(time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC))
	configProvider.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	configProvider.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{{
			Policy: []string{"file://" + policyDir},
		}},
	})

	evaluator, err := NewOPAEvaluator(ctx, []source.PolicySource{policySource}, configProvider, ecc.Source{
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
	}, nil)
	require.NoError(t, err)
	defer evaluator.Destroy()

	inputData := map[string]any{"test": "value"}
	inputBytes, err := json.Marshal(inputData)
	require.NoError(t, err)
	inputPath := filepath.Join(tmpDir, "input.json")
	require.NoError(t, os.WriteFile(inputPath, inputBytes, 0o600))

	t.Run("comp1 excludes check_a", func(t *testing.T) {
		results, err := evaluator.Evaluate(ctx, EvaluationTarget{
			Inputs:        []string{inputPath},
			Target:        "quay.io/repo/img@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			ComponentName: "comp1",
		})
		require.NoError(t, err)

		hasCheckA, hasCheckB := false, false
		for _, outcome := range results {
			for _, failure := range outcome.Failures {
				if code, ok := failure.Metadata["code"].(string); ok {
					if code == "test.check_a" {
						hasCheckA = true
					}
					if code == "test.check_b" {
						hasCheckB = true
					}
				}
			}
		}
		assert.False(t, hasCheckA, "Expected check_a to be excluded for comp1")
		assert.True(t, hasCheckB, "Expected check_b to be evaluated for comp1")
	})

	t.Run("comp2 evaluates both checks", func(t *testing.T) {
		results, err := evaluator.Evaluate(ctx, EvaluationTarget{
			Inputs:        []string{inputPath},
			Target:        "quay.io/repo/img@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			ComponentName: "comp2",
		})
		require.NoError(t, err)

		hasCheckA, hasCheckB := false, false
		for _, outcome := range results {
			for _, failure := range outcome.Failures {
				if code, ok := failure.Metadata["code"].(string); ok {
					if code == "test.check_a" {
						hasCheckA = true
					}
					if code == "test.check_b" {
						hasCheckB = true
					}
				}
			}
		}
		assert.True(t, hasCheckA, "Expected check_a to be evaluated for comp2")
		assert.True(t, hasCheckB, "Expected check_b to be evaluated for comp2")
	})
}
