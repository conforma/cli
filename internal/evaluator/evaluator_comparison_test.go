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
	"sort"
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
)

type evaluatorPair struct {
	conftest Evaluator
	opa      Evaluator
}

func setupEvaluatorPair(t *testing.T, policyContent string, src ecc.Source) evaluatorPair {
	t.Helper()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policy")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))
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

	ctx := context.Background()
	sources := []source.PolicySource{policySource}

	conftestEval, err := NewConftestEvaluator(ctx, sources, configProvider, src)
	require.NoError(t, err)
	t.Cleanup(conftestEval.Destroy)

	opaEval, err := NewOPAEvaluator(ctx, sources, configProvider, src, nil)
	require.NoError(t, err)
	t.Cleanup(opaEval.Destroy)

	return evaluatorPair{conftest: conftestEval, opa: opaEval}
}

func writeInput(t *testing.T, data map[string]any) string {
	t.Helper()
	inputBytes, err := json.Marshal(data)
	require.NoError(t, err)
	inputPath := filepath.Join(t.TempDir(), "input.json")
	require.NoError(t, os.WriteFile(inputPath, inputBytes, 0o600))
	return inputPath
}

type outcomeSummary struct {
	failureCodes  []string
	warningCodes  []string
	successCodes  []string
	failureMsgs   []string
	warningMsgs   []string
	exceptionMsgs []string
}

func summarizeOutcomes(outcomes []Outcome) outcomeSummary {
	var s outcomeSummary
	for _, o := range outcomes {
		for _, f := range o.Failures {
			if code, ok := f.Metadata["code"].(string); ok {
				s.failureCodes = append(s.failureCodes, code)
			}
			s.failureMsgs = append(s.failureMsgs, f.Message)
		}
		for _, w := range o.Warnings {
			if code, ok := w.Metadata["code"].(string); ok {
				s.warningCodes = append(s.warningCodes, code)
			}
			s.warningMsgs = append(s.warningMsgs, w.Message)
		}
		for _, sc := range o.Successes {
			if code, ok := sc.Metadata["code"].(string); ok {
				s.successCodes = append(s.successCodes, code)
			}
		}
		for _, e := range o.Exceptions {
			s.exceptionMsgs = append(s.exceptionMsgs, e.Message)
		}
	}
	sort.Strings(s.failureCodes)
	sort.Strings(s.warningCodes)
	sort.Strings(s.successCodes)
	sort.Strings(s.failureMsgs)
	sort.Strings(s.warningMsgs)
	sort.Strings(s.exceptionMsgs)
	return s
}

func assertSameOutcomes(t *testing.T, label string, conftestResults, opaResults []Outcome) {
	t.Helper()
	cs := summarizeOutcomes(conftestResults)
	os := summarizeOutcomes(opaResults)

	assert.Equal(t, cs.failureCodes, os.failureCodes, "%s: failure codes differ", label)
	assert.Equal(t, cs.warningCodes, os.warningCodes, "%s: warning codes differ", label)
	assert.Equal(t, cs.successCodes, os.successCodes, "%s: success codes differ", label)
	assert.Equal(t, cs.failureMsgs, os.failureMsgs, "%s: failure messages differ", label)
	assert.Equal(t, cs.warningMsgs, os.warningMsgs, "%s: warning messages differ", label)
}

func TestComparisonDenyRule(t *testing.T) {
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
	pair := setupEvaluatorPair(t, policyContent, ecc.Source{})
	ctx := context.Background()
	inputPath := writeInput(t, map[string]any{"test": "value"})

	target := EvaluationTarget{
		Inputs: []string{inputPath},
		Target: "image:latest",
	}

	conftestResults, err := pair.conftest.Evaluate(ctx, target)
	require.NoError(t, err)

	opaResults, err := pair.opa.Evaluate(ctx, target)
	require.NoError(t, err)

	assertSameOutcomes(t, "always-deny", conftestResults, opaResults)

	cs := summarizeOutcomes(conftestResults)
	assert.Contains(t, cs.failureCodes, "main.always_deny")
}

func TestComparisonConditionalDeny(t *testing.T) {
	policyContent := `package main

import rego.v1

# METADATA
# title: Conditional deny
# custom:
#   short_name: conditional_deny
deny contains result if {
	input.should_fail == true
	result := {
		"code": "main.conditional_deny",
		"msg": "Conditional failure triggered",
	}
}
`
	pair := setupEvaluatorPair(t, policyContent, ecc.Source{})
	ctx := context.Background()

	t.Run("triggered", func(t *testing.T) {
		inputPath := writeInput(t, map[string]any{"should_fail": true})
		target := EvaluationTarget{Inputs: []string{inputPath}, Target: "image:latest"}

		cr, err := pair.conftest.Evaluate(ctx, target)
		require.NoError(t, err)
		or, err := pair.opa.Evaluate(ctx, target)
		require.NoError(t, err)

		assertSameOutcomes(t, "conditional-deny-triggered", cr, or)
		assert.Contains(t, summarizeOutcomes(cr).failureCodes, "main.conditional_deny")
	})

	t.Run("not triggered", func(t *testing.T) {
		inputPath := writeInput(t, map[string]any{"should_fail": false})
		target := EvaluationTarget{Inputs: []string{inputPath}, Target: "image:latest"}

		cr, err := pair.conftest.Evaluate(ctx, target)
		require.NoError(t, err)
		or, err := pair.opa.Evaluate(ctx, target)
		require.NoError(t, err)

		assertSameOutcomes(t, "conditional-deny-not-triggered", cr, or)
		assert.Contains(t, summarizeOutcomes(cr).successCodes, "main.conditional_deny")
	})
}

func TestComparisonWarnRule(t *testing.T) {
	policyContent := `package main

import rego.v1

# METADATA
# title: Always warn
# custom:
#   short_name: always_warn
warn contains result if {
	result := {
		"code": "main.always_warn",
		"msg": "This is a warning",
	}
}
`
	pair := setupEvaluatorPair(t, policyContent, ecc.Source{})
	ctx := context.Background()
	inputPath := writeInput(t, map[string]any{"test": "value"})

	target := EvaluationTarget{Inputs: []string{inputPath}, Target: "image:latest"}

	cr, err := pair.conftest.Evaluate(ctx, target)
	require.NoError(t, err)
	or, err := pair.opa.Evaluate(ctx, target)
	require.NoError(t, err)

	assertSameOutcomes(t, "always-warn", cr, or)
	assert.Contains(t, summarizeOutcomes(cr).warningCodes, "main.always_warn")
}

func TestComparisonMixedDenyAndWarn(t *testing.T) {
	policyContent := `package main

import rego.v1

# METADATA
# title: Deny rule
# custom:
#   short_name: deny_rule
deny contains result if {
	input.fail == true
	result := {
		"code": "main.deny_rule",
		"msg": "Failure detected",
	}
}

# METADATA
# title: Warn rule
# custom:
#   short_name: warn_rule
warn contains result if {
	input.warn == true
	result := {
		"code": "main.warn_rule",
		"msg": "Warning detected",
	}
}
`
	pair := setupEvaluatorPair(t, policyContent, ecc.Source{})
	ctx := context.Background()

	t.Run("both triggered", func(t *testing.T) {
		inputPath := writeInput(t, map[string]any{"fail": true, "warn": true})
		target := EvaluationTarget{Inputs: []string{inputPath}, Target: "image:latest"}

		cr, err := pair.conftest.Evaluate(ctx, target)
		require.NoError(t, err)
		or, err := pair.opa.Evaluate(ctx, target)
		require.NoError(t, err)

		assertSameOutcomes(t, "both-triggered", cr, or)

		s := summarizeOutcomes(cr)
		assert.Contains(t, s.failureCodes, "main.deny_rule")
		assert.Contains(t, s.warningCodes, "main.warn_rule")
	})

	t.Run("none triggered", func(t *testing.T) {
		inputPath := writeInput(t, map[string]any{"fail": false, "warn": false})
		target := EvaluationTarget{Inputs: []string{inputPath}, Target: "image:latest"}

		cr, err := pair.conftest.Evaluate(ctx, target)
		require.NoError(t, err)
		or, err := pair.opa.Evaluate(ctx, target)
		require.NoError(t, err)

		assertSameOutcomes(t, "none-triggered", cr, or)

		s := summarizeOutcomes(cr)
		assert.Empty(t, s.failureCodes)
		assert.Empty(t, s.warningCodes)
		assert.NotEmpty(t, s.successCodes)
	})
}

func TestComparisonMultipleDenyRules(t *testing.T) {
	policyContent := `package main

import rego.v1

# METADATA
# title: Check Alpha
# custom:
#   short_name: check_alpha
deny contains result if {
	input.alpha == true
	result := {
		"code": "main.check_alpha",
		"msg": "Alpha check failed",
	}
}

# METADATA
# title: Check Beta
# custom:
#   short_name: check_beta
deny contains result if {
	input.beta == true
	result := {
		"code": "main.check_beta",
		"msg": "Beta check failed",
	}
}

# METADATA
# title: Check Gamma
# custom:
#   short_name: check_gamma
deny contains result if {
	input.gamma == true
	result := {
		"code": "main.check_gamma",
		"msg": "Gamma check failed",
	}
}
`
	pair := setupEvaluatorPair(t, policyContent, ecc.Source{})
	ctx := context.Background()

	t.Run("all fail", func(t *testing.T) {
		inputPath := writeInput(t, map[string]any{"alpha": true, "beta": true, "gamma": true})
		target := EvaluationTarget{Inputs: []string{inputPath}, Target: "image:latest"}

		cr, err := pair.conftest.Evaluate(ctx, target)
		require.NoError(t, err)
		or, err := pair.opa.Evaluate(ctx, target)
		require.NoError(t, err)

		assertSameOutcomes(t, "all-fail", cr, or)
		s := summarizeOutcomes(cr)
		assert.Len(t, s.failureCodes, 3)
		assert.Empty(t, s.successCodes)
	})

	t.Run("partial fail", func(t *testing.T) {
		inputPath := writeInput(t, map[string]any{"alpha": true, "beta": false, "gamma": true})
		target := EvaluationTarget{Inputs: []string{inputPath}, Target: "image:latest"}

		cr, err := pair.conftest.Evaluate(ctx, target)
		require.NoError(t, err)
		or, err := pair.opa.Evaluate(ctx, target)
		require.NoError(t, err)

		assertSameOutcomes(t, "partial-fail", cr, or)
		s := summarizeOutcomes(cr)
		assert.Len(t, s.failureCodes, 2)
		assert.Contains(t, s.successCodes, "main.check_beta")
	})

	t.Run("all pass", func(t *testing.T) {
		inputPath := writeInput(t, map[string]any{"alpha": false, "beta": false, "gamma": false})
		target := EvaluationTarget{Inputs: []string{inputPath}, Target: "image:latest"}

		cr, err := pair.conftest.Evaluate(ctx, target)
		require.NoError(t, err)
		or, err := pair.opa.Evaluate(ctx, target)
		require.NoError(t, err)

		assertSameOutcomes(t, "all-pass", cr, or)
		s := summarizeOutcomes(cr)
		assert.Empty(t, s.failureCodes)
		assert.Len(t, s.successCodes, 3)
	})
}

func TestComparisonWithParsedInput(t *testing.T) {
	policyContent := `package main

import rego.v1

# METADATA
# title: Image ref check
# custom:
#   short_name: image_ref_check
deny contains result if {
	input.image.ref == "bad:latest"
	result := {
		"code": "main.image_ref_check",
		"msg": "Bad image reference",
	}
}
`
	pair := setupEvaluatorPair(t, policyContent, ecc.Source{})
	ctx := context.Background()

	inputData := map[string]any{
		"image": map[string]any{"ref": "bad:latest"},
	}

	// Conftest needs file-based input; OPA supports ParsedInput.
	// Use file input for conftest, parsed input for OPA, then compare.
	inputPath := writeInput(t, inputData)

	cr, err := pair.conftest.Evaluate(ctx, EvaluationTarget{
		Inputs: []string{inputPath},
		Target: "bad:latest",
	})
	require.NoError(t, err)

	or, err := pair.opa.Evaluate(ctx, EvaluationTarget{
		ParsedInput: inputData,
		Target:      "bad:latest",
	})
	require.NoError(t, err)

	assertSameOutcomes(t, "parsed-vs-file-input", cr, or)
	assert.Contains(t, summarizeOutcomes(cr).failureCodes, "main.image_ref_check")
}

func TestComparisonWithComponentNameFiltering(t *testing.T) {
	policyContent := `package test

import rego.v1

# METADATA
# title: Check A
# custom:
#   short_name: check_a
deny contains result if {
	result := {
		"code": "test.check_a",
		"msg": "Check A fails",
	}
}

# METADATA
# title: Check B
# custom:
#   short_name: check_b
deny contains result if {
	result := {
		"code": "test.check_b",
		"msg": "Check B fails",
	}
}
`
	src := ecc.Source{
		VolatileConfig: &ecc.VolatileSourceConfig{
			Exclude: []ecc.VolatileCriteria{
				{
					Value:          "test.check_a",
					ComponentNames: []ecc.ComponentName{"excluded-comp"},
					EffectiveOn:    "2024-01-01T00:00:00Z",
					EffectiveUntil: "2030-01-01T00:00:00Z",
				},
			},
		},
	}

	pair := setupEvaluatorPair(t, policyContent, src)
	ctx := context.Background()
	inputPath := writeInput(t, map[string]any{"test": true})

	t.Run("excluded component", func(t *testing.T) {
		target := EvaluationTarget{
			Inputs:        []string{inputPath},
			Target:        "quay.io/img@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			ComponentName: "excluded-comp",
		}

		cr, err := pair.conftest.Evaluate(ctx, target)
		require.NoError(t, err)
		or, err := pair.opa.Evaluate(ctx, target)
		require.NoError(t, err)

		assertSameOutcomes(t, "excluded-component", cr, or)

		s := summarizeOutcomes(cr)
		assert.NotContains(t, s.failureCodes, "test.check_a", "check_a should be excluded")
		assert.Contains(t, s.failureCodes, "test.check_b", "check_b should remain")
	})

	t.Run("non-excluded component", func(t *testing.T) {
		target := EvaluationTarget{
			Inputs:        []string{inputPath},
			Target:        "quay.io/img@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			ComponentName: "other-comp",
		}

		cr, err := pair.conftest.Evaluate(ctx, target)
		require.NoError(t, err)
		or, err := pair.opa.Evaluate(ctx, target)
		require.NoError(t, err)

		assertSameOutcomes(t, "non-excluded-component", cr, or)

		s := summarizeOutcomes(cr)
		assert.Contains(t, s.failureCodes, "test.check_a", "check_a should be present")
		assert.Contains(t, s.failureCodes, "test.check_b", "check_b should be present")
	})
}
