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

// This file contains unit tests for the core evaluation logic and basic functionalities
// of the Conftest Evaluator. It includes tests for:
// - Basic evaluation functionality (TestConftestEvaluatorEvaluate)
// - Severity handling (TestConftestEvaluatorEvaluateSeverity)
// - Capabilities configuration (TestConftestEvaluatorCapabilities)
// - Success/warning/failure scenarios (TestConftestEvaluatorEvaluateNoSuccessWarningsOrFailures)
// - Unconforming rule behavior (TestUnconformingRule)
// These are fast, deterministic unit tests that focus on the core evaluation logic.

//go:build unit

package evaluator

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/kube-openapi/pkg/util/sets"

	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

func TestConftestEvaluatorEvaluateSeverity(t *testing.T) {
	results := []Outcome{
		{
			Failures: []Result{
				{
					Message:  "missing effective date",
					Metadata: map[string]any{},
				},
				{
					Message: "already effective",
					Metadata: map[string]any{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
				{
					Message: "invalid effective date",
					Metadata: map[string]any{
						"effective_on": "hangout-not-a-date",
					},
				},
				{
					Message: "unexpected effective date type",
					Metadata: map[string]any{
						"effective_on": true,
					},
				},
				{
					Message: "not yet effective",
					Metadata: map[string]any{
						"effective_on": "3021-01-01T00:00:00Z",
					},
				},
				{
					Message: "failure to warning",
					Metadata: map[string]any{
						"severity": "warning",
					},
				},
				{
					Message: "failure to failure",
					Metadata: map[string]any{
						"severity": "failure",
					},
				},
				{
					Message: "unexpected severity value on failure",
					Metadata: map[string]any{
						"severity": "spam",
					},
				},
				{
					Message: "unexpected severity type on failure",
					Metadata: map[string]any{
						"severity": 42,
					},
				},
			},
			Warnings: []Result{
				{
					Message: "existing warning",
					Metadata: map[string]any{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
				{
					Message: "warning to failure",
					Metadata: map[string]any{
						"severity": "failure",
					},
				},
				{
					Message: "warning to warning",
					Metadata: map[string]any{
						"severity": "warning",
					},
				},
				{
					Message: "unexpected severity value on warning",
					Metadata: map[string]any{
						"severity": "spam",
					},
				},
				{
					Message: "unexpected severity type on warning",
					Metadata: map[string]any{
						"severity": 42,
					},
				},
			},
		},
	}

	expectedResults := []Outcome{
		{
			Failures: []Result{
				{
					Message: "warning to failure",
					Metadata: map[string]any{
						"severity": "failure",
					},
				},
				{
					Message:  "missing effective date",
					Metadata: map[string]any{},
				},
				{
					Message: "already effective",
					Metadata: map[string]any{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
				{
					Message: "invalid effective date",
					Metadata: map[string]any{
						"effective_on": "hangout-not-a-date",
					},
				},
				{
					Message: "unexpected effective date type",
					Metadata: map[string]any{
						"effective_on": true,
					},
				},
				{
					Message: "failure to failure",
					Metadata: map[string]any{
						"severity": "failure",
					},
				},
				{
					Message: "unexpected severity value on failure",
					Metadata: map[string]any{
						"severity": "spam",
					},
				},
				{
					Message: "unexpected severity type on failure",
					Metadata: map[string]any{
						"severity": 42,
					},
				},
			},
			Warnings: []Result{
				{
					Message: "existing warning",
					Metadata: map[string]any{
						"effective_on": "2021-01-01T00:00:00Z",
					},
				},
				{
					Message: "warning to warning",
					Metadata: map[string]any{
						"severity": "warning",
					},
				},
				{
					Message: "unexpected severity value on warning",
					Metadata: map[string]any{
						"severity": "spam",
					},
				},
				{
					Message: "unexpected severity type on warning",
					Metadata: map[string]any{
						"severity": 42,
					},
				},

				{
					Message: "not yet effective",
					Metadata: map[string]any{
						"effective_on": "3021-01-01T00:00:00Z",
					},
				},
				{
					Message: "failure to warning",
					Metadata: map[string]any{
						"severity": "warning",
					},
				},
			},
			Skipped:    []Result{},
			Exceptions: []Result{},
		},
	}

	r := mockTestRunner{}
	dl := mockDownloader{}
	inputs := EvaluationTarget{Inputs: []string{"inputs"}}
	expectedData := Data(map[string]any{
		"a": 1,
	})

	ctx := setupTestContext(&r, &dl)
	r.On("Run", ctx, inputs.Inputs).Return(results, expectedData, nil)

	pol, err := policy.NewOfflinePolicy(ctx, policy.Now)
	assert.NoError(t, err)

	src := testPolicySource{}
	evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
		src,
	}, pol, ecc.Source{}, []string{})

	assert.NoError(t, err)
	actualResults, err := evaluator.Evaluate(ctx, inputs)
	assert.NoError(t, err)
	assert.Equal(t, expectedResults, actualResults)
}

func TestConftestEvaluatorCapabilities(t *testing.T) {
	ctx := setupTestContext(nil, nil)
	fs := utils.FS(ctx)

	p, err := policy.NewOfflinePolicy(ctx, policy.Now)
	assert.NoError(t, err)

	evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
		testPolicySource{},
	}, p, ecc.Source{}, []string{})
	assert.NoError(t, err)

	blob, err := afero.ReadFile(fs, evaluator.CapabilitiesPath())
	assert.NoError(t, err)
	var capabilities ast.Capabilities
	err = json.Unmarshal(blob, &capabilities)
	assert.NoError(t, err)

	defaultBuiltins := sets.NewString()
	for _, b := range ast.CapabilitiesForThisVersion().Builtins {
		defaultBuiltins.Insert(b.Name)
	}

	gotBuiltins := sets.NewString()
	for _, b := range capabilities.Builtins {
		gotBuiltins.Insert(b.Name)
	}

	expectedRemoved := sets.NewString("opa.runtime", "http.send", "net.lookup_ip_addr")

	assert.Equal(t, defaultBuiltins.Difference(gotBuiltins), expectedRemoved)
	assert.Equal(t, []string{""}, capabilities.AllowNet)
}

func TestConftestEvaluatorEvaluateNoSuccessWarningsOrFailures(t *testing.T) {
	tests := []struct {
		name         string
		results      []Outcome
		sourceConfig *ecc.SourceConfig
	}{
		{
			name: "no results",
			results: []Outcome{
				{
					Failures:  []Result{},
					Warnings:  []Result{},
					Successes: []Result{},
				},
			},
		},
		{
			name: "no included results",
			results: []Outcome{
				{
					Failures:  []Result{{Metadata: map[string]any{"code": "breakfast.spam"}}},
					Warnings:  []Result{{Metadata: map[string]any{"code": "lunch.spam"}}},
					Successes: []Result{{Metadata: map[string]any{"code": "dinner.spam"}}},
				},
			},
			sourceConfig: &ecc.SourceConfig{
				Include: []string{"brunch.spam"},
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

			evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
				testPolicySource{},
			}, p, ecc.Source{Config: tt.sourceConfig}, []string{})

			assert.NoError(t, err)
			actualResults, err := evaluator.Evaluate(ctx, inputs)
			assert.ErrorContains(t, err, "no successes, warnings, or failures, check input")
			assert.Nil(t, actualResults)
		})
	}
}

func TestConftestEvaluatorEvaluate(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0o755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0o600))

	rego, err := fs.Sub(policies, "__testdir__/simple")
	require.NoError(t, err)

	rules, err := rulesArchiveFromFS(t, rego)
	require.NoError(t, err)

	ctx := withCapabilities(context.Background(), testCapabilities)

	eTime, err := time.Parse(policy.DateFormat, "2014-05-31")
	require.NoError(t, err)
	config := &mockConfigProvider{}
	config.On("EffectiveTime").Return(eTime)
	config.On("SigstoreOpts").Return(policy.SigstoreOpts{
		CertificateIdentity:         "cert-identity",
		CertificateIdentityRegExp:   "cert-identity-regexp",
		CertificateOIDCIssuer:       "cert-oidc-issuer",
		CertificateOIDCIssuerRegExp: "cert-oidc-issuer-regexp",
		IgnoreRekor:                 true,
		RekorURL:                    "https://rekor.local/",
		PublicKey:                   utils.TestPublicKey,
	}, nil)
	config.On("Spec").Return(ecc.EnterpriseContractPolicySpec{})

	evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
		&source.PolicyUrl{
			Url:  rules,
			Kind: source.PolicyKind,
		},
	}, config, ecc.Source{}, []string{})
	require.NoError(t, err)

	results, err := evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{path.Join(dir, "inputs")}})
	require.NoError(t, err)

	// sort the slice by code for test stability
	sort.Slice(results, func(l, r int) bool {
		return strings.Compare(results[l].Namespace, results[r].Namespace) < 0
	})

	for i := range results {
		// let's not fail the snapshot on different locations of $TMPDIR
		results[i].FileName = filepath.ToSlash(strings.Replace(results[i].FileName, dir, "$TMPDIR", 1))
		// sort the slice by code for test stability
		sort.Slice(results[i].Successes, func(l, r int) bool {
			return strings.Compare(results[i].Successes[l].Metadata[metadataCode].(string), results[i].Successes[r].Metadata[metadataCode].(string)) < 0
		})
	}

	snaps.MatchSnapshot(t, results)
}

func TestUnconformingRule(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0o755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0o600))

	rego, err := fs.Sub(policies, "__testdir__/unconforming")
	require.NoError(t, err)

	rules, err := rulesArchiveFromFS(t, rego)
	require.NoError(t, err)

	ctx := context.Background()

	p, err := policy.NewInertPolicy(ctx, "")
	require.NoError(t, err)

	evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
		&source.PolicyUrl{
			Url:  rules,
			Kind: source.PolicyKind,
		},
	}, p, ecc.Source{}, []string{})
	require.NoError(t, err)

	_, err = evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{path.Join(dir, "inputs")}})
	require.Error(t, err)
	assert.EqualError(t, err, `the rule "deny = true if { true }" returns an unsupported value, at no_msg.rego:5`)
}

// --- Reintroduced tests from the original monolith ---
// These restore coverage for mixed annotated vs non-annotated rule behavior
// and filtering across mixed packages.

// TestAnnotatedAndNonAnnotatedRules tests the separation of annotated and non-annotated rules
func TestAnnotatedAndNonAnnotatedRules(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0o755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0o600))

	// Create a test directory with both annotated and non-annotated rules
	testDir := path.Join(dir, "test_policies")
	require.NoError(t, os.MkdirAll(testDir, 0o755))

	// Annotated rule
	annotatedRule := `package annotated

import rego.v1

# METADATA
# title: Annotated Rule
# description: This rule has annotations
# custom:
#   short_name: annotated_rule
deny contains result if {
	result := {
		"code": "annotated.rule",
		"msg": "Annotated rule failure",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "annotated.rego"), []byte(annotatedRule), 0o600))

	// Non-annotated rule
	nonAnnotatedRule := `package nonannotated

import rego.v1

deny contains result if {
	result := {
		"code": "nonannotated.rule",
		"msg": "Non-annotated rule failure",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "nonannotated.rego"), []byte(nonAnnotatedRule), 0o600))

	// Non-annotated rule without code in result
	nonAnnotatedRuleNoCode := `package noresultcode

import rego.v1

deny contains result if {
	result := "No code in result"
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "noresultcode.rego"), []byte(nonAnnotatedRuleNoCode), 0o600))

	// Create rules archive
	archivePath := path.Join(dir, "rules.tar.gz")
	createTestArchive(t, testDir, archivePath)

	ctx := withCapabilities(context.Background(), testCapabilities)

	eTime, err := time.Parse(policy.DateFormat, "2014-05-31")
	require.NoError(t, err)
	config := &mockConfigProvider{}
	config.On("EffectiveTime").Return(eTime)
	config.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	config.On("Spec").Return(ecc.EnterpriseContractPolicySpec{})

	evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
		&source.PolicyUrl{Url: archivePath, Kind: source.PolicyKind},
	}, config, ecc.Source{}, []string{})
	require.NoError(t, err)

	results, err := evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{path.Join(dir, "inputs")}})
	require.NoError(t, err)

	// Verify annotated successes tracked, non-annotated successes not tracked
	foundAnnotatedSuccess := false
	foundNonAnnotatedSuccess := false
	for _, result := range results {
		for _, success := range result.Successes {
			if code, ok := success.Metadata[metadataCode].(string); ok {
				if code == "annotated.annotated_rule" {
					foundAnnotatedSuccess = true
					assert.Contains(t, success.Metadata, metadataTitle)
					assert.Contains(t, success.Metadata, metadataDescription)
				}
				if code == "nonannotated.rule" {
					foundNonAnnotatedSuccess = true
				}
			}
		}
	}
	assert.True(t, foundAnnotatedSuccess, "Annotated rule should be tracked for success computation")
	assert.False(t, foundNonAnnotatedSuccess, "Non-annotated rules should not be tracked for success computation")
}

// TestRuleCollectionWithMixedRules tests rule collection logic with mixed annotated and non-annotated rules
func TestRuleCollectionWithMixedRules(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0o755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0o600))

	// Create test directory with mixed rules
	testDir := path.Join(dir, "mixed_policies")
	require.NoError(t, os.MkdirAll(testDir, 0o755))

	// Annotated failing
	annotatedFailingRule := `package mixed

import rego.v1

# METADATA
# title: Annotated Failing Rule
# description: This annotated rule will fail
# custom:
#   short_name: annotated_failing
deny contains result if {
	result := {
		"code": "mixed.annotated_failing",
		"msg": "Annotated rule failure",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "annotated_failing.rego"), []byte(annotatedFailingRule), 0o600))

	// Annotated passing
	annotatedPassingRule := `package mixed

import rego.v1

# METADATA
# title: Annotated Passing Rule
# description: This annotated rule will pass
# custom:
#   short_name: annotated_passing
deny contains result if {
	false
	result := "This should not be reached"
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "annotated_passing.rego"), []byte(annotatedPassingRule), 0o600))

	// Non-annotated failing
	nonAnnotatedFailingRule := `package mixed

import rego.v1

deny contains result if {
	result := {
		"code": "mixed.nonannotated_failing",
		"msg": "Non-annotated rule failure",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "nonannotated_failing.rego"), []byte(nonAnnotatedFailingRule), 0o600))

	// Non-annotated passing
	nonAnnotatedPassingRule := `package mixed

import rego.v1

deny contains result if {
	false
	result := "This should not be reached"
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "nonannotated_passing.rego"), []byte(nonAnnotatedPassingRule), 0o600))

	// Create rules archive
	archivePath := path.Join(dir, "rules.tar.gz")
	createTestArchive(t, testDir, archivePath)

	ctx := withCapabilities(context.Background(), testCapabilities)

	eTime, err := time.Parse(policy.DateFormat, "2014-05-31")
	require.NoError(t, err)
	config := &mockConfigProvider{}
	config.On("EffectiveTime").Return(eTime)
	config.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	config.On("Spec").Return(ecc.EnterpriseContractPolicySpec{})

	evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
		&source.PolicyUrl{Url: archivePath, Kind: source.PolicyKind},
	}, config, ecc.Source{}, []string{})
	require.NoError(t, err)

	results, err := evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{path.Join(dir, "inputs")}})
	require.NoError(t, err)

	var annotatedFailures, annotatedSuccesses, nonAnnotatedFailures, nonAnnotatedSuccesses int
	for _, result := range results {
		for _, failure := range result.Failures {
			if code, ok := failure.Metadata[metadataCode].(string); ok {
				switch code {
				case "mixed.annotated_failing":
					annotatedFailures++
				case "mixed.nonannotated_failing":
					nonAnnotatedFailures++
				}
			}
		}
		for _, success := range result.Successes {
			if code, ok := success.Metadata[metadataCode].(string); ok {
				switch code {
				case "mixed.annotated_passing":
					annotatedSuccesses++
				case "mixed.nonannotated_passing":
					nonAnnotatedSuccesses++
				}
			}
		}
	}
	assert.Equal(t, 1, annotatedFailures, "Should have one annotated failure")
	assert.Equal(t, 1, annotatedSuccesses, "Should have one annotated success")
	assert.Equal(t, 1, nonAnnotatedFailures, "Should have one non-annotated failure")
	assert.Equal(t, 0, nonAnnotatedSuccesses, "Should not track non-annotated rules for success computation")
}

// TestFilteringWithMixedRules verifies that both annotated and non-annotated rules participate in filtering
func TestFilteringWithMixedRules(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0o755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0o600))

	// Create test directory with rules in different packages
	testDir := path.Join(dir, "filtering_policies")
	require.NoError(t, os.MkdirAll(testDir, 0o755))

	// Annotated rule in package 'a'
	annotatedRuleA := `package a

import rego.v1

# METADATA
# title: Annotated Rule A
# description: This annotated rule is in package a
# custom:
#   short_name: annotated_a
deny contains result if {
	result := {
		"code": "a.annotated",
		"msg": "Annotated rule in package a",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "a_annotated.rego"), []byte(annotatedRuleA), 0o600))

	// Non-annotated rule in package 'b'
	nonAnnotatedRuleB := `package b

import rego.v1

deny contains result if {
	result := {
		"code": "b.nonannotated",
		"msg": "Non-annotated rule in package b",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "b_nonannotated.rego"), []byte(nonAnnotatedRuleB), 0o600))

	// Create rules archive
	archivePath := path.Join(dir, "rules.tar.gz")
	createTestArchive(t, testDir, archivePath)

	ctx := withCapabilities(context.Background(), testCapabilities)

	eTime, err := time.Parse(policy.DateFormat, "2014-05-31")
	require.NoError(t, err)
	config := &mockConfigProvider{}
	config.On("EffectiveTime").Return(eTime)
	config.On("SigstoreOpts").Return(policy.SigstoreOpts{}, nil)
	config.On("Spec").Return(ecc.EnterpriseContractPolicySpec{
		Configuration: &ecc.EnterpriseContractPolicyConfiguration{
			Include: []string{"a.*", "b.*"}, // Include both packages
		},
	})

	evaluator, err := NewConftestEvaluatorWithNamespace(ctx, []source.PolicySource{
		&source.PolicyUrl{Url: archivePath, Kind: source.PolicyKind},
	}, config, ecc.Source{}, []string{})
	require.NoError(t, err)

	results, err := evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{path.Join(dir, "inputs")}})
	require.NoError(t, err)

	foundAnnotatedFailure := false
	foundNonAnnotatedFailure := false
	for _, result := range results {
		for _, failure := range result.Failures {
			if code, ok := failure.Metadata[metadataCode].(string); ok {
				if code == "a.annotated" {
					foundAnnotatedFailure = true
				}
				if code == "b.nonannotated" {
					foundNonAnnotatedFailure = true
				}
			}
		}
	}
	assert.True(t, foundAnnotatedFailure, "Annotated rule should be included in filtering")
	assert.True(t, foundNonAnnotatedFailure, "Non-annotated rule should be included in filtering")
}
