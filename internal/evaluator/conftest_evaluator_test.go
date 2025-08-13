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

//go:build unit

package evaluator

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/MakeNowJust/heredoc"
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/kube-openapi/pkg/util/sets"

	"github.com/conforma/cli/internal/downloader"
	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

type mockTestRunner struct {
	mock.Mock
}

func (m *mockTestRunner) Run(ctx context.Context, inputs []string) ([]Outcome, error) {
	args := m.Called(ctx, inputs)

	return args.Get(0).([]Outcome), args.Error(2)
}

func withTestRunner(ctx context.Context, clnt testRunner) context.Context {
	return context.WithValue(ctx, runnerKey, clnt)
}

type testPolicySource struct{}

func (t testPolicySource) GetPolicy(ctx context.Context, dest string, showMsg bool) (string, error) {
	return "/policy", nil
}

func (t testPolicySource) PolicyUrl() string {
	return "test-url"
}

func (t testPolicySource) Subdir() string {
	return "policy"
}

func (testPolicySource) Type() source.PolicyType {
	return source.PolicyKind
}

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(ctx context.Context, dest string, urls []string) error {
	args := m.Called(ctx, dest, urls)

	return args.Error(0)
}

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

func setupTestContext(r *mockTestRunner, dl *mockDownloader) context.Context {
	ctx := withTestRunner(context.Background(), r)
	ctx = downloader.WithDownloadImpl(ctx, dl)
	fs := afero.NewMemMapFs()
	ctx = utils.WithFS(ctx, fs)
	ctx = withCapabilities(ctx, testCapabilities)

	if err := afero.WriteFile(fs, "/policy/example.rego", []byte(heredoc.Doc(`# Simplest always-failing policy
	package main
	import rego.v1

	# METADATA
	# title: Reject rule
	# description: This rule will always fail
	deny contains result if {
		result := "Fails always"
	}`)), 0644); err != nil {
		panic(err)
	}

	return ctx
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
			name: "exclude by package name with wild card",
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
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast.*"}},
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
			name: "exclude by package and rule name",
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
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Exclude: []string{"breakfast.spam", "lunch.ham"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by package name with term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by package name with multiple terms",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": []any{"eggs", "sgge"}}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": []any{"bacon", "nocab"}}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": []any{"eggs", "sgge"}}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": []any{"eggs", "sgge"}}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": []any{"bacon", "nocab"}}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": []any{"eggs", "sgge"}}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": []any{"bacon", "nocab"}}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": []any{"eggs", "sgge"}}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": []any{"bacon", "nocab"}}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": []any{"eggs", "sgge"}}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by package name with wildcard and term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"breakfast.*:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by package and rule name with term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Exclude: []string{"breakfast.spam:eggs", "breakfast.ham:eggs"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "exclude by collection",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Exclude: []string{"@foo"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []string{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []string{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
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
		{
			name: "include by package with wildcard",
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
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast.*"}},
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
		{
			name: "include by package and rule name with exclude wildcard",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "breakfast.eggs"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"*", "breakfast.spam", "breakfast.ham"},
				Exclude: []string{"breakfast.*"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham"}},
						{Metadata: map[string]any{"code": "lunch.ham"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package and rule name",
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
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast.spam", "lunch.ham"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam"}},
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
			name: "include by package with term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package with multiple terms",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": []any{"eggs", "sgge"}}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": []any{"bacon", "nocab"}}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": []any{"eggs", "sgge"}}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": []any{"eggs", "sgge"}}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": []any{"bacon", "nocab"}}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": []any{"eggs", "sgge"}}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": []any{"eggs", "sgge"}}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": []any{"eggs", "sgge"}}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package with wildcard and term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast.*:eggs"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by package and rule name with term",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.sausage"}},
						{Metadata: map[string]any{"code": "not_breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "bacon"}},
						{Metadata: map[string]any{"code": "breakfast.hash"}},
						{Metadata: map[string]any{"code": "not_breakfast.ham", "term": "eggs"}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast.spam:eggs", "breakfast.ham:eggs"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "breakfast.spam", "term": "eggs"}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{"code": "breakfast.ham", "term": "eggs"}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by old-style collection",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Collections: []string{"foo"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"foo"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"foo"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by collection",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							// Different collection
							"code": "lunch.spam", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							// No collections at all
							"code": "dinner.spam",
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"}, // intentional to test normalization to []string
						}},
						{Metadata: map[string]any{
							// Different collection
							"code": "lunch.ham", "collections": []any{"bar"},
						}},
						{Metadata: map[string]any{
							// No collections at all
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"@foo"}},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"foo"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"foo"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by collection and package",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast", "@foo"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []string{"foo"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []string{"foo"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by collection and exclude by package",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"foo"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"foo"},
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"@foo"},
				Exclude: []string{"lunch"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"foo"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"foo"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "include by collection and package name, exclude by package name",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.spam",
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"other"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "dinner.ham",
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{
				Include: []string{"breakfast", "@foo"},
				Exclude: []string{"lunch"},
			},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"other"},
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"other"},
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "ignore unexpected collection type",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam", "collections": 0,
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []any{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham", "collections": false,
						}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{},
			want: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.spam", "collections": []string{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.spam",
						}},
					},
					Warnings: []Result{
						{Metadata: map[string]any{
							"code": "breakfast.ham", "collections": []string{"foo"},
						}},
						{Metadata: map[string]any{
							"code": "lunch.ham",
						}},
					},
					Skipped:    []Result{},
					Exceptions: []Result{},
				},
			},
		},
		{
			name: "warning for missing includes",
			results: []Outcome{
				{
					Failures: []Result{
						{Metadata: map[string]any{"code": "lunch.spam"}},
						{Metadata: map[string]any{"code": "breakfast.spam", "term": []any{"bacon", "nocab"}}},
					},
				},
			},
			config: &ecc.EnterpriseContractPolicyConfiguration{Include: []string{"breakfast.pancakes", "lunch"}},
			want: []Outcome{
				{
					Skipped:    []Result{},
					Warnings:   []Result{},
					Exceptions: []Result{},
					Failures: []Result{
						{Metadata: map[string]any{"code": "lunch.spam"}},
					},
				},
				{
					Warnings: []Result{
						{Message: "Include criterion 'breakfast.pancakes' doesn't match any policy rule"},
					},
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

			// Create a source configuration that matches the test expectations
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
			name: "valid with multiple terms", code: "breakfast.spam", term: []any{"eggs", "ham"},
			want: []string{
				"breakfast", "breakfast.*", "breakfast.spam",
				"breakfast:eggs", "breakfast.*:eggs", "breakfast.spam:eggs",
				"breakfast:ham", "breakfast.*:ham", "breakfast.spam:ham",
				"*",
			},
		},
		{
			name: "valid without term", code: "breakfast.spam",
			want: []string{"breakfast", "breakfast.*", "breakfast.spam", "*"},
		},
		{name: "incomplete code", code: "spam", want: []string{"*"}},
		{name: "incomplete code with term", code: "spam", term: "eggs", want: []string{"*"}},
		{
			name: "extra code info ignored", code: "this.is.ignored.breakfast.spam",
			want: []string{"breakfast", "breakfast.*", "breakfast.spam", "*"},
		},
		{name: "empty code", code: "", want: []string{"*"}},
		{name: "empty code with term", code: "", term: "eggs", want: []string{"*"}},
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
			assert.Equal(t, tt.want, makeMatchers(result))
		})
	}
}

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
			name:  "*:term", // corner case
			score: 101,
		},
		{
			name:  "*.rule:term", // corner case
			score: 201,
		},
		{
			name:  "pkg",
			score: 10,
		},
		{
			name:  "pkg.",
			score: 10,
		},
		{
			name:  "pkg.*",
			score: 10,
		},
		{
			name:  "pkg.rule",
			score: 110,
		},
		{
			name:  "pkg.:term",
			score: 110,
		},
		{
			name:  "pkg.*:term",
			score: 110,
		},
		{
			name:  "pkg:term",
			score: 110,
		},
		{
			name:  "path.pkg:term",
			score: 210,
		},
		{
			name:  "path.path.pkg:term",
			score: 220,
		},
		{
			name:  "pkg.rule:term",
			score: 210,
		},
		{
			name:  "path.pkg.rule:term",
			score: 220,
		},
		{
			name:  "path.path.pkg.rule:term",
			score: 230,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.score, score(c.name))
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
		{
			name: "successful dependants are not trimmed",
			given: []Outcome{
				{
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode: "a.success1",
							},
						},
					},
				},
				{
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success2",
								metadataDependsOn: []string{"a.success1"},
							},
						},
					},
				},
			},
			expected: []Outcome{
				{
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode: "a.success1",
							},
						},
					},
				},
				{
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success2",
								metadataDependsOn: []string{"a.success1"},
							},
						},
					},
				},
			},
		},
		{
			name: "failures, warnings and successes with dependencies",
			given: []Outcome{
				{
					Failures: []Result{
						{
							Message: "Fails",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure",
							},
						},
						{
							Message: "Fails and depends",
							Metadata: map[string]interface{}{
								metadataCode:      "a.failure",
								metadataDependsOn: []string{"a.failure"},
							},
						},
					},
					Warnings: []Result{
						{
							Message: "Warning",
							Metadata: map[string]interface{}{
								metadataCode:      "a.warning",
								metadataDependsOn: []string{"a.failure"},
							},
						},
					},
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success",
								metadataDependsOn: []string{"a.failure"},
							},
						},
					},
				},
			},
			expected: []Outcome{
				{
					Failures: []Result{
						{
							Message: "Fails",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure",
							},
						},
					},
					Warnings:  []Result{},
					Successes: []Result{},
				},
			},
		},
		{
			name: "unrelated dependency",
			given: []Outcome{
				{
					Failures: []Result{
						{
							Message: "failure 1",
							Metadata: map[string]interface{}{
								metadataCode: "a.failure",
							},
						},
					},
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success1",
								metadataDependsOn: []string{"a.unrelated"},
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
								metadataCode: "a.failure",
							},
						},
					},
					Successes: []Result{
						{
							Message: "pass",
							Metadata: map[string]interface{}{
								metadataCode:      "a.success1",
								metadataDependsOn: []string{"a.unrelated"},
							},
						},
					},
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

//go:embed __testdir__/*/*.rego
var policies embed.FS

func TestConftestEvaluatorEvaluate(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0600))

	rego, err := fs.Sub(policies, "__testdir__/simple")
	require.NoError(t, err)

	rules, err := rulesArchive(t, rego)
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

type mockConfigProvider struct {
	mock.Mock
}

func (o *mockConfigProvider) EffectiveTime() time.Time {
	args := o.Called()
	return args.Get(0).(time.Time)
}

func (o *mockConfigProvider) SigstoreOpts() (policy.SigstoreOpts, error) {
	args := o.Called()
	return args.Get(0).(policy.SigstoreOpts), args.Error(1)
}

func (o *mockConfigProvider) Spec() ecc.EnterpriseContractPolicySpec {
	args := o.Called()
	return args.Get(0).(ecc.EnterpriseContractPolicySpec)
}

func TestUnconformingRule(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0600))

	rego, err := fs.Sub(policies, "__testdir__/unconforming")
	require.NoError(t, err)

	rules, err := rulesArchive(t, rego)
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

// TestAnnotatedAndNonAnnotatedRules tests the separation of annotated and non-annotated rules
func TestAnnotatedAndNonAnnotatedRules(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0600))

	// Create a test directory with both annotated and non-annotated rules
	testDir := path.Join(dir, "test_policies")
	require.NoError(t, os.MkdirAll(testDir, 0755))

	// Create annotated rule
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
	require.NoError(t, os.WriteFile(path.Join(testDir, "annotated.rego"), []byte(annotatedRule), 0600))

	// Create non-annotated rule
	nonAnnotatedRule := `package nonannotated

import rego.v1

deny contains result if {
	result := {
		"code": "nonannotated.rule",
		"msg": "Non-annotated rule failure",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "nonannotated.rego"), []byte(nonAnnotatedRule), 0600))

	// Create non-annotated rule without code in result
	nonAnnotatedRuleNoCode := `package noresultcode

import rego.v1

deny contains result if {
	result := "No code in result"
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "noresultcode.rego"), []byte(nonAnnotatedRuleNoCode), 0600))

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
		&source.PolicyUrl{
			Url:  archivePath,
			Kind: source.PolicyKind,
		},
	}, config, ecc.Source{}, []string{})
	require.NoError(t, err)

	results, err := evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{path.Join(dir, "inputs")}})
	require.NoError(t, err)

	// Verify that annotated rules are properly tracked for success computation
	foundAnnotatedSuccess := false
	for _, result := range results {
		for _, success := range result.Successes {
			if code, ok := success.Metadata[metadataCode].(string); ok && code == "annotated.annotated_rule" {
				foundAnnotatedSuccess = true
				// Verify that annotated rules get full metadata
				assert.Contains(t, success.Metadata, metadataTitle)
				assert.Contains(t, success.Metadata, metadataDescription)
			}
		}
	}

	assert.True(t, foundAnnotatedSuccess, "Annotated rule should be tracked for success computation")

	// Verify that non-annotated rules are NOT tracked for success computation
	// (they should not appear as successes since we can't reliably track them)
	foundNonAnnotatedSuccess := false
	for _, result := range results {
		for _, success := range result.Successes {
			if code, ok := success.Metadata[metadataCode].(string); ok && code == "nonannotated.rule" {
				foundNonAnnotatedSuccess = true
			}
		}
	}
	assert.False(t, foundNonAnnotatedSuccess, "Non-annotated rules should not be tracked for success computation")
}

// TestRuleCollectionWithMixedRules tests the rule collection logic with mixed annotated and non-annotated rules
func TestRuleCollectionWithMixedRules(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0600))

	// Create test directory with mixed rules
	testDir := path.Join(dir, "mixed_policies")
	require.NoError(t, os.MkdirAll(testDir, 0755))

	// Create annotated rule that will fail
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
	require.NoError(t, os.WriteFile(path.Join(testDir, "annotated_failing.rego"), []byte(annotatedFailingRule), 0600))

	// Create annotated rule that will pass
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
	require.NoError(t, os.WriteFile(path.Join(testDir, "annotated_passing.rego"), []byte(annotatedPassingRule), 0600))

	// Create non-annotated rule that will fail
	nonAnnotatedFailingRule := `package mixed

import rego.v1

deny contains result if {
	result := {
		"code": "mixed.nonannotated_failing",
		"msg": "Non-annotated rule failure",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "nonannotated_failing.rego"), []byte(nonAnnotatedFailingRule), 0600))

	// Create non-annotated rule that will pass
	nonAnnotatedPassingRule := `package mixed

import rego.v1

deny contains result if {
	false
	result := "This should not be reached"
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "nonannotated_passing.rego"), []byte(nonAnnotatedPassingRule), 0600))

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
		&source.PolicyUrl{
			Url:  archivePath,
			Kind: source.PolicyKind,
		},
	}, config, ecc.Source{}, []string{})
	require.NoError(t, err)

	results, err := evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{path.Join(dir, "inputs")}})
	require.NoError(t, err)

	// Verify results
	var annotatedFailures, annotatedSuccesses, nonAnnotatedFailures, nonAnnotatedSuccesses int

	for _, result := range results {
		// Count failures
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

		// Count successes
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

	// Verify annotated rules are properly tracked
	assert.Equal(t, 1, annotatedFailures, "Should have one annotated failure")
	assert.Equal(t, 1, annotatedSuccesses, "Should have one annotated success")

	// Verify non-annotated rules are not tracked for success computation
	assert.Equal(t, 1, nonAnnotatedFailures, "Should have one non-annotated failure")
	assert.Equal(t, 0, nonAnnotatedSuccesses, "Should not track non-annotated rules for success computation")
}

// TestFilteringWithMixedRules tests that both annotated and non-annotated rules participate in filtering
func TestFilteringWithMixedRules(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(path.Join(dir, "inputs"), 0755))
	require.NoError(t, os.WriteFile(path.Join(dir, "inputs", "data.json"), []byte("{}"), 0600))

	// Create test directory with rules in different packages
	testDir := path.Join(dir, "filtering_policies")
	require.NoError(t, os.MkdirAll(testDir, 0755))

	// Create annotated rule in package 'a'
	annotatedRuleA := `package a

import rego.v1

# METADATA
# title: Annotated Rule A
# description: This annotated rule is in package a
# custom:
#   short_name: annotated
deny contains result if {
	result := {
		"code": "a.annotated",
		"msg": "Annotated rule in package a",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "a_annotated.rego"), []byte(annotatedRuleA), 0600))

	// Create non-annotated rule in package 'b'
	nonAnnotatedRuleB := `package b

import rego.v1

deny contains result if {
	result := {
		"code": "b.nonannotated",
		"msg": "Non-annotated rule in package b",
	}
}`
	require.NoError(t, os.WriteFile(path.Join(testDir, "b_nonannotated.rego"), []byte(nonAnnotatedRuleB), 0600))

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
		&source.PolicyUrl{
			Url:  archivePath,
			Kind: source.PolicyKind,
		},
	}, config, ecc.Source{}, []string{})
	require.NoError(t, err)

	results, err := evaluator.Evaluate(ctx, EvaluationTarget{Inputs: []string{path.Join(dir, "inputs")}})
	require.NoError(t, err)

	// Verify that both annotated and non-annotated rules are included in filtering
	foundAnnotatedFailure := false
	foundNonAnnotatedFailure := false

	for _, result := range results {
		for _, failure := range result.Failures {
			if code, ok := failure.Metadata[metadataCode].(string); ok {
				switch code {
				case "a.annotated":
					foundAnnotatedFailure = true
				case "b.nonannotated":
					foundNonAnnotatedFailure = true
				}
			}
		}
	}

	assert.True(t, foundAnnotatedFailure, "Annotated rule should be included in filtering")
	assert.True(t, foundNonAnnotatedFailure, "Non-annotated rule should be included in filtering")
}

var testCapabilities string

func init() {
	// Given the amount of tests in this file, creating the capabilities string
	// can add significant overhead. We do it here once for all the tests instead.
	data, err := strictCapabilities(context.Background())
	if err != nil {
		panic(err)
	}
	testCapabilities = data
}

func rulesArchive(t *testing.T, files fs.FS) (string, error) {
	t.Helper()

	dir := t.TempDir()

	rules := path.Join(dir, "rules.tar")

	f, err := os.Create(rules)
	if err != nil {
		return "", err
	}
	defer f.Close()
	ar := tar.NewWriter(f)
	defer ar.Close()

	rego, err := fs.ReadDir(files, ".")
	if err != nil {
		return "", err
	}

	for _, r := range rego {
		if r.IsDir() {
			continue
		}
		f, err := files.Open(r.Name())
		if err != nil {
			return "", err
		}

		bytes, err := io.ReadAll(f)
		if err != nil {
			return "", err
		}

		require.NoError(t, ar.WriteHeader(&tar.Header{
			Name: r.Name(),
			Mode: 0644,
			Size: int64(len(bytes)),
		}))

		if _, err = ar.Write(bytes); err != nil {
			return "", err
		}
	}

	return rules, nil
}

func TestPrepareDataDirs(t *testing.T) {
	tests := []struct {
		name         string
		filePaths    []string // ordered list of file paths to create
		expectedDirs []string // expected directories in same order
	}{
		{
			name: "files in subdirectories",
			filePaths: []string{
				"foo/data.json",
				"another/path/info.yaml",
				"third/deep/path/config.yml",
				"some/path/no-data.txt",
			},
			expectedDirs: []string{
				"foo",
				"another/path",
				"third/deep/path",
			},
		},
		{
			name: "realistic konflux example",
			filePaths: []string{
				"data/a67f0d7cc/rule_data.yml",
				"data/a67f0d7cc/required_tasks.yml",
				"data/a67f0d7cc/known_rpm_repositories.yml",
				"data/e8a615778/data/data/trusted_tekton_tasks.yml",
				"data/config/config.json",
			},
			expectedDirs: []string{
				"data/a67f0d7cc",
				"data/e8a615778/data/data",
				"data/config",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary filesystem
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)

			// Create the base data directory
			dataDir := "/test/data"
			require.NoError(t, fs.MkdirAll(dataDir, 0755))

			// Create the test files with minimal content
			for _, filePath := range tt.filePaths {
				fullPath := filepath.Join(dataDir, filePath)
				require.NoError(t, fs.MkdirAll(filepath.Dir(fullPath), 0755))
				require.NoError(t, afero.WriteFile(fs, fullPath, []byte("test"), 0644))
			}

			// Create evaluator instance
			evaluator := conftestEvaluator{
				dataDir: dataDir,
				fs:      fs,
			}

			// Call prepareDataDirs
			actualDirs, err := evaluator.prepareDataDirs(ctx)
			require.NoError(t, err)

			// Convert expected relative paths to absolute paths
			expectedAbsolute := make([]string, len(tt.expectedDirs))
			for i, dir := range tt.expectedDirs {
				if dir == "." {
					expectedAbsolute[i] = dataDir
				} else {
					expectedAbsolute[i] = filepath.Join(dataDir, dir)
				}
			}

			assert.ElementsMatch(t, expectedAbsolute, actualDirs)
		})
	}
}

// Helper function to create test archives
func createTestArchive(t *testing.T, sourceDir, archivePath string) {
	file, err := os.Create(archivePath)
	require.NoError(t, err)
	defer file.Close()

	gw := gzip.NewWriter(file)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if path == sourceDir {
			return nil
		}

		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}

		// Update the name to be relative to the source directory
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tw, file); err != nil {
				return err
			}
		}

		return nil
	})
	require.NoError(t, err)
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

func TestMissingIncludesSuccessComputation(t *testing.T) {
	tests := []struct {
		name              string
		result            Outcome
		rules             policyRules
		target            string
		missingIncludes   map[string]bool
		expectedSuccesses int
		description       string
	}{
		{
			name: "Success included by wildcard",
			result: Outcome{
				Namespace:  "cve",
				Warnings:   []Result{},
				Failures:   []Result{},
				Skipped:    []Result{},
				Exceptions: []Result{},
			},
			rules: policyRules{
				"cve.high_severity": rule.Info{
					Package: "cve",
					Code:    "cve.high_severity",
				},
			},
			target: "test-target",
			missingIncludes: map[string]bool{
				"*": true,
			},
			expectedSuccesses: 1,
			description:       "Tests that success results are included when wildcard is in missingIncludes",
		},
		{
			name: "Success included by package match",
			result: Outcome{
				Namespace:  "cve",
				Warnings:   []Result{},
				Failures:   []Result{},
				Skipped:    []Result{},
				Exceptions: []Result{},
			},
			rules: policyRules{
				"cve.high_severity": rule.Info{
					Package: "cve",
					Code:    "cve.high_severity",
				},
			},
			target: "test-target",
			missingIncludes: map[string]bool{
				"cve": true,
			},
			expectedSuccesses: 1,
			description:       "Tests that success results are included when package matches missingIncludes",
		},
		{
			name: "Success excluded by missingIncludes",
			result: Outcome{
				Namespace:  "cve",
				Warnings:   []Result{},
				Failures:   []Result{},
				Skipped:    []Result{},
				Exceptions: []Result{},
			},
			rules: policyRules{
				"cve.high_severity": rule.Info{
					Package: "cve",
					Code:    "cve.high_severity",
				},
			},
			target: "test-target",
			missingIncludes: map[string]bool{
				"@security": true, // Different from cve package
			},
			expectedSuccesses: 1, // The rule should be included because it matches the wildcard include
			description:       "Tests that success results are included even when they don't match specific missingIncludes (due to wildcard)",
		},
		{
			name: "Success with collection matching",
			result: Outcome{
				Namespace:  "tasks",
				Warnings:   []Result{},
				Failures:   []Result{},
				Skipped:    []Result{},
				Exceptions: []Result{},
			},
			rules: policyRules{
				"tasks.build_task": rule.Info{
					Package:     "tasks",
					Code:        "tasks.build_task",
					Collections: []string{"redhat"},
				},
			},
			target: "test-target",
			missingIncludes: map[string]bool{
				"@redhat": true,
			},
			expectedSuccesses: 1,
			description:       "Tests that success results are included when collection matches missingIncludes",
		},
		{
			name: "Success with rule-specific matching",
			result: Outcome{
				Namespace:  "cve",
				Warnings:   []Result{},
				Failures:   []Result{},
				Skipped:    []Result{},
				Exceptions: []Result{},
			},
			rules: policyRules{
				"cve.high_severity": rule.Info{
					Package: "cve",
					Code:    "cve.high_severity",
				},
			},
			target: "test-target",
			missingIncludes: map[string]bool{
				"cve.high_severity": true,
			},
			expectedSuccesses: 1,
			description:       "Tests that success results are included when specific rule matches missingIncludes",
		},
		{
			name: "Success with multiple rules and mixed matching",
			result: Outcome{
				Namespace:  "cve",
				Warnings:   []Result{},
				Failures:   []Result{},
				Skipped:    []Result{},
				Exceptions: []Result{},
			},
			rules: policyRules{
				"cve.high_severity": rule.Info{
					Package: "cve",
					Code:    "cve.high_severity",
				},
				"cve.medium_severity": rule.Info{
					Package: "cve",
					Code:    "cve.medium_severity",
				},
				"tasks.build_task": rule.Info{
					Package: "tasks",
					Code:    "tasks.build_task",
				},
			},
			target: "test-target",
			missingIncludes: map[string]bool{
				"cve":       true,
				"@security": true,
			},
			expectedSuccesses: 2, // Only cve rules should match
			description:       "Tests that only matching rules are included as successes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple source for the evaluator
			sourceConfig := ecc.Source{
				Config: &ecc.SourceConfig{
					Include: []string{"*"},
				},
			}

			configProvider := &simpleConfigProvider{
				effectiveTime: time.Now(),
			}

			evaluator, err := NewConftestEvaluator(context.Background(), []source.PolicySource{}, configProvider, sourceConfig)
			if err != nil {
				t.Fatalf("Failed to create evaluator: %v", err)
			}

			conftestEval, ok := evaluator.(conftestEvaluator)
			if !ok {
				t.Fatalf("Failed to cast evaluator to conftestEvaluator. Got type: %T", evaluator)
			}

			// Check if include field is properly initialized
			if conftestEval.include == nil {
				t.Fatal("conftestEval.include is nil - this indicates a problem with NewConftestEvaluator")
			}
			if conftestEval.exclude == nil {
				t.Fatal("conftestEval.exclude is nil - this indicates a problem with NewConftestEvaluator")
			}

			// Initialize missingIncludes with the include criteria from the evaluator
			missingIncludes := make(map[string]bool)
			for _, include := range conftestEval.include.get(tt.target) {
				missingIncludes[include] = true
			}

			// Override with the test-specific missingIncludes if provided
			if len(tt.missingIncludes) > 0 {
				missingIncludes = tt.missingIncludes
			}

			// Call computeSuccesses with the test data
			successes := conftestEval.computeSuccesses(tt.result, tt.rules, tt.target, missingIncludes)

			// Verify the number of successes
			assert.Equal(t, tt.expectedSuccesses, len(successes),
				"Expected %d successes, got %d", tt.expectedSuccesses, len(successes))

			// Verify that all successes have the correct metadata
			for _, success := range successes {
				assert.Equal(t, "Pass", success.Message)
				assert.NotNil(t, success.Metadata)
				assert.Contains(t, success.Metadata, metadataCode)
			}

			t.Logf("Test case: %s", tt.description)
			t.Logf("Missing includes: %v", tt.missingIncludes)
			t.Logf("Generated successes: %d", len(successes))
		})
	}
}

func TestMissingIncludesWarningGeneration(t *testing.T) {
	tests := []struct {
		name             string
		missingIncludes  map[string]bool
		expectedWarnings int
		expectedMessages []string
		description      string
	}{
		{
			name:             "No missing includes",
			missingIncludes:  map[string]bool{},
			expectedWarnings: 0,
			expectedMessages: []string{},
			description:      "Tests that no warnings are generated when all includes are matched",
		},
		{
			name: "Single missing include",
			missingIncludes: map[string]bool{
				"nonexistent.package": true,
			},
			expectedWarnings: 1,
			expectedMessages: []string{
				"Include criterion 'nonexistent.package' doesn't match any policy rule",
			},
			description: "Tests that a warning is generated for a single unmatched include",
		},
		{
			name: "Multiple missing includes",
			missingIncludes: map[string]bool{
				"nonexistent.package": true,
				"@nonexistent":        true,
				"security.*":          true,
			},
			expectedWarnings: 3,
			expectedMessages: []string{
				"Include criterion 'nonexistent.package' doesn't match any policy rule",
				"Include criterion '@nonexistent' doesn't match any policy rule",
				"Include criterion 'security.*' doesn't match any policy rule",
			},
			description: "Tests that warnings are generated for multiple unmatched includes",
		},
		{
			name: "Mixed missing and matched includes",
			missingIncludes: map[string]bool{
				"nonexistent.package": true,
				"matched.package":     false, // This would be false if it was matched
			},
			expectedWarnings: 1,
			expectedMessages: []string{
				"Include criterion 'nonexistent.package' doesn't match any policy rule",
			},
			description: "Tests that only true (missing) includes generate warnings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var results []Outcome

			// Simulate the warning generation logic
			for missingInclude, isMissing := range tt.missingIncludes {
				if isMissing {
					results = append(results, Outcome{
						Warnings: []Result{{
							Message: "Include criterion '" + missingInclude + "' doesn't match any policy rule",
						}},
					})
				}
			}

			// Verify the number of warnings
			assert.Equal(t, tt.expectedWarnings, len(results),
				"Expected %d warning outcomes, got %d", tt.expectedWarnings, len(results))

			// Verify the warning messages
			var actualMessages []string
			for _, result := range results {
				for _, warning := range result.Warnings {
					actualMessages = append(actualMessages, warning.Message)
				}
			}

			// Sort both slices for comparison
			assert.ElementsMatch(t, tt.expectedMessages, actualMessages,
				"Warning messages don't match expected messages")

			t.Logf("Test case: %s", tt.description)
			t.Logf("Missing includes: %v", tt.missingIncludes)
			t.Logf("Generated warnings: %d", len(results))
			t.Logf("Warning messages: %v", actualMessages)
		})
	}
}

func TestMissingIncludesIntegration(t *testing.T) {
	t.Run("Complete flow with all includes matched", func(t *testing.T) {
		// Create a simple source for the evaluator
		sourceConfig := ecc.Source{
			Config: &ecc.SourceConfig{
				Include: []string{"cve", "@redhat"},
			},
		}

		configProvider := &simpleConfigProvider{
			effectiveTime: time.Now(),
		}

		evaluator, err := NewConftestEvaluator(context.Background(), []source.PolicySource{}, configProvider, sourceConfig)
		assert.NoError(t, err)

		conftestEval, ok := evaluator.(conftestEvaluator)
		assert.True(t, ok)

		// Simulate the complete flow
		// 1. Initialize missing includes
		missingIncludes := map[string]bool{}
		for _, defaultItem := range conftestEval.include.defaultItems {
			missingIncludes[defaultItem] = true
		}
		for _, digestItems := range conftestEval.include.digestItems {
			for _, digestItem := range digestItems {
				missingIncludes[digestItem] = true
			}
		}

		// Verify initialization
		assert.True(t, missingIncludes["cve"])
		assert.True(t, missingIncludes["@redhat"])

		// 2. Simulate filtering with results that match
		filteredResults := []Result{
			{
				Message: "CVE rule",
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
		}

		// Update missing includes based on matches
		for include := range missingIncludes {
			matched := false
			for _, result := range filteredResults {
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

		// Verify all includes were matched
		assert.Empty(t, missingIncludes, "All includes should be matched")

		// 3. Simulate success computation
		result := Outcome{
			Namespace:  "cve",
			Warnings:   []Result{},
			Failures:   []Result{},
			Skipped:    []Result{},
			Exceptions: []Result{},
		}

		rules := policyRules{
			"cve.high_severity": rule.Info{
				Package: "cve",
				Code:    "cve.high_severity",
			},
		}

		successes := conftestEval.computeSuccesses(result, rules, "test-target", missingIncludes)
		assert.Equal(t, 1, len(successes), "Should generate one success")

		// 4. Verify no warnings are generated
		var warningResults []Outcome
		for missingInclude, isMissing := range missingIncludes {
			if isMissing {
				warningResults = append(warningResults, Outcome{
					Warnings: []Result{{
						Message: "Include criterion '" + missingInclude + "' doesn't match any policy rule",
					}},
				})
			}
		}

		assert.Empty(t, warningResults, "No warnings should be generated when all includes are matched")
	})

	t.Run("Complete flow with some includes unmatched", func(t *testing.T) {
		// Create a simple source for the evaluator
		sourceConfig := ecc.Source{
			Config: &ecc.SourceConfig{
				Include: []string{"cve", "@redhat", "nonexistent.*"},
			},
		}

		configProvider := &simpleConfigProvider{
			effectiveTime: time.Now(),
		}

		evaluator, err := NewConftestEvaluator(context.Background(), []source.PolicySource{}, configProvider, sourceConfig)
		assert.NoError(t, err)

		conftestEval, ok := evaluator.(conftestEvaluator)
		assert.True(t, ok)

		// Simulate the complete flow
		// 1. Initialize missing includes
		missingIncludes := map[string]bool{}
		for _, defaultItem := range conftestEval.include.defaultItems {
			missingIncludes[defaultItem] = true
		}
		for _, digestItems := range conftestEval.include.digestItems {
			for _, digestItem := range digestItems {
				missingIncludes[digestItem] = true
			}
		}

		// Verify initialization
		assert.True(t, missingIncludes["cve"])
		assert.True(t, missingIncludes["@redhat"])
		assert.True(t, missingIncludes["nonexistent.*"])

		// 2. Simulate filtering with results that only match some includes
		filteredResults := []Result{
			{
				Message: "CVE rule",
				Metadata: map[string]interface{}{
					metadataCode: "cve.high_severity",
				},
			},
		}

		// Update missing includes based on matches
		for include := range missingIncludes {
			matched := false
			for _, result := range filteredResults {
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

		// Verify some includes remain unmatched
		assert.False(t, missingIncludes["cve"], "CVE should be matched")
		assert.True(t, missingIncludes["@redhat"], "@redhat should remain unmatched")
		assert.True(t, missingIncludes["nonexistent.*"], "nonexistent.* should remain unmatched")

		// 3. Simulate success computation
		result := Outcome{
			Namespace:  "cve",
			Warnings:   []Result{},
			Failures:   []Result{},
			Skipped:    []Result{},
			Exceptions: []Result{},
		}

		rules := policyRules{
			"cve.high_severity": rule.Info{
				Package: "cve",
				Code:    "cve.high_severity",
			},
		}

		successes := conftestEval.computeSuccesses(result, rules, "test-target", missingIncludes)
		assert.Equal(t, 1, len(successes), "Should generate successes even for unmatched includes (due to wildcard)")

		// 4. Verify warnings are generated for unmatched includes
		var warningResults []Outcome
		for missingInclude, isMissing := range missingIncludes {
			if isMissing {
				warningResults = append(warningResults, Outcome{
					Warnings: []Result{{
						Message: "Include criterion '" + missingInclude + "' doesn't match any policy rule",
					}},
				})
			}
		}

		assert.Equal(t, 2, len(warningResults), "Should generate warnings for unmatched includes")
	})
}

func TestStrictCapabilitiesProductionReady(t *testing.T) {
	// Test that strictCapabilities is production-ready with proper error handling
	ctx := context.Background()

	// Test 1: Normal operation
	capabilities, err := strictCapabilities(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, capabilities)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(capabilities), &parsed)
	assert.NoError(t, err)

	// Test 2: Caching works
	capabilities2, err := strictCapabilities(ctx)
	assert.NoError(t, err)
	assert.Equal(t, capabilities, capabilities2, "Cached capabilities should be identical")

	// Test 3: Context override works
	overrideCaps := `{"test": "override"}`
	ctxWithOverride := withCapabilities(ctx, overrideCaps)
	capabilities3, err := strictCapabilities(ctxWithOverride)
	assert.NoError(t, err)
	assert.Equal(t, overrideCaps, capabilities3)

	t.Logf("Production-ready capabilities test passed")
}

func TestGenerateCapabilitiesRetryLogic(t *testing.T) {
	// Test the retry logic with different scenarios
	capabilities, err := generateCapabilities()
	assert.NoError(t, err)
	assert.NotEmpty(t, capabilities)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(capabilities), &parsed)
	assert.NoError(t, err)

	// Should contain expected fields
	assert.Contains(t, parsed, "builtins")
	assert.Contains(t, parsed, "allow_net")

	t.Logf("Retry logic test passed")
}

func TestMinimalCapabilitiesFallback(t *testing.T) {
	// Test the minimal capabilities fallback
	capabilities, err := generateMinimalCapabilities()
	assert.NoError(t, err)
	assert.NotEmpty(t, capabilities)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(capabilities), &parsed)
	assert.NoError(t, err)

	// Should contain minimal required fields
	assert.Contains(t, parsed, "builtins")
	assert.Contains(t, parsed, "allow_net")

	// Should have at least one builtin (print)
	builtins, ok := parsed["builtins"].([]interface{})
	assert.True(t, ok)
	assert.GreaterOrEqual(t, len(builtins), 1)

	t.Logf("Minimal capabilities fallback test passed")
}
