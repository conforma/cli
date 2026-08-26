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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	conftest "github.com/open-policy-agent/conftest/policy"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/utils"
)

func TestOPADestroy(t *testing.T) {
	fs := afero.NewMemMapFs()
	workDir := "/tmp/workdir"

	testCases := []struct {
		name         string
		workDir      string
		EC_DEBUG     bool
		expectRemove bool
	}{
		{
			name:         "Empty workDir, EC_DEBUG not set",
			workDir:      "",
			EC_DEBUG:     false,
			expectRemove: false,
		},
		{
			name:         "Non-empty workDir, EC_DEBUG not set",
			workDir:      workDir,
			EC_DEBUG:     false,
			expectRemove: true,
		},
		{
			name:         "Non-empty workDir, EC_DEBUG set",
			workDir:      workDir,
			EC_DEBUG:     true,
			expectRemove: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.workDir != "" {
				err := fs.MkdirAll(tc.workDir, 0o755)
				assert.NoError(t, err)
			}

			if tc.EC_DEBUG {
				t.Setenv("EC_DEBUG", "true")
			} else {
				t.Setenv("EC_DEBUG", "")
				os.Unsetenv("EC_DEBUG")
			}

			opaEval := opaEvaluator{
				basePolicyEvaluator: basePolicyEvaluator{
					workDir: tc.workDir,
					fs:      fs,
				},
			}

			opaEval.Destroy()

			exists, err := afero.DirExists(fs, tc.workDir)
			assert.NoError(t, err)

			if tc.expectRemove {
				assert.False(t, exists, "workDir should be removed")
			} else {
				assert.True(t, exists, "workDir should not be removed")
			}

			_ = fs.RemoveAll(tc.workDir)
		})
	}
}

func TestOPACapabilitiesPath(t *testing.T) {
	testCases := []struct {
		name     string
		workDir  string
		expected string
	}{
		{
			name:     "Non-empty workDir",
			workDir:  "/tmp/workdir",
			expected: "/tmp/workdir/capabilities.json",
		},
		{
			name:     "Root workDir",
			workDir:  "/",
			expected: "/capabilities.json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opaEval := opaEvaluator{
				basePolicyEvaluator: basePolicyEvaluator{
					workDir: tc.workDir,
					fs:      afero.NewMemMapFs(),
				},
			}

			result := opaEval.CapabilitiesPath()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsOPAFailure(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"deny", "deny", true},
		{"deny_with_suffix", "deny_foo", true},
		{"deny_multi_suffix", "deny_foo_bar", true},
		{"violation", "violation", true},
		{"violation_with_suffix", "violation_check1", true},
		{"warn_not_failure", "warn", false},
		{"warn_suffix_not_failure", "warn_thing", false},
		{"random_name", "allow", false},
		{"deny_prefix_only", "denyall", false},
		{"empty", "", false},
		{"deny_special_chars", "deny_foo-bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isOPAFailure(tt.input))
		})
	}
}

func TestIsOPAWarning(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"warn", "warn", true},
		{"warn_with_suffix", "warn_foo", true},
		{"warn_multi_suffix", "warn_foo_bar", true},
		{"deny_not_warning", "deny", false},
		{"violation_not_warning", "violation", false},
		{"random_name", "allow", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isOPAWarning(tt.input))
		})
	}
}

func TestStripRulePrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"deny_bare", "deny", ""},
		{"violation_bare", "violation", ""},
		{"warn_bare", "warn", ""},
		{"deny_prefix", "deny_foo", "foo"},
		{"violation_prefix", "violation_check", "check"},
		{"warn_prefix", "warn_thing", "thing"},
		{"no_prefix", "allow", "allow"},
		{"deny_multi_part", "deny_foo_bar", "foo_bar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, stripRulePrefix(tt.input))
		})
	}
}

func TestOpaPrintHook(t *testing.T) {
	s := &[]string{}
	ph := opaPrintHook{s: s}

	err := ph.Print(print.Context{Location: nil}, "hello world")
	require.NoError(t, err)
	assert.Len(t, *s, 1)
	assert.Contains(t, (*s)[0], "hello world")

	err = ph.Print(print.Context{Location: nil}, "second message")
	require.NoError(t, err)
	assert.Len(t, *s, 2)
}

func TestOpaParseInputFiles(t *testing.T) {
	t.Run("single file", func(t *testing.T) {
		dir := t.TempDir()
		inputFile := filepath.Join(dir, "input.json")
		content := `{"image": {"ref": "registry.example.com/image:latest"}}`
		require.NoError(t, os.WriteFile(inputFile, []byte(content), 0600))

		configs, err := opaParseInputFiles([]string{inputFile})
		require.NoError(t, err)
		assert.Len(t, configs, 1)

		for _, v := range configs {
			m, ok := v.(map[string]any)
			require.True(t, ok)
			img, ok := m["image"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "registry.example.com/image:latest", img["ref"])
		}
	})

	t.Run("directory of files", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "a.json"),
			[]byte(`{"key": "value_a"}`), 0600))
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "b.json"),
			[]byte(`{"key": "value_b"}`), 0600))

		configs, err := opaParseInputFiles([]string{dir})
		require.NoError(t, err)
		assert.Len(t, configs, 2)
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := opaParseInputFiles([]string{"/nonexistent/file.json"})
		assert.Error(t, err)
	})
}

func setupOPAEngine(t *testing.T, policyContent string) (*conftest.Engine, string) {
	t.Helper()
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policy")
	require.NoError(t, os.MkdirAll(policyDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(policyDir, "policy.rego"),
		[]byte(policyContent), 0600))

	capPath := filepath.Join(dir, "capabilities.json")
	require.NoError(t, os.WriteFile(capPath, []byte(testCapabilities), 0600))

	capabilities, err := conftest.LoadCapabilities(capPath)
	require.NoError(t, err)

	engine, err := conftest.LoadWithData([]string{policyDir}, nil, conftest.CompilerOptions{
		RegoVersion:  "v1",
		Capabilities: capabilities,
	})
	require.NoError(t, err)
	return engine, dir
}

func TestEvalOPAQuery(t *testing.T) {
	policyContent := `package main

import rego.v1

deny contains result if {
	input.value == "bad"
	result := "value is bad"
}

deny_structured contains result if {
	input.value == "structured"
	result := {
		"msg": "structured failure",
		"code": "main.structured",
	}
}

warn contains result if {
	input.level == "warning"
	result := "this is a warning"
}
`
	engine, _ := setupOPAEngine(t, policyContent)

	o := &opaEvaluator{engine: engine}
	ctx := context.Background()

	t.Run("deny rule with string result", func(t *testing.T) {
		results, err := o.evalOPAQuery(ctx, map[string]any{"value": "bad"}, "data.main.deny")
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "value is bad", results[0].Message)
	})

	t.Run("deny rule with structured result", func(t *testing.T) {
		results, err := o.evalOPAQuery(ctx, map[string]any{"value": "structured"}, "data.main.deny_structured")
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "structured failure", results[0].Message)
		assert.Equal(t, "main.structured", results[0].Metadata["code"])
	})

	t.Run("no match returns empty result", func(t *testing.T) {
		results, err := o.evalOPAQuery(ctx, map[string]any{"value": "good"}, "data.main.deny")
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "", results[0].Message)
	})

	t.Run("warn rule", func(t *testing.T) {
		results, err := o.evalOPAQuery(ctx, map[string]any{"level": "warning"}, "data.main.warn")
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "this is a warning", results[0].Message)
	})

	t.Run("unexpected result type surfaces as message", func(t *testing.T) {
		intPolicy := `package inttest

import rego.v1

deny contains result if {
	input.value == "bad"
	result := 42
}
`
		intEngine, _ := setupOPAEngine(t, intPolicy)
		oi := &opaEvaluator{engine: intEngine}

		results, err := oi.evalOPAQuery(ctx, map[string]any{"value": "bad"}, "data.inttest.deny")
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Contains(t, results[0].Message, "unexpected policy result type")
	})
}

func TestCollectRuleNames(t *testing.T) {
	policyContent := `package collect.test

import rego.v1

deny contains result if {
	result := "fail"
}

warn contains result if {
	result := "warning"
}

deny_extra contains result if {
	result := "extra"
}

allow if { true }
`
	engine, _ := setupOPAEngine(t, policyContent)
	o := &opaEvaluator{engine: engine}

	t.Run("collects deny and warn rules", func(t *testing.T) {
		names := o.collectRuleNames("collect.test")
		assert.Contains(t, names, "deny")
		assert.Contains(t, names, "warn")
		assert.Contains(t, names, "deny_extra")
		assert.Len(t, names, 3)
	})

	t.Run("excludes non-deny/warn rules", func(t *testing.T) {
		names := o.collectRuleNames("collect.test")
		for _, n := range names {
			assert.NotEqual(t, "allow", n)
		}
	})

	t.Run("returns nil for unknown namespace", func(t *testing.T) {
		names := o.collectRuleNames("unknown.ns")
		assert.Nil(t, names)
	})
}

func TestEvaluateRule(t *testing.T) {
	policyContent := `package rule.test

import rego.v1

deny contains result if {
	input.fail == true
	result := "denied"
}

warn contains result if {
	input.warn == true
	result := "warned"
}
`
	engine, _ := setupOPAEngine(t, policyContent)
	o := &opaEvaluator{engine: engine}
	ctx := context.Background()

	t.Run("failure result", func(t *testing.T) {
		result, err := o.evaluateRule(ctx, map[string]any{"fail": true}, "rule.test", "deny")
		require.NoError(t, err)
		require.Len(t, result.failures, 1)
		assert.Equal(t, "denied", result.failures[0].Message)
		assert.Empty(t, result.warnings)
		assert.Empty(t, result.exceptions)
	})

	t.Run("warning result", func(t *testing.T) {
		result, err := o.evaluateRule(ctx, map[string]any{"warn": true}, "rule.test", "warn")
		require.NoError(t, err)
		require.Len(t, result.warnings, 1)
		assert.Equal(t, "warned", result.warnings[0].Message)
		assert.Empty(t, result.failures)
	})

	t.Run("success when rule passes", func(t *testing.T) {
		result, err := o.evaluateRule(ctx, map[string]any{"fail": false}, "rule.test", "deny")
		require.NoError(t, err)
		assert.Empty(t, result.failures)
		assert.Equal(t, 1, result.successes)
	})

	t.Run("exception suppresses failures", func(t *testing.T) {
		excPolicy := `package rule.exc

import rego.v1

deny contains result if {
	input.fail == true
	result := "denied"
}

exception contains rules if {
	rules := ["", ""]
}
`
		excEngine, _ := setupOPAEngine(t, excPolicy)
		oe := &opaEvaluator{engine: excEngine}

		result, err := oe.evaluateRule(ctx, map[string]any{"fail": true}, "rule.exc", "deny")
		require.NoError(t, err)
		assert.NotEmpty(t, result.exceptions)
		assert.Empty(t, result.failures)
	})
}

func TestQueryNamespace(t *testing.T) {
	policyContent := `package test.ns

import rego.v1

deny contains result if {
	input.fail == true
	result := {
		"msg": "input failed",
		"code": "test.ns.deny",
	}
}

warn contains result if {
	input.warn == true
	result := "warning message"
}

deny_extra contains result if {
	input.extra == true
	result := "extra failure"
}
`
	engine, _ := setupOPAEngine(t, policyContent)

	o := &opaEvaluator{engine: engine}
	ctx := context.Background()

	t.Run("failure result", func(t *testing.T) {
		outcome, err := o.queryNamespace(ctx, "test.json", map[string]any{"fail": true}, "test.ns")
		require.NoError(t, err)
		assert.Equal(t, "test.ns", outcome.Namespace)
		assert.Equal(t, "test.json", outcome.FileName)
		assert.Len(t, outcome.Failures, 1)
		assert.Equal(t, "input failed", outcome.Failures[0].Message)
	})

	t.Run("warning result", func(t *testing.T) {
		outcome, err := o.queryNamespace(ctx, "test.json", map[string]any{"warn": true}, "test.ns")
		require.NoError(t, err)
		assert.Len(t, outcome.Warnings, 1)
		assert.Equal(t, "warning message", outcome.Warnings[0].Message)
	})

	t.Run("success when rules pass", func(t *testing.T) {
		outcome, err := o.queryNamespace(ctx, "test.json", map[string]any{"fail": false, "warn": false, "extra": false}, "test.ns")
		require.NoError(t, err)
		assert.Empty(t, outcome.Failures)
		assert.Empty(t, outcome.Warnings)
		assert.NotEmpty(t, outcome.Successes)
	})

	t.Run("nonexistent namespace", func(t *testing.T) {
		outcome, err := o.queryNamespace(ctx, "test.json", map[string]any{}, "nonexistent.ns")
		require.NoError(t, err)
		assert.Empty(t, outcome.Failures)
		assert.Empty(t, outcome.Warnings)
		assert.Empty(t, outcome.Successes)
	})

	t.Run("multiple failures", func(t *testing.T) {
		outcome, err := o.queryNamespace(ctx, "test.json", map[string]any{"fail": true, "extra": true}, "test.ns")
		require.NoError(t, err)
		assert.Len(t, outcome.Failures, 2)
	})
}

func TestQueryNamespaceWithExceptions(t *testing.T) {
	policyContent := `package test.exc

import rego.v1

deny contains result if {
	input.fail == true
	result := "should fail"
}

exception contains rules if {
	rules := ["", ""]
}
`
	engine, _ := setupOPAEngine(t, policyContent)

	o := &opaEvaluator{engine: engine}
	ctx := context.Background()

	outcome, err := o.queryNamespace(ctx, "test.json", map[string]any{"fail": true}, "test.exc")
	require.NoError(t, err)
	assert.Empty(t, outcome.Failures, "failures should be suppressed by exception")
	assert.NotEmpty(t, outcome.Exceptions)
}

func TestEvaluateWithEngine(t *testing.T) {
	policyContent := `package eval.test

import rego.v1

deny contains result if {
	input.should_fail == true
	result := {
		"msg": "evaluation failed",
		"code": "eval.test.deny",
	}
}
`
	engine, dir := setupOPAEngine(t, policyContent)

	t.Run("with parsed input", func(t *testing.T) {
		o := &opaEvaluator{
			engine: engine,
			basePolicyEvaluator: basePolicyEvaluator{
				namespace: []string{"eval.test"},
			},
		}

		target := EvaluationTarget{
			ParsedInput: map[string]any{"should_fail": true},
		}

		results, err := o.evaluateWithEngine(context.Background(), target, nil)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Len(t, results[0].Failures, 1)
		assert.Equal(t, "evaluation failed", results[0].Failures[0].Message)
	})

	t.Run("with file input", func(t *testing.T) {
		inputFile := filepath.Join(dir, "input.json")
		require.NoError(t, os.WriteFile(inputFile, []byte(`{"should_fail": true}`), 0600))

		o := &opaEvaluator{
			engine: engine,
			basePolicyEvaluator: basePolicyEvaluator{
				namespace: []string{"eval.test"},
			},
		}

		target := EvaluationTarget{
			Inputs: []string{inputFile},
		}

		results, err := o.evaluateWithEngine(context.Background(), target, nil)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Len(t, results[0].Failures, 1)
	})

	t.Run("with filtered namespaces", func(t *testing.T) {
		o := &opaEvaluator{
			engine: engine,
			basePolicyEvaluator: basePolicyEvaluator{
				namespace: []string{"some.other.ns"},
			},
		}

		target := EvaluationTarget{
			ParsedInput: map[string]any{"should_fail": true},
		}

		results, err := o.evaluateWithEngine(context.Background(), target, []string{"eval.test"})
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Len(t, results[0].Failures, 1)
	})

	t.Run("uses engine namespaces when none specified", func(t *testing.T) {
		o := &opaEvaluator{
			engine: engine,
			basePolicyEvaluator: basePolicyEvaluator{
				namespace: nil,
			},
		}

		target := EvaluationTarget{
			ParsedInput: map[string]any{"should_fail": true},
		}

		results, err := o.evaluateWithEngine(context.Background(), target, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, results)
	})

	t.Run("with list input", func(t *testing.T) {
		inputFile := filepath.Join(dir, "list_input.json")
		require.NoError(t, os.WriteFile(inputFile, []byte(`[{"should_fail": true}, {"should_fail": false}]`), 0600))

		o := &opaEvaluator{
			engine: engine,
			basePolicyEvaluator: basePolicyEvaluator{
				namespace: []string{"eval.test"},
			},
		}

		target := EvaluationTarget{
			Inputs: []string{inputFile},
		}

		results, err := o.evaluateWithEngine(context.Background(), target, nil)
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Len(t, results[0].Failures, 1)
	})
}

func TestEnsureInitialized(t *testing.T) {
	t.Run("returns error when no policy sources", func(t *testing.T) {
		o := &opaEvaluator{
			initOnce: &sync.Once{},
			basePolicyEvaluator: basePolicyEvaluator{
				fs: afero.NewMemMapFs(),
			},
		}

		err := o.ensureInitialized(context.Background())
		assert.Error(t, err)
	})

	t.Run("only runs once", func(t *testing.T) {
		callCount := 0
		o := &opaEvaluator{
			initOnce: &sync.Once{},
		}
		o.initOnce.Do(func() {
			callCount++
			o.initErr = fmt.Errorf("test error")
		})

		err := o.ensureInitialized(context.Background())
		assert.Error(t, err)
		assert.Equal(t, 1, callCount)

		err = o.ensureInitialized(context.Background())
		assert.Error(t, err)
		assert.Equal(t, 1, callCount)
	})
}

func TestOPAEvaluateNilEngine(t *testing.T) {
	o := &opaEvaluator{
		initOnce: &sync.Once{},
		engine:   nil,
	}
	o.initOnce.Do(func() {})

	_, err := o.Evaluate(context.Background(), EvaluationTarget{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OPA engine not compiled")
}

func TestBasePolicyEvaluatorPrepareDataDirs(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	dataDir := "/test/data"
	require.NoError(t, fs.MkdirAll(dataDir, 0755))

	require.NoError(t, fs.MkdirAll(filepath.Join(dataDir, "subdir"), 0755))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(dataDir, "subdir", "data.json"), []byte("{}"), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(dataDir, "config.yaml"), []byte("---"), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(dataDir, "readme.txt"), []byte("skip"), 0644))

	b := &basePolicyEvaluator{
		dataDir: dataDir,
		fs:      fs,
	}

	dirs, err := b.prepareDataDirs(ctx)
	require.NoError(t, err)
	assert.Contains(t, dirs, dataDir)
	assert.Contains(t, dirs, filepath.Join(dataDir, "subdir"))
	assert.Len(t, dirs, 2)
}

func TestBasePolicyEvaluatorPrepareDataDirsWithDataSourceDirs(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	dataDir := "/test/data"
	sourceDir := "/test/sources"

	require.NoError(t, fs.MkdirAll(dataDir, 0755))
	require.NoError(t, fs.MkdirAll(filepath.Join(sourceDir, "rule_data"), 0755))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(sourceDir, "rule_data", "data.yml"), []byte("---"), 0644))

	b := &basePolicyEvaluator{
		dataDir:        dataDir,
		fs:             fs,
		dataSourceDirs: []string{sourceDir},
	}

	dirs, err := b.prepareDataDirs(ctx)
	require.NoError(t, err)
	assert.Contains(t, dirs, filepath.Join(sourceDir, "rule_data"))
}

func TestBasePolicyEvaluatorCreateDataDirectory(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	ctx = withCapabilities(ctx, testCapabilities)
	dataDir := "/test/data"

	config := &simpleConfigProvider{effectiveTime: time.Now()}

	b := &basePolicyEvaluator{
		dataDir: dataDir,
		fs:      fs,
		policy:  config,
	}

	err := b.createDataDirectory(ctx)
	require.NoError(t, err)

	exists, err := afero.DirExists(fs, dataDir)
	require.NoError(t, err)
	assert.True(t, exists)

	configExists, err := afero.Exists(fs, filepath.Join(dataDir, "config", "config.json"))
	require.NoError(t, err)
	assert.True(t, configExists)
}

func TestBasePolicyEvaluatorCreateCapabilitiesFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	ctx = withCapabilities(ctx, testCapabilities)
	workDir := "/test/work"

	require.NoError(t, fs.MkdirAll(workDir, 0755))

	b := &basePolicyEvaluator{
		workDir: workDir,
		fs:      fs,
	}

	err := b.createCapabilitiesFile(ctx)
	require.NoError(t, err)

	capPath := b.CapabilitiesPath()
	exists, err := afero.Exists(fs, capPath)
	require.NoError(t, err)
	assert.True(t, exists)

	content, err := afero.ReadFile(fs, capPath)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(content, &parsed))
}

func TestBasePolicyEvaluatorInitWorkDir(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	ctx = withCapabilities(ctx, testCapabilities)

	config := &simpleConfigProvider{effectiveTime: time.Now()}

	b := &basePolicyEvaluator{
		fs:     fs,
		policy: config,
	}

	err := b.initWorkDir(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, b.workDir)
	assert.NotEmpty(t, b.policyDir)
	assert.NotEmpty(t, b.dataDir)

	exists, err := afero.DirExists(fs, b.workDir)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestBasePolicyEvaluatorComputeSuccesses(t *testing.T) {
	rules := policyRules{
		"test.ns.rule1": rule.Info{
			Code:      "test.ns.rule1",
			Package:   "test.ns",
			ShortName: "rule1",
			Title:     "Rule 1",
		},
		"test.ns.rule2": rule.Info{
			Code:      "test.ns.rule2",
			Package:   "test.ns",
			ShortName: "rule2",
			Title:     "Rule 2",
		},
	}

	t.Run("computes successes for rules not in failures", func(t *testing.T) {
		b := &basePolicyEvaluator{
			include: &Criteria{defaultItems: []string{"*"}},
			exclude: &Criteria{},
		}

		result := Outcome{
			Namespace: "test.ns",
			Failures: []Result{
				{
					Message:  "rule1 failed",
					Metadata: map[string]any{metadataCode: "test.ns.rule1"},
				},
			},
		}

		successes := b.computeSuccesses(result, rules, "", "", map[string]bool{}, nil, time.Now())
		assert.Len(t, successes, 1)
		assert.Equal(t, "Pass", successes[0].Message)
		assert.Equal(t, "test.ns.rule2", successes[0].Metadata[metadataCode])
	})

	t.Run("no successes when all rules fail", func(t *testing.T) {
		b := &basePolicyEvaluator{
			include: &Criteria{defaultItems: []string{"*"}},
			exclude: &Criteria{},
		}

		result := Outcome{
			Namespace: "test.ns",
			Failures: []Result{
				{Message: "r1", Metadata: map[string]any{metadataCode: "test.ns.rule1"}},
				{Message: "r2", Metadata: map[string]any{metadataCode: "test.ns.rule2"}},
			},
		}

		successes := b.computeSuccesses(result, rules, "", "", map[string]bool{}, nil, time.Now())
		assert.Empty(t, successes)
	})

	t.Run("all rules succeed", func(t *testing.T) {
		b := &basePolicyEvaluator{
			include: &Criteria{defaultItems: []string{"*"}},
			exclude: &Criteria{},
		}

		result := Outcome{Namespace: "test.ns"}

		successes := b.computeSuccesses(result, rules, "", "", map[string]bool{}, nil, time.Now())
		assert.Len(t, successes, 2)
	})

	t.Run("includes metadata fields", func(t *testing.T) {
		extendedRules := policyRules{
			"test.ns.full": rule.Info{
				Code:        "test.ns.full",
				Package:     "test.ns",
				ShortName:   "full",
				Title:       "Full Rule",
				Description: "A complete rule",
				Collections: []string{"col1"},
				DependsOn:   []string{"dep1"},
				EffectiveOn: "2024-01-01T00:00:00Z",
			},
		}

		b := &basePolicyEvaluator{
			include: &Criteria{defaultItems: []string{"*"}},
			exclude: &Criteria{},
		}
		result := Outcome{Namespace: "test.ns"}

		successes := b.computeSuccesses(result, extendedRules, "", "", map[string]bool{}, nil, time.Now())
		require.Len(t, successes, 1)
		assert.Equal(t, "Full Rule", successes[0].Metadata[metadataTitle])
		assert.Equal(t, "A complete rule", successes[0].Metadata[metadataDescription])
		assert.Equal(t, []string{"col1"}, successes[0].Metadata[metadataCollections])
		assert.Equal(t, []string{"dep1"}, successes[0].Metadata[metadataDependsOn])
		assert.Equal(t, "2024-01-01T00:00:00Z", successes[0].Metadata[metadataEffectiveOn])
	})
}

func TestBasePolicyEvaluatorIsResultIncluded(t *testing.T) {
	t.Run("included by default with wildcard", func(t *testing.T) {
		b := &basePolicyEvaluator{
			include: &Criteria{defaultItems: []string{"*"}},
			exclude: &Criteria{},
		}

		result := Result{
			Metadata: map[string]any{metadataCode: "test.rule"},
		}

		assert.True(t, b.isResultIncluded(result, "image:latest", "", map[string]bool{}))
	})

	t.Run("excluded rule", func(t *testing.T) {
		b := &basePolicyEvaluator{
			include: &Criteria{},
			exclude: &Criteria{
				defaultItems: []string{"test.rule"},
			},
		}

		result := Result{
			Metadata: map[string]any{metadataCode: "test.rule"},
		}

		assert.False(t, b.isResultIncluded(result, "image:latest", "", map[string]bool{}))
	})
}

func TestBasePolicyEvaluatorPostProcessResults(t *testing.T) {
	rules := policyRules{
		"test.ns.rule1": rule.Info{
			Code:      "test.ns.rule1",
			Package:   "test.ns",
			ShortName: "rule1",
			Title:     "Rule 1",
		},
	}

	config := &simpleConfigProvider{effectiveTime: time.Now()}

	src := ecc.Source{}
	b := &basePolicyEvaluator{
		policy:   config,
		rules:    rules,
		allRules: rules,
		include:  &Criteria{defaultItems: []string{"*"}},
		exclude:  &Criteria{},
	}
	b.policyResolver = NewIncludeExcludePolicyResolver(src, config)

	t.Run("processes results with successes", func(t *testing.T) {
		ctx := context.Background()
		runResults := []Outcome{
			{
				Namespace: "test.ns",
				Failures: []Result{
					{
						Message:  "test failure",
						Metadata: map[string]any{metadataCode: "test.ns.rule1"},
					},
				},
			},
		}
		target := EvaluationTarget{Target: "image:latest"}

		results, err := b.postProcessResults(ctx, runResults, target)
		require.NoError(t, err)
		assert.NotEmpty(t, results)
	})

	t.Run("returns error on no results", func(t *testing.T) {
		ctx := context.Background()
		emptyRules := policyRules{}
		bEmpty := &basePolicyEvaluator{
			policy:   config,
			rules:    emptyRules,
			allRules: emptyRules,
			include:  &Criteria{defaultItems: []string{"*"}},
			exclude:  &Criteria{},
		}
		bEmpty.policyResolver = NewIncludeExcludePolicyResolver(src, config)

		runResults := []Outcome{
			{Namespace: "empty.ns"},
		}
		target := EvaluationTarget{Target: "image:latest"}

		_, err := bEmpty.postProcessResults(ctx, runResults, target)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no successes, warnings, or failures")
	})
}

func TestBasePolicyEvaluatorResolveFilteredNamespaces(t *testing.T) {
	t.Run("nil resolver returns nil", func(t *testing.T) {
		b := &basePolicyEvaluator{}
		ns := b.resolveFilteredNamespaces(EvaluationTarget{})
		assert.Nil(t, ns)
	})

	t.Run("with resolver returns packages", func(t *testing.T) {
		b := &basePolicyEvaluator{
			allRules: policyRules{
				"test.ns.rule1": rule.Info{
					Code:    "test.ns.rule1",
					Package: "test.ns",
				},
			},
		}
		b.policyResolver = NewIncludeExcludePolicyResolver(ecc.Source{}, &simpleConfigProvider{})

		ns := b.resolveFilteredNamespaces(EvaluationTarget{Target: "image:latest"})
		assert.NotNil(t, ns)
	})
}

func TestBasePolicyEvaluatorInitPolicyResolver(t *testing.T) {
	config := &simpleConfigProvider{}
	src := ecc.Source{}

	b := &basePolicyEvaluator{}
	b.initPolicyResolver(src, config)

	assert.NotNil(t, b.policyResolver)
	assert.NotNil(t, b.include)
	assert.NotNil(t, b.exclude)
}
