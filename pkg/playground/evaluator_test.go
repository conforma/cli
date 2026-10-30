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

package playground

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	"github.com/stretchr/testify/require"
)

const testPolicy = `# file: main.rego
package main

import rego.v1

import data.lib.pipeline

# METADATA
# title: Required build task is present
# description: Confirm the expected build task is present in the pipeline.
# custom:
#   short_name: required_task_missing
#   solution: Add the build task to the pipeline definition.
deny contains result if {
	not pipeline.has_required_task(input, "build-container")
	result := {
		"code": "main.required_task_missing",
		"msg": "required task build-container is missing",
	}
}

# METADATA
# title: Application label is present
# description: Confirm the application label is available for grouping.
# custom:
#   short_name: application_label_missing
#   solution: Add the application label to the input metadata.
warn contains result if {
	not input.metadata.labels["appstudio.openshift.io/application"]
	result := {
		"code": "main.application_label_missing",
		"msg": "application label is recommended",
	}
}

# file: lib/pipeline.rego
package lib.pipeline

import rego.v1

has_required_task(snapshot, task_name) if {
	some task in snapshot.pipeline.tasks
	task.name == task_name
}
`

func TestEvaluateConformaMetadataFailure(t *testing.T) {
	response, err := Evaluate(context.Background(), Request{
		Policy: testPolicy,
		Input: `metadata:
  labels: {}
pipeline:
  tasks:
    - name: unit-test`,
	})

	require.NoError(t, err)
	require.False(t, response.Success)
	require.Equal(t, "main", response.Package)
	require.Equal(t, []string{"main.rego", "lib/pipeline.rego"}, response.Modules)
	require.Equal(t, 0, response.SuccessCount)
	require.Empty(t, response.Successes)

	require.Len(t, response.Violations, 1)
	require.Equal(t, "required task build-container is missing", response.Violations[0].Message)
	require.Equal(t, "main.required_task_missing", response.Violations[0].Metadata["code"])
	require.Equal(t, "Required build task is present", response.Violations[0].Metadata["title"])
	require.Equal(t, "Confirm the expected build task is present in the pipeline.", response.Violations[0].Metadata["description"])
	require.Equal(t, "Add the build task to the pipeline definition.", response.Violations[0].Metadata["solution"])

	require.Len(t, response.Warnings, 1)
	require.Equal(t, "application label is recommended", response.Warnings[0].Message)
	require.Equal(t, "main.application_label_missing", response.Warnings[0].Metadata["code"])
	require.Equal(t, "Application label is present", response.Warnings[0].Metadata["title"])
	require.Equal(t, "Add the application label to the input metadata.", response.Warnings[0].Metadata["solution"])
}

func TestEvaluateConformaMetadataSuccess(t *testing.T) {
	response, err := Evaluate(context.Background(), Request{
		Policy: testPolicy,
		Input: `metadata:
  labels:
    appstudio.openshift.io/application: demo
pipeline:
  tasks:
    - name: build-container`,
	})

	require.NoError(t, err)
	require.True(t, response.Success)
	require.Empty(t, response.Violations)
	require.Empty(t, response.Warnings)
	require.Len(t, response.Successes, 2)
	require.Equal(t, 2, response.SuccessCount)
	requireResult(t, response.Successes, "main.required_task_missing", "Pass")
	requireResult(t, response.Successes, "main.application_label_missing", "Pass")
}

func TestEvaluateWithInlineData(t *testing.T) {
	policy := `package main

import rego.v1

# METADATA
# title: Attestation signer is allowed
# custom:
#   short_name: signer_not_allowed
deny contains result if {
	not data.allowed_signers[input.signer]
	result := {
		"code": "main.signer_not_allowed",
		"msg": sprintf("attestation signer %q is not allowed", [input.signer]),
	}
}
`

	response, err := Evaluate(context.Background(), Request{
		Policy: policy,
		Input:  `signer: https://untrusted.example/signer`,
		Data: `allowed_signers:
  https://tekton.dev/chains/trusted: true`,
	})

	require.NoError(t, err)
	require.False(t, response.Success)
	require.Len(t, response.Violations, 1)
	require.Equal(t, "main.signer_not_allowed", response.Violations[0].Metadata["code"])
	require.Equal(t, "Attestation signer is allowed", response.Violations[0].Metadata["title"])
}

func TestEvaluateNonAnnotatedRule(t *testing.T) {
	response, err := Evaluate(context.Background(), Request{
		Policy: `package main

import rego.v1

deny contains "bad input" if input.bad
`,
		Input: `bad: true`,
	})

	require.NoError(t, err)
	require.False(t, response.Success)
	require.Len(t, response.Violations, 1)
	require.Equal(t, "bad input", response.Violations[0].Message)
}

func TestEvaluateReturnsParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		request Request
		want    string
	}{
		{
			name: "input",
			request: Request{
				Policy: `package main

import rego.v1

deny contains "bad input" if input.bad
`,
				Input: `{"bad":`,
			},
			want: "parse input:",
		},
		{
			name: "data must be object",
			request: Request{
				Policy: `package main

import rego.v1

deny contains "bad input" if input.bad
`,
				Input: `{}`,
				Data:  `["not", "an", "object"]`,
			},
			want: "parse data: data must be a JSON or YAML object",
		},
		{
			name: "empty policy",
			request: Request{
				Input: `{}`,
			},
			want: "parse policy: no Rego modules provided",
		},
		{
			name: "compile policy",
			request: Request{
				Policy: `package main

import rego.v1

deny contains "bad input" if missing.reference == true
`,
				Input: `{}`,
			},
			want: "compile policy:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Evaluate(context.Background(), tt.request)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestAppendValueHandlesScalarAndNestedResults(t *testing.T) {
	results := appendValue(nil, []any{
		nil,
		true,
		false,
		"bad input",
		[]any{"nested"},
		42,
		map[string]any{
			"msg":  "object result",
			"code": "main.object",
		},
	})

	require.Len(t, results, 5)
	require.Empty(t, results[0].Message)
	require.Equal(t, "bad input", results[1].Message)
	require.Equal(t, "nested", results[2].Message)
	require.Equal(t, "unexpected policy result type int: 42", results[3].Message)
	require.Equal(t, "object result", results[4].Message)
	require.Equal(t, "main.object", results[4].Metadata["code"])
}

func TestMarshalResponse(t *testing.T) {
	out := MarshalResponse(Response{
		Success:      true,
		SuccessCount: 1,
		Successes: []Result{{
			Message: "Pass",
			Metadata: map[string]any{
				"code": "main.ok",
			},
		}},
	})

	var response Response
	require.NoError(t, json.Unmarshal([]byte(out), &response))
	require.True(t, response.Success)
	require.Equal(t, 1, response.SuccessCount)
	require.Equal(t, "main.ok", response.Successes[0].Metadata["code"])
}

func TestMarshalResponseFallback(t *testing.T) {
	out := MarshalResponse(Response{
		Violations: []Result{{
			Metadata: map[string]any{
				"unsupported": func() {},
			},
		}},
	})

	require.Contains(t, out, "json: unsupported type: func()")
}

func TestOpaPrintHookIncludesLocation(t *testing.T) {
	outputs := []string{}
	hook := opaPrintHook{s: &outputs}

	err := hook.Print(print.Context{
		Location: &ast.Location{
			File: "playground.rego",
			Row:  12,
			Col:  3,
		},
	}, "hello")

	require.NoError(t, err)
	require.Len(t, outputs, 1)
	require.True(t, strings.HasSuffix(outputs[0], "hello"))
	require.Contains(t, outputs[0], "playground.rego")
}

func requireResult(t *testing.T, results []Result, code string, msg string) {
	t.Helper()
	for _, result := range results {
		if result.Metadata["code"] == code {
			require.Equal(t, msg, result.Message)
			return
		}
	}
	t.Fatalf("result with code %q not found in %#v", code, results)
}
