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

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvaluatePlaygroundViolation(t *testing.T) {
	policy := `package main

deny contains msg if {
	input.kind != "Deployment"
	msg := "kind must be Deployment"
}
`

	report := evaluatePlayground(context.Background(), policy, `{"kind":"Service"}`)

	require.True(t, report.Success == false)
	require.Empty(t, report.Errors)
	require.Len(t, report.Violations, 1)
	require.Equal(t, "kind must be Deployment", report.Violations[0].Message)
}

func TestEvaluatePlaygroundSuccess(t *testing.T) {
	policy := `package main

deny contains msg if {
	input.kind != "Deployment"
	msg := "kind must be Deployment"
}
`

	report := evaluatePlayground(context.Background(), policy, `kind: Deployment`)

	require.True(t, report.Success)
	require.Empty(t, report.Errors)
	require.Empty(t, report.Violations)
}

func TestEvaluatePlaygroundSyntaxError(t *testing.T) {
	report := evaluatePlayground(context.Background(), `package main

deny contains msg if {
	input.kind =
}
`, `{"kind":"Service"}`)

	require.False(t, report.Success)
	require.NotEmpty(t, report.Errors)
	require.Equal(t, "rego", report.Errors[0].Stage)
}

func TestEvaluatePlaygroundWithHelperModuleAndData(t *testing.T) {
	policy := `# file: main.rego
package main

import data.lib

deny contains msg if {
	not lib.allowed_kind(input.kind)
	msg := sprintf("kind must be one of %v", [data.allowed_kinds])
}

# file: lib/kinds.rego
package lib

allowed_kind(kind) if {
	data.allowed_kinds[_] == kind
}
`

	report := evaluatePlaygroundWithData(context.Background(), policy, `kind: Service`, `allowed_kinds: ["Deployment"]`)

	require.False(t, report.Success)
	require.Empty(t, report.Errors)
	require.Equal(t, []string{"main.rego", "lib/kinds.rego"}, report.Modules)
	require.Len(t, report.Violations, 1)
	require.Equal(t, "kind must be one of [\"Deployment\"]", report.Violations[0].Message)
}

func TestEvaluatePlaygroundWithHelperModuleAndDataSuccess(t *testing.T) {
	policy := `# file: main.rego
package main

import data.lib

deny contains msg if {
	not lib.allowed_kind(input.kind)
	msg := sprintf("kind must be one of %v", [data.allowed_kinds])
}

# file: lib/kinds.rego
package lib

allowed_kind(kind) if {
	data.allowed_kinds[_] == kind
}
`

	report := evaluatePlaygroundWithData(context.Background(), policy, `kind: Deployment`, `allowed_kinds: ["Deployment"]`)

	require.True(t, report.Success)
	require.Empty(t, report.Errors)
	require.Empty(t, report.Violations)
}
