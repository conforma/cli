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

package input

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
)

func Test_ReportJson(t *testing.T) {
	filePaths := []string{"/path/to/file1.yaml", "/path/to/file2.yaml", "/path/to/file3.yaml"}
	inputs := testInputsFor(filePaths)
	ctx := context.Background()
	testPolicy := createTestPolicy(t, ctx)
	report, err := NewReport(inputs, testPolicy, nil, false, true)
	assert.NoError(t, err)

	testEffectiveTime := testPolicy.EffectiveTime().UTC().Format(time.RFC3339Nano)

	expected := fmt.Sprintf(`
	{
		"success": false,
		"filepaths": [
		  {
			"filepath": "/path/to/file1.yaml",
			"violations": [
			  {
				"msg": "violation1"
			  }
			],
			"warnings": [
			  {
				"msg": "warning1"
			  }
			],
			"successes": [
			  {
				"msg": "success1"
			  }
			],
			"success": false,
			"success-count": 0
		  },
		  {
			"filepath": "/path/to/file2.yaml",
			"violations": [
			  {
				"msg": "violation2"
			  }
			],
			"warnings": null,
			"successes": null,
			"success": false,
			"success-count": 0
		  },
		  {
			"filepath": "/path/to/file3.yaml",
			"violations": null,
			"warnings": null,
			"successes": [
			  {
				"msg": "success3"
			  }
			],
			"success": true,
			"success-count": 0
		  }
		],
		"policy": {
		  "name": "Default",
		  "description": "Stuff and things",
		  "sources": [
			{
			  "name": "Default",
			  "policy": [
				"github.com/org/repo//policy"
			  ],
			  "data": [
				"github.com/org/repo//data"
			  ],
			  "config": {
				"include": [
				  "basic"
				]
			  }
			}
		  ]
		},
		"ec-version": "development",
		"effective-time": %q
	  }
	`, testEffectiveTime)

	reportJson, err := report.toFormat(JSON)
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(reportJson))
	assert.False(t, report.Success)
}

func Test_ReportYaml(t *testing.T) {
	filePaths := []string{"/path/to/file1.yaml", "/path/to/file2.yaml", "/path/to/file3.yaml"}
	inputs := testInputsFor(filePaths)
	ctx := context.Background()
	testPolicy := createTestPolicy(t, ctx)
	report, err := NewReport(inputs, testPolicy, nil, false, true)
	assert.NoError(t, err)

	testEffectiveTime := testPolicy.EffectiveTime().UTC().Format(time.RFC3339Nano)

	expected := fmt.Sprintf(`
ec-version: development
effective-time: "%s"
filepaths:
- filepath: /path/to/file1.yaml
  success: false
  success-count: 0
  successes:
  - msg: success1
  violations:
  - msg: violation1
  warnings:
  - msg: warning1
- filepath: /path/to/file2.yaml
  success: false
  success-count: 0
  successes: null
  violations:
  - msg: violation2
  warnings: null
- filepath: /path/to/file3.yaml
  success: true
  success-count: 0
  successes:
  - msg: success3
  violations: null
  warnings: null
policy:
  description: Stuff and things
  name: Default
  sources:
  - config:
      include:
      - basic
    data:
    - github.com/org/repo//data
    name: Default
    policy:
    - github.com/org/repo//policy
success: false
`, testEffectiveTime)

	reportYaml, err := report.toFormat(YAML)
	assert.NoError(t, err)
	assert.YAMLEq(t, expected, string(reportYaml))
	assert.False(t, report.Success)
}

func Test_ReportSummary(t *testing.T) {
	tests := []struct {
		name  string
		input []Input
		want  summary
	}{
		{
			name: "testing one violation and warning",
			input: []Input{{
				FilePath: "/path/to/file1.yaml",
				Violations: []evaluator.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Warnings: []evaluator.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Success: false,
			}},
			want: summary{
				FilePaths: []inputSummary{
					{
						FilePath: "/path/to/file1.yaml",
						Violations: map[string][]string{
							"short_name": {"short report"},
						},
						Warnings: map[string][]string{
							"short_name": {"short report"},
						},
						Successes:       map[string][]string{},
						TotalViolations: 1,
						TotalSuccesses:  0,
						TotalWarnings:   1,
						Success:         false,
					},
				},
				Success: false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("NewReport=%s", tc.name), func(t *testing.T) {
			ctx := context.Background()
			report, err := NewReport(tc.input, createTestPolicy(t, ctx), nil, false, true)
			// report, err := NewReport(tc.snapshot, []Component{tc.input}, createTestPolicy(t, ctx), nil, nil)
			assert.NoError(t, err)
			fmt.Println("\n\nExpected:\n", tc.want, "\n\nActual:\n", report.toSummary())
			assert.Equal(t, tc.want, report.toSummary())
		})
	}
}

func testInputsFor(filePaths []string) []Input {
	inputs := []Input{
		{
			FilePath: filePaths[0],
			Violations: []evaluator.Result{
				{
					Message: "violation1",
				},
			},
			Warnings: []evaluator.Result{
				{
					Message: "warning1",
				},
			},
			Successes: []evaluator.Result{
				{
					Message: "success1",
				},
			},
			Success: false,
		},
		{
			FilePath: filePaths[1],
			Violations: []evaluator.Result{
				{
					Message: "violation2",
				},
			},
			Success: false,
		},
		{
			FilePath: filePaths[2],
			Successes: []evaluator.Result{
				{
					Message: "success3",
				},
			},
			Success: true,
		},
	}
	return inputs
}

func Test_ReportText(t *testing.T) {
	inputs := []Input{
		{
			FilePath: "/path/to/file1.yaml",
			Violations: []evaluator.Result{
				{
					Message: "violation1",
					Metadata: map[string]interface{}{
						"code": "test.violation",
					},
				},
			},
			Warnings: []evaluator.Result{
				{
					Message: "warning1",
					Metadata: map[string]interface{}{
						"code": "test.warning",
					},
				},
			},
			Successes: []evaluator.Result{
				{
					Message: "success1",
					Metadata: map[string]interface{}{
						"code": "test.success",
					},
				},
			},
			SuccessCount: 1,
			Success:      false,
		},
	}
	ctx := context.Background()
	testPolicy := createTestPolicy(t, ctx)
	report, err := NewReport(inputs, testPolicy, nil, false, true)
	assert.NoError(t, err)

	reportText, err := report.toFormat(Text)
	assert.NoError(t, err)
	textOutput := string(reportText)

	// Verify basic structure
	assert.Contains(t, textOutput, "Success: false")
	assert.Contains(t, textOutput, "Result: FAILURE")
	assert.Contains(t, textOutput, "Violations: 1")
	assert.Contains(t, textOutput, "Warnings: 1")
	assert.Contains(t, textOutput, "Successes: 1")
	assert.Contains(t, textOutput, "Input File: /path/to/file1.yaml")
	assert.Contains(t, textOutput, "Results:")
	assert.Contains(t, textOutput, "[Violation] test.violation")
	assert.Contains(t, textOutput, "[Warning] test.warning")
	// Successes should not be shown when showSuccesses=false
	assert.NotContains(t, textOutput, "[Success] test.success")
}

func Test_ReportText_ShowSuccesses(t *testing.T) {
	inputs := []Input{
		{
			FilePath: "/path/to/file1.yaml",
			Successes: []evaluator.Result{
				{
					Message: "success1",
					Metadata: map[string]interface{}{
						"code": "test.success",
					},
				},
			},
			SuccessCount: 1,
			Success:      true,
		},
	}
	ctx := context.Background()
	testPolicy := createTestPolicy(t, ctx)
	report, err := NewReport(inputs, testPolicy, nil, true, true)
	assert.NoError(t, err)

	reportText, err := report.toFormat(Text)
	assert.NoError(t, err)
	textOutput := string(reportText)

	// Verify successes are shown when showSuccesses=true
	assert.Contains(t, textOutput, "Success: true")
	assert.Contains(t, textOutput, "Result: SUCCESS")
	assert.Contains(t, textOutput, "Successes: 1")
	assert.Contains(t, textOutput, "[Success] test.success")
}

func Test_ReportText_NoResultsSection(t *testing.T) {
	// When there are only successes and showSuccesses=false, Results section should not appear
	inputs := []Input{
		{
			FilePath:     "/path/to/file1.yaml",
			SuccessCount: 1,
			Success:      true,
		},
	}
	ctx := context.Background()
	testPolicy := createTestPolicy(t, ctx)
	report, err := NewReport(inputs, testPolicy, nil, false, true)
	assert.NoError(t, err)

	reportText, err := report.toFormat(Text)
	assert.NoError(t, err)
	textOutput := string(reportText)

	// Results section should not appear when there's nothing to show
	assert.Contains(t, textOutput, "Success: true")
	assert.Contains(t, textOutput, "Result: SUCCESS")
	assert.NotContains(t, textOutput, "Results:")
}

func createTestPolicy(t *testing.T, ctx context.Context) policy.Policy {
	utils.SetTestRekorPublicKey(t)

	policyConfiguration := `
name: Default
description: >-
  Stuff and things
sources:
  - name: Default
    policy:
      - github.com/org/repo//policy
    data:
      - github.com/org/repo//data
    config:
      include:
      - "basic"
      exclude:
        []
`
	p, err := policy.NewInputPolicy(ctx, policyConfiguration, "now")
	assert.NoError(t, err)
	return p
}
