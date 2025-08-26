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

package applicationsnapshot

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gkampitakis/go-snaps/snaps"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/format"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
)

//go:embed test_snapshot.json
var testSnapshot string

func Test_ReportJson(t *testing.T) {
	var snapshot app.SnapshotSpec
	err := json.Unmarshal([]byte(testSnapshot), &snapshot)
	assert.NoError(t, err)

	components := testComponentsFor(snapshot)

	ctx := context.Background()
	testPolicy := createTestPolicy(t, ctx)
	report, err := NewReport("snappy", components, testPolicy, nil, true)
	assert.NoError(t, err)

	testEffectiveTime := testPolicy.EffectiveTime().UTC().Format(time.RFC3339Nano)

	expected := fmt.Sprintf(`
    {
      "success": false,
	  "ec-version": "development",
	  "effective-time": %q,
	  "key": %s,
	  "snapshot": "snappy",
      "components": [
        {
          "name": "spam",
          "containerImage": "quay.io/caf/spam@sha256:123…",
		  "source": {},
          "violations": [{"msg": "violation1"}],
          "warnings": [{"msg": "warning1"}],
		  "successes": [{"msg": "success1"}],
          "success": false
        },
        {
          "name": "bacon",
          "containerImage": "quay.io/caf/bacon@sha256:234…",
		  "source": {},
          "violations": [{"msg": "violation2"}],
          "success": false
        },
        {
			"name": "eggs",
			"containerImage": "quay.io/caf/eggs@sha256:345…",
			"source": {},
			"successes": [{"msg": "success3"}],
			"success": true
        }
      ],
	  "policy": {
		"publicKey": %s
	  }
    }
  	`, testEffectiveTime, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON)

	reportJson, err := report.toFormat(JSON)
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(reportJson))
	assert.False(t, report.Success)
}

func Test_ReportYaml(t *testing.T) {
	var snapshot *app.SnapshotSpec
	err := json.Unmarshal([]byte(testSnapshot), &snapshot)
	assert.NoError(t, err)

	components := testComponentsFor(*snapshot)

	ctx := context.Background()
	testPolicy := createTestPolicy(t, ctx)
	report, err := NewReport("snappy", components, testPolicy, nil, true)
	assert.NoError(t, err)

	testEffectiveTime := testPolicy.EffectiveTime().UTC().Format(time.RFC3339Nano)

	expected := fmt.Sprintf(`
success: false
effective-time: %q
key: %s
ec-version: development
snapshot: snappy
components:
  - name: spam
    containerImage: quay.io/caf/spam@sha256:123…
    source: {}
    violations:
      - msg: violation1
    warnings:
      - msg: warning1
    successes:
      - msg: success1
    success: false
  - name: bacon
    containerImage: quay.io/caf/bacon@sha256:234…
    source: {}
    violations:
      - msg: violation2
    success: false
  - name: eggs
    containerImage: quay.io/caf/eggs@sha256:345…
    source: {}
    successes:
      - msg: success3
    success: true
policy:
  publicKey: %s
`, testEffectiveTime, utils.TestPublicKeyJSON, utils.TestPublicKeyJSON)

	reportYaml, err := report.toFormat(YAML)
	assert.NoError(t, err)
	assert.YAMLEq(t, expected, string(reportYaml))
	assert.False(t, report.Success)
}

func Test_GenerateMarkdownSummary(t *testing.T) {
	cases := []struct {
		name       string
		snapshot   string
		components []Component
	}{
		{
			name: "One Warning and One Success",
			components: []Component{
				{
					Successes: []evaluator.Result{
						{Message: "Success1"},
					},
					SuccessCount: 1,
					Warnings: []evaluator.Result{
						{Message: "Warning1"},
					},
					Success: true,
				},
			},
		},
		{
			name: "One failure and One Success",
			components: []Component{
				{
					Successes: []evaluator.Result{
						{Message: "Success1"},
					},
					SuccessCount: 1,
					Violations: []evaluator.Result{
						{Message: "faulure1"},
					},
					Success: true,
				},
			},
		},
		{
			name: "One Failure and One Violation",
			components: []Component{
				{
					Violations: []evaluator.Result{
						{Message: "failure1"},
					},
					Warnings: []evaluator.Result{
						{Message: "Warning1"},
					},
					Success: false,
				},
			},
		},
		{
			name: "Multiple Failure and One Violation",
			components: []Component{
				{
					Violations: []evaluator.Result{
						{Message: "failure1"},
						{Message: "failure2"},
						{Message: "failure3"},
					},
					Warnings: []evaluator.Result{
						{Message: "Warning1"},
						{Message: "Warning2"},
					},
					Success: false,
				},
			},
		},
		{
			name: "With success",
			components: []Component{
				{
					Successes: []evaluator.Result{
						{Message: "Success1"},
						{Message: "Success2"},
						{Message: "Success3"},
					},
					SuccessCount: 3,
					Success:      true,
				},
			},
		},
		{
			name:     "With Snapshot",
			snapshot: "snappy",
			components: []Component{
				{
					Violations: []evaluator.Result{
						{Message: "failure1"},
						{Message: "failure2"},
					},
					Warnings: []evaluator.Result{
						{Message: "Warning1"},
						{Message: "Warning2"},
					},
					Success: false,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			report, err := NewReport(c.snapshot, c.components, createTestPolicy(t, ctx), nil, true)
			assert.NoError(t, err)
			report.created = time.Unix(0, 0).UTC()

			markdownSummary, err := generateMarkdownSummary(&report)
			assert.NoError(t, err)
			snaps.MatchSnapshot(t, string(markdownSummary))
		})
	}
}

func Test_ReportSummary(t *testing.T) {
	tests := []struct {
		name     string
		snapshot string
		input    Component
		want     summary
	}{
		{
			name: "testing one violation and warning",
			input: Component{
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
			},
			want: summary{
				Components: []componentSummary{
					{
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
						Name:            "",
					},
				},
				Success: false,
				Key:     utils.TestPublicKey,
			},
		},
		{
			name: "testing no metadata",
			input: Component{
				Violations: []evaluator.Result{
					{
						Message: "short report",
					},
				},
				Warnings: []evaluator.Result{
					{
						Message: "short report",
					},
				},
				Success: false,
			},
			want: summary{
				Components: []componentSummary{
					{
						Violations:      map[string][]string{},
						Warnings:        map[string][]string{},
						Successes:       map[string][]string{},
						TotalViolations: 1,
						TotalWarnings:   1,
						Success:         false,
						TotalSuccesses:  0,
						Name:            "",
					},
				},
				Success: false,
				Key:     utils.TestPublicKey,
			},
		},
		{
			name: "testing multiple violations and warnings",
			input: Component{
				Violations: []evaluator.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
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
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Success: false,
			},
			want: summary{
				Components: []componentSummary{
					{
						Violations: map[string][]string{
							"short_name": {"short report", "There are 1 more \"short_name\" messages"},
						},
						Warnings: map[string][]string{
							"short_name": {"short report", "There are 1 more \"short_name\" messages"},
						},
						Successes:       map[string][]string{},
						TotalViolations: 2,
						TotalWarnings:   2,
						Success:         false,
						TotalSuccesses:  0,
						Name:            "",
					},
				},
				Success: false,
				Key:     utils.TestPublicKey,
			},
		},
		{
			name: "with successes",
			input: Component{
				Violations: []evaluator.Result{
					{
						Message: "violation",
						Metadata: map[string]interface{}{
							"code": "violation",
						},
					},
				},
				Warnings: []evaluator.Result{
					{
						Message: "warning",
						Metadata: map[string]interface{}{
							"code": "warning",
						},
					},
				},
				Successes: []evaluator.Result{
					{
						Message: "success",
						Metadata: map[string]interface{}{
							"code": "success",
						},
					},
				},
				Success:      false,
				SuccessCount: 1,
			},
			want: summary{
				Components: []componentSummary{
					{
						Violations:      map[string][]string{"violation": {"violation"}},
						Warnings:        map[string][]string{"warning": {"warning"}},
						Successes:       map[string][]string{"success": {"success"}},
						TotalViolations: 1,
						TotalWarnings:   1,
						TotalSuccesses:  1,
						Success:         false,
						Name:            "",
					},
				},
				Success: false,
				Key:     utils.TestPublicKey,
			},
		},
		{
			name:     "with snapshot",
			snapshot: "snappy",
			input: Component{
				Violations: []evaluator.Result{
					{
						Message: "violation",
						Metadata: map[string]interface{}{
							"code": "violation",
						},
					},
				},
				Warnings: []evaluator.Result{
					{
						Message: "warning",
						Metadata: map[string]interface{}{
							"code": "warning",
						},
					},
				},
				Successes: []evaluator.Result{
					{
						Message: "success",
						Metadata: map[string]interface{}{
							"code": "success",
						},
					},
				},
				Success:      false,
				SuccessCount: 1,
			},
			want: summary{
				Snapshot: "snappy",
				Components: []componentSummary{
					{
						Violations:      map[string][]string{"violation": {"violation"}},
						Warnings:        map[string][]string{"warning": {"warning"}},
						Successes:       map[string][]string{"success": {"success"}},
						TotalViolations: 1,
						TotalWarnings:   1,
						TotalSuccesses:  1,
						Success:         false,
						Name:            "",
					},
				},
				Success: false,
				Key:     utils.TestPublicKey,
			},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("NewReport=%s", tc.name), func(t *testing.T) {
			ctx := context.Background()
			report, err := NewReport(tc.snapshot, []Component{tc.input}, createTestPolicy(t, ctx), nil, true)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, report.toSummary())
		})
	}
}

func Test_ReportAppstudio(t *testing.T) {
	cases := []struct {
		name       string
		expected   string
		snapshot   string
		components []Component
		success    bool
	}{
		{
			name: "success",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "SUCCESS",
				"successes": 42,
				"timestamp": "0",
				"warnings": 0
			}`,
			components: []Component{
				{Success: true, SuccessCount: 39},
				{Success: true, SuccessCount: 2},
				{Success: true, SuccessCount: 1},
			},
			success: true,
		},
		{
			name: "warning",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "WARNING",
				"successes": 2,
				"timestamp": "0",
				"warnings": 1
			}`,
			components: []Component{
				{Success: true, SuccessCount: 1},
				{Success: true, SuccessCount: 1, Warnings: []evaluator.Result{{Message: "this is a warning"}}},
			},
			success: true,
		},
		{
			name: "failure",
			expected: `
			{
				"failures": 1,
				"namespace": "",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "0",
				"warnings": 0
			}`,
			components: []Component{
				{Success: true, SuccessCount: 1},
				{Success: false, Violations: []evaluator.Result{{Message: "this is a violation"}}},
			},
			success: false,
		},
		{
			name: "failure without violations",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "0",
				"warnings": 0
			}`,
			components: []Component{{Success: false}, {Success: true, SuccessCount: 1}},
			success:    false,
		},
		{
			name: "failure over warning",
			expected: `
			{
				"failures": 1,
				"namespace": "",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "0",
				"warnings": 1
			}`,
			components: []Component{
				{Success: true, SuccessCount: 1},
				{Success: false, Violations: []evaluator.Result{{Message: "this is a violation"}}},
				{Success: false, Warnings: []evaluator.Result{{Message: "this is a warning"}}},
			},
			success: false,
		},
		{
			name: "skipped",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "SKIPPED",
				"successes": 0,
				"timestamp": "0",
				"warnings": 0
			}`,
			components: []Component{},
			success:    true,
		},
		{
			name: "with snapshot",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "SUCCESS",
				"successes": 3,
				"timestamp": "0",
				"warnings": 0
			}`,
			snapshot:   "snappy",
			components: []Component{{Success: true, SuccessCount: 3}, {Success: true}, {Success: true}},
			success:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			defaultWriter, err := fs.Create("default")
			assert.NoError(t, err)

			ctx := context.Background()
			report, err := NewReport(c.snapshot, c.components, createTestPolicy(t, ctx), nil, true)
			assert.NoError(t, err)
			assert.False(t, report.created.IsZero())
			assert.Equal(t, c.success, report.Success)

			report.created = time.Unix(0, 0).UTC()

			p := format.NewTargetParser(JSON, format.Options{}, defaultWriter, fs)
			assert.NoError(t, report.WriteAll([]string{"appstudio=report.json", "appstudio"}, p))

			reportText, err := afero.ReadFile(fs, "report.json")
			assert.NoError(t, err)
			assert.JSONEq(t, c.expected, string(reportText))

			defaultReportText, err := afero.ReadFile(fs, "default")
			assert.NoError(t, err)
			assert.JSONEq(t, c.expected, string(defaultReportText))
		})
	}
}

// Deprecated. Remove when hacbs output is removed
func Test_ReportHACBS(t *testing.T) {
	cases := []struct {
		name       string
		expected   string
		snapshot   string
		components []Component
		success    bool
	}{
		{
			name: "success",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "SUCCESS",
				"successes": 42,
				"timestamp": "0",
				"warnings": 0
			}`,
			components: []Component{{Success: true, SuccessCount: 42}, {Success: true}, {Success: true}},
			success:    true,
		},
		{
			name: "warning",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "WARNING",
				"successes": 2,
				"timestamp": "0",
				"warnings": 1
			}`,
			components: []Component{
				{Success: true, SuccessCount: 1},
				{Success: true, SuccessCount: 1, Warnings: []evaluator.Result{{Message: "this is a warning"}}},
			},
			success: true,
		},
		{
			name: "failure",
			expected: `
			{
				"failures": 1,
				"namespace": "",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "0",
				"warnings": 0
			}`,
			components: []Component{
				{Success: true, SuccessCount: 1},
				{Success: false, Violations: []evaluator.Result{{Message: "this is a violation"}}},
			},
			success: false,
		},
		{
			name: "failure without violations",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "0",
				"warnings": 0
			}`,
			components: []Component{{Success: false}, {Success: true, SuccessCount: 1}},
			success:    false,
		},
		{
			name: "failure over warning",
			expected: `
			{
				"failures": 1,
				"namespace": "",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "0",
				"warnings": 1
			}`,
			components: []Component{
				{Success: true, SuccessCount: 1},
				{Success: false, Violations: []evaluator.Result{{Message: "this is a violation"}}},
				{Success: false, Warnings: []evaluator.Result{{Message: "this is a warning"}}},
			},
			success: false,
		},
		{
			name: "skipped",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "SKIPPED",
				"successes": 0,
				"timestamp": "0",
				"warnings": 0
			}`,
			components: []Component{},
			success:    true,
		},
		{
			name: "with snapshot",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "SUCCESS",
				"successes": 3,
				"timestamp": "0",
				"warnings": 0
			}`,
			snapshot:   "snappy",
			components: []Component{{Success: true, SuccessCount: 1}, {Success: true, SuccessCount: 1}, {Success: true, SuccessCount: 1}},
			success:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			defaultWriter, err := fs.Create("default")
			assert.NoError(t, err)

			ctx := context.Background()
			report, err := NewReport(c.snapshot, c.components, createTestPolicy(t, ctx), nil, true)
			assert.NoError(t, err)
			assert.False(t, report.created.IsZero())
			assert.Equal(t, c.success, report.Success)

			report.created = time.Unix(0, 0).UTC()

			p := format.NewTargetParser(JSON, format.Options{}, defaultWriter, fs)
			assert.NoError(t, report.WriteAll([]string{"hacbs=report.json", "hacbs"}, p))

			reportText, err := afero.ReadFile(fs, "report.json")
			assert.NoError(t, err)
			assert.JSONEq(t, c.expected, string(reportText))

			defaultReportText, err := afero.ReadFile(fs, "default")
			assert.NoError(t, err)
			assert.JSONEq(t, c.expected, string(defaultReportText))
		})
	}
}

func Test_ReportPolicyInput(t *testing.T) {
	fs := afero.NewMemMapFs()
	defaultWriter, err := fs.Create("default")
	require.NoError(t, err)

	policyInput := [][]byte{
		[]byte(`{"ref": "one"}`),
		[]byte(`{"ref": "two"}`),
	}

	ctx := context.Background()
	report, err := NewReport("snapshot", nil, createTestPolicy(t, ctx), policyInput, true)
	require.NoError(t, err)

	p := format.NewTargetParser(JSON, format.Options{}, defaultWriter, fs)
	require.NoError(t, report.WriteAll([]string{"policy-input=policy-input.yaml", "policy-input"}, p))

	matchesJSONLFile(t, fs, policyInput, "policy-input.yaml")
	matchesJSONLFile(t, fs, policyInput, "default")
}

func Test_TextReport(t *testing.T) {
	warnings := []evaluator.Result{
		{
			Metadata: map[string]interface{}{
				"code":        "warning-1",
				"title":       "Warning 1 title",
				"description": "Warning 1 description",
				"solution":    "Warning 1 solution",
			},
			Message: "Warning 1 message",
		},
		{
			Metadata: map[string]interface{}{
				"code": "warning-2",
			},
			Message: "Warning 2 message",
		},
	}
	violations := []evaluator.Result{
		{
			Metadata: map[string]interface{}{
				"code":        "violation-1",
				"title":       "Violation 1 title",
				"description": "Violation 1 description",
				"solution":    "Violation 1 solution",
			},
			Message: "Violation 1 message",
		},
		{
			Metadata: map[string]interface{}{
				"code": "violation-2",
			},
			Message: "Violation 2 message",
		},
	}
	successes := []evaluator.Result{
		{
			Metadata: map[string]interface{}{
				"code":        "success-1",
				"title":       "Success 1 title",
				"description": "Success 1 description",
				"solution":    "Success 1 solution",
			},
			Message: "Success 1 message",
		},
		{
			Metadata: map[string]interface{}{
				"code": "success-2",
			},
			Message: "Success 2 message",
		},
	}

	cases := []struct {
		name   string
		report Report
	}{
		{"nothing", Report{}},
		{"bunch", Report{
			ShowSuccesses: true,
			Components: []Component{
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/component-1:tag",
					},
					Violations: violations,
				},
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/component-2:tag",
					},
					Warnings: warnings,
				},
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/component-3:tag",
					},
					Successes:    successes,
					SuccessCount: 2,
				},
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/component-4:tag",
					},
					Warnings:     warnings,
					Violations:   violations,
					Successes:    successes,
					SuccessCount: 2,
				},
			},
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.report
			output, err := generateTextReport(&r)
			require.NoError(t, err)

			snaps.MatchSnapshot(t, string(output))
		})
	}
}

func matchesJSONLFile(t *testing.T, fs afero.Fs, expected [][]byte, filename string) {
	f, err := fs.Open(filename)
	require.NoError(t, err)
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for i := 0; scanner.Scan(); i++ {
		require.JSONEq(t, string(expected[i]), scanner.Text())
	}
}

func testComponentsFor(snapshot app.SnapshotSpec) []Component {
	components := []Component{
		{
			SnapshotComponent: snapshot.Components[0],
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
			SnapshotComponent: snapshot.Components[1],
			Violations: []evaluator.Result{
				{
					Message: "violation2",
				},
			},
			Success: false,
		},
		{
			SnapshotComponent: snapshot.Components[2],
			Successes: []evaluator.Result{
				{
					Message: "success3",
				},
			},
			Success: true,
		},
	}
	return components
}

func createTestPolicy(t *testing.T, ctx context.Context) policy.Policy {
	utils.SetTestRekorPublicKey(t)

	p, err := policy.NewPolicy(ctx, policy.Options{
		PublicKey:     utils.TestPublicKey,
		EffectiveTime: policy.Now,
	})
	assert.NoError(t, err)
	return p
}

func Test_DocumentationLink_OnlySuccesses(t *testing.T) {
	// Test case: Only successes - should NOT show documentation link
	r := Report{
		ShowSuccesses: true,
		Components: []Component{
			{
				Successes: []evaluator.Result{
					{
						Metadata: map[string]interface{}{
							"code": "success.policy",
						},
						Message: "Policy passed successfully",
					},
				},
				SuccessCount: 1,
			},
		},
	}

	output, err := generateTextReport(&r)
	require.NoError(t, err)

	outputStr := string(output)
	hasDocLink := strings.Contains(outputStr, "https://conforma.dev/docs/policy/")

	assert.False(t, hasDocLink, "Documentation link should NOT appear when there are only successes")
}

func Test_DocumentationLink_OnlyWarnings(t *testing.T) {
	// Test case: Only warnings - should show documentation link
	r := Report{
		Components: []Component{
			{
				Warnings: []evaluator.Result{
					{
						Metadata: map[string]interface{}{
							"code": "warning.policy",
						},
						Message: "Policy warning message",
					},
				},
			},
		},
	}

	output, err := generateTextReport(&r)
	require.NoError(t, err)

	outputStr := string(output)
	hasDocLink := strings.Contains(outputStr, "https://conforma.dev/docs/policy/")

	assert.True(t, hasDocLink, "Documentation link should appear when there are warnings")
	assert.Contains(t, outputStr, "For more information about policy issues", "Should contain the documentation link message")
}

func Test_DocumentationLink_OnlyFailures(t *testing.T) {
	// Test case: Only failures - should show documentation link
	r := Report{
		Components: []Component{
			{
				Violations: []evaluator.Result{
					{
						Metadata: map[string]interface{}{
							"code": "failure.policy",
						},
						Message: "Policy violation message",
					},
				},
			},
		},
	}

	output, err := generateTextReport(&r)
	require.NoError(t, err)

	outputStr := string(output)
	hasDocLink := strings.Contains(outputStr, "https://conforma.dev/docs/policy/")

	assert.True(t, hasDocLink, "Documentation link should appear when there are failures")
	assert.Contains(t, outputStr, "For more information about policy issues", "Should contain the documentation link message")
}

func Test_DocumentationLink_WarningsAndFailures(t *testing.T) {
	// Test case: Both warnings and failures - should show documentation link
	r := Report{
		Components: []Component{
			{
				Violations: []evaluator.Result{
					{
						Metadata: map[string]interface{}{
							"code": "failure.policy",
						},
						Message: "Policy violation message",
					},
				},
				Warnings: []evaluator.Result{
					{
						Metadata: map[string]interface{}{
							"code": "warning.policy",
						},
						Message: "Policy warning message",
					},
				},
			},
		},
	}

	output, err := generateTextReport(&r)
	require.NoError(t, err)

	outputStr := string(output)
	hasDocLink := strings.Contains(outputStr, "https://conforma.dev/docs/policy/")

	assert.True(t, hasDocLink, "Documentation link should appear when there are both warnings and failures")
	assert.Contains(t, outputStr, "For more information about policy issues", "Should contain the documentation link message")
}

func Test_DocumentationLink_MultipleComponents(t *testing.T) {
	// Test case: Multiple components with mixed results - should show documentation link
	r := Report{
		ShowSuccesses: true,
		Components: []Component{
			{
				// Component 1: Only successes
				Successes: []evaluator.Result{
					{
						Metadata: map[string]interface{}{"code": "success1.policy"},
						Message:  "Success in component 1",
					},
				},
				SuccessCount: 1,
			},
			{
				// Component 2: Has warnings (should trigger the link)
				Warnings: []evaluator.Result{
					{
						Metadata: map[string]interface{}{"code": "warning1.policy"},
						Message:  "Warning in component 2",
					},
				},
				Successes: []evaluator.Result{
					{
						Metadata: map[string]interface{}{"code": "success2.policy"},
						Message:  "Success in component 2",
					},
				},
				SuccessCount: 1,
			},
		},
	}

	output, err := generateTextReport(&r)
	require.NoError(t, err)

	outputStr := string(output)
	hasDocLink := strings.Contains(outputStr, "https://conforma.dev/docs/policy/")

	assert.True(t, hasDocLink, "Documentation link should appear when any component has warnings or failures")
}

func Test_DocumentationLink_EmptyReport(t *testing.T) {
	// Test case: Empty report - should NOT show documentation link
	r := Report{
		Components: []Component{},
	}

	output, err := generateTextReport(&r)
	require.NoError(t, err)

	outputStr := string(output)
	hasDocLink := strings.Contains(outputStr, "https://conforma.dev/docs/policy/")

	assert.False(t, hasDocLink, "Documentation link should NOT appear for empty reports")
}

func TestNewVSAReport(t *testing.T) {
	components := []VSAComponent{
		{
			Name:           "test-component",
			ContainerImage: "quay.io/test/image:latest",
			Success:        true,
		},
		{
			Name:           "failing-component",
			ContainerImage: "quay.io/test/failing:latest",
			Success:        false,
			Error:          "validation failed",
		},
	}

	report := NewVSAReport(components)

	assert.False(t, report.Success, "Report should be false when any component fails")
	assert.Equal(t, 2, len(report.Components), "Report should have 2 components")
	assert.Contains(t, report.Summary, "failed", "Summary should indicate failure")
}

func TestWriteVSAReport(t *testing.T) {
	components := []VSAComponent{
		{
			Name:           "test-component",
			ContainerImage: "quay.io/test/image:latest",
			Success:        true,
		},
	}

	report := NewVSAReport(components)

	// Test JSON output
	var buf bytes.Buffer
	p := format.NewTargetParser("json", format.Options{}, &buf, utils.FS(context.Background()))

	err := WriteVSAReport(report, []string{"json"}, p)
	assert.NoError(t, err)

	// Verify the output is valid JSON
	var result VSAReport
	err = json.Unmarshal(buf.Bytes(), &result)
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, 1, len(result.Components))
}
