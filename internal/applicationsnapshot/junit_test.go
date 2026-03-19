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
	"testing"

	"github.com/jstemmer/go-junit-report/v2/junit"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/signature"
)

func TestMapResults(t *testing.T) {
	s := junit.Testsuite{}
	mapResults(&s, []evaluator.Result{{Message: "0"}, {Message: "1"}, {Message: "2"}}, func(r evaluator.Result) junit.Testcase {
		return junit.Testcase{
			Name: r.Message,
		}
	})

	assert.Equal(t, junit.Testsuite{
		Tests: 3,
		Testcases: []junit.Testcase{
			{Name: "0"},
			{Name: "1"},
			{Name: "2"},
		},
	}, s)
}

func TestAsTestCase(t *testing.T) {
	cases := []struct {
		name     string
		result   evaluator.Result
		expected junit.Testcase
	}{
		{
			name:     "nil",
			expected: junit.Testcase{},
		},
		{
			name:     "trivial",
			result:   evaluator.Result{Message: "msg"},
			expected: junit.Testcase{Name: "msg", Classname: "msg"},
		},
		{
			name:     "with code",
			result:   evaluator.Result{Message: "msg", Metadata: map[string]interface{}{"code": "a.b.c"}},
			expected: junit.Testcase{Name: "a.b.c: msg", Classname: "a.b.c: msg"},
		},
		{
			name:     "with metadata",
			result:   evaluator.Result{Message: "msg", Metadata: map[string]interface{}{"x": "1", "y": "2", "z": "3"}},
			expected: junit.Testcase{Name: "msg [x=1, y=2, z=3]", Classname: "msg [x=1, y=2, z=3]"},
		},
		{
			name:     "with code and metadata",
			result:   evaluator.Result{Message: "msg", Metadata: map[string]interface{}{"code": "a.b.c", "x": "1", "y": "2", "z": "3"}},
			expected: junit.Testcase{Name: "a.b.c: msg [x=1, y=2, z=3]", Classname: "a.b.c: msg [x=1, y=2, z=3]"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := asTestCase(c.result)

			assert.Equal(t, c.expected, got)
		})
	}
}

func TestToJunit(t *testing.T) {
	cases := []struct {
		name     string
		report   Report
		expected junit.Testsuites
	}{
		{
			name: "trivial",
		},
		{
			name: "one trivial component",
			report: Report{
				Components: []Component{
					{
						SnapshotComponent: app.SnapshotComponent{
							Name:           "Name",
							ContainerImage: "registry.io/repository/image:tag",
						},
						Signatures: []signature.EntitySignature{
							{
								KeyID:     "keyID1",
								Signature: "signature1",
							},
							{
								KeyID:     "keyID2",
								Signature: "signature2",
								Metadata: map[string]string{
									"C": "D",
									"A": "B",
									"B": "C",
								},
							},
						},
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
						Success: true,
					},
				},
				Key:     "key",
				Success: true,
			},
			expected: junit.Testsuites{
				Tests:    3,
				Failures: 1,
				Skipped:  1,
				Suites: []junit.Testsuite{
					{
						Name:      "Name (registry.io/repository/image:tag)",
						Timestamp: "0o001-01-01T00:00:00Z",
						Tests:     3,
						Failures:  1,
						Skipped:   1,
						Properties: &[]junit.Property{
							{
								Name:  "image",
								Value: "registry.io/repository/image:tag",
							},
							{
								Name:  "key",
								Value: "key",
							},
							{
								Name:  "success",
								Value: "true",
							},
							{
								Name:  "keyId",
								Value: "keyID1",
							},
							{
								Name:  "signature",
								Value: "signature1",
							},
							{
								Name:  "keyId",
								Value: "keyID2",
							},
							{
								Name:  "signature",
								Value: "signature2",
							},
							{
								Name:  "metadata.A",
								Value: "B",
							},
							{
								Name:  "metadata.B",
								Value: "C",
							},
							{
								Name:  "metadata.C",
								Value: "D",
							},
						},
						Testcases: []junit.Testcase{
							{
								Name:      "success: success",
								Classname: "success: success",
							},
							{
								Name:      "violation: violation",
								Classname: "violation: violation",
								Failure: &junit.Result{
									Message: "violation",
									Data:    "violation",
								},
							},
							{
								Name:      "warning: warning",
								Classname: "warning: warning",
								Skipped: &junit.Result{
									Message: "warning",
									Data:    "warning",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.report.toJUnit()

			assert.Equal(t, c.expected, got)
		})
	}
}
