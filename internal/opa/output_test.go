// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package opa

import (
	"bytes"
	"encoding/json"
	"testing"

	hd "github.com/MakeNowJust/heredoc/v2"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
)

func Test_RegoTextOutput(t *testing.T) {
	fooBarDeny := hd.Doc(`
		{
			"path":[
				{"type":"var","value":"data"},
				{"type":"string","value":"policy"},
				{"type":"string","value":"foo"},
				{"type":"string","value":"bar"},
				{"type":"string","value":"deny"}
			],
			"annotations":{
				"scope":"rule",
				"title":"Rule title",
				"description":"Rule description",
				"custom":{
					"short_name":"rule_title"
				}
			}
		}
	`)

	tests := []struct {
		name     string
		source   string
		annJson  string
		template string
		expected string
		err      error
	}{
		{
			name:     "Smoke test",
			source:   "spam.io/bacon-bundle",
			annJson:  fooBarDeny,
			template: "text",
			expected: hd.Doc(`
				# Source: spam.io/bacon-bundle

				policy.foo.bar.rule_title (deny)
				https://conforma.dev/docs/policy/packages/release_bar.html#bar__rule_title
				Rule title
				Rule description
				--
			`),
			err: nil,
		},
		{
			name:     "Smoke test",
			source:   "spam.io/bacon-bundle",
			annJson:  fooBarDeny,
			template: "names",
			expected: "policy.foo.bar.rule_title\n",
			err:      nil,
		},
		{
			name:     "Smoke test",
			source:   "spam.io/bacon-bundle",
			annJson:  fooBarDeny,
			template: "short-names",
			expected: "policy.foo.bar.rule_title\n",
			err:      nil,
		},
		{
			name:   "With collections",
			source: "spam.io/bacon-bundle",
			annJson: hd.Doc(`
				{
					"path":[
						{"type":"var","value":"data"},
						{"type":"string","value":"policy"},
						{"type":"string","value":"foo"},
						{"type":"string","value":"bar"},
						{"type":"string","value":"deny"}
					],
					"annotations":{
						"scope":"rule",
						"title":"Rule title",
						"description":"Rule description",
						"custom": {
							"collections": ["eggs"]
						}
					}
				}
			`),
			template: "text",
			expected: hd.Doc(`
				# Source: spam.io/bacon-bundle

				policy.foo.bar. (deny)
				Rule title
				Rule description
				[eggs]
				--
			`),
			err: nil,
		},
		{
			// Probably not likely to happen any time soon but let's
			// make sure it is handled okay and does't crash
			name:   "No short name",
			source: "spam.io/bacon-bundle",
			annJson: hd.Doc(`
				{
					"path":[
						{"type":"var","value":"data"},
						{"type":"string","value":"policy"},
						{"type":"string","value":"foo"},
						{"type":"string","value":"bar"},
						{"type":"string","value":"deny"}
					],
					"annotations":{
						"scope":"rule",
						"title":"Rule title",
						"description":"Rule description"
					}
				}
			`),
			template: "text",
			expected: hd.Doc(`
				# Source: spam.io/bacon-bundle

				policy.foo.bar. (deny)
				Rule title
				Rule description
				--
			`),
			err: nil,
		},
		{
			name:   "No annotations",
			source: "spam.io/bacon-bundle",
			annJson: hd.Doc(`
				{
					"path":[
						{"type":"var","value":"data"},
						{"type":"string","value":"policy"},
						{"type":"string","value":"foo"},
						{"type":"string","value":"bar"},
						{"type":"string","value":"deny"}
					]
				}
			`),
			template: "text",
			expected: hd.Doc(`
				# Source: spam.io/bacon-bundle

				policy.foo.bar.deny
				(No annotations found)
				--
			`),
			err: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a ast.AnnotationsRef
			err := json.Unmarshal([]byte(tt.annJson), &a)
			if err != nil {
				panic(err)
			}

			input := map[string][]*ast.AnnotationsRef{
				tt.source: {
					&a,
				},
			}

			buf := new(bytes.Buffer)
			err = OutputText(buf, input, tt.template)

			assert.Equal(t, tt.err, err, tt.name)
			assert.Equal(t, tt.expected, buf.String(), tt.name)
		})
	}
}

func TestTextOutputIsSorted(t *testing.T) {
	ann := ast.AnnotationsRef{}
	data := map[string][]*ast.AnnotationsRef{
		"A": {&ann},
		"C": {&ann},
		"B": {&ann},
	}

	buffy := bytes.Buffer{}
	err := OutputText(&buffy, data, "text")

	assert.NoError(t, err)
	assert.Equal(t, "# Source: A\n\n\n(No annotations found)\n--\n# Source: B\n\n\n(No annotations found)\n--\n# Source: C\n\n\n(No annotations found)\n--\n", buffy.String())
}

func TestOutputText(t *testing.T) {
	cases := []struct {
		name      string
		allData   map[string][]*ast.AnnotationsRef
		template  string
		expected  string
		expectErr bool
		errMsg    string
	}{
		{
			name: "successful output with multiple sources",
			allData: map[string][]*ast.AnnotationsRef{
				"source1": {
					{
						Path: ast.Ref{
							ast.VarTerm("data"),
							ast.StringTerm("policy"),
							ast.StringTerm("test"),
							ast.StringTerm("deny"),
						},
						Annotations: &ast.Annotations{
							Scope:       "rule",
							Title:       "Test Rule",
							Description: "Test Description",
						},
					},
				},
				"source2": {
					{
						Path: ast.Ref{
							ast.VarTerm("data"),
							ast.StringTerm("policy"),
							ast.StringTerm("warn"),
						},
						Annotations: &ast.Annotations{
							Scope: "rule",
							Title: "Warning Rule",
						},
					},
				},
			},
			template:  "text",
			expected:  "# Source: source1\n\npolicy.test. (deny)\nTest Rule\nTest Description\n--\n# Source: source2\n\npolicy. (warn)\nWarning Rule\n\n--\n",
			expectErr: false,
		},
		{
			name: "successful output with no annotations",
			allData: map[string][]*ast.AnnotationsRef{
				"source1": {
					{
						Path: ast.Ref{
							ast.VarTerm("data"),
							ast.StringTerm("policy"),
							ast.StringTerm("test"),
							ast.StringTerm("deny"),
						},
						// No annotations
					},
				},
			},
			template:  "text",
			expected:  "# Source: source1\n\npolicy.test.deny\n(No annotations found)\n--\n",
			expectErr: false,
		},
		{
			name: "failed output with invalid template",
			allData: map[string][]*ast.AnnotationsRef{
				"source1": {
					{
						Path: ast.Ref{
							ast.VarTerm("data"),
							ast.StringTerm("policy"),
							ast.StringTerm("test"),
							ast.StringTerm("deny"),
						},
						Annotations: &ast.Annotations{
							Scope: "rule",
							Title: "Test Rule",
						},
					},
				},
			},
			template:  "invalid-template",
			expected:  "",
			expectErr: true,
			errMsg:    "no template",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			err := OutputText(buf, c.allData, c.template)

			if c.expectErr {
				assert.Error(t, err, "Expected error for invalid input")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Expected no error for valid input")
				assert.Equal(t, c.expected, buf.String(), "Output should match expected")
			}
		})
	}
}

func TestRenderAnn(t *testing.T) {
	cases := []struct {
		name        string
		annotations *ast.AnnotationsRef
		tmplName    string
		expected    string
		expectErr   bool
		errMsg      string
	}{
		{
			name: "successful render with text template",
			annotations: &ast.AnnotationsRef{
				Path: ast.Ref{
					ast.VarTerm("data"),
					ast.StringTerm("policy"),
					ast.StringTerm("test"),
					ast.StringTerm("deny"),
				},
				Annotations: &ast.Annotations{
					Scope:       "rule",
					Title:       "Test Rule",
					Description: "Test Description",
					Custom: map[string]interface{}{
						"short_name": "test_rule",
					},
				},
			},
			tmplName:  "text",
			expected:  "policy.test.test_rule (deny)\nhttps://conforma.dev/docs/policy/packages/release_test.html#test__test_rule\nTest Rule\nTest Description\n--\n",
			expectErr: false,
		},
		{
			name: "successful render with names template",
			annotations: &ast.AnnotationsRef{
				Path: ast.Ref{
					ast.VarTerm("data"),
					ast.StringTerm("policy"),
					ast.StringTerm("test"),
					ast.StringTerm("warn"),
				},
				Annotations: &ast.Annotations{
					Scope: "rule",
					Title: "Warning Rule",
					Custom: map[string]interface{}{
						"short_name": "warning_rule",
					},
				},
			},
			tmplName:  "names",
			expected:  "policy.test.warning_rule\n",
			expectErr: false,
		},
		{
			name: "failed render with invalid template",
			annotations: &ast.AnnotationsRef{
				Path: ast.Ref{
					ast.VarTerm("data"),
					ast.StringTerm("policy"),
					ast.StringTerm("test"),
					ast.StringTerm("deny"),
				},
				Annotations: &ast.Annotations{
					Scope: "rule",
					Title: "Test Rule",
				},
			},
			tmplName:  "invalid-template",
			expected:  "",
			expectErr: true,
			errMsg:    "no template",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			err := renderAnn(buf, c.annotations, c.tmplName)

			if c.expectErr {
				assert.Error(t, err, "Expected error for invalid template")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Expected no error for valid template")
				assert.Equal(t, c.expected, buf.String(), "Output should match expected")
			}
		})
	}
}
