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

	hd "github.com/MakeNowJust/heredoc"
	"github.com/open-policy-agent/opa/ast"
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
