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

package opa

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"testing"

	hd "github.com/MakeNowJust/heredoc/v2"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_InspectMultiple(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		modules  []string
		expected string
		err      error
	}{
		{
			name:  "Smoke test",
			paths: []string{"foo/bar/bacon.rego"},
			modules: []string{hd.Doc(`
				package bacon
				import rego.v1

				# METADATA
				# title: Enough spam
				deny if {
					input.spam_count > 42
				}
			`)},
			expected: hd.Doc(`
				[
					{
						"location":{
							"file":"foo/bar/bacon.rego",
							"row":6,
							"col":1
						},
						"path":[
							{"type":"var","value":"data"},
							{"type":"string","value":"bacon"},
							{"type":"string","value":"deny"}
						],
						"annotations":{
							"scope":"rule",
							"title":"Enough spam"
						}
					}
				]
			`),
			err: nil,
		},
	}
	for _, tt := range tests {
		results, err := inspectMultiple(tt.paths, tt.modules)
		assert.Equal(t, tt.err, err, tt.name)

		jsonResults, err := json.Marshal(results)
		if err != nil {
			panic(err)
		}
		assert.JSONEq(t, tt.expected, string(jsonResults), tt.expected, tt.name)
	}
}

func TestInspectDir(t *testing.T) {
	files := map[string]string{
		"spam.rego": hd.Doc(`
			package spam
			import rego.v1

			# METADATA
			# title: Enough spam
			deny contains msg if {
				input.spam_count > 42
				msg := "plenty spam"
			}
		`),
		"spam_test.rego":   "ignored",
		"spammy_TEST.rego": "ignored",
		"spam.text":        "ignored",
		"more/bacon.REGO": hd.Doc(`
			package more.bacon
			import rego.v1

			# METADATA
			# title: Enough bacon
			deny contains msg if {
				input.bacon_count > 42
				msg := "plenty bacon"
			}
		`),
	}

	cases := []struct {
		name    string
		symlink bool
	}{
		{name: "simple"},
		{name: "symlink", symlink: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Must use OsFs so we can test symlinks are working as expected
			fs := afero.NewOsFs()
			root := t.TempDir()

			policiesDir := filepath.Join(root, "policies")

			// Setup test data
			for path, value := range files {
				fullpath := filepath.Join(policiesDir, path)
				dir := filepath.Dir(fullpath)
				require.NoError(t, fs.MkdirAll(dir, 0755))
				require.NoError(t, afero.WriteFile(fs, fullpath, []byte(value), 0660))
			}

			if c.symlink {
				symlink := filepath.Join(root, "symlink")
				require.NoError(t, os.Symlink(policiesDir, symlink))
				policiesDir = symlink
			}

			annotations, err := InspectDir(fs, policiesDir)
			require.NoError(t, err)

			jsonAnnotations, err := json.MarshalIndent(annotations, "", "  ")
			require.NoError(t, err)
			snaps.MatchSnapshot(t, string(jsonAnnotations))
		})
	}
}

func TestCheckRules(t *testing.T) {
	cases := []struct {
		name string
		rego string
		err  string
	}{
		{
			name: "assignement",
			rego: `package test
			import rego.v1
			x := "value"`,
		},
		{
			name: "no message",
			rego: `package test
			import rego.v1
			deny if { true }`,
			err: `the rule "deny = true { true }" returns an unsupported value, at rules.rego:2`,
		},
		{
			// we can't check for this, we don't know the type of `x`
			name: "var assignement",
			rego: `package test
			import rego.v1
			deny contains x if { x := true }`,
		},
		{
			// we can't check for this, we don't know if `o` is an empty object
			name: "object assignement",
			rego: `package test
			import rego.v1
			deny contains o if { o := {} }`,
		},
		{
			name: "not string",
			rego: `package test
			import rego.v1
			deny if { 2 }`,
			err: `the rule "deny = true { 2 }" returns an unsupported value, at rules.rego:2`,
		},
		{
			name: "string",
			rego: `package test
			import rego.v1
			deny contains msg if { msg := "str" }`,
		},
		{
			name: "object",
			rego: `package test
			import rego.v1
			deny := {"key": "val"}`,
		},
		{
			name: "function",
			rego: `package test
			import rego.v1
			deny contains fn() if {
				true
			}
			fn := {"key": "val"}`,
		},
		{
			name: "assign",
			rego: `package test
			import rego.v1
			deny := "value" if {
				true
			}`,
		},
	}

	for _, c := range cases[len(cases)-1:] {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			require.NoError(t, os.WriteFile(path.Join(tmp, "rules.rego"), []byte(c.rego), 0600))

			_, err := InspectDir(afero.NewOsFs(), tmp)
			if c.err != "" {
				assert.EqualError(t, err, c.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHasAnnotations(t *testing.T) {
	cases := []struct {
		name           string
		rule           *ast.AnnotationsRef
		expectedResult bool
		description    string
	}{
		{
			name: "rule with annotations",
			rule: &ast.AnnotationsRef{
				Annotations: &ast.Annotations{
					Scope: "rule",
					Title: "Test Rule",
				},
			},
			expectedResult: true,
			description:    "Should return true when rule has annotations",
		},
		{
			name: "rule with empty annotations",
			rule: &ast.AnnotationsRef{
				Annotations: &ast.Annotations{},
			},
			expectedResult: true,
			description:    "Should return true when rule has empty annotations object",
		},
		{
			name:           "rule without annotations",
			rule:           &ast.AnnotationsRef{},
			expectedResult: false,
			description:    "Should return false when rule has no annotations",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := hasAnnotations(c.rule)
			assert.Equal(t, c.expectedResult, result, c.description)
		})
	}
}
