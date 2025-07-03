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

package rule

import (
	"fmt"
	"testing"

	"github.com/MakeNowJust/heredoc"
	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/assert"
)

func annotationRef(rego string) *ast.AnnotationsRef {
	module := ast.MustParseModuleWithOpts(rego, ast.ParserOptions{
		ProcessAnnotation: true,
	})

	if len(module.Annotations) == 0 {
		return nil
	}

	// first rule
	return ast.NewAnnotationsRef(module.Annotations[0])
}

func TestTitle(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   "",
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				deny if { true }`)),
			expected: "",
		},
		{
			name: "with custom annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   hmm: 14
				deny if { true }`)),
			expected: "",
		},
		{
			name: "with title annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# title: title
				deny if { true }`)),
			expected: "title",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, title(c.annotation))
		})
	}
}

func TestDescription(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   "",
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				deny if { true }`)),
			expected: "",
		},
		{
			name: "with custom annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   hmm: 14
				deny if { true }`)),
			expected: "",
		},
		{
			name: "with title annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# description: description
				deny if { true }`)),
			expected: "description",
		},
		{
			name: "with xref links",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# description: >-
				#   See xref:release_policy.adoc#attestation_task_bundle_package[here] and
				#   xref:attachment$trusted_tekton_tasks.yml[over there] for details.
				deny if { true }`)),
			expected: "See here and over there for details.",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, description(c.annotation))
		})
	}
}

func TestKind(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   RuleKind
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   Other,
		},
		{
			name: "other rule",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# title: test
				helper if { true }`)),
			expected: Other,
		},
		{
			name: "deny rule",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# title: test
				deny if { true }`)),
			expected: Deny,
		},
		{
			name: "warn rule",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# title: test
				warn if { true }`)),
			expected: Warn,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, kind(c.annotation))
		})
	}
}

func TestShortName(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   "",
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				deny if { true }`)),
			expected: "",
		},
		{
			name: "without custom annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# title: title
				deny if { true }`)),
			expected: "",
		},
		{
			name: "with custom annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   hmm: 14
				deny if { true }`)),
			expected: "",
		},
		{
			name: "with short_name annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   short_name: here
				deny if { true }`)),
			expected: "here",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, shortName(c.annotation))
		})
	}
}

func TestEffectiveOn(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   string
	}{
		{
			name:       "empty",
			annotation: nil,
			expected:   "",
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				deny if { false }`)),
			expected: "",
		},
		{
			name: "without custom annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# title: title
				deny if { false }`)),
			expected: "",
		},
		{
			name: "with custom annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   hmm: 14
				deny if { false }`)),
			expected: "",
		},
		{
			name: "with effective_on annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   effective_on: 2022-01-01T00:00:00Z
				deny if { true }`)),
			expected: "2022-01-01T00:00:00Z",
		},
		{
			name: "with effective_on annotation as string",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   effective_on: '2022-01-01T00:00:00Z'
				deny if { true }`)),
			expected: "2022-01-01T00:00:00Z",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, effectiveOn(c.annotation))
		})
	}
}

func TestSolution(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   string
	}{
		// I don't want to redo all the edge cases here. I think there's enough
		// coverage for those code paths already in TestEffectiveOn above.
		{
			name: "with solution",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   solution: Chunky bacon
				deny if { true }`)),
			expected: "Chunky bacon",
		},
		{
			name: "with xref links",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#  solution: >-
				#    See xref:release_policy.adoc#attestation_task_bundle_package[here] and
				#    xref:attachment$trusted_tekton_tasks.yml[over there] for details.
				deny if { true }`)),
			expected: "See here and over there for details.",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, solution(c.annotation))
		})
	}
}

func TestCollections(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   []string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   []string{},
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				deny if { true }`)),
			expected: []string{},
		},
		{
			name: "without custom annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# title: title
				deny if { true }`)),
			expected: []string{},
		},
		{
			name: "with custom annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   hmm: 14
				deny if { true }`)),
			expected: []string{},
		},
		{
			name: "with one collection annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   collections:
				#     - A
				deny if { true }`)),
			expected: []string{"A"},
		},
		{
			name: "with several collection annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   collections:
				#     - A
				#     - B
				#     - C
				deny if { true }`)),
			expected: []string{"A", "B", "C"},
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, collections(c.annotation))
		})
	}
}

func TestPipelineIntention(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   []string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   []string{},
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				deny if { true }`)),
			expected: []string{},
		},
		{
			name: "without custom annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# title: title
				deny if { true }`)),
			expected: []string{},
		},
		{
			name: "with custom annotation but no pipeline_intention",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   short_name: test
				deny if { true }`)),
			expected: []string{},
		},
		{
			name: "with single pipeline_intention",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   pipeline_intention:
				#     - release
				deny if { true }`)),
			expected: []string{"release"},
		},
		{
			name: "with multiple pipeline_intentions",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   pipeline_intention:
				#     - release
				#     - production
				#     - test
				deny if { true }`)),
			expected: []string{"release", "production", "test"},
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, pipelineIntention(c.annotation))
		})
	}
}

func TestCodeAndDocumentationUrl(t *testing.T) {
	cases := []struct {
		name        string
		annotation  *ast.AnnotationsRef
		expected    string
		expectedUrl string
	}{
		{
			name:       "no code",
			annotation: nil,
			expected:   "",
		},
		{
			name: "no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				deny if { true }`)),
			expected:    "",
			expectedUrl: "",
		},
		{
			name: "with short_name",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   short_name: x
				deny if { true }`)),
			expected:    "a.x",
			expectedUrl: "https://conforma.dev/docs/policy/release_policy.html#a__x",
		},
		{
			name: "nested packages no annotations",
			annotation: annotationRef(heredoc.Doc(`
				package a.b.c
				import rego.v1
				deny if { true }`)),
			expected:    "",
			expectedUrl: "",
		},
		{
			name: "nested packages with short_name",
			annotation: annotationRef(heredoc.Doc(`
				package a.b.c
				import rego.v1
				# METADATA
				# custom:
				#   short_name: x
				deny if { true }`)),
			expected:    "a.b.c.x",
			expectedUrl: "https://conforma.dev/docs/policy/release_policy.html#c__x",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("[%d] - %s", i, c.name), func(t *testing.T) {
			assert.Equal(t, c.expected, code(c.annotation))
			assert.Equal(t, c.expectedUrl, documentationUrl(c.annotation))
		})
	}
}

func TestDependsOn(t *testing.T) {
	cases := []struct {
		name       string
		annotation *ast.AnnotationsRef
		expected   []string
	}{
		{
			name:       "nothing",
			annotation: nil,
			expected:   []string{},
		},
		{
			name: "no depends_on annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				deny if { true }`)),
			expected: []string{},
		},
		{
			name: "single depends_on annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   depends_on: a.b.c
				deny if { true }`)),
			expected: []string{"a.b.c"},
		},
		{
			name: "multiple depends_on annotation",
			annotation: annotationRef(heredoc.Doc(`
				package a
				import rego.v1
				# METADATA
				# custom:
				#   depends_on:
				#     - a.b.c
				#     - d.e.f
				#     - g.h.i
				deny if { true }`)),
			expected: []string{"a.b.c", "d.e.f", "g.h.i"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, dependsOn(c.annotation))
		})
	}
}

func TestReplaceXrefReferencesWithURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Single valid reference",
			input:    "xref:cli:ROOT:configuration.adoc#_data_sources[data sources]",
			expected: "https://conforma.dev/docs/cli/configuration.html#_data_sources",
		},
		{
			name: "Multiple valid references",
			input: "Check xref:group1:ROOT:guide.adoc#intro[Introduction] and " +
				"xref:group2:ROOT:manual.adoc#usage[Usage] for details.",
			expected: "Check https://conforma.dev/docs/group1/guide.html#intro and " +
				"https://conforma.dev/docs/group2/manual.html#usage for details.",
		},
		{
			name:     "No valid reference",
			input:    "This is a test string with no reference.",
			expected: "This is a test string with no reference.",
		},
		{
			name:     "Malformed reference",
			input:    "xref:malformed",
			expected: "xref:malformed",
		},
		{
			name:     "Reference missing bracketed text",
			input:    "xref:cli:ROOT:configuration.adoc#_data_sources", // Missing trailing "[...]"
			expected: "xref:cli:ROOT:configuration.adoc#_data_sources", // No match → remains unchanged.
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := replaceXrefReferencesWithURL(tc.input)
			if result != tc.expected {
				t.Errorf("Test %q failed:\nexpected: %q\ngot: %q", tc.name, tc.expected, result)
			}
		})
	}
}
