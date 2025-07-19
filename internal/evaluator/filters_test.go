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

package evaluator

import (
	"encoding/json"
	"testing"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

//////////////////////////////////////////////////////////////////////////////
// test scaffolding
//////////////////////////////////////////////////////////////////////////////

func makeSource(ruleData string, includes []string) ecc.Source {
	s := ecc.Source{}
	if ruleData != "" {
		s.RuleData = &extv1.JSON{Raw: json.RawMessage(ruleData)}
	}
	if len(includes) > 0 {
		s.Config = &ecc.SourceConfig{Include: includes}
	}
	return s
}

//////////////////////////////////////////////////////////////////////////////
// FilterFactory tests
//////////////////////////////////////////////////////////////////////////////

func TestDefaultFilterFactory(t *testing.T) {
	tests := []struct {
		name        string
		source      ecc.Source
		wantFilters int
	}{
		{
			name:        "no config",
			source:      ecc.Source{},
			wantFilters: 0,
		},
		{
			name:        "pipeline intention only",
			source:      makeSource(`{"pipeline_intention":"release"}`, nil),
			wantFilters: 1,
		},
		{
			name:        "include list only",
			source:      makeSource("", []string{"@redhat", "cve"}),
			wantFilters: 1,
		},
		{
			name:        "both pipeline_intention and include list",
			source:      makeSource(`{"pipeline_intention":"release"}`, []string{"@redhat", "cve"}),
			wantFilters: 2,
		},
		{
			name:        "no includes and no pipeline_intention - should include all packages",
			source:      makeSource("", nil),
			wantFilters: 0, // No filters means all packages are included
		},
	}

	for _, tc := range tests {
		got := NewDefaultFilterFactory().CreateFilters(tc.source)
		assert.Len(t, got, tc.wantFilters, tc.name)
	}
}

//////////////////////////////////////////////////////////////////////////////
// IncludeListFilter – core behaviour
//////////////////////////////////////////////////////////////////////////////

func TestIncludeListFilter(t *testing.T) {
	rules := policyRules{
		"pkg.rule":    {Collections: []string{"redhat"}},
		"cve.rule":    {Collections: []string{"security"}},
		"other.rule":  {},
		"labels.rule": {Collections: []string{"security"}},
		"foo.bar":     {},
	}

	tests := []struct {
		name     string
		entries  []string
		wantPkgs []string
	}{
		{
			name:     "@redhat collection",
			entries:  []string{"@redhat"},
			wantPkgs: []string{"pkg"},
		},
		{
			name:     "explicit package",
			entries:  []string{"cve"},
			wantPkgs: []string{"cve"},
		},
		{
			name:     "package.rule entry",
			entries:  []string{"labels.rule"},
			wantPkgs: []string{"labels"},
		},
		{
			name:     "OR across entries",
			entries:  []string{"@redhat", "cve"},
			wantPkgs: []string{"pkg", "cve"},
		},
		{
			name:     "non‑existent entry",
			entries:  []string{"@none"},
			wantPkgs: []string{},
		},
	}

	for _, tc := range tests {
		got := filterNamespaces(rules, NewIncludeListFilter(tc.entries))
		assert.ElementsMatch(t, tc.wantPkgs, got, tc.name)
	}
}

//////////////////////////////////////////////////////////////////////////////
// PipelineIntentionFilter
//////////////////////////////////////////////////////////////////////////////

func TestPipelineIntentionFilter(t *testing.T) {
	rules := policyRules{
		"a.r": {PipelineIntention: []string{"release"}},
		"b.r": {PipelineIntention: []string{"dev"}},
		"c.r": {},
	}

	tests := []struct {
		name       string
		intentions []string
		wantPkgs   []string
	}{
		{
			name:       "no intentions ⇒ no filtering",
			intentions: nil,
			wantPkgs:   []string{"a", "b", "c"},
		},
		{
			name:       "pipeline_intention set - include packages with any pipeline_intention metadata",
			intentions: []string{"release"},
			wantPkgs:   []string{"a", "b"}, // Both a and b have pipeline_intention metadata
		},
		{
			name:       "pipeline_intention set with multiple values - still include packages with any pipeline_intention metadata",
			intentions: []string{"dev", "release"},
			wantPkgs:   []string{"a", "b"}, // Both a and b have pipeline_intention metadata
		},
	}

	for _, tc := range tests {
		got := filterNamespaces(rules, NewPipelineIntentionFilter(tc.intentions))
		assert.ElementsMatch(t, tc.wantPkgs, got, tc.name)
	}
}

//////////////////////////////////////////////////////////////////////////////
// Complete filtering behavior tests
//////////////////////////////////////////////////////////////////////////////

func TestCompleteFilteringBehavior(t *testing.T) {
	rules := policyRules{
		"release.rule1": {PipelineIntention: []string{"release"}},
		"release.rule2": {PipelineIntention: []string{"release", "production"}},
		"dev.rule1":     {PipelineIntention: []string{"dev"}},
		"general.rule1": {}, // No pipeline_intention metadata
		"general.rule2": {}, // No pipeline_intention metadata
	}

	tests := []struct {
		name        string
		source      ecc.Source
		expectedPkg []string
	}{
		{
			name:        "no includes and no pipeline_intention - all packages included",
			source:      makeSource("", nil),
			expectedPkg: []string{"release", "dev", "general"},
		},
		{
			name:        "pipeline_intention set - only packages with pipeline_intention metadata",
			source:      makeSource(`{"pipeline_intention":"release"}`, nil),
			expectedPkg: []string{"release", "dev"}, // general has no pipeline_intention metadata
		},
		{
			name:        "includes set - only matching packages",
			source:      makeSource("", []string{"release", "general"}),
			expectedPkg: []string{"release", "general"},
		},
		{
			name:        "both pipeline_intention and includes - AND logic",
			source:      makeSource(`{"pipeline_intention":"release"}`, []string{"release"}),
			expectedPkg: []string{"release"}, // Only release matches both conditions
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filterFactory := NewDefaultFilterFactory()
			filters := filterFactory.CreateFilters(tc.source)
			got := filterNamespaces(rules, filters...)
			assert.ElementsMatch(t, tc.expectedPkg, got, tc.name)
		})
	}
}
