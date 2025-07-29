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

package evaluator

import (
	"testing"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/policy"
)

type testConfigProvider struct {
	effectiveTime time.Time
}

func (t *testConfigProvider) EffectiveTime() time.Time {
	return t.effectiveTime
}

func (t *testConfigProvider) SigstoreOpts() (policy.SigstoreOpts, error) {
	return policy.SigstoreOpts{}, nil
}

func (t *testConfigProvider) Spec() ecc.EnterpriseContractPolicySpec {
	return ecc.EnterpriseContractPolicySpec{}
}

func TestUnifiedRuleSelector(t *testing.T) {
	// Create test rules
	allRules := map[string]rule.Info{
		"release.security_check": {
			Code:        "release.security_check",
			Package:     "release",
			ShortName:   "security_check",
			Collections: []string{"security"},
			Terms:       []string{"sast-snyk-check-oci-ta"},
		},
		"release.deprecated_rule": {
			Code:        "release.deprecated_rule",
			Package:     "release",
			ShortName:   "deprecated_rule",
			Collections: []string{"security"},
		},
		"release.new_feature": {
			Code:      "release.new_feature",
			Package:   "release",
			ShortName: "new_feature",
		},
		"other.general_rule": {
			Code:      "other.general_rule",
			Package:   "other",
			ShortName: "general_rule",
		},
	}

	// Create test source with minimal config
	source := ecc.Source{
		Config: &ecc.SourceConfig{
			Include: []string{"@security", "release.*"},
			Exclude: []string{"release.deprecated_rule"},
		},
	}

	// Create image context
	imageContext := &ImageContext{
		Digest: "sha256:abc123",
		Time:   time.Now(),
	}

	// Create test config provider
	configProvider := &testConfigProvider{
		effectiveTime: time.Now(),
	}

	// Create unified rule selector
	selector := NewUnifiedRuleSelector(source, configProvider, imageContext)
	selector.SetAllRules(allRules)

	t.Run("PackagesToEvaluate", func(t *testing.T) {
		packages := selector.PackagesToEvaluate(allRules)
		// Should include release package (has included rules) but not other package
		assert.Contains(t, packages, "release")
		assert.NotContains(t, packages, "other")
	})

	t.Run("ShouldReport", func(t *testing.T) {
		// Test rule that is excluded by config
		assert.False(t, selector.ShouldReport("release.deprecated_rule", "sha256:abc123", time.Now()))

		// Test rule that should be included
		assert.True(t, selector.ShouldReport("release.new_feature", "sha256:abc123", time.Now()))

		// Test rule that is excluded by low score
		assert.False(t, selector.ShouldReport("other.general_rule", "sha256:abc123", time.Now()))
	})

	t.Run("ExplainExclusion", func(t *testing.T) {
		explanation := selector.ExplainExclusion("release.deprecated_rule")
		assert.Contains(t, explanation, "exclude score")
	})

	t.Run("GetIncludedRules", func(t *testing.T) {
		includedRules := selector.GetIncludedRules("release")
		assert.Contains(t, includedRules, "release.new_feature")
		assert.NotContains(t, includedRules, "release.deprecated_rule")
	})
}
