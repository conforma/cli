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
	"context"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

// mockPolicySource implements source.PolicySource for testing
type mockPolicySource struct {
	policyDir string
}

func (m mockPolicySource) GetPolicy(ctx context.Context, dest string, showMsg bool) (string, error) {
	return m.policyDir, nil
}

func (m mockPolicySource) PolicyUrl() string {
	return "mock-url"
}

func (m mockPolicySource) Subdir() string {
	return "policy"
}

func (mockPolicySource) Type() source.PolicyType {
	return source.PolicyKind
}

func TestRuleDiscoveryService_DiscoverRules(t *testing.T) {
	// Create a test filesystem
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	// Create a test policy file with annotations
	policyContent := `package test

import rego.v1

# METADATA
# title: Test Rule
# description: A test rule for rule discovery
# custom:
#   short_name: test_rule
#   failure_msg: Test rule failed

deny contains result if {
    result := {
        "msg": "Test rule failed",
        "code": "test.test_rule"
    }
}`

	// Write the policy file directly to the test filesystem
	policyPath := "/policy/test.rego"
	err := afero.WriteFile(fs, policyPath, []byte(policyContent), 0644)
	require.NoError(t, err)

	// Create a mock policy source that points to our test directory
	policySource := mockPolicySource{policyDir: "/policy"}

	// Create the rule discovery service
	service := NewRuleDiscoveryService()

	// Discover rules
	rules, err := service.DiscoverRules(ctx, []source.PolicySource{policySource})
	require.NoError(t, err)

	// Verify that we found the expected rule
	assert.Len(t, rules, 1, "Expected to find exactly one rule")

	ruleInfo, exists := rules["test.test_rule"]
	assert.True(t, exists, "Expected to find rule with code 'test.test_rule'")
	assert.Equal(t, "test.test_rule", ruleInfo.Code)
	assert.Equal(t, "test", ruleInfo.Package)
	assert.Equal(t, "test_rule", ruleInfo.ShortName)
	assert.Equal(t, "Test Rule", ruleInfo.Title)
	assert.Equal(t, "A test rule for rule discovery", ruleInfo.Description)
}

func TestRuleDiscoveryService_DiscoverRules_NoPolicyFiles(t *testing.T) {
	// Create a test filesystem
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	// Create an empty directory in the test filesystem
	err := fs.MkdirAll("/empty", 0755)
	require.NoError(t, err)

	// Create a mock policy source that points to an empty directory
	policySource := mockPolicySource{policyDir: "/empty"}

	// Create the rule discovery service
	service := NewRuleDiscoveryService()

	// Discover rules - this should succeed but return no rules
	rules, err := service.DiscoverRules(ctx, []source.PolicySource{policySource})
	require.NoError(t, err)

	// Verify that we found no rules
	assert.Len(t, rules, 0, "Expected to find no rules in empty directory")
}

func TestRuleDiscoveryService_DiscoverRules_MultipleSources(t *testing.T) {
	// Create a test filesystem
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)

	// Create test policy files
	policyContent1 := `package test1

import rego.v1

# METADATA
# title: Test Rule 1
# description: First test rule
# custom:
#   short_name: test_rule_1
#   failure_msg: Test rule 1 failed

deny contains result if {
    result := {
        "msg": "Test rule 1 failed",
        "code": "test1.test_rule_1"
    }
}`

	policyContent2 := `package test2

import rego.v1

# METADATA
# title: Test Rule 2
# description: Second test rule
# custom:
#   short_name: test_rule_2
#   failure_msg: Test rule 2 failed

deny contains result if {
    result := {
        "msg": "Test rule 2 failed",
        "code": "test2.test_rule_2"
    }
}`

	// Write the policy files directly to the test filesystem
	policyPath1 := "/policy1/test1.rego"
	err := afero.WriteFile(fs, policyPath1, []byte(policyContent1), 0644)
	require.NoError(t, err)

	policyPath2 := "/policy2/test2.rego"
	err = afero.WriteFile(fs, policyPath2, []byte(policyContent2), 0644)
	require.NoError(t, err)

	// Create policy sources
	policySource1 := mockPolicySource{policyDir: "/policy1"}
	policySource2 := mockPolicySource{policyDir: "/policy2"}

	// Create the rule discovery service
	service := NewRuleDiscoveryService()

	// Discover rules from both sources
	rules, err := service.DiscoverRules(ctx, []source.PolicySource{policySource1, policySource2})
	require.NoError(t, err)

	// Verify that we found both rules
	assert.Len(t, rules, 2, "Expected to find exactly two rules")

	// Check first rule
	ruleInfo1, exists := rules["test1.test_rule_1"]
	assert.True(t, exists, "Expected to find rule with code 'test1.test_rule_1'")
	assert.Equal(t, "test1.test_rule_1", ruleInfo1.Code)
	assert.Equal(t, "test1", ruleInfo1.Package)

	// Check second rule
	ruleInfo2, exists := rules["test2.test_rule_2"]
	assert.True(t, exists, "Expected to find rule with code 'test2.test_rule_2'")
	assert.Equal(t, "test2.test_rule_2", ruleInfo2.Code)
	assert.Equal(t, "test2", ruleInfo2.Package)
}
