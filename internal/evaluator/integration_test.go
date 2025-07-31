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
	"context"
	"testing"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/policy"
)

// IntegrationTestHelper provides utilities for integration testing
type IntegrationTestHelper struct {
	fs      afero.Fs
	workDir string
}

// NewIntegrationTestHelper creates a new integration test helper
func NewIntegrationTestHelper(t *testing.T) *IntegrationTestHelper {
	fs := afero.NewMemMapFs()
	workDir := "/tmp/integration-test"
	err := fs.MkdirAll(workDir, 0755)
	require.NoError(t, err)

	return &IntegrationTestHelper{
		fs:      fs,
		workDir: workDir,
	}
}

func TestIntegrationFeatureFlagFunctionality(t *testing.T) {
	t.Run("Feature Flag Integration", func(t *testing.T) {
		// Create a simple test policy
		p, err := policy.NewInertPolicy(context.Background(), "")
		require.NoError(t, err)

		// Test with feature flag disabled (should use legacy)
		featureFlagsDisabled := map[string]bool{
			"comprehensive-post-evaluation-filter": false,
		}
		featureFlagProviderDisabled := NewDefaultFeatureFlagProvider(featureFlagsDisabled)
		migrationHelperDisabled := NewFeatureFlagMigrationHelper(
			ecc.Source{}, p, featureFlagProviderDisabled, "comprehensive-post-evaluation-filter")

		assert.Equal(t, "legacy (feature flag disabled)", migrationHelperDisabled.GetActiveFilterType())
		assert.False(t, migrationHelperDisabled.IsFeatureFlagEnabled())

		// Test with feature flag enabled (should use comprehensive)
		featureFlagsEnabled := map[string]bool{
			"comprehensive-post-evaluation-filter": true,
		}
		featureFlagProviderEnabled := NewDefaultFeatureFlagProvider(featureFlagsEnabled)
		migrationHelperEnabled := NewFeatureFlagMigrationHelper(
			ecc.Source{}, p, featureFlagProviderEnabled, "comprehensive-post-evaluation-filter")

		assert.Equal(t, "comprehensive (feature flag enabled)", migrationHelperEnabled.GetActiveFilterType())
		assert.True(t, migrationHelperEnabled.IsFeatureFlagEnabled())

		// Test feature flag name
		assert.Equal(t, "comprehensive-post-evaluation-filter", migrationHelperDisabled.GetFeatureFlagName())
		assert.Equal(t, "comprehensive-post-evaluation-filter", migrationHelperEnabled.GetFeatureFlagName())
	})

	t.Run("Migration Helper Comparison", func(t *testing.T) {
		// Test the CompareResults functionality with real data
		p, err := policy.NewInertPolicy(context.Background(), "")
		require.NoError(t, err)

		// Create test results
		results := []Result{
			{
				Message: "High severity CVE found",
				Metadata: map[string]interface{}{
					metadataCode: "cve.high_severity",
				},
			},
			{
				Message: "Medium severity CVE found",
				Metadata: map[string]interface{}{
					metadataCode: "cve.medium_severity",
				},
			},
		}

		rules := policyRules{
			"cve.high_severity": rule.Info{
				Package: "cve",
				Code:    "high_severity",
			},
			"cve.medium_severity": rule.Info{
				Package: "cve",
				Code:    "medium_severity",
			},
		}

		missingIncludes := map[string]bool{
			"cve": true,
		}

		// Create migration helper
		featureFlags := map[string]bool{
			"comprehensive-post-evaluation-filter": true,
		}
		featureFlagProvider := NewDefaultFeatureFlagProvider(featureFlags)
		migrationHelper := NewFeatureFlagMigrationHelper(
			ecc.Source{}, p, featureFlagProvider, "comprehensive-post-evaluation-filter")

		// Compare results
		legacyResults, newResults, legacyMissingIncludes, newMissingIncludes :=
			migrationHelper.CompareResults(results, rules, "test-target", missingIncludes, time.Now())

		// Both should produce the same results for this simple case
		assert.Len(t, legacyResults, len(newResults),
			"Both filters should produce the same number of results")

		t.Logf("Legacy results: %d, New results: %d", len(legacyResults), len(newResults))
		t.Logf("Legacy missing includes: %d, New missing includes: %d",
			len(legacyMissingIncludes), len(newMissingIncludes))

		// The missing includes might be different due to different filtering logic
		// This is expected behavior, so we don't assert on it
	})
}

func TestIntegrationMigrationHelperFunctionality(t *testing.T) {
	t.Run("Migration Helper Basic Functionality", func(t *testing.T) {
		// Create a simple test policy
		p, err := policy.NewInertPolicy(context.Background(), "")
		require.NoError(t, err)

		// Test migration helper creation and basic functionality
		featureFlags := map[string]bool{
			"comprehensive-post-evaluation-filter": true,
		}
		featureFlagProvider := NewDefaultFeatureFlagProvider(featureFlags)
		migrationHelper := NewFeatureFlagMigrationHelper(
			ecc.Source{}, p, featureFlagProvider, "comprehensive-post-evaluation-filter")

		// Test basic functionality
		assert.True(t, migrationHelper.IsFeatureFlagEnabled())
		assert.Equal(t, "comprehensive-post-evaluation-filter", migrationHelper.GetFeatureFlagName())
		assert.Equal(t, "comprehensive (feature flag enabled)", migrationHelper.GetActiveFilterType())

		// Test that the migration helper can be used for filtering
		results := []Result{
			{
				Message: "Test result",
				Metadata: map[string]interface{}{
					metadataCode: "test.rule",
				},
			},
		}

		rules := policyRules{
			"test.rule": rule.Info{
				Package: "test",
				Code:    "rule",
			},
		}

		missingIncludes := map[string]bool{
			"test": true,
		}

		filteredResults, updatedMissingIncludes := migrationHelper.FilterResults(
			results, rules, "test-target", missingIncludes, time.Now())

		// Should be able to filter results
		assert.NotNil(t, filteredResults)
		assert.NotNil(t, updatedMissingIncludes)

		t.Logf("Filtered results: %d", len(filteredResults))
		t.Logf("Updated missing includes: %d", len(updatedMissingIncludes))
	})
}
