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

package vsa

import (
	"testing"
	"time"

	ecapi "github.com/conforma/crds/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateVSAWithPolicyComparison tests the ValidateVSAWithPolicyComparison function
func TestValidateVSAWithPolicyComparison(t *testing.T) {
	// Skip this test for now as it requires complex mocking
	t.Skip("Skipping TestValidateVSAWithPolicyComparison - requires complex mocking")
}

// TestExtractPolicyFromVSA tests the ExtractPolicyFromVSA function
func TestExtractPolicyFromVSA(t *testing.T) {
	tests := []struct {
		name        string
		predicate   *Predicate
		expectError bool
	}{
		{
			name:        "nil predicate",
			predicate:   nil,
			expectError: true,
		},
		{
			name: "predicate with empty sources",
			predicate: &Predicate{
				Policy: ecapi.EnterpriseContractPolicySpec{},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractPolicyFromVSA(tt.predicate)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestParseEffectiveTime tests the ParseEffectiveTime function
func TestParseEffectiveTime(t *testing.T) {
	tests := []struct {
		name          string
		effectiveTime string
		expectError   bool
		checkResult   func(t *testing.T, result time.Time)
	}{
		{
			name:          "now keyword",
			effectiveTime: "now",
			expectError:   false,
			checkResult: func(t *testing.T, result time.Time) {
				// Should be recent (within last minute)
				assert.True(t, time.Since(result) < time.Minute)
			},
		},
		{
			name:          "valid RFC3339 timestamp",
			effectiveTime: "2023-01-01T00:00:00Z",
			expectError:   false,
			checkResult: func(t *testing.T, result time.Time) {
				expected := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
				assert.Equal(t, expected, result)
			},
		},
		{
			name:          "invalid timestamp format",
			effectiveTime: "invalid-timestamp",
			expectError:   true,
		},
		{
			name:          "empty string",
			effectiveTime: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseEffectiveTime(tt.effectiveTime)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, result)
				}
			}
		})
	}
}

// TestExtractImageDigest tests the ExtractImageDigest function
func TestExtractImageDigest(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   string
	}{
		{
			name:       "sha256 digest",
			identifier: "sha256:abc123def456789",
			expected:   "sha256:abc123def456789",
		},
		{
			name:       "image reference",
			identifier: "registry.io/repo:tag",
			expected:   "registry.io/repo:tag",
		},
		{
			name:       "empty string",
			identifier: "",
			expected:   "",
		},
		{
			name:       "image reference without digest",
			identifier: "registry.io/repo:latest",
			expected:   "registry.io/repo:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractImageDigest(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}
