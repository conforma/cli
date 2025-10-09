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

package validate

import (
	"testing"
	"time"

	ecapi "github.com/conforma/crds/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/validate/vsa"
)

func TestNewValidateVSACmd(t *testing.T) {
	cmd := NewValidateVSACmd()

	// Check basic command properties
	if cmd.Use != "vsa <vsa-identifier>" {
		t.Errorf("Expected Use to be 'vsa <vsa-identifier>', got '%s'", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected Short description to be set")
	}

	if cmd.Long == "" {
		t.Error("Expected Long description to be set")
	}

	// Check that flags are added
	flags := cmd.Flags()
	if flags.Lookup("vsa") == nil {
		t.Error("Expected --vsa flag to be added")
	}

	if flags.Lookup("policy") == nil {
		t.Error("Expected --policy flag to be added")
	}

	if flags.Lookup("images") == nil {
		t.Error("Expected --images flag to be added")
	}
}

func TestDetectIdentifierType(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   vsa.IdentifierType
	}{
		{
			name:       "file path absolute",
			identifier: "/path/to/vsa.json",
			expected:   vsa.IdentifierImageReference, // name.ParseReference accepts this as valid
		},
		{
			name:       "file path relative",
			identifier: "./vsa.json",
			expected:   vsa.IdentifierImageReference, // name.ParseReference accepts this as valid
		},
		{
			name:       "file path with extension",
			identifier: "vsa.json",
			expected:   vsa.IdentifierImageReference, // name.ParseReference accepts this as valid
		},
		{
			name:       "image digest sha256",
			identifier: "sha256:abc123def456789",
			expected:   vsa.IdentifierImageDigest,
		},
		{
			name:       "image digest sha512",
			identifier: "sha512:abc123def456789",
			expected:   vsa.IdentifierImageDigest,
		},
		{
			name:       "image reference with tag",
			identifier: "registry.io/repo:tag",
			expected:   vsa.IdentifierImageReference,
		},
		{
			name:       "image reference with digest",
			identifier: "registry.io/repo:sha256-abc123",
			expected:   vsa.IdentifierImageReference,
		},
		{
			name:       "docker hub reference",
			identifier: "nginx:latest",
			expected:   vsa.IdentifierImageReference,
		},
		{
			name:       "quay reference",
			identifier: "quay.io/redhat/ubi8:latest",
			expected:   vsa.IdentifierImageReference,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vsa.DetectIdentifierType(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsImageReference(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   bool
	}{
		{
			name:       "docker hub reference",
			identifier: "nginx:latest",
			expected:   true,
		},
		{
			name:       "registry reference",
			identifier: "registry.io/repo:tag",
			expected:   true,
		},
		{
			name:       "reference with digest",
			identifier: "registry.io/repo:sha256-abc123",
			expected:   true,
		},
		{
			name:       "quay reference",
			identifier: "quay.io/redhat/ubi8:latest",
			expected:   true,
		},
		{
			name:       "image digest only",
			identifier: "sha256:abc123",
			expected:   false,
		},
		{
			name:       "file path",
			identifier: "/path/to/file.json",
			expected:   false,
		},
		{
			name:       "invalid reference",
			identifier: "invalid:",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vsa.IsImageReference(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidVSAIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   bool
	}{
		{
			name:       "valid file path",
			identifier: "/path/to/vsa.json",
			expected:   true,
		},
		{
			name:       "valid image digest",
			identifier: "sha256:abc123def456789",
			expected:   true,
		},
		{
			name:       "valid image reference",
			identifier: "registry.io/repo:tag",
			expected:   true,
		},
		{
			name:       "empty identifier",
			identifier: "",
			expected:   false,
		},
		{
			name:       "file path with spaces",
			identifier: "file with spaces.json",
			expected:   true,
		},
		{
			name:       "image reference with spaces",
			identifier: "nginx with spaces:latest",
			expected:   false,
		},
		{
			name:       "invalid digest format",
			identifier: "sha128:abc123",
			expected:   true, // name.ParseReference accepts this as valid
		},
		{
			name:       "invalid image reference",
			identifier: "invalid:",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vsa.IsValidVSAIdentifier(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseVSAExpirationDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration string
		expected time.Duration
		hasError bool
	}{
		{
			name:     "hours",
			duration: "24h",
			expected: 24 * time.Hour,
			hasError: false,
		},
		{
			name:     "days",
			duration: "7d",
			expected: 7 * 24 * time.Hour,
			hasError: false,
		},
		{
			name:     "weeks",
			duration: "2w",
			expected: 2 * 7 * 24 * time.Hour,
			hasError: false,
		},
		{
			name:     "months",
			duration: "1mo",
			expected: 30 * 24 * time.Hour,
			hasError: false,
		},
		{
			name:     "standard Go duration",
			duration: "168h",
			expected: 168 * time.Hour,
			hasError: false,
		},
		{
			name:     "invalid format",
			duration: "invalid",
			expected: 0,
			hasError: true,
		},
		{
			name:     "empty duration",
			duration: "",
			expected: 0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vsa.ParseVSAExpirationDuration(tt.duration)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestExtractPolicyFromVSA(t *testing.T) {
	tests := []struct {
		name        string
		predicate   *vsa.Predicate
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil predicate",
			predicate:   nil,
			expectError: true,
			errorMsg:    "VSA predicate is nil",
		},
		{
			name: "predicate with empty sources",
			predicate: &vsa.Predicate{
				Policy: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{},
				},
			},
			expectError: true,
			errorMsg:    "VSA predicate does not contain policy sources",
		},
		{
			name: "predicate with valid policy and sources",
			predicate: &vsa.Predicate{
				Policy: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{
						{
							Policy: []string{"https://example.com/policy.yaml"},
							Data:   []string{"https://example.com/data.yaml"},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "predicate with multiple sources",
			predicate: &vsa.Predicate{
				Policy: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{
						{
							Policy: []string{"https://example.com/policy1.yaml"},
							Data:   []string{"https://example.com/data1.yaml"},
						},
						{
							Policy: []string{"https://example.com/policy2.yaml"},
							Data:   []string{"https://example.com/data2.yaml"},
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vsa.ExtractPolicyFromVSA(tt.predicate)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result.Sources)
				assert.Equal(t, len(tt.predicate.Policy.Sources), len(result.Sources))
			}
		})
	}
}

// TestValidateVSAInput tests the validateVSAInput function
func TestValidateVSAInput(t *testing.T) {
	tests := []struct {
		name        string
		data        *validateVSAData
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid with vsa identifier in args",
			data: &validateVSAData{
				vsaIdentifier:               "",
				images:                      "",
				vsaExpirationStr:            "24h",
				ignoreSignatureVerification: true,
			},
			args:        []string{"sha256:abc123"},
			expectError: false,
		},
		{
			name: "valid with vsa flag set",
			data: &validateVSAData{
				vsaIdentifier:               "sha256:abc123",
				images:                      "",
				vsaExpirationStr:            "24h",
				ignoreSignatureVerification: true,
			},
			args:        []string{},
			expectError: false,
		},
		{
			name: "valid with images flag set",
			data: &validateVSAData{
				vsaIdentifier:               "",
				images:                      "snapshot.json",
				vsaExpirationStr:            "24h",
				ignoreSignatureVerification: true,
			},
			args:        []string{},
			expectError: false,
		},
		{
			name: "error when neither vsa nor images provided",
			data: &validateVSAData{
				vsaIdentifier:               "",
				images:                      "",
				vsaExpirationStr:            "24h",
				ignoreSignatureVerification: true,
			},
			args:        []string{},
			expectError: true,
			errorMsg:    "either --vsa, --images, or VSA identifier must be provided",
		},
		{
			name: "error when both vsa and images provided",
			data: &validateVSAData{
				vsaIdentifier:               "sha256:abc123",
				images:                      "snapshot.json",
				vsaExpirationStr:            "24h",
				ignoreSignatureVerification: true,
			},
			args:        []string{},
			expectError: true,
			errorMsg:    "--vsa and --images are mutually exclusive",
		},
		{
			name: "error with invalid vsa expiration",
			data: &validateVSAData{
				vsaIdentifier:               "sha256:abc123",
				images:                      "",
				vsaExpirationStr:            "invalid",
				ignoreSignatureVerification: true,
			},
			args:        []string{},
			expectError: true,
			errorMsg:    "invalid --vsa-expiration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVSAInput(tt.data, tt.args)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestParseEffectiveTime tests the parseEffectiveTime function
func TestParseEffectiveTime(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		checkTime   func(t *testing.T, result time.Time)
	}{
		{
			name:        "now keyword",
			input:       "now",
			expectError: false,
			checkTime: func(t *testing.T, result time.Time) {
				// Should be recent (within last minute)
				now := time.Now().UTC()
				diff := now.Sub(result)
				assert.True(t, diff >= 0 && diff < time.Minute, "Time should be recent")
			},
		},
		{
			name:        "valid RFC3339 timestamp",
			input:       "2023-01-01T12:00:00Z",
			expectError: false,
			checkTime: func(t *testing.T, result time.Time) {
				expected := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
				assert.Equal(t, expected, result)
			},
		},
		{
			name:        "invalid timestamp format",
			input:       "invalid-timestamp",
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vsa.ParseEffectiveTime(tt.input)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkTime != nil {
					tt.checkTime(t, result)
				}
			}
		})
	}
}

// TestExtractImageDigest tests the extractImageDigest function
func TestExtractImageDigest(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "sha256 digest",
			input:    "sha256:abc123def456",
			expected: "sha256:abc123def456",
		},
		{
			name:     "image reference",
			input:    "nginx:latest",
			expected: "nginx:latest",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "image reference without digest",
			input:    "registry.io/namespace/image:tag",
			expected: "registry.io/namespace/image:tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vsa.ExtractImageDigest(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConvertYAMLToJSON tests the convertYAMLToJSON function
func TestConvertYAMLToJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{
			name:     "map with interface{} keys",
			input:    map[interface{}]interface{}{"key": "value"},
			expected: map[string]interface{}{"key": "value"},
		},
		{
			name:     "slice of interfaces",
			input:    []interface{}{"item1", "item2"},
			expected: []interface{}{"item1", "item2"},
		},
		{
			name:     "nested map",
			input:    map[interface{}]interface{}{"nested": map[interface{}]interface{}{"key": "value"}},
			expected: map[string]interface{}{"nested": map[string]interface{}{"key": "value"}},
		},
		{
			name:     "primitive value",
			input:    "simple string",
			expected: "simple string",
		},
		{
			name:     "number",
			input:    42,
			expected: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vsa.ConvertYAMLToJSON(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseVSAExpiration tests the parseVSAExpiration function
func TestParseVSAExpiration(t *testing.T) {
	tests := []struct {
		name        string
		data        *validateVSAData
		expectError bool
		checkResult func(t *testing.T, data *validateVSAData)
	}{
		{
			name: "valid hours",
			data: &validateVSAData{
				vsaExpirationStr: "24h",
			},
			expectError: false,
			checkResult: func(t *testing.T, data *validateVSAData) {
				assert.Equal(t, 24*time.Hour, data.vsaExpiration)
			},
		},
		{
			name: "valid days",
			data: &validateVSAData{
				vsaExpirationStr: "7d",
			},
			expectError: false,
			checkResult: func(t *testing.T, data *validateVSAData) {
				assert.Equal(t, 7*24*time.Hour, data.vsaExpiration)
			},
		},
		{
			name: "valid weeks",
			data: &validateVSAData{
				vsaExpirationStr: "2w",
			},
			expectError: false,
			checkResult: func(t *testing.T, data *validateVSAData) {
				assert.Equal(t, 2*7*24*time.Hour, data.vsaExpiration)
			},
		},
		{
			name: "valid months",
			data: &validateVSAData{
				vsaExpirationStr: "1mo",
			},
			expectError: false,
			checkResult: func(t *testing.T, data *validateVSAData) {
				assert.Equal(t, 30*24*time.Hour, data.vsaExpiration)
			},
		},
		{
			name: "invalid format",
			data: &validateVSAData{
				vsaExpirationStr: "invalid",
			},
			expectError: true,
		},
		{
			name: "empty string",
			data: &validateVSAData{
				vsaExpirationStr: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseVSAExpiration(tt.data)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, tt.data)
				}
			}
		})
	}
}
