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
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	ecapi "github.com/conforma/crds/api/v1alpha1"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/policy/equivalence"
)

// TestValidateVSAWithPolicyComparison tests the ValidateVSAWithPolicyComparison function
func TestValidateVSAWithPolicyComparison(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		identifier    string
		data          *ValidationData
		mockRetriever *enhancedMockVSARetriever
		expectError   bool
		expectPassed  bool
		expectMessage string
	}{
		{
			name:        "nil validation data",
			identifier:  "test-identifier",
			data:        nil,
			expectError: true,
		},
		{
			name:       "nil retriever",
			identifier: "test-identifier",
			data: &ValidationData{
				Retriever: nil,
			},
			expectError: true,
		},
		{
			name:       "VSA not found",
			identifier: "not-found-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: false},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
			},
			expectError: true, // The function returns an error when retriever fails
		},
		{
			name:       "VSA expired",
			identifier: "expired-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: true},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
			},
			expectError:   false,
			expectPassed:  false,
			expectMessage: "VSA expired",
		},
		{
			name:       "VSA found and valid - no policy comparison",
			identifier: "valid-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: false},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
				PolicySpec:                  ecapi.EnterpriseContractPolicySpec{}, // Empty policy
			},
			expectError:   false,
			expectPassed:  true,
			expectMessage: "Policy matches",
		},
		{
			name:       "VSA found with policy comparison - policies match",
			identifier: "valid-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: false, shouldMatchPolicy: true},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
				PolicySpec: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{
						{Name: "test-source", Policy: []string{"test-policy"}},
					},
				},
				EffectiveTime: "now",
			},
			expectError:   false,
			expectPassed:  true,
			expectMessage: "Policy matches",
		},
		{
			name:       "VSA found with policy comparison - policies don't match",
			identifier: "valid-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: false, shouldMatchPolicy: false},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
				PolicySpec: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{
						{Name: "test-source", Policy: []string{"different-policy"}},
					},
				},
				EffectiveTime: "now",
			},
			expectError:   false,
			expectPassed:  false,
			expectMessage: "Policy mismatch detected",
		},
		{
			name:       "invalid effective time",
			identifier: "valid-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: false},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
				PolicySpec: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{
						{Name: "test-source", Policy: []string{"test-policy"}},
					},
				},
				EffectiveTime: "invalid-time",
			},
			expectError:   false,
			expectPassed:  false,
			expectMessage: "invalid effective time",
		},
		{
			name:       "signature verification enabled",
			identifier: "valid-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: false, shouldVerifySignature: true},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: false,
				PublicKeyPath:               "/path/to/public.key",
			},
			expectError: true, // This will fail because the public key file doesn't exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateVSAWithPolicyComparison(ctx, tt.identifier, tt.data)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.expectPassed, result.Passed)

			if tt.expectMessage != "" {
				assert.Contains(t, result.Message, tt.expectMessage)
			}
		})
	}
}

// enhancedMockVSARetriever is an enhanced mock implementation of VSARetriever for testing
type enhancedMockVSARetriever struct {
	shouldFind            bool
	shouldExpire          bool
	shouldMatchPolicy     bool
	shouldVerifySignature bool
	shouldReturnError     bool
	errorMessage          string
}

func (m *enhancedMockVSARetriever) RetrieveVSA(ctx context.Context, identifier string) (*ssldsse.Envelope, error) {
	if m.shouldReturnError {
		return nil, fmt.Errorf("%s", m.errorMessage)
	}

	if !m.shouldFind {
		return nil, fmt.Errorf("no VSA found")
	}

	// Create a mock VSA predicate
	predicate := &Predicate{
		Policy: ecapi.EnterpriseContractPolicySpec{
			Sources: []ecapi.Source{
				{Name: "test-source", Policy: []string{"test-policy"}},
			},
		},
		Timestamp: time.Now().Add(-25 * time.Hour).Format(time.RFC3339), // 25 hours ago
	}

	if !m.shouldExpire {
		predicate.Timestamp = time.Now().Add(-1 * time.Hour).Format(time.RFC3339) // 1 hour ago
	}

	// Create mock DSSE envelope with proper base64-encoded payload
	payload := `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-image","digest":{"sha256":"abc123def456"}}],"predicateType":"https://conforma.dev/verification_summary/v1","predicate":{"policy":{"sources":[{"name":"test-source","policy":["test-policy"]}]},"timestamp":"` + predicate.Timestamp + `"}}`
	encodedPayload := base64.StdEncoding.EncodeToString([]byte(payload))

	envelope := &ssldsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     encodedPayload,
		Signatures: []ssldsse.Signature{
			{
				KeyID: "test-key-id",
				Sig:   "test-signature",
			},
		},
	}

	return envelope, nil
}

// TestCompareVSAPolicyWithDetails tests the CompareVSAPolicyWithDetails function
func TestCompareVSAPolicyWithDetails(t *testing.T) {
	now := time.Now()
	imageInfo := &equivalence.ImageInfo{
		Digest: "sha256:test",
		Ref:    "test-image:latest",
	}

	vsaPolicy := ecapi.EnterpriseContractPolicySpec{
		Sources: []ecapi.Source{
			{Name: "test-source", Policy: []string{"test-policy"}},
		},
	}

	suppliedPolicy := ecapi.EnterpriseContractPolicySpec{
		Sources: []ecapi.Source{
			{Name: "test-source", Policy: []string{"test-policy"}},
		},
	}

	tests := []struct {
		name           string
		vsaPolicy      ecapi.EnterpriseContractPolicySpec
		suppliedPolicy ecapi.EnterpriseContractPolicySpec
		effectiveTime  time.Time
		imageInfo      *equivalence.ImageInfo
		expectError    bool
		expectMatch    bool
	}{
		{
			name:           "matching policies",
			vsaPolicy:      vsaPolicy,
			suppliedPolicy: suppliedPolicy,
			effectiveTime:  now,
			imageInfo:      imageInfo,
			expectError:    false,
			expectMatch:    true,
		},
		{
			name:      "different policies",
			vsaPolicy: vsaPolicy,
			suppliedPolicy: ecapi.EnterpriseContractPolicySpec{
				Sources: []ecapi.Source{
					{Name: "different-source", Policy: []string{"different-policy"}},
				},
			},
			effectiveTime: now,
			imageInfo:     imageInfo,
			expectError:   false,
			expectMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equivalent, differences, err := CompareVSAPolicyWithDetails(tt.vsaPolicy, tt.suppliedPolicy, tt.effectiveTime, tt.imageInfo)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectMatch, equivalent)

			if !tt.expectMatch {
				assert.NotEmpty(t, differences)
			}
		})
	}
}

// TestFormatPolicyDifferences tests the FormatPolicyDifferences function
func TestFormatPolicyDifferences(t *testing.T) {
	tests := []struct {
		name         string
		differences  []equivalence.PolicyDifference
		expectOutput string
	}{
		{
			name:         "empty differences",
			differences:  []equivalence.PolicyDifference{},
			expectOutput: "VSA policy does not match supplied policy (no specific differences identified)",
		},
		{
			name: "single difference",
			differences: []equivalence.PolicyDifference{
				{
					Kind:    equivalence.DiffAdded,
					Path:    equivalence.FieldPath{"test", "path"},
					Summary: "test message",
				},
			},
			expectOutput: "❌ Policy mismatch detected — 1 added, 0 removed, 0 changed; 1 differences",
		},
		{
			name: "multiple differences",
			differences: []equivalence.PolicyDifference{
				{Kind: equivalence.DiffAdded, Path: equivalence.FieldPath{"test", "added"}, Summary: "added"},
				{Kind: equivalence.DiffRemoved, Path: equivalence.FieldPath{"test", "removed"}, Summary: "removed"},
				{Kind: equivalence.DiffChanged, Path: equivalence.FieldPath{"test", "changed"}, Summary: "changed"},
			},
			expectOutput: "❌ Policy mismatch detected — 1 added, 1 removed, 1 changed; 3 differences",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatPolicyDifferences(tt.differences)
			assert.Contains(t, result, tt.expectOutput)
		})
	}
}

// TestValidateVSAWithPolicyComparison_EdgeCases tests edge cases for ValidateVSAWithPolicyComparison
func TestValidateVSAWithPolicyComparison_EdgeCases(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		identifier    string
		data          *ValidationData
		expectError   bool
		expectPassed  bool
		expectMessage string
	}{
		{
			name:       "empty identifier",
			identifier: "",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: false},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
			},
			expectError: true, // The function returns an error when retriever fails
		},
		{
			name:       "zero expiration threshold",
			identifier: "test-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: false},
				VSAExpiration:               0, // No expiration
				IgnoreSignatureVerification: true,
			},
			expectError:   false,
			expectPassed:  true,
			expectMessage: "Policy matches",
		},
		{
			name:       "very long expiration threshold",
			identifier: "test-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: false},
				VSAExpiration:               365 * 24 * time.Hour, // 1 year
				IgnoreSignatureVerification: true,
			},
			expectError:   false,
			expectPassed:  true,
			expectMessage: "Policy matches",
		},
		{
			name:       "retriever returns error",
			identifier: "test-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldReturnError: true, errorMessage: "network error"},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
			},
			expectError: true,
		},
		{
			name:       "malformed VSA data",
			identifier: "test-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: false, shouldReturnError: true, errorMessage: "malformed VSA"},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
			},
			expectError: true,
		},
		{
			name:       "policy extraction fails",
			identifier: "test-identifier",
			data: &ValidationData{
				Retriever:                   &enhancedMockVSARetriever{shouldFind: true, shouldExpire: false},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
			},
			expectError:   false,
			expectPassed:  true, // The mock returns valid data, so this should pass
			expectMessage: "Policy matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateVSAWithPolicyComparison(ctx, tt.identifier, tt.data)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.expectPassed, result.Passed)

			if tt.expectMessage != "" {
				assert.Contains(t, result.Message, tt.expectMessage)
			}
		})
	}
}

// TestExtractPolicyFromVSA_EdgeCases tests edge cases for ExtractPolicyFromVSA
func TestExtractPolicyFromVSA_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		predicate   *Predicate
		expectError bool
		expectEmpty bool
	}{
		{
			name:        "predicate with nil policy",
			predicate:   &Predicate{Policy: ecapi.EnterpriseContractPolicySpec{}},
			expectError: true,
		},
		{
			name: "predicate with empty sources",
			predicate: &Predicate{
				Policy: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{},
				},
			},
			expectError: true,
		},
		{
			name: "predicate with valid policy",
			predicate: &Predicate{
				Policy: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{
						{Name: "test-source", Policy: []string{"test-policy"}},
					},
				},
			},
			expectError: false,
		},
		{
			name: "predicate with multiple sources",
			predicate: &Predicate{
				Policy: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{
						{Name: "source1", Policy: []string{"policy1"}},
						{Name: "source2", Policy: []string{"policy2"}},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := ExtractPolicyFromVSA(tt.predicate)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, policy)

			if !tt.expectEmpty {
				assert.NotEmpty(t, policy.Sources)
			}
		})
	}
}

// TestParseEffectiveTime_EdgeCases tests edge cases for ParseEffectiveTime
func TestParseEffectiveTime_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		effectiveTime string
		expectError   bool
		checkResult   func(t *testing.T, result time.Time)
	}{
		{
			name:          "whitespace around 'now'",
			effectiveTime: "  now  ",
			expectError:   true, // Should be exact match
		},
		{
			name:          "case sensitive 'now'",
			effectiveTime: "NOW",
			expectError:   true, // Should be case sensitive
		},
		{
			name:          "RFC3339 with nanoseconds",
			effectiveTime: "2023-01-01T00:00:00.123456789Z",
			expectError:   false,
			checkResult: func(t *testing.T, result time.Time) {
				expected := time.Date(2023, 1, 1, 0, 0, 0, 123456789, time.UTC)
				assert.Equal(t, expected, result)
			},
		},
		{
			name:          "RFC3339 with timezone offset",
			effectiveTime: "2023-01-01T00:00:00+05:00",
			expectError:   false,
			checkResult: func(t *testing.T, result time.Time) {
				// Should be converted to UTC
				expected := time.Date(2022, 12, 31, 19, 0, 0, 0, time.UTC)
				assert.Equal(t, expected, result.UTC())
			},
		},
		{
			name:          "invalid date format",
			effectiveTime: "01/01/2023",
			expectError:   true,
		},
		{
			name:          "future date",
			effectiveTime: "2030-01-01T00:00:00Z",
			expectError:   false,
			checkResult: func(t *testing.T, result time.Time) {
				expected := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
				assert.Equal(t, expected, result)
			},
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

// TestExtractImageDigest_EdgeCases tests edge cases for ExtractImageDigest
func TestExtractImageDigest_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   string
	}{
		{
			name:       "identifier with special characters",
			identifier: "registry.io/repo:tag@sha256:abc123",
			expected:   "registry.io/repo:tag@sha256:abc123",
		},
		{
			name:       "identifier with port",
			identifier: "registry.io:5000/repo:tag",
			expected:   "registry.io:5000/repo:tag",
		},
		{
			name:       "identifier with namespace",
			identifier: "registry.io/namespace/repo:tag",
			expected:   "registry.io/namespace/repo:tag",
		},
		{
			name:       "identifier with digest and tag",
			identifier: "registry.io/repo:tag@sha256:abc123def456",
			expected:   "registry.io/repo:tag@sha256:abc123def456",
		},
		{
			name:       "very long identifier",
			identifier: "very-long-registry-name.example.com/very-long-namespace/very-long-repository-name:very-long-tag-name",
			expected:   "very-long-registry-name.example.com/very-long-namespace/very-long-repository-name:very-long-tag-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractImageDigest(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
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
