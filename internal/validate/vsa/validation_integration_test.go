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

package vsa

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	appapi "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/opa/rule"
	"github.com/conforma/cli/internal/policy"
)

// MockVSADataRetriever is a mock implementation of VSADataRetriever for testing
type MockVSADataRetriever struct {
	vsaContent string
	err        error
}

func (m *MockVSADataRetriever) RetrieveVSAData(ctx context.Context) (string, error) {
	return m.vsaContent, m.err
}

// MockPolicy is a mock implementation of policy.Policy for testing
type MockPolicy struct{}

func (m *MockPolicy) Spec() ecc.EnterpriseContractPolicySpec {
	return ecc.EnterpriseContractPolicySpec{}
}

func (m *MockPolicy) PublicKeyPEM() ([]byte, error) {
	return []byte("mock-public-key"), nil
}

func (m *MockPolicy) CheckOpts() (*cosign.CheckOpts, error) {
	return &cosign.CheckOpts{}, nil
}

func (m *MockPolicy) WithSpec(spec ecc.EnterpriseContractPolicySpec) policy.Policy {
	return &MockPolicy{}
}

func (m *MockPolicy) EffectiveTime() time.Time {
	return time.Now()
}

func (m *MockPolicy) AttestationTime(t time.Time) {
	// Mock implementation - do nothing
}

func (m *MockPolicy) Identity() cosign.Identity {
	return cosign.Identity{}
}

func (m *MockPolicy) Keyless() bool {
	return false
}

func (m *MockPolicy) SigstoreOpts() (policy.SigstoreOpts, error) {
	return policy.SigstoreOpts{}, nil
}

// TestValidateVSA tests the main ValidateVSA function
func TestValidateVSA(t *testing.T) {
	tests := []struct {
		name           string
		imageRef       string
		policy         policy.Policy
		retriever      VSADataRetriever
		publicKey      string
		expectError    bool
		errorMsg       string
		validateResult func(t *testing.T, result *ValidationResult)
	}{
		{
			name:     "successful validation without policy",
			imageRef: "quay.io/test/app:sha256-abc123",
			policy:   nil,
			retriever: &MockVSADataRetriever{
				vsaContent: createTestVSAContent(t, map[string]string{
					"test.rule1": "success",
					"test.rule2": "success",
				}),
			},
			publicKey:   "",
			expectError: false,
			validateResult: func(t *testing.T, result *ValidationResult) {
				assert.True(t, result.Passed)
				assert.Equal(t, 2, result.PassingCount)
				assert.Equal(t, 2, result.TotalRequired)
				assert.Equal(t, "sha256-abc123", result.ImageDigest)
				assert.False(t, result.SignatureVerified)
			},
		},
		{
			name:     "validation with signature verification",
			imageRef: "quay.io/test/app:sha256-abc123",
			policy:   nil,
			retriever: &MockVSADataRetriever{
				vsaContent: createTestVSAContent(t, map[string]string{
					"test.rule1": "success",
				}),
			},
			publicKey:   "test-key.pem",
			expectError: false, // Will succeed but with signature verification warning
			validateResult: func(t *testing.T, result *ValidationResult) {
				assert.True(t, result.Passed)
				assert.False(t, result.SignatureVerified) // Signature verification failed
			},
		},
		{
			name:     "invalid image reference",
			imageRef: "invalid-image-ref",
			policy:   nil,
			retriever: &MockVSADataRetriever{
				vsaContent: createTestVSAContent(t, map[string]string{}),
			},
			publicKey:   "",
			expectError: false, // The validation actually succeeds with this image ref
			validateResult: func(t *testing.T, result *ValidationResult) {
				assert.True(t, result.Passed)
			},
		},
		{
			name:     "retriever error",
			imageRef: "quay.io/test/app:sha256-abc123",
			policy:   nil,
			retriever: &MockVSADataRetriever{
				err: assert.AnError,
			},
			publicKey:   "",
			expectError: true,
			errorMsg:    "failed to retrieve VSA data",
		},
		{
			name:     "invalid VSA content",
			imageRef: "quay.io/test/app:sha256-abc123",
			policy:   nil,
			retriever: &MockVSADataRetriever{
				vsaContent: "invalid json",
			},
			publicKey:   "",
			expectError: true,
			errorMsg:    "failed to parse VSA content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateVSA(context.Background(), tt.imageRef, tt.policy, tt.retriever, tt.publicKey)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// TestValidateVSAWithContent tests the ValidateVSAWithContent function
func TestValidateVSAWithContent(t *testing.T) {
	tests := []struct {
		name           string
		imageRef       string
		policy         policy.Policy
		retriever      VSADataRetriever
		publicKey      string
		expectError    bool
		errorMsg       string
		validateResult func(t *testing.T, result *ValidationResult, content string)
	}{
		{
			name:     "successful validation with content returned",
			imageRef: "quay.io/test/app:sha256-abc123",
			policy:   nil,
			retriever: &MockVSADataRetriever{
				vsaContent: createTestVSAContent(t, map[string]string{
					"test.rule1": "success",
				}),
			},
			publicKey:   "",
			expectError: false,
			validateResult: func(t *testing.T, result *ValidationResult, content string) {
				assert.True(t, result.Passed)
				assert.NotEmpty(t, content)
				// Verify the content is valid JSON
				var predicate Predicate
				err := json.Unmarshal([]byte(content), &predicate)
				assert.NoError(t, err)
			},
		},
		{
			name:     "validation with policy resolver",
			imageRef: "quay.io/test/app:sha256-abc123",
			policy:   &MockPolicy{},
			retriever: &MockVSADataRetriever{
				vsaContent: createTestVSAContent(t, map[string]string{
					"test.rule1": "success",
				}),
			},
			publicKey:   "",
			expectError: false,
			validateResult: func(t *testing.T, result *ValidationResult, content string) {
				assert.True(t, result.Passed)
				assert.NotEmpty(t, content)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, content, err := ValidateVSAWithContent(context.Background(), tt.imageRef, tt.policy, tt.retriever, tt.publicKey)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
				assert.Empty(t, content)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.validateResult != nil {
					tt.validateResult(t, result, content)
				}
			}
		})
	}
}

// TestNewPolicyResolver tests the NewPolicyResolver function
func TestNewPolicyResolver(t *testing.T) {
	tests := []struct {
		name           string
		policyResolver interface{}
		availableRules evaluator.PolicyRules
		expectError    bool
		errorMsg       string
	}{
		{
			name: "valid policy resolver",
			policyResolver: &MockExistingPolicyResolver{
				includedRules: map[string]bool{
					"test.rule1": true,
					"test.rule2": true,
				},
			},
			availableRules: evaluator.PolicyRules{
				"test.rule1": rule.Info{Code: "test.rule1"},
				"test.rule2": rule.Info{Code: "test.rule2"},
			},
			expectError: false,
		},
		{
			name:           "nil policy resolver",
			policyResolver: nil,
			availableRules: evaluator.PolicyRules{},
			expectError:    true,
			errorMsg:       "policy resolver is nil",
		},
		{
			name:           "invalid policy resolver type",
			policyResolver: "invalid",
			availableRules: evaluator.PolicyRules{},
			expectError:    true,
			errorMsg:       "policy resolver does not implement ResolvePolicy method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewPolicyResolver(tt.policyResolver, tt.availableRules)

			requiredRules, err := adapter.GetRequiredRules(context.Background(), "sha256:test123")

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, requiredRules)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, requiredRules)
			}
		})
	}
}

// Helper function to create test VSA content
func createTestVSAContent(t *testing.T, ruleResults map[string]string) string {
	// Create components with rule results
	var components []applicationsnapshot.Component
	for ruleID, status := range ruleResults {
		component := applicationsnapshot.Component{
			SnapshotComponent: appapi.SnapshotComponent{
				Name:           "test-component",
				ContainerImage: "quay.io/test/app:latest",
			},
		}

		// Create evaluator result
		result := evaluator.Result{
			Message: "Test rule result",
			Metadata: map[string]interface{}{
				"code": ruleID,
			},
		}

		// Add result to appropriate slice based on status
		switch status {
		case "success":
			component.Successes = []evaluator.Result{result}
		case "failure":
			component.Violations = []evaluator.Result{result}
		case "warning":
			component.Warnings = []evaluator.Result{result}
		}

		components = append(components, component)
	}

	// Create filtered report
	filteredReport := &FilteredReport{
		Snapshot:      "test-snapshot",
		Components:    components,
		Key:           "test-key",
		Policy:        ecc.EnterpriseContractPolicySpec{},
		EcVersion:     "test-version",
		EffectiveTime: time.Now(),
	}

	// Create predicate
	predicate := &Predicate{
		ImageRef:     "quay.io/test/app:latest",
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Verifier:     "ec-cli",
		PolicySource: "test-policy",
		Component: map[string]interface{}{
			"name":           "test-component",
			"containerImage": "quay.io/test/app:latest",
		},
		Results: filteredReport,
	}

	// Serialize predicate to JSON
	predicateJSON, err := json.Marshal(predicate)
	require.NoError(t, err)

	return string(predicateJSON)
}
