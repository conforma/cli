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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/opa/rule"
	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	appapi "github.com/konflux-ci/application-api/api/v1alpha1"
)

// MockPolicyResolver implements PolicyResolver for testing
type MockPolicyResolver struct {
	requiredRules map[string]bool
}

func NewMockPolicyResolver(requiredRules map[string]bool) PolicyResolver {
	return &MockPolicyResolver{
		requiredRules: requiredRules,
	}
}

func (m *MockPolicyResolver) GetRequiredRules(ctx context.Context, imageDigest string) (map[string]bool, error) {
	return m.requiredRules, nil
}

// TestEvaluatorPolicyResolver tests the adapter that uses the existing PolicyResolver
func TestEvaluatorPolicyResolver(t *testing.T) {
	// Create a mock available rules set
	availableRules := evaluator.PolicyRules{
		"test.rule1": rule.Info{
			Code:    "test.rule1",
			Package: "test",
		},
		"test.rule2": rule.Info{
			Code:    "test.rule2",
			Package: "test",
		},
	}

	// Create a mock existing PolicyResolver
	mockExistingResolver := &MockExistingPolicyResolver{
		includedRules: map[string]bool{
			"test.rule1": true,
			"test.rule2": true,
		},
	}

	// Create the adapter
	adapter := NewPolicyResolver(mockExistingResolver, availableRules)

	// Test the adapter
	requiredRules, err := adapter.GetRequiredRules(context.Background(), "sha256:test123")
	assert.NoError(t, err)
	assert.Equal(t, map[string]bool{
		"test.rule1": true,
		"test.rule2": true,
	}, requiredRules)
}

// MockExistingPolicyResolver implements evaluator.PolicyResolver for testing
type MockExistingPolicyResolver struct {
	includedRules map[string]bool
}

func (m *MockExistingPolicyResolver) ResolvePolicy(rules evaluator.PolicyRules, target string) evaluator.PolicyResolutionResult {
	result := evaluator.NewPolicyResolutionResult()
	for ruleID := range m.includedRules {
		result.IncludedRules[ruleID] = true
	}
	return result
}

func (m *MockExistingPolicyResolver) Includes() *evaluator.Criteria {
	return &evaluator.Criteria{}
}

func (m *MockExistingPolicyResolver) Excludes() *evaluator.Criteria {
	return &evaluator.Criteria{}
}

func TestVSARuleValidatorImpl_ValidateVSARules(t *testing.T) {
	tests := []struct {
		name           string
		vsaRecords     []VSARecord
		requiredRules  map[string]bool
		expectedResult *ValidationResult
		expectError    bool
	}{
		{
			name: "all required rules present and passing",
			vsaRecords: []VSARecord{
				createMockVSARecord(t, map[string]string{
					"test.rule1": "success",
					"test.rule2": "success",
				}),
			},
			requiredRules: map[string]bool{
				"test.rule1": true,
				"test.rule2": true,
			},
			expectedResult: &ValidationResult{
				Passed:        true,
				MissingRules:  []MissingRule{},
				FailingRules:  []FailingRule{},
				PassingCount:  2,
				TotalRequired: 2,
				Summary:       "PASS: All 2 required rules are present and passing",
				ImageDigest:   "sha256:test123",
			},
			expectError: false,
		},
		{
			name: "missing required rules",
			vsaRecords: []VSARecord{
				createMockVSARecord(t, map[string]string{
					"test.rule1": "success",
				}),
			},
			requiredRules: map[string]bool{
				"test.rule1": true,
				"test.rule2": true,
			},
			expectedResult: &ValidationResult{
				Passed: false,
				MissingRules: []MissingRule{
					{
						RuleID:  "test.rule2",
						Package: "test",
						Reason:  "Rule required by policy but not found in VSA",
					},
				},
				FailingRules:  []FailingRule{},
				PassingCount:  1,
				TotalRequired: 2,
				Summary:       "FAIL: 1 missing rules, 0 failing rules",
				ImageDigest:   "sha256:test123",
			},
			expectError: false,
		},
		{
			name: "failing rules in VSA",
			vsaRecords: []VSARecord{
				createMockVSARecord(t, map[string]string{
					"test.rule1": "success",
					"test.rule2": "failure",
				}),
			},
			requiredRules: map[string]bool{
				"test.rule1": true,
				"test.rule2": true,
			},
			expectedResult: &ValidationResult{
				Passed:       false,
				MissingRules: []MissingRule{},
				FailingRules: []FailingRule{
					{
						RuleID:  "test.rule2",
						Package: "test",
						Message: "Rule test.rule2 failure",
						Reason:  "Rule failed validation in VSA",
					},
				},
				PassingCount:  1,
				TotalRequired: 2,
				Summary:       "FAIL: 0 missing rules, 1 failing rules",
				ImageDigest:   "sha256:test123",
			},
			expectError: false,
		},
		{
			name: "mixed scenario - missing and failing rules",
			vsaRecords: []VSARecord{
				createMockVSARecord(t, map[string]string{
					"test.rule1": "success",
					"test.rule2": "failure",
				}),
			},
			requiredRules: map[string]bool{
				"test.rule1": true,
				"test.rule2": true,
				"test.rule3": true,
			},
			expectedResult: &ValidationResult{
				Passed: false,
				MissingRules: []MissingRule{
					{
						RuleID:  "test.rule3",
						Package: "test",
						Reason:  "Rule required by policy but not found in VSA",
					},
				},
				FailingRules: []FailingRule{
					{
						RuleID:  "test.rule2",
						Package: "test",
						Message: "Rule test.rule2 failure",
						Reason:  "Rule failed validation in VSA",
					},
				},
				PassingCount:  1,
				TotalRequired: 3,
				Summary:       "FAIL: 1 missing rules, 1 failing rules",
				ImageDigest:   "sha256:test123",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewVSARuleValidator()
			policyResolver := NewMockPolicyResolver(tt.requiredRules)

			result, err := validator.ValidateVSARules(context.Background(), tt.vsaRecords, policyResolver, "sha256:test123")

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)

				// Compare the result
				assert.Equal(t, tt.expectedResult.Passed, result.Passed)
				assert.Equal(t, tt.expectedResult.PassingCount, result.PassingCount)
				assert.Equal(t, tt.expectedResult.TotalRequired, result.TotalRequired)
				assert.Equal(t, tt.expectedResult.Summary, result.Summary)
				assert.Equal(t, tt.expectedResult.ImageDigest, result.ImageDigest)

				// Compare missing rules
				assert.Len(t, result.MissingRules, len(tt.expectedResult.MissingRules))
				for i, expected := range tt.expectedResult.MissingRules {
					assert.Equal(t, expected.RuleID, result.MissingRules[i].RuleID)
					assert.Equal(t, expected.Package, result.MissingRules[i].Package)
					assert.Equal(t, expected.Reason, result.MissingRules[i].Reason)
				}

				// Compare failing rules
				assert.Len(t, result.FailingRules, len(tt.expectedResult.FailingRules))
				for i, expected := range tt.expectedResult.FailingRules {
					assert.Equal(t, expected.RuleID, result.FailingRules[i].RuleID)
					assert.Equal(t, expected.Package, result.FailingRules[i].Package)
					assert.Equal(t, expected.Message, result.FailingRules[i].Message)
					assert.Equal(t, expected.Reason, result.FailingRules[i].Reason)
				}
			}
		})
	}
}

func TestVSARuleValidatorImpl_ExtractRuleID(t *testing.T) {
	validator := &VSARuleValidatorImpl{}

	tests := []struct {
		name     string
		result   evaluator.Result
		expected string
	}{
		{
			name: "valid rule ID",
			result: evaluator.Result{
				Metadata: map[string]interface{}{
					"code": "test.rule1",
				},
			},
			expected: "test.rule1",
		},
		{
			name: "no metadata",
			result: evaluator.Result{
				Metadata: nil,
			},
			expected: "",
		},
		{
			name: "no code field",
			result: evaluator.Result{
				Metadata: map[string]interface{}{
					"other": "value",
				},
			},
			expected: "",
		},
		{
			name: "code is not string",
			result: evaluator.Result{
				Metadata: map[string]interface{}{
					"code": 123,
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.extractRuleID(tt.result)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVSARuleValidatorImpl_ExtractPackageFromRuleID(t *testing.T) {
	validator := &VSARuleValidatorImpl{}

	tests := []struct {
		name     string
		ruleID   string
		expected string
	}{
		{
			name:     "package.rule format",
			ruleID:   "test.rule1",
			expected: "test",
		},
		{
			name:     "no dot separator",
			ruleID:   "testrule",
			expected: "testrule",
		},
		{
			name:     "empty string",
			ruleID:   "",
			expected: "",
		},
		{
			name:     "multiple dots",
			ruleID:   "package.subpackage.rule",
			expected: "package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.extractPackageFromRuleID(tt.ruleID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create mock VSA records for testing
func createMockVSARecord(t *testing.T, ruleResults map[string]string) VSARecord {
	// Create a mock VSA record with the given rule results
	// This creates a proper VSA predicate structure that the validator can parse

	// Create components with rule results
	var components []applicationsnapshot.Component
	for ruleID, status := range ruleResults {
		component := applicationsnapshot.Component{
			SnapshotComponent: appapi.SnapshotComponent{
				Name:           "test-component",
				ContainerImage: "test-image:tag",
			},
		}

		// Create evaluator result
		result := evaluator.Result{
			Message: fmt.Sprintf("Rule %s %s", ruleID, status),
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
		ImageRef:     "test-image:tag",
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Verifier:     "ec-cli",
		PolicySource: "test-policy",
		Component: map[string]interface{}{
			"name":           "test-component",
			"containerImage": "test-image:tag",
		},
		Results: filteredReport,
	}

	// Serialize predicate to JSON
	predicateJSON, err := json.Marshal(predicate)
	if err != nil {
		t.Fatalf("Failed to marshal predicate: %v", err)
	}

	// Encode as base64 for attestation data
	attestationData := base64.StdEncoding.EncodeToString(predicateJSON)

	return VSARecord{
		LogIndex: 1,
		LogID:    "test-log-id",
		Body:     "test-body",
		Attestation: &models.LogEntryAnonAttestation{
			Data: strfmt.Base64(attestationData),
		},
	}
}
