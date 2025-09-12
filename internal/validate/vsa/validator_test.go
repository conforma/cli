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

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/go-openapi/strfmt"
	appapi "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/opa/rule"
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
		{
			name: "real VSA scenario - minimal policy rules",
			vsaRecords: []VSARecord{
				createRealisticVSARecord(t),
			},
			requiredRules: map[string]bool{
				"slsa_build_scripted_build.image_built_by_trusted_task": true,
				"slsa_source_correlated.source_code_reference_provided": true,
				"tasks.required_untrusted_task_found":                   true,
				"trusted_task.trusted":                                  true,
				"attestation_type.known_attestation_type":               true,
				"builtin.attestation.signature_check":                   true,
			},
			expectedResult: &ValidationResult{
				Passed:       false,
				MissingRules: []MissingRule{},
				FailingRules: []FailingRule{
					{
						RuleID:      "slsa_build_scripted_build.image_built_by_trusted_task",
						Package:     "slsa_build_scripted_build",
						Message:     "Image \"quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:5b836b3fff54b9c6959bab62503f70e28184e2de80c28ca70e7e57b297a4e693\" not built by a trusted task: Build Task(s) \"build-image-manifest,buildah\" are not trusted",
						Reason:      "Rule failed validation in VSA",
						Title:       "Image built by trusted Task",
						Description: "Verify the digest of the image being validated is reported by a trusted Task in its IMAGE_DIGEST result.",
						Solution:    "Make sure the build Pipeline definition uses a trusted Task to build images.",
					},
					{
						RuleID:      "slsa_source_correlated.source_code_reference_provided",
						Package:     "slsa_source_correlated",
						Message:     "Expected source code reference was not provided for verification",
						Reason:      "Rule failed validation in VSA",
						Title:       "Source code reference provided",
						Description: "Check if the expected source code reference is provided.",
						Solution:    "Provide the expected source code reference for verification.",
					},
					{
						RuleID:      "tasks.required_untrusted_task_found",
						Package:     "tasks",
						Message:     "Required task \"buildah\" is required and present but not from a trusted task",
						Reason:      "Rule failed validation in VSA",
						Title:       "All required tasks are from trusted tasks",
						Description: "Ensure that the all required tasks are resolved from trusted tasks.",
						Solution:    "Use only trusted tasks in the pipeline.",
					},
					{
						RuleID:      "trusted_task.trusted",
						Package:     "trusted_task",
						Message:     "PipelineTask \"build-container-amd64\" uses an untrusted task reference: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:c777fdb0947aff3e4ac29a93ed6358c6f7994e6b150154427646788ec773c440. Please upgrade the task version to: sha256:4548c9d1783b00781073788d7b073ac150c0d22462f06d2d468ad8661892313a",
						Reason:      "Rule failed validation in VSA",
						Title:       "Tasks are trusted",
						Description: "Check the trust of the Tekton Tasks used in the build Pipeline.",
						Solution:    "Upgrade the task version to a trusted version.",
					},
				},
				PassingCount:  2, // attestation_type.known_attestation_type and builtin.attestation.signature_check
				TotalRequired: 6,
				Summary:       "FAIL: 0 missing rules, 4 failing rules",
				ImageDigest:   "sha256:test123",
			},
			expectError: false,
		},
		{
			name: "real VSA scenario with warnings",
			vsaRecords: []VSARecord{
				createRealisticVSARecordWithWarnings(t),
			},
			requiredRules: map[string]bool{
				"labels.required_labels":                  true,
				"labels.optional_labels":                  true,
				"attestation_type.known_attestation_type": true,
			},
			expectedResult: &ValidationResult{
				Passed:       false, // Still fails because of the violation (failure)
				MissingRules: []MissingRule{},
				FailingRules: []FailingRule{
					{
						RuleID:  "labels.required_labels",
						Package: "labels",
						Message: "The required \"cpe\" label is missing. Label description: The CPE (Common Platform Enumeration) identifier for the product, e.g., cpe:/a:redhat:openshift_gitops:1.16::el8. This label is required for on-prem product releases.",
						Reason:  "Rule failed validation in VSA",
					},
				},
				PassingCount:  2, // 1 success + 1 warning (warnings are now acceptable)
				TotalRequired: 3,
				ImageDigest:   "sha256:test123",
				Summary:       "FAIL: 0 missing rules, 1 failing rules",
			},
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

				// Create maps to compare failing rules without requiring specific order
				expectedFailingRules := make(map[string]FailingRule)
				actualFailingRules := make(map[string]FailingRule)

				for _, expected := range tt.expectedResult.FailingRules {
					expectedFailingRules[expected.RuleID] = expected
				}

				for _, actual := range result.FailingRules {
					actualFailingRules[actual.RuleID] = actual
				}

				// Compare each expected failing rule
				for ruleID, expected := range expectedFailingRules {
					actual, exists := actualFailingRules[ruleID]
					assert.True(t, exists, "Expected failing rule %s not found", ruleID)
					if exists {
						assert.Equal(t, expected.RuleID, actual.RuleID)
						assert.Equal(t, expected.Package, actual.Package)
						assert.Equal(t, expected.Message, actual.Message)
						assert.Equal(t, expected.Reason, actual.Reason)
					}
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
		{
			name: "real rule ID from VSA",
			result: evaluator.Result{
				Metadata: map[string]interface{}{
					"code": "slsa_build_scripted_build.image_built_by_trusted_task",
					"collections": []interface{}{
						"redhat",
					},
					"description": "Verify the digest of the image being validated is reported by a trusted Task in its IMAGE_DIGEST result.",
					"title":       "Image built by trusted Task",
				},
			},
			expected: "slsa_build_scripted_build.image_built_by_trusted_task",
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
		{
			name:     "real rule ID from VSA",
			ruleID:   "slsa_build_scripted_build.image_built_by_trusted_task",
			expected: "slsa_build_scripted_build",
		},
		{
			name:     "tasks rule ID from VSA",
			ruleID:   "tasks.required_untrusted_task_found",
			expected: "tasks",
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

// createRealisticVSARecord creates a VSA record that mimics the structure of the real VSA example
func createRealisticVSARecord(t *testing.T) VSARecord {
	// Create a single component with multiple rule results (like the real VSA)
	component := applicationsnapshot.Component{
		SnapshotComponent: appapi.SnapshotComponent{
			Name:           "Unnamed-sha256:5b836b3fff54b9c6959bab62503f70e28184e2de80c28ca70e7e57b297a4e693-arm64",
			ContainerImage: "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:5b836b3fff54b9c6959bab62503f70e28184e2de80c28ca70e7e57b297a4e693",
		},
	}

	// Add violations (failures) - these are the rules that failed
	component.Violations = []evaluator.Result{
		{
			Message: "Image \"quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:5b836b3fff54b9c6959bab62503f70e28184e2de80c28ca70e7e57b297a4e693\" not built by a trusted task: Build Task(s) \"build-image-manifest,buildah\" are not trusted",
			Metadata: map[string]interface{}{
				"code": "slsa_build_scripted_build.image_built_by_trusted_task",
				"collections": []interface{}{
					"redhat",
				},
				"description": "Verify the digest of the image being validated is reported by a trusted Task in its IMAGE_DIGEST result.",
				"title":       "Image built by trusted Task",
				"solution":    "Make sure the build Pipeline definition uses a trusted Task to build images.",
			},
		},
		{
			Message: "Expected source code reference was not provided for verification",
			Metadata: map[string]interface{}{
				"code": "slsa_source_correlated.source_code_reference_provided",
				"collections": []interface{}{
					"minimal", "slsa3", "redhat", "redhat_rpms",
				},
				"description": "Check if the expected source code reference is provided.",
				"title":       "Source code reference provided",
				"solution":    "Provide the expected source code reference for verification.",
			},
		},
		{
			Message: "Required task \"buildah\" is required and present but not from a trusted task",
			Metadata: map[string]interface{}{
				"code": "tasks.required_untrusted_task_found",
				"collections": []interface{}{
					"redhat", "redhat_rpms",
				},
				"description": "Ensure that the all required tasks are resolved from trusted tasks.",
				"title":       "All required tasks are from trusted tasks",
				"solution":    "Use only trusted tasks in the pipeline.",
				"term":        "buildah",
			},
		},
		{
			Message: "PipelineTask \"build-container-amd64\" uses an untrusted task reference: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:c777fdb0947aff3e4ac29a93ed6358c6f7994e6b150154427646788ec773c440. Please upgrade the task version to: sha256:4548c9d1783b00781073788d7b073ac150c0d22462f06d2d468ad8661892313a",
			Metadata: map[string]interface{}{
				"code": "trusted_task.trusted",
				"collections": []interface{}{
					"redhat",
				},
				"description": "Check the trust of the Tekton Tasks used in the build Pipeline.",
				"title":       "Tasks are trusted",
				"solution":    "Upgrade the task version to a trusted version.",
				"term":        "buildah",
			},
		},
	}

	// Add successes - these are the rules that passed
	component.Successes = []evaluator.Result{
		{
			Message: "Pass",
			Metadata: map[string]interface{}{
				"code": "attestation_type.known_attestation_type",
				"collections": []interface{}{
					"minimal", "redhat", "redhat_rpms",
				},
				"description": "Confirm the attestation found for the image has a known attestation type.",
				"title":       "Known attestation type found",
			},
		},
		{
			Message: "Pass",
			Metadata: map[string]interface{}{
				"code":        "builtin.attestation.signature_check",
				"description": "The attestation signature matches available signing materials.",
				"title":       "Attestation signature check passed",
			},
		},
	}

	// Create filtered report
	filteredReport := &FilteredReport{
		Snapshot:      "",
		Components:    []applicationsnapshot.Component{component},
		Key:           "test-key",
		Policy:        ecc.EnterpriseContractPolicySpec{},
		EcVersion:     "test-version",
		EffectiveTime: time.Now(),
	}

	// Create predicate
	predicate := &Predicate{
		ImageRef:     "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:185f6c39e5544479863024565bb7e63c6f2f0547c3ab4ddf99ac9b5755075cc9",
		Timestamp:    "2025-08-18T14:59:08Z",
		Verifier:     "ec-cli",
		PolicySource: "Minimal (deprecated)",
		Component: map[string]interface{}{
			"name":           "Unnamed",
			"containerImage": "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:185f6c39e5544479863024565bb7e63c6f2f0547c3ab4ddf99ac9b5755075cc9",
			"source":         map[string]interface{}{},
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

// createRealisticVSARecordWithWarnings creates a VSA record that includes warnings
func createRealisticVSARecordWithWarnings(t *testing.T) VSARecord {
	// Create a single component with violations and warnings
	component := applicationsnapshot.Component{
		SnapshotComponent: appapi.SnapshotComponent{
			Name:           "Unnamed-sha256:5b836b3fff54b9c6959bab62503f70e28184e2de80c28ca70e7e57b297a4e693-arm64",
			ContainerImage: "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:5b836b3fff54b9c6959bab62503f70e28184e2de80c28ca70e7e57b297a4e693",
		},
	}

	// Add violations (failures)
	component.Violations = []evaluator.Result{
		{
			Message: "The required \"cpe\" label is missing. Label description: The CPE (Common Platform Enumeration) identifier for the product, e.g., cpe:/a:redhat:openshift_gitops:1.16::el8. This label is required for on-prem product releases.",
			Metadata: map[string]interface{}{
				"code": "labels.required_labels",
				"collections": []interface{}{
					"redhat",
				},
				"description":  "Check the image for the presence of labels that are required.",
				"effective_on": "2026-06-07T00:00:00Z",
				"title":        "Required labels",
				"term":         "cpe",
			},
		},
	}

	// Add warnings
	component.Warnings = []evaluator.Result{
		{
			Message: "The required \"org.opencontainers.image.created\" label is missing. Label description: The creation timestamp of the image. This label must always be set by the Konflux build task for on-prem product releases.",
			Metadata: map[string]interface{}{
				"code": "labels.optional_labels",
				"collections": []interface{}{
					"redhat",
				},
				"description":  "Check the image for the presence of labels that are required.",
				"effective_on": "2026-06-07T00:00:00Z",
				"title":        "Required labels",
				"term":         "org.opencontainers.image.created",
			},
		},
	}

	// Add successes
	component.Successes = []evaluator.Result{
		{
			Message: "Pass",
			Metadata: map[string]interface{}{
				"code": "attestation_type.known_attestation_type",
				"collections": []interface{}{
					"minimal", "redhat", "redhat_rpms",
				},
				"description": "Confirm the attestation found for the image has a known attestation type.",
				"title":       "Known attestation type found",
			},
		},
	}

	// Create filtered report
	filteredReport := &FilteredReport{
		Snapshot:      "",
		Components:    []applicationsnapshot.Component{component},
		Key:           "test-key",
		Policy:        ecc.EnterpriseContractPolicySpec{},
		EcVersion:     "test-version",
		EffectiveTime: time.Now(),
	}

	// Create predicate
	predicate := &Predicate{
		ImageRef:     "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:185f6c39e5544479863024565bb7e63c6f2f0547c3ab4ddf99ac9b5755075cc9",
		Timestamp:    "2025-08-18T14:59:08Z",
		Verifier:     "ec-cli",
		PolicySource: "Minimal (deprecated)",
		Component: map[string]interface{}{
			"name":           "Unnamed",
			"containerImage": "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:185f6c39e5544479863024565bb7e63c6f2f0547c3ab4ddf99ac9b5755075cc9",
			"source":         map[string]interface{}{},
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
