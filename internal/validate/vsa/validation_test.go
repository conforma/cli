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
	"testing"

	appapi "github.com/konflux-ci/application-api/api/v1alpha1"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
)

// TestParseVSAContent tests the ParseVSAContent function with different VSA formats
func TestParseVSAContent(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
		errorMsg    string
		validate    func(t *testing.T, predicate *Predicate)
	}{
		{
			name: "raw predicate format",
			content: `{
				"imageRef": "quay.io/test/app:latest",
				"timestamp": "2024-01-01T00:00:00Z",
				"verifier": "ec-cli",
				"policySource": "test-policy",
				"component": {
					"name": "test-component",
					"containerImage": "quay.io/test/app:latest"
				},
				"results": {
					"components": []
				}
			}`,
			expectError: false,
			validate: func(t *testing.T, predicate *Predicate) {
				assert.Equal(t, "quay.io/test/app:latest", predicate.ImageRef)
				assert.Equal(t, "2024-01-01T00:00:00Z", predicate.Timestamp)
				assert.Equal(t, "ec-cli", predicate.Verifier)
				assert.Equal(t, "test-policy", predicate.PolicySource)
				assert.NotNil(t, predicate.Component)
				assert.NotNil(t, predicate.Results)
			},
		},
		{
			name: "DSSE envelope with raw predicate payload",
			content: `{
				"imageRef": "quay.io/test/app:latest",
				"timestamp": "2024-01-01T00:00:00Z",
				"verifier": "ec-cli",
				"policySource": "test-policy",
				"component": {
					"name": "test-component",
					"containerImage": "quay.io/test/app:latest"
				},
				"results": {
					"components": []
				}
			}`,
			expectError: false,
			validate: func(t *testing.T, predicate *Predicate) {
				assert.Equal(t, "quay.io/test/app:latest", predicate.ImageRef)
				assert.Equal(t, "ec-cli", predicate.Verifier)
			},
		},
		{
			name: "DSSE envelope with in-toto statement payload",
			content: `{
				"_type": "https://in-toto.io/Statement/v0.1",
				"predicateType": "https://conforma.dev/vsa/v0.1",
				"subject": [{
					"name": "quay.io/test/app:latest",
					"digest": {
						"sha256": "abc123"
					}
				}],
				"predicate": {
					"imageRef": "quay.io/test/app:latest",
					"timestamp": "2024-01-01T00:00:00Z",
					"verifier": "ec-cli",
					"policySource": "test-policy",
					"component": {
						"name": "test-component",
						"containerImage": "quay.io/test/app:latest"
					},
					"results": {
						"components": []
					}
				}
			}`,
			expectError: false,
			validate: func(t *testing.T, predicate *Predicate) {
				assert.Equal(t, "quay.io/test/app:latest", predicate.ImageRef)
				assert.Equal(t, "ec-cli", predicate.Verifier)
			},
		},
		{
			name:        "invalid JSON",
			content:     `invalid json content`,
			expectError: true,
			errorMsg:    "failed to parse VSA predicate from DSSE payload",
		},
		{
			name:        "DSSE envelope with invalid base64 payload",
			content:     "invalid-base64",
			expectError: true,
			errorMsg:    "failed to parse VSA predicate from DSSE payload",
		},
		{
			name:        "DSSE envelope with invalid JSON payload",
			content:     "invalid json",
			expectError: true,
			errorMsg:    "failed to parse VSA predicate from DSSE payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a DSSE envelope from the content
			envelope := &ssldsse.Envelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     tt.content,
				Signatures:  []ssldsse.Signature{},
			}
			predicate, err := ParseVSAContent(envelope)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, predicate)
			} else {
				require.NoError(t, err)
				require.NotNil(t, predicate)
				if tt.validate != nil {
					tt.validate(t, predicate)
				}
			}
		})
	}
}

// TestExtractRuleResultsFromPredicate tests the extractRuleResultsFromPredicate function
func TestExtractRuleResultsFromPredicate(t *testing.T) {
	tests := []struct {
		name            string
		predicate       *Predicate
		expectedResults map[string][]RuleResult
	}{
		{
			name: "predicate with successes, violations, and warnings",
			predicate: &Predicate{
				Results: &FilteredReport{
					Components: []applicationsnapshot.Component{
						{
							SnapshotComponent: appapi.SnapshotComponent{
								Name:           "test-component",
								ContainerImage: "quay.io/test/app:latest",
							},
							Successes: []evaluator.Result{
								{
									Message: "Rule passed successfully",
									Metadata: map[string]interface{}{
										"code": "test.rule1",
									},
								},
							},
							Violations: []evaluator.Result{
								{
									Message: "Rule failed validation",
									Metadata: map[string]interface{}{
										"code":        "test.rule2",
										"title":       "Test Rule 2",
										"description": "This is a test rule",
										"solution":    "Fix the issue",
									},
								},
							},
							Warnings: []evaluator.Result{
								{
									Message: "Rule has warning",
									Metadata: map[string]interface{}{
										"code": "test.rule3",
									},
								},
							},
						},
					},
				},
			},
			expectedResults: map[string][]RuleResult{
				"test.rule1": {
					{
						RuleID:         "test.rule1",
						Status:         "success",
						Message:        "Rule passed successfully",
						ComponentImage: "quay.io/test/app:latest",
					},
				},
				"test.rule2": {
					{
						RuleID:         "test.rule2",
						Status:         "failure",
						Message:        "Rule failed validation",
						Title:          "Test Rule 2",
						Description:    "This is a test rule",
						Solution:       "Fix the issue",
						ComponentImage: "quay.io/test/app:latest",
					},
				},
				"test.rule3": {
					{
						RuleID:         "test.rule3",
						Status:         "warning",
						Message:        "Rule has warning",
						ComponentImage: "quay.io/test/app:latest",
					},
				},
			},
		},
		{
			name: "predicate with nil results",
			predicate: &Predicate{
				Results: nil,
			},
			expectedResults: map[string][]RuleResult{},
		},
		{
			name: "predicate with empty components",
			predicate: &Predicate{
				Results: &FilteredReport{
					Components: []applicationsnapshot.Component{},
				},
			},
			expectedResults: map[string][]RuleResult{},
		},
		{
			name: "predicate with results missing rule ID",
			predicate: &Predicate{
				Results: &FilteredReport{
					Components: []applicationsnapshot.Component{
						{
							SnapshotComponent: appapi.SnapshotComponent{
								Name:           "test-component",
								ContainerImage: "quay.io/test/app:latest",
							},
							Successes: []evaluator.Result{
								{
									Message: "Rule without code",
									Metadata: map[string]interface{}{
										"other": "value",
									},
								},
							},
						},
					},
				},
			},
			expectedResults: map[string][]RuleResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := extractRuleResultsFromPredicate(tt.predicate)
			assert.Equal(t, tt.expectedResults, results)
		})
	}
}

// TestCompareRules tests the compareRules function
func TestCompareRules(t *testing.T) {
	tests := []struct {
		name           string
		vsaRuleResults map[string][]RuleResult
		requiredRules  map[string]bool
		imageDigest    string
		expectedResult *ValidationResult
	}{
		{
			name: "all required rules present and passing",
			vsaRuleResults: map[string][]RuleResult{
				"test.rule1": {
					{RuleID: "test.rule1", Status: "success", Message: "Rule passed"},
				},
				"test.rule2": {
					{RuleID: "test.rule2", Status: "success", Message: "Rule passed"},
				},
			},
			requiredRules: map[string]bool{
				"test.rule1": true,
				"test.rule2": true,
			},
			imageDigest: "sha256:test123",
			expectedResult: &ValidationResult{
				Passed:        true,
				MissingRules:  []MissingRule{},
				FailingRules:  []FailingRule{},
				PassingCount:  2,
				TotalRequired: 2,
				ImageDigest:   "sha256:test123",
				Summary:       "VSA validation PASSED: All 2 required rules are present and passing",
			},
		},
		{
			name: "missing required rules",
			vsaRuleResults: map[string][]RuleResult{
				"test.rule1": {
					{RuleID: "test.rule1", Status: "success", Message: "Rule passed"},
				},
			},
			requiredRules: map[string]bool{
				"test.rule1": true,
				"test.rule2": true,
			},
			imageDigest: "sha256:test123",
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
				ImageDigest:   "sha256:test123",
				Summary:       "VSA validation FAILED: 1 missing rules, 0 failing rules",
			},
		},
		{
			name: "failing rules",
			vsaRuleResults: map[string][]RuleResult{
				"test.rule1": {
					{RuleID: "test.rule1", Status: "success", Message: "Rule passed"},
				},
				"test.rule2": {
					{
						RuleID:         "test.rule2",
						Status:         "failure",
						Message:        "Rule failed",
						Title:          "Test Rule",
						Description:    "This is a test rule",
						Solution:       "Fix the issue",
						ComponentImage: "quay.io/test/app:latest",
					},
				},
			},
			requiredRules: map[string]bool{
				"test.rule1": true,
				"test.rule2": true,
			},
			imageDigest: "sha256:test123",
			expectedResult: &ValidationResult{
				Passed:       false,
				MissingRules: []MissingRule{},
				FailingRules: []FailingRule{
					{
						RuleID:         "test.rule2",
						Package:        "test",
						Message:        "Rule failed",
						Reason:         "Rule failed",
						Title:          "Test Rule",
						Description:    "This is a test rule",
						Solution:       "Fix the issue",
						ComponentImage: "quay.io/test/app:latest",
					},
				},
				PassingCount:  1,
				TotalRequired: 2,
				ImageDigest:   "sha256:test123",
				Summary:       "VSA validation FAILED: 0 missing rules, 1 failing rules",
			},
		},
		{
			name: "warnings are acceptable",
			vsaRuleResults: map[string][]RuleResult{
				"test.rule1": {
					{RuleID: "test.rule1", Status: "success", Message: "Rule passed"},
				},
				"test.rule2": {
					{RuleID: "test.rule2", Status: "warning", Message: "Rule has warning"},
				},
			},
			requiredRules: map[string]bool{
				"test.rule1": true,
				"test.rule2": true,
			},
			imageDigest: "sha256:test123",
			expectedResult: &ValidationResult{
				Passed:        true,
				MissingRules:  []MissingRule{},
				FailingRules:  []FailingRule{},
				PassingCount:  2, // warnings count as passing
				TotalRequired: 2,
				ImageDigest:   "sha256:test123",
				Summary:       "VSA validation PASSED: All 2 required rules are present and passing",
			},
		},
		{
			name: "mixed scenario - missing and failing rules",
			vsaRuleResults: map[string][]RuleResult{
				"test.rule1": {
					{RuleID: "test.rule1", Status: "success", Message: "Rule passed"},
				},
				"test.rule2": {
					{RuleID: "test.rule2", Status: "failure", Message: "Rule failed"},
				},
			},
			requiredRules: map[string]bool{
				"test.rule1": true,
				"test.rule2": true,
				"test.rule3": true,
			},
			imageDigest: "sha256:test123",
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
						Message: "Rule failed",
						Reason:  "Rule failed",
					},
				},
				PassingCount:  1,
				TotalRequired: 3,
				ImageDigest:   "sha256:test123",
				Summary:       "VSA validation FAILED: 1 missing rules, 1 failing rules",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareRules(tt.vsaRuleResults, tt.requiredRules, tt.imageDigest)

			assert.Equal(t, tt.expectedResult.Passed, result.Passed)
			assert.Equal(t, tt.expectedResult.PassingCount, result.PassingCount)
			assert.Equal(t, tt.expectedResult.TotalRequired, result.TotalRequired)
			assert.Equal(t, tt.expectedResult.ImageDigest, result.ImageDigest)
			assert.Equal(t, tt.expectedResult.Summary, result.Summary)

			assert.Len(t, result.MissingRules, len(tt.expectedResult.MissingRules))
			for i, expected := range tt.expectedResult.MissingRules {
				assert.Equal(t, expected.RuleID, result.MissingRules[i].RuleID)
				assert.Equal(t, expected.Package, result.MissingRules[i].Package)
				assert.Equal(t, expected.Reason, result.MissingRules[i].Reason)
			}

			assert.Len(t, result.FailingRules, len(tt.expectedResult.FailingRules))
			for i, expected := range tt.expectedResult.FailingRules {
				assert.Equal(t, expected.RuleID, result.FailingRules[i].RuleID)
				assert.Equal(t, expected.Package, result.FailingRules[i].Package)
				assert.Equal(t, expected.Message, result.FailingRules[i].Message)
				assert.Equal(t, expected.Reason, result.FailingRules[i].Reason)
				assert.Equal(t, expected.Title, result.FailingRules[i].Title)
				assert.Equal(t, expected.Description, result.FailingRules[i].Description)
				assert.Equal(t, expected.Solution, result.FailingRules[i].Solution)
				assert.Equal(t, expected.ComponentImage, result.FailingRules[i].ComponentImage)
			}
		})
	}
}

// TestExtractRuleID tests the extractRuleID function
func TestExtractRuleID(t *testing.T) {
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
			result := extractRuleID(tt.result)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractMetadataString tests the extractMetadataString function
func TestExtractMetadataString(t *testing.T) {
	tests := []struct {
		name     string
		result   evaluator.Result
		key      string
		expected string
	}{
		{
			name: "valid string value",
			result: evaluator.Result{
				Metadata: map[string]interface{}{
					"title": "Test Rule",
				},
			},
			key:      "title",
			expected: "Test Rule",
		},
		{
			name: "no metadata",
			result: evaluator.Result{
				Metadata: nil,
			},
			key:      "title",
			expected: "",
		},
		{
			name: "key not found",
			result: evaluator.Result{
				Metadata: map[string]interface{}{
					"other": "value",
				},
			},
			key:      "title",
			expected: "",
		},
		{
			name: "value is not string",
			result: evaluator.Result{
				Metadata: map[string]interface{}{
					"title": 123,
				},
			},
			key:      "title",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractMetadataString(tt.result, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractPackageFromCode tests the extractPackageFromCode function
func TestExtractPackageFromCode(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "package.rule format",
			code:     "test.rule1",
			expected: "test",
		},
		{
			name:     "no dot separator",
			code:     "testrule",
			expected: "testrule",
		},
		{
			name:     "empty string",
			code:     "",
			expected: "",
		},
		{
			name:     "multiple dots",
			code:     "package.subpackage.rule",
			expected: "package",
		},
		{
			name:     "real rule ID from VSA",
			code:     "slsa_build_scripted_build.image_built_by_trusted_task",
			expected: "slsa_build_scripted_build",
		},
		{
			name:     "tasks rule ID from VSA",
			code:     "tasks.required_untrusted_task_found",
			expected: "tasks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPackageFromCode(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractPackageFromCodeCaching tests the caching behavior of extractPackageFromCode
func TestExtractPackageFromCodeCaching(t *testing.T) {
	// Clear the cache before testing
	packageCacheMutex.Lock()
	packageCache = make(map[string]string)
	packageCacheMutex.Unlock()

	// First call should populate cache
	result1 := extractPackageFromCode("test.rule1")
	assert.Equal(t, "test", result1)

	// Check that cache was populated
	packageCacheMutex.RLock()
	cached, exists := packageCache["test.rule1"]
	packageCacheMutex.RUnlock()
	assert.True(t, exists)
	assert.Equal(t, "test", cached)

	// Second call should use cache
	result2 := extractPackageFromCode("test.rule1")
	assert.Equal(t, "test", result2)
	assert.Equal(t, result1, result2)
}
