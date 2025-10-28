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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/output"
)

func TestShouldTriggerFallback(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		result         *ValidationResult
		expectedResult bool
	}{
		{
			name:           "VSA retrieval failed - should trigger fallback",
			err:            errors.New("VSA retrieval failed"),
			result:         nil,
			expectedResult: true,
		},
		{
			name:           "No result - should trigger fallback",
			err:            nil,
			result:         nil,
			expectedResult: true,
		},
		{
			name: "VSA validation failed - should trigger fallback",
			err:  nil,
			result: &ValidationResult{
				Passed:            false,
				Message:           "VSA validation failed",
				SignatureVerified: false,
				PredicateOutcome:  "failed",
			},
			expectedResult: true,
		},
		{
			name: "VSA validation passed but predicate outcome is not 'passed' - should trigger fallback",
			err:  nil,
			result: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed",
				SignatureVerified: true,
				PredicateOutcome:  "failed", // Not "passed"
			},
			expectedResult: true,
		},
		{
			name: "VSA validation passed and predicate outcome is 'passed' - should not trigger fallback",
			err:  nil,
			result: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed",
				SignatureVerified: true,
				PredicateOutcome:  "passed",
			},
			expectedResult: false,
		},
		{
			name: "VSA validation passed and predicate outcome is empty - should not trigger fallback",
			err:  nil,
			result: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed",
				SignatureVerified: true,
				PredicateOutcome:  "", // Empty predicate outcome
			},
			expectedResult: false,
		},
		{
			name: "VSA validation passed but predicate outcome is 'warning' - should trigger fallback",
			err:  nil,
			result: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed",
				SignatureVerified: true,
				PredicateOutcome:  "warning", // Not "passed"
			},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldTriggerFallback(tt.err, tt.result)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestPerformFallbackValidation(t *testing.T) {
	tests := []struct {
		name              string
		result            *ValidationResult
		predicateStatus   string
		expectedVSAResult *ValidationResult
		expectedError     error
	}{
		{
			name: "With VSA result - should use provided result",
			result: &ValidationResult{
				Passed:            false,
				Message:           "VSA validation failed",
				SignatureVerified: false,
				PredicateOutcome:  "failed",
			},
			predicateStatus: "failed",
			expectedVSAResult: &ValidationResult{
				Passed:            false,
				Message:           "VSA validation failed",
				SignatureVerified: false,
				PredicateOutcome:  "failed",
			},
			expectedError: nil,
		},
		{
			name:            "Without VSA result - should create minimal result",
			result:          nil, // No VSA result
			predicateStatus: "failed",
			expectedVSAResult: &ValidationResult{
				Passed:            false,
				Message:           "VSA validation failed",
				SignatureVerified: false,
				PredicateOutcome:  "failed",
			},
			expectedError: nil,
		},
		{
			name: "With successful VSA result - should use provided result",
			result: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed",
				SignatureVerified: true,
				PredicateOutcome:  "passed",
			},
			predicateStatus: "passed",
			expectedVSAResult: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed",
				SignatureVerified: true,
				PredicateOutcome:  "passed",
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fallbackResult := PerformFallbackValidation(
				tt.result,
				tt.predicateStatus,
			)

			// Verify the result structure
			assert.NotNil(t, fallbackResult)
			assert.Equal(t, tt.expectedError, fallbackResult.Error)
			assert.Nil(t, fallbackResult.FallbackOutput) // Should be nil as it's set by CLI layer
			assert.Equal(t, tt.expectedVSAResult, fallbackResult.VSAResult)
		})
	}
}

func TestGetPolicyConfig(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		policyConfig   string
		expectedResult string
		expectedError  error
	}{
		{
			name:           "Empty policy config - should return empty string",
			policyConfig:   "",
			expectedResult: "",
			expectedError:  nil,
		},
		{
			name:           "Valid policy config - should return the config",
			policyConfig:   "test-policy.yaml",
			expectedResult: "test-policy.yaml",
			expectedError:  nil,
		},
		{
			name:           "Policy config with path - should return the path",
			policyConfig:   "/path/to/policy.yaml",
			expectedResult: "/path/to/policy.yaml",
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getPolicyConfig(ctx, tt.policyConfig)
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestFallbackResult_Structure(t *testing.T) {
	// Test that FallbackResult can be created and accessed
	fallbackOutput := &output.Output{}
	vsaResult := &ValidationResult{
		Passed:            true,
		Message:           "Test message",
		SignatureVerified: true,
		PredicateOutcome:  "passed",
	}
	testError := errors.New("test error")

	fallbackResult := &FallbackResult{
		FallbackOutput: fallbackOutput,
		VSAResult:      vsaResult,
		Error:          testError,
	}

	// Verify all fields can be accessed
	assert.Equal(t, fallbackOutput, fallbackResult.FallbackOutput)
	assert.Equal(t, vsaResult, fallbackResult.VSAResult)
	assert.Equal(t, testError, fallbackResult.Error)
}

func TestFallbackConfig_Structure(t *testing.T) {
	// Test that FallbackConfig can be created and accessed
	config := &FallbackConfig{
		FallbackToImageValidation: true,
		FallbackPublicKey:         "test-key",
		PolicyConfig:              "test-policy.yaml",
		EffectiveTime:             "2023-01-01T00:00:00Z",
		Info:                      "test-info",
	}

	// Verify all fields can be accessed
	assert.True(t, config.FallbackToImageValidation)
	assert.Equal(t, "test-key", config.FallbackPublicKey)
	assert.Equal(t, "test-policy.yaml", config.PolicyConfig)
	assert.Equal(t, "2023-01-01T00:00:00Z", config.EffectiveTime)
	assert.Equal(t, "test-info", config.Info)
}

func TestFallbackValidationContext_Structure(t *testing.T) {
	// Test that FallbackValidationContext can be created and accessed
	policyConfig := "test-policy.yaml"
	// Note: FallbackPolicy is an interface, so we can't easily mock it in unit tests
	// In real usage, this would be set by CreateFallbackValidationContext

	context := &FallbackValidationContext{
		PolicyConfiguration: policyConfig,
		FallbackPolicy:      nil, // Will be set by CreateFallbackValidationContext
	}

	// Verify all fields can be accessed
	assert.Equal(t, policyConfig, context.PolicyConfiguration)
	assert.Nil(t, context.FallbackPolicy) // Will be set by CreateFallbackValidationContext
}

func TestWorkerFallbackContext_Structure(t *testing.T) {
	// Test that WorkerFallbackContext can be created and accessed
	evaluators := []evaluator.Evaluator{} // Mock evaluators

	context := &WorkerFallbackContext{
		Evaluators: evaluators,
	}

	// Verify all fields can be accessed
	assert.Equal(t, evaluators, context.Evaluators)
	assert.Len(t, context.Evaluators, 0)
}

// Test edge cases for ShouldTriggerFallback
func TestShouldTriggerFallback_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		result         *ValidationResult
		expectedResult bool
		description    string
	}{
		{
			name:           "Nil error and nil result",
			err:            nil,
			result:         nil,
			expectedResult: true,
			description:    "Should trigger fallback when both error and result are nil",
		},
		{
			name: "Result with empty predicate outcome",
			err:  nil,
			result: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed",
				SignatureVerified: true,
				PredicateOutcome:  "", // Empty predicate outcome
			},
			expectedResult: false,
			description:    "Should not trigger fallback when predicate outcome is empty and validation passed",
		},
		{
			name: "Result with 'passed' predicate outcome",
			err:  nil,
			result: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed",
				SignatureVerified: true,
				PredicateOutcome:  "passed",
			},
			expectedResult: false,
			description:    "Should not trigger fallback when predicate outcome is 'passed'",
		},
		{
			name: "Result with 'warning' predicate outcome",
			err:  nil,
			result: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed with warnings",
				SignatureVerified: true,
				PredicateOutcome:  "warning",
			},
			expectedResult: true,
			description:    "Should trigger fallback when predicate outcome is 'warning'",
		},
		{
			name: "Result with 'error' predicate outcome",
			err:  nil,
			result: &ValidationResult{
				Passed:            true,
				Message:           "VSA validation passed but predicate failed",
				SignatureVerified: true,
				PredicateOutcome:  "error",
			},
			expectedResult: true,
			description:    "Should trigger fallback when predicate outcome is 'error'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldTriggerFallback(tt.err, tt.result)
			assert.Equal(t, tt.expectedResult, result, tt.description)
		})
	}
}

// Test PerformFallbackValidation with different predicate statuses
func TestPerformFallbackValidation_PredicateStatuses(t *testing.T) {

	tests := []struct {
		name            string
		result          *ValidationResult
		predicateStatus string
		expectedOutcome string
	}{
		{
			name: "With VSA result - predicate status should be ignored",
			result: &ValidationResult{
				Passed:            false,
				Message:           "VSA validation failed",
				SignatureVerified: false,
				PredicateOutcome:  "failed",
			},
			predicateStatus: "passed", // Different from result
			expectedOutcome: "failed", // Should use result's predicate outcome
		},
		{
			name:            "Without VSA result - should use predicate status",
			result:          nil,
			predicateStatus: "warning",
			expectedOutcome: "warning",
		},
		{
			name:            "Without VSA result and empty predicate status",
			result:          nil,
			predicateStatus: "",
			expectedOutcome: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fallbackResult := PerformFallbackValidation(
				tt.result,
				tt.predicateStatus,
			)

			require.NotNil(t, fallbackResult)
			require.NotNil(t, fallbackResult.VSAResult)
			assert.Equal(t, tt.expectedOutcome, fallbackResult.VSAResult.PredicateOutcome)
		})
	}
}
