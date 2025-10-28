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
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

// FallbackValidationContext holds precomputed fallback validation resources
type FallbackValidationContext struct {
	PolicyConfiguration string
	FallbackPolicy      policy.Policy
}

// WorkerFallbackContext holds per-worker fallback resources
type WorkerFallbackContext struct {
	Evaluators []evaluator.Evaluator
}

// FallbackResult contains the results of fallback validation
type FallbackResult struct {
	FallbackOutput *output.Output
	VSAResult      *ValidationResult
	Error          error
}

// FallbackConfig holds configuration for fallback validation
type FallbackConfig struct {
	FallbackToImageValidation bool
	FallbackPublicKey         string
	PolicyConfig              string
	EffectiveTime             string
	Info                      interface{}
}

// shouldTriggerFallback determines if fallback should be triggered based on VSA validation results
func ShouldTriggerFallback(err error, result *ValidationResult) bool {
	// VSA retrieval failed - trigger fallback
	if err != nil {
		return true
	}

	// No result means we should fallback
	if result == nil {
		return true
	}

	// VSA validation failed - trigger fallback
	if !result.Passed {
		return true
	}

	// Predicate status is not "passed" - trigger fallback
	if result.PredicateOutcome != "" && result.PredicateOutcome != "passed" {
		return true
	}

	return false
}

// performFallbackValidation performs the common fallback validation logic
// Note: This function now only handles the VSA result logic, image validation is handled in CLI layer
func PerformFallbackValidation(result *ValidationResult, predicateStatus string) *FallbackResult {
	// Use the actual VSA result for fallback case
	// If we have a result, use it; otherwise create a minimal result
	var vsaResult *ValidationResult
	if result != nil {
		vsaResult = result
	} else {
		// Create a minimal result for cases where VSA retrieval completely failed
		vsaResult = &ValidationResult{
			Passed:            false,
			Message:           "VSA validation failed",
			SignatureVerified: false,
			PredicateOutcome:  predicateStatus,
		}
	}

	return &FallbackResult{
		FallbackOutput: nil, // Will be set by CLI layer
		VSAResult:      vsaResult,
		Error:          nil,
	}
}

// createFallbackValidationContext precomputes the fallback validation context once
func CreateFallbackValidationContext(ctx context.Context, config *FallbackConfig) (*FallbackValidationContext, error) {
	log.Debugf("🔄 Precomputing fallback validation context...")

	// Get policy configuration (same as VSA command)
	policyConfiguration, err := getPolicyConfig(ctx, config.PolicyConfig)
	if err != nil {
		return nil, fmt.Errorf("fallback validation: failed to get policy configuration: %w", err)
	}

	log.Debugf("🔄 Fallback context: Policy configuration resolved to: %s", policyConfiguration)

	// Create policy options with fallback public key
	policyOptions := policy.Options{
		IgnoreRekor:   true,
		EffectiveTime: config.EffectiveTime,
		PolicyRef:     policyConfiguration,
		PublicKey:     config.FallbackPublicKey, // Different public key for fallback
	}

	log.Debugf("🔄 Fallback context: Policy options: %+v", policyOptions)

	// Process policy with fallback public key
	fallbackPolicy, _, err := policy.PreProcessPolicy(ctx, policyOptions)
	if err != nil {
		return nil, fmt.Errorf("fallback validation: failed to process policy: %w", err)
	}

	log.Debugf("🔄 Fallback context: Policy processed successfully")
	log.Debugf("🔄 Fallback context: Policy spec sources count: %d", len(fallbackPolicy.Spec().Sources))

	// Note: evaluators will be created per-worker for thread safety
	log.Debugf("🔄 Fallback context: Evaluators will be created per-worker for thread safety")

	return &FallbackValidationContext{
		PolicyConfiguration: policyConfiguration,
		FallbackPolicy:      fallbackPolicy,
	}, nil
}

// createWorkerFallbackContext creates evaluators once per worker thread
// This ensures thread safety while reusing evaluators within the worker
func CreateWorkerFallbackContext(ctx context.Context, fallbackPolicy policy.Policy) (*WorkerFallbackContext, error) {
	log.Debugf("🔄 Creating worker fallback context (evaluators created once per worker)...")
	evaluators := []evaluator.Evaluator{}

	// Create evaluators for each policy source group (same as image command)
	for i, sourceGroup := range fallbackPolicy.Spec().Sources {
		log.Debugf("🔄 Worker: Processing source group %d: '%s'", i, sourceGroup.Name)
		policySources := source.PolicySourcesFrom(sourceGroup)

		log.Debugf("🔄 Worker: Found %d policy sources for group '%s'", len(policySources), sourceGroup.Name)

		var c evaluator.Evaluator
		var err error
		if utils.IsOpaEnabled() {
			log.Debugf("🔄 Worker: Using OPA evaluator")
			c, err = evaluator.NewOPAEvaluator()
		} else {
			log.Debugf("🔄 Worker: Using Conftest evaluator with filter type: include-exclude")
			// Use the unified filtering approach with the specified filter type
			c, err = evaluator.NewConftestEvaluatorWithFilterType(
				ctx, policySources, fallbackPolicy, sourceGroup, "include-exclude") // Default filter type
		}

		if err != nil {
			log.Debugf("🔄 Worker: Failed to initialize evaluator: %v", err)
			return nil, err
		}

		log.Debugf("🔄 Worker: Successfully created evaluator for source group '%s'", sourceGroup.Name)
		evaluators = append(evaluators, c)
	}

	log.Debugf("🔄 Worker: Created %d total evaluators (reused for all components in this worker)", len(evaluators))
	return &WorkerFallbackContext{
		Evaluators: evaluators,
	}, nil
}

// getPolicyConfig resolves policy configuration (copied from validate package to avoid circular dependency)
func getPolicyConfig(ctx context.Context, policyConfig string) (string, error) {
	if policyConfig == "" {
		return "", nil
	}
	return policyConfig, nil
}
