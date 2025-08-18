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
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/evaluator"
)

// Error definitions
var (
	ErrNoAttestationData = errors.New("no attestation data in VSA record")
)

// VSARuleValidator defines the interface for validating VSA records against policy expectations
type VSARuleValidator interface {
	// ValidateVSARules validates VSA records against policy expectations
	// It compares the rules present in the VSA against the rules required by the policy
	ValidateVSARules(ctx context.Context, vsaRecords []VSARecord, policyResolver PolicyResolver, imageDigest string) (*ValidationResult, error)
}

// PolicyResolver defines the interface for resolving policy rules
// This is a simplified interface that can be implemented by different policy resolvers
type PolicyResolver interface {
	// GetRequiredRules returns a map of rule IDs that are required by the policy
	// The map key is the rule ID (e.g., "package.rule") and the value indicates if it's required
	GetRequiredRules(ctx context.Context, imageDigest string) (map[string]bool, error)
}

// NewEvaluatorPolicyResolver creates an adapter that wraps the evaluator.PolicyResolver
func NewPolicyResolver(resolver evaluator.PolicyResolver, availableRules evaluator.PolicyRules) PolicyResolver {
	return &policyResolverWrapper{
		resolver:       resolver,
		availableRules: availableRules,
	}
}

type policyResolverWrapper struct {
	resolver       evaluator.PolicyResolver
	availableRules evaluator.PolicyRules
}

func (p *policyResolverWrapper) GetRequiredRules(ctx context.Context, imageDigest string) (map[string]bool, error) {
	result := p.resolver.ResolvePolicy(p.availableRules, imageDigest)
	return result.IncludedRules, nil
}

// ValidationResult contains the results of VSA rule validation
type ValidationResult struct {
	Passed        bool          `json:"passed"`
	MissingRules  []MissingRule `json:"missing_rules,omitempty"`
	FailingRules  []FailingRule `json:"failing_rules,omitempty"`
	PassingCount  int           `json:"passing_count"`
	TotalRequired int           `json:"total_required"`
	Summary       string        `json:"summary"`
	ImageDigest   string        `json:"image_digest"`
}

// MissingRule represents a rule that is required by the policy but not found in the VSA
type MissingRule struct {
	RuleID  string `json:"rule_id"`
	Package string `json:"package"`
	Reason  string `json:"reason"`
}

// FailingRule represents a rule that is present in the VSA but failed validation
type FailingRule struct {
	RuleID  string `json:"rule_id"`
	Package string `json:"package"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
}

// RuleResult represents a rule result extracted from the VSA
type RuleResult struct {
	RuleID  string `json:"rule_id"`
	Status  string `json:"status"` // "success", "failure", "warning", "skipped", "exception"
	Message string `json:"message"`
}

// VSARuleValidatorImpl implements VSARuleValidator with comprehensive validation logic
type VSARuleValidatorImpl struct{}

// NewVSARuleValidator creates a new VSA rule validator
func NewVSARuleValidator() VSARuleValidator {
	return &VSARuleValidatorImpl{}
}

// ValidateVSARules validates VSA records against policy expectations
func (v *VSARuleValidatorImpl) ValidateVSARules(ctx context.Context, vsaRecords []VSARecord, policyResolver PolicyResolver, imageDigest string) (*ValidationResult, error) {
	log.Debugf("Validating VSA rules for image digest: %s", imageDigest)

	// 1. Extract rule results from VSA records
	vsaRuleResults, err := v.extractRuleResults(vsaRecords)
	if err != nil {
		return nil, fmt.Errorf("extract rule results from VSA: %w", err)
	}

	log.Debugf("Extracted %d rule results from VSA", len(vsaRuleResults))

	// 2. Get required rules from policy resolver
	requiredRules, err := policyResolver.GetRequiredRules(ctx, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("get required rules from policy: %w", err)
	}

	log.Debugf("Policy requires %d rules", len(requiredRules))

	// 3. Compare VSA rules against required rules
	result := v.compareRules(vsaRuleResults, requiredRules, imageDigest)

	return result, nil
}

// extractRuleResults extracts rule results from VSA records
func (v *VSARuleValidatorImpl) extractRuleResults(vsaRecords []VSARecord) (map[string]RuleResult, error) {
	ruleResults := make(map[string]RuleResult)

	for _, record := range vsaRecords {
		// Parse VSA predicate to extract rule results
		predicate, err := v.parseVSAPredicate(record)
		if err != nil {
			log.Debugf("parse VSA predicate: %v", err)
			continue // Skip invalid records
		}

		// Extract rule results from predicate components
		if predicate.Results != nil {
			for _, component := range predicate.Results.Components {
				// Process successes
				for _, success := range component.Successes {
					ruleID := v.extractRuleID(success)
					if ruleID != "" {
						ruleResults[ruleID] = RuleResult{
							RuleID:  ruleID,
							Status:  "success",
							Message: success.Message,
						}
					}
				}

				// Process violations (failures)
				for _, violation := range component.Violations {
					ruleID := v.extractRuleID(violation)
					if ruleID != "" {
						ruleResults[ruleID] = RuleResult{
							RuleID:  ruleID,
							Status:  "failure",
							Message: violation.Message,
						}
					}
				}

				// Process warnings
				for _, warning := range component.Warnings {
					ruleID := v.extractRuleID(warning)
					if ruleID != "" {
						ruleResults[ruleID] = RuleResult{
							RuleID:  ruleID,
							Status:  "warning",
							Message: warning.Message,
						}
					}
				}

			}
		}
	}

	return ruleResults, nil
}

// parseVSAPredicate parses a VSA record to extract the predicate
func (v *VSARuleValidatorImpl) parseVSAPredicate(record VSARecord) (*Predicate, error) {
	if record.Attestation == nil || record.Attestation.Data == nil {
		return nil, ErrNoAttestationData
	}

	// Decode the attestation data
	attestationData, err := base64.StdEncoding.DecodeString(string(record.Attestation.Data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation data: %w", err)
	}

	// Parse the predicate JSON
	var predicate Predicate
	if err := json.Unmarshal(attestationData, &predicate); err != nil {
		return nil, fmt.Errorf("failed to unmarshal predicate: %w", err)
	}

	return &predicate, nil
}

// extractRuleID extracts the rule ID from an evaluator result
func (v *VSARuleValidatorImpl) extractRuleID(result evaluator.Result) string {
	if result.Metadata == nil {
		return ""
	}

	// Look for the "code" field in metadata which contains the rule ID
	if code, exists := result.Metadata["code"]; exists {
		if codeStr, ok := code.(string); ok {
			return codeStr
		}
	}

	return ""
}

// extractPackageFromRuleID extracts the package name from a rule ID
func (v *VSARuleValidatorImpl) extractPackageFromRuleID(ruleID string) string {
	if idx := strings.Index(ruleID, "."); idx != -1 {
		return ruleID[:idx]
	}
	return ruleID
}

// compareRules compares VSA rule results against required rules
func (v *VSARuleValidatorImpl) compareRules(vsaRuleResults map[string]RuleResult, requiredRules map[string]bool, imageDigest string) *ValidationResult {
	result := &ValidationResult{
		MissingRules:  []MissingRule{},
		FailingRules:  []FailingRule{},
		PassingCount:  0,
		TotalRequired: len(requiredRules),
		ImageDigest:   imageDigest,
	}

	// Check for missing rules
	for ruleID := range requiredRules {
		if ruleResult, exists := vsaRuleResults[ruleID]; !exists {
			result.MissingRules = append(result.MissingRules, MissingRule{
				RuleID:  ruleID,
				Package: v.extractPackageFromRuleID(ruleID),
				Reason:  "Rule required by policy but not found in VSA",
			})
		} else if ruleResult.Status == "failure" || ruleResult.Status == "warning" {
			result.FailingRules = append(result.FailingRules, FailingRule{
				RuleID:  ruleID,
				Package: v.extractPackageFromRuleID(ruleID),
				Message: ruleResult.Message,
				Reason:  "Rule failed validation in VSA",
			})
		} else if ruleResult.Status == "success" {
			result.PassingCount++
		}
	}

	// Determine overall pass/fail status
	result.Passed = len(result.MissingRules) == 0 && len(result.FailingRules) == 0

	// Generate summary
	if result.Passed {
		result.Summary = fmt.Sprintf("PASS: All %d required rules are present and passing", result.TotalRequired)
	} else {
		result.Summary = fmt.Sprintf("FAIL: %d missing rules, %d failing rules",
			len(result.MissingRules), len(result.FailingRules))
	}

	return result
}
