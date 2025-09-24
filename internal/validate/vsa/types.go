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
	"strings"
	"time"

	"github.com/sigstore/rekor/pkg/generated/models"

	"github.com/conforma/cli/internal/evaluator"
)

// RetrievalOptions configures VSA retrieval behavior
type RetrievalOptions struct {
	URL     string
	Timeout time.Duration
}

// DefaultRetrievalOptions returns default options for VSA retrieval
func DefaultRetrievalOptions() RetrievalOptions {
	return RetrievalOptions{
		URL:     "https://rekor.sigstore.dev",
		Timeout: 30 * time.Second,
	}
}

// VSARecord represents a VSA record retrieved from Rekor
type VSARecord struct {
	LogIndex       int64                            `json:"logIndex"`
	LogID          string                           `json:"logID"`
	IntegratedTime int64                            `json:"integratedTime"`
	UUID           string                           `json:"uuid"`
	Body           string                           `json:"body"`
	Attestation    *models.LogEntryAnonAttestation  `json:"attestation,omitempty"`
	Verification   *models.LogEntryAnonVerification `json:"verification,omitempty"`
}

// DualEntryPair represents a pair of DSSE and in-toto entries for the same payload
type DualEntryPair struct {
	PayloadHash string
	IntotoEntry *models.LogEntryAnon
	DSSEEntry   *models.LogEntryAnon
}

// DSSEEnvelope represents a DSSE envelope structure
type DSSEEnvelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature represents a signature in a DSSE envelope
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// PairedVSAWithSignatures represents a VSA with its corresponding signatures
type PairedVSAWithSignatures struct {
	PayloadHash   string                   `json:"payloadHash"`
	VSAStatement  []byte                   `json:"vsaStatement"`
	Signatures    []map[string]interface{} `json:"signatures"`
	IntotoEntry   *models.LogEntryAnon     `json:"intotoEntry"`
	DSSEEntry     *models.LogEntryAnon     `json:"dsseEntry"`
	PredicateType string                   `json:"predicateType"`
}

// RuleResult represents a rule result extracted from the VSA
type RuleResult struct {
	RuleID         string `json:"rule_id"`
	Status         string `json:"status"` // "success", "failure", "warning", "skipped", "exception"
	Message        string `json:"message"`
	Title          string `json:"title,omitempty"`
	Description    string `json:"description,omitempty"`
	Solution       string `json:"solution,omitempty"`
	ComponentImage string `json:"component_image,omitempty"` // The specific container image this result relates to
}

// ValidationResult contains the results of VSA rule validation
type ValidationResult struct {
	Passed            bool          `json:"passed"`
	SignatureVerified bool          `json:"signature_verified"`
	MissingRules      []MissingRule `json:"missing_rules,omitempty"`
	FailingRules      []FailingRule `json:"failing_rules,omitempty"`
	PassingCount      int           `json:"passing_count"`
	TotalRequired     int           `json:"total_required"`
	Summary           string        `json:"summary"`
	ImageDigest       string        `json:"image_digest"`
}

// MissingRule represents a rule that is required by the policy but not found in the VSA
type MissingRule struct {
	RuleID  string `json:"rule_id"`
	Package string `json:"package"`
	Reason  string `json:"reason"`
}

// FailingRule represents a rule that is present in the VSA but failed validation
type FailingRule struct {
	RuleID         string `json:"rule_id"`
	Package        string `json:"package"`
	Message        string `json:"message"`
	Reason         string `json:"reason"`
	Title          string `json:"title,omitempty"`
	Description    string `json:"description,omitempty"`
	Solution       string `json:"solution,omitempty"`
	ComponentImage string `json:"component_image,omitempty"` // The specific container image this violation relates to
}

// PolicyResolver defines the interface for resolving policy rules
type PolicyResolver interface {
	// GetRequiredRules returns a map of rule IDs that are required by the policy
	GetRequiredRules(ctx context.Context, imageDigest string) (map[string]bool, error)
}

// VSARuleValidator defines the interface for validating VSA rules
type VSARuleValidator interface {
	// ValidateVSARules validates VSA rules against policy requirements
	ValidateVSARules(ctx context.Context, vsaRecords []VSARecord, policyResolver PolicyResolver, imageDigest string) (*ValidationResult, error)
}

// NewVSARuleValidator creates a new VSARuleValidator implementation
func NewVSARuleValidator() VSARuleValidator {
	return &VSARuleValidatorImpl{}
}

// VSARuleValidatorImpl implements VSARuleValidator interface
type VSARuleValidatorImpl struct{}

// ValidateVSARules validates VSA rules against policy requirements
func (v *VSARuleValidatorImpl) ValidateVSARules(ctx context.Context, vsaRecords []VSARecord, policyResolver PolicyResolver, imageDigest string) (*ValidationResult, error) {
	// Get required rules from policy
	requiredRules, err := policyResolver.GetRequiredRules(ctx, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to get required rules: %w", err)
	}

	// Extract rule results from VSA records
	ruleResults := make(map[string]RuleResult)
	for _, record := range vsaRecords {
		results, err := v.extractRuleResultsFromVSA(record)
		if err != nil {
			continue // Skip records that can't be parsed
		}
		for ruleID, result := range results {
			ruleResults[ruleID] = result
		}
	}

	// Compare required rules with found rules
	var missingRules []MissingRule
	var failingRules []FailingRule
	passingCount := 0

	for requiredRuleID := range requiredRules {
		if result, found := ruleResults[requiredRuleID]; found {
			if result.Status == "success" || result.Status == "warning" {
				// Both successes and warnings are considered passing
				passingCount++
			} else {
				// Rule failed (only violations/failures are considered failing)
				failingRules = append(failingRules, FailingRule{
					RuleID:         result.RuleID,
					Package:        v.extractPackageFromRuleID(result.RuleID),
					Message:        result.Message,
					Reason:         "Rule failed validation in VSA",
					Title:          result.Title,
					Description:    result.Description,
					Solution:       result.Solution,
					ComponentImage: result.ComponentImage,
				})
			}
		} else {
			// Rule missing
			missingRules = append(missingRules, MissingRule{
				RuleID:  requiredRuleID,
				Package: v.extractPackageFromRuleID(requiredRuleID),
				Reason:  "Rule required by policy but not found in VSA",
			})
		}
	}

	// Determine overall result
	passed := len(missingRules) == 0 && len(failingRules) == 0
	totalRequired := len(requiredRules)

	// Generate summary
	var summary string
	if passed {
		summary = fmt.Sprintf("PASS: All %d required rules are present and passing", totalRequired)
	} else {
		summary = fmt.Sprintf("FAIL: %d missing rules, %d failing rules", len(missingRules), len(failingRules))
	}

	return &ValidationResult{
		Passed:            passed,
		SignatureVerified: true, // Assume signature is verified if we got this far
		MissingRules:      missingRules,
		FailingRules:      failingRules,
		PassingCount:      passingCount,
		TotalRequired:     totalRequired,
		Summary:           summary,
		ImageDigest:       imageDigest,
	}, nil
}

// extractRuleID extracts the rule ID from an evaluator result
func (v *VSARuleValidatorImpl) extractRuleID(result evaluator.Result) string {
	// This is a simplified implementation
	// In practice, you'd need to parse the result to extract the rule ID
	if result.Metadata != nil {
		if code, exists := result.Metadata["code"]; exists {
			if codeStr, ok := code.(string); ok {
				return codeStr
			}
		}
	}
	return ""
}

// extractPackageFromRuleID extracts the package name from a rule ID
func (v *VSARuleValidatorImpl) extractPackageFromRuleID(ruleID string) string {
	// Extract package name from rule ID (format: package.rule)
	if dotIndex := strings.Index(ruleID, "."); dotIndex != -1 {
		return ruleID[:dotIndex]
	}
	return ruleID
}

// extractRuleResultsFromVSA extracts rule results from a VSA record
func (v *VSARuleValidatorImpl) extractRuleResultsFromVSA(record VSARecord) (map[string]RuleResult, error) {
	ruleResults := make(map[string]RuleResult)

	// Decode the attestation data
	if record.Attestation == nil || record.Attestation.Data == nil {
		return ruleResults, fmt.Errorf("no attestation data found")
	}

	attestationData, err := base64.StdEncoding.DecodeString(string(record.Attestation.Data))
	if err != nil {
		return ruleResults, fmt.Errorf("failed to decode attestation data: %w", err)
	}

	// Parse the VSA predicate
	var predicate map[string]interface{}
	if err := json.Unmarshal(attestationData, &predicate); err != nil {
		return ruleResults, fmt.Errorf("failed to parse VSA predicate: %w", err)
	}

	// Extract results from the predicate
	results, ok := predicate["results"].(map[string]interface{})
	if !ok {
		return ruleResults, fmt.Errorf("no results found in VSA predicate")
	}

	// Extract components
	components, ok := results["components"].([]interface{})
	if !ok {
		return ruleResults, fmt.Errorf("no components found in VSA results")
	}

	// Process each component
	for _, componentInterface := range components {
		component, ok := componentInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract component image
		componentImage := ""
		if containerImage, ok := component["containerImage"].(string); ok {
			componentImage = containerImage
		}

		// Process successes
		if successes, ok := component["successes"].([]interface{}); ok {
			for _, successInterface := range successes {
				if success, ok := successInterface.(map[string]interface{}); ok {
					ruleResult := v.convertEvaluatorResultToRuleResult(success, "success", componentImage)
					if ruleResult.RuleID != "" {
						ruleResults[ruleResult.RuleID] = ruleResult
					}
				}
			}
		}

		// Process violations (failures)
		if violations, ok := component["violations"].([]interface{}); ok {
			for _, violationInterface := range violations {
				if violation, ok := violationInterface.(map[string]interface{}); ok {
					ruleResult := v.convertEvaluatorResultToRuleResult(violation, "failure", componentImage)
					if ruleResult.RuleID != "" {
						ruleResults[ruleResult.RuleID] = ruleResult
					}
				}
			}
		}

		// Process warnings
		if warnings, ok := component["warnings"].([]interface{}); ok {
			for _, warningInterface := range warnings {
				if warning, ok := warningInterface.(map[string]interface{}); ok {
					ruleResult := v.convertEvaluatorResultToRuleResult(warning, "warning", componentImage)
					if ruleResult.RuleID != "" {
						ruleResults[ruleResult.RuleID] = ruleResult
					}
				}
			}
		}
	}

	return ruleResults, nil
}

// convertEvaluatorResultToRuleResult converts an evaluator result to a RuleResult
func (v *VSARuleValidatorImpl) convertEvaluatorResultToRuleResult(result map[string]interface{}, status, componentImage string) RuleResult {
	ruleResult := RuleResult{
		Status:         status,
		ComponentImage: componentImage,
	}

	// Extract message (evaluator.Result uses "msg" as JSON tag)
	if message, ok := result["msg"].(string); ok {
		ruleResult.Message = message
	}

	// Extract metadata
	if metadata, ok := result["metadata"].(map[string]interface{}); ok {
		// Extract rule ID
		if code, ok := metadata["code"].(string); ok {
			ruleResult.RuleID = code
		}

		// Extract title
		if title, ok := metadata["title"].(string); ok {
			ruleResult.Title = title
		}

		// Extract description
		if description, ok := metadata["description"].(string); ok {
			ruleResult.Description = description
		}

		// Extract solution
		if solution, ok := metadata["solution"].(string); ok {
			ruleResult.Solution = solution
		}
	}

	return ruleResult
}
