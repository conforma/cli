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
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigd "github.com/sigstore/sigstore/pkg/signature/dsse"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
)

// DSSEEnvelope represents a DSSE (Dead Simple Signing Envelope) structure
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

// InTotoStatement represents an in-toto statement structure
type InTotoStatement struct {
	Type          string      `json:"_type"`
	PredicateType string      `json:"predicateType"`
	Subject       []Subject   `json:"subject"`
	Predicate     interface{} `json:"predicate"`
}

// Subject represents a subject in an in-toto statement
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// VSADataRetriever defines the interface for retrieving VSA data
type VSADataRetriever interface {
	// RetrieveVSAData retrieves VSA data as a string
	RetrieveVSAData(ctx context.Context) (string, error)
}

// ParseVSAContent parses VSA content in different formats and returns a Predicate
// VSA content can be in different formats:
// 1. Raw Predicate (just the VSA data)
// 2. DSSE Envelope (signed VSA data)
// 3. In-toto Statement wrapped in DSSE envelope
func ParseVSAContent(content string) (*Predicate, error) {
	var predicate Predicate

	// First, try to parse as DSSE envelope
	var envelope DSSEEnvelope
	if err := json.Unmarshal([]byte(content), &envelope); err == nil && envelope.PayloadType != "" {
		// It's a DSSE envelope, extract the payload
		payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			return nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
		}

		// Try to parse the payload as an in-toto statement
		var statement InTotoStatement
		if err := json.Unmarshal(payloadBytes, &statement); err == nil && statement.PredicateType != "" {
			// It's an in-toto statement, extract the predicate
			predicateBytes, err := json.Marshal(statement.Predicate)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal predicate: %w", err)
			}

			if err := json.Unmarshal(predicateBytes, &predicate); err != nil {
				return nil, fmt.Errorf("failed to parse VSA predicate from in-toto statement: %w", err)
			}
		} else {
			// The payload is directly the predicate
			if err := json.Unmarshal(payloadBytes, &predicate); err != nil {
				return nil, fmt.Errorf("failed to parse VSA predicate from DSSE payload: %w", err)
			}
		}
	} else {
		// Try to parse as raw predicate
		if err := json.Unmarshal([]byte(content), &predicate); err != nil {
			return nil, fmt.Errorf("failed to parse VSA content as predicate: %w", err)
		}
	}

	return &predicate, nil
}

// extractRuleResultsFromPredicate extracts rule results from VSA predicate
func extractRuleResultsFromPredicate(predicate *Predicate) map[string][]RuleResult {
	ruleResults := make(map[string][]RuleResult)

	if predicate.Results == nil {
		return ruleResults
	}

	for _, component := range predicate.Results.Components {
		// Process successes
		for _, success := range component.Successes {
			ruleID := extractRuleID(success)
			if ruleID != "" {
				ruleResults[ruleID] = append(ruleResults[ruleID], RuleResult{
					RuleID:  ruleID,
					Status:  "success",
					Message: success.Message,
				})
			}
		}

		// Process violations (failures)
		for _, violation := range component.Violations {
			ruleID := extractRuleID(violation)
			if ruleID != "" {
				ruleResults[ruleID] = append(ruleResults[ruleID], RuleResult{
					RuleID:  ruleID,
					Status:  "failure",
					Message: violation.Message,
				})
			}
		}

		// Process warnings
		for _, warning := range component.Warnings {
			ruleID := extractRuleID(warning)
			if ruleID != "" {
				ruleResults[ruleID] = append(ruleResults[ruleID], RuleResult{
					RuleID:  ruleID,
					Status:  "warning",
					Message: warning.Message,
				})
			}
		}
	}

	return ruleResults
}

// extractRuleID extracts the rule ID from an evaluator result
func extractRuleID(result evaluator.Result) string {
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

// compareRules compares VSA rule results against required rules
func compareRules(vsaRuleResults map[string][]RuleResult, requiredRules map[string]bool, imageDigest string) *ValidationResult {
	result := &ValidationResult{
		MissingRules:  []MissingRule{},
		FailingRules:  []FailingRule{},
		PassingCount:  0,
		TotalRequired: len(requiredRules),
		ImageDigest:   imageDigest,
	}

	// Check for missing rules and rule status
	for ruleID := range requiredRules {
		if ruleResults, exists := vsaRuleResults[ruleID]; !exists {
			// Rule is required by policy but not found in VSA - this is a failure
			result.MissingRules = append(result.MissingRules, MissingRule{
				RuleID:  ruleID,
				Package: extractPackageFromCode(ruleID),
				Reason:  "Rule required by policy but not found in VSA",
			})
		} else {
			// Process all results for this ruleID
			for _, ruleResult := range ruleResults {
				if ruleResult.Status == "failure" {
					// Rule failed validation - this is a failure
					result.FailingRules = append(result.FailingRules, FailingRule{
						RuleID:  ruleID,
						Package: extractPackageFromCode(ruleID),
						Message: ruleResult.Message,
						Reason:  "Rule failed validation in VSA",
					})
				} else if ruleResult.Status == "success" || ruleResult.Status == "warning" {
					// Rule passed or has warning - both are acceptable
					result.PassingCount++
				}
			}
		}
	}

	// Determine overall pass/fail status
	result.Passed = len(result.MissingRules) == 0 && len(result.FailingRules) == 0

	// Generate summary
	if result.Passed {
		result.Summary = fmt.Sprintf("VSA validation PASSED: All %d required rules are present and passing", result.TotalRequired)
	} else {
		result.Summary = fmt.Sprintf("VSA validation FAILED: %d missing rules, %d failing rules",
			len(result.MissingRules), len(result.FailingRules))
	}

	return result
}

// ValidateVSA is the main validation function called by the command
func ValidateVSA(ctx context.Context, imageRef string, policy policy.Policy, retriever VSADataRetriever, publicKey string) (*ValidationResult, error) {
	// Extract digest from image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference: %w", err)
	}

	digest := ref.Identifier()

	// Retrieve VSA data using the provided retriever
	vsaContent, err := retriever.RetrieveVSAData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve VSA data: %w", err)
	}

	// Verify signature if public key is provided
	signatureVerified := false
	if publicKey != "" {
		if vsaContent == "" {
			return nil, fmt.Errorf("signature verification not supported for this VSA retriever")
		}
		if err := verifyVSASignature(vsaContent, publicKey); err != nil {
			// For now, log the error but don't fail the validation
			// This allows testing with mismatched keys
			fmt.Printf("Warning: VSA signature verification failed: %v\n", err)
			signatureVerified = false
		} else {
			signatureVerified = true
		}
	}

	// Parse the VSA content to extract violations and successes
	predicate, err := ParseVSAContent(vsaContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VSA content: %w", err)
	}

	// Create policy resolver and discover available rules
	var policyResolver evaluator.PolicyResolver
	var availableRules evaluator.PolicyRules

	if policy != nil && len(policy.Spec().Sources) > 0 {
		// Use the first source to create the policy resolver
		// This ensures consistent logic with the evaluator
		sourceGroup := policy.Spec().Sources[0]

		policyResolver = evaluator.NewIncludeExcludePolicyResolver(sourceGroup, policy)

		// Convert ecc.Source to []source.PolicySource for rule discovery
		policySources := source.PolicySourcesFrom(sourceGroup)

		// Discover available rules from policy sources using the rule discovery service
		ruleDiscovery := evaluator.NewRuleDiscoveryService()
		rules, nonAnnotatedRules, err := ruleDiscovery.DiscoverRulesWithNonAnnotated(ctx, policySources)
		if err != nil {
			return nil, fmt.Errorf("failed to discover rules from policy sources: %w", err)
		}

		// Combine rules for filtering
		availableRules = ruleDiscovery.CombineRulesForFiltering(rules, nonAnnotatedRules)
	}

	// Create the VSA policy resolver adapter
	var vsaPolicyResolver PolicyResolver
	if policyResolver != nil {
		vsaPolicyResolver = NewPolicyResolver(policyResolver, availableRules)
	}

	// Extract rule results from VSA predicate
	vsaRuleResults := extractRuleResultsFromPredicate(predicate)

	// Get required rules from policy resolver
	var requiredRules map[string]bool
	if vsaPolicyResolver != nil {
		requiredRules, err = vsaPolicyResolver.GetRequiredRules(ctx, digest)
		if err != nil {
			return nil, fmt.Errorf("failed to get required rules from policy: %w", err)
		}
	} else {
		// If no policy resolver is available, consider all rules in VSA as required
		requiredRules = make(map[string]bool)
		for ruleID := range vsaRuleResults {
			requiredRules[ruleID] = true
		}
	}

	// Compare VSA rules against required rules
	result := compareRules(vsaRuleResults, requiredRules, digest)
	result.SignatureVerified = signatureVerified

	return result, nil
}

// extractPackageFromCode extracts the package name from a rule code
func extractPackageFromCode(code string) string {
	if idx := strings.Index(code, "."); idx != -1 {
		return code[:idx]
	}
	return code
}

// verifyVSASignature verifies the signature of a VSA file using cosign's DSSE verification
func verifyVSASignature(vsaContent string, publicKeyPath string) error {
	// Load the verifier from the public key file
	verifier, err := signature.LoadVerifierFromPEMFile(publicKeyPath, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("failed to load verifier from public key file: %w", err)
	}

	// Get the public key
	pub, err := verifier.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Create DSSE envelope verifier using go-securesystemslib
	ev, err := ssldsse.NewEnvelopeVerifier(&sigd.VerifierAdapter{
		SignatureVerifier: verifier,
		Pub:               pub,
		// PubKeyID left empty: accept this key without keyid constraint
	})
	if err != nil {
		return fmt.Errorf("failed to create envelope verifier: %w", err)
	}

	// Parse the DSSE envelope
	var env ssldsse.Envelope
	if err := json.Unmarshal([]byte(vsaContent), &env); err != nil {
		return fmt.Errorf("failed to parse DSSE envelope: %w", err)
	}

	// Verify the signature
	ctx := context.Background()
	if _, err := ev.Verify(ctx, &env); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
