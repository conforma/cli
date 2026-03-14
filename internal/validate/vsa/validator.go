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
	"fmt"
	"math"
	"strings"
	"time"

	ecapi "github.com/conforma/crds/api/v1alpha1"

	"github.com/conforma/cli/internal/policy/equivalence"
)

// VSAValidationConfig represents the configuration needed for VSA validation
type VSAValidationConfig struct {
	Retriever                   VSARetriever
	VSAExpiration               time.Duration
	IgnoreSignatureVerification bool
	PublicKeyPath               string
	PolicySpec                  ecapi.EnterpriseContractPolicySpec
	EffectiveTime               string
}

// ValidateVSAAndComparePolicy performs optimized VSA validation with single retrieval
func ValidateVSAAndComparePolicy(ctx context.Context, identifier string, data *VSAValidationConfig) (*ValidationResult, error) {
	if data == nil {
		return nil, fmt.Errorf("validation data cannot be nil")
	}

	if data.Retriever == nil {
		return nil, fmt.Errorf("VSA retriever cannot be nil")
	}

	// Use VSA library's VSAChecker for efficient VSA validation
	checker := NewVSAChecker(data.Retriever)

	// SINGLE VSA RETRIEVAL with optional signature verification
	result, err := checker.CheckExistingVSAWithVerification(
		ctx,
		identifier,
		data.VSAExpiration,
		!data.IgnoreSignatureVerification, // Whether to verify signature (inverse of ignore flag)
		data.PublicKeyPath,                // Public key path (if signature verification requested)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing VSA: %w", err)
	}

	if !result.Found {
		return &ValidationResult{
			Passed:            false,
			Message:           "No VSA found for the specified identifier",
			SignatureVerified: result.SignatureVerified,
			PredicateOutcome:  "",
			ReasonCode:        "no_vsa",
		}, nil
	}

	if result.Expired {
		days := int(math.Ceil(time.Since(result.Timestamp).Hours() / 24))
		predicateStatus := ""
		if result.VSA != nil {
			predicateStatus = result.VSA.Status
		}
		return &ValidationResult{
			Passed:            false,
			Message:           fmt.Sprintf("VSA expired %d day(s) ago", days),
			SignatureVerified: result.SignatureVerified,
			PredicateOutcome:  predicateStatus,
			ReasonCode:        "expired",
		}, nil
	}

	// Extract predicate status FIRST to avoid unnecessary policy comparison
	predicateStatus := ""
	if result.VSA != nil {
		predicateStatus = result.VSA.Status
	}

	// If predicate status is not "passed", return early to avoid expensive policy comparison
	// This is the key optimization: check predicate status before doing policy work
	if predicateStatus != "" && predicateStatus != predicateStatusPassed {
		return &ValidationResult{
			Passed:            false,
			Message:           fmt.Sprintf("VSA predicate status is '%s' (not 'passed')", predicateStatus),
			SignatureVerified: result.SignatureVerified,
			PredicateOutcome:  predicateStatus,
			ReasonCode:        "predicate_failed",
		}, nil
	}

	// If signature verification was requested and failed, the error would have been returned above
	// If signature verification was requested and succeeded, we continue with policy comparison

	// Extract policy from VSA predicate (only if predicate status is "passed")
	vsaPolicy, err := ExtractPolicyFromVSA(result.VSA)
	if err != nil {
		return &ValidationResult{
			Passed:            false,
			Message:           err.Error(),
			SignatureVerified: result.SignatureVerified,
			PredicateOutcome:  predicateStatus,
		}, nil
	}

	// Compare policies if supplied policy is provided (only if predicate status is "passed")
	if len(data.PolicySpec.Sources) > 0 {
		// Parse effective time
		effectiveTime, err := ParseEffectiveTime(data.EffectiveTime)
		if err != nil {
			return &ValidationResult{
				Passed:            false,
				Message:           fmt.Sprintf("invalid effective time: %v", err),
				SignatureVerified: result.SignatureVerified,
				PredicateOutcome:  predicateStatus,
			}, nil
		}

		// Create image info for volatile config matching
		imageInfo := &equivalence.ImageInfo{
			Digest: ExtractImageDigest(identifier),
			Ref:    identifier,
		}

		// Compare policies with detailed error reporting
		equivalent, differences, err := CompareVSAPolicyWithDetails(vsaPolicy, data.PolicySpec, effectiveTime, imageInfo)
		if err != nil {
			return &ValidationResult{
				Passed:            false,
				Message:           fmt.Sprintf("policy comparison failed: %v", err),
				SignatureVerified: result.SignatureVerified,
				PredicateOutcome:  predicateStatus,
			}, nil
		}

		if !equivalent {
			// Count policy differences for structured field
			added, removed, changed := 0, 0, 0
			for _, diff := range differences {
				switch diff.Kind {
				case equivalence.DiffAdded:
					added++
				case equivalence.DiffRemoved:
					removed++
				case equivalence.DiffChanged:
					changed++
				}
			}

			return &ValidationResult{
				Passed:            false,
				Message:           FormatPolicyDifferences(differences),
				SignatureVerified: result.SignatureVerified,
				PredicateOutcome:  predicateStatus,
				ReasonCode:        "policy_mismatch",
				PolicyDiff: &PolicyDiff{
					Added:   added,
					Removed: removed,
					Changed: changed,
				},
			}, nil
		}
	}

	// Return success result
	return &ValidationResult{
		Passed:            true,
		Message:           "Policy matches",
		SignatureVerified: result.SignatureVerified,
		PredicateOutcome:  predicateStatus,
	}, nil
}

// ExtractPolicyFromVSA extracts the policy from VSA predicate
func ExtractPolicyFromVSA(predicate *Predicate) (ecapi.EnterpriseContractPolicySpec, error) {
	// Check if predicate has a Policy field
	if predicate == nil {
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("VSA predicate is nil")
	}

	// Check if policy has any sources
	if len(predicate.Policy.Sources) == 0 {
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("VSA predicate does not contain policy sources")
	}

	return predicate.Policy, nil
}

// CompareVSAPolicyWithDetails compares VSA policy with supplied policy and returns detailed differences
func CompareVSAPolicyWithDetails(vsaPolicy ecapi.EnterpriseContractPolicySpec, suppliedPolicy ecapi.EnterpriseContractPolicySpec, effectiveTime time.Time, imageInfo *equivalence.ImageInfo) (bool, []equivalence.PolicyDifference, error) {
	checker := equivalence.NewEquivalenceChecker(effectiveTime, imageInfo)

	equivalent, differences, err := checker.AreEquivalentWithDifferences(vsaPolicy, suppliedPolicy)
	if err != nil {
		return false, nil, fmt.Errorf("policy comparison failed: %w", err)
	}

	return equivalent, differences, nil
}

// FormatPolicyDifferences formats policy differences using unified diff format
func FormatPolicyDifferences(differences []equivalence.PolicyDifference) string {
	if len(differences) == 0 {
		return "VSA policy does not match supplied policy (no specific differences identified)"
	}

	// Count different types of changes for the header
	added, removed, changed := 0, 0, 0
	for _, diff := range differences {
		switch diff.Kind {
		case equivalence.DiffAdded:
			added++
		case equivalence.DiffRemoved:
			removed++
		case equivalence.DiffChanged:
			changed++
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("❌ Policy mismatch detected — %d added, %d removed, %d changed; %d differences\n",
		added, removed, changed, len(differences)))

	// Generate unified diff output
	checker := &equivalence.EquivalenceChecker{}
	unifiedDiff := checker.GenerateUnifiedDiffOutputWithLabels(differences, "VSA Policy", "Release Policy")
	sb.WriteString(unifiedDiff)

	return sb.String()
}

// ParseEffectiveTime parses the effective time string
func ParseEffectiveTime(effectiveTime string) (time.Time, error) {
	switch effectiveTime {
	case "now":
		return time.Now().UTC(), nil
	default:
		return time.Parse(time.RFC3339, effectiveTime)
	}
}

// ExtractImageDigest extracts image digest from identifier
func ExtractImageDigest(identifier string) string {
	// For now, return the identifier as-is
	// TODO: Implement proper digest extraction logic
	return identifier
}
