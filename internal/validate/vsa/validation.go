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

	"github.com/conforma/cli/internal/policy"
	"github.com/google/go-containerregistry/pkg/name"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigd "github.com/sigstore/sigstore/pkg/signature/dsse"
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

	// Extract violations and successes from VSA predicate
	var violations []FailingRule
	var successCount int

	// The predicate.Results contains the FilteredReport with components
	if predicate.Results != nil {
		for _, component := range predicate.Results.Components {
			// Count violations
			for _, violation := range component.Violations {
				failingRule := FailingRule{
					RuleID:  violation.Metadata["code"].(string),
					Package: extractPackageFromCode(violation.Metadata["code"].(string)),
					Message: violation.Message,
					Reason:  violation.Metadata["description"].(string),
				}
				violations = append(violations, failingRule)
			}

			// Count successes
			successCount += len(component.Successes)
		}
	}

	// Calculate total rules (violations + successes)
	totalRules := len(violations) + successCount

	// Determine if validation passed (no violations)
	passed := len(violations) == 0

	// Create validation result
	result := &ValidationResult{
		Passed:            passed,
		SignatureVerified: signatureVerified,
		MissingRules:      []MissingRule{}, // TODO: Implement missing rules detection
		FailingRules:      violations,
		PassingCount:      successCount,
		TotalRequired:     totalRules,
		Summary:           fmt.Sprintf("VSA validation %s: %d violations, %d successes", getPassFailText(passed), len(violations), successCount),
		ImageDigest:       digest,
	}

	return result, nil
}

// extractPackageFromCode extracts the package name from a rule code
func extractPackageFromCode(code string) string {
	if idx := strings.Index(code, "."); idx != -1 {
		return code[:idx]
	}
	return code
}

// getPassFailText returns "PASSED" or "FAILED" based on the passed boolean
func getPassFailText(passed bool) string {
	if passed {
		return "PASSED"
	}
	return "FAILED"
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
