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
	"strings"

	"github.com/conforma/cli/internal/policy"
	"github.com/google/go-containerregistry/pkg/name"
)

// VSAFile represents the structure of a VSA file
type VSAFile struct {
	ImageRef  string `json:"imageRef"`
	Timestamp string `json:"timestamp"`
	Verifier  string `json:"verifier"`
	Results   struct {
		Components []struct {
			Violations []struct {
				Msg      string `json:"msg"`
				Metadata struct {
					Code        string   `json:"code"`
					Collections []string `json:"collections"`
					Description string   `json:"description"`
					Solution    string   `json:"solution"`
					Title       string   `json:"title"`
					Term        string   `json:"term,omitempty"`
					DependsOn   []string `json:"depends_on,omitempty"`
				} `json:"metadata"`
			} `json:"violations"`
			Successes []struct {
				Msg      string `json:"msg"`
				Metadata struct {
					Code        string   `json:"code"`
					Collections []string `json:"collections"`
					Description string   `json:"description"`
					Solution    string   `json:"solution"`
					Title       string   `json:"title"`
					Term        string   `json:"term,omitempty"`
					DependsOn   []string `json:"depends_on,omitempty"`
				} `json:"metadata"`
			} `json:"successes"`
		} `json:"components"`
	} `json:"results"`
}

// VSADataRetriever defines the interface for retrieving VSA data
type VSADataRetriever interface {
	// RetrieveVSAData retrieves VSA data
	RetrieveVSAData(ctx context.Context) (*VSAFile, error)
}

// ValidateVSA is the main validation function called by the command
func ValidateVSA(ctx context.Context, imageRef string, policy policy.Policy, retriever VSADataRetriever) (*ValidationResult, error) {
	// Extract digest from image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference: %w", err)
	}

	digest := ref.Identifier()

	// Retrieve VSA data using the provided retriever
	vsaFile, err := retriever.RetrieveVSAData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve VSA data: %w", err)
	}

	// Extract violations and successes from VSA file
	var violations []FailingRule
	var successCount int
	for _, component := range vsaFile.Results.Components {
		// Count violations
		for _, violation := range component.Violations {
			failingRule := FailingRule{
				RuleID:  violation.Metadata.Code,
				Package: extractPackageFromCode(violation.Metadata.Code),
				Message: violation.Msg,
				Reason:  violation.Metadata.Description,
			}
			violations = append(violations, failingRule)
		}

		// Count successes
		successCount += len(component.Successes)
	}

	// Calculate total rules (violations + successes)
	totalRules := len(violations) + successCount

	// Determine if validation passed (no violations)
	passed := len(violations) == 0

	// Create validation result
	result := &ValidationResult{
		Passed:        passed,
		MissingRules:  []MissingRule{}, // TODO: Implement missing rules detection
		FailingRules:  violations,
		PassingCount:  successCount,
		TotalRequired: totalRules,
		Summary:       fmt.Sprintf("VSA validation %s: %d violations, %d successes", getPassFailText(passed), len(violations), successCount),
		ImageDigest:   digest,
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
