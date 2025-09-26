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

package compare

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/policy/equivalence"
)

var (
	effectiveTime string
	imageDigest   string
	imageRef      string
	imageURL      string
	outputFormat  string
)

var CompareCmd *cobra.Command

func init() {
	CompareCmd = NewCompareCmd()
}

func NewCompareCmd() *cobra.Command {
	compareCmd := &cobra.Command{
		Use:   "compare <policy1> <policy2>",
		Short: "Compare two Conforma Policy specs for equivalence",
		Long: `Compare two Conforma Policy specs to determine if they would
produce the same evaluation result for a given image at a specific time.

The comparison is based on:
- Policy and data source URIs (treated as sets)
- RuleData content (canonicalized JSON comparison)
- Include/exclude matchers (normalized and deduplicated)
- Active volatile configuration (filtered by effective time and image matching)
- Global configuration merging

Examples:
  # Compare two policy files
  ec compare policy1.yaml policy2.yaml

  # Compare with specific effective time
  ec compare policy1.yaml policy2.yaml --effective-time "2024-01-15T12:00:00Z"

  # Compare with image information for volatile config matching
  ec compare policy1.yaml policy2.yaml --image-digest "sha256:abc123" --image-ref "registry.redhat.io/ubi8/ubi:latest"

  # Compare with JSON output
  ec compare policy1.yaml policy2.yaml --output json`,
		Args: cobra.ExactArgs(2),
		RunE: runCompare,
	}

	compareCmd.Flags().StringVar(&effectiveTime, "effective-time", "now", "Effective time for policy evaluation (RFC3339 format, 'now')")
	compareCmd.Flags().StringVar(&imageDigest, "image-digest", "", "Image digest for volatile config matching")
	compareCmd.Flags().StringVar(&imageRef, "image-ref", "", "Image reference for volatile config matching")
	compareCmd.Flags().StringVar(&imageURL, "image-url", "", "Image URL for volatile config matching")
	compareCmd.Flags().StringVar(&outputFormat, "output", "text", "Output format (text, json)")

	return compareCmd
}

func runCompare(cmd *cobra.Command, args []string) error {

	// Parse effective time
	var effectiveTimeValue time.Time
	switch effectiveTime {
	case "now":
		effectiveTimeValue = time.Now().UTC()
	case "attestation":
		// For now, use current time as default for attestation time
		effectiveTimeValue = time.Now().UTC()
	default:
		var err error
		effectiveTimeValue, err = time.Parse(time.RFC3339, effectiveTime)
		if err != nil {
			return fmt.Errorf("invalid effective time format: %w", err)
		}
	}

	// Create image info if provided
	var imageInfo *equivalence.ImageInfo
	if imageDigest != "" || imageRef != "" || imageURL != "" {
		imageInfo = &equivalence.ImageInfo{
			Digest: imageDigest,
			Ref:    imageRef,
			URL:    imageURL,
		}
	}

	// Load first policy
	spec1, err := loadPolicySpec(args[0])
	if err != nil {
		return fmt.Errorf("failed to load first policy: %w", err)
	}

	// Load second policy
	spec2, err := loadPolicySpec(args[1])
	if err != nil {
		return fmt.Errorf("failed to load second policy: %w", err)
	}

	// Create equivalence checker
	checker := equivalence.NewEquivalenceChecker(effectiveTimeValue, imageInfo)

	// Compare policies
	equivalent, err := checker.AreEquivalent(spec1, spec2)
	if err != nil {
		return fmt.Errorf("failed to compare policies: %w", err)
	}

	// Output result
	if outputFormat == "json" {
		result := map[string]interface{}{
			"equivalent":     equivalent,
			"effective_time": effectiveTimeValue.Format(time.RFC3339),
			"policy1":        args[0],
			"policy2":        args[1],
		}
		if imageInfo != nil {
			result["image_info"] = imageInfo
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Text output
	if equivalent {
		fmt.Println("✅ Policies are equivalent")
	} else {
		fmt.Println("❌ Policies are not equivalent")
	}

	fmt.Printf("Effective time: %s\n", effectiveTimeValue.Format(time.RFC3339))
	if imageInfo != nil {
		fmt.Printf("Image digest: %s\n", imageInfo.Digest)
		fmt.Printf("Image ref: %s\n", imageInfo.Ref)
		fmt.Printf("Image URL: %s\n", imageInfo.URL)
	}

	return nil
}

func loadPolicySpec(policyRef string) (ecc.EnterpriseContractPolicySpec, error) {
	content, err := os.ReadFile(policyRef)
	if err != nil {
		return ecc.EnterpriseContractPolicySpec{}, fmt.Errorf("failed to read policy file %q: %w", policyRef, err)
	}

	var ecp ecc.EnterpriseContractPolicy
	if err := yaml.Unmarshal(content, &ecp); err != nil {
		// If parsing as EnterpriseContractPolicy fails, try as EnterpriseContractPolicySpec
		var spec ecc.EnterpriseContractPolicySpec
		if err := yaml.Unmarshal(content, &spec); err != nil {
			return ecc.EnterpriseContractPolicySpec{}, fmt.Errorf("unable to parse EnterpriseContractPolicySpec: %w", err)
		}
		return spec, nil
	}

	// Check if this is actually a valid CRD (has required fields)
	if ecp.APIVersion == "" || ecp.Kind == "" {
		// This is not a valid CRD, try parsing as EnterpriseContractPolicySpec
		var spec ecc.EnterpriseContractPolicySpec
		if err := yaml.Unmarshal(content, &spec); err != nil {
			return ecc.EnterpriseContractPolicySpec{}, fmt.Errorf("unable to parse EnterpriseContractPolicySpec: %w", err)
		}
		return spec, nil
	}

	return ecp.Spec, nil
}
