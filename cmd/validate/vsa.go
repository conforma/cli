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

package validate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	ecapi "github.com/conforma/crds/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/applicationsnapshot"
	validate_utils "github.com/conforma/cli/internal/validate"
	"github.com/conforma/cli/internal/validate/vsa"
)

// validateVSAData holds the command data
type validateVSAData struct {
	// Input options
	vsaIdentifier string // Single VSA identifier (image digest, file path)
	images        string // Application snapshot file
	policyConfig  string // Policy configuration

	// VSA retrieval options
	vsaRetrieval []string // VSA retrieval backends (rekor@, file@)

	// Policy comparison options
	effectiveTime string // Effective time for comparison
	// Note: imageDigest, imageRef, imageURL will be extracted from vsaIdentifier or images

	// VSA options
	vsaExpirationStr string        // VSA expiration threshold as string
	vsaExpiration    time.Duration // VSA expiration threshold as duration

	// Signature verification options
	ignoreSignatureVerification bool   // Whether to ignore signature verification (default: false, so signature is verified by default)
	publicKeyPath               string // Path to public key for verification

	// Output options
	output     []string // Output formats
	outputFile string   // Output file
	strict     bool     // Strict mode (fail on any error)

	// Parallel processing options
	workers int // Number of worker threads for parallel processing

	// Output formatting options
	noColor    bool // Disable color output
	forceColor bool // Force color output

	// Internal state
	policySpec ecapi.EnterpriseContractPolicySpec
	retriever  vsa.VSARetriever
}

func NewValidateVSACmd() *cobra.Command {
	data := &validateVSAData{
		strict:           true,
		effectiveTime:    "now",
		vsaExpirationStr: "168h",          // 7 days default
		vsaExpiration:    168 * time.Hour, // 7 days default
		workers:          5,               // 5 workers default
	}

	cmd := &cobra.Command{
		Use:   "vsa <vsa-identifier>",
		Short: "Validate VSA (Verification Summary Attestation)",
		Long: hd.Doc(`
			Validate VSA by comparing the embedded policy against a supplied policy configuration.
			
			By default, VSA signature verification is enabled and requires a public key.
			Use --ignore-signature-verification to disable signature verification.
			
			Supports validation of:
			- Single VSA by identifier (image digest, file path)
			- Multiple VSAs from application snapshot
			
			VSA retrieval supports:
			- Rekor transparency log
			- Local filesystem storage
			- Multiple backends with fallback
		`),
		// Check positional arguments
		// Example: ec validate vsa image1@sha256:abc123 --policy policy.yaml --public-key key.pub
		Args: func(cmd *cobra.Command, args []string) error {
			// Custom argument validation using Cobra's Args field
			if len(args) > 1 {
				return fmt.Errorf("too many arguments provided")
			}

			// Validate VSA identifier format if provided
			if len(args) == 1 {
				identifier := args[0]
				if !vsa.IsValidVSAIdentifier(identifier) {
					return fmt.Errorf("invalid VSA identifier format: %s", identifier)
				}
			}

			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateVSAInput(data, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidateVSA(cmd, data, args)
		},
	}

	// Add flags
	addVSAFlags(cmd, data)
	return cmd
}

// addVSAFlags adds all the command flags with enhanced validation
func addVSAFlags(cmd *cobra.Command, data *validateVSAData) {
	// Input options
	cmd.Flags().StringVarP(&data.vsaIdentifier, "vsa", "v", "", "VSA identifier (image digest, file path)")
	cmd.Flags().StringVar(&data.images, "images", "", "Application snapshot file")
	cmd.Flags().StringVarP(&data.policyConfig, "policy", "p", "", "Policy configuration")

	// Mark required flags will be done after all flags are defined

	// Add flag validation annotations for better error messages
	if err := cmd.Flags().SetAnnotation("vsa", "validation", []string{"identifier"}); err != nil {
		log.Warnf("Failed to set annotation for vsa flag: %v", err)
	}
	if err := cmd.Flags().SetAnnotation("images", "validation", []string{"file"}); err != nil {
		log.Warnf("Failed to set annotation for images flag: %v", err)
	}
	if err := cmd.Flags().SetAnnotation("policy", "validation", []string{"required"}); err != nil {
		log.Warnf("Failed to set annotation for policy flag: %v", err)
	}

	// VSA retrieval options
	cmd.Flags().StringSliceVar(&data.vsaRetrieval, "vsa-retrieval", []string{}, "VSA retrieval backends (rekor@, file@)")

	// Add validation for VSA retrieval backends
	if err := cmd.Flags().SetAnnotation("vsa-retrieval", "validation", []string{"backend"}); err != nil {
		log.Warnf("Failed to set annotation for vsa-retrieval flag: %v", err)
	}

	// Policy comparison options
	cmd.Flags().StringVar(&data.effectiveTime, "effective-time", "now", "Effective time for comparison")

	// VSA options with custom validation
	cmd.Flags().StringVar(&data.vsaExpirationStr, "vsa-expiration", "168h", "VSA expiration threshold (e.g., 24h, 7d, 1w, 1m)")
	if err := cmd.Flags().SetAnnotation("vsa-expiration", "validation", []string{"duration"}); err != nil {
		log.Warnf("Failed to set annotation for vsa-expiration flag: %v", err)
	}

	// Signature verification options
	cmd.Flags().BoolVar(&data.ignoreSignatureVerification, "ignore-signature-verification", false, "Ignore VSA signature verification (signature verification is enabled by default)")
	cmd.Flags().StringVar(&data.publicKeyPath, "public-key", "", "Path to public key for signature verification (required by default)")
	if err := cmd.Flags().SetAnnotation("public-key", "validation", []string{"file"}); err != nil {
		log.Warnf("Failed to set annotation for public-key flag: %v", err)
	}

	// Output options
	cmd.Flags().StringSliceVar(&data.output, "output", []string{}, "Output formats")
	cmd.Flags().StringVarP(&data.outputFile, "output-file", "o", "", "Output file")
	cmd.Flags().BoolVar(&data.strict, "strict", true, "Exit with non-zero code if validation fails")

	// Parallel processing options
	cmd.Flags().IntVar(&data.workers, "workers", 5, "Number of worker threads for parallel processing")

	// Output formatting options
	cmd.Flags().BoolVar(&data.noColor, "no-color", false, "Disable color when using text output even when the current terminal supports it")
	cmd.Flags().BoolVar(&data.forceColor, "color", false, "Enable color when using text output even when the current terminal does not support it")

	// Mark required flags after all flags are defined
	if err := cmd.MarkFlagRequired("policy"); err != nil {
		log.Warnf("Failed to mark policy flag as required: %v", err)
	}
	// Note: public-key is conditionally required based on --ignore-signature-verification flag
	// This is handled in validateVSAInput function
}

// runValidateVSA is the main command execution function
func runValidateVSA(cmd *cobra.Command, data *validateVSAData, args []string) error {
	ctx := cmd.Context()

	// Parse VSA expiration
	if err := parseVSAExpiration(data); err != nil {
		return err
	}

	// Load policy configuration
	if err := loadPolicyConfig(ctx, data); err != nil {
		return err
	}

	// Create VSA retriever
	retriever, err := vsa.CreateVSARetriever(data.vsaRetrieval, data.vsaIdentifier, data.images)
	if err != nil {
		return err
	}
	data.retriever = retriever

	// Process validation
	// Images is a snapshot
	if data.images != "" {
		return validateSnapshotVSAs(ctx, data)
	} else {
		// VSA identifier is a single VSA, usually from a file system
		return validateSingleVSA(ctx, data, args)
	}
}

// validateVSAInput validates the command input using Cobra's validation patterns
func validateVSAInput(data *validateVSAData, args []string) error {
	// Set VSA identifier from args if provided
	if len(args) > 0 {
		data.vsaIdentifier = args[0]
	}

	// Check if we have either VSA identifier or images (mutual exclusivity validation)
	if data.vsaIdentifier == "" && data.images == "" {
		return fmt.Errorf("either --vsa, --images, or VSA identifier must be provided")
	}

	// Check mutual exclusivity: can't have both --vsa and --images
	if data.vsaIdentifier != "" && data.images != "" {
		return fmt.Errorf("--vsa and --images are mutually exclusive")
	}

	// Validate VSA expiration format early
	if err := parseVSAExpiration(data); err != nil {
		return fmt.Errorf("invalid --vsa-expiration: %w", err)
	}

	// Validate signature verification flags
	// By default, signature verification is enabled, so public-key is required unless --ignore-signature-verification is set
	if !data.ignoreSignatureVerification && data.publicKeyPath == "" {
		return fmt.Errorf("--public-key is required for signature verification (use --ignore-signature-verification to disable signature verification)")
	}

	return nil
}

// parseVSAExpiration parses the VSA expiration string into a duration
func parseVSAExpiration(data *validateVSAData) error {
	expiration, err := vsa.ParseVSAExpirationDuration(data.vsaExpirationStr)
	if err != nil {
		return fmt.Errorf("invalid VSA expiration: %w", err)
	}
	data.vsaExpiration = expiration
	return nil
}

// loadPolicyConfig loads the policy configuration from multiple sources
func loadPolicyConfig(ctx context.Context, data *validateVSAData) error {
	// Use GetPolicyConfig to handle multiple sources (file, git, http, inline JSON)
	policyConfig, err := validate_utils.GetPolicyConfig(ctx, data.policyConfig)
	if err != nil {
		return fmt.Errorf("failed to load policy configuration: %w", err)
	}

	// Parse the policy configuration string into EnterpriseContractPolicySpec
	policySpec, err := vsa.ParsePolicySpec(policyConfig)
	if err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	// Store the policy spec for comparison
	data.policySpec = policySpec

	return nil
}

// validateSingleVSA validates a single VSA
func validateSingleVSA(ctx context.Context, data *validateVSAData, args []string) error {
	identifier := data.vsaIdentifier
	if len(args) > 0 {
		identifier = args[0]
	}

	fmt.Printf("Validating VSA: %s\n", identifier)
	fmt.Printf("Policy: %s\n", data.policyConfig)

	// Validate VSA with policy comparison
	validationData := &vsa.ValidationData{
		Retriever:                   data.retriever,
		VSAExpiration:               data.vsaExpiration,
		IgnoreSignatureVerification: data.ignoreSignatureVerification,
		PublicKeyPath:               data.publicKeyPath,
		PolicySpec:                  data.policySpec,
		EffectiveTime:               data.effectiveTime,
	}
	result, err := vsa.ValidateVSAWithPolicyComparison(ctx, identifier, validationData)
	if err != nil {
		return fmt.Errorf("VSA validation failed: %w", err)
	}

	if result.Passed {
		fmt.Println("✅ VSA validation passed")
		if result.Message != "" {
			fmt.Printf("   %s\n", result.Message)
		}
		if result.SignatureVerified {
			fmt.Println("   🔐 Signature verified")
		} else if !data.ignoreSignatureVerification {
			fmt.Println("   ⚠️  Signature verification requested but not performed")
		}
	} else {
		fmt.Println("❌ VSA validation failed")
		if result.Message != "" {
			fmt.Printf("   %s\n", result.Message)
		}
		if data.strict {
			return fmt.Errorf("VSA validation failed: %s", result.Message)
		}
	}

	return nil
}

// worker processes components from the jobs channel and sends results to the results channel
func worker(jobs <-chan app.SnapshotComponent, results chan<- vsa.ComponentResult, ctx context.Context, data *validateVSAData) {
	for component := range jobs {
		result := processSnapshotComponent(ctx, component, data)
		results <- result
	}
}

// validateSnapshotVSAs validates VSAs from application snapshot using parallel processing
func validateSnapshotVSAs(ctx context.Context, data *validateVSAData) error {
	fmt.Printf("Validating VSAs from snapshot: %s\n", data.images)
	fmt.Printf("Policy: %s\n", data.policyConfig)

	// Parse the snapshot using applicationsnapshot.DetermineInputSpec
	snapshot, _, err := applicationsnapshot.DetermineInputSpec(ctx, applicationsnapshot.Input{
		Images: data.images,
	})
	if err != nil {
		return fmt.Errorf("failed to parse snapshot: %w", err)
	}

	if len(snapshot.Components) == 0 {
		return fmt.Errorf("snapshot contains no components")
	}

	numComponents := len(snapshot.Components)
	numWorkers := data.workers

	fmt.Printf("Found %d components in snapshot\n", numComponents)
	fmt.Printf("=== Processing Components in Parallel (%d workers) ===\n", numWorkers)

	// Create channels for parallel processing
	jobs := make(chan app.SnapshotComponent, numComponents)
	results := make(chan vsa.ComponentResult, numComponents)

	// Start workers
	for i := 0; i < numWorkers; i++ {
		go worker(jobs, results, ctx, data)
	}

	// Send jobs to workers
	for _, component := range snapshot.Components {
		jobs <- component
	}
	close(jobs)

	// Collect results
	var allResults []vsa.ComponentResult
	var allErrors error
	var successCount, failureCount int

	for i := 0; i < numComponents; i++ {
		result := <-results
		allResults = append(allResults, result)

		if result.Error != nil {
			failureCount++
			allErrors = errors.Join(allErrors, result.Error)
		} else if result.Result != nil && result.Result.Passed {
			successCount++
		} else if result.Result != nil && !result.Result.Passed {
			failureCount++
		}
	}
	close(results)

	// Sort results by component name for consistent display
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].ComponentName < allResults[j].ComponentName
	})

	// Display results
	fmt.Printf("\n=== Component Validation Results ===\n")
	for _, result := range allResults {
		fmt.Printf("\nComponent: %s\n", result.ComponentName)
		fmt.Printf("  Image: %s\n", result.ImageRef)

		if result.Error != nil {
			fmt.Printf("  ❌ Failed: %v\n", result.Error)
		} else if result.Result != nil && result.Result.Passed {
			fmt.Printf("  ✅ Passed: %s\n", result.Result.Message)
			if result.Result.SignatureVerified {
				fmt.Println("   🔐 Signature verified")
			} else if !data.ignoreSignatureVerification {
				fmt.Println("   ⚠️  Signature verification requested but not performed")
			}
		} else if result.Result != nil && !result.Result.Passed {
			if result.Result.SignatureVerified {
				fmt.Println("  🔐 Signature verified")
			} else if !data.ignoreSignatureVerification {
				fmt.Println("  ⚠️  Signature verification requested but not performed")
			}
			fmt.Printf("  ❌ Failed: %s\n", result.Result.Message)
		}
	}

	// Print summary
	fmt.Printf("\n=== Snapshot Validation Summary ===\n")
	fmt.Printf("Total components: %d\n", len(allResults))
	fmt.Printf("Successful: %d\n", successCount)
	fmt.Printf("Failed: %d\n", failureCount)

	// TODO: Add proper output formatting support for VSA validation
	// For now, output formatting is not implemented for VSA validation
	// The parallel processing functionality is the main focus

	if failureCount > 0 && data.strict {
		if allErrors != nil {
			return fmt.Errorf("snapshot validation failed for %d components: %w", failureCount, allErrors)
		}
		return fmt.Errorf("snapshot validation failed for %d components", failureCount)
	}

	return allErrors
}

// processSnapshotComponent processes a single snapshot component
func processSnapshotComponent(ctx context.Context, component app.SnapshotComponent, data *validateVSAData) vsa.ComponentResult {
	// Extract digest from ContainerImage
	digest, err := vsa.ExtractDigestFromImageRef(component.ContainerImage)
	if err != nil {
		return vsa.ComponentResult{
			ComponentName: component.Name,
			ImageRef:      component.ContainerImage,
			Error:         fmt.Errorf("failed to extract digest: %w", err),
		}
	}

	// Validate VSA with policy comparison
	validationData := &vsa.ValidationData{
		Retriever:                   data.retriever,
		VSAExpiration:               data.vsaExpiration,
		IgnoreSignatureVerification: data.ignoreSignatureVerification,
		PublicKeyPath:               data.publicKeyPath,
		PolicySpec:                  data.policySpec,
		EffectiveTime:               data.effectiveTime,
	}
	result, err := vsa.ValidateVSAWithPolicyComparison(ctx, digest, validationData)
	if err != nil {
		return vsa.ComponentResult{
			ComponentName: component.Name,
			ImageRef:      component.ContainerImage,
			Error:         fmt.Errorf("VSA validation failed: %w", err),
		}
	}

	return vsa.ComponentResult{
		ComponentName: component.Name,
		ImageRef:      component.ContainerImage,
		Result:        result,
		Error:         nil,
	}
}
