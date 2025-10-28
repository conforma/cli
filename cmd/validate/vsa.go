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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	ecapi "github.com/conforma/crds/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/image"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	validate_utils "github.com/conforma/cli/internal/validate"
	"github.com/conforma/cli/internal/validate/vsa"
)

// Constants for default values
const (
	DefaultWorkers         = 5
	DefaultVSAExpiration   = "168h" // 7 days
	DefaultEffectiveTime   = "now"
	DefaultStrictMode      = true
	DefaultFallbackEnabled = true
)

// Helper functions for color-aware output
func printVSAStatus(w io.Writer, message string, status string) {
	if utils.ColorEnabled {
		switch status {
		case "success":
			fmt.Fprintf(w, "✅ %s\n", message)
		case "failure":
			fmt.Fprintf(w, "❌ %s\n", message)
		case "warning":
			fmt.Fprintf(w, "⚠️  %s\n", message)
		case "info":
			fmt.Fprintf(w, "ℹ️  %s\n", message)
		default:
			fmt.Fprintf(w, "%s\n", message)
		}
	} else {
		fmt.Fprintf(w, "[%s] %s\n", strings.ToUpper(status), message)
	}

}

func printVSAInfo(w io.Writer, message string) {
	if utils.ColorEnabled {
		fmt.Fprintf(w, "ℹ️  %s\n", message)
	} else {
		fmt.Fprintf(w, "[INFO] %s\n", message)
	}
}

func printVSAWarning(w io.Writer, message string) {
	if utils.ColorEnabled {
		fmt.Fprintf(w, "⚠️  %s\n", message)
	} else {
		fmt.Fprintf(w, "[WARNING] %s\n", message)
	}
}

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

	// Fallback options
	fallbackToImageValidation bool   // Enable fallback to image validation (computed from noFallback)
	noFallback                bool   // Disable fallback to image validation
	fallbackPublicKey         string // Public key for fallback image validation

	// Output options
	output     []string // Output formats
	outputFile string   // Output file (deprecated)
	strict     bool     // Strict mode (fail on any error)

	// Parallel processing options
	workers int // Number of worker threads for parallel processing

	// Output formatting options
	noColor    bool // Disable color output
	forceColor bool // Force color output

	// Internal state
	policySpec ecapi.EnterpriseContractPolicySpec
	retriever  vsa.VSARetriever
	info       bool // Detailed output flag

	// Precomputed fallback validation context (created once, reused for all fallbacks)
	fallbackContext *vsa.FallbackValidationContext
}

func NewValidateVSACmd() *cobra.Command {
	data := &validateVSAData{
		strict:                    DefaultStrictMode,
		effectiveTime:             DefaultEffectiveTime,
		vsaExpirationStr:          DefaultVSAExpiration,
		vsaExpiration:             168 * time.Hour, // 7 days default
		workers:                   DefaultWorkers,
		fallbackToImageValidation: DefaultFallbackEnabled,
	}

	cmd := &cobra.Command{
		Use:   "vsa <vsa-identifier>",
		Short: "Validate VSA (Verification Summary Attestation)",
		Long: hd.Doc(`
			Validate VSA by comparing the embedded policy against a supplied policy configuration.
			
			By default, VSA signature verification is enabled and requires a public key.
			Use --ignore-signature-verification to disable signature verification.
			
			By default, fallback to image validation is enabled when VSA validation fails.
			Use --no-fallback to disable this behavior.
			
			Supports validation of:
			- Single VSA by identifier (image digest, file path)
			- Multiple VSAs from application snapshot
			
			VSA retrieval supports:
			- Rekor transparency log
			- Local filesystem storage
			- Multiple backends with fallback
		`),
		// Check positional arguments
		// Example: ec validate vsa image1@sha256:abc123 --policy policy.yaml --vsa-public-key key.pub
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
			// Compute fallback behavior: enabled by default, disabled if --no-fallback is set
			data.fallbackToImageValidation = !data.noFallback

			return validateVSAInput(data, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidateVSA(cmd, data, args, afero.NewOsFs())
		},
	}

	// Add flags
	addVSAFlags(cmd, data)
	return cmd
}

// addVSAFlags adds all the command flags with Cobra's built-in validation
func addVSAFlags(cmd *cobra.Command, data *validateVSAData) {
	// Input options
	cmd.Flags().StringVarP(&data.vsaIdentifier, "vsa", "v", "", "VSA identifier (image digest, file path)")
	cmd.Flags().StringVar(&data.images, "images", "", "Application snapshot file")
	cmd.Flags().StringVarP(&data.policyConfig, "policy", "p", "", "Policy configuration")

	// VSA retrieval options
	cmd.Flags().StringSliceVar(&data.vsaRetrieval, "vsa-retrieval", []string{}, "VSA retrieval backends (rekor@, file@)")

	// Policy comparison options
	cmd.Flags().StringVar(&data.effectiveTime, "effective-time", "now", "Effective time for comparison")

	// VSA options
	cmd.Flags().StringVar(&data.vsaExpirationStr, "vsa-expiration", DefaultVSAExpiration, "VSA expiration threshold (e.g., 24h, 7d, 1w, 1m)")

	// Signature verification options
	cmd.Flags().BoolVar(&data.ignoreSignatureVerification, "ignore-signature-verification", false, "Ignore VSA signature verification (signature verification is enabled by default)")
	cmd.Flags().StringVar(&data.publicKeyPath, "vsa-public-key", "", "Path to public key for VSA signature verification (required by default)")

	// Fallback options
	cmd.Flags().BoolVar(&data.noFallback, "no-fallback", false, "Disable fallback to image validation when VSA validation fails (fallback is enabled by default)")
	cmd.Flags().StringVar(&data.fallbackPublicKey, "fallback-public-key", "", "Public key to use for fallback image validation (different from VSA verification key)")
	// Output options
	cmd.Flags().StringSliceVar(&data.output, "output", []string{}, "Output formats (e.g., json, yaml, text)")
	cmd.Flags().BoolVar(&data.strict, "strict", DefaultStrictMode, "Exit with non-zero code if validation fails")

	// Parallel processing options
	cmd.Flags().IntVar(&data.workers, "workers", DefaultWorkers, "Number of worker threads for parallel processing")

	// Output formatting options
	cmd.Flags().BoolVar(&data.noColor, "no-color", false, "Disable color when using text output even when the current terminal supports it")
	cmd.Flags().BoolVar(&data.forceColor, "color", false, "Enable color when using text output even when the current terminal does not support it")

	// ===== COBRA BUILT-IN VALIDATION =====

	// 1. Required flags
	if err := cmd.MarkFlagRequired("policy"); err != nil {
		log.Warnf("Failed to mark policy flag as required: %v", err)
	}

	// 2. Mutual exclusivity: --vsa and --images are mutually exclusive
	cmd.MarkFlagsMutuallyExclusive("vsa", "images")

}

// runValidateVSA is the main command execution function
func runValidateVSA(cmd *cobra.Command, data *validateVSAData, args []string, fs afero.Fs) error {
	ctx := cmd.Context()

	// Set color support based on flags
	utils.SetColorEnabled(data.noColor, data.forceColor)

	// Parse VSA expiration
	if err := parseVSAExpiration(data); err != nil {
		return err
	}

	// Load policy configuration
	if err := loadPolicyConfig(ctx, data); err != nil {
		return err
	}

	// Precompute fallback validation context if fallback is enabled
	if data.fallbackToImageValidation {
		// Use the same resolved policy configuration as the main validation
		policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfig)
		if err != nil {
			return fmt.Errorf("failed to get policy configuration for fallback: %w", err)
		}

		fallbackConfig := &vsa.FallbackConfig{
			FallbackToImageValidation: data.fallbackToImageValidation,
			FallbackPublicKey:         data.fallbackPublicKey,
			PolicyConfig:              policyConfiguration, // Use resolved policy configuration
			EffectiveTime:             data.effectiveTime,
			Info:                      data.info,
		}
		fallbackContext, err := vsa.CreateFallbackValidationContext(ctx, fallbackConfig)
		if err != nil {
			return fmt.Errorf("failed to create fallback validation context: %w", err)
		}
		data.fallbackContext = fallbackContext
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
		return validateSnapshotVSAs(ctx, data, fs)
	} else {
		// VSA identifier is a single VSA, usually from a file system
		return validateSingleVSA(ctx, data, args, fs)
	}
}

// validateVSAInput validates the command input using Cobra's validation patterns
func validateVSAInput(data *validateVSAData, args []string) error {
	// Set VSA identifier from args if provided
	if len(args) > 0 {
		data.vsaIdentifier = args[0]
	}

	// Check if we have either VSA identifier, --vsa, or --images
	if data.vsaIdentifier == "" && data.images == "" {
		return fmt.Errorf("either --vsa, --images, or VSA identifier must be provided")
	}

	// Validate VSA expiration format early
	if err := parseVSAExpiration(data); err != nil {
		return fmt.Errorf("invalid --vsa-expiration: %w", err)
	}

	// Validate signature verification flags
	// By default, signature verification is enabled, so vsa-public-key is required unless --ignore-signature-verification is set
	if !data.ignoreSignatureVerification && data.publicKeyPath == "" {
		return fmt.Errorf("--vsa-public-key is required for signature verification (use --ignore-signature-verification to disable signature verification)")
	}

	// Validate fallback flags
	if data.fallbackToImageValidation && data.fallbackPublicKey == "" {
		return fmt.Errorf("--fallback-public-key is required when --fallback-to-image-validation is enabled")
	}

	// Validate that fallback only works with image references
	if data.fallbackToImageValidation && data.vsaIdentifier != "" {
		identifierType := vsa.DetectIdentifierType(data.vsaIdentifier)

		// Check if it's actually a file path (even if detected as image reference due to name.ParseReference bug)
		if vsa.IsFilePathLike(data.vsaIdentifier) {
			return fmt.Errorf("fallback not supported for file paths (identifier: %s)", data.vsaIdentifier)
		}

		if identifierType != vsa.IdentifierImageReference && identifierType != vsa.IdentifierImageDigest {
			return fmt.Errorf("fallback only supported for image references and digests, not %v (identifier: %s)", identifierType, data.vsaIdentifier)
		}
	}

	return nil
}

// outputVSAWithUnifiedResults outputs the combined VSA and fallback results using unified result structure
func outputVSAWithUnifiedResults(vsaResult *vsa.ValidationResult, fallbackOutput *output.Output, data *validateVSAData, fs afero.Fs) error {
	// Create unified result
	unifiedResult := vsa.BuildUnifiedValidationResult(vsaResult, fallbackOutput, true, data.vsaIdentifier)

	// Default to console output if no output formats specified
	if len(data.output) == 0 {
		data.output = append(data.output, "text")
	}

	// Use the reusable output function with adapter
	adapter := &UnifiedResultAdapter{result: unifiedResult}
	if err := writeOutputToFormats(adapter, data, fs); err != nil {
		return err
	}

	// Handle strict mode
	if data.strict && !unifiedResult.OverallSuccess {
		return fmt.Errorf("validation failed")
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
	// Resolve policy configuration using the standard utility function
	policyConfiguration, err := validate_utils.GetPolicyConfig(ctx, data.policyConfig)
	if err != nil {
		return fmt.Errorf("failed to get policy configuration: %w", err)
	}

	// Use the standard policy processing like other validation commands
	policyOptions := policy.Options{
		EffectiveTime: data.effectiveTime,
		PolicyRef:     policyConfiguration, // Use the resolved policy configuration
		PublicKey:     data.publicKeyPath,  // Use the available publicKeyPath field
		// Note: RekorURL is not available in VSA command, will use default
	}

	// Process policy using the standard PreProcessPolicy function
	processedPolicy, _, err := policy.PreProcessPolicy(ctx, policyOptions)
	if err != nil {
		return fmt.Errorf("failed to process policy: %w", err)
	}

	// Store the policy spec for comparison
	data.policySpec = processedPolicy.Spec()

	return nil
}

// validateSingleVSA validates a single VSA with optional fallback
func validateSingleVSA(ctx context.Context, data *validateVSAData, args []string, fs afero.Fs) error {
	identifier := extractVSAIdentifier(data, args)
	printVSAInfo(os.Stdout, fmt.Sprintf("Validating VSA: %s", identifier))
	printVSAInfo(os.Stdout, fmt.Sprintf("Policy: %s", data.policyConfig))

	// Perform VSA validation
	result, err := performVSAValidationForSingle(ctx, identifier, data)

	// Handle fallback logic if enabled
	if data.fallbackToImageValidation && vsa.ShouldTriggerFallback(err, result) {
		return handleFallbackValidation(ctx, identifier, result, data, fs)
	}

	// Handle VSA validation results (when no fallback or fallback not triggered)
	return handleVSAResult(result, err, data)
}

// extractVSAIdentifier extracts the VSA identifier from args or data
func extractVSAIdentifier(data *validateVSAData, args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return data.vsaIdentifier
}

// performVSAValidationForSingle performs VSA validation for a single identifier
func performVSAValidationForSingle(ctx context.Context, identifier string, data *validateVSAData) (*vsa.ValidationResult, error) {
	validationData := &vsa.VSAValidationConfig{
		Retriever:                   data.retriever,
		VSAExpiration:               data.vsaExpiration,
		IgnoreSignatureVerification: data.ignoreSignatureVerification,
		PublicKeyPath:               data.publicKeyPath,
		PolicySpec:                  data.policySpec,
		EffectiveTime:               data.effectiveTime,
	}

	return vsa.ValidateVSAAndComparePolicy(ctx, identifier, validationData)
}

// handleFallbackValidation handles the fallback validation logic
func handleFallbackValidation(ctx context.Context, imageRef string, result *vsa.ValidationResult, data *validateVSAData, fs afero.Fs) error {
	printVSAInfo(os.Stdout, "Falling back to image validation...")
	printVSAInfo(os.Stdout, fmt.Sprintf("Image reference: %s", imageRef))

	// Create worker context for fallback validation
	workerFallbackContext, workerErr := vsa.CreateWorkerFallbackContext(ctx, data.fallbackContext.FallbackPolicy)
	if workerErr != nil {
		return fmt.Errorf("failed to create fallback context: %w", workerErr)
	}

	// Use the common fallback validation logic
	fallbackResult := vsa.PerformFallbackValidation(result, "")
	if fallbackResult.Error != nil {
		return fallbackResult.Error
	}

	// Perform image validation
	fallbackOutput, fallbackErr := validateImageFallbackWithWorkerContext(ctx, data, imageRef, "single-vsa-component", workerFallbackContext)
	if fallbackErr != nil {
		return fmt.Errorf("fallback image validation failed: %w", fallbackErr)
	}

	// Set the fallback output
	fallbackResult.FallbackOutput = fallbackOutput

	// Output fallback results and return
	return outputVSAWithUnifiedResults(fallbackResult.VSAResult, fallbackResult.FallbackOutput, data, fs)
}

// handleVSAResult handles the VSA validation result display and error handling
func handleVSAResult(result *vsa.ValidationResult, err error, data *validateVSAData) error {
	if err != nil {
		return fmt.Errorf("VSA validation failed: %w", err)
	}

	if result.Passed {
		printVSAStatus(os.Stdout, "VSA validation passed", "success")
		displayVSASuccessDetails(result, data)
	} else {
		printVSAStatus(os.Stdout, "VSA validation failed", "failure")
		displayVSAFailureDetails(result, data)
		if data.strict {
			return fmt.Errorf("VSA validation failed")
		}
	}

	return nil
}

// displayVSASuccessDetails displays success details for VSA validation
func displayVSASuccessDetails(result *vsa.ValidationResult, data *validateVSAData) {
	if result.Message != "" {
		printVSAInfo(os.Stdout, fmt.Sprintf("   %s", result.Message))
	}
	if result.SignatureVerified {
		printVSAInfo(os.Stdout, "   🔐 Signature verified")
	} else if !data.ignoreSignatureVerification {
		printVSAWarning(os.Stdout, "Signature verification requested but not performed")
	}
	if result.PredicateOutcome != "" {
		printVSAInfo(os.Stdout, fmt.Sprintf("   Predicate Status: %s", result.PredicateOutcome))
	}
}

// displayVSAFailureDetails displays failure details for VSA validation
func displayVSAFailureDetails(result *vsa.ValidationResult, data *validateVSAData) {
	if result.Message != "" {
		printVSAInfo(os.Stdout, fmt.Sprintf("   %s", result.Message))
	}
	if result.PredicateOutcome != "" {
		printVSAInfo(os.Stdout, fmt.Sprintf("   Predicate Status: %s", result.PredicateOutcome))
	}
}

// worker processes components from the jobs channel and sends results to the results channel
func worker(jobs <-chan app.SnapshotComponent, results chan<- vsa.ComponentResult, ctx context.Context, data *validateVSAData) {
	// Create worker-specific fallback context once per worker
	var workerFallbackContext *vsa.WorkerFallbackContext
	var ctxErr error

	if data.fallbackToImageValidation && data.fallbackContext != nil {
		var err error
		workerFallbackContext, err = vsa.CreateWorkerFallbackContext(ctx, data.fallbackContext.FallbackPolicy)
		if err != nil {
			// Store the error but don't drain the channel - let other workers continue
			ctxErr = fmt.Errorf("failed to create worker fallback context: %w", err)
		}
	}

	// Process jobs with error handling that doesn't starve other workers
	for component := range jobs {
		var result vsa.ComponentResult

		if ctxErr != nil {
			// If we have a context error, emit error for this specific job and continue
			// Other workers can still process their share of jobs
			result = vsa.ComponentResult{
				ComponentName: component.Name,
				ImageRef:      component.ContainerImage,
				Error:         ctxErr,
			}
		} else {
			// Normal processing with worker context
			result = processSnapshotComponentWithWorkerContext(ctx, component, data, workerFallbackContext)
		}

		results <- result
	}
}

// validateSnapshotVSAs processes multiple components from a snapshot file in parallel
func validateSnapshotVSAs(ctx context.Context, data *validateVSAData, fs afero.Fs) error {
	printVSAInfo(os.Stdout, fmt.Sprintf("Validating VSAs from snapshot: %s", data.images))
	printVSAInfo(os.Stdout, fmt.Sprintf("Policy: %s", data.policyConfig))

	// Parse snapshot
	snapshot, err := parseSnapshot(ctx, data.images)
	if err != nil {
		return err
	}

	// Process components in parallel
	allResults, err := processComponentsInParallel(ctx, snapshot.Components, data)
	if err != nil {
		return err
	}

	// Display results
	displayComponentResults(allResults, data)

	// Handle output formatting
	if err := handleSnapshotOutput(allResults, data, fs); err != nil {
		return err
	}

	// Check strict mode
	return checkStrictMode(allResults, data)
}

// parseSnapshot parses the application snapshot from the input file
func parseSnapshot(ctx context.Context, imagesPath string) (*app.SnapshotSpec, error) {
	snapshot, _, err := applicationsnapshot.DetermineInputSpec(ctx, applicationsnapshot.Input{
		Images: imagesPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse snapshot: %w", err)
	}

	if len(snapshot.Components) == 0 {
		return nil, fmt.Errorf("snapshot contains no components")
	}

	return snapshot, nil
}

// processComponentsInParallel processes all components using parallel workers
func processComponentsInParallel(ctx context.Context, components []app.SnapshotComponent, data *validateVSAData) ([]vsa.ComponentResult, error) {
	numComponents := len(components)
	numWorkers := data.workers

	printVSAInfo(os.Stdout, fmt.Sprintf("Found %d components in snapshot", numComponents))
	printVSAInfo(os.Stdout, fmt.Sprintf("=== Processing Components in Parallel (%d workers) ===", numWorkers))

	// Add timeout for parallel processing to prevent hanging
	timeoutDuration := 30 * time.Minute
	ctx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()

	// Set up parallel processing infrastructure
	jobs := make(chan app.SnapshotComponent, numComponents)
	results := make(chan vsa.ComponentResult, numComponents)

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		go worker(jobs, results, ctx, data)
	}

	// Send all components to workers
	for _, component := range components {
		select {
		case jobs <- component:
			// Component sent successfully
		case <-ctx.Done():
			close(jobs)
			return nil, fmt.Errorf("parallel processing timeout after %v: %w", timeoutDuration, ctx.Err())
		}
	}
	close(jobs)

	// Collect results with timeout handling
	var allResults []vsa.ComponentResult
	for i := 0; i < numComponents; i++ {
		select {
		case result := <-results:
			allResults = append(allResults, result)
		case <-ctx.Done():
			close(results)
			return nil, fmt.Errorf("parallel processing timeout after %v: %w", timeoutDuration, ctx.Err())
		}
	}
	close(results)

	// Sort results by component name for consistent display
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].ComponentName < allResults[j].ComponentName
	})

	return allResults, nil
}

// displayComponentResults displays the validation results for each component
func displayComponentResults(allResults []vsa.ComponentResult, data *validateVSAData) {
	var successCount, failureCount, fallbackCount int

	printVSAInfo(os.Stdout, "\n=== Component Validation Results ===")
	for _, result := range allResults {
		printVSAInfo(os.Stdout, fmt.Sprintf("\nComponent: %s", result.ComponentName))
		printVSAInfo(os.Stdout, fmt.Sprintf("  Image: %s", result.ImageRef))

		resultType := classifyResult(result)
		switch resultType {
		case ResultTypeError:
			failureCount++
			printVSAStatus(os.Stdout, fmt.Sprintf("Failed: %v", result.Error), "failure")
		case ResultTypeFallback:
			fallbackCount++
			if result.UnifiedResult.OverallSuccess {
				successCount++
			} else {
				failureCount++
			}
			displayFallbackResult(result)
		case ResultTypeVSASuccess:
			successCount++
			displayVSASuccessResult(result, data)
		case ResultTypeVSAFailure:
			failureCount++
			displayVSAFailureResult(result, data)
		case ResultTypeUnexpected:
			failureCount++
			printVSAStatus(os.Stdout, fmt.Sprintf("  Unexpected state: no validation result for component %s", result.ComponentName), "failure")
		}
	}

	// Print summary statistics
	printVSAInfo(os.Stdout, "\n=== Snapshot Validation Summary ===")
	printVSAInfo(os.Stdout, fmt.Sprintf("Total components: %d", len(allResults)))
	printVSAInfo(os.Stdout, fmt.Sprintf("Successful: %d", successCount))
	printVSAInfo(os.Stdout, fmt.Sprintf("Failed: %d", failureCount))
	if fallbackCount > 0 {
		printVSAInfo(os.Stdout, fmt.Sprintf("Used fallback: %d", fallbackCount))
	}
}

// displayFallbackResult displays fallback validation results
func displayFallbackResult(result vsa.ComponentResult) {
	printVSAInfo(os.Stdout, "  🔄 Fallback validation used")
	if err := result.UnifiedResult.PrintConsole(os.Stdout); err != nil {
		printVSAWarning(os.Stdout, fmt.Sprintf("  Failed to display fallback results: %v", err))
	}
}

// displayVSASuccessResult displays VSA success results
func displayVSASuccessResult(result vsa.ComponentResult, data *validateVSAData) {
	printVSAStatus(os.Stdout, fmt.Sprintf("Passed: %s", result.Result.Message), "success")
	if result.Result.SignatureVerified {
		printVSAInfo(os.Stdout, "   🔐 Signature verified")
	} else if !data.ignoreSignatureVerification {
		printVSAWarning(os.Stdout, "   Signature verification requested but not performed")
	}
	if result.Result.PredicateOutcome != "" {
		printVSAInfo(os.Stdout, fmt.Sprintf("   Predicate Status: %s", result.Result.PredicateOutcome))
	}
}

// displayVSAFailureResult displays VSA failure results
func displayVSAFailureResult(result vsa.ComponentResult, data *validateVSAData) {
	if result.Result.SignatureVerified {
		printVSAInfo(os.Stdout, "  🔐 Signature verified")
	} else if !data.ignoreSignatureVerification {
		printVSAWarning(os.Stdout, "Signature verification requested but not performed")
	}
	if result.Result.PredicateOutcome != "" {
		printVSAInfo(os.Stdout, fmt.Sprintf("  Predicate Status: %s", result.Result.PredicateOutcome))
	}
	printVSAStatus(os.Stdout, fmt.Sprintf("Failed: %s", result.Result.Message), "failure")
}

// handleSnapshotOutput handles output formatting for snapshot validation
func handleSnapshotOutput(allResults []vsa.ComponentResult, data *validateVSAData, fs afero.Fs) error {
	if len(data.output) > 0 || len(data.outputFile) > 0 {
		report := createVSAReport(allResults, data)
		return writeOutputToFormats(report, data, fs)
	}
	return nil
}

// checkStrictMode checks if validation should fail based on strict mode
func checkStrictMode(allResults []vsa.ComponentResult, data *validateVSAData) error {
	if !data.strict {
		return nil
	}

	var failureCount int
	var allErrors error

	for _, result := range allResults {
		resultType := classifyResult(result)
		if resultType == ResultTypeError || resultType == ResultTypeVSAFailure ||
			(resultType == ResultTypeFallback && !result.UnifiedResult.OverallSuccess) ||
			resultType == ResultTypeUnexpected {
			failureCount++
			if result.Error != nil {
				allErrors = errors.Join(allErrors, result.Error)
			}
		}
	}

	if failureCount > 0 {
		if allErrors != nil {
			return fmt.Errorf("snapshot validation failed for %d components: %w", failureCount, allErrors)
		}
		return fmt.Errorf("snapshot validation failed for %d components", failureCount)
	}

	return nil
}

// validateImageFallbackWithWorkerContext performs image validation using worker-specific evaluators
// This ensures thread safety while reusing evaluators within the worker
func validateImageFallbackWithWorkerContext(ctx context.Context, data *validateVSAData, imageRef string, componentName string, workerFallbackContext *vsa.WorkerFallbackContext) (*output.Output, error) {
	log.Debugf("🔄 Starting fallback validation for image: %s", imageRef)

	// Use provided component name or default to "fallback-component"
	name := "fallback-component"
	if componentName != "" {
		name = componentName
	}
	log.Debugf("🔄 Fallback: Using component name: %s", name)

	// Create a minimal SnapshotComponent for single image validation
	comp := app.SnapshotComponent{
		ContainerImage: imageRef,
		Name:           name,
	}

	// Create a minimal SnapshotSpec
	spec := &app.SnapshotSpec{
		Components: []app.SnapshotComponent{comp},
	}

	// Use precomputed fallback context and worker-specific evaluators
	if data.fallbackContext == nil {
		return nil, fmt.Errorf("fallback context not initialized - this should not happen")
	}

	if workerFallbackContext == nil {
		return nil, fmt.Errorf("worker fallback context not initialized - this should not happen")
	}

	log.Debugf("🔄 Fallback: Using precomputed policy configuration: %s", data.fallbackContext.PolicyConfiguration)
	log.Debugf("🔄 Fallback: Using worker evaluators: %d", len(workerFallbackContext.Evaluators))

	// Perform image validation using precomputed context and worker-specific evaluators
	log.Debugf("🔄 Fallback: Starting image validation...")
	log.Debugf("🔄 Fallback: Using fallback policy: %s", data.fallbackContext.FallbackPolicy)
	result, err := image.ValidateImage(ctx, comp, spec, data.fallbackContext.FallbackPolicy, workerFallbackContext.Evaluators, data.info)
	if err != nil {
		log.Debugf("🔄 Fallback: Image validation failed with error: %v", err)
		return nil, err
	}

	log.Debugf("🔄 Fallback: Image validation completed")
	log.Debugf("🔄 Fallback: Exit code: %d", result.ExitCode)
	log.Debugf("🔄 Fallback: Violations: %d", len(result.Violations()))
	log.Debugf("🔄 Fallback: Warnings: %d", len(result.Warnings()))
	log.Debugf("🔄 Fallback: Successes: %d", len(result.Successes()))

	return result, nil
}

// processSnapshotComponentWithWorkerContext processes a single component using worker-specific fallback context
func processSnapshotComponentWithWorkerContext(ctx context.Context, component app.SnapshotComponent, data *validateVSAData, workerFallbackContext *vsa.WorkerFallbackContext) vsa.ComponentResult {
	// Extract digest from ContainerImage
	digest, err := vsa.ExtractDigestFromImageRef(component.ContainerImage)
	if err != nil {
		return createErrorResult(component, fmt.Errorf("failed to extract digest: %w", err))
	}

	// Perform VSA validation
	result, err := performVSAValidation(ctx, digest, data)
	if err != nil {
		return createErrorResult(component, fmt.Errorf("VSA validation failed: %w", err))
	}

	// Handle fallback if enabled and needed
	if data.fallbackToImageValidation && shouldTriggerFallbackForComponent(err, result) {
		return handleComponentFallback(ctx, component, data, result, workerFallbackContext)
	}

	// Return VSA-only result
	return vsa.ComponentResult{
		ComponentName: component.Name,
		ImageRef:      component.ContainerImage,
		Result:        result,
		Error:         nil,
	}
}

// performVSAValidation performs VSA validation for a component
func performVSAValidation(ctx context.Context, digest string, data *validateVSAData) (*vsa.ValidationResult, error) {
	validationData := &vsa.VSAValidationConfig{
		Retriever:                   data.retriever,
		VSAExpiration:               data.vsaExpiration,
		IgnoreSignatureVerification: data.ignoreSignatureVerification,
		PublicKeyPath:               data.publicKeyPath,
		PolicySpec:                  data.policySpec,
		EffectiveTime:               data.effectiveTime,
	}

	return vsa.ValidateVSAAndComparePolicy(ctx, digest, validationData)
}

// shouldTriggerFallbackForComponent determines if fallback should be triggered for a component
func shouldTriggerFallbackForComponent(err error, result *vsa.ValidationResult) bool {
	if err != nil {
		return true
	}
	if result != nil && !result.Passed {
		return true
	}
	if result != nil && result.PredicateOutcome != "" && result.PredicateOutcome != "passed" {
		return true
	}
	return false
}

// handleComponentFallback handles fallback validation for a component
func handleComponentFallback(ctx context.Context, component app.SnapshotComponent, data *validateVSAData, result *vsa.ValidationResult, workerFallbackContext *vsa.WorkerFallbackContext) vsa.ComponentResult {
	imageRef := component.ContainerImage
	predicateStatus := ""
	if result != nil {
		predicateStatus = result.PredicateOutcome
	}

	// Use the common fallback validation logic
	fallbackResult := vsa.PerformFallbackValidation(result, predicateStatus)
	if fallbackResult.Error != nil {
		return createErrorResult(component, fallbackResult.Error)
	}

	// Perform image validation
	fallbackOutput, fallbackErr := validateImageFallbackWithWorkerContext(ctx, data, imageRef, component.Name, workerFallbackContext)
	if fallbackErr != nil {
		return createErrorResult(component, fmt.Errorf("fallback image validation failed: %w", fallbackErr))
	}

	// Set the fallback output
	fallbackResult.FallbackOutput = fallbackOutput

	// Create unified result with fallback
	unifiedResult := vsa.BuildUnifiedValidationResult(fallbackResult.VSAResult, fallbackResult.FallbackOutput, true, imageRef)

	return vsa.ComponentResult{
		ComponentName: component.Name,
		ImageRef:      component.ContainerImage,
		Result:        result, // Keep original VSA result for compatibility
		Error:         nil,
		UnifiedResult: unifiedResult, // Add fallback result
	}
}

// createErrorResult creates a ComponentResult with an error
func createErrorResult(component app.SnapshotComponent, err error) vsa.ComponentResult {
	return vsa.ComponentResult{
		ComponentName: component.Name,
		ImageRef:      component.ContainerImage,
		Error:         err,
	}
}

// OutputFormatter defines the interface for objects that can be formatted for output
type OutputFormatter interface {
	PrintJSON(writer io.Writer) error
	PrintText(writer io.Writer) error
}

// UnifiedResultAdapter adapts VSAValidationResult to OutputFormatter interface
type UnifiedResultAdapter struct {
	result *vsa.VSAValidationResult
}

// PrintJSON outputs the unified result as JSON
func (a *UnifiedResultAdapter) PrintJSON(writer io.Writer) error {
	return a.result.PrintJSON(writer)
}

// PrintText outputs the unified result as text (using PrintConsole)
func (a *UnifiedResultAdapter) PrintText(writer io.Writer) error {
	return a.result.PrintConsole(writer)
}

// VSAReport represents the output structure for VSA validation results
type VSAReport struct {
	Timestamp      string                `json:"timestamp"`
	TotalResults   int                   `json:"total_results"`
	SuccessCount   int                   `json:"success_count"`
	FailureCount   int                   `json:"failure_count"`
	FallbackCount  int                   `json:"fallback_count,omitempty"`
	Results        []vsa.ComponentResult `json:"results"`
	OverallSuccess bool                  `json:"overall_success"`
}

// PrintJSON outputs the report in JSON format
func (r *VSAReport) PrintJSON(writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// PrintText outputs the report in text format
func (r *VSAReport) PrintText(writer io.Writer) error {
	fmt.Fprintf(writer, "VSA Validation Report\n")
	fmt.Fprintf(writer, "====================\n")
	fmt.Fprintf(writer, "Timestamp: %s\n", r.Timestamp)
	fmt.Fprintf(writer, "Total Results: %d\n", r.TotalResults)
	fmt.Fprintf(writer, "Successful: %d\n", r.SuccessCount)
	fmt.Fprintf(writer, "Failed: %d\n", r.FailureCount)
	if r.FallbackCount > 0 {
		fmt.Fprintf(writer, "Used Fallback: %d\n", r.FallbackCount)
	}
	fmt.Fprintf(writer, "Overall Success: %t\n", r.OverallSuccess)
	fmt.Fprintf(writer, "\nDetailed Results:\n")

	for _, result := range r.Results {
		fmt.Fprintf(writer, "\nComponent: %s\n", result.ComponentName)
		fmt.Fprintf(writer, "  Image: %s\n", result.ImageRef)

		if result.Error != nil {
			fmt.Fprintf(writer, "  ❌ Error: %v\n", result.Error)
		} else if result.UnifiedResult != nil {
			fmt.Fprintf(writer, "  🔄 Fallback used\n")
			if result.UnifiedResult.OverallSuccess {
				fmt.Fprintf(writer, "  ✅ Fallback succeeded\n")
			} else {
				fmt.Fprintf(writer, "  ❌ Fallback failed\n")
			}
		} else if result.Result != nil {
			if result.Result.Passed {
				fmt.Fprintf(writer, "  ✅ VSA validation passed\n")
			} else {
				fmt.Fprintf(writer, "  ❌ VSA validation failed: %s\n", result.Result.Message)
			}
		}
	}

	return nil
}

// writeOutputToFormats writes the given formatter to all specified output formats
func writeOutputToFormats(formatter OutputFormatter, data *validateVSAData, fs afero.Fs) error {
	// Handle deprecated outputFile flag
	if len(data.outputFile) > 0 {
		data.output = append(data.output, fmt.Sprintf("json=%s", data.outputFile))
	}

	// Output to all specified formats
	for _, outputSpec := range data.output {
		parts := strings.SplitN(outputSpec, "=", 2)
		format := parts[0]
		file := ""
		if len(parts) > 1 {
			file = parts[1]
		}

		var writer io.Writer = os.Stdout
		if file != "" {
			f, err := fs.Create(file)
			if err != nil {
				return fmt.Errorf("failed to create output file %s: %w", file, err)
			}
			defer f.Close()
			writer = f
		}

		switch format {
		case "json":
			err := formatter.PrintJSON(writer)
			if err != nil {
				return fmt.Errorf("failed to output JSON: %w", err)
			}
		case "text", "console":
			err := formatter.PrintText(writer)
			if err != nil {
				return fmt.Errorf("failed to output text: %w", err)
			}
		default:
			return fmt.Errorf("unsupported output format: %s", format)
		}
	}

	return nil
}

// createVSAReport creates a report structure from VSA validation results
func createVSAReport(results []vsa.ComponentResult, data *validateVSAData) *VSAReport {
	successCount := 0
	failureCount := 0
	fallbackCount := 0

	for _, result := range results {
		if result.Error != nil {
			failureCount++
		} else if result.UnifiedResult != nil {
			fallbackCount++
			if result.UnifiedResult.OverallSuccess {
				successCount++
			} else {
				failureCount++
			}
		} else if result.Result != nil && result.Result.Passed {
			successCount++
		} else if result.Result != nil && !result.Result.Passed {
			failureCount++
		}
	}

	return &VSAReport{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		TotalResults:   len(results),
		SuccessCount:   successCount,
		FailureCount:   failureCount,
		FallbackCount:  fallbackCount,
		Results:        results,
		OverallSuccess: failureCount == 0,
	}
}

// ResultType represents the classification of a component validation result
type ResultType int

const (
	ResultTypeError ResultType = iota
	ResultTypeFallback
	ResultTypeVSASuccess
	ResultTypeVSAFailure
	ResultTypeUnexpected
)

// classifyResult determines the type of a component validation result
func classifyResult(result vsa.ComponentResult) ResultType {
	if result.Error != nil {
		return ResultTypeError
	}
	if result.UnifiedResult != nil {
		return ResultTypeFallback
	}
	if result.Result != nil && result.Result.Passed {
		return ResultTypeVSASuccess
	}
	if result.Result != nil && !result.Result.Passed {
		return ResultTypeVSAFailure
	}
	return ResultTypeUnexpected
}
