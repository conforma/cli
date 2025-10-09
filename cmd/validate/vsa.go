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
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	ecapi "github.com/conforma/crds/api/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/policy/equivalence"
	validate_utils "github.com/conforma/cli/internal/validate"
	"github.com/conforma/cli/internal/validate/vsa"
)

// ValidationResult represents the result of VSA validation
type ValidationResult struct {
	Passed            bool   `json:"passed"`
	Message           string `json:"message,omitempty"`
	SignatureVerified bool   `json:"signature_verified,omitempty"`
}

// IdentifierType represents the type of VSA identifier
type IdentifierType int

const (
	// IdentifierFile represents a local file path (absolute, relative, or files with extensions)
	IdentifierFile IdentifierType = iota
	// IdentifierImageDigest represents a container image digest (e.g., sha256:abc123...)
	IdentifierImageDigest
	// IdentifierImageReference represents a container image reference (e.g., nginx:latest, registry.io/repo:tag)
	IdentifierImageReference
)

// ComponentResult represents the validation result for a snapshot component
type ComponentResult struct {
	ComponentName string
	ImageRef      string
	Result        *ValidationResult
	Error         error
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
				if !isValidVSAIdentifier(identifier) {
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
	if err := createVSARetriever(data); err != nil {
		return err
	}

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

// detectIdentifierType detects the type of VSA identifier
func detectIdentifierType(identifier string) IdentifierType {
	if isImageDigest(identifier) {
		return IdentifierImageDigest
	}

	// Try image reference parse first; it's authoritative for registries
	if _, err := name.ParseReference(identifier); err == nil {
		return IdentifierImageReference
	}

	// Check if it's a file path using the dedicated function
	if isFilePath(identifier) {
		return IdentifierFile
	}

	// last resort: keep as reference so users can pass bare names like "nginx:latest"
	if _, err := name.ParseReference("docker.io/library/" + identifier); err == nil {
		return IdentifierImageReference
	}
	return IdentifierFile
}

// isFilePath checks if the identifier is a file path
func isFilePath(identifier string) bool {
	// If it contains @ or :, it's likely an image reference, not a file
	if strings.Contains(identifier, "@") || strings.Contains(identifier, ":") {
		return false
	}

	// Check if it's an absolute path
	if filepath.IsAbs(identifier) {
		return true
	}

	// Check if it's a relative path (./ or ../)
	if strings.HasPrefix(identifier, "./") || strings.HasPrefix(identifier, "../") {
		return true
	}

	// Check if it's a relative path that exists
	if _, err := os.Stat(identifier); err == nil {
		return true
	}

	// Check if it looks like a file path (contains path separators)
	if strings.Contains(identifier, "/") || strings.Contains(identifier, "\\") {
		return true
	}

	// Check if it has a file extension
	if filepath.Ext(identifier) != "" {
		return true
	}

	// If it doesn't look like a file path and doesn't contain special characters,
	// it might be a simple filename, but we need to be more careful
	return false
}

// isImageDigest checks if the identifier is an image digest
func isImageDigest(identifier string) bool {
	// Image digests typically start with sha256: or sha512:
	digestRegex := regexp.MustCompile(`^sha(256|512):[a-f0-9]+$`)
	return digestRegex.MatchString(identifier)
}

// isImageReference checks if the identifier is an image reference
func isImageReference(identifier string) bool {
	// First check if it's an image digest (more specific)
	if isImageDigest(identifier) {
		return false
	}

	// First check if it's clearly not an image reference
	if filepath.IsAbs(identifier) || strings.HasPrefix(identifier, "./") || strings.HasPrefix(identifier, "../") {
		return false
	}

	// Check if it has a file extension (likely a file, not an image)
	if filepath.Ext(identifier) != "" {
		return false
	}

	// Check if it looks like a digest (starts with sha)
	if strings.HasPrefix(identifier, "sha") {
		return false
	}

	// Try to parse as a container registry reference
	_, err := name.ParseReference(identifier)
	if err != nil {
		return false
	}

	// Additional validation: make sure it's not just a single word with a colon
	// (like "invalid:" or "sha128:abc123") but allow Docker Hub references
	if !strings.Contains(identifier, "/") && strings.Contains(identifier, ":") {
		// Check if it starts with "sha" (invalid digest format)
		if strings.HasPrefix(identifier, "sha") {
			return false
		}
		// Check if it's just a single word with colon (like "invalid:")
		parts := strings.Split(identifier, ":")
		if len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 {
			// This could be a valid Docker Hub reference like "nginx:latest"
			return true
		}
		// Single word with colon but no value after colon is invalid
		return false
	}

	// Additional validation: reject identifiers that look like digests but aren't valid
	// This catches cases like "sha128:abc123" that pass ParseReference but aren't valid
	if strings.HasPrefix(identifier, "sha") && strings.Contains(identifier, ":") {
		// Check if it's a valid digest format
		if !isImageDigest(identifier) {
			return false
		}
	}

	return true
}

// isValidVSAIdentifier validates VSA identifier format
func isValidVSAIdentifier(identifier string) bool {
	// Basic validation for VSA identifier
	if len(identifier) == 0 {
		return false
	}

	// Check if it's a valid identifier type
	identifierType := detectIdentifierType(identifier)
	switch identifierType {
	case IdentifierFile:
		// For file paths, check if it exists or looks like a valid path
		// Note: File paths with spaces are valid in many file systems
		if filepath.IsAbs(identifier) || strings.HasPrefix(identifier, "./") || strings.HasPrefix(identifier, "../") {
			return true
		}
		if _, err := os.Stat(identifier); err == nil {
			return true
		}
		// heuristics: has path sep or ext → likely a file
		return strings.ContainsAny(identifier, "/\\") || filepath.Ext(identifier) != ""
	case IdentifierImageDigest:
		// For image digests, validate the format
		return isImageDigest(identifier)
	case IdentifierImageReference:
		// For image references, validate using go-containerregistry
		// This will automatically reject identifiers with spaces
		_, err := name.ParseReference(identifier)
		return err == nil
	default:
		// If we can't determine the type, it's invalid
		return false
	}
}

// parseVSAExpiration parses the VSA expiration string into a duration
func parseVSAExpiration(data *validateVSAData) error {
	expiration, err := parseVSAExpirationDuration(data.vsaExpirationStr)
	if err != nil {
		return fmt.Errorf("invalid VSA expiration: %w", err)
	}
	data.vsaExpiration = expiration
	return nil
}

// parseVSAExpirationDuration parses a duration string with support for h, d, w, m suffixes
func parseVSAExpirationDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, "mo"): // non-standard but unambiguous
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "mo"), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid months: %w", err)
		}
		return time.Duration(n*30*24) * time.Hour, nil
	case strings.HasSuffix(s, "d"):
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(n*24) * time.Hour, nil
	case strings.HasSuffix(s, "w"):
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "w"), 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(n*7*24) * time.Hour, nil
	default:
		return time.ParseDuration(s) // supports h, m, s, etc.
	}
}

// loadPolicyConfig loads the policy configuration from multiple sources
func loadPolicyConfig(ctx context.Context, data *validateVSAData) error {
	// Use GetPolicyConfig to handle multiple sources (file, git, http, inline JSON)
	policyConfig, err := validate_utils.GetPolicyConfig(ctx, data.policyConfig)
	if err != nil {
		return fmt.Errorf("failed to load policy configuration: %w", err)
	}

	// Parse the policy configuration string into EnterpriseContractPolicySpec
	policySpec, err := parsePolicySpec(policyConfig)
	if err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	// Store the policy spec for comparison
	data.policySpec = policySpec

	return nil
}

// convertYAMLToJSON converts YAML interface{} types to proper types for JSON marshaling
func convertYAMLToJSON(data interface{}) interface{} {
	switch v := data.(type) {
	case map[interface{}]interface{}:
		result := make(map[string]interface{})
		for k, val := range v {
			if strKey, ok := k.(string); ok {
				result[strKey] = convertYAMLToJSON(val)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, val := range v {
			result[i] = convertYAMLToJSON(val)
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, val := range v {
			result[k] = convertYAMLToJSON(val)
		}
		return result
	default:
		return v
	}
}

// parsePolicySpec parses a policy configuration string to extract the EnterpriseContractPolicySpec
func parsePolicySpec(policyConfig string) (ecapi.EnterpriseContractPolicySpec, error) {
	content := []byte(policyConfig)

	// Convert YAML to JSON first to handle ruleData field mapping correctly
	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(content, &yamlData); err != nil {
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Convert interface{} types to proper types for JSON marshaling
	jsonData := convertYAMLToJSON(yamlData)

	// Convert to JSON bytes
	jsonBytes, err := json.Marshal(jsonData)
	if err != nil {
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	// Now parse as JSON which should handle ruleData field mapping correctly
	var ecp ecapi.EnterpriseContractPolicy
	if err := json.Unmarshal(jsonBytes, &ecp); err == nil && ecp.APIVersion != "" {
		// Check if this is actually a valid CRD (has required fields)
		if ecp.APIVersion == "" || ecp.Kind == "" {
			// This is not a valid CRD, try parsing as EnterpriseContractPolicySpec
			var spec ecapi.EnterpriseContractPolicySpec
			if err := json.Unmarshal(jsonBytes, &spec); err != nil {
				return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("unable to parse EnterpriseContractPolicySpec: %w", err)
			}
			return spec, nil
		}
		return ecp.Spec, nil
	}

	// If parsing as EnterpriseContractPolicy fails, try as EnterpriseContractPolicySpec
	var spec ecapi.EnterpriseContractPolicySpec
	if err := json.Unmarshal(jsonBytes, &spec); err != nil {
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("unable to parse EnterpriseContractPolicySpec: %w", err)
	}
	return spec, nil
}

// createVSARetriever creates the VSA retriever based on flags and identifier type
func createVSARetriever(data *validateVSAData) error {
	// If explicit retrieval backends are specified, use VSA library
	if len(data.vsaRetrieval) > 0 {
		retriever := vsa.CreateRetrieverFromUploadFlags(data.vsaRetrieval)
		if retriever == nil {
			return fmt.Errorf("no valid retriever found from flags: %v", data.vsaRetrieval)
		}
		data.retriever = retriever
		return nil
	}

	// Auto-detect retriever based on identifier type
	if data.vsaIdentifier != "" {
		identifierType := detectIdentifierType(data.vsaIdentifier)
		switch identifierType {
		case IdentifierFile:
			data.retriever = vsa.NewFileVSARetrieverWithOSFs(".")
		case IdentifierImageDigest, IdentifierImageReference:
			// Use VSA library to create Rekor retriever for image-based identifiers
			retriever := vsa.CreateRetrieverFromUploadFlags([]string{"rekor"})
			if retriever == nil {
				return fmt.Errorf("failed to create Rekor retriever")
			}
			data.retriever = retriever
		default:
			return fmt.Errorf("unsupported identifier type for VSA: %s", data.vsaIdentifier)
		}
		return nil
	}

	// For snapshot validation, always use Rekor retriever
	if data.images != "" {
		retriever := vsa.CreateRetrieverFromUploadFlags([]string{"rekor"})
		if retriever == nil {
			return fmt.Errorf("failed to create Rekor retriever")
		}
		data.retriever = retriever
		return nil
	}

	// Default to file retriever for backward compatibility
	data.retriever = vsa.NewFileVSARetrieverWithOSFs(".")
	return nil
}

// validateVSAWithPolicyComparison validates a VSA by comparing its policy with the supplied policy
func validateVSAWithPolicyComparison(ctx context.Context, identifier string, data *validateVSAData) (*ValidationResult, error) {
	// Use VSA library's VSAChecker for efficient VSA validation
	checker := vsa.NewVSAChecker(data.retriever)

	// SINGLE VSA RETRIEVAL with optional signature verification
	result, err := checker.CheckExistingVSAWithVerification(
		ctx,
		identifier,
		data.vsaExpiration,
		!data.ignoreSignatureVerification, // Whether to verify signature (inverse of ignore flag)
		data.publicKeyPath,                // Public key path (if signature verification requested)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing VSA: %w", err)
	}

	if !result.Found {
		return &ValidationResult{
			Passed:            false,
			Message:           "No VSA found for the specified identifier",
			SignatureVerified: result.SignatureVerified,
		}, nil
	}

	if result.Expired {
		days := int(math.Ceil(time.Since(result.Timestamp).Hours() / 24))
		return &ValidationResult{
			Passed:            false,
			Message:           fmt.Sprintf("VSA expired %d day(s) ago", days),
			SignatureVerified: result.SignatureVerified,
		}, nil
	}

	// If signature verification was requested and failed, the error would have been returned above
	// If signature verification was requested and succeeded, we continue with policy comparison

	// Extract policy from VSA predicate
	vsaPolicy, err := extractPolicyFromVSA(result.VSA)
	if err != nil {
		return &ValidationResult{
			Passed:            false,
			Message:           err.Error(),
			SignatureVerified: result.SignatureVerified,
		}, nil
	}

	// Compare policies if supplied policy is provided
	if len(data.policySpec.Sources) > 0 {
		// Parse effective time
		effectiveTime, err := parseEffectiveTime(data.effectiveTime)
		if err != nil {
			return &ValidationResult{
				Passed:            false,
				Message:           fmt.Sprintf("invalid effective time: %v", err),
				SignatureVerified: result.SignatureVerified,
			}, nil
		}

		// Create image info for volatile config matching
		imageInfo := &equivalence.ImageInfo{
			Digest: extractImageDigest(identifier),
			Ref:    identifier,
		}

		// Compare policies with detailed error reporting
		equivalent, differences, err := compareVSAPolicyWithDetails(vsaPolicy, data.policySpec, effectiveTime, imageInfo)
		if err != nil {
			return &ValidationResult{
				Passed:            false,
				Message:           fmt.Sprintf("policy comparison failed: %v", err),
				SignatureVerified: result.SignatureVerified,
			}, nil
		}

		if !equivalent {
			return &ValidationResult{
				Passed:            false,
				Message:           formatPolicyDifferences(differences),
				SignatureVerified: result.SignatureVerified,
			}, nil
		}
	}

	// Return success result
	return &ValidationResult{
		Passed:            true,
		Message:           "Policy matches",
		SignatureVerified: result.SignatureVerified,
	}, nil
}

// extractPolicyFromVSA extracts the policy from VSA predicate
func extractPolicyFromVSA(predicate *vsa.Predicate) (ecapi.EnterpriseContractPolicySpec, error) {
	// Check if predicate has a Policy field
	if predicate == nil {
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("VSA predicate is nil")
	}

	// Check if policy has any sources
	if len(predicate.Policy.Sources) == 0 {
		log.Debugf("VSA predicate policy sources: %+v", predicate.Policy.Sources)
		return ecapi.EnterpriseContractPolicySpec{}, fmt.Errorf("VSA predicate does not contain policy sources")
	}

	log.Debugf("VSA predicate contains policy with %d sources", len(predicate.Policy.Sources))
	return predicate.Policy, nil
}

// compareVSAPolicyWithDetails compares VSA policy with supplied policy and returns detailed differences
func compareVSAPolicyWithDetails(vsaPolicy ecapi.EnterpriseContractPolicySpec, suppliedPolicy ecapi.EnterpriseContractPolicySpec, effectiveTime time.Time, imageInfo *equivalence.ImageInfo) (bool, []equivalence.PolicyDifference, error) {
	checker := equivalence.NewEquivalenceChecker(effectiveTime, imageInfo)

	equivalent, differences, err := checker.AreEquivalentWithDifferences(vsaPolicy, suppliedPolicy)
	if err != nil {
		return false, nil, fmt.Errorf("policy comparison failed: %w", err)
	}

	return equivalent, differences, nil
}

// formatPolicyDifferences formats policy differences using unified diff format
func formatPolicyDifferences(differences []equivalence.PolicyDifference) string {
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

// parseEffectiveTime parses the effective time string
func parseEffectiveTime(effectiveTime string) (time.Time, error) {
	switch effectiveTime {
	case "now":
		return time.Now().UTC(), nil
	default:
		return time.Parse(time.RFC3339, effectiveTime)
	}
}

// extractImageDigest extracts image digest from identifier
func extractImageDigest(identifier string) string {
	// For now, return the identifier as-is
	// TODO: Implement proper digest extraction logic
	return identifier
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
	result, err := validateVSAWithPolicyComparison(ctx, identifier, data)
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
func worker(jobs <-chan app.SnapshotComponent, results chan<- ComponentResult, ctx context.Context, data *validateVSAData) {
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
	results := make(chan ComponentResult, numComponents)

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
	var allResults []ComponentResult
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
func processSnapshotComponent(ctx context.Context, component app.SnapshotComponent, data *validateVSAData) ComponentResult {
	// Extract digest from ContainerImage
	digest, err := extractDigestFromImageRef(component.ContainerImage)
	if err != nil {
		return ComponentResult{
			ComponentName: component.Name,
			ImageRef:      component.ContainerImage,
			Error:         fmt.Errorf("failed to extract digest: %w", err),
		}
	}

	// Validate VSA with policy comparison
	result, err := validateVSAWithPolicyComparison(ctx, digest, data)
	if err != nil {
		return ComponentResult{
			ComponentName: component.Name,
			ImageRef:      component.ContainerImage,
			Error:         fmt.Errorf("VSA validation failed: %w", err),
		}
	}

	return ComponentResult{
		ComponentName: component.Name,
		ImageRef:      component.ContainerImage,
		Result:        result,
		Error:         nil,
	}
}

// extractDigestFromImageRef extracts the digest from an image reference
func extractDigestFromImageRef(imageRef string) (string, error) {
	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("failed to parse image reference %s: %w", imageRef, err)
	}

	// Check if it's already a digest reference
	if digestRef, ok := ref.(name.Digest); ok {
		return digestRef.DigestStr(), nil
	}

	// For tag references, we need to resolve to digest
	// For now, return the image reference as-is and let the retriever handle it
	// In a full implementation, this would resolve the tag to a digest
	return imageRef, nil
}
