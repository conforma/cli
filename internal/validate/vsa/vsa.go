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
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	ecapi "github.com/conforma/crds/api/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigd "github.com/sigstore/sigstore/pkg/signature/dsse"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/utils"
)

// ComponentSummary represents the summary information for a single component
type ComponentSummary struct {
	Name           string      `json:"name"`
	ContainerImage string      `json:"containerImage"`
	Source         interface{} `json:"source"`
}

// ComponentDetail represents detailed information about a component in the summary
type ComponentDetail struct {
	Name       string `json:"Name"`
	ImageRef   string `json:"ImageRef"`
	Violations int    `json:"Violations"`
	Warnings   int    `json:"Warnings"`
	Successes  int    `json:"Successes"`
}

// VSASummary represents the summary information for a VSA predicate
type VSASummary struct {
	Violations int               `json:"violations"`
	Warnings   int               `json:"warnings"`
	Successes  int               `json:"successes"`
	Components []ComponentDetail `json:"Components"`
	Component  ComponentSummary  `json:"component"`
}

type Predicate struct {
	Policy       ecapi.EnterpriseContractPolicySpec `json:"policy"`
	PolicySource string                             `json:"policySource"`
	ImageRefs    []string                           `json:"imageRefs"`
	Timestamp    string                             `json:"timestamp"`
	Status       string                             `json:"status"`
	Verifier     string                             `json:"verifier"`
	Summary      VSASummary                         `json:"summary"`
	PublicKey    string                             `json:"publicKey"`
}

// ValidationResult represents the result of VSA validation
type ValidationResult struct {
	Passed            bool   `json:"passed"`
	Message           string `json:"message,omitempty"`
	SignatureVerified bool   `json:"signature_verified,omitempty"`
	PredicateOutcome  string `json:"predicate_outcome,omitempty"` // Outcome from VSA predicate
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
	UnifiedResult *VSAValidationResult // Unified result when fallback was used
}

// Generator handles VSA predicate generation
type Generator struct {
	Report       applicationsnapshot.Report
	Component    applicationsnapshot.Component
	PolicySource string
	Policy       PublicKeyProvider
}

// PublicKeyProvider defines the interface for accessing public key information
type PublicKeyProvider interface {
	PublicKeyPEM() ([]byte, error)
}

// NewGenerator creates a new VSA predicate generator
func NewGenerator(report applicationsnapshot.Report, comp applicationsnapshot.Component, policySource string, policy PublicKeyProvider) *Generator {
	return &Generator{
		Report:       report,
		Component:    comp,
		PolicySource: policySource,
		Policy:       policy,
	}
}

// normalizeIndexRef normalizes an image reference to its pinned digest form if it's an index
func normalizeIndexRef(ref string, exp *applicationsnapshot.ExpansionInfo) string {
	if exp == nil {
		return ref
	}
	if pinned, ok := exp.GetIndexAlias(ref); ok {
		return pinned
	}
	return ref
}

// GeneratePredicate creates a Predicate for a validated image/component.
func (g *Generator) GeneratePredicate(ctx context.Context) (*Predicate, error) {
	log.Infof("Generating EC predicate for image: %s", g.Component.ContainerImage)

	// Get all image references including the index and architecture-specific images
	imageRefs := g.getAllImageRefs()

	// Determine the overall status based on component success
	status := "failed"
	if g.Component.Success {
		status = "passed"
	}

	// Create detailed summary with architecture breakdown
	summary := g.createDetailedSummary()

	// Get the public key from the policy
	publicKey := ""
	if g.Policy != nil {
		if publicKeyBytes, err := g.Policy.PublicKeyPEM(); err != nil {
			log.Warnf("Failed to get public key from policy: %v", err)
		} else {
			publicKey = string(publicKeyBytes)
		}
	}

	return &Predicate{
		Policy:       g.Report.Policy, // This contains the resolved policy with pinned URLs
		PolicySource: g.PolicySource,  // This contains the original policy location
		ImageRefs:    imageRefs,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Status:       status,
		Verifier:     "conforma",
		Summary:      summary,
		PublicKey:    publicKey,
	}, nil
}

// createDetailedSummary creates a detailed summary with architecture breakdown
func (g *Generator) createDetailedSummary() VSASummary {
	// Start with main component
	mainViolations := len(g.Component.Violations)
	mainWarnings := len(g.Component.Warnings)
	mainSuccesses := len(g.Component.Successes)

	// Initialize totals with main component
	totalViolations := mainViolations
	totalWarnings := mainWarnings
	totalSuccesses := mainSuccesses

	// Create components list with detailed breakdown
	components := []ComponentDetail{
		{
			Name:       g.Component.Name,
			ImageRef:   g.Component.ContainerImage,
			Violations: mainViolations,
			Warnings:   mainWarnings,
			Successes:  mainSuccesses,
		},
	}

	// If we have expansion info, add architecture-specific details
	if g.Report.Expansion != nil {
		// Get all child manifests for the main component
		mainImageRef := g.Component.ContainerImage
		if children, ok := g.Report.Expansion.GetChildrenByIndex(mainImageRef); ok {
			for _, childRef := range children {
				// Skip if this is the main component itself (shouldn't happen, but be safe)
				if childRef == g.Component.ContainerImage {
					continue
				}

				// Find the actual child component in the report to get its real data
				var childComponent *applicationsnapshot.Component
				for _, comp := range g.Report.Components {
					if comp.ContainerImage == childRef {
						childComponent = &comp
						break
					}
				}

				// Use actual child component data if found, otherwise use zeros
				var archViolations, archWarnings, archSuccesses int
				var childName string
				if childComponent != nil {
					archViolations = len(childComponent.Violations)
					archWarnings = len(childComponent.Warnings)
					archSuccesses = len(childComponent.Successes)
					childName = childComponent.Name
				} else {
					// If child component not found in report, use a default name
					childName = fmt.Sprintf("%s-%s", g.Component.Name, childRef)
				}

				components = append(components, ComponentDetail{
					Name:       childName,
					ImageRef:   childRef,
					Violations: archViolations,
					Warnings:   archWarnings,
					Successes:  archSuccesses,
				})

				// Add to totals
				totalViolations += archViolations
				totalWarnings += archWarnings
				totalSuccesses += archSuccesses
			}
		}
	}

	return VSASummary{
		Violations: totalViolations,
		Warnings:   totalWarnings,
		Successes:  totalSuccesses,
		Components: components,
		Component: ComponentSummary{
			Name:           g.Component.Name,
			ContainerImage: g.Component.ContainerImage,
			Source:         g.Component.Source,
		},
	}
}

// getAllImageRefs returns all image references including the index and architecture-specific images
func (g *Generator) getAllImageRefs() []string {
	var imageRefs []string

	// Add the main component image reference
	imageRefs = append(imageRefs, g.Component.ContainerImage)

	// If we have expansion info, add the index and all architecture-specific images
	if g.Report.Expansion != nil {
		// Get the normalized index reference
		normalizedRef := normalizeIndexRef(g.Component.ContainerImage, g.Report.Expansion)

		// Add the index reference if it's different from the component image
		if normalizedRef != g.Component.ContainerImage {
			imageRefs = append(imageRefs, normalizedRef)
		}

		// Get all child images for this index
		if children, ok := g.Report.Expansion.GetChildrenByIndex(normalizedRef); ok {
			imageRefs = append(imageRefs, children...)
		}
	}

	// Remove duplicates and return
	return removeDuplicateStrings(imageRefs)
}

// removeDuplicateStrings removes duplicate strings from a slice
func removeDuplicateStrings(slice []string) []string {
	if len(slice) == 0 {
		return []string{}
	}

	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Writer handles VSA file writing
type Writer struct {
	FS            afero.Fs    // defaults to the package-level FS or afero.NewOsFs()
	TempDirPrefix string      // defaults to "vsa-"
	FilePerm      os.FileMode // defaults to 0600
}

// NewWriter creates a new VSA file writer
func NewWriter() *Writer {
	return &Writer{
		FS:            afero.NewOsFs(),
		TempDirPrefix: "vsa-",
		FilePerm:      0o600,
	}
}

// WritePredicate writes the Predicate as a JSON file to a temp directory and returns the path.
func (w *Writer) WritePredicate(predicate *Predicate) (string, error) {
	log.Infof("Writing VSA for images: %v", predicate.ImageRefs)

	// Serialize with indent
	data, err := json.MarshalIndent(predicate, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal VSA predicate: %w", err)
	}

	// Create temp directory
	tempDir, err := afero.TempDir(w.FS, "", w.TempDirPrefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Write to file with same naming convention as old VSA
	componentName := "unknown"
	if predicate.Summary.Component.Name != "" {
		componentName = predicate.Summary.Component.Name
	}
	filename := fmt.Sprintf("vsa-%s.json", componentName)
	filepath := filepath.Join(tempDir, filename)
	err = afero.WriteFile(w.FS, filepath, data, w.FilePerm)
	if err != nil {
		return "", fmt.Errorf("failed to write VSA predicate to file: %w", err)
	}

	log.Infof("VSA predicate written to: %s", filepath)
	return filepath, nil
}

// VSALookupResult represents the result of looking up an existing VSA
type VSALookupResult struct {
	Found             bool
	Expired           bool
	VSA               *Predicate
	Timestamp         time.Time
	Envelope          *ssldsse.Envelope // Store the envelope for signature verification
	SignatureVerified bool              // Whether signature verification was performed and succeeded
}

// VSAChecker handles checking for existing VSAs using any VSARetriever
type VSAChecker struct {
	retriever VSARetriever
}

// NewVSAChecker creates a new VSA checker with a VSARetriever
func NewVSAChecker(retriever VSARetriever) *VSAChecker {
	return &VSAChecker{
		retriever: retriever,
	}
}

// InTotoStatement represents an in-toto statement structure
type InTotoStatement struct {
	Type          string    `json:"_type"`
	PredicateType string    `json:"predicateType"`
	Subject       []Subject `json:"subject"`
	Predicate     Predicate `json:"predicate"`
}

// Subject represents a subject in an in-toto statement
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ParseVSAContent parses VSA content from a DSSE envelope and returns a Predicate
// The function handles different payload formats:
// 1. In-toto Statement wrapped in DSSE envelope
// 2. Raw Predicate directly in DSSE payload
func ParseVSAContent(envelope *ssldsse.Envelope) (*Predicate, error) {
	// Decode the base64-encoded payload
	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
	}

	var predicate Predicate

	// Try to parse the payload as an in-toto statement first
	var statement InTotoStatement
	if err := json.Unmarshal(payloadBytes, &statement); err == nil && statement.PredicateType != "" {
		// It's an in-toto statement, the predicate is already unmarshaled
		predicate = statement.Predicate
	} else {
		// The payload is directly the predicate
		if err := json.Unmarshal(payloadBytes, &predicate); err != nil {
			return nil, fmt.Errorf("failed to parse VSA predicate from DSSE payload: %w", err)
		}
	}

	return &predicate, nil
}

// CheckExistingVSAWithVerification looks up existing VSAs for an image and performs all checks including optional signature verification
func (c *VSAChecker) CheckExistingVSAWithVerification(ctx context.Context, imageRef string, expirationThreshold time.Duration, verifySignature bool, publicKeyPath string) (*VSALookupResult, error) {
	result := &VSALookupResult{
		Found:   false,
		Expired: false,
	}

	log.Debugf("Checking for existing VSA for image %s with expiration threshold %v", imageRef, expirationThreshold)

	// Check if retriever is available
	if c.retriever == nil {
		return nil, fmt.Errorf("VSA retriever not available")
	}

	// 1. SINGLE VSA RETRIEVAL
	envelope, err := c.retriever.RetrieveVSA(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve VSA envelope: %w", err)
	}

	if envelope == nil {
		log.Debugf("No VSA envelope found for image %s", imageRef)
		return result, nil
	}

	// Store envelope for potential signature verification
	result.Envelope = envelope

	// 2. OPTIONAL signature verification (if requested) - MUST happen before payload extraction
	if verifySignature {
		if publicKeyPath == "" {
			return nil, fmt.Errorf("public key path required for signature verification")
		}

		if err := verifyVSASignatureFromEnvelope(ctx, envelope, publicKeyPath); err != nil {
			return nil, fmt.Errorf("VSA signature verification failed: %w", err)
		}

		result.SignatureVerified = true
		log.Debugf("VSA signature verification successful for image %s", imageRef)
	}

	// 3. Extract predicate from the envelope (after signature verification)
	predicate, err := ParseVSAContent(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to extract predicate from VSA envelope: %w", err)
	}

	// 4. Parse timestamp and check expiration
	recordTime, err := time.Parse(time.RFC3339, predicate.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VSA timestamp: %w", err)
	}

	result.Found = true
	result.Timestamp = recordTime
	result.Expired = IsVSAExpired(recordTime, expirationThreshold)
	result.VSA = predicate

	log.WithFields(log.Fields{
		"image":                imageRef,
		"vsa_timestamp":        recordTime,
		"expiration_threshold": expirationThreshold,
		"expired":              result.Expired,
		"signature_verified":   verifySignature,
		"verifier":             predicate.Verifier,
	}).Debug("VSA validation completed")

	return result, nil
}

// CheckExistingVSA looks up existing VSAs for an image and determines if they're valid/expired
// This method is kept for backward compatibility
func (c *VSAChecker) CheckExistingVSA(ctx context.Context, imageRef string, expirationThreshold time.Duration) (*VSALookupResult, error) {
	return c.CheckExistingVSAWithVerification(ctx, imageRef, expirationThreshold, false, "")
}

// IsValidVSA checks if a VSA exists and is not expired for the given image
// Returns true if validation should be skipped, false if validation should proceed
func (c *VSAChecker) IsValidVSA(ctx context.Context, imageRef string, expirationThreshold time.Duration) (bool, error) {
	if c.retriever == nil {
		return false, fmt.Errorf("VSA retriever not available")
	}

	result, err := c.CheckExistingVSA(ctx, imageRef, expirationThreshold)
	if err != nil {
		return false, err
	}

	// Return true if VSA exists and is not expired (validation should be skipped)
	return result.Found && !result.Expired, nil
}

// IsVSAExpired checks if a VSA is expired based on the timestamp and threshold
func IsVSAExpired(vsaTimestamp time.Time, expirationThreshold time.Duration) bool {
	// Zero threshold means "never expires"
	if expirationThreshold == 0 {
		return false
	}
	cutoffTime := time.Now().Add(-expirationThreshold)
	return vsaTimestamp.Before(cutoffTime)
}

// CreateVSACheckerFromUploadFlags creates a VSA checker based on available upload flags
// Returns nil if no suitable retriever can be created
func CreateVSACheckerFromUploadFlags(vsaUpload []string) *VSAChecker {
	// Try to create a retriever from the upload flags
	retriever := CreateRetrieverFromUploadFlags(vsaUpload)
	if retriever == nil {
		log.Debugf("No suitable VSA retriever found in upload flags, VSA checking disabled")
		return nil
	}

	return NewVSAChecker(retriever)
}

// CreateRetrieverFromUploadFlags creates a VSA retriever based on upload flags
// Currently supports Rekor, but can be extended for other retrievers
func CreateRetrieverFromUploadFlags(vsaUpload []string) VSARetriever {
	for _, uploadFlag := range vsaUpload {
		config, err := ParseStorageFlag(uploadFlag)
		if err != nil {
			log.Debugf("Failed to parse VSA upload flag '%s': %v", uploadFlag, err)
			continue
		}

		// Create retriever based on backend type
		switch strings.ToLower(config.Backend) {
		case "rekor":
			rekorURL := config.BaseURL
			if rekorURL == "" {
				// Use default if no URL specified
				rekorURL = "https://rekor.sigstore.dev"
			}

			retrieverOpts := RetrievalOptions{
				URL:     rekorURL,
				Timeout: 30 * time.Second,
			}

			retriever, err := NewRekorVSARetriever(retrieverOpts)
			if err != nil {
				log.Debugf("Failed to create Rekor VSA retriever: %v", err)
				continue
			}

			log.Debugf("Created Rekor VSA retriever: %s", rekorURL)
			return retriever
		case "file":
			basePath := config.BaseURL
			if basePath == "" {
				// Use current directory if no path specified
				basePath = "."
			}

			retriever := NewFileVSARetrieverWithOSFs(basePath)
			log.Debugf("Created File VSA retriever with base path: %s", basePath)
			return retriever
		default:
			log.Debugf("No VSA retriever available for backend: %s", config.Backend)
		}
	}

	return nil
}

// verifyVSASignatureFromEnvelope verifies the signature of a DSSE envelope
func verifyVSASignatureFromEnvelope(ctx context.Context, envelope *ssldsse.Envelope, publicKeyPath string) error {
	// Debug: Log envelope details
	log.Debugf("DSSE Envelope details:")
	log.Debugf("  PayloadType: %s", envelope.PayloadType)
	log.Debugf("  Payload length: %d", len(envelope.Payload))
	log.Debugf("  Signatures count: %d", len(envelope.Signatures))

	// Check if payload is base64 encoded
	if len(envelope.Payload) > 0 {
		// Try to decode to see if it's base64
		if _, err := base64.StdEncoding.DecodeString(envelope.Payload); err != nil {
			log.Debugf("Payload is not base64 encoded, treating as raw")
		} else {
			log.Debugf("Payload is base64 encoded")
		}
	}

	// Validate that we have at least one signature
	if len(envelope.Signatures) == 0 {
		return fmt.Errorf("envelope contains no signatures")
	}

	// Extract KeyID from the first signature (we'll use the first one for verification)
	keyID := envelope.Signatures[0].KeyID
	if keyID == "" {
		// If no KeyID is provided, use "default" as fallback
		keyID = "default"
		log.Debugf("No KeyID found in signature, using default fallback")
	} else {
		log.Debugf("Using KeyID from signature: %s", keyID)
	}

	// Load public key using the utility function that supports both files and Kubernetes secrets
	keyBytes, err := utils.PublicKeyFromKeyRef(ctx, publicKeyPath, afero.NewOsFs())
	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}

	// log the public key
	log.Debugf("Public key bytes: %s", string(keyBytes))

	// Convert PEM to crypto.PublicKey
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal PEM to public key: %w", err)
	}
	// Create verifier from the loaded key bytes
	verifier, err := signature.LoadVerifier(publicKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("failed to create verifier from public key: %w", err)
	}

	// Get the public key
	pub, err := verifier.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// log the public key
	log.Debugf("Public key: %s", pub)

	// Create DSSE envelope verifier using go-securesystemslib with extracted KeyID
	ev, err := ssldsse.NewEnvelopeVerifier(&sigd.VerifierAdapter{
		SignatureVerifier: verifier,
		Pub:               pub,
		PubKeyID:          keyID, // Use the actual KeyID from the signature
	})
	if err != nil {
		return fmt.Errorf("failed to create envelope verifier: %w", err)
	}

	// Verify the signature
	acceptedSignatures, err := ev.Verify(ctx, envelope)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	if len(acceptedSignatures) == 0 {
		return fmt.Errorf("signature verification failed: no signatures were accepted")
	}

	return nil
}

// isImageDigest checks if the identifier is an image digest
func isImageDigest(identifier string) bool {
	// Pure image digests typically start with sha256: or sha512:
	digestRegex := regexp.MustCompile(`^sha(256|512):[a-f0-9]+$`)
	if digestRegex.MatchString(identifier) {
		return true
	}

	// Check if it's an image reference with digest (e.g., registry.com/image@sha256:abc123)
	if strings.Contains(identifier, "@") {
		parts := strings.Split(identifier, "@")
		if len(parts) == 2 {
			digest := parts[1]
			return digestRegex.MatchString(digest)
		}
	}

	return false
}

// isPureDigest checks if the identifier is a pure digest (like sha256:abc123) without repository
func isPureDigest(identifier string) bool {
	digestRegex := regexp.MustCompile(`^sha(256|512):[a-f0-9]+$`)
	return digestRegex.MatchString(identifier)
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

// DetectIdentifierType detects the type of VSA identifier
func DetectIdentifierType(identifier string) IdentifierType {
	// Check if it's a file path first - this is more specific than image references
	if isFilePath(identifier) {
		return IdentifierFile
	}

	// Check for image digests (including pure digests)
	if isImageDigest(identifier) {
		return IdentifierImageDigest
	}

	// Try image reference parse - but be more restrictive
	// Empty strings and pure digests should not be considered image references
	if identifier != "" && !isPureDigest(identifier) {
		if _, err := name.ParseReference(identifier); err == nil {
			return IdentifierImageReference
		}
	}

	// last resort: keep as reference so users can pass bare names like "nginx:latest"
	if identifier != "" && !isPureDigest(identifier) {
		if _, err := name.ParseReference("docker.io/library/" + identifier); err == nil {
			return IdentifierImageReference
		}
	}
	return IdentifierFile
}

// IsImageReference checks if the identifier is an image reference
func IsImageReference(identifier string) bool {
	// First check if it's an image digest (more specific)
	if DetectIdentifierType(identifier) == IdentifierImageDigest {
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
		if DetectIdentifierType(identifier) != IdentifierImageDigest {
			return false
		}
	}

	return true
}

// IsValidVSAIdentifier validates VSA identifier format
func IsValidVSAIdentifier(identifier string) bool {
	// Basic validation for VSA identifier
	if len(identifier) == 0 {
		return false
	}

	// Check if it's a valid identifier type
	identifierType := DetectIdentifierType(identifier)
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
		return DetectIdentifierType(identifier) == IdentifierImageDigest
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

// ParseVSAExpirationDuration parses a duration string with support for h, d, w, m suffixes
func ParseVSAExpirationDuration(s string) (time.Duration, error) {
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

// ConvertYAMLToJSON converts YAML interface{} types to proper types for JSON marshaling
func ConvertYAMLToJSON(data interface{}) interface{} {
	switch v := data.(type) {
	case map[interface{}]interface{}:
		result := make(map[string]interface{})
		for k, val := range v {
			if strKey, ok := k.(string); ok {
				result[strKey] = ConvertYAMLToJSON(val)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, val := range v {
			result[i] = ConvertYAMLToJSON(val)
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, val := range v {
			result[k] = ConvertYAMLToJSON(val)
		}
		return result
	default:
		return v
	}
}

// ExtractDigestFromImageRef extracts the digest from an image reference
func ExtractDigestFromImageRef(imageRef string) (string, error) {
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

// isFilePathLike checks if an identifier looks like a file path
// This handles the case where name.ParseReference incorrectly accepts file paths as valid image references
func IsFilePathLike(identifier string) bool {
	// Check for relative path prefixes (most reliable indicator)
	if strings.HasPrefix(identifier, "./") || strings.HasPrefix(identifier, "../") {
		return true
	}

	// Check for absolute paths
	if filepath.IsAbs(identifier) {
		return true
	}

	// Check for file extensions (but not for image tags like :latest)
	if filepath.Ext(identifier) != "" && !strings.Contains(identifier, ":") {
		return true
	}

	// Check for path separators but not registry separators
	// Image references can have / but not \ or multiple / in a row
	if strings.Contains(identifier, "\\") || strings.Contains(identifier, "//") {
		return true
	}

	return false
}
