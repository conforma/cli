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
	"strings"
	"time"

	ecapi "github.com/conforma/crds/api/v1alpha1"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigd "github.com/sigstore/sigstore/pkg/signature/dsse"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/applicationsnapshot"
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

	return &predicate, nil
}

// extractPredicateFromEnvelope extracts the VSA predicate from a DSSE envelope
// This is a legacy function that only handles direct predicate extraction
func extractPredicateFromEnvelope(envelope *ssldsse.Envelope) (*Predicate, error) {
	// Check if payload is already decoded or needs base64 decoding
	var payloadBytes []byte
	var err error

	// Try to decode as base64 first
	payloadBytes, err = base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		// If base64 decoding fails, treat as raw JSON string
		payloadBytes = []byte(envelope.Payload)
	}

	// Parse the payload as JSON to extract the predicate
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse envelope payload: %w", err)
	}

	// Extract the predicate from the payload
	predicateData, ok := payload["predicate"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("envelope payload does not contain predicate")
	}

	// Convert to Predicate struct
	predicateBytes, err := json.Marshal(predicateData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal predicate data: %w", err)
	}

	var predicate Predicate
	if err := json.Unmarshal(predicateBytes, &predicate); err != nil {
		return nil, fmt.Errorf("failed to parse predicate: %w", err)
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

		if err := verifyVSASignatureFromEnvelope(envelope, publicKeyPath); err != nil {
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
func verifyVSASignatureFromEnvelope(envelope *ssldsse.Envelope, publicKeyPath string) error {
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
		PubKeyID:          "default", // Match the KeyID we set in the signature
	})
	if err != nil {
		return fmt.Errorf("failed to create envelope verifier: %w", err)
	}

	// Verify the signature
	ctx := context.Background()
	acceptedSignatures, err := ev.Verify(ctx, envelope)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	if len(acceptedSignatures) == 0 {
		return fmt.Errorf("signature verification failed: no signatures were accepted")
	}

	return nil
}
