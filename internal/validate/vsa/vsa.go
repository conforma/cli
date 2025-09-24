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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/applicationsnapshot"
)

// Predicate represents a Verification Summary Attestation (VSA) predicate.
type Predicate struct {
	ImageRef     string                 `json:"imageRef"`
	Timestamp    string                 `json:"timestamp"`
	Verifier     string                 `json:"verifier"`
	PolicySource string                 `json:"policySource"`
	Component    map[string]interface{} `json:"component"`
	Results      *FilteredReport        `json:"results,omitempty"` // Filtered report containing the target and its children if it's a manifest
}

// Generator handles VSA predicate generation
type Generator struct {
	Report    applicationsnapshot.Report
	Component applicationsnapshot.Component
}

// NewGenerator creates a new VSA predicate generator
func NewGenerator(report applicationsnapshot.Report, comp applicationsnapshot.Component) *Generator {
	return &Generator{
		Report:    report,
		Component: comp,
	}
}

// FilteredReport represents a filtered version of the application snapshot report
// that contains the target component and its architecture variants if it's a manifest.
type FilteredReport struct {
	Snapshot      string                           `json:"snapshot"`
	Components    []applicationsnapshot.Component  `json:"components"`
	Key           string                           `json:"key"`
	Policy        ecc.EnterpriseContractPolicySpec `json:"policy"`
	EcVersion     string                           `json:"ec-version"`
	EffectiveTime time.Time                        `json:"effective-time"`
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

// FilterReportForTargetRef filters the report based on the target image reference.
// If the target is an image index (manifest), it includes the index and all its child manifests.
// If the target is a single-arch image, it includes only that image.
//
// Parameters:
//   - report: The complete application snapshot report
//   - targetRef: The container image reference to filter for
//
// Returns:
//   - A FilteredReport containing the target and its children if it's a manifest
func FilterReportForTargetRef(report applicationsnapshot.Report, targetRef string) *FilteredReport {
	exp := report.Expansion
	targetRef = normalizeIndexRef(targetRef, exp)

	include := map[string]struct{}{}
	if exp != nil {
		if imgs, ok := exp.GetChildrenByIndex(targetRef); ok {
			// This is an image index, include the index and all its children
			include[targetRef] = struct{}{}
			for _, c := range imgs {
				include[c] = struct{}{}
			}
		} else {
			// This is a single-arch image, include only itself
			include[targetRef] = struct{}{}
		}
	} else {
		// No expansion info available, include only the target
		include[targetRef] = struct{}{}
	}

	comps := make([]applicationsnapshot.Component, 0, len(report.Components))
	for _, c := range report.Components {
		if _, ok := include[c.ContainerImage]; ok {
			comps = append(comps, c)
		}
	}

	return &FilteredReport{
		Snapshot:      report.Snapshot,
		Components:    comps,
		Key:           report.Key,
		Policy:        report.Policy,
		EcVersion:     report.EcVersion,
		EffectiveTime: report.EffectiveTime,
	}
}

// GeneratePredicate creates a Predicate for a validated image/component.
func (g *Generator) GeneratePredicate(ctx context.Context) (*Predicate, error) {
	log.Infof("Generating VSA predicate for image: %s", g.Component.ContainerImage)

	// Compose the component info as a map
	componentInfo := map[string]interface{}{
		"name":           g.Component.Name,
		"containerImage": g.Component.ContainerImage,
		"source":         g.Component.Source,
	}

	policySource := ""
	if g.Report.Policy.Name != "" {
		policySource = g.Report.Policy.Name
	}

	// Filter the report to include the target component and its architecture variants if it's a manifest
	filteredReport := FilterReportForTargetRef(g.Report, g.Component.ContainerImage)

	return &Predicate{
		ImageRef:     g.Component.ContainerImage,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Verifier:     "ec-cli",
		PolicySource: policySource,
		Component:    componentInfo,
		Results:      filteredReport,
	}, nil
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
	log.Infof("Writing VSA for image: %s", predicate.ImageRef)

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

	// Write to file
	filename := fmt.Sprintf("vsa-%s.json", predicate.Component["name"])
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
	Found     bool
	Expired   bool
	VSA       *Predicate
	Timestamp time.Time
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

// extractPredicateFromEnvelope extracts the VSA predicate from a DSSE envelope
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

// CheckExistingVSA looks up existing VSAs for an image and determines if they're valid/expired
func (c *VSAChecker) CheckExistingVSA(ctx context.Context, imageRef string, expirationThreshold time.Duration) (*VSALookupResult, error) {
	result := &VSALookupResult{
		Found:   false,
		Expired: false,
	}

	log.Debugf("Checking for existing VSA for image %s with expiration threshold %v", imageRef, expirationThreshold)

	// Check if retriever is available
	if c.retriever == nil {
		return nil, fmt.Errorf("VSA retriever not available")
	}

	// Retrieve VSA envelope for this image reference
	// Pass the original imageRef to the retriever, which can extract what it needs
	envelope, err := c.retriever.RetrieveVSA(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve VSA envelope: %w", err)
	}

	if envelope == nil {
		log.Debugf("No VSA envelope found for image %s", imageRef)
		return result, nil
	}

	// Extract predicate from the envelope
	predicate, err := extractPredicateFromEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to extract predicate from VSA envelope: %w", err)
	}

	// Parse timestamp from predicate
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
		"verifier":             predicate.Verifier,
		"policy_source":        predicate.PolicySource,
	}).Debug("Found VSA envelope")

	return result, nil
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
