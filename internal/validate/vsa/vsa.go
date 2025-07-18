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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/cosign/v2/pkg/oci"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
)

// Predicate represents a Verification Summary Attestation (VSA) predicate.
type Predicate struct {
	ImageRef         string                 `json:"imageRef"`
	ValidationResult string                 `json:"validationResult"`
	Timestamp        string                 `json:"timestamp"`
	Verifier         string                 `json:"verifier"`
	PolicySource     string                 `json:"policySource"`
	Component        map[string]interface{} `json:"component"`
	RuleResults      []evaluator.Result     `json:"ruleResults"`
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

// GeneratePredicate creates a Predicate for a validated image/component.
func (g *Generator) GeneratePredicate(ctx context.Context) (*Predicate, error) {
	log.Infof("Generating VSA predicate for image: %s", g.Component.ContainerImage)

	// Compose the component info as a map
	componentInfo := map[string]interface{}{
		"name":           g.Component.Name,
		"containerImage": g.Component.ContainerImage,
		"source":         g.Component.Source,
	}

	// Compose rule results: combine violations, warnings, and successes
	ruleResults := make([]evaluator.Result, 0, len(g.Component.Violations)+len(g.Component.Warnings)+len(g.Component.Successes))
	ruleResults = append(ruleResults, g.Component.Violations...)
	ruleResults = append(ruleResults, g.Component.Warnings...)
	ruleResults = append(ruleResults, g.Component.Successes...)

	validationResult := "failed"
	if g.Component.Success {
		validationResult = "passed"
	}

	policySource := ""
	if g.Report.Policy.Name != "" {
		policySource = g.Report.Policy.Name
	}

	return &Predicate{
		ImageRef:         g.Component.ContainerImage,
		ValidationResult: validationResult,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Verifier:         "ec-cli",
		PolicySource:     policySource,
		Component:        componentInfo,
		RuleResults:      ruleResults,
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

// AttestationUploader is a function that uploads an attestation and returns a result string or error
// This allows pluggable upload logic (OCI, Rekor, None, or custom)
type AttestationUploader func(ctx context.Context, att oci.Signature, location string) (string, error)

// Built-in uploaders
func OCIUploader(ctx context.Context, att oci.Signature, location string) (string, error) {
	log.Infof("Uploading VSA attestation to OCI registry for %s", location)
	// TODO: Implement OCI upload logic here
	return "", fmt.Errorf("OCI upload not implemented")
}

func RekorUploader(ctx context.Context, att oci.Signature, location string) (string, error) {
	log.Infof("Uploading VSA attestation to Rekor for %s", location)
	// TODO: Implement Rekor upload logic here
	return "", fmt.Errorf("rekor upload not implemented")
}

func NoopUploader(ctx context.Context, att oci.Signature, location string) (string, error) {
	log.Infof("Upload type is 'none'; skipping upload for %s", location)
	return "", nil
}
