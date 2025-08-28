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

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/oci"
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
	if pinned, ok := exp.IndexAliases[ref]; ok {
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
		if imgs, ok := exp.ChildrenByIndex[targetRef]; ok {
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
