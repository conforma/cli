// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package applicationsnapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

// SnapshotComponentDetail represents detailed information about a component in the snapshot summary
type SnapshotComponentDetail struct {
	Name           string `json:"name"`
	ContainerImage string `json:"containerImage"`
	Success        bool   `json:"success"`
	Violations     int    `json:"violations"`
	Warnings       int    `json:"warnings"`
	Successes      int    `json:"successes"`
}

// SnapshotSummary represents the summary information for a snapshot predicate
type SnapshotSummary struct {
	Snapshot         string                    `json:"snapshot"`
	Components       int                       `json:"components"`
	Success          bool                      `json:"success"`
	Key              string                    `json:"key"`
	EcVersion        string                    `json:"ec_version"`
	ComponentDetails []SnapshotComponentDetail `json:"component_details"`
	Violations       int                       `json:"Violations"`
	Warnings         int                       `json:"Warnings"`
}

// SnapshotPredicate represents a predicate for an entire application snapshot
type SnapshotPredicate struct {
	Policy    ecc.EnterpriseContractPolicySpec `json:"policy"`
	ImageRefs []string                         `json:"imageRefs"`
	Timestamp string                           `json:"timestamp"`
	Status    string                           `json:"status"`
	Verifier  string                           `json:"verifier"`
	Summary   SnapshotSummary                  `json:"summary"`
}

// SnapshotPredicateWriter handles writing application snapshot predicates to files
type SnapshotPredicateWriter struct {
	FS            afero.Fs    // defaults to afero.NewOsFs()
	TempDirPrefix string      // defaults to "snapshot-predicate-"
	FilePerm      os.FileMode // defaults to 0o600
}

// NewSnapshotPredicateWriter creates a new application snapshot predicate file writer
func NewSnapshotPredicateWriter() *SnapshotPredicateWriter {
	return &SnapshotPredicateWriter{
		FS:            afero.NewOsFs(),
		TempDirPrefix: "snapshot-predicate-",
		FilePerm:      0o600,
	}
}

// WritePredicate writes the SnapshotPredicate as a JSON file to a temp directory and returns the path
func (s *SnapshotPredicateWriter) WritePredicate(predicate *SnapshotPredicate) (string, error) {
	log.Infof("Writing application snapshot VSA")

	// Serialize with indent
	data, err := json.MarshalIndent(predicate, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal application snapshot VSA predicate: %w", err)
	}

	// Create temp directory
	tempDir, err := afero.TempDir(s.FS, "", s.TempDirPrefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Write to file with same naming convention as old VSA
	filename := "application-snapshot-vsa.json"
	filepath := filepath.Join(tempDir, filename)
	err = afero.WriteFile(s.FS, filepath, data, s.FilePerm)
	if err != nil {
		return "", fmt.Errorf("failed to write application snapshot VSA predicate to file: %w", err)
	}

	log.Infof("Application snapshot VSA written to: %s", filepath)
	return filepath, nil
}

// SnapshotPredicateGenerator generates predicates for application snapshots
type SnapshotPredicateGenerator struct {
	Report Report
}

// NewSnapshotPredicateGenerator creates a new predicate generator for application snapshots
func NewSnapshotPredicateGenerator(report Report) *SnapshotPredicateGenerator {
	return &SnapshotPredicateGenerator{
		Report: report,
	}
}

// GeneratePredicate creates a predicate for the entire application snapshot
func (s *SnapshotPredicateGenerator) GeneratePredicate(ctx context.Context) (*SnapshotPredicate, error) {
	log.Infof("Generating application snapshot EC predicate with %d components", len(s.Report.Components))

	// Collect all image references from all components
	imageRefs := s.getAllImageRefs()

	// Determine overall status
	status := "failed"
	if s.Report.Success {
		status = "passed"
	}

	// Add detailed component breakdown and calculate totals
	components := make([]SnapshotComponentDetail, 0, len(s.Report.Components))
	totalViolations := 0
	totalWarnings := 0

	for _, comp := range s.Report.Components {
		compViolations := len(comp.Violations)
		compWarnings := len(comp.Warnings)

		compDetails := SnapshotComponentDetail{
			Name:           comp.Name,
			ContainerImage: comp.ContainerImage,
			Success:        comp.Success,
			Violations:     compViolations,
			Warnings:       compWarnings,
			Successes:      len(comp.Successes),
		}
		components = append(components, compDetails)

		// Add to totals
		totalViolations += compViolations
		totalWarnings += compWarnings
	}

	// Create summary with component information
	summary := SnapshotSummary{
		Snapshot:         s.Report.Snapshot,
		Components:       len(s.Report.Components),
		Success:          s.Report.Success,
		Key:              s.Report.Key,
		EcVersion:        s.Report.EcVersion,
		ComponentDetails: components,
		Violations:       totalViolations,
		Warnings:         totalWarnings,
	}

	return &SnapshotPredicate{
		Policy:    s.Report.Policy, // This contains the resolved policy with pinned URLs
		ImageRefs: imageRefs,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    status,
		Verifier:  "conforma",
		Summary:   summary,
	}, nil
}

// getAllImageRefs returns all image references from all components including expansion info
func (s *SnapshotPredicateGenerator) getAllImageRefs() []string {
	var allImageRefs []string

	for _, comp := range s.Report.Components {
		// Add the main component image reference
		allImageRefs = append(allImageRefs, comp.ContainerImage)

		// If we have expansion info, add the index and all architecture-specific images
		if s.Report.Expansion != nil {
			// Get the normalized index reference
			normalizedRef := normalizeIndexRef(comp.ContainerImage, s.Report.Expansion)

			// Add the index reference if it's different from the component image
			if normalizedRef != comp.ContainerImage {
				allImageRefs = append(allImageRefs, normalizedRef)
			}

			// Get all child images for this index
			if children, ok := s.Report.Expansion.GetChildrenByIndex(normalizedRef); ok {
				allImageRefs = append(allImageRefs, children...)
			}
		}
	}

	// Remove duplicates and return
	return removeDuplicateStrings(allImageRefs)
}

// normalizeIndexRef normalizes an image reference to its pinned digest form if it's an index
func normalizeIndexRef(ref string, exp *ExpansionInfo) string {
	if exp == nil {
		return ref
	}
	if pinned, ok := exp.GetIndexAlias(ref); ok {
		return pinned
	}
	return ref
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
