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

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

// SnapshotVSAWriter handles writing application snapshot VSA predicates to files
type SnapshotVSAWriter struct {
	FS            afero.Fs    // defaults to afero.NewOsFs()
	TempDirPrefix string      // defaults to "snapshot-vsa-"
	FilePerm      os.FileMode // defaults to 0600
}

// NewSnapshotVSAWriter creates a new application snapshot VSA file writer
func NewSnapshotVSAWriter() *SnapshotVSAWriter {
	return &SnapshotVSAWriter{
		FS:            afero.NewOsFs(),
		TempDirPrefix: "snapshot-vsa-",
		FilePerm:      0o600,
	}
}

// WritePredicate writes the Report as a VSA predicate to a file
func (w *SnapshotVSAWriter) WritePredicate(report Report) (string, error) {
	log.Infof("Writing application snapshot VSA")

	// Serialize with indent
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal application snapshot VSA: %w", err)
	}

	// Create temp directory
	tempDir, err := afero.TempDir(w.FS, "", w.TempDirPrefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Write to file
	filename := "application-snapshot-vsa.json"
	filepath := filepath.Join(tempDir, filename)
	err = afero.WriteFile(w.FS, filepath, data, w.FilePerm)
	if err != nil {
		return "", fmt.Errorf("failed to write application snapshot VSA to file: %w", err)
	}

	log.Infof("Application snapshot VSA written to: %s", filepath)
	return filepath, nil
}

type SnapshotVSAGenerator struct {
	Report Report
}

// NewSnapshotVSAGenerator creates a new VSA predicate generator for application snapshots
func NewSnapshotVSAGenerator(report Report) *SnapshotVSAGenerator {
	return &SnapshotVSAGenerator{
		Report: report,
	}
}

// GeneratePredicate creates a VSA predicate for the entire application snapshot
func (g *SnapshotVSAGenerator) GeneratePredicate(ctx context.Context) (Report, error) {
	log.Infof("Generating application snapshot VSA predicate with %d components", len(g.Report.Components))

	return g.Report, nil
}
