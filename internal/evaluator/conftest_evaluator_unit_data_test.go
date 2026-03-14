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

// This file contains unit tests for data directory preparation and processing.
// It includes tests for:
// - Data directory preparation (TestPrepareDataDirs)
// These tests focus on how the evaluator prepares and processes data directories
// that are passed to OPA policies during evaluation.

//go:build unit

package evaluator

import (
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareDataDirs(t *testing.T) {
	tests := []struct {
		name         string
		filePaths    []string // ordered list of file paths to create
		expectedDirs []string // expected directories in same order
	}{
		{
			name: "files in subdirectories",
			filePaths: []string{
				"foo/data.json",
				"another/path/info.yaml",
				"third/deep/path/config.yml",
				"some/path/no-data.txt",
			},
			expectedDirs: []string{
				"foo",
				"another/path",
				"third/deep/path",
			},
		},
		{
			name: "realistic konflux example",
			filePaths: []string{
				"data/a67f0d7cc/rule_data.yml",
				"data/a67f0d7cc/required_tasks.yml",
				"data/a67f0d7cc/known_rpm_repositories.yml",
				"data/e8a615778/data/data/trusted_tekton_tasks.yml",
				"data/config/config.json",
			},
			expectedDirs: []string{
				"data/a67f0d7cc",
				"data/e8a615778/data/data",
				"data/config",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary filesystem
			fs := afero.NewMemMapFs()

			// Create the base data directory
			dataDir := "/test/data"
			require.NoError(t, fs.MkdirAll(dataDir, 0755))

			// Create the test files with minimal content
			for _, filePath := range tt.filePaths {
				fullPath := filepath.Join(dataDir, filePath)
				require.NoError(t, fs.MkdirAll(filepath.Dir(fullPath), 0755))
				require.NoError(t, afero.WriteFile(fs, fullPath, []byte("test"), 0644))
			}

			// Create evaluator instance
			evaluator := conftestEvaluator{
				dataDir: dataDir,
				fs:      fs,
			}

			// Call prepareDataDirs with the base data directory as data source
			// In real usage, dataSourceDirs would be the directories returned by GetPolicy
			actualDirs, err := evaluator.prepareDataDirs([]string{dataDir})
			require.NoError(t, err)

			// Convert expected relative paths to absolute paths
			expectedAbsolute := make([]string, len(tt.expectedDirs))
			for i, dir := range tt.expectedDirs {
				if dir == "." {
					expectedAbsolute[i] = dataDir
				} else {
					expectedAbsolute[i] = filepath.Join(dataDir, dir)
				}
			}

			assert.ElementsMatch(t, expectedAbsolute, actualDirs)
		})
	}
}
