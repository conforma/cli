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

package evaluator

import (
	"context"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

// TestNewOPAEvaluator tests the constructor NewOPAEvaluator.
func TestNewOPAEvaluator(t *testing.T) {
	evaluator, err := NewOPAEvaluator()
	assert.NoError(t, err, "Expected no error from NewOPAEvaluator")
	assert.Equal(t, evaluator, opaEvaluator{})
}

func TestEvaluate(t *testing.T) {
	opaEval := opaEvaluator{}

	outcomes, err := opaEval.Evaluate(context.Background(), EvaluationTarget{})
	assert.NoError(t, err, "Expected no error from Evaluate")
	assert.Equal(t, []Outcome{}, outcomes)
}

// Test Destroy method of opaEvaluator.
func TestDestroy(t *testing.T) {
	// Setup an in-memory filesystem
	fs := afero.NewMemMapFs()
	workDir := "/tmp/workdir"

	// Define test cases
	testCases := []struct {
		name         string
		workDir      string
		EC_DEBUG     bool
		expectRemove bool
	}{
		{
			name:         "Empty workDir, EC_DEBUG not set",
			workDir:      "",
			EC_DEBUG:     false,
			expectRemove: false,
		},
		{
			name:         "Non-empty workDir, EC_DEBUG not set",
			workDir:      workDir,
			EC_DEBUG:     false,
			expectRemove: true,
		},
		{
			name:         "Non-empty workDir, EC_DEBUG set",
			workDir:      workDir,
			EC_DEBUG:     true,
			expectRemove: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up the environment
			if tc.workDir != "" {
				err := fs.MkdirAll(tc.workDir, 0755)
				assert.NoError(t, err, "Failed to create workDir in in-memory filesystem")
			}

			if tc.EC_DEBUG {
				os.Setenv("EC_DEBUG", "true")
			} else {
				os.Unsetenv("EC_DEBUG")
			}

			// Initialize the evaluator
			opaEval := opaEvaluator{
				workDir: tc.workDir,
				fs:      fs,
			}

			// Call Destroy
			opaEval.Destroy()

			// Verify the result
			exists, err := afero.DirExists(fs, tc.workDir)
			assert.NoError(t, err, "Error checking if workDir exists after Destroy")

			if tc.expectRemove {
				assert.False(t, exists, "workDir should be removed")
			} else {
				assert.True(t, exists, "workDir should not be removed")
			}

			// Clean up for next test
			_ = fs.RemoveAll(tc.workDir)
			os.Unsetenv("EC_DEBUG")
		})
	}
}

// TestCapabilitiesPath tests the CapabilitiesPath method of opaEvaluator.
func TestCapabilitiesPath(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name     string
		workDir  string
		expected string
	}{
		{
			name:     "Non-empty workDir",
			workDir:  "/tmp/workdir",
			expected: "/tmp/workdir/capabilities.json",
		},
		{
			name:     "Root workDir",
			workDir:  "/",
			expected: "/capabilities.json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock filesystem (though not strictly needed for this test)
			fs := afero.NewMemMapFs()

			// Initialize the evaluator with test data
			opaEval := opaEvaluator{
				workDir: tc.workDir,
				fs:      fs,
			}

			// Call CapabilitiesPath
			result := opaEval.CapabilitiesPath()

			// Verify the result
			assert.Equal(t, tc.expected, result, "CapabilitiesPath should return the expected path")
		})
	}
}
