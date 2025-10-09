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

package vsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateVSARetriever tests the CreateVSARetriever function
func TestCreateVSARetriever(t *testing.T) {
	tests := []struct {
		name           string
		vsaRetrieval   []string
		vsaIdentifier  string
		images         string
		expectError    bool
		checkRetriever func(t *testing.T, retriever VSARetriever)
	}{
		{
			name:          "explicit rekor retrieval",
			vsaRetrieval:  []string{"rekor"},
			vsaIdentifier: "",
			images:        "",
			expectError:   false,
			checkRetriever: func(t *testing.T, retriever VSARetriever) {
				assert.NotNil(t, retriever)
			},
		},
		{
			name:          "explicit file retrieval",
			vsaRetrieval:  []string{"file"},
			vsaIdentifier: "",
			images:        "",
			expectError:   true, // "file" is not a valid retrieval backend
		},
		{
			name:          "file identifier auto-detection",
			vsaRetrieval:  []string{},
			vsaIdentifier: "/path/to/vsa.json",
			images:        "",
			expectError:   false,
			checkRetriever: func(t *testing.T, retriever VSARetriever) {
				assert.NotNil(t, retriever)
			},
		},
		{
			name:          "image digest identifier auto-detection",
			vsaRetrieval:  []string{},
			vsaIdentifier: "sha256:abc123def456789",
			images:        "",
			expectError:   false,
			checkRetriever: func(t *testing.T, retriever VSARetriever) {
				assert.NotNil(t, retriever)
			},
		},
		{
			name:          "image reference identifier auto-detection",
			vsaRetrieval:  []string{},
			vsaIdentifier: "registry.io/repo:tag",
			images:        "",
			expectError:   false,
			checkRetriever: func(t *testing.T, retriever VSARetriever) {
				assert.NotNil(t, retriever)
			},
		},
		{
			name:          "snapshot validation with images",
			vsaRetrieval:  []string{},
			vsaIdentifier: "",
			images:        "snapshot.yaml",
			expectError:   false,
			checkRetriever: func(t *testing.T, retriever VSARetriever) {
				assert.NotNil(t, retriever)
			},
		},
		{
			name:          "default file retriever",
			vsaRetrieval:  []string{},
			vsaIdentifier: "",
			images:        "",
			expectError:   false,
			checkRetriever: func(t *testing.T, retriever VSARetriever) {
				assert.NotNil(t, retriever)
			},
		},
		{
			name:          "invalid retrieval backend",
			vsaRetrieval:  []string{"invalid"},
			vsaIdentifier: "",
			images:        "",
			expectError:   true,
		},
		{
			name:          "unsupported identifier type",
			vsaRetrieval:  []string{},
			vsaIdentifier: "invalid-identifier-format",
			images:        "",
			expectError:   false, // This will be detected as a file path
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retriever, err := CreateVSARetriever(tt.vsaRetrieval, tt.vsaIdentifier, tt.images)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkRetriever != nil {
					tt.checkRetriever(t, retriever)
				}
			}
		})
	}
}
