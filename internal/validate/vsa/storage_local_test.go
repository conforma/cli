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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalBackend(t *testing.T) {
	tests := []struct {
		name        string
		config      *StorageConfig
		expectError bool
	}{
		{
			name: "valid local backend config",
			config: &StorageConfig{
				Backend: "local",
				BaseURL: "/tmp/vsa",
			},
			expectError: false,
		},
		{
			name: "empty base path",
			config: &StorageConfig{
				Backend: "local",
				BaseURL: "",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := NewLocalBackend(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, backend)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, backend)
				localBackend := backend.(*LocalBackend)

				// Special case for empty base path - should use default
				expectedPath := tt.config.BaseURL
				if tt.name == "empty base path" && expectedPath == "" {
					expectedPath = "./vsa-upload"
				}
				assert.Equal(t, expectedPath, localBackend.basePath)
			}
		})
	}
}

func TestLocalBackend_Name(t *testing.T) {
	backend := &LocalBackend{basePath: "/tmp/test"}
	assert.Equal(t, "Local (/tmp/test)", backend.Name())
}

func TestLocalBackend_Upload_ComponentVSA(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	backend := &LocalBackend{basePath: tempDir}

	ctx := context.Background()
	testEnvelope := `{"payload":"test-component","signatures":[{"sig":"test-sig"}]}`
	imageRef := "quay.io/test/image@sha256:abc123def456"

	err := backend.Upload(ctx, []byte(testEnvelope), imageRef)
	require.NoError(t, err)

	// Verify file was created (should contain hash of imageRef)
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	require.Len(t, files, 1)

	filename := files[0].Name()
	assert.True(t, strings.HasPrefix(filename, "vsa-"))
	assert.True(t, strings.HasSuffix(filename, ".json"))
	assert.Contains(t, filename, "-") // Should have timestamp and hash parts

	// Verify file content
	filePath := filepath.Join(tempDir, filename)
	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, testEnvelope, string(content))
}

func TestLocalBackend_Upload_SnapshotVSA(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	backend := &LocalBackend{basePath: tempDir}

	ctx := context.Background()
	testEnvelope := `{"payload":"test-snapshot","signatures":[{"sig":"test-sig"}]}`
	imageRef := "" // Empty for snapshot VSAs

	err := backend.Upload(ctx, []byte(testEnvelope), imageRef)
	require.NoError(t, err)

	// Verify file was created with snapshot naming
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	require.Len(t, files, 1)

	filename := files[0].Name()
	assert.True(t, strings.HasPrefix(filename, "vsa-snapshot-"))
	assert.True(t, strings.HasSuffix(filename, ".json"))

	// Verify file content
	filePath := filepath.Join(tempDir, filename)
	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, testEnvelope, string(content))
}

func TestLocalBackend_Upload_FilenameUniqueness(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	backend := &LocalBackend{basePath: tempDir}

	ctx := context.Background()
	testEnvelope := `{"payload":"test","signatures":[{"sig":"test"}]}`
	imageRef := "quay.io/test/image@sha256:same"

	// Upload same content multiple times
	err1 := backend.Upload(ctx, []byte(testEnvelope), imageRef)
	require.NoError(t, err1)

	err2 := backend.Upload(ctx, []byte(testEnvelope), imageRef)
	require.NoError(t, err2)

	// Should have created two different files due to timestamps
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.Len(t, files, 2)

	// Both should be valid component VSA files
	for _, file := range files {
		assert.True(t, strings.HasPrefix(file.Name(), "vsa-"))
		assert.True(t, strings.HasSuffix(file.Name(), ".json"))
		assert.False(t, strings.HasPrefix(file.Name(), "vsa-snapshot-"))
	}
}

func TestLocalBackend_Upload_SnapshotFilenameUniqueness(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	backend := &LocalBackend{basePath: tempDir}

	ctx := context.Background()
	testEnvelope := `{"payload":"test-snapshot","signatures":[{"sig":"test"}]}`
	imageRef := "" // Empty for snapshots

	// Upload multiple snapshot VSAs
	err1 := backend.Upload(ctx, []byte(testEnvelope), imageRef)
	require.NoError(t, err1)

	err2 := backend.Upload(ctx, []byte(testEnvelope), imageRef)
	require.NoError(t, err2)

	// Should have created two different files due to timestamps
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.Len(t, files, 2)

	// Both should be snapshot VSA files
	for _, file := range files {
		assert.True(t, strings.HasPrefix(file.Name(), "vsa-snapshot-"))
		assert.True(t, strings.HasSuffix(file.Name(), ".json"))
	}
}

func TestLocalBackend_Upload_WriteError(t *testing.T) {
	// Use non-existent directory to trigger write error (without creating it first)
	backend := &LocalBackend{basePath: "/non/existent/path"}

	ctx := context.Background()
	testEnvelope := `{"payload":"test","signatures":[{"sig":"test"}]}`
	imageRef := "test-image@sha256:abc123"

	err := backend.Upload(ctx, []byte(testEnvelope), imageRef)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create directory")
}

func TestLocalBackend_Upload_DirectoryCreation(t *testing.T) {
	// Create base temp directory
	baseDir := t.TempDir()

	// Use a subdirectory that doesn't exist yet
	subDir := filepath.Join(baseDir, "subdir", "nested")
	backend := &LocalBackend{basePath: subDir}

	ctx := context.Background()
	testEnvelope := `{"payload":"test","signatures":[{"sig":"test"}]}`
	imageRef := "test-image@sha256:abc123"

	// This should create the directory structure
	err := backend.Upload(ctx, []byte(testEnvelope), imageRef)
	require.NoError(t, err)

	// Verify directory was created
	_, err = os.Stat(subDir)
	assert.NoError(t, err)

	// Verify file was created
	files, err := os.ReadDir(subDir)
	require.NoError(t, err)
	assert.Len(t, files, 1)
}
