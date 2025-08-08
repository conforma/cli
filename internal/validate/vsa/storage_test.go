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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseStorageFlag(t *testing.T) {
	tests := []struct {
		name        string
		storageFlag string
		expected    *StorageConfig
		expectError bool
	}{
		{
			name:        "rekor with default URL",
			storageFlag: "rekor@https://rekor.sigstore.dev",
			expected: &StorageConfig{
				Backend:    "rekor",
				BaseURL:    "https://rekor.sigstore.dev",
				Parameters: map[string]string{},
			},
			expectError: false,
		},
		{
			name:        "local file backend",
			storageFlag: "local@/tmp/vsa",
			expected: &StorageConfig{
				Backend:    "local",
				BaseURL:    "/tmp/vsa",
				Parameters: map[string]string{},
			},
			expectError: false,
		},
		{
			name:        "rekor with custom parameters",
			storageFlag: "rekor@https://custom.rekor.com?timeout=30s&retries=5",
			expected: &StorageConfig{
				Backend: "rekor",
				BaseURL: "https://custom.rekor.com",
				Parameters: map[string]string{
					"timeout": "30s",
					"retries": "5",
				},
			},
			expectError: false,
		},
		{
			name:        "unsupported backend name",
			storageFlag: "rekor-https://rekor.sigstore.dev",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "empty backend",
			storageFlag: "@https://rekor.sigstore.dev",
			expected:    nil,
			expectError: true,
		},
		{
			name:        "empty URL - should use defaults",
			storageFlag: "rekor@",
			expected: &StorageConfig{
				Backend:    "rekor",
				BaseURL:    "", // ParseStorageFlag only parses, doesn't apply defaults
				Parameters: map[string]string{},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseStorageFlag(tt.storageFlag)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCreateStorageBackend(t *testing.T) {
	tests := []struct {
		name        string
		config      *StorageConfig
		expectError bool
		expectType  string
	}{
		{
			name: "rekor backend",
			config: &StorageConfig{
				Backend: "rekor",
				BaseURL: "https://rekor.sigstore.dev",
			},
			expectError: false,
			expectType:  "*vsa.RekorBackend",
		},
		{
			name: "local backend",
			config: &StorageConfig{
				Backend: "local",
				BaseURL: "/tmp/vsa",
			},
			expectError: false,
			expectType:  "*vsa.LocalBackend",
		},
		{
			name: "file backend (alias for local)",
			config: &StorageConfig{
				Backend: "file",
				BaseURL: "/tmp/vsa",
			},
			expectError: false,
			expectType:  "*vsa.LocalBackend",
		},
		{
			name: "unsupported backend",
			config: &StorageConfig{
				Backend: "s3",
				BaseURL: "s3://bucket/path",
			},
			expectError: true,
			expectType:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := CreateStorageBackend(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, backend)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, backend)
				// Note: We can't easily test the exact type without reflection,
				// but we can test that the backend implements the interface
				assert.Implements(t, (*StorageBackend)(nil), backend)
			}
		})
	}
}

func TestUploadVSAEnvelope_EmptyConfigs(t *testing.T) {
	// Create a temporary file for the envelope
	tempFile, err := os.CreateTemp("", "test-envelope-*.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	// Write test content
	testContent := `{"test":"envelope"}`
	_, err = tempFile.WriteString(testContent)
	require.NoError(t, err)
	tempFile.Close()

	envelopePath := tempFile.Name()

	ctx := context.Background()
	err = UploadVSAEnvelope(ctx, envelopePath, "test-image@sha256:abc123", []string{}, nil)
	assert.NoError(t, err)
}

func TestUploadVSAEnvelope_InvalidEnvelopePath(t *testing.T) {
	ctx := context.Background()

	err := UploadVSAEnvelope(ctx, "/non/existent/path", "test-image@sha256:abc123", []string{"local@/tmp"}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read VSA envelope")
}

func TestUploadVSAEnvelope_InvalidStorageConfig(t *testing.T) {
	// Create a temporary file for the envelope
	tempFile, err := os.CreateTemp("", "test-envelope-*.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	// Write test content
	testContent := `{"test":"envelope"}`
	_, err = tempFile.WriteString(testContent)
	require.NoError(t, err)
	tempFile.Close()

	envelopePath := tempFile.Name()

	ctx := context.Background()
	err = UploadVSAEnvelope(ctx, envelopePath, "test-image@sha256:abc123", []string{"invalid-format"}, nil)
	assert.NoError(t, err) // Should not error, just warn and continue
}
