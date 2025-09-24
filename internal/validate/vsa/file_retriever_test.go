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
	"os"
	"path/filepath"
	"testing"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileVSARetriever_RetrieveVSA(t *testing.T) {
	// Create a test DSSE envelope
	envelope := &ssldsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "eyJ0eXBlIjoiaHR0cHM6Ly9pbi10b3RvLmlvL0pzb25TZXJpYWxpemF0aW9uLzEuMC9wcmVkaWNhdGUifQ==",
		Signatures: []ssldsse.Signature{
			{
				KeyID: "test-key-id",
				Sig:   "test-signature",
			},
		},
	}

	// Create a temporary directory for testing
	tempDir := t.TempDir()
	fs := afero.NewMemMapFs()

	// Create a test VSA file
	vsaPath := filepath.Join(tempDir, "test-vsa.json")
	envelopeJSON, err := json.Marshal(envelope)
	require.NoError(t, err)

	// Write to both real filesystem and memory filesystem for different tests
	err = os.WriteFile(vsaPath, envelopeJSON, 0600)
	require.NoError(t, err)

	// Also write to memory filesystem
	err = afero.WriteFile(fs, "test-vsa.json", envelopeJSON, 0600)
	require.NoError(t, err)

	tests := []struct {
		name        string
		identifier  string
		basePath    string
		fs          afero.Fs
		expectError bool
		errorMsg    string
	}{
		{
			name:        "absolute path with real filesystem",
			identifier:  vsaPath,
			basePath:    "",
			fs:          afero.NewOsFs(),
			expectError: false,
		},
		{
			name:        "relative path with memory filesystem",
			identifier:  "test-vsa.json",
			basePath:    "",
			fs:          fs,
			expectError: false,
		},
		{
			name:        "relative path with base path",
			identifier:  "test-vsa.json",
			basePath:    tempDir,
			fs:          afero.NewOsFs(),
			expectError: false,
		},
		{
			name:        "non-existent file",
			identifier:  "non-existent.json",
			basePath:    "",
			fs:          fs,
			expectError: true,
			errorMsg:    "VSA file not found",
		},
		{
			name:        "empty identifier",
			identifier:  "",
			basePath:    "",
			fs:          fs,
			expectError: true,
			errorMsg:    "file path identifier cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retriever := &FileVSARetriever{
				fs:       tt.fs,
				basePath: tt.basePath,
			}

			result, err := retriever.RetrieveVSA(context.Background(), tt.identifier)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, envelope.PayloadType, result.PayloadType)
				assert.Equal(t, envelope.Payload, result.Payload)
				assert.Len(t, result.Signatures, 1)
				assert.Equal(t, envelope.Signatures[0].KeyID, result.Signatures[0].KeyID)
				assert.Equal(t, envelope.Signatures[0].Sig, result.Signatures[0].Sig)
			}
		})
	}
}

func TestFileVSARetriever_NewFileVSARetriever(t *testing.T) {
	fs := afero.NewMemMapFs()
	basePath := "/test/path"

	retriever := NewFileVSARetriever(fs, basePath)

	assert.Equal(t, fs, retriever.fs)
	assert.Equal(t, basePath, retriever.basePath)
}

func TestFileVSARetriever_NewFileVSARetrieverWithOSFs(t *testing.T) {
	basePath := "/test/path"

	retriever := NewFileVSARetrieverWithOSFs(basePath)

	assert.IsType(t, &afero.OsFs{}, retriever.fs)
	assert.Equal(t, basePath, retriever.basePath)
}

func TestFileVSARetriever_NewFileVSARetrieverWithOptions(t *testing.T) {
	fs := afero.NewMemMapFs()
	basePath := "/test/path"

	opts := FileVSARetrieverOptions{
		BasePath: basePath,
		FS:       fs,
	}

	retriever := NewFileVSARetrieverWithOptions(opts)

	assert.Equal(t, fs, retriever.fs)
	assert.Equal(t, basePath, retriever.basePath)
}

func TestFileVSARetriever_NewFileVSARetrieverWithOptions_DefaultFS(t *testing.T) {
	basePath := "/test/path"

	opts := FileVSARetrieverOptions{
		BasePath: basePath,
		// FS is nil, should use default
	}

	retriever := NewFileVSARetrieverWithOptions(opts)

	assert.IsType(t, &afero.OsFs{}, retriever.fs)
	assert.Equal(t, basePath, retriever.basePath)
}

func TestFileVSARetriever_parseDSSEEnvelope(t *testing.T) {
	fs := afero.NewMemMapFs()
	retriever := &FileVSARetriever{fs: fs}

	// Test valid envelope
	envelope := &ssldsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "test-payload",
		Signatures: []ssldsse.Signature{
			{KeyID: "test-key", Sig: "test-sig"},
		},
	}

	envelopeJSON, err := json.Marshal(envelope)
	require.NoError(t, err)

	result, err := retriever.parseDSSEEnvelope(envelopeJSON)
	require.NoError(t, err)
	assert.Equal(t, envelope.PayloadType, result.PayloadType)
	assert.Equal(t, envelope.Payload, result.Payload)
	assert.Len(t, result.Signatures, 1)

	// Test invalid JSON
	_, err = retriever.parseDSSEEnvelope([]byte("invalid json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal DSSE envelope")

	// Test missing payloadType
	invalidEnvelope := map[string]interface{}{
		"payload": "test",
		"signatures": []map[string]interface{}{
			{"keyid": "test", "sig": "test"},
		},
	}
	invalidJSON, err := json.Marshal(invalidEnvelope)
	require.NoError(t, err)

	_, err = retriever.parseDSSEEnvelope(invalidJSON)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DSSE envelope missing payloadType")
}

func TestFileVSARetriever_resolveFilePath(t *testing.T) {
	retriever := &FileVSARetriever{
		fs:       afero.NewMemMapFs(),
		basePath: "/base/path",
	}

	tests := []struct {
		name       string
		identifier string
		expected   string
	}{
		{
			name:       "absolute path",
			identifier: "/absolute/path/file.json",
			expected:   "/absolute/path/file.json",
		},
		{
			name:       "relative path with base",
			identifier: "file.json",
			expected:   "/base/path/file.json",
		},
		{
			name:       "relative path without base",
			identifier: "file.json",
			expected:   "/base/path/file.json",
		},
	}

	// Test with base path
	for _, tt := range tests {
		t.Run(tt.name+"_with_base", func(t *testing.T) {
			result := retriever.resolveFilePath(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}

	// Test without base path
	retriever.basePath = ""
	for _, tt := range tests {
		t.Run(tt.name+"_without_base", func(t *testing.T) {
			result := retriever.resolveFilePath(tt.identifier)
			if tt.identifier == "/absolute/path/file.json" {
				assert.Equal(t, "/absolute/path/file.json", result)
			} else {
				assert.Equal(t, tt.identifier, result)
			}
		})
	}
}
