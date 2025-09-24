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
	"path/filepath"
	"strings"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

// FileVSARetriever implements VSARetriever using filesystem storage
type FileVSARetriever struct {
	fs       afero.Fs
	basePath string
}

// NewFileVSARetriever creates a new filesystem-based VSA retriever
func NewFileVSARetriever(fs afero.Fs, basePath string) *FileVSARetriever {
	return &FileVSARetriever{
		fs:       fs,
		basePath: basePath,
	}
}

// NewFileVSARetrieverWithOSFs creates a new filesystem-based VSA retriever using the OS filesystem
func NewFileVSARetrieverWithOSFs(basePath string) *FileVSARetriever {
	return &FileVSARetriever{
		fs:       afero.NewOsFs(),
		basePath: basePath,
	}
}

// RetrieveVSA retrieves VSA data as a DSSE envelope from a file path
// The identifier can be:
// - A direct file path (e.g., "/path/to/vsa.json")
// - A relative path that will be resolved against basePath
// - A filename that will be looked up in basePath
func (f *FileVSARetriever) RetrieveVSA(ctx context.Context, identifier string) (*ssldsse.Envelope, error) {
	if identifier == "" {
		return nil, fmt.Errorf("file path identifier cannot be empty")
	}

	// Determine the full file path
	filePath := f.resolveFilePath(identifier)

	log.Debugf("Retrieving VSA from file: %s", filePath)

	// Check if file exists
	exists, err := afero.Exists(f.fs, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to check if file exists: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("VSA file not found: %s", filePath)
	}

	// Read the file
	data, err := afero.ReadFile(f.fs, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read VSA file: %w", err)
	}

	// Parse the DSSE envelope
	envelope, err := f.parseDSSEEnvelope(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DSSE envelope from file: %w", err)
	}

	log.Debugf("Successfully retrieved VSA from file: %s", filePath)
	return envelope, nil
}

// resolveFilePath determines the full file path from the identifier
func (f *FileVSARetriever) resolveFilePath(identifier string) string {
	// If it's an absolute path, use it directly
	if filepath.IsAbs(identifier) {
		return identifier
	}

	// If basePath is empty, use the identifier as-is
	if f.basePath == "" {
		return identifier
	}

	// Otherwise, resolve relative to basePath
	return filepath.Join(f.basePath, identifier)
}

// parseDSSEEnvelope parses a DSSE envelope from JSON data
func (f *FileVSARetriever) parseDSSEEnvelope(data []byte) (*ssldsse.Envelope, error) {
	var envelope ssldsse.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DSSE envelope: %w", err)
	}

	// Validate the envelope has required fields
	if envelope.PayloadType == "" {
		return nil, fmt.Errorf("DSSE envelope missing payloadType")
	}
	if envelope.Payload == "" {
		return nil, fmt.Errorf("DSSE envelope missing payload")
	}
	if len(envelope.Signatures) == 0 {
		return nil, fmt.Errorf("DSSE envelope missing signatures")
	}

	return &envelope, nil
}

// FileVSARetrieverOptions configures filesystem-based VSA retrieval behavior
type FileVSARetrieverOptions struct {
	BasePath string
	FS       afero.Fs
}

// NewFileVSARetrieverWithOptions creates a new filesystem-based VSA retriever with options
func NewFileVSARetrieverWithOptions(opts FileVSARetrieverOptions) *FileVSARetriever {
	fs := opts.FS
	if fs == nil {
		fs = afero.NewOsFs()
	}

	return &FileVSARetriever{
		fs:       fs,
		basePath: opts.BasePath,
	}
}

// CreateFileVSARetrieverFromFlags creates a file VSA retriever based on upload flags
// This is used for consistency with other retriever creation functions
func CreateFileVSARetrieverFromFlags(vsaUpload []string) *FileVSARetriever {
	for _, uploadFlag := range vsaUpload {
		config, err := ParseStorageFlag(uploadFlag)
		if err != nil {
			log.Debugf("Failed to parse VSA upload flag '%s': %v", uploadFlag, err)
			continue
		}

		// Check if this is a file-based configuration
		if strings.ToLower(config.Backend) == "file" {
			basePath := config.BaseURL // Use BaseURL as the base path for files
			if basePath == "" {
				basePath = "." // Default to current directory
			}

			log.Debugf("Created File VSA retriever with base path: %s", basePath)
			return NewFileVSARetrieverWithOSFs(basePath)
		}
	}

	return nil
}
