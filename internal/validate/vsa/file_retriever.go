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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"

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

	// Try to parse as DSSE envelope first, then fall back to raw predicate
	envelope, err := f.parseVSAContent(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VSA content from file: %w", err)
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

// parseVSAContent attempts to parse VSA content from either DSSE envelope or raw predicate format
func (f *FileVSARetriever) parseVSAContent(data []byte) (*ssldsse.Envelope, error) {
	// First, try to parse as a DSSE envelope (signed format)
	envelope, err := f.parseDSSEEnvelope(data)
	if err == nil {
		return envelope, nil
	}

	// If DSSE parsing failed, try to parse as raw predicate (unsigned format)
	return f.parseRawPredicate(data)
}

// parseRawPredicate parses a raw VSA predicate and wraps it in a minimal DSSE envelope structure
func (f *FileVSARetriever) parseRawPredicate(data []byte) (*ssldsse.Envelope, error) {
	// Verify it's valid JSON and looks like a VSA predicate
	var predicate map[string]interface{}
	if err := json.Unmarshal(data, &predicate); err != nil {
		return nil, fmt.Errorf("content is neither valid DSSE envelope nor valid JSON predicate: %w", err)
	}

	// Check if it looks like a VSA predicate (should have expected fields)
	if _, hasPolicy := predicate["policy"]; !hasPolicy {
		return nil, fmt.Errorf("content does not appear to be a VSA predicate (missing 'policy' field)")
	}
	if _, hasTimestamp := predicate["timestamp"]; !hasTimestamp {
		return nil, fmt.Errorf("content does not appear to be a VSA predicate (missing 'timestamp' field)")
	}

	// Create a minimal DSSE envelope with the raw predicate as base64-encoded payload
	// This allows the rest of the VSA processing pipeline to work unchanged
	envelope := &ssldsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString(data),
		Signatures:  []ssldsse.Signature{}, // Empty signatures for unsigned content
	}

	return envelope, nil
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
