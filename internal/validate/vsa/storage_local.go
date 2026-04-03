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
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// LocalBackend implements VSA storage to local filesystem
type LocalBackend struct {
	basePath string
}

// NewLocalBackend creates a new local file storage backend
func NewLocalBackend(config *StorageConfig) (StorageBackend, error) {
	basePath := "./vsa-upload" // Default

	// Use base URL as path if provided
	if config.BaseURL != "" {
		basePath = config.BaseURL
	}

	// Check parameters
	for key, value := range config.Parameters {
		switch key {
		case "path", "dir", "directory":
			basePath = value
		default:
			log.Warnf("[VSA] Local backend: ignoring unknown parameter '%s'", key)
		}
	}

	// Ensure directory exists
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory %s: %w", basePath, err)
	}

	return &LocalBackend{basePath: basePath}, nil
}

// Name returns the backend name
func (l *LocalBackend) Name() string {
	return fmt.Sprintf("Local (%s)", l.basePath)
}

// Upload saves the VSA envelope to a local file
func (l *LocalBackend) Upload(ctx context.Context, envelopeContent []byte) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(l.basePath, 0o755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", l.basePath, err)
	}

	// Generate filename with timestamp and content hash for uniqueness
	timestamp := time.Now().Format("2006-01-02T15-04-05.000000000")
	contentHash := sha256.Sum256(envelopeContent)
	filename := fmt.Sprintf("vsa-%s-%x.json", timestamp, contentHash[:8])

	// Write to file
	filePath := filepath.Join(l.basePath, filename)
	if err := os.WriteFile(filePath, envelopeContent, 0o600); err != nil {
		return fmt.Errorf("failed to write VSA envelope to %s: %w", filePath, err)
	}

	// Get absolute path for logging
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath // fallback to relative path
	}

	log.WithFields(log.Fields{
		"path": absPath,
		"size": len(envelopeContent),
	}).Info("[VSA] Successfully saved VSA to local file")

	return nil
}
