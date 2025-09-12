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
	"fmt"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// StorageBackend defines the interface for VSA storage implementations
type StorageBackend interface {
	Name() string
	Upload(ctx context.Context, envelopeContent []byte) error
}

// SignerAwareUploader extends StorageBackend for backends that need access to the signer
// (e.g., Rekor backend needs the public key for transparency log upload)
type SignerAwareUploader interface {
	StorageBackend
	UploadWithSigner(ctx context.Context, envelopeContent []byte, signer *Signer) (string, error)
}

// StorageConfig represents parsed storage configuration
type StorageConfig struct {
	Backend    string            // rekor, local (maybe others in future)
	BaseURL    string            // Primary URL
	Parameters map[string]string // Additional parameters
}

// ParseStorageFlag parses the --vsa-upload flag format
// Supported formats:
//   - rekor@https://rekor.sigstore.dev
//   - local@/path/to/directory
//   - rekor?server=custom.rekor.com&timeout=30s
func ParseStorageFlag(storageFlag string) (*StorageConfig, error) {
	if storageFlag == "" {
		return nil, fmt.Errorf("storage flag cannot be empty")
	}

	config := &StorageConfig{
		Parameters: make(map[string]string),
	}

	// Split on @ to separate backend from URL/config
	var configPart string
	if strings.Contains(storageFlag, "@") {
		parts := strings.SplitN(storageFlag, "@", 2)
		config.Backend = parts[0]
		configPart = parts[1]
	} else {
		// No @ means it's just backend name, possibly with query params
		if strings.Contains(storageFlag, "?") {
			parts := strings.SplitN(storageFlag, "?", 2)
			config.Backend = parts[0]
			configPart = "?" + parts[1] // Add ? back for URL parsing
		} else {
			config.Backend = storageFlag
		}
	}

	// Validate that backend is not empty
	if config.Backend == "" {
		return nil, fmt.Errorf("backend name cannot be empty")
	}

	// Validate that backend is supported
	supportedBackends := []string{"rekor", "local"}
	isSupported := false
	for _, supported := range supportedBackends {
		if strings.ToLower(config.Backend) == supported {
			isSupported = true
			break
		}
	}
	if !isSupported {
		return nil, fmt.Errorf("unsupported backend '%s'. Supported backends: %s", config.Backend, strings.Join(supportedBackends, ", "))
	}

	// Parse URL-style parameters if present
	if configPart != "" {
		// If it doesn't start with http(s), add a dummy scheme for parsing
		parseURL := configPart
		if !strings.HasPrefix(configPart, "http") && !strings.HasPrefix(configPart, "?") {
			parseURL = "dummy://" + configPart
		} else if strings.HasPrefix(configPart, "?") {
			parseURL = "dummy://dummy" + configPart
		}

		parsed, err := url.Parse(parseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid storage configuration format: %w", err)
		}

		// Extract base URL (without query params)
		if parsed.Scheme != "dummy" {
			config.BaseURL = fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path)
		} else if parsed.Host != "dummy" {
			config.BaseURL = parsed.Host + parsed.Path
		}

		// Extract query parameters
		for key, values := range parsed.Query() {
			if len(values) > 0 {
				config.Parameters[key] = values[0]
			}
		}
	}

	return config, nil
}

// CreateStorageBackend creates the appropriate storage backend based on config
func CreateStorageBackend(config *StorageConfig) (StorageBackend, error) {
	switch strings.ToLower(config.Backend) {
	case "rekor":
		return NewRekorBackend(config)
	case "local":
		return NewLocalBackend(config)
	default:
		return nil, fmt.Errorf("unsupported storage backend: %s. Supported backends: rekor, local", config.Backend)
	}
}

// UploadVSAEnvelope uploads a VSA envelope to the configured storage backends
func UploadVSAEnvelope(ctx context.Context, envelopePath string, storageConfigs []string, signer *Signer) error {
	if len(storageConfigs) == 0 {
		log.Infof("[VSA] No storage backends configured, skipping upload")
		return nil
	}

	// Read envelope content
	envelopeContent, err := os.ReadFile(envelopePath)
	log.Debugf("UploadVSAEnvelope called with envelopePath: %s", envelopePath)
	log.Debugf("UploadVSAEnvelope called with envelopeContent: %s", string(envelopeContent))
	if err != nil {
		return fmt.Errorf("failed to read VSA envelope from %s: %w", envelopePath, err)
	}

	// Upload to each configured backend
	for _, storageFlag := range storageConfigs {
		config, err := ParseStorageFlag(storageFlag)
		if err != nil {
			log.Warnf("invalid storage config '%s': %v", storageFlag, err)
			continue
		}

		backend, err := CreateStorageBackend(config)
		if err != nil {
			log.Warnf("failed to create %s backend: %v", config.Backend, err)
			continue
		}

		// Upload using the appropriate method
		var uploadErr error
		if signerAwareUploader, ok := backend.(SignerAwareUploader); ok && signer != nil {
			payloadHash, uploadErr := signerAwareUploader.UploadWithSigner(ctx, envelopeContent, signer)
			if uploadErr == nil && payloadHash != "" {
				log.WithFields(log.Fields{
					"backend":      backend.Name(),
					"payload_hash": payloadHash,
				}).Debug("[VSA] Upload successful, payload hash available for retrieval")
			}
		} else {
			uploadErr = backend.Upload(ctx, envelopeContent)
		}

		if uploadErr != nil {
			log.Warnf("failed to upload to %s: %v", backend.Name(), uploadErr)
			continue
		}
	}

	return nil
}
