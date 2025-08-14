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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	rekorapi "github.com/sigstore/rekor/pkg/client"
	log "github.com/sirupsen/logrus"
)

// RekorBackend implements VSA storage in Rekor transparency log
type RekorBackend struct {
	serverURL string
	timeout   time.Duration
	retries   int
}

// NewRekorBackend creates a new Rekor storage backend
func NewRekorBackend(config *StorageConfig) (StorageBackend, error) {
	backend := &RekorBackend{
		serverURL: "https://rekor.sigstore.dev", // Default
		timeout:   30 * time.Second,             // Default timeout
		retries:   3,                            // Default retries
	}

	// Use base URL if provided
	if config.BaseURL != "" {
		backend.serverURL = config.BaseURL
	}

	// Parse parameters
	for key, value := range config.Parameters {
		switch key {
		case "server", "url":
			backend.serverURL = value
		case "timeout":
			if timeout, err := time.ParseDuration(value); err == nil {
				backend.timeout = timeout
			} else {
				return nil, fmt.Errorf("invalid timeout format '%s': %w", value, err)
			}
		case "retries":
			if retries, err := strconv.Atoi(value); err == nil {
				backend.retries = retries
			} else {
				return nil, fmt.Errorf("invalid retries format '%s': %w", value, err)
			}
		default:
			log.Warnf("[VSA] Rekor backend: ignoring unknown parameter '%s'", key)
		}
	}

	return backend, nil
}

// Name returns the backend name
func (r *RekorBackend) Name() string {
	return fmt.Sprintf("Rekor (%s)", r.serverURL)
}

// Upload is not supported for Rekor backend - use UploadWithSigner instead
func (r *RekorBackend) Upload(ctx context.Context, envelopeContent []byte, imageRef string) error {
	return fmt.Errorf("Rekor backend requires signer access for public key. Use UploadWithSigner instead")
}

// UploadWithSigner uploads a VSA envelope to the Rekor transparency log with access to the signer for public key extraction
func (r *RekorBackend) UploadWithSigner(ctx context.Context, envelopeContent []byte, imageRef string, signer *Signer) error {
	// Safely convert retries to uint
	var retryCount uint
	if r.retries < 0 {
		retryCount = 0
	} else {
		retryCount = uint(r.retries)
	}

	rekorClient, err := rekorapi.GetRekorClient(r.serverURL,
		rekorapi.WithUserAgent("conforma-cli"),
		rekorapi.WithRetryCount(retryCount),
	)
	if err != nil {
		return fmt.Errorf("failed to create Rekor client for %s: %w", r.serverURL, err)
	}

	uploadCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Extract the public key from the signer
	pubKeyBytes, err := r.extractPublicKeyFromSigner(signer)
	if err != nil {
		return fmt.Errorf("failed to extract public key from signer: %w", err)
	}

	// Upload to Rekor
	entry, err := cosign.TLogUploadInTotoAttestation(uploadCtx, rekorClient, envelopeContent, pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to upload VSA to Rekor: %w", err)
	}

	// Extract basic information for logging
	var entryUUID string
	if entry.LogID != nil {
		entryUUID = *entry.LogID
	} else {
		entryUUID = "unknown"
	}

	var logIndex string
	if entry.LogIndex != nil {
		logIndex = strconv.FormatInt(*entry.LogIndex, 10)
	} else {
		logIndex = "unknown"
	}

	// Log success with different messages for component vs snapshot VSAs
	var logMessage string
	if imageRef == "" {
		logMessage = "[VSA] Successfully uploaded Snapshot VSA to Rekor"
	} else {
		logMessage = "[VSA] Successfully uploaded Component VSA to Rekor"
	}

	log.WithFields(log.Fields{
		"rekor_uuid":  entryUUID,
		"rekor_url":   fmt.Sprintf("%s/api/v1/log/entries/%s", r.serverURL, entryUUID),
		"rekor_index": logIndex,
	}).Info(logMessage)

	return nil
}

// extractPublicKeyFromSigner extracts the public key from the signer and converts it to PEM format
func (r *RekorBackend) extractPublicKeyFromSigner(signer *Signer) ([]byte, error) {
	// Check if signer is nil
	if signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}

	// Get the public key from the signer
	pubKey, err := signer.SignerVerifier.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from signer: %w", err)
	}

	// Convert the public key to PEM format (same logic as in attest.go)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, nil
}
