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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/sigstore/rekor/pkg/client"
	gen_client "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	log "github.com/sirupsen/logrus"

	// Import packages to register types
	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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
func (r *RekorBackend) Upload(ctx context.Context, envelopeContent []byte) error {
	return fmt.Errorf("Rekor backend requires signer access for public key. Use UploadWithSigner instead")
}

// UploadWithSigner uploads a VSA envelope to the Rekor transparency log with access to the signer for public key extraction
func (r *RekorBackend) UploadWithSigner(ctx context.Context, envelopeContent []byte, signer *Signer) (string, error) {
	// Safely convert retries to uint
	var retryCount uint
	if r.retries < 0 {
		retryCount = 0
	} else {
		retryCount = uint(r.retries)
	}

	rekorClient, err := client.GetRekorClient(r.serverURL,
		client.WithUserAgent("conforma-cli"),
		client.WithRetryCount(retryCount),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create Rekor client for %s: %w", r.serverURL, err)
	}

	log.WithFields(log.Fields{
		"server_url":  r.serverURL,
		"retry_count": retryCount,
		"timeout":     r.timeout,
	}).Info("[VSA] Created Rekor client")

	uploadCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Extract the public key from the signer
	pubKeyBytes, err := r.extractPublicKeyFromSigner(signer)
	if err != nil {
		return "", fmt.Errorf("failed to extract public key from signer: %w", err)
	}

	// Use dual uploader to upload as both DSSE and in-toto entries
	return r.uploadBoth(uploadCtx, rekorClient, envelopeContent, pubKeyBytes)
}

// uploadBoth uploads the same envelope as both DSSE and in-toto entries
func (r *RekorBackend) uploadBoth(ctx context.Context, rekorClient *gen_client.Rekor, envelopeContent []byte, pubKeyBytes []byte) (string, error) {
	// Prepare the DSSE envelope for Rekor
	preparedEnvelope, payloadHash, err := r.prepareDSSEForRekor(envelopeContent, pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to prepare DSSE envelope for Rekor: %w", err)
	}

	log.WithFields(log.Fields{
		"payload_hash":     payloadHash,
		"original_size":    len(envelopeContent),
		"prepared_size":    len(preparedEnvelope),
		"payload_preview":  string(envelopeContent[:min(100, len(envelopeContent))]),
		"prepared_preview": string(preparedEnvelope[:min(100, len(preparedEnvelope))]),
	}).Info("[VSA] Prepared DSSE envelope for dual upload")

	// Upload as in-toto entry first
	log.Info("[VSA] Starting in-toto entry upload")
	intotoEntry, err := r.uploadIntotoEnvelope(ctx, rekorClient, envelopeContent, pubKeyBytes)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to upload in-toto entry")
		return "", fmt.Errorf("failed to upload in-toto entry: %w", err)
	}
	log.Info("[VSA] Completed in-toto entry upload")

	// Upload as DSSE entry
	log.Info("[VSA] Starting DSSE entry upload")
	dsseEntry, err := r.uploadDSSE(ctx, rekorClient, preparedEnvelope, pubKeyBytes)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to upload DSSE entry")
		return "", fmt.Errorf("failed to upload DSSE entry: %w", err)
	}
	log.Info("[VSA] Completed DSSE entry upload")

	// Log successful dual upload
	log.WithFields(log.Fields{
		"payload_hash": payloadHash,
		"intoto_uuid":  intotoEntry.LogID,
		"intoto_index": intotoEntry.LogIndex,
		"dsse_uuid":    dsseEntry.LogID,
		"dsse_index":   dsseEntry.LogIndex,
		"intoto_url":   fmt.Sprintf("%s/api/v1/log/entries/%s", r.serverURL, *intotoEntry.LogID),
		"dsse_url":     fmt.Sprintf("%s/api/v1/log/entries/%s", r.serverURL, *dsseEntry.LogID),
	}).Info("[VSA] Successfully uploaded VSA to Rekor as dual entries")

	return payloadHash, nil
}

// uploadIntotoEnvelope uploads the envelope as an in-toto entry
func (r *RekorBackend) uploadIntotoEnvelope(ctx context.Context, rekorClient *gen_client.Rekor, envelopeContent []byte, pubKeyBytes []byte) (*models.LogEntryAnon, error) {
	log.Info("[VSA] Creating artifact properties for in-toto entry")

	// Log the envelope content for debugging
	log.WithFields(log.Fields{
		"envelope_size":    len(envelopeContent),
		"envelope_preview": string(envelopeContent[:min(200, len(envelopeContent))]),
		"pubkey_size":      len(pubKeyBytes),
	}).Info("[VSA] Envelope content for in-toto upload")

	// Create artifact properties for in-toto entry
	artifactProps := types.ArtifactProperties{
		ArtifactBytes:  envelopeContent,
		PublicKeyBytes: [][]byte{pubKeyBytes},
	}

	// Create the proposed in-toto entry
	log.Info("[VSA] Creating proposed in-toto entry")
	proposedEntry, err := types.NewProposedEntry(ctx, "intoto", "0.0.1", artifactProps)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to create proposed in-toto entry")
		return nil, fmt.Errorf("failed to create proposed in-toto entry: %w", err)
	}

	// Create the upload parameters
	log.Info("[VSA] Creating upload parameters for in-toto")
	params := entries.NewCreateLogEntryParams()
	params.SetContext(ctx)
	params.SetProposedEntry(proposedEntry)

	// Upload to Rekor
	log.Info("[VSA] Calling CreateLogEntry for in-toto")
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		log.WithError(err).Error("[VSA] CreateLogEntry for in-toto failed")
		return nil, fmt.Errorf("failed to create in-toto log entry: %w", err)
	}

	// Extract the created entry
	var logEntry models.LogEntryAnon
	for _, entry := range resp.Payload {
		logEntry = entry
		break
	}

	log.WithFields(log.Fields{
		"entry_type": "in-toto",
		"uuid":       logEntry.LogID,
		"index":      logEntry.LogIndex,
	}).Info("[VSA] Successfully uploaded in-toto entry")

	return &logEntry, nil
}

// uploadDSSE uploads the envelope as a DSSE entry
func (r *RekorBackend) uploadDSSE(ctx context.Context, rekorClient *gen_client.Rekor, envelopeContent []byte, pubKeyBytes []byte) (*models.LogEntryAnon, error) {
	log.Info("[VSA] Creating artifact properties for DSSE entry")
	// Create artifact properties for DSSE entry
	artifactProps := types.ArtifactProperties{
		ArtifactBytes:  envelopeContent,
		PublicKeyBytes: [][]byte{pubKeyBytes},
	}

	// Create the proposed DSSE entry
	log.Info("[VSA] Creating proposed DSSE entry")
	log.WithFields(log.Fields{
		"envelope_size":    len(envelopeContent),
		"envelope_preview": string(envelopeContent[:min(len(envelopeContent), 200)]),
		"pubkey_size":      len(pubKeyBytes),
	}).Info("[VSA] DSSE envelope details for upload")

	proposedEntry, err := types.NewProposedEntry(ctx, "dsse", "0.0.1", artifactProps)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to create proposed DSSE entry")
		return nil, fmt.Errorf("failed to create proposed DSSE entry: %w", err)
	}

	// Create the upload parameters
	log.Info("[VSA] Creating upload parameters")
	params := entries.NewCreateLogEntryParams()
	params.SetContext(ctx)
	params.SetProposedEntry(proposedEntry)

	// Upload to Rekor
	log.Info("[VSA] Calling CreateLogEntry")
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		log.WithError(err).Error("[VSA] CreateLogEntry failed")
		return nil, fmt.Errorf("failed to create DSSE log entry: %w", err)
	}

	// Extract the created entry
	var logEntry models.LogEntryAnon
	for _, entry := range resp.Payload {
		logEntry = entry
		break
	}

	log.WithFields(log.Fields{
		"entry_type": "dsse",
		"uuid":       logEntry.LogID,
		"index":      logEntry.LogIndex,
	}).Info("[VSA] Successfully uploaded DSSE entry")

	return &logEntry, nil
}

// prepareDSSEForRekor prepares the DSSE envelope for Rekor by canonicalizing the base64 payload and injecting public keys
func (r *RekorBackend) prepareDSSEForRekor(envelopeContent []byte, pubKeyBytes []byte) ([]byte, string, error) {
	// Parse the existing DSSE envelope
	var envelope map[string]interface{}
	if err := json.Unmarshal(envelopeContent, &envelope); err != nil {
		return nil, "", fmt.Errorf("failed to parse DSSE envelope: %w", err)
	}

	// Canonicalize the payload base64
	if payload, ok := envelope["payload"].(string); ok {
		canonicalizedPayload, err := r.canonicalizeBase64([]byte(payload))
		if err != nil {
			return nil, "", fmt.Errorf("failed to canonicalize payload: %w", err)
		}
		envelope["payload"] = string(canonicalizedPayload)
	}

	// Canonicalize signature base64 and inject public keys
	if signatures, ok := envelope["signatures"].([]interface{}); ok {
		for i, sig := range signatures {
			if sigMap, ok := sig.(map[string]interface{}); ok {
				// Canonicalize signature
				if sigValue, ok := sigMap["sig"].(string); ok {
					canonicalizedSig, err := r.canonicalizeBase64([]byte(sigValue))
					if err != nil {
						return nil, "", fmt.Errorf("failed to canonicalize signature %d: %w", i, err)
					}
					sigMap["sig"] = string(canonicalizedSig)
				}

				// Inject public key if missing
				if _, hasKey := sigMap["publicKey"]; !hasKey {
					sigMap["publicKey"] = string(pubKeyBytes)
				}
			}
		}
	}

	// Marshal back to JSON
	canonicalizedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal canonicalized envelope: %w", err)
	}

	// Calculate the payload hash (SHA256 of the canonicalized envelope)
	payloadHash := sha256.Sum256(canonicalizedEnvelope)
	payloadHashHex := fmt.Sprintf("%x", payloadHash[:])

	return canonicalizedEnvelope, payloadHashHex, nil
}

// canonicalizeBase64 canonicalizes the base64 payload by removing newlines and ensuring proper padding
func (r *RekorBackend) canonicalizeBase64(payload []byte) ([]byte, error) {
	// Remove newlines first
	payload = bytes.ReplaceAll(payload, []byte("\n"), []byte(""))

	// Remove existing padding
	payload = bytes.TrimRight(payload, "=")

	// Add proper padding back for Rekor compatibility
	missingPadding := len(payload) % 4
	if missingPadding > 0 {
		padding := make([]byte, 4-missingPadding)
		for i := range padding {
			padding[i] = '='
		}
		payload = append(payload, padding...)
	}

	return payload, nil
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
