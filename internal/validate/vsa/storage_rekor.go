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
	"crypto/x509"
	"encoding/base64"
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
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	log "github.com/sirupsen/logrus"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RekorBackend implements VSA storage in Rekor transparency log using single in-toto 0.0.2 entries
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

	// Upload as single in-toto 0.0.2 entry with embedded DSSE envelope
	return r.uploadSingle(uploadCtx, rekorClient, envelopeContent, pubKeyBytes)
}

// uploadSingle uploads the envelope as a single in-toto 0.0.2 entry with embedded DSSE envelope
func (r *RekorBackend) uploadSingle(ctx context.Context, rekorClient *gen_client.Rekor, envelopeContent []byte, pubKeyBytes []byte) (string, error) {
	// Prepare the DSSE envelope for Rekor - canonicalize for single upload
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
	}).Info("[VSA] Prepared DSSE envelope for single entry upload")

	// Upload as single in-toto 0.0.2 entry
	log.Info("[VSA] Starting in-toto 0.0.2 single entry upload")
	intotoEntry, err := r.uploadIntotoV002Envelope(ctx, rekorClient, preparedEnvelope, pubKeyBytes)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to upload in-toto 0.0.2 entry")
		return "", fmt.Errorf("failed to upload in-toto 0.0.2 entry: %w", err)
	}
	log.Info("[VSA] Completed in-toto 0.0.2 single entry upload")

	// Log successful single upload
	log.WithFields(log.Fields{
		"payload_hash": payloadHash,
		"intoto_uuid":  *intotoEntry.LogID,
		"intoto_index": *intotoEntry.LogIndex,
		"intoto_url":   fmt.Sprintf("%s/api/v1/log/entries/%s", r.serverURL, *intotoEntry.LogID),
	}).Info("[VSA] Successfully uploaded VSA to Rekor as single in-toto 0.0.2 entry")

	return payloadHash, nil
}

// uploadIntotoV002Envelope uploads the envelope as an in-toto 0.0.2 entry with embedded DSSE envelope
func (r *RekorBackend) uploadIntotoV002Envelope(ctx context.Context, rekorClient *gen_client.Rekor, envelopeContent []byte, pubKeyBytes []byte) (*models.LogEntryAnon, error) {
	log.Info("[VSA] Creating artifact properties for in-toto 0.0.2 entry")

	// Log the envelope content for debugging (now canonicalized)
	log.WithFields(log.Fields{
		"envelope_size":    len(envelopeContent),
		"envelope_preview": string(envelopeContent[:min(200, len(envelopeContent))]),
		"pubkey_size":      len(pubKeyBytes),
		"note":             "envelope is canonicalized for in-toto 0.0.2 entry with embedded DSSE",
	}).Info("[VSA] Canonicalized envelope content for in-toto 0.0.2 upload")

	// Create artifact properties for in-toto 0.0.2 entry
	artifactProps := types.ArtifactProperties{
		ArtifactBytes:  envelopeContent,
		PublicKeyBytes: [][]byte{pubKeyBytes},
	}

	// Log the artifact properties being passed to in-toto 0.0.2 entry creation
	publicKeyLength := 0
	if len(artifactProps.PublicKeyBytes) > 0 {
		publicKeyLength = len(artifactProps.PublicKeyBytes[0])
	}
	log.WithFields(log.Fields{
		"artifact_bytes_length":   len(artifactProps.ArtifactBytes),
		"artifact_bytes_preview":  string(artifactProps.ArtifactBytes[:min(200, len(artifactProps.ArtifactBytes))]),
		"public_key_bytes_count":  len(artifactProps.PublicKeyBytes),
		"public_key_bytes_length": publicKeyLength,
	}).Info("[VSA] Artifact properties for in-toto 0.0.2 entry creation")

	// Create the proposed in-toto 0.0.2 entry
	log.Info("[VSA] Creating proposed in-toto 0.0.2 entry")
	proposedEntry, err := types.NewProposedEntry(ctx, "intoto", "0.0.2", artifactProps)
	if err != nil {
		log.WithError(err).Error("[VSA] Failed to create proposed in-toto 0.0.2 entry")
		return nil, fmt.Errorf("failed to create proposed in-toto 0.0.2 entry: %w", err)
	}

	// Create the upload parameters
	log.Info("[VSA] Creating upload parameters for in-toto 0.0.2")
	params := entries.NewCreateLogEntryParams()
	params.SetContext(ctx)
	params.SetProposedEntry(proposedEntry)

	// Upload to Rekor
	log.Info("[VSA] Calling CreateLogEntry for in-toto 0.0.2")
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		log.WithError(err).Error("[VSA] CreateLogEntry for in-toto 0.0.2 failed")
		return nil, fmt.Errorf("failed to create in-toto 0.0.2 log entry: %w", err)
	}

	// Extract the created entry
	var logEntry models.LogEntryAnon
	for _, entry := range resp.Payload {
		logEntry = entry
		break
	}

	log.WithFields(log.Fields{
		"entry_type": "in-toto-0.0.2",
		"uuid":       *logEntry.LogID,
		"index":      *logEntry.LogIndex,
	}).Info("[VSA] Successfully uploaded in-toto 0.0.2 entry")

	return &logEntry, nil
}

// prepareDSSEForRekor prepares the DSSE envelope for Rekor by injecting public keys.
// The payload hash is calculated from the decoded payload bytes, not the envelope JSON, to ensure
// a stable identifier for the VSA entry.
func (r *RekorBackend) prepareDSSEForRekor(envelopeContent []byte, pubKeyBytes []byte) ([]byte, string, error) {
	// Strongly-typed DSSE envelope to avoid map gymnastics
	type dsseSig struct {
		KeyID     string  `json:"keyid,omitempty"`
		Sig       string  `json:"sig"`
		PublicKey *string `json:"publicKey,omitempty"`
	}
	type dsseEnvelope struct {
		Payload     string    `json:"payload"`
		PayloadType string    `json:"payloadType"`
		Signatures  []dsseSig `json:"signatures"`
	}

	var env dsseEnvelope
	if err := json.Unmarshal(envelopeContent, &env); err != nil {
		return nil, "", fmt.Errorf("failed to parse DSSE envelope: %w", err)
	}
	if env.Payload == "" || env.PayloadType == "" || len(env.Signatures) == 0 {
		return nil, "", fmt.Errorf("invalid DSSE envelope: missing payload/payloadType/signatures")
	}

	// Decode payload bytes (try URL-safe no-pad first, then std no-pad, then std)
	decodeB64 := func(s string) ([]byte, error) {
		if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		return base64.StdEncoding.DecodeString(s)
	}

	payloadBytes, err := decodeB64(env.Payload)
	if err != nil {
		// include a short prefix to aid debugging, but avoid dumping entire payload
		prefix := env.Payload
		if len(prefix) > 16 {
			prefix = prefix[:16] + "..."
		}
		return nil, "", fmt.Errorf("could not base64-decode DSSE payload (tried RawURL, RawStd, Std): prefix=%q: %w", prefix, err)
	}

	// Hash = sha256(decoded payload bytes) - this is the stable join key
	sum := sha256.Sum256(payloadBytes)
	payloadHashHex := fmt.Sprintf("%x", sum[:])

	// Inject PEM public key into each signature if missing
	pub := string(pubKeyBytes) // must be PEM with BEGIN/END PUBLIC KEY
	for i := range env.Signatures {
		if env.Signatures[i].PublicKey == nil || *env.Signatures[i].PublicKey == "" {
			env.Signatures[i].PublicKey = &pub
		}
	}

	// Log the DSSE envelope structure before re-marshaling
	log.WithFields(log.Fields{
		"payload_length":   len(env.Payload),
		"payload_preview":  env.Payload[:min(100, len(env.Payload))],
		"payload_type":     env.PayloadType,
		"signatures_count": len(env.Signatures),
		"payload_hash":     payloadHashHex,
	}).Info("[VSA] DSSE envelope structure before re-marshaling")

	// Log signature details before re-marshaling
	for i, sig := range env.Signatures {
		previewLen := 50
		if len(sig.Sig) < previewLen {
			previewLen = len(sig.Sig)
		}
		log.WithFields(log.Fields{
			"signature_index":   i,
			"signature_length":  len(sig.Sig),
			"signature_preview": sig.Sig[:previewLen],
			"keyid":             sig.KeyID,
		}).Info("[VSA] Signature before re-marshaling")
	}

	// Re-marshal envelope **only** with publicKey additions (no payload/sig changes)
	out, err := json.Marshal(env)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal DSSE envelope with public keys: %w", err)
	}

	// Log the re-marshaled envelope to verify payload is preserved
	var verifyEnv dsseEnvelope
	if err := json.Unmarshal(out, &verifyEnv); err == nil {
		log.WithFields(log.Fields{
			"remarshaled_payload_length":   len(verifyEnv.Payload),
			"remarshaled_payload_preview":  verifyEnv.Payload[:min(100, len(verifyEnv.Payload))],
			"remarshaled_payload_type":     verifyEnv.PayloadType,
			"remarshaled_signatures_count": len(verifyEnv.Signatures),
		}).Info("[VSA] DSSE envelope structure after re-marshaling")

		// Log signature details after re-marshaling
		for i, sig := range verifyEnv.Signatures {
			previewLen := 50
			if len(sig.Sig) < previewLen {
				previewLen = len(sig.Sig)
			}
			log.WithFields(log.Fields{
				"signature_index":   i,
				"signature_length":  len(sig.Sig),
				"signature_preview": sig.Sig[:previewLen],
				"keyid":             sig.KeyID,
			}).Info("[VSA] Signature after re-marshaling")
		}
	}

	return out, payloadHashHex, nil
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
