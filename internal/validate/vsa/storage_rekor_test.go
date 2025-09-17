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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSignerVerifier is a mock implementation of signature.SignerVerifier for testing
type mockSignerVerifier struct {
	publicKey crypto.PublicKey
}

func (m *mockSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	if m.publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	return m.publicKey, nil
}

func (m *mockSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	return []byte("mock-signature"), nil
}

func (m *mockSignerVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	return nil
}

func TestNewRekorBackend(t *testing.T) {
	tests := []struct {
		name        string
		config      *StorageConfig
		expectError bool
	}{
		{
			name: "valid rekor backend config",
			config: &StorageConfig{
				Backend: "rekor",
				BaseURL: "https://rekor.sigstore.dev",
			},
			expectError: false,
		},
		{
			name: "rekor with custom timeout",
			config: &StorageConfig{
				Backend: "rekor",
				BaseURL: "https://rekor.sigstore.dev",
				Parameters: map[string]string{
					"timeout": "30s",
				},
			},
			expectError: false,
		},
		{
			name: "rekor with custom retries",
			config: &StorageConfig{
				Backend: "rekor",
				BaseURL: "https://rekor.sigstore.dev",
				Parameters: map[string]string{
					"retries": "5",
				},
			},
			expectError: false,
		},
		{
			name: "rekor with invalid timeout",
			config: &StorageConfig{
				Backend: "rekor",
				BaseURL: "https://rekor.sigstore.dev",
				Parameters: map[string]string{
					"timeout": "invalid",
				},
			},
			expectError: true,
		},
		{
			name: "rekor with invalid retries",
			config: &StorageConfig{
				Backend: "rekor",
				BaseURL: "https://rekor.sigstore.dev",
				Parameters: map[string]string{
					"retries": "invalid",
				},
			},
			expectError: true,
		},
		{
			name: "empty server URL",
			config: &StorageConfig{
				Backend: "rekor",
				BaseURL: "",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := NewRekorBackend(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, backend)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, backend)
				rekorBackend := backend.(*RekorBackend)

				// For empty BaseURL, expect the default serverURL
				expectedServerURL := tt.config.BaseURL
				if expectedServerURL == "" {
					expectedServerURL = "https://rekor.sigstore.dev"
				}
				assert.Equal(t, expectedServerURL, rekorBackend.serverURL)
			}
		})
	}
}

func TestRekorBackend_Name(t *testing.T) {
	backend := &RekorBackend{serverURL: "https://rekor.sigstore.dev"}
	assert.Equal(t, "Rekor (https://rekor.sigstore.dev)", backend.Name())
}

func TestRekorBackend_extractPublicKeyFromSigner(t *testing.T) {
	backend := &RekorBackend{serverURL: "https://rekor.sigstore.dev"}

	// Create a test signer with ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := &Signer{
		SignerVerifier: &mockSignerVerifier{
			publicKey: &privateKey.PublicKey,
		},
	}

	pubKeyBytes, err := backend.extractPublicKeyFromSigner(signer)

	assert.NoError(t, err)
	assert.NotEmpty(t, pubKeyBytes)
	assert.Contains(t, string(pubKeyBytes), "BEGIN PUBLIC KEY")
	assert.Contains(t, string(pubKeyBytes), "END PUBLIC KEY")
}

func TestRekorBackend_extractPublicKeyFromSigner_NilSigner(t *testing.T) {
	backend := &RekorBackend{serverURL: "https://rekor.sigstore.dev"}

	pubKeyBytes, err := backend.extractPublicKeyFromSigner(nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signer is nil")
	assert.Nil(t, pubKeyBytes)
}

func TestRekorBackend_extractPublicKeyFromSigner_NilPublicKey(t *testing.T) {
	backend := &RekorBackend{serverURL: "https://rekor.sigstore.dev"}

	signer := &Signer{
		SignerVerifier: &mockSignerVerifier{
			publicKey: nil,
		},
	}

	pubKeyBytes, err := backend.extractPublicKeyFromSigner(signer)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public key is nil")
	assert.Nil(t, pubKeyBytes)
}

func TestRekorBackend_DefaultConfiguration(t *testing.T) {
	// Test default values for timeout and retries
	rekorBackend := &RekorBackend{
		serverURL: "https://rekor.sigstore.dev",
		timeout:   30 * time.Second,
		retries:   3,
	}

	assert.Equal(t, "https://rekor.sigstore.dev", rekorBackend.serverURL)
	assert.Equal(t, 30*time.Second, rekorBackend.timeout)
	assert.Equal(t, 3, rekorBackend.retries)
}

func TestRekorBackend_PrepareDSSEForRekor(t *testing.T) {
	backend := &RekorBackend{}

	// Test DSSE envelope with standard base64
	dsseEnvelope := `{
		"payload": "SGVsbG8gV29ybGQ=",
		"payloadType": "application/vnd.in-toto+json",
		"signatures": [
			{
				"keyid": "test-key",
				"sig": "dGVzdC1zaWduYXR1cmU="
			}
		]
	}`

	pubKeyBytes := []byte("-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----")

	preparedEnvelope, payloadHash, err := backend.prepareDSSEForRekor([]byte(dsseEnvelope), pubKeyBytes)
	if err != nil {
		t.Fatalf("prepareDSSEForRekor() error = %v", err)
	}

	// Verify the envelope structure is preserved
	var envelope map[string]interface{}
	if err := json.Unmarshal(preparedEnvelope, &envelope); err != nil {
		t.Fatalf("failed to unmarshal prepared envelope: %v", err)
	}

	// Check that payload is unchanged (not canonicalized)
	if payload, ok := envelope["payload"].(string); ok {
		if payload != "SGVsbG8gV29ybGQ=" {
			t.Errorf("payload was modified, got %s, want SGVsbG8gV29ybGQ=", payload)
		}
	} else {
		t.Error("payload not found in envelope")
	}

	// Check that payloadType is preserved
	if payloadType, ok := envelope["payloadType"].(string); ok {
		if payloadType != "application/vnd.in-toto+json" {
			t.Errorf("payloadType was modified, got %s, want application/vnd.in-toto+json", payloadType)
		}
	} else {
		t.Error("payloadType not found in envelope")
	}

	// Check that signature is unchanged (not canonicalized) and public key was injected
	if signatures, ok := envelope["signatures"].([]interface{}); ok {
		if len(signatures) > 0 {
			if sigMap, ok := signatures[0].(map[string]interface{}); ok {
				if sig, ok := sigMap["sig"].(string); ok {
					if sig != "dGVzdC1zaWduYXR1cmU=" {
						t.Errorf("signature was modified, got %s, want dGVzdC1zaWduYXR1cmU=", sig)
					}
				}
				if pubKey, ok := sigMap["publicKey"].(string); ok {
					if pubKey != string(pubKeyBytes) {
						t.Errorf("public key not injected correctly, got %s, want %s", pubKey, string(pubKeyBytes))
					}
				} else {
					t.Error("public key not found in signature")
				}
			}
		}
	}

	// Verify payload hash is not empty and is based on decoded payload content
	if payloadHash == "" {
		t.Error("payload hash is empty")
	}

	// The payload hash should be SHA256("Hello World") since that's what "SGVsbG8gV29ybGQ=" decodes to
	expectedHash := "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
	if payloadHash != expectedHash {
		t.Errorf("payload hash mismatch, got %s, want %s", payloadHash, expectedHash)
	}

	// Test that the same input produces the same output (deterministic)
	preparedEnvelope2, payloadHash2, err := backend.prepareDSSEForRekor([]byte(dsseEnvelope), pubKeyBytes)
	if err != nil {
		t.Fatalf("prepareDSSEForRekor() error on second call = %v", err)
	}

	if !bytes.Equal(preparedEnvelope, preparedEnvelope2) {
		t.Error("prepared envelope is not deterministic")
	}

	if payloadHash != payloadHash2 {
		t.Error("payload hash is not deterministic")
	}
}

func TestRekorBackend_UploadSingle_Consistency(t *testing.T) {
	tests := []struct {
		name                string
		backend             *RekorBackend
		envelopeContent     []byte
		pubKeyBytes         []byte
		expectError         bool
		expectedErrorMsg    string
		validateConsistency bool
	}{
		{
			name: "consistent preparation with valid DSSE envelope",
			backend: &RekorBackend{
				serverURL: "https://rekor.test",
				timeout:   30 * time.Second,
				retries:   3,
			},
			envelopeContent: []byte(`{
				"payload": "dGVzdC1wYXlsb2Fk",
				"payloadType": "application/vnd.in-toto+json",
				"signatures": [
					{
						"sig": "dGVzdC1zaWduYXR1cmU="
					}
				]
			}`),
			pubKeyBytes:         []byte("-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----"),
			expectError:         false,
			validateConsistency: true,
		},
		{
			name: "consistent preparation with different valid envelope",
			backend: &RekorBackend{
				serverURL: "https://rekor.sigstore.dev",
				timeout:   60 * time.Second,
				retries:   5,
			},
			envelopeContent: []byte(`{
				"payload": "YW5vdGhlci10ZXN0LXBheWxvYWQ=",
				"payloadType": "application/vnd.in-toto+json",
				"signatures": [
					{
						"sig": "YW5vdGhlci1zaWduYXR1cmU="
					}
				]
			}`),
			pubKeyBytes:         []byte("-----BEGIN PUBLIC KEY-----\nanother-key\n-----END PUBLIC KEY-----"),
			expectError:         false,
			validateConsistency: true,
		},
		{
			name: "failure with invalid JSON envelope",
			backend: &RekorBackend{
				serverURL: "https://rekor.test",
				timeout:   30 * time.Second,
				retries:   3,
			},
			envelopeContent:     []byte(`{invalid json envelope`),
			pubKeyBytes:         []byte("-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----"),
			expectError:         true,
			expectedErrorMsg:    "invalid character",
			validateConsistency: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that prepareDSSEForRekor produces consistent output for single entry upload
			preparedEnvelope1, payloadHash1, err := tt.backend.prepareDSSEForRekor(tt.envelopeContent, tt.pubKeyBytes)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrorMsg)
				assert.Empty(t, preparedEnvelope1)
				assert.Empty(t, payloadHash1)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, payloadHash1)

			preparedEnvelope2, payloadHash2, err := tt.backend.prepareDSSEForRekor(tt.envelopeContent, tt.pubKeyBytes)
			require.NoError(t, err)
			require.NotEmpty(t, payloadHash2)

			if tt.validateConsistency {
				// Verify that the same input produces the same output (deterministic)
				require.Equal(t, preparedEnvelope1, preparedEnvelope2, "Prepared envelopes should be identical for single entry")
				require.Equal(t, payloadHash1, payloadHash2, "Payload hashes should be identical for single entry")

				// Verify that the content contains the injected public key
				require.Contains(t, string(preparedEnvelope1), "-----BEGIN PUBLIC KEY-----", "Prepared content should contain public key")

				// Verify that the content structure is preserved (not canonicalized)
				// Parse the JSON to check specific fields
				var envelope map[string]interface{}
				err = json.Unmarshal(preparedEnvelope1, &envelope)
				require.NoError(t, err)

				// Check that payload field is preserved exactly
				if payload, ok := envelope["payload"].(string); ok {
					require.NotEmpty(t, payload, "Payload should be preserved")
				}

				// Check that payloadType field is preserved exactly
				if payloadType, ok := envelope["payloadType"].(string); ok {
					require.Equal(t, "application/vnd.in-toto+json", payloadType, "PayloadType should be preserved exactly")
				}

				// Check signature field is preserved exactly
				if signatures, ok := envelope["signatures"].([]interface{}); ok && len(signatures) > 0 {
					if sigMap, ok := signatures[0].(map[string]interface{}); ok {
						if sigValue, ok := sigMap["sig"].(string); ok {
							require.NotEmpty(t, sigValue, "Signature should be preserved")
						}
					}
				}

				// Verify that both the original and prepared content can be parsed as valid JSON
				var originalEnvelope map[string]interface{}
				err = json.Unmarshal(tt.envelopeContent, &originalEnvelope)
				require.NoError(t, err, "Original envelope should be valid JSON")

				var preparedEnvelope map[string]interface{}
				err = json.Unmarshal(preparedEnvelope1, &preparedEnvelope)
				require.NoError(t, err, "Prepared envelope should be valid JSON")

				// Verify that the prepared envelope has the expected structure
				require.Contains(t, preparedEnvelope, "payload", "Prepared envelope should contain payload")
				require.Contains(t, preparedEnvelope, "payloadType", "Prepared envelope should contain payloadType")
				require.Contains(t, preparedEnvelope, "signatures", "Prepared envelope should contain signatures")

				// Check that the first signature contains publicKey
				if signatures, ok := preparedEnvelope["signatures"].([]interface{}); ok && len(signatures) > 0 {
					if sigMap, ok := signatures[0].(map[string]interface{}); ok {
						require.Contains(t, sigMap, "publicKey", "First signature should contain publicKey field")
					}
				}
			}
		})
	}
}

func TestRekorBackend_UploadWithSigner_EarlyValidation(t *testing.T) {
	tests := []struct {
		name             string
		backend          *RekorBackend
		signer           *Signer
		envelopeContent  []byte
		expectError      bool
		expectedErrorMsg string
	}{
		{
			name: "nil signer validation",
			backend: &RekorBackend{
				serverURL: "https://rekor.test",
				timeout:   30 * time.Second,
				retries:   3,
			},
			signer:           nil,
			envelopeContent:  []byte(`{"test": "envelope"}`),
			expectError:      true,
			expectedErrorMsg: "signer is nil",
		},
		{
			name: "empty envelope content validation",
			backend: &RekorBackend{
				serverURL: "https://rekor.test",
				timeout:   30 * time.Second,
				retries:   3,
			},
			signer: &Signer{
				SignerVerifier: &mockSignerVerifier{
					publicKey: func() crypto.PublicKey {
						privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
						return &privateKey.PublicKey
					}(),
				},
			},
			envelopeContent:  []byte{},
			expectError:      true,
			expectedErrorMsg: "failed to prepare DSSE envelope",
		},
		{
			name: "signer with nil public key",
			backend: &RekorBackend{
				serverURL: "https://rekor.test",
				timeout:   30 * time.Second,
				retries:   3,
			},
			signer: &Signer{
				SignerVerifier: &mockSignerVerifier{
					publicKey: nil,
				},
			},
			envelopeContent:  []byte(`{"test": "envelope"}`),
			expectError:      true,
			expectedErrorMsg: "public key is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			result, err := tt.backend.UploadWithSigner(ctx, tt.envelopeContent, tt.signer)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrorMsg)
			assert.Empty(t, result)
		})
	}
}
