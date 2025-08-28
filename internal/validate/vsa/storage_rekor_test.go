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

func TestRekorBackend_CanonicalizeBase64(t *testing.T) {
	backend := &RekorBackend{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard base64 with padding",
			input:    "SGVsbG8gV29ybGQ=",
			expected: "SGVsbG8gV29ybGQ=",
		},
		{
			name:     "raw base64 without padding",
			input:    "SGVsbG8gV29ybGQ",
			expected: "SGVsbG8gV29ybGQ=",
		},
		{
			name:     "base64 with newlines",
			input:    "SGVsbG8g\nV29ybGQ=",
			expected: "SGVsbG8gV29ybGQ=",
		},
		{
			name:     "base64 with multiple newlines and padding",
			input:    "SGVsbG8g\nV29ybGQ=\n",
			expected: "SGVsbG8gV29ybGQ=",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "string with only newlines",
			input:    "\n\n\n",
			expected: "",
		},
		{
			name:     "string with only padding",
			input:    "====",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := backend.canonicalizeBase64([]byte(tt.input))
			if err != nil {
				t.Fatalf("canonicalizeBase64() error = %v", err)
			}

			if string(result) != tt.expected {
				t.Errorf("canonicalizeBase64() = %v, want %v", string(result), tt.expected)
			}
		})
	}
}

func TestRekorBackend_PrepareDSSEForRekor(t *testing.T) {
	backend := &RekorBackend{}

	// Test DSSE envelope with standard base64
	dsseEnvelope := `{
		"payload": "SGVsbG8gV29ybGQ=",
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

	// Verify the envelope was canonicalized
	var envelope map[string]interface{}
	if err := json.Unmarshal(preparedEnvelope, &envelope); err != nil {
		t.Fatalf("failed to unmarshal prepared envelope: %v", err)
	}

	// Check that payload was canonicalized
	if payload, ok := envelope["payload"].(string); ok {
		if payload != "SGVsbG8gV29ybGQ=" {
			t.Errorf("payload not canonicalized correctly, got %s, want SGVsbG8gV29ybGQ=", payload)
		}
	} else {
		t.Error("payload not found in envelope")
	}

	// Check that signature was canonicalized and public key was injected
	if signatures, ok := envelope["signatures"].([]interface{}); ok {
		if len(signatures) > 0 {
			if sigMap, ok := signatures[0].(map[string]interface{}); ok {
				if sig, ok := sigMap["sig"].(string); ok {
					if sig != "dGVzdC1zaWduYXR1cmU=" {
						t.Errorf("signature not canonicalized correctly, got %s, want dGVzdC1zaWduYXR1cmU=", sig)
					}
				}
				if pubKey, ok := sigMap["publicKey"].(string); ok {
					if pubKey != string(pubKeyBytes) {
						t.Errorf("public key not injected correctly")
					}
				} else {
					t.Error("public key not found in signature")
				}
			}
		}
	}

	// Verify payload hash is not empty
	if payloadHash == "" {
		t.Error("payload hash is empty")
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
