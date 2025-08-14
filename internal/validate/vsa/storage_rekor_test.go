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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
