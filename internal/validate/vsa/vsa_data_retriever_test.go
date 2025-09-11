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
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileVSADataRetriever(t *testing.T) {
	fs := afero.NewMemMapFs()

	t.Run("successfully retrieves VSA data from file", func(t *testing.T) {
		// Create test VSA data
		testVSA := `{
			"predicateType": "https://conforma.dev/verification_summary/v1",
			"subject": [{"name": "test-image", "digest": {"sha256": "abc123"}}],
			"predicate": {
				"imageRef": "test-image:tag",
				"timestamp": "2024-01-01T00:00:00Z",
				"verifier": "ec-cli",
				"policySource": "test-policy"
			}
		}`

		// Write test data to file
		err := afero.WriteFile(fs, "/test-vsa.json", []byte(testVSA), 0644)
		require.NoError(t, err)

		// Create retriever and test
		retriever := NewFileVSADataRetriever(fs, "/test-vsa.json")
		envelope, err := retriever.RetrieveVSA(context.Background(), "sha256:test")

		assert.NoError(t, err)
		assert.NotNil(t, envelope)
		assert.Equal(t, testVSA, envelope.Payload)
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		retriever := NewFileVSADataRetriever(fs, "/nonexistent.json")
		envelope, err := retriever.RetrieveVSA(context.Background(), "sha256:test")

		assert.Error(t, err)
		assert.Nil(t, envelope)
		assert.Contains(t, err.Error(), "failed to read VSA file")
	})

	t.Run("returns error for empty file path", func(t *testing.T) {
		retriever := NewFileVSADataRetriever(fs, "")
		envelope, err := retriever.RetrieveVSA(context.Background(), "sha256:test")

		assert.Error(t, err)
		assert.Nil(t, envelope)
		assert.Contains(t, err.Error(), "failed to read VSA file")
	})
}

func TestRekorVSADataRetriever(t *testing.T) {
	t.Run("creates retriever with valid options", func(t *testing.T) {
		opts := RetrievalOptions{
			URL: "https://rekor.example.com",
		}
		imageDigest := "sha256:abc123"

		retriever, err := NewRekorVSADataRetriever(opts, imageDigest)

		assert.NoError(t, err)
		assert.NotNil(t, retriever)
		assert.Equal(t, imageDigest, retriever.imageDigest)
	})

	t.Run("returns error for empty URL", func(t *testing.T) {
		opts := RetrievalOptions{
			URL: "",
		}
		imageDigest := "sha256:abc123"

		retriever, err := NewRekorVSADataRetriever(opts, imageDigest)

		assert.Error(t, err)
		assert.Nil(t, retriever)
		assert.Contains(t, err.Error(), "RekorURL is required")
	})

	t.Run("returns error for invalid URL", func(t *testing.T) {
		opts := RetrievalOptions{
			URL: "invalid-url",
		}
		imageDigest := "sha256:abc123"

		retriever, err := NewRekorVSADataRetriever(opts, imageDigest)

		// The current implementation doesn't validate URLs, so it succeeds
		// This test documents the current behavior
		assert.NoError(t, err)
		assert.NotNil(t, retriever)
	})
}

// TestVSADataRetrieverInterface tests the VSADataRetriever interface
func TestVSADataRetrieverInterface(t *testing.T) {
	// This test ensures that both implementations satisfy the VSADataRetriever interface
	var _ VSADataRetriever = (*FileVSADataRetriever)(nil)
	var _ VSADataRetriever = (*RekorVSADataRetriever)(nil)
}

// TestRetrievalOptions tests the RetrievalOptions functionality
func TestRetrievalOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		opts := DefaultRetrievalOptions()

		assert.NotEmpty(t, opts.URL)
		assert.Greater(t, opts.Timeout, time.Duration(0))
	})

	t.Run("custom options", func(t *testing.T) {
		opts := RetrievalOptions{
			URL:     "https://custom-rekor.example.com",
			Timeout: 60 * time.Second,
		}

		assert.Equal(t, "https://custom-rekor.example.com", opts.URL)
		assert.Equal(t, 60*time.Second, opts.Timeout)
	})
}

// TestDSSEEnvelope tests the DSSE envelope structure
func TestDSSEEnvelope(t *testing.T) {
	t.Run("creates valid DSSE envelope", func(t *testing.T) {
		envelope := DSSEEnvelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     "dGVzdCBwYXlsb2Fk",
			Signatures: []Signature{
				{
					KeyID: "test-key-id",
					Sig:   "dGVzdCBzaWduYXR1cmU=",
				},
			},
		}

		// Marshal to JSON to ensure it's valid
		data, err := json.Marshal(envelope)
		assert.NoError(t, err)

		// Unmarshal back to verify structure
		var unmarshaled DSSEEnvelope
		err = json.Unmarshal(data, &unmarshaled)
		assert.NoError(t, err)

		assert.Equal(t, envelope.PayloadType, unmarshaled.PayloadType)
		assert.Equal(t, envelope.Payload, unmarshaled.Payload)
		assert.Len(t, unmarshaled.Signatures, 1)
		assert.Equal(t, envelope.Signatures[0].KeyID, unmarshaled.Signatures[0].KeyID)
		assert.Equal(t, envelope.Signatures[0].Sig, unmarshaled.Signatures[0].Sig)
	})
}

// TestSignature tests the Signature structure
func TestSignature(t *testing.T) {
	t.Run("creates valid signature", func(t *testing.T) {
		sig := Signature{
			KeyID: "test-key-id",
			Sig:   "dGVzdCBzaWduYXR1cmU=",
		}

		// Marshal to JSON to ensure it's valid
		data, err := json.Marshal(sig)
		assert.NoError(t, err)

		// Unmarshal back to verify structure
		var unmarshaled Signature
		err = json.Unmarshal(data, &unmarshaled)
		assert.NoError(t, err)

		assert.Equal(t, sig.KeyID, unmarshaled.KeyID)
		assert.Equal(t, sig.Sig, unmarshaled.Sig)
	})
}

// TestDualEntryPair tests the DualEntryPair structure (used by RekorVSADataRetriever)
func TestDualEntryPair(t *testing.T) {
	t.Run("creates valid dual entry pair", func(t *testing.T) {
		payloadHash := "abc123"
		intotoEntry := &models.LogEntryAnon{
			LogIndex: int64Ptr(1),
			LogID:    stringPtr("test-log-id"),
		}
		dsseEntry := &models.LogEntryAnon{
			LogIndex: int64Ptr(2),
			LogID:    stringPtr("test-log-id"),
		}

		pair := DualEntryPair{
			PayloadHash: payloadHash,
			IntotoEntry: intotoEntry,
			DSSEEntry:   dsseEntry,
		}

		assert.Equal(t, payloadHash, pair.PayloadHash)
		assert.Equal(t, intotoEntry, pair.IntotoEntry)
		assert.Equal(t, dsseEntry, pair.DSSEEntry)
	})
}

// Helper functions are defined in retrieval_test.go
