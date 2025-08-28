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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"
)

// mockRekorClient implements RekorClient for testing
type mockRekorClient struct {
	searchEntries []models.LogEntryAnon
	searchError   error
	indexEntry    *models.LogEntryAnon
	indexError    error
	uuidEntry     *models.LogEntryAnon
	uuidError     error
}

func (m *mockRekorClient) SearchIndex(ctx context.Context, query *models.SearchIndex) ([]models.LogEntryAnon, error) {
	if m.searchError != nil {
		return nil, m.searchError
	}
	fmt.Printf("Mock SearchIndex called, returning %d entries\n", len(m.searchEntries))
	return m.searchEntries, nil
}

func (m *mockRekorClient) SearchLogQuery(ctx context.Context, query *models.SearchLogQuery) ([]models.LogEntryAnon, error) {
	if m.searchError != nil {
		return nil, m.searchError
	}
	fmt.Printf("Mock SearchLogQuery called, returning %d entries\n", len(m.searchEntries))
	return m.searchEntries, nil
}

func (m *mockRekorClient) GetLogEntryByIndex(ctx context.Context, index int64) (*models.LogEntryAnon, error) {
	if m.indexError != nil {
		return nil, m.indexError
	}
	return m.indexEntry, nil
}

func (m *mockRekorClient) GetLogEntryByUUID(ctx context.Context, uuid string) (*models.LogEntryAnon, error) {
	if m.uuidError != nil {
		return nil, m.uuidError
	}
	return m.uuidEntry, nil
}

func TestNewRekorVSARetriever(t *testing.T) {
	tests := []struct {
		name        string
		options     RetrievalOptions
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid options",
			options: RetrievalOptions{
				URL:     "https://rekor.example.com",
				Timeout: 30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "missing rekor URL",
			options: RetrievalOptions{
				Timeout: 30 * time.Second,
			},
			expectError: true,
			errorMsg:    "RekorURL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retriever, err := NewRekorVSARetriever(tt.options)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, retriever)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, retriever)
				assert.Equal(t, tt.options, retriever.options)
			}
		})
	}
}

func TestRekorVSARetriever_RetrieveVSA(t *testing.T) {
	tests := []struct {
		name          string
		imageDigest   string
		mockEntries   []models.LogEntryAnon
		mockError     error
		expectedCount int
		expectError   bool
		expectedError string
	}{
		{
			name:        "single VSA record found",
			imageDigest: "sha256:abc123",
			mockEntries: []models.LogEntryAnon{
				{
					LogIndex:       int64Ptr(1),
					LogID:          stringPtr("test-log-id"),
					IntegratedTime: int64Ptr(1234567890),
					Body:           "test-body",
					Attestation: &models.LogEntryAnonAttestation{
						Data: strfmt.Base64("eyJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9jb25mb3JtYS5kZXYvdmVyaWZpY2F0aW9uX3N1bW1hcnkvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoicXVheS5pby90ZXN0L2ltYWdlIiwiZGlnZXN0Ijp7InNoYTI1NiI6ImFiYzEyMyJ9fV19"),
					},
				},
			},
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:        "multiple VSA records found",
			imageDigest: "sha256:abc123",
			mockEntries: []models.LogEntryAnon{
				{
					LogIndex:       int64Ptr(1),
					LogID:          stringPtr("test-log-id-1"),
					IntegratedTime: int64Ptr(1234567890),
					Body:           "test-body-1",
					Attestation: &models.LogEntryAnonAttestation{
						Data: strfmt.Base64("eyJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9jb25mb3JtYS5kZXYvdmVyaWZpY2F0aW9uX3N1bW1hcnkvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoicXVheS5pby90ZXN0L2ltYWdlIiwiZGlnZXN0Ijp7InNoYTI1NiI6ImFiYzEyMyJ9fV19"),
					},
				},
				{
					LogIndex:       int64Ptr(2),
					LogID:          stringPtr("test-log-id-2"),
					IntegratedTime: int64Ptr(1234567891),
					Body:           "test-body-2",
					Attestation: &models.LogEntryAnonAttestation{
						Data: strfmt.Base64("eyJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9jb25mb3JtYS5kZXYvdmVyaWZpY2F0aW9uX3N1bW1hcnkvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoicXVheS5pby90ZXN0L2ltYWdlIiwiZGlnZXN0Ijp7InNoYTI1NiI6ImFiYzEyMyJ9fV19"),
					},
				},
			},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "no VSA records found",
			imageDigest:   "sha256:abc123",
			mockEntries:   []models.LogEntryAnon{},
			expectedCount: 0,
			expectError:   false,
		},
		{
			name:          "empty image digest",
			imageDigest:   "",
			expectError:   true,
			expectedError: "image digest cannot be empty",
		},
		{
			name:          "invalid image digest format",
			imageDigest:   "invalid-digest",
			expectError:   true,
			expectedError: "invalid image digest format",
		},
		{
			name:          "Rekor search error",
			imageDigest:   "sha256:abc123",
			mockError:     errors.New("rekor unreachable"),
			expectError:   true,
			expectedError: "failed to search Rekor for image digest",
		},
		{
			name:          "unsupported algorithm",
			imageDigest:   "md5:abc123",
			expectError:   true,
			expectedError: "invalid image digest format",
		},
		{
			name:          "invalid hex hash",
			imageDigest:   "sha256:invalid-hex",
			expectError:   true,
			expectedError: "invalid image digest format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockRekorClient{
				searchEntries: tt.mockEntries,
				searchError:   tt.mockError,
			}

			t.Logf("Creating retriever with mock client")
			retriever := NewRekorVSARetrieverWithClient(mockClient, RetrievalOptions{
				URL:     "https://rekor.example.com",
				Timeout: 30 * time.Second,
			})

			// Debug: Check what the mock client has
			t.Logf("Mock client has %d entries", len(tt.mockEntries))
			for i, entry := range tt.mockEntries {
				t.Logf("Entry %d: LogIndex=%v, LogID=%v, Body=%v, Attestation=%v",
					i, entry.LogIndex, entry.LogID, entry.Body, entry.Attestation)
				if entry.Attestation != nil && entry.Attestation.Data != nil {
					decoded, err := base64.StdEncoding.DecodeString(string(entry.Attestation.Data))
					t.Logf("Entry %d: Decoded attestation data: %s (err: %v)", i, string(decoded), err)
				}
			}

			t.Logf("Calling RetrieveVSA with image digest: %s", tt.imageDigest)
			records, err := retriever.RetrieveVSA(context.Background(), tt.imageDigest)

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedError != "" {
					assert.Contains(t, err.Error(), tt.expectedError)
				}
				assert.Nil(t, records)
			} else {
				assert.NoError(t, err)
				t.Logf("Retrieved %d records", len(records))
				assert.Len(t, records, tt.expectedCount)

				// Verify record structure
				for i, record := range records {
					assert.NotZero(t, record.LogIndex)
					assert.NotEmpty(t, record.LogID)
					assert.NotZero(t, record.IntegratedTime)
					assert.NotNil(t, record.Attestation)

					// Verify the record contains the image digest
					assert.True(t, isVSARecord(tt.mockEntries[i], tt.imageDigest))
				}
			}
		})
	}
}

func TestIsValidImageDigest(t *testing.T) {
	tests := []struct {
		name     string
		digest   string
		expected bool
	}{
		{
			name:     "valid sha256 digest",
			digest:   "sha256:abc123def4567890abcdef1234567890abcdef1234567890abcdef1234567890",
			expected: true,
		},
		{
			name:     "valid sha512 digest",
			digest:   "sha512:abc123def4567890abcdef1234567890abcdef1234567890abcdef1234567890",
			expected: true,
		},
		{
			name:     "empty digest",
			digest:   "",
			expected: false,
		},
		{
			name:     "missing algorithm",
			digest:   "abc123",
			expected: false,
		},
		{
			name:     "unsupported algorithm",
			digest:   "md5:abc123",
			expected: false,
		},
		{
			name:     "invalid hex hash",
			digest:   "sha256:invalid-hex",
			expected: false,
		},
		{
			name:     "empty hash",
			digest:   "sha256:",
			expected: false,
		},
		{
			name:     "multiple colons",
			digest:   "sha256:abc:123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidImageDigest(tt.digest)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsVSARecord(t *testing.T) {
	tests := []struct {
		name        string
		entry       models.LogEntryAnon
		imageDigest string
		expected    bool
	}{
		{
			name: "valid VSA record with predicate type",
			entry: models.LogEntryAnon{
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64("eyJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9jb25mb3JtYS5kZXYvdmVyaWZpY2F0aW9uX3N1bW1hcnkvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoicXVheS5pby90ZXN0L2ltYWdlIiwiZGlnZXN0Ijp7InNoYTI1NiI6ImFiYzEyMyJ9fV19"),
				},
			},
			imageDigest: "sha256:abc123",
			expected:    true,
		},
		{
			name: "entry without attestation",
			entry: models.LogEntryAnon{
				Body: "sha256:abc123",
			},
			imageDigest: "sha256:abc123",
			expected:    false,
		},
		{
			name: "entry with nil attestation data",
			entry: models.LogEntryAnon{
				Attestation: &models.LogEntryAnonAttestation{
					Data: nil,
				},
			},
			imageDigest: "sha256:abc123",
			expected:    false,
		},
		{
			name: "entry with non-VSA attestation",
			entry: models.LogEntryAnon{
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64("eyJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9vdGhlci1hdHRlc3RhdGlvbiIsInN1YmplY3QiOlt7Im5hbWUiOiJxdWF5LmlvL3Rlc3QvaW1hZ2UiLCJkaWdlc3QiOnsic2hhMjU2IjoiZGVmNDU2In19XX0="),
				},
			},
			imageDigest: "sha256:abc123",
			expected:    false,
		},
		{
			name: "entry with malformed attestation data",
			entry: models.LogEntryAnon{
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64("aW52YWxpZC1iYXNlNjQ="),
				},
			},
			imageDigest: "sha256:abc123",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isVSARecord(tt.entry, tt.imageDigest)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseVSARecord(t *testing.T) {
	retriever := &RekorVSARetriever{}

	tests := []struct {
		name        string
		entry       models.LogEntryAnon
		expected    VSARecord
		expectError bool
	}{
		{
			name: "complete entry",
			entry: models.LogEntryAnon{
				LogIndex:       int64Ptr(1),
				LogID:          stringPtr("test-log-id"),
				IntegratedTime: int64Ptr(1234567890),
				Body:           "test-body",
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64("dGVzdC1kYXRh"),
				},
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{},
				},
			},
			expected: VSARecord{
				LogIndex:       1,
				LogID:          "test-log-id",
				IntegratedTime: 1234567890,
				Body:           "test-body",
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64("dGVzdC1kYXRh"),
				},
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{},
				},
			},
			expectError: false,
		},
		{
			name: "entry with nil fields",
			entry: models.LogEntryAnon{
				LogIndex:       nil,
				LogID:          nil,
				IntegratedTime: nil,
				Body:           nil,
			},
			expected: VSARecord{
				LogIndex:       0,
				LogID:          "",
				IntegratedTime: 0,
				Body:           "",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := retriever.parseVSARecord(tt.entry)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestDefaultRetrievalOptions(t *testing.T) {
	opts := DefaultRetrievalOptions()

	assert.Equal(t, 30*time.Second, opts.Timeout)
	assert.Equal(t, "https://rekor.sigstore.dev", opts.URL)
}

func TestMockRekorClient(t *testing.T) {
	mockClient := &mockRekorClient{
		searchEntries: []models.LogEntryAnon{
			{
				LogIndex: int64Ptr(1),
				LogID:    stringPtr("test-log-id"),
			},
		},
	}

	entries, err := mockClient.SearchLogQuery(context.Background(), &models.SearchLogQuery{})
	assert.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, int64(1), *entries[0].LogIndex)
	assert.Equal(t, "test-log-id", *entries[0].LogID)
}

// Helper functions for creating test data
func int64Ptr(v int64) *int64 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}
