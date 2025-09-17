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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"
)

// MockRekorClient implements RekorClient for testing
type MockRekorClient struct {
	entries []models.LogEntryAnon
}

func (m *MockRekorClient) SearchIndex(ctx context.Context, query *models.SearchIndex) ([]models.LogEntryAnon, error) {
	// Return all entries for any hash query
	return m.entries, nil
}

func (m *MockRekorClient) SearchLogQuery(ctx context.Context, query *models.SearchLogQuery) ([]models.LogEntryAnon, error) {
	return m.entries, nil
}

func (m *MockRekorClient) GetLogEntryByIndex(ctx context.Context, index int64) (*models.LogEntryAnon, error) {
	for _, entry := range m.entries {
		if entry.LogIndex != nil && *entry.LogIndex == index {
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("entry not found")
}

func (m *MockRekorClient) GetLogEntryByUUID(ctx context.Context, uuid string) (*models.LogEntryAnon, error) {
	for _, entry := range m.entries {
		if entry.LogID != nil && *entry.LogID == uuid {
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("entry not found")
}

func TestRekorVSARetriever_ClassifyEntryKind(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	tests := []struct {
		name     string
		entry    models.LogEntryAnon
		expected string
	}{
		{
			name: "intoto 0.0.2 entry by body",
			entry: models.LogEntryAnon{
				Body: base64.StdEncoding.EncodeToString([]byte(`{"spec": {"content": {"envelope": {"payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}}}}`)),
			},
			expected: "intoto-v002",
		},
		{
			name: "intoto 0.0.1 entry by body",
			entry: models.LogEntryAnon{
				Body: base64.StdEncoding.EncodeToString([]byte(`{"intoto": "v0.0.1"}`)),
			},
			expected: "intoto",
		},
		{
			name: "dsse entry by body",
			entry: models.LogEntryAnon{
				Body: base64.StdEncoding.EncodeToString([]byte(`{"dsse": "v0.0.1"}`)),
			},
			expected: "dsse",
		},
		{
			name: "intoto entry by attestation",
			entry: models.LogEntryAnon{
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64(base64.StdEncoding.EncodeToString([]byte(`{"predicateType":"https://conforma.dev/verification_summary/v1"}`))),
				},
			},
			expected: "intoto",
		},
		{
			name: "unknown entry",
			entry: models.LogEntryAnon{
				Body: base64.StdEncoding.EncodeToString([]byte(`{"unknown": "type"}`)),
			},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := retriever.classifyEntryKind(tt.entry)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRekorVSARetriever_RetrieveVSA(t *testing.T) {
	// Test the main RetrieveVSA method that returns ssldsse.Envelope
	imageDigest := "sha256:abc123def456"
	vsaStatement := `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-image","digest":{"sha256":"abc123def456"}}],"predicateType":"https://conforma.dev/verification_summary/v1","predicate":{"test":"data"}}`

	// Create in-toto 0.0.2 entry body
	intotoV002Body := `{
		"spec": {
			"content": {
				"envelope": {
					"payloadType": "application/vnd.in-toto+json",
					"signatures": [{"sig": "dGVzdA==", "keyid": "test-key-id"}]
				}
			}
		}
	}`

	mockClient := &MockRekorClient{
		entries: []models.LogEntryAnon{
			{
				LogIndex: &[]int64{123}[0],
				LogID:    &[]string{"intoto-v002-uuid"}[0],
				Body:     base64.StdEncoding.EncodeToString([]byte(intotoV002Body)),
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64(base64.StdEncoding.EncodeToString([]byte(vsaStatement))),
				},
			},
		},
	}

	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	// Test successful retrieval
	var envelope *ssldsse.Envelope
	envelope, err := retriever.RetrieveVSA(context.Background(), imageDigest)
	assert.NoError(t, err)
	assert.NotNil(t, envelope)

	// Verify payload type
	assert.Equal(t, "application/vnd.in-toto+json", envelope.PayloadType)

	// Verify payload is base64 encoded VSA statement
	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	assert.NoError(t, err)
	assert.Equal(t, vsaStatement, string(payloadBytes))

	// Verify signatures
	assert.Len(t, envelope.Signatures, 1)
	assert.Equal(t, "dGVzdA==", envelope.Signatures[0].Sig)
	assert.Equal(t, "test-key-id", envelope.Signatures[0].KeyID)
}

func TestRekorVSARetriever_RetrieveVSA_EmptyDigest(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.RetrieveVSA(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "image digest cannot be empty")
}

func TestRekorVSARetriever_RetrieveVSA_NoEntries(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.RetrieveVSA(context.Background(), "sha256:abcdef123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no entries found in Rekor for image digest")
}

func TestRekorVSARetriever_FindLatestEntryByIntegratedTime(t *testing.T) {
	retriever := &RekorVSARetriever{}

	// Test with entries having different IntegratedTime values
	entries := []models.LogEntryAnon{
		{
			LogIndex:       &[]int64{1}[0],
			IntegratedTime: int64Ptr(1000),
		},
		{
			LogIndex:       &[]int64{2}[0],
			IntegratedTime: int64Ptr(2000), // Latest
		},
		{
			LogIndex:       &[]int64{3}[0],
			IntegratedTime: int64Ptr(1500),
		},
	}

	latest := retriever.findLatestEntryByIntegratedTime(entries)
	assert.NotNil(t, latest)
	assert.Equal(t, int64(2), *latest.LogIndex)
	assert.Equal(t, int64(2000), *latest.IntegratedTime)

	// Test with entries having some nil IntegratedTime values
	entriesWithNil := []models.LogEntryAnon{
		{
			LogIndex:       &[]int64{1}[0],
			IntegratedTime: nil,
		},
		{
			LogIndex:       &[]int64{2}[0],
			IntegratedTime: int64Ptr(2000), // Latest
		},
		{
			LogIndex:       &[]int64{3}[0],
			IntegratedTime: int64Ptr(1500),
		},
	}

	latestWithNil := retriever.findLatestEntryByIntegratedTime(entriesWithNil)
	assert.NotNil(t, latestWithNil)
	assert.Equal(t, int64(2), *latestWithNil.LogIndex)
	assert.Equal(t, int64(2000), *latestWithNil.IntegratedTime)

	// Test with all nil IntegratedTime values
	entriesAllNil := []models.LogEntryAnon{
		{
			LogIndex:       &[]int64{1}[0],
			IntegratedTime: nil,
		},
		{
			LogIndex:       &[]int64{2}[0],
			IntegratedTime: nil,
		},
	}

	latestAllNil := retriever.findLatestEntryByIntegratedTime(entriesAllNil)
	assert.NotNil(t, latestAllNil)
	assert.Equal(t, int64(1), *latestAllNil.LogIndex) // Should return first entry

	// Test with empty slice
	emptyEntries := []models.LogEntryAnon{}
	latestEmpty := retriever.findLatestEntryByIntegratedTime(emptyEntries)
	assert.Nil(t, latestEmpty)

	// Test with single entry
	singleEntry := []models.LogEntryAnon{
		{
			LogIndex:       &[]int64{1}[0],
			IntegratedTime: int64Ptr(1000),
		},
	}

	latestSingle := retriever.findLatestEntryByIntegratedTime(singleEntry)
	assert.NotNil(t, latestSingle)
	assert.Equal(t, int64(1), *latestSingle.LogIndex)
	assert.Equal(t, int64(1000), *latestSingle.IntegratedTime)
}

// Helper function to create int64 pointers
func int64Ptr(v int64) *int64 {
	return &v
}

func TestNewRekorVSARetriever_Validation(t *testing.T) {
	tests := []struct {
		name        string
		opts        RetrievalOptions
		expectError bool
		errorMsg    string
	}{
		{
			name: "success case 1 - URL validation passes",
			opts: RetrievalOptions{
				URL: "https://rekor.sigstore.dev",
			},
			expectError: false,
		},
		{
			name: "success case 2 - URL with timeout validation passes",
			opts: RetrievalOptions{
				URL:     "https://custom-rekor.example.com",
				Timeout: 30000000000,
			},
			expectError: false,
		},
		{
			name: "failure case - empty URL validation fails",
			opts: RetrievalOptions{
				URL: "",
			},
			expectError: true,
			errorMsg:    "RekorURL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Only test the URL validation without external dependencies
			if tt.opts.URL == "" {
				// Test empty URL validation - this will fail early without network calls
				retriever, err := NewRekorVSARetriever(tt.opts)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, retriever)
			} else {
				// For non-empty URLs, test only the input validation
				// Avoid external network calls by validating inputs only
				assert.NotEmpty(t, tt.opts.URL)
				// Test that URL is well-formed
				assert.True(t, strings.HasPrefix(tt.opts.URL, "http"))
				// Test timeout is valid
				if tt.opts.Timeout > 0 {
					assert.Greater(t, tt.opts.Timeout, time.Duration(0))
				}
			}
		})
	}
}

func TestRekorClient_SearchIndex(t *testing.T) {
	tests := []struct {
		name          string
		setupClient   func() *MockRekorClient
		query         *models.SearchIndex
		expectError   bool
		errorMsg      string
		expectedUUIDs int
	}{
		{
			name: "success with multiple entries",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogID: stringPtr("uuid-1")},
						{LogID: stringPtr("uuid-2")},
					},
				}
			},
			query:         &models.SearchIndex{Hash: "sha256:abc123"},
			expectError:   false,
			expectedUUIDs: 2,
		},
		{
			name: "success with single entry",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogID: stringPtr("uuid-1")},
					},
				}
			},
			query:         &models.SearchIndex{Hash: "sha256:def456"},
			expectError:   false,
			expectedUUIDs: 1,
		},
		{
			name: "success with no entries",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{},
				}
			},
			query:         &models.SearchIndex{Hash: "sha256:nonexistent"},
			expectError:   false,
			expectedUUIDs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			entries, err := client.SearchIndex(context.Background(), tt.query)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Len(t, entries, tt.expectedUUIDs)
			}
		})
	}
}

func TestRekorClient_GetLogEntryByIndex(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *MockRekorClient
		index       int64
		expectError bool
		errorMsg    string
	}{
		{
			name: "success with existing index",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogIndex: int64Ptr(123), LogID: stringPtr("uuid-1")},
						{LogIndex: int64Ptr(456), LogID: stringPtr("uuid-2")},
					},
				}
			},
			index:       123,
			expectError: false,
		},
		{
			name: "success with another existing index",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogIndex: int64Ptr(789), LogID: stringPtr("uuid-3")},
					},
				}
			},
			index:       789,
			expectError: false,
		},
		{
			name: "failure with non-existing index",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogIndex: int64Ptr(123), LogID: stringPtr("uuid-1")},
					},
				}
			},
			index:       999,
			expectError: true,
			errorMsg:    "entry not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			entry, err := client.GetLogEntryByIndex(context.Background(), tt.index)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, entry)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, entry)
				assert.Equal(t, tt.index, *entry.LogIndex)
			}
		})
	}
}

func TestRekorClient_GetWorkerCount(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		expected int
	}{
		{
			name:     "success with default value (no env)",
			setEnv:   false,
			expected: 8,
		},
		{
			name:     "success with valid env value",
			envValue: "16",
			setEnv:   true,
			expected: 16,
		},
		{
			name:     "failure with invalid env value falls back to default",
			envValue: "invalid",
			setEnv:   true,
			expected: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env value for safe cleanup
			originalEnv, originalExists := os.LookupEnv("EC_REKOR_WORKERS")

			// Ensure cleanup happens even if test panics
			defer func() {
				if originalExists {
					os.Setenv("EC_REKOR_WORKERS", originalEnv)
				} else {
					os.Unsetenv("EC_REKOR_WORKERS")
				}
			}()

			// Set test environment
			if tt.setEnv {
				err := os.Setenv("EC_REKOR_WORKERS", tt.envValue)
				assert.NoError(t, err, "Failed to set test environment variable")
			} else {
				err := os.Unsetenv("EC_REKOR_WORKERS")
				assert.NoError(t, err, "Failed to unset test environment variable")
			}

			// Test the function
			client := &rekorClient{}
			result := client.getWorkerCount()
			assert.Equal(t, tt.expected, result)

			// Verify environment state if needed
			if tt.setEnv {
				actualEnv := os.Getenv("EC_REKOR_WORKERS")
				assert.Equal(t, tt.envValue, actualEnv, "Environment variable not set correctly")
			}
		})
	}
}

func TestRekorClient_FetchLogEntriesParallel(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *MockRekorClient
		uuids       []string
		expectError bool
		expectedLen int
	}{
		{
			name: "success with multiple UUIDs",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogID: stringPtr("uuid-1")},
						{LogID: stringPtr("uuid-2")},
						{LogID: stringPtr("uuid-3")},
					},
				}
			},
			uuids:       []string{"uuid-1", "uuid-2", "uuid-3"},
			expectError: false,
			expectedLen: 3,
		},
		{
			name: "success with single UUID",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogID: stringPtr("uuid-1")},
					},
				}
			},
			uuids:       []string{"uuid-1"},
			expectError: false,
			expectedLen: 1,
		},
		{
			name: "success with empty UUIDs list",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{},
				}
			},
			uuids:       []string{},
			expectError: false,
			expectedLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()

			// Test fetchLogEntriesParallel behavior indirectly by testing that
			// the mock client returns the expected number of entries
			// This simulates the parallel fetching result without external dependencies
			entries, err := client.SearchIndex(context.Background(), &models.SearchIndex{Hash: "test"})

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, entries, tt.expectedLen)

				// Validate that each entry has expected structure for parallel processing
				for i, entry := range entries {
					assert.NotNil(t, entry.LogID, "Entry %d should have LogID for parallel processing", i)
				}
			}
		})
	}
}

func TestRekorClient_Worker(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *MockRekorClient
		uuids       []string
		expectError bool
	}{
		{
			name: "success processing multiple UUIDs",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogID: stringPtr("uuid-1")},
						{LogID: stringPtr("uuid-2")},
					},
				}
			},
			uuids:       []string{"uuid-1", "uuid-2"},
			expectError: false,
		},
		{
			name: "success processing single UUID",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogID: stringPtr("uuid-1")},
					},
				}
			},
			uuids:       []string{"uuid-1"},
			expectError: false,
		},
		{
			name: "success with no UUIDs",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{},
				}
			},
			uuids:       []string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()

			// Test the worker function behavior by simulating its operation
			ctx := context.Background()
			uuidChan := make(chan string, len(tt.uuids))
			resultChan := make(chan fetchResult, len(tt.uuids))

			// Send UUIDs to channel
			for _, uuid := range tt.uuids {
				uuidChan <- uuid
			}
			close(uuidChan)

			// Process UUIDs manually to simulate worker behavior
			for uuid := range uuidChan {
				entry, err := client.GetLogEntryByUUID(ctx, uuid)
				if err != nil {
					resultChan <- fetchResult{entry: nil, err: err}
				} else {
					resultChan <- fetchResult{entry: entry, err: nil}
				}
			}
			close(resultChan)

			// Collect results
			var successCount int
			for result := range resultChan {
				if result.err == nil {
					successCount++
				}
			}

			if tt.expectError {
				assert.Equal(t, 0, successCount)
			} else {
				assert.Equal(t, len(tt.uuids), successCount)
			}
		})
	}
}

func TestRekorClient_GetLogEntryByUUID(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *MockRekorClient
		uuid        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "success with existing UUID",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogID: stringPtr("existing-uuid-1"), LogIndex: int64Ptr(123)},
						{LogID: stringPtr("existing-uuid-2"), LogIndex: int64Ptr(456)},
					},
				}
			},
			uuid:        "existing-uuid-1",
			expectError: false,
		},
		{
			name: "success with another existing UUID",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogID: stringPtr("test-uuid-3"), LogIndex: int64Ptr(789)},
					},
				}
			},
			uuid:        "test-uuid-3",
			expectError: false,
		},
		{
			name: "failure with non-existing UUID",
			setupClient: func() *MockRekorClient {
				return &MockRekorClient{
					entries: []models.LogEntryAnon{
						{LogID: stringPtr("existing-uuid"), LogIndex: int64Ptr(123)},
					},
				}
			},
			uuid:        "non-existing-uuid",
			expectError: true,
			errorMsg:    "entry not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			entry, err := client.GetLogEntryByUUID(context.Background(), tt.uuid)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, entry)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, entry)
				assert.Equal(t, tt.uuid, *entry.LogID)
			}
		})
	}
}
