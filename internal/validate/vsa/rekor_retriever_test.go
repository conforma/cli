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
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/client/pubkey"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"
)

// MockRekorAPI provides a mock implementation for testing the actual rekorClient with mocked client.Rekor dependency
type MockRekorAPI struct {
	searchIndexResult []string
	searchIndexError  error
	logEntries        map[string]*models.LogEntryAnon
	getEntryError     error
}

// MockRekorClientWrapper creates a mock client.Rekor struct
type MockRekorClientWrapper struct{}

// NewMockRekorClientWrapper creates a new mock wrapper that returns a client.Rekor struct
func NewMockRekorClientWrapper(api *MockRekorAPI) *client.Rekor {
	indexSvc := &MockIndexClient{api: api}
	entriesSvc := &MockEntriesClient{api: api}

	// Create and return a client.Rekor struct with mocked services
	return &client.Rekor{
		Index:   indexSvc,
		Entries: entriesSvc,
		Pubkey:  &MockPubkeyClient{},
		Tlog:    &MockTlogClient{},
	}
}

// MockIndexClient implements index.ClientService
type MockIndexClient struct {
	api *MockRekorAPI
}

func (m *MockIndexClient) SearchIndex(params *index.SearchIndexParams, opts ...index.ClientOption) (*index.SearchIndexOK, error) {
	if m.api.searchIndexError != nil {
		return nil, m.api.searchIndexError
	}
	if params == nil {
		return nil, fmt.Errorf("params cannot be nil")
	}
	return &index.SearchIndexOK{
		Payload: m.api.searchIndexResult,
	}, nil
}

func (m *MockIndexClient) SetTransport(transport runtime.ClientTransport) {}

// MockEntriesClient implements entries.ClientService
type MockEntriesClient struct {
	api *MockRekorAPI
}

func (m *MockEntriesClient) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	if m.api.getEntryError != nil {
		return nil, m.api.getEntryError
	}

	if params == nil {
		return nil, fmt.Errorf("params cannot be nil")
	}

	entry, exists := m.api.logEntries[params.EntryUUID]
	if !exists {
		return nil, fmt.Errorf("entry not found for UUID: %s", params.EntryUUID)
	}

	payload := make(map[string]models.LogEntryAnon)
	payload[params.EntryUUID] = *entry

	return &entries.GetLogEntryByUUIDOK{
		Payload: payload,
	}, nil
}

func (m *MockEntriesClient) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	if params == nil {
		return nil, fmt.Errorf("params cannot be nil")
	}

	// Find entry by index in the logEntries map
	for uuid, entry := range m.api.logEntries {
		if entry.LogIndex != nil && *entry.LogIndex == params.LogIndex {
			logEntryMap := map[string]models.LogEntryAnon{
				uuid: *entry,
			}
			return &entries.GetLogEntryByIndexOK{
				Payload: logEntryMap,
			}, nil
		}
	}

	return nil, fmt.Errorf("log entry not found for index: %d", params.LogIndex)
}

func (m *MockEntriesClient) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	// Implementation for SearchLogQuery if needed
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockEntriesClient) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	// Implementation for CreateLogEntry if needed
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockEntriesClient) SetTransport(transport runtime.ClientTransport) {}

// MockPubkeyClient implements pubkey.ClientService (minimal implementation)
type MockPubkeyClient struct{}

func (m *MockPubkeyClient) GetPublicKey(params *pubkey.GetPublicKeyParams, opts ...pubkey.ClientOption) (*pubkey.GetPublicKeyOK, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockPubkeyClient) SetTransport(transport runtime.ClientTransport) {}

// MockTlogClient implements tlog.ClientService (minimal implementation)
type MockTlogClient struct{}

func (m *MockTlogClient) GetLogInfo(params *tlog.GetLogInfoParams, opts ...tlog.ClientOption) (*tlog.GetLogInfoOK, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockTlogClient) GetLogProof(params *tlog.GetLogProofParams, opts ...tlog.ClientOption) (*tlog.GetLogProofOK, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockTlogClient) SetTransport(transport runtime.ClientTransport) {}

// MockRekorClient implements RekorClient for testing
type MockRekorClient struct {
	entries []models.LogEntryAnon
}

func (m *MockRekorClient) SearchIndex(ctx context.Context, query *models.SearchIndex) ([]models.LogEntryAnon, error) {
	// Validate query parameter
	if query == nil {
		return nil, fmt.Errorf("query cannot be nil")
	}
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
	// The signature needs to be double-base64 encoded for the implementation
	doubleEncodedSig := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte("test"))))
	intotoV002Body := `{
		"spec": {
			"content": {
				"envelope": {
					"payloadType": "application/vnd.in-toto+json",
					"signatures": [{"sig": "` + doubleEncodedSig + `", "keyid": "test-key-id"}]
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
					Data: strfmt.Base64([]byte(vsaStatement)), // Raw JSON, not base64 encoded
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
	assert.Contains(t, err.Error(), "identifier cannot be empty")
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
			retriever, err := NewRekorVSARetriever(tt.opts)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, retriever)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, retriever)
				assert.Equal(t, tt.opts, retriever.options)
			}
		})
	}
}

func TestRekorClient_SearchIndex(t *testing.T) {
	// This test instantiates an actual rekorClient object and mocks its client.Rekor dependency
	// and allows us to test the actual rekorClientimplementation while controlling the behavior
	//  of the underlying Rekor API calls.

	tests := []struct {
		name          string
		setupMock     func() *MockRekorAPI
		query         *models.SearchIndex
		expectError   bool
		errorMsg      string
		expectedCount int
	}{
		{
			name: "success with multiple entries",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{"uuid-1", "uuid-2"},
					logEntries: map[string]*models.LogEntryAnon{
						"uuid-1": {LogID: stringPtr("uuid-1"), LogIndex: int64Ptr(1)},
						"uuid-2": {LogID: stringPtr("uuid-2"), LogIndex: int64Ptr(2)},
					},
				}
			},
			query:         &models.SearchIndex{Hash: "sha256:abc123"},
			expectError:   false,
			expectedCount: 2,
		},
		{
			name: "success with single entry",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{"uuid-1"},
					logEntries: map[string]*models.LogEntryAnon{
						"uuid-1": {LogID: stringPtr("uuid-1"), LogIndex: int64Ptr(1)},
					},
				}
			},
			query:         &models.SearchIndex{Hash: "sha256:def456"},
			expectError:   false,
			expectedCount: 1,
		},
		{
			name: "success with no entries",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{},
					logEntries:        map[string]*models.LogEntryAnon{},
				}
			},
			query:         &models.SearchIndex{Hash: "sha256:nonexistent"},
			expectError:   false,
			expectedCount: 0,
		},
		{
			name: "search index API error",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexError: fmt.Errorf("search index failed"),
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:error"},
			expectError: true,
			errorMsg:    "search index failed",
		},
		{
			name: "get log entry by UUID error - should succeed with empty results",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{"uuid-1"},
					getEntryError:     fmt.Errorf("entry not found"),
				}
			},
			query:         &models.SearchIndex{Hash: "sha256:entryerror"},
			expectError:   false,
			expectedCount: 0, // No entries returned due to fetch errors, but operation succeeds
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock Rekor API client
			mockAPI := tt.setupMock()

			// Create an actual rekorClient instance with the mocked client.Rekor dependency
			rekorClientInstance := &rekorClient{
				client: NewMockRekorClientWrapper(mockAPI),
			}

			// Test the actual rekorClient.SearchIndex method
			entries, err := rekorClientInstance.SearchIndex(context.Background(), tt.query)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, entries, tt.expectedCount)

				// Verify that entries have the expected structure
				for i, entry := range entries {
					assert.NotNil(t, entry.LogID, "Entry %d should have LogID", i)
					assert.NotNil(t, entry.LogIndex, "Entry %d should have LogIndex", i)
				}
			}
		})
	}
}

func TestRekorClient_GetLogEntryByIndex(t *testing.T) {
	// This test now instantiates an actual rekorClient object and mocks its client.Rekor dependency
	// as suggested in the original comment. This approach allows us to test the actual rekorClient
	// implementation while controlling the behavior of the underlying Rekor API calls.

	tests := []struct {
		name        string
		setupMock   func() *MockRekorAPI
		index       int64
		expectError bool
		errorMsg    string
	}{
		{
			name: "success with existing index",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					logEntries: map[string]*models.LogEntryAnon{
						"uuid-1": {LogID: stringPtr("uuid-1"), LogIndex: int64Ptr(123)},
						"uuid-2": {LogID: stringPtr("uuid-2"), LogIndex: int64Ptr(456)},
					},
				}
			},
			index:       123,
			expectError: false,
		},
		{
			name: "success with another existing index",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					logEntries: map[string]*models.LogEntryAnon{
						"uuid-3": {LogID: stringPtr("uuid-3"), LogIndex: int64Ptr(789)},
					},
				}
			},
			index:       789,
			expectError: false,
		},
		{
			name: "failure with non-existing index",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					logEntries: map[string]*models.LogEntryAnon{
						"uuid-1": {LogID: stringPtr("uuid-1"), LogIndex: int64Ptr(123)},
					},
				}
			},
			index:       999,
			expectError: true,
			errorMsg:    "log entry not found for index: 999",
		},
		{
			name: "failure with empty log entries",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					logEntries: map[string]*models.LogEntryAnon{},
				}
			},
			index:       123,
			expectError: true,
			errorMsg:    "log entry not found for index: 123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock Rekor API client
			mockAPI := tt.setupMock()

			// Create an actual rekorClient instance with the mocked client.Rekor dependency
			rekorClientInstance := &rekorClient{
				client: NewMockRekorClientWrapper(mockAPI),
			}

			// Test the actual rekorClient.GetLogEntryByIndex method
			entry, err := rekorClientInstance.GetLogEntryByIndex(context.Background(), tt.index)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
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
	// This test instantiates an actual rekorClient object to test the getWorkerCount method.
	// This method doesn't depend on external API calls, so no mocking is needed.
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

			// Create an actual rekorClient instance
			rekorClientInstance := &rekorClient{}

			// Test the actual rekorClient.getWorkerCount method
			result := rekorClientInstance.getWorkerCount()
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
	// This test now instantiates an actual rekorClient object and mocks its client.Rekor dependency
	// to test the fetchLogEntriesParallel logic. Since fetchLogEntriesParallel is a private method,
	// we test it indirectly through the SearchIndex method which exercises the parallel fetching logic.

	tests := []struct {
		name        string
		setupMock   func() *MockRekorAPI
		query       *models.SearchIndex
		expectError bool
		expectedLen int
	}{
		{
			name: "success with multiple entries (tests parallel fetching)",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{"uuid-1", "uuid-2", "uuid-3"},
					logEntries: map[string]*models.LogEntryAnon{
						"uuid-1": {LogID: stringPtr("uuid-1"), LogIndex: int64Ptr(1)},
						"uuid-2": {LogID: stringPtr("uuid-2"), LogIndex: int64Ptr(2)},
						"uuid-3": {LogID: stringPtr("uuid-3"), LogIndex: int64Ptr(3)},
					},
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:test123"},
			expectError: false,
			expectedLen: 3,
		},
		{
			name: "success with single entry (tests single worker)",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{"uuid-1"},
					logEntries: map[string]*models.LogEntryAnon{
						"uuid-1": {LogID: stringPtr("uuid-1"), LogIndex: int64Ptr(1)},
					},
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:test456"},
			expectError: false,
			expectedLen: 1,
		},
		{
			name: "success with no entries (tests empty parallel fetching)",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{},
					logEntries:        map[string]*models.LogEntryAnon{},
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:nonexistent"},
			expectError: false,
			expectedLen: 0,
		},
		{
			name: "success with many entries (tests parallel worker scaling)",
			setupMock: func() *MockRekorAPI {
				// Create 20 entries to test parallel processing with multiple workers
				searchResult := make([]string, 20)
				logEntries := make(map[string]*models.LogEntryAnon)
				for i := 0; i < 20; i++ {
					uuid := fmt.Sprintf("uuid-%d", i+1)
					searchResult[i] = uuid
					logEntries[uuid] = &models.LogEntryAnon{
						LogID:    stringPtr(uuid),
						LogIndex: int64Ptr(int64(i + 1)),
					}
				}
				return &MockRekorAPI{
					searchIndexResult: searchResult,
					logEntries:        logEntries,
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:test789"},
			expectError: false,
			expectedLen: 20,
		},
		{
			name: "search index API error",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexError: fmt.Errorf("search index failed"),
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:error"},
			expectError: true,
			expectedLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock Rekor API client
			mockAPI := tt.setupMock()

			// Create an actual rekorClient instance with the mocked client.Rekor dependency
			rekorClientInstance := &rekorClient{
				client: NewMockRekorClientWrapper(mockAPI),
			}

			// Test the actual rekorClient.SearchIndex method which internally calls fetchLogEntriesParallel
			// This exercises the parallel fetching logic while testing the actual implementation
			entries, err := rekorClientInstance.SearchIndex(context.Background(), tt.query)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, entries, tt.expectedLen)

				// Validate that each entry has expected structure for parallel processing
				for i, entry := range entries {
					assert.NotNil(t, entry.LogID, "Entry %d should have LogID for parallel processing", i)
					assert.NotNil(t, entry.LogIndex, "Entry %d should have LogIndex for parallel processing", i)
				}
			}
		})
	}
}

func TestRekorClient_Worker(t *testing.T) {
	// This test now instantiates an actual rekorClient object and mocks its client.Rekor dependency
	// as suggested in the original comment. This approach allows us to test the actual rekorClient
	// implementation while controlling the behavior of the underlying Rekor API calls.
	// The worker method is called internally by fetchLogEntriesParallel, which is called
	// by SearchIndex, so we test it indirectly through the SearchIndex method.

	tests := []struct {
		name        string
		setupMock   func() *MockRekorAPI
		query       *models.SearchIndex
		expectError bool
		expectedLen int
	}{
		{
			name: "success processing multiple UUIDs (tests worker behavior)",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{"uuid-1", "uuid-2"},
					logEntries: map[string]*models.LogEntryAnon{
						"uuid-1": {LogID: stringPtr("uuid-1"), LogIndex: int64Ptr(1)},
						"uuid-2": {LogID: stringPtr("uuid-2"), LogIndex: int64Ptr(2)},
					},
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:test123"},
			expectError: false,
			expectedLen: 2,
		},
		{
			name: "success processing single UUID (tests single worker)",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{"uuid-1"},
					logEntries: map[string]*models.LogEntryAnon{
						"uuid-1": {LogID: stringPtr("uuid-1"), LogIndex: int64Ptr(1)},
					},
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:test456"},
			expectError: false,
			expectedLen: 1,
		},
		{
			name: "success with no UUIDs (tests worker with empty input)",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexResult: []string{},
					logEntries:        map[string]*models.LogEntryAnon{},
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:nonexistent"},
			expectError: false,
			expectedLen: 0,
		},
		{
			name: "success with many UUIDs (tests multiple workers)",
			setupMock: func() *MockRekorAPI {
				// Create 15 entries to test multiple workers processing in parallel
				searchResult := make([]string, 15)
				logEntries := make(map[string]*models.LogEntryAnon)
				for i := 0; i < 15; i++ {
					uuid := fmt.Sprintf("uuid-%d", i+1)
					searchResult[i] = uuid
					logEntries[uuid] = &models.LogEntryAnon{
						LogID:    stringPtr(uuid),
						LogIndex: int64Ptr(int64(i + 1)),
					}
				}
				return &MockRekorAPI{
					searchIndexResult: searchResult,
					logEntries:        logEntries,
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:test789"},
			expectError: false,
			expectedLen: 15,
		},
		{
			name: "search index API error",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					searchIndexError: fmt.Errorf("search index failed"),
				}
			},
			query:       &models.SearchIndex{Hash: "sha256:error"},
			expectError: true,
			expectedLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock Rekor API client
			mockAPI := tt.setupMock()

			// Create an actual rekorClient instance with the mocked client.Rekor dependency
			rekorClientInstance := &rekorClient{
				client: NewMockRekorClientWrapper(mockAPI),
			}

			// Test the actual rekorClient.SearchIndex method which internally calls fetchLogEntriesParallel
			// which uses the worker method, so we test the worker behavior indirectly
			entries, err := rekorClientInstance.SearchIndex(context.Background(), tt.query)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, entries, tt.expectedLen)

				// Validate that each entry has expected structure for worker processing
				for i, entry := range entries {
					assert.NotNil(t, entry.LogID, "Entry %d should have LogID for worker processing", i)
					assert.NotNil(t, entry.LogIndex, "Entry %d should have LogIndex for worker processing", i)
				}
			}
		})
	}
}

func TestRekorClient_GetLogEntryByUUID(t *testing.T) {
	// This test now instantiates an actual rekorClient object and mocks its client.Rekor dependency
	// as suggested in the original comment. This approach allows us to test the actual rekorClient
	// implementation while controlling the behavior of the underlying Rekor API calls.

	tests := []struct {
		name        string
		setupMock   func() *MockRekorAPI
		uuid        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "success with existing UUID",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					logEntries: map[string]*models.LogEntryAnon{
						"existing-uuid-1": {LogID: stringPtr("existing-uuid-1"), LogIndex: int64Ptr(123)},
						"existing-uuid-2": {LogID: stringPtr("existing-uuid-2"), LogIndex: int64Ptr(456)},
					},
				}
			},
			uuid:        "existing-uuid-1",
			expectError: false,
		},
		{
			name: "success with another existing UUID",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					logEntries: map[string]*models.LogEntryAnon{
						"test-uuid-3": {LogID: stringPtr("test-uuid-3"), LogIndex: int64Ptr(789)},
					},
				}
			},
			uuid:        "test-uuid-3",
			expectError: false,
		},
		{
			name: "failure with non-existing UUID",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					logEntries: map[string]*models.LogEntryAnon{
						"existing-uuid": {LogID: stringPtr("existing-uuid"), LogIndex: int64Ptr(123)},
					},
				}
			},
			uuid:        "non-existing-uuid",
			expectError: true,
			errorMsg:    "entry not found for UUID: non-existing-uuid",
		},
		{
			name: "empty UUID parameter",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					logEntries: map[string]*models.LogEntryAnon{
						"existing-uuid": {LogID: stringPtr("existing-uuid"), LogIndex: int64Ptr(123)},
					},
				}
			},
			uuid:        "",
			expectError: true,
			errorMsg:    "entry not found for UUID: ",
		},
		{
			name: "get entry API error",
			setupMock: func() *MockRekorAPI {
				return &MockRekorAPI{
					getEntryError: fmt.Errorf("API error occurred"),
				}
			},
			uuid:        "any-uuid",
			expectError: true,
			errorMsg:    "API error occurred",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock Rekor API client
			mockAPI := tt.setupMock()

			// Create an actual rekorClient instance with the mocked client.Rekor dependency
			rekorClientInstance := &rekorClient{
				client: NewMockRekorClientWrapper(mockAPI),
			}

			// Test the actual rekorClient.GetLogEntryByUUID method
			entry, err := rekorClientInstance.GetLogEntryByUUID(context.Background(), tt.uuid)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, entry)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, entry)
				assert.Equal(t, tt.uuid, *entry.LogID)
			}
		})
	}
}
