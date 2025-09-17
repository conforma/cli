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
	"testing"

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
					"signatures": [{"sig": "ZEdWemRBPT0=", "keyid": "test-key-id"}]
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
					Data: strfmt.Base64([]byte(vsaStatement)),
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

	// Verify the payload itself is base64-encoded
	expectedPayload := base64.StdEncoding.EncodeToString([]byte(vsaStatement))
	assert.Equal(t, expectedPayload, envelope.Payload)

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
