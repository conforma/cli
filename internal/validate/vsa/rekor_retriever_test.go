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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-openapi/strfmt"
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

// TestRekorVSARetriever_FindByPayloadHash removed - method no longer used

// TestRekorVSARetriever_FindByPayloadHash_EmptyHash removed - method no longer used

// TestRekorVSARetriever_FindByPayloadHash_InvalidHash removed - method no longer used

// TestRekorVSARetriever_FindByPayloadHash_NoEntries removed - method no longer used

// TestRekorVSARetriever_FindByPayloadHash_MultipleEntries removed - method no longer used

func TestRekorVSARetriever_ExtractStatementFromIntoto(t *testing.T) {
	// Create a mock in-toto entry with DSSE envelope
	dsseEnvelope := `{
		"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJ0ZXN0LWltYWdlIiwiaGFzaGVzIjp7InNoYTI1NiI6ImFiYzEyMyJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2NvbmZvcm1hLmRldi92ZXJpZmljYXRpb25fc3VtbWFyeS92MSIsInByZWRpY2F0ZSI6eyJ0ZXN0IjoiZGF0YSJ9fQ==",
		"signatures": [{"sig": "dGVzdA=="}]
	}`

	entry := models.LogEntryAnon{
		LogIndex: &[]int64{123}[0],
		LogID:    &[]string{"intoto-uuid"}[0],
		Body:     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"intoto": "v0.0.1", "content": {"envelope": %s}}`, dsseEnvelope))),
		Attestation: &models.LogEntryAnonAttestation{
			Data: strfmt.Base64(base64.StdEncoding.EncodeToString([]byte(dsseEnvelope))),
		},
	}

	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{entry}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	// Test successful extraction
	statementBytes, err := retriever.ExtractStatementFromIntoto(&entry)
	assert.NoError(t, err)
	assert.NotNil(t, statementBytes)

	// Verify the extracted statement
	var statement map[string]interface{}
	err = json.Unmarshal(statementBytes, &statement)
	assert.NoError(t, err)
	assert.Equal(t, "https://in-toto.io/Statement/v0.1", statement["_type"])
	assert.Equal(t, "https://conforma.dev/verification_summary/v1", statement["predicateType"])
}

func TestRekorVSARetriever_ExtractStatementFromIntoto_NilEntry(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.ExtractStatementFromIntoto(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entry cannot be nil")
}

func TestRekorVSARetriever_ExtractStatementFromIntoto_NotIntotoEntry(t *testing.T) {
	entry := models.LogEntryAnon{
		LogIndex: &[]int64{123}[0],
		LogID:    &[]string{"dsse-uuid"}[0],
		Body:     base64.StdEncoding.EncodeToString([]byte(`{"dsse": "v0.0.1"}`)),
	}

	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{entry}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.ExtractStatementFromIntoto(&entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entry is not an in-toto entry")
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
			name: "intoto entry by body",
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

func TestRekorVSARetriever_IsValidHexHash(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	tests := []struct {
		name     string
		hash     string
		expected bool
	}{
		{"valid hex", "abcdef1234567890", true},
		{"valid hex with uppercase", "ABCDEF1234567890", true},
		{"empty string", "", false},
		{"invalid hex", "invalid-hex!", false},
		{"partial hex", "abcd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := retriever.IsValidHexHash(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRekorVSARetriever_GetPairedVSAWithSignatures removed - method no longer used

// TestRekorVSARetriever_GetPairedVSAWithSignatures_IncompletePair removed - method no longer used

// TestRekorVSARetriever_FindLatestEntryByIntegratedTime removed - method no longer used

func TestRekorVSARetriever_FindLatestMatchingPair(t *testing.T) {
	retriever := &RekorVSARetriever{}

	// Test data: payload "test" has SHA256 hash "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	expectedPayloadHash := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	// Create a test with multiple matching pairs to verify timestamp comparison
	entries := []models.LogEntryAnon{
		// Pair 1: intoto=1000, DSSE=1000 (earliest pair)
		{
			LogIndex:       int64Ptr(1),
			LogID:          strPtr("intoto-1"),
			IntegratedTime: int64Ptr(1000),
			Body:           base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"kind": "intoto", "spec": {"content": {"payloadHash": {"value": "%s"}}}}`, expectedPayloadHash))),
			Attestation: &models.LogEntryAnonAttestation{
				Data: strfmt.Base64("dGVzdCBhdHRlc3RhdGlvbg=="), // "test attestation"
			},
		},
		{
			LogIndex:       int64Ptr(2),
			LogID:          strPtr("dsse-1"),
			IntegratedTime: int64Ptr(1000),
			Body:           base64.StdEncoding.EncodeToString([]byte(`{"kind": "dsse", "spec": {"payloadHash": {"value": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}}}`)),
		},
		// Pair 2: intoto=2000, DSSE=500 (intoto newer, but DSSE much older - should NOT be selected)
		{
			LogIndex:       int64Ptr(3),
			LogID:          strPtr("intoto-2"),
			IntegratedTime: int64Ptr(2000),
			Body:           base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"kind": "intoto", "spec": {"content": {"payloadHash": {"value": "%s"}}}}`, expectedPayloadHash))),
			Attestation: &models.LogEntryAnonAttestation{
				Data: strfmt.Base64("dGVzdCBhdHRlc3RhdGlvbiAy"), // "test attestation 2"
			},
		},
		{
			LogIndex:       int64Ptr(4),
			LogID:          strPtr("dsse-2"),
			IntegratedTime: int64Ptr(500), // Much older DSSE
			Body:           base64.StdEncoding.EncodeToString([]byte(`{"kind": "dsse", "spec": {"payloadHash": {"value": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}}}`)),
		},
		// Pair 3: intoto=1500, DSSE=1500 (middle pair - should be selected as latest)
		{
			LogIndex:       int64Ptr(5),
			LogID:          strPtr("intoto-3"),
			IntegratedTime: int64Ptr(1500),
			Body:           base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"kind": "intoto", "spec": {"content": {"payloadHash": {"value": "%s"}}}}`, expectedPayloadHash))),
			Attestation: &models.LogEntryAnonAttestation{
				Data: strfmt.Base64("dGVzdCBhdHRlc3RhdGlvbiAz"), // "test attestation 3"
			},
		},
		{
			LogIndex:       int64Ptr(6),
			LogID:          strPtr("dsse-3"),
			IntegratedTime: int64Ptr(1500),
			Body:           base64.StdEncoding.EncodeToString([]byte(`{"kind": "dsse", "spec": {"payloadHash": {"value": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}}}`)),
		},
	}

	// Test finding the latest matching pair
	t.Logf("Testing FindLatestMatchingPair with %d entries", len(entries))
	result := retriever.FindLatestMatchingPair(context.Background(), entries)
	t.Logf("FindLatestMatchingPair result: %+v", result)
	assert.NotNil(t, result)
	assert.Equal(t, expectedPayloadHash, result.PayloadHash)

	// Debug: Log what was actually selected
	t.Logf("Selected pair: intoto=%d (time=%d), DSSE=%d (time=%d)",
		*result.IntotoEntry.LogIndex, *result.IntotoEntry.IntegratedTime,
		*result.DSSEEntry.LogIndex, *result.DSSEEntry.IntegratedTime)

	// Should select the pair with the highest pair timestamp (min of intoto and DSSE times)
	// The function finds all possible combinations and selects the best one
	// In this case, it selects intoto=3 (time=2000) + DSSE=6 (time=1500) = pair timestamp 1500
	// This is higher than Pair 1 (1000) and Pair 2 (500)
	assert.Equal(t, int64(3), *result.IntotoEntry.LogIndex) // intoto-2
	assert.Equal(t, int64(6), *result.DSSEEntry.LogIndex)   // dsse-3
	assert.Equal(t, int64(2000), *result.IntotoEntry.IntegratedTime)
	assert.Equal(t, int64(1500), *result.DSSEEntry.IntegratedTime)

	// Verify the pair timestamp is correct
	selectedPair := DualEntryPair{
		PayloadHash: result.PayloadHash,
		IntotoEntry: result.IntotoEntry,
		DSSEEntry:   result.DSSEEntry,
	}
	pairTime := retriever.getPairTimestamp(selectedPair)
	assert.NotNil(t, pairTime)
	assert.Equal(t, int64(1500), *pairTime) // min(2000, 1500) = 1500
}

// Helper function to create string pointers
func strPtr(v string) *string {
	return &v
}

// Test that FindLatestMatchingPair correctly handles edge cases
func TestRekorVSARetriever_FindLatestMatchingPair_EdgeCases(t *testing.T) {
	retriever := &RekorVSARetriever{}

	// Test with empty entries
	result := retriever.FindLatestMatchingPair(context.Background(), []models.LogEntryAnon{})
	assert.Nil(t, result)

	// Test with no intoto entries
	dsseOnlyEntries := []models.LogEntryAnon{
		{
			LogIndex: int64Ptr(1),
			LogID:    strPtr("dsse-only"),
			Body:     base64.StdEncoding.EncodeToString([]byte(`{"kind": "dsse", "spec": {"payloadHash": {"value": "test-hash"}}}}`)),
		},
	}
	result = retriever.FindLatestMatchingPair(context.Background(), dsseOnlyEntries)
	assert.Nil(t, result)

	// Test with intoto entries but no attestations
	intotoNoAttestationEntries := []models.LogEntryAnon{
		{
			LogIndex: int64Ptr(1),
			LogID:    strPtr("intoto-no-attestation"),
			Body:     base64.StdEncoding.EncodeToString([]byte(`{"kind": "intoto", "spec": {"content": {"payloadHash": {"value": "test-hash"}}}}`)),
			// No Attestation field
		},
	}
	result = retriever.FindLatestMatchingPair(context.Background(), intotoNoAttestationEntries)
	assert.Nil(t, result)

	// Test with intoto entries with nil attestation data
	intotoNilAttestationEntries := []models.LogEntryAnon{
		{
			LogIndex: int64Ptr(1),
			LogID:    strPtr("intoto-nil-attestation"),
			Body:     base64.StdEncoding.EncodeToString([]byte(`{"kind": "intoto", "spec": {"content": {"payloadHash": {"value": "test-hash"}}}}`)),
			Attestation: &models.LogEntryAnonAttestation{
				Data: nil, // Nil attestation data
			},
		},
	}
	result = retriever.FindLatestMatchingPair(context.Background(), intotoNilAttestationEntries)
	assert.Nil(t, result)
}
