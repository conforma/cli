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

func TestRekorVSARetriever_FindByPayloadHash(t *testing.T) {
	// Create a mock client with dual entries
	mockClient := &MockRekorClient{
		entries: []models.LogEntryAnon{
			{
				LogIndex: &[]int64{123}[0],
				LogID:    &[]string{"intoto-uuid"}[0],
				Body:     `{"intoto": "v0.0.1", "content": {"envelope": {"payload": "dGVzdA==", "signatures": [{"sig": "dGVzdA=="}]}}}`,
				Attestation: &models.LogEntryAnonAttestation{
					Data: strfmt.Base64("ZXlKd2NtVmthV05oZEdWVWVYQmxJam9pYUhSMGNITTZMeTlqYjI1bWIzSnRZUzVrWlhZdmRtVnlhV1pwWTJGMGFXOXVYM04xYlcxaGNua3ZkakVpTENKemRXSnFaV04wSWpwYmV5SnVZVzFsSWpvaWNYVmhlUzVwYnk5MFpYTjBMMmx0WVdkbElpd2laR2xuWlhOMElqcDdJbk5vWVRJMU5pSTZJbUZpWXpFeU15SjlmVjE5"),
				},
			},
			{
				LogIndex: &[]int64{124}[0],
				LogID:    &[]string{"dsse-uuid"}[0],
				Body:     `{"dsse": "v0.0.1", "content": {"envelope": {"payload": "dGVzdA==", "signatures": [{"sig": "dGVzdA=="}]}}}`,
			},
		},
	}

	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	// Test successful retrieval
	dualPair, err := retriever.FindByPayloadHash(context.Background(), "abcdef1234567890")
	assert.NoError(t, err)
	assert.NotNil(t, dualPair)
	assert.Equal(t, "abcdef1234567890", dualPair.PayloadHash)
	assert.NotNil(t, dualPair.IntotoEntry)
	assert.NotNil(t, dualPair.DSSEEntry)
	assert.Equal(t, int64(123), *dualPair.IntotoEntry.LogIndex)
	assert.Equal(t, "intoto-uuid", *dualPair.IntotoEntry.LogID)
	assert.Equal(t, int64(124), *dualPair.DSSEEntry.LogIndex)
	assert.Equal(t, "dsse-uuid", *dualPair.DSSEEntry.LogID)
}

func TestRekorVSARetriever_FindByPayloadHash_EmptyHash(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.FindByPayloadHash(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "payload hash cannot be empty")
}

func TestRekorVSARetriever_FindByPayloadHash_InvalidHash(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.FindByPayloadHash(context.Background(), "invalid-hex!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid payload hash format")
}

func TestRekorVSARetriever_FindByPayloadHash_NoEntries(t *testing.T) {
	mockClient := &MockRekorClient{entries: []models.LogEntryAnon{}}
	retriever := NewRekorVSARetrieverWithClient(mockClient, DefaultRetrievalOptions())

	_, err := retriever.FindByPayloadHash(context.Background(), "abcdef1234567890")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no entries found for payload hash")
}

func TestRekorVSARetriever_ExtractStatementFromIntoto(t *testing.T) {
	// Create a mock in-toto entry with DSSE envelope
	dsseEnvelope := `{
		"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJ0ZXN0LWltYWdlIiwiaGFzaGVzIjp7InNoYTI1NiI6ImFiYzEyMyJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2NvbmZvcm1hLmRldi92ZXJpZmljYXRpb25fc3VtbWFyeS92MSIsInByZWRpY2F0ZSI6eyJ0ZXN0IjoiZGF0YSJ9fQ==",
		"signatures": [{"sig": "dGVzdA=="}]
	}`

	entry := models.LogEntryAnon{
		LogIndex: &[]int64{123}[0],
		LogID:    &[]string{"intoto-uuid"}[0],
		Body:     fmt.Sprintf(`{"intoto": "v0.0.1", "content": {"envelope": %s}}`, dsseEnvelope),
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
		Body:     `{"dsse": "v0.0.1"}`,
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
				Body: `{"intoto": "v0.0.1"}`,
			},
			expected: "intoto",
		},
		{
			name: "dsse entry by body",
			entry: models.LogEntryAnon{
				Body: `{"dsse": "v0.0.1"}`,
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
				Body: `{"unknown": "type"}`,
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
