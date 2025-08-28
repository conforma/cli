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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	log "github.com/sirupsen/logrus"
)

// RekorVSARetriever implements VSARetriever using Rekor API
type RekorVSARetriever struct {
	client  RekorClient
	options RetrievalOptions
}

// RekorClient defines the interface for Rekor client operations
// This allows for easy mocking in tests
type RekorClient interface {
	SearchIndex(ctx context.Context, query *models.SearchIndex) ([]models.LogEntryAnon, error)
	SearchLogQuery(ctx context.Context, query *models.SearchLogQuery) ([]models.LogEntryAnon, error)
	GetLogEntryByIndex(ctx context.Context, index int64) (*models.LogEntryAnon, error)
	GetLogEntryByUUID(ctx context.Context, uuid string) (*models.LogEntryAnon, error)
}

// NewRekorVSARetriever creates a new Rekor-based VSA retriever
func NewRekorVSARetriever(opts RetrievalOptions) (*RekorVSARetriever, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("RekorURL is required")
	}

	client, err := rekor.NewClient(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create Rekor client: %w", err)
	}

	return &RekorVSARetriever{
		client:  &rekorClient{client: client},
		options: opts,
	}, nil
}

// NewRekorVSARetrieverWithClient creates a new Rekor-based VSA retriever with a custom client
// This is primarily for testing purposes
func NewRekorVSARetrieverWithClient(client RekorClient, opts RetrievalOptions) *RekorVSARetriever {
	log.Debugf("Creating RekorVSARetriever with custom client")
	return &RekorVSARetriever{
		client:  client,
		options: opts,
	}
}

// RetrieveVSA implements VSARetriever.RetrieveVSA
func (r *RekorVSARetriever) RetrieveVSA(ctx context.Context, imageDigest string) ([]VSARecord, error) {
	if imageDigest == "" {
		return nil, fmt.Errorf("image digest cannot be empty")
	}

	// Validate image digest format
	if !isValidImageDigest(imageDigest) {
		return nil, fmt.Errorf("invalid image digest format: %s", imageDigest)
	}

	// Create context with timeout if specified
	if r.options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.options.Timeout)
		defer cancel()
	}

	log.Debugf("Retrieving VSA records for image digest: %s", imageDigest)

	// Search for entries containing the image digest
	entries, err := r.searchForImageDigest(ctx, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to search Rekor for image digest: %w", err)
	}

	log.Debugf("RetrieveVSA: search returned %d entries", len(entries))

	var vsaRecords []VSARecord

	// Process each entry to find VSA records
	for _, entry := range entries {
		log.Debugf("Processing entry: LogIndex=%v, LogID=%v", entry.LogIndex, entry.LogID)
		if isVSARecord(entry, imageDigest) {
			vsaRecord, err := r.parseVSARecord(entry)
			if err != nil {
				log.Warnf("Failed to parse VSA record: %v", err)
				continue
			}
			vsaRecords = append(vsaRecords, vsaRecord)
			log.Debugf("Added VSA record: LogIndex=%d, LogID=%s", vsaRecord.LogIndex, vsaRecord.LogID)
		} else {
			log.Debugf("Entry is not a VSA record")
		}
	}

	log.Debugf("Found %d VSA records for image digest: %s", len(vsaRecords), imageDigest)
	return vsaRecords, nil
}

// FindByPayloadHash implements VSARetriever.FindByPayloadHash
func (r *RekorVSARetriever) FindByPayloadHash(ctx context.Context, payloadHashHex string) (*DualEntryPair, error) {
	if payloadHashHex == "" {
		return nil, fmt.Errorf("payload hash cannot be empty")
	}

	// Validate payload hash format (should be hex)
	if !r.IsValidHexHash(payloadHashHex) {
		return nil, fmt.Errorf("invalid payload hash format: %s", payloadHashHex)
	}

	// Create context with timeout if specified
	if r.options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.options.Timeout)
		defer cancel()
	}

	log.Debugf("Finding dual entries for payload hash: %s", payloadHashHex)

	// Search for entries containing the payload hash
	entries, err := r.searchForPayloadHash(ctx, payloadHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to search Rekor for payload hash: %w", err)
	}

	log.Debugf("FindByPayloadHash: search returned %d entries", len(entries))

	// Classify entries by kind and find the pair
	dualPair := &DualEntryPair{
		PayloadHash: payloadHashHex,
	}

	for _, entry := range entries {
		entryKind := r.classifyEntryKind(entry)
		switch entryKind {
		case "intoto":
			if dualPair.IntotoEntry == nil {
				dualPair.IntotoEntry = &entry
				log.Debugf("Found in-toto entry: LogIndex=%d, LogID=%s", *entry.LogIndex, *entry.LogID)
			}
		case "dsse":
			if dualPair.DSSEEntry == nil {
				dualPair.DSSEEntry = &entry
				log.Debugf("Found DSSE entry: LogIndex=%d, LogID=%s", *entry.LogIndex, *entry.LogID)
			}
		default:
			log.Debugf("Ignoring entry of unknown kind: %s", entryKind)
		}
	}

	// Check if we found at least one entry
	if dualPair.IntotoEntry == nil && dualPair.DSSEEntry == nil {
		log.Debugf("No entries found for payload hash: %s", payloadHashHex)
		return nil, fmt.Errorf("no entries found for payload hash: %s", payloadHashHex)
	}

	log.Debugf("Found dual entries for payload hash %s: intoto=%v, dsse=%v",
		payloadHashHex, dualPair.IntotoEntry != nil, dualPair.DSSEEntry != nil)

	return dualPair, nil
}

// searchForImageDigest searches Rekor for entries containing the given image digest
func (r *RekorVSARetriever) searchForImageDigest(ctx context.Context, imageDigest string) ([]models.LogEntryAnon, error) {
	log.Debugf("searchForImageDigest called with imageDigest: %s", imageDigest)

	// Create search query using the search index API
	query := &models.SearchIndex{
		Hash: imageDigest,
	}

	log.Debugf("Calling client.SearchIndex")
	entries, err := r.client.SearchIndex(ctx, query)
	if err != nil {
		log.Debugf("SearchIndex returned error: %v", err)
		return nil, fmt.Errorf("failed to search Rekor index: %w", err)
	}

	log.Debugf("Search returned %d entries", len(entries))

	// The search index should return only entries containing our image digest
	// No need for additional filtering
	return entries, nil
}

// searchForPayloadHash searches Rekor for entries containing the given payload hash
func (r *RekorVSARetriever) searchForPayloadHash(ctx context.Context, payloadHashHex string) ([]models.LogEntryAnon, error) {
	log.Debugf("searchForPayloadHash called with payloadHashHex: %s", payloadHashHex)

	// Create search query using the search index API
	query := &models.SearchIndex{
		Hash: payloadHashHex,
	}

	log.Debugf("Calling client.SearchIndex")
	entries, err := r.client.SearchIndex(ctx, query)
	if err != nil {
		log.Debugf("SearchIndex returned error: %v", err)
		return nil, fmt.Errorf("failed to search Rekor index: %w", err)
	}

	log.Debugf("Search returned %d entries", len(entries))

	return entries, nil
}

// isValidImageDigest validates the format of an image digest
func isValidImageDigest(digest string) bool {
	// Image digest should be in format: algorithm:hash
	parts := strings.Split(digest, ":")
	if len(parts) != 2 {
		return false
	}

	// Check if algorithm is supported (sha256, sha512, etc.)
	algorithm := parts[0]
	if algorithm != "sha256" && algorithm != "sha512" {
		return false
	}

	// Check if hash is valid hex
	hash := parts[1]
	if len(hash) == 0 {
		return false
	}

	// Validate hex format
	_, err := hex.DecodeString(hash)
	return err == nil
}

// IsValidHexHash validates that a string is a valid hex hash
func (r *RekorVSARetriever) IsValidHexHash(hash string) bool {
	if len(hash) == 0 {
		return false
	}

	// Check if it's a valid hex string
	_, err := hex.DecodeString(hash)
	return err == nil
}

// isVSARecord determines if a Rekor entry contains a VSA record for the given image digest
func isVSARecord(entry models.LogEntryAnon, imageDigest string) bool {
	// Check if entry has attestation data
	if entry.Attestation == nil || entry.Attestation.Data == nil {
		log.Debugf("Entry has no attestation data")
		return false
	}

	// Decode the attestation data to check for VSA predicate type
	attestationData, err := base64.StdEncoding.DecodeString(string(entry.Attestation.Data))
	if err != nil {
		log.Debugf("Failed to decode attestation data: %v", err)
		return false
	}

	// Check if the attestation contains the VSA predicate type
	attestationStr := string(attestationData)
	vsaPredicateType := "https://conforma.dev/verification_summary/v1"

	if strings.Contains(attestationStr, vsaPredicateType) {
		log.Debugf("Found VSA predicate type in attestation")
		return true
	}

	log.Debugf("Attestation does not contain VSA predicate type")
	return false
}

// parseVSARecord converts a Rekor log entry to a VSARecord
func (r *RekorVSARetriever) parseVSARecord(entry models.LogEntryAnon) (VSARecord, error) {
	record := VSARecord{
		Attestation:  entry.Attestation,
		Verification: entry.Verification,
	}

	// Extract log index
	if entry.LogIndex != nil {
		record.LogIndex = *entry.LogIndex
	}

	// Extract log ID
	if entry.LogID != nil {
		record.LogID = *entry.LogID
	}

	// Extract integrated time
	if entry.IntegratedTime != nil {
		record.IntegratedTime = *entry.IntegratedTime
	}

	// Extract body
	if entry.Body != nil {
		if bodyStr, ok := entry.Body.(string); ok {
			record.Body = bodyStr
		}
	}

	return record, nil
}

// classifyEntryKind determines the kind of a Rekor entry (intoto, dsse, etc.)
func (r *RekorVSARetriever) classifyEntryKind(entry models.LogEntryAnon) string {
	// Check the body field for entry type information
	if entry.Body != nil {
		if bodyStr, ok := entry.Body.(string); ok {
			// Look for type indicators in the body
			if strings.Contains(bodyStr, `"intoto"`) {
				return "intoto"
			}
			if strings.Contains(bodyStr, `"dsse"`) {
				return "dsse"
			}
		}
	}

	// Check attestation data for VSA predicate type (indicates in-toto entry)
	if entry.Attestation != nil && entry.Attestation.Data != nil {
		attestationData, err := base64.StdEncoding.DecodeString(string(entry.Attestation.Data))
		if err == nil {
			attestationStr := string(attestationData)
			if strings.Contains(attestationStr, "https://conforma.dev/verification_summary/v1") {
				return "intoto"
			}
		}
	}

	// Default to unknown if we can't determine the type
	return "unknown"
}

// ExtractStatementFromIntoto extracts the Statement JSON from an in-toto entry
func (r *RekorVSARetriever) ExtractStatementFromIntoto(entry *models.LogEntryAnon) ([]byte, error) {
	if entry == nil {
		return nil, fmt.Errorf("entry cannot be nil")
	}

	// Check if this is an in-toto entry
	entryKind := r.classifyEntryKind(*entry)
	if entryKind != "intoto" {
		return nil, fmt.Errorf("entry is not an in-toto entry (kind: %s)", entryKind)
	}

	// Extract the DSSE envelope from the entry
	envelopeBytes, err := r.extractDSSEEnvelopeFromEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract DSSE envelope from entry: %w", err)
	}

	// Parse the DSSE envelope
	var envelope map[string]interface{}
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse DSSE envelope: %w", err)
	}

	// Extract the payload
	payloadBase64, ok := envelope["payload"].(string)
	if !ok {
		return nil, fmt.Errorf("payload not found in DSSE envelope")
	}

	// Decode the base64 payload
	payloadBytes, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 payload: %w", err)
	}

	// The payload should contain the Statement JSON
	return payloadBytes, nil
}

// extractDSSEEnvelopeFromEntry extracts the DSSE envelope from a Rekor entry
func (r *RekorVSARetriever) extractDSSEEnvelopeFromEntry(entry *models.LogEntryAnon) ([]byte, error) {
	// Try to extract from attestation data first
	if entry.Attestation != nil && entry.Attestation.Data != nil {
		attestationData, err := base64.StdEncoding.DecodeString(string(entry.Attestation.Data))
		if err == nil {
			// Check if this contains a DSSE envelope
			var attestation map[string]interface{}
			if err := json.Unmarshal(attestationData, &attestation); err == nil {
				// If it has payload and signatures, it's likely a DSSE envelope
				if _, hasPayload := attestation["payload"]; hasPayload {
					if _, hasSignatures := attestation["signatures"]; hasSignatures {
						return attestationData, nil
					}
				}
			}
		}
	}

	// Try to extract from body field
	if entry.Body != nil {
		if bodyStr, ok := entry.Body.(string); ok {
			// Try to parse as JSON
			var body map[string]interface{}
			if err := json.Unmarshal([]byte(bodyStr), &body); err == nil {
				// If it has payload and signatures, it's likely a DSSE envelope
				if _, hasPayload := body["payload"]; hasPayload {
					if _, hasSignatures := body["signatures"]; hasSignatures {
						return []byte(bodyStr), nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("could not extract DSSE envelope from entry")
}

// rekorClient wraps the actual Rekor client to implement our interface
type rekorClient struct {
	client *client.Rekor
}

func (rc *rekorClient) SearchIndex(ctx context.Context, query *models.SearchIndex) ([]models.LogEntryAnon, error) {
	params := &index.SearchIndexParams{
		Context: ctx,
		Query:   query,
	}

	result, err := rc.client.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}

	// SearchIndex returns a list of UUIDs, we need to fetch the full entries
	var entries []models.LogEntryAnon

	if result.Payload != nil {
		for _, uuid := range result.Payload {
			// Fetch the full log entry for each UUID
			entry, err := rc.GetLogEntryByUUID(ctx, uuid)
			if err != nil {
				log.Debugf("Failed to fetch log entry for UUID %s: %v", uuid, err)
				continue
			}
			if entry != nil {
				entries = append(entries, *entry)
			}
		}
	}

	log.Debugf("SearchIndex returned %d UUIDs, fetched %d full entries", len(result.Payload), len(entries))
	return entries, nil
}

func (rc *rekorClient) SearchLogQuery(ctx context.Context, query *models.SearchLogQuery) ([]models.LogEntryAnon, error) {
	params := &entries.SearchLogQueryParams{
		Context: ctx,
		Entry:   query,
	}

	result, err := rc.client.Entries.SearchLogQuery(params)
	if err != nil {
		return nil, err
	}

	var entries []models.LogEntryAnon
	if result.Payload != nil {
		for _, logEntryMap := range result.Payload {
			// Each logEntryMap is a models.LogEntry (map[string]models.LogEntryAnon)
			// Extract all LogEntryAnon values from the map
			for _, entry := range logEntryMap {
				entries = append(entries, entry)
			}
		}
	}

	return entries, nil
}

func (rc *rekorClient) GetLogEntryByIndex(ctx context.Context, index int64) (*models.LogEntryAnon, error) {
	params := &entries.GetLogEntryByIndexParams{
		Context:  ctx,
		LogIndex: index,
	}

	result, err := rc.client.Entries.GetLogEntryByIndex(params)
	if err != nil {
		return nil, err
	}

	// Convert the result to the expected format
	// GetLogEntryByIndex returns a map[string]models.LogEntryAnon
	if result.Payload != nil {
		// The payload is a map where the key is the UUID and value is the log entry
		// We need to find the entry by index, but the map is keyed by UUID
		// For now, return the first entry found (this might need refinement)
		for _, entry := range result.Payload {
			return &entry, nil
		}
	}

	return nil, fmt.Errorf("log entry not found for index: %d", index)
}

func (rc *rekorClient) GetLogEntryByUUID(ctx context.Context, uuid string) (*models.LogEntryAnon, error) {
	params := &entries.GetLogEntryByUUIDParams{
		Context:   ctx,
		EntryUUID: uuid,
	}

	result, err := rc.client.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}

	// Convert the result to the expected format
	// GetLogEntryByUUID returns a map[string]models.LogEntryAnon
	if result.Payload != nil {
		// The payload is a map where the key is the UUID and value is the log entry
		if entry, exists := result.Payload[uuid]; exists {
			return &entry, nil
		}
	}

	return nil, fmt.Errorf("log entry not found for UUID: %s", uuid)
}
