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

// RekorVSADataRetriever implements VSADataRetriever for Rekor-based VSA retrieval
type RekorVSADataRetriever struct {
	rekorRetriever *RekorVSARetriever
	imageDigest    string
}

// NewRekorVSADataRetriever creates a new Rekor-based VSA data retriever
func NewRekorVSADataRetriever(opts RetrievalOptions, imageDigest string) (*RekorVSADataRetriever, error) {
	rekorRetriever, err := NewRekorVSARetriever(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Rekor retriever: %w", err)
	}

	return &RekorVSADataRetriever{
		rekorRetriever: rekorRetriever,
		imageDigest:    imageDigest,
	}, nil
}

// RetrieveVSAData retrieves VSA data from Rekor and returns it as a string
func (r *RekorVSADataRetriever) RetrieveVSAData(ctx context.Context) (string, error) {
	// Retrieve VSA records from Rekor
	records, err := r.rekorRetriever.RetrieveVSA(ctx, r.imageDigest)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve VSA records from Rekor: %w", err)
	}

	if len(records) == 0 {
		return "", fmt.Errorf("no VSA records found for image digest: %s", r.imageDigest)
	}

	// For now, use the first record (we could extend this to handle multiple records)
	record := records[0]

	// Return the raw body content from the Rekor record
	// This should contain the original VSA data that was stored in Rekor
	return record.Body, nil
}
