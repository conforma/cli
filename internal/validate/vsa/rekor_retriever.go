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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

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
		if isVSARecord(entry) {
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

	// Maps to store the latest entry per payload hash for each type
	intotoMap := make(map[string]models.LogEntryAnon)
	dsseMap := make(map[string]models.LogEntryAnon)

	// Single pass: classify entries and extract payload hashes, keeping only the latest per hash
	for _, entry := range entries {
		entryKind := r.classifyEntryKind(entry)
		switch entryKind {
		case "intoto":
			// Extract the payload hash from the intoto entry
			payloadHash, err := r.extractPayloadHash(entry)
			if err != nil {
				log.Debugf("Failed to extract payload hash from intoto entry: %v", err)
				continue
			}

			// Keep only the latest intoto entry per payload hash
			if existing, exists := intotoMap[payloadHash]; !exists || r.isEntryNewer(entry, existing) {
				intotoMap[payloadHash] = entry
			}

		case "dsse":
			// Extract the payload hash from the DSSE entry
			payloadHash, err := r.extractPayloadHash(entry)
			if err != nil {
				log.Debugf("Failed to extract payload hash from DSSE entry: %v", err)
				continue
			}

			// Keep only the latest DSSE entry per payload hash
			if existing, exists := dsseMap[payloadHash]; !exists || r.isEntryNewer(entry, existing) {
				dsseMap[payloadHash] = entry
			}

		default:
			log.Debugf("Ignoring entry of unknown kind: %s", entryKind)
		}
	}

	log.Debugf("Found %d unique intoto payload hashes and %d unique DSSE payload hashes", len(intotoMap), len(dsseMap))

	// Find all valid pairs by checking intersection of payload hashes
	var validPairs []DualEntryPair
	for payloadHash, intotoEntry := range intotoMap {
		if dsseEntry, exists := dsseMap[payloadHash]; exists {
			// Verify both entries actually contain the same payloadHash (double-check)
			if r.entriesSharePayloadHash(intotoEntry, dsseEntry) {
				validPairs = append(validPairs, DualEntryPair{
					PayloadHash: payloadHash,
					IntotoEntry: &intotoEntry,
					DSSEEntry:   &dsseEntry,
				})
				log.Debugf("Found valid pair: intoto LogIndex=%d, DSSE LogIndex=%d",
					*intotoEntry.LogIndex, *dsseEntry.LogIndex)
			}
		}
	}

	log.Debugf("Found %d valid pairs that share the same payloadHash", len(validPairs))

	// If no valid pairs found, handle the error cases
	if len(validPairs) == 0 {
		log.Debugf("No valid pairs found for payload hash: %s", payloadHashHex)

		// Check if we have entries but they don't match (this indicates a problem)
		if len(intotoMap) > 0 && len(dsseMap) > 0 {
			log.Warnf("Found %d in-toto and %d DSSE entries but none share the same payloadHash. This may indicate corrupted or mismatched entries.",
				len(intotoMap), len(dsseMap))
			return nil, fmt.Errorf("found entries but none share the same payloadHash: %s", payloadHashHex)
		}

		// If we only have one type of entry, that's incomplete and indicates a problem
		if len(intotoMap) > 0 {
			log.Warnf("Found only in-toto entry for payload hash: %s. This indicates an incomplete dual upload - DSSE entry is missing.", payloadHashHex)
			return nil, fmt.Errorf("incomplete dual upload: found in-toto entry but no DSSE entry for payload hash: %s. Both entries are required for signature verification.", payloadHashHex)
		}
		if len(dsseMap) > 0 {
			log.Warnf("Found only DSSE entry for payload hash: %s. This indicates an incomplete dual upload - in-toto entry is missing.", payloadHashHex)
			return nil, fmt.Errorf("incomplete dual upload: found DSSE entry but no in-toto entry for payload hash: %s. Both entries are required for signature verification.", payloadHashHex)
		}

		// If we still have no entries at all, return an error for backward compatibility
		return nil, fmt.Errorf("no entries found for payload hash: %s", payloadHashHex)
	}

	// Now select the latest pair from the valid pairs based on IntegratedTime
	// This ensures we get the most recent data from entries that actually correspond to each other
	latestPair := validPairs[0]
	for _, pair := range validPairs[1:] {
		if r.isPairNewer(pair, latestPair) {
			latestPair = pair
		}
	}

	log.Debugf("Selected latest valid pair: intoto LogIndex=%d, DSSE LogIndex=%d",
		*latestPair.IntotoEntry.LogIndex, *latestPair.DSSEEntry.LogIndex)

	return &latestPair, nil
}

// isEntryNewer determines if entry1 is newer than entry2 based on IntegratedTime
// Returns true if entry1 is newer, false otherwise
func (r *RekorVSARetriever) isEntryNewer(entry1, entry2 models.LogEntryAnon) bool {
	time1 := entry1.IntegratedTime
	time2 := entry2.IntegratedTime

	// If both have timestamps, compare them
	if time1 != nil && time2 != nil {
		return *time1 > *time2
	}

	// If only one has a timestamp, prefer the one with timestamp
	if time1 != nil && time2 == nil {
		return true
	}
	if time1 == nil && time2 != nil {
		return false
	}

	// If neither has a timestamp, prefer the first one (maintains original order)
	return false
}

// isPairNewer determines if pair1 is newer than pair2 based on IntegratedTime
// Returns true if pair1 is newer, false otherwise
func (r *RekorVSARetriever) isPairNewer(pair1, pair2 DualEntryPair) bool {
	time1 := r.getPairTimestamp(pair1)
	time2 := r.getPairTimestamp(pair2)

	// If both have timestamps, compare them
	if time1 != nil && time2 != nil {
		return *time1 > *time2
	}

	// If only one has a timestamp, prefer the one with timestamp
	if time1 != nil && time2 == nil {
		return true
	}
	if time1 == nil && time2 != nil {
		return false
	}

	// If neither has a timestamp, prefer the first one (maintains original order)
	return false
}

// getPairTimestamp returns the timestamp for a pair based on the earliest IntegratedTime
// This ensures we're consistent about which timestamp represents the pair
func (r *RekorVSARetriever) getPairTimestamp(pair DualEntryPair) *int64 {
	var intotoTime, dsseTime *int64

	if pair.IntotoEntry != nil && pair.IntotoEntry.IntegratedTime != nil {
		intotoTime = pair.IntotoEntry.IntegratedTime
	}
	if pair.DSSEEntry != nil && pair.DSSEEntry.IntegratedTime != nil {
		dsseTime = pair.DSSEEntry.IntegratedTime
	}

	// If both have timestamps, return the earlier one (more conservative)
	if intotoTime != nil && dsseTime != nil {
		if *intotoTime < *dsseTime {
			return intotoTime
		}
		return dsseTime
	}

	// If only one has a timestamp, return that one
	if intotoTime != nil {
		return intotoTime
	}
	if dsseTime != nil {
		return dsseTime
	}

	// Neither has a timestamp
	return nil
}

// findLatestEntryByIntegratedTime finds the entry with the latest IntegratedTime
// If multiple entries have the same time or no IntegratedTime, returns the first one
func (r *RekorVSARetriever) findLatestEntryByIntegratedTime(entries []models.LogEntryAnon) *models.LogEntryAnon {
	if len(entries) == 0 {
		return nil
	}

	latest := entries[0]
	for _, entry := range entries[1:] {
		if entry.IntegratedTime != nil && latest.IntegratedTime != nil {
			if *entry.IntegratedTime > *latest.IntegratedTime {
				latest = entry
			}
		} else if entry.IntegratedTime != nil && latest.IntegratedTime == nil {
			// Prefer entries with IntegratedTime over those without
			latest = entry
		}
	}

	return &latest
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

// GetAllEntriesForImageDigest returns all entries for an image digest without VSA filtering
func (r *RekorVSARetriever) GetAllEntriesForImageDigest(ctx context.Context, imageDigest string) ([]models.LogEntryAnon, error) {
	return r.searchForImageDigest(ctx, imageDigest)
}

// FindLatestMatchingPair finds the latest pair where intoto has attestation and DSSE matches
func (r *RekorVSARetriever) FindLatestMatchingPair(ctx context.Context, entries []models.LogEntryAnon) *DualEntryPair {
	// Maps to store the latest entry per payload hash for each type
	intotoMap := make(map[string]models.LogEntryAnon)
	dsseMap := make(map[string]models.LogEntryAnon)

	// Single pass: classify entries and extract payload hashes, keeping only the latest per hash
	for _, entry := range entries {
		entryKind := r.classifyEntryKind(entry)

		switch entryKind {
		case "intoto":
			// Only consider intoto entries with attestations
			if entry.Attestation == nil || entry.Attestation.Data == nil {
				continue
			}

			// Extract the payload hash from the intoto entry body
			payloadHash, err := r.extractIntotoPayloadHash(entry)
			if err != nil {
				log.Debugf("Failed to extract intoto payload hash: %v", err)
				continue
			}

			// Keep only the latest intoto entry per payload hash
			if existing, exists := intotoMap[payloadHash]; !exists || r.isEntryNewer(entry, existing) {
				intotoMap[payloadHash] = entry
			}

		case "dsse":
			// Extract the payload hash from the DSSE entry body
			payloadHash, err := r.extractDSSEPayloadHash(entry)
			if err != nil {
				continue
			}

			// Keep only the latest DSSE entry per payload hash
			if existing, exists := dsseMap[payloadHash]; !exists || r.isEntryNewer(entry, existing) {
				dsseMap[payloadHash] = entry
			}
		}
	}

	log.Debugf("Found %d unique intoto payload hashes and %d unique DSSE payload hashes", len(intotoMap), len(dsseMap))

	// Find the latest matching pair by checking intersection of payload hashes
	var latestPair *DualEntryPair
	var latestTime int64

	for payloadHash, intotoEntry := range intotoMap {
		if dsseEntry, exists := dsseMap[payloadHash]; exists {
			// Found matching pair - create it and check if it's the latest
			tempPair := &DualEntryPair{
				PayloadHash: payloadHash,
				IntotoEntry: &intotoEntry,
				DSSEEntry:   &dsseEntry,
			}

			// Get the pair timestamp (earliest of intoto and DSSE times)
			pairTime := r.getPairTimestamp(*tempPair)
			if pairTime != nil && *pairTime > latestTime {
				latestTime = *pairTime
				latestPair = tempPair
			}
		}
	}

	return latestPair
}

// decodeBodyJSON decodes the base64-encoded body of a Rekor entry
func (r *RekorVSARetriever) decodeBodyJSON(entry models.LogEntryAnon) (map[string]any, error) {
	bodyStr, ok := entry.Body.(string)
	if !ok || bodyStr == "" {
		return nil, fmt.Errorf("empty or non-string body")
	}
	raw, err := base64.StdEncoding.DecodeString(bodyStr)
	if err != nil {
		return nil, fmt.Errorf("rekor body base64 decode failed: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("rekor body json unmarshal failed: %w", err)
	}
	return m, nil
}

// extractIntotoPayloadHash extracts the payload hash from an intoto entry's body
func (r *RekorVSARetriever) extractIntotoPayloadHash(entry models.LogEntryAnon) (string, error) {
	body, err := r.decodeBodyJSON(entry)
	if err != nil {
		return "", err
	}

	// Look for spec.content.payloadHash.value structure (intoto entries)
	if spec, ok := body["spec"].(map[string]any); ok {
		if content, ok := spec["content"].(map[string]any); ok {
			if payloadHash, ok := content["payloadHash"].(map[string]any); ok {
				if value, ok := payloadHash["value"].(string); ok {
					return value, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not extract payload hash from intoto entry")
}

// extractDSSEPayloadHash extracts the payload hash from a DSSE entry
func (r *RekorVSARetriever) extractDSSEPayloadHash(entry models.LogEntryAnon) (string, error) {
	body, err := r.decodeBodyJSON(entry)
	if err != nil {
		return "", err
	}

	// Look for spec.payloadHash.value structure
	if spec, ok := body["spec"].(map[string]any); ok {
		if payloadHash, ok := spec["payloadHash"].(map[string]any); ok {
			if value, ok := payloadHash["value"].(string); ok {
				return value, nil
			}
		}
	}

	return "", fmt.Errorf("could not extract payload hash from DSSE entry")
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

// isVSARecord determines if a Rekor entry contains a VSA record
func isVSARecord(entry models.LogEntryAnon) bool {
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
	// Prefer Body structure from the decoded Rekor body
	body, err := r.decodeBodyJSON(entry)
	if err == nil {
		// Check for the top-level "kind" field which indicates the entry type
		if kind, ok := body["kind"].(string); ok {
			switch strings.ToLower(kind) {
			case "intoto":
				return "intoto"
			case "dsse":
				return "dsse"
			}
		}

		// Fallback: check for top-level entry type indicators (legacy format)
		if _, hasIntoto := body["intoto"]; hasIntoto {
			return "intoto"
		}
		if _, hasDsse := body["dsse"]; hasDsse {
			return "dsse"
		}
	}

	// Fallback (only if Body missing/unreadable): look at Attestation for VSA predicate (intoto hint)
	if entry.Attestation != nil && entry.Attestation.Data != nil {
		if attBytes, err := base64.StdEncoding.DecodeString(string(entry.Attestation.Data)); err == nil {
			if strings.Contains(string(attBytes), "https://conforma.dev/verification_summary/v1") {
				return "intoto"
			}
		}
	}

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
	// Determine entry type first
	entryKind := r.classifyEntryKind(*entry)

	// Try to extract from attestation data first
	if entry.Attestation != nil && entry.Attestation.Data != nil {
		attestationData, err := base64.StdEncoding.DecodeString(string(entry.Attestation.Data))
		if err == nil {
			// Check if this contains a DSSE envelope
			var attestation map[string]interface{}
			if err := json.Unmarshal(attestationData, &attestation); err == nil {
				if _, hasPayload := attestation["payload"]; hasPayload {
					// For intoto entries, payload is sufficient (signatures not required)
					if entryKind == "intoto" {
						return attestationData, nil
					}
					// For DSSE entries, require both payload and signatures
					if _, hasSignatures := attestation["signatures"]; hasSignatures {
						return attestationData, nil
					}
				}
			}
		}
	}

	// Try to extract from body field
	if entry.Body != nil {
		body, err := r.decodeBodyJSON(*entry)
		if err == nil {
			// Look for content.envelope structure
			if content, ok := body["content"].(map[string]interface{}); ok {
				if envelope, ok := content["envelope"].(map[string]interface{}); ok {
					if _, hasPayload := envelope["payload"]; hasPayload {
						// For intoto entries, payload is sufficient (signatures not required)
						if entryKind == "intoto" {
							// Return the envelope as JSON
							envelopeBytes, err := json.Marshal(envelope)
							if err == nil {
								return envelopeBytes, nil
							}
						}
						// For DSSE entries, require both payload and signatures
						if _, hasSignatures := envelope["signatures"]; hasSignatures {
							// Return the envelope as JSON
							envelopeBytes, err := json.Marshal(envelope)
							if err == nil {
								return envelopeBytes, nil
							}
						}
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("could not extract DSSE envelope from entry")
}

// extractSignaturesAndPublicKey extracts signatures and public key from a DSSE entry
func (r *RekorVSARetriever) extractSignaturesAndPublicKey(entry models.LogEntryAnon) ([]map[string]interface{}, error) {
	envelopeBytes, err := r.extractDSSEEnvelopeFromEntry(&entry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract DSSE envelope: %w", err)
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse DSSE envelope: %w", err)
	}

	signatures, ok := envelope["signatures"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("signatures not found in DSSE envelope")
	}

	var result []map[string]interface{}
	for _, sig := range signatures {
		if sigMap, ok := sig.(map[string]interface{}); ok {
			result = append(result, sigMap)
		}
	}

	return result, nil
}

// entriesSharePayloadHash checks if two Rekor entries share the same payloadHash
func (r *RekorVSARetriever) entriesSharePayloadHash(intotoEntry, dsseEntry models.LogEntryAnon) bool {
	// Extract payload hashes from both entries
	intotoPayloadHash, err := r.extractPayloadHash(intotoEntry)
	if err != nil {
		log.Debugf("Failed to extract payload hash from intoto entry: %v", err)
		return false
	}
	dssePayloadHash, err := r.extractPayloadHash(dsseEntry)
	if err != nil {
		log.Debugf("Failed to extract payload hash from dsse entry: %v", err)
		return false
	}

	// Compare payload hashes
	return intotoPayloadHash == dssePayloadHash
}

// extractPayloadHash extracts the payload hash from a Rekor entry's body or attestation data
func (r *RekorVSARetriever) extractPayloadHash(entry models.LogEntryAnon) (string, error) {
	// Try to extract from body field first (modern schema)
	if entry.Body != nil {
		body, err := r.decodeBodyJSON(entry)
		if err == nil {
			// Look for spec.content.payloadHash.value structure (intoto entries)
			if spec, ok := body["spec"].(map[string]interface{}); ok {
				if content, ok := spec["content"].(map[string]interface{}); ok {
					if payloadHash, ok := content["payloadHash"].(map[string]interface{}); ok {
						if value, ok := payloadHash["value"].(string); ok {
							return value, nil
						}
					}
				}
			}

			// Look for spec.payloadHash.value structure (DSSE entries)
			if spec, ok := body["spec"].(map[string]interface{}); ok {
				if payloadHash, ok := spec["payloadHash"].(map[string]interface{}); ok {
					if value, ok := payloadHash["value"].(string); ok {
						return value, nil
					}
				}
			}
		}
	}

	// Try to extract from attestation data (only if it contains a direct hash)
	if entry.Attestation != nil && entry.Attestation.Data != nil {
		attestationData, err := base64.StdEncoding.DecodeString(string(entry.Attestation.Data))
		if err == nil {
			// Check if this contains a DSSE envelope with a direct payloadHash
			var attestation map[string]interface{}
			if err := json.Unmarshal(attestationData, &attestation); err == nil {
				// Look for direct payloadHash in attestation (if available)
				if payloadHash, ok := attestation["payloadHash"].(string); ok {
					return payloadHash, nil
				}
			}
		}
	}

	// Legacy fallback: Look for content.envelope.payload structure (only if absolutely necessary)
	if entry.Body != nil {
		body, err := r.decodeBodyJSON(entry)
		if err == nil {
			if content, ok := body["content"].(map[string]interface{}); ok {
				if envelope, ok := content["envelope"].(map[string]interface{}); ok {
					if payload, ok := envelope["payload"].(string); ok {
						// Decode the base64 payload to get the actual content
						payloadBytes, err := base64.StdEncoding.DecodeString(payload)
						if err == nil {
							// Calculate SHA256 hash of the decoded payload
							hash := sha256.Sum256(payloadBytes)
							return fmt.Sprintf("%x", hash[:]), nil
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("could not extract payload hash from entry")
}

// extractVSAStatement extracts the VSA Statement from an in-toto entry
func (r *RekorVSARetriever) extractVSAStatement(entry models.LogEntryAnon) ([]byte, error) {
	envelopeBytes, err := r.extractDSSEEnvelopeFromEntry(&entry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract DSSE envelope: %w", err)
	}

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

// GetPairedVSAWithSignatures retrieves a VSA with its corresponding signatures by payloadHash
// This ensures the signatures actually correspond to the VSA Statement being evaluated
func (r *RekorVSARetriever) GetPairedVSAWithSignatures(ctx context.Context, payloadHashHex string) (*PairedVSAWithSignatures, error) {
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

	log.Debugf("Getting paired VSA with signatures for payload hash: %s", payloadHashHex)

	// Find the dual entry pair
	dualPair, err := r.FindByPayloadHash(ctx, payloadHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to find dual entries: %w", err)
	}

	// Ensure we have both entries for complete verification
	if dualPair.IntotoEntry == nil || dualPair.DSSEEntry == nil {
		if dualPair.IntotoEntry == nil && dualPair.DSSEEntry == nil {
			return nil, fmt.Errorf("no entries found for payload hash: %s", payloadHashHex)
		} else if dualPair.IntotoEntry == nil {
			return nil, fmt.Errorf("incomplete dual upload: found DSSE entry but no in-toto entry for payload hash: %s. Both entries are required for signature verification.", payloadHashHex)
		} else {
			return nil, fmt.Errorf("incomplete dual upload: found in-toto entry but no DSSE entry for payload hash: %s. Both entries are required for signature verification.", payloadHashHex)
		}
	}

	// Extract signatures and public key from DSSE entry
	signatures, err := r.extractSignaturesAndPublicKey(*dualPair.DSSEEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract signatures from DSSE entry: %w", err)
	}

	// Extract VSA Statement from in-toto entry
	vsaStatement, err := r.extractVSAStatement(*dualPair.IntotoEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to extract VSA Statement from in-toto entry: %w", err)
	}

	// Verify that the VSA Statement contains the expected predicate type
	var statement map[string]interface{}
	if err := json.Unmarshal(vsaStatement, &statement); err != nil {
		return nil, fmt.Errorf("failed to parse VSA Statement: %w", err)
	}

	predicateType, ok := statement["predicateType"].(string)
	if !ok {
		return nil, fmt.Errorf("predicateType not found in VSA Statement")
	}

	expectedPredicateType := "https://conforma.dev/verification_summary/v1"
	if predicateType != expectedPredicateType {
		return nil, fmt.Errorf("unexpected predicate type: got %s, want %s", predicateType, expectedPredicateType)
	}

	result := &PairedVSAWithSignatures{
		PayloadHash:   payloadHashHex,
		VSAStatement:  vsaStatement,
		Signatures:    signatures,
		IntotoEntry:   dualPair.IntotoEntry,
		DSSEEntry:     dualPair.DSSEEntry,
		PredicateType: predicateType,
	}

	log.Debugf("Successfully paired VSA with %d signatures for payload hash: %s", len(signatures), payloadHashHex)
	return result, nil
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
	if len(result.Payload) == 0 {
		log.Debugf("SearchIndex returned no UUIDs")
		return nil, nil
	}

	log.Debugf("SearchIndex returned %d UUIDs, fetching full entries in parallel", len(result.Payload))

	// Fetch the full log entries for each UUID using parallel workers
	entries, err := rc.fetchLogEntriesParallel(ctx, result.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch log entries: %w", err)
	}

	log.Debugf("Successfully fetched %d full entries from %d UUIDs", len(entries), len(result.Payload))
	return entries, nil
}

// fetchLogEntriesParallel fetches log entries in parallel using a worker pool
func (rc *rekorClient) fetchLogEntriesParallel(ctx context.Context, uuids []string) ([]models.LogEntryAnon, error) {
	if len(uuids) == 0 {
		return nil, nil
	}

	// Get worker count from environment variable, default to 8
	workerCount := rc.getWorkerCount()

	// For small numbers of UUIDs, use fewer workers to avoid overhead
	if len(uuids) < workerCount {
		workerCount = len(uuids)
	}

	log.Debugf("Fetching %d log entries using %d workers", len(uuids), workerCount)

	// Create channels for coordination
	uuidChan := make(chan string, len(uuids))
	resultChan := make(chan fetchResult, len(uuids))
	errorChan := make(chan error, 1)

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rc.worker(ctx, uuidChan, resultChan, errorChan, workerID)
		}(i)
	}

	// Send UUIDs to workers
	go func() {
		defer close(uuidChan)
		for _, uuid := range uuids {
			select {
			case uuidChan <- uuid:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results and handle errors
	var entries []models.LogEntryAnon
	var fetchErrors []error

	// Collect all results
	for result := range resultChan {
		if result.err != nil {
			fetchErrors = append(fetchErrors, result.err)
			continue
		}
		if result.entry != nil {
			entries = append(entries, *result.entry)
		}
	}

	// Check for context cancellation or worker errors
	select {
	case err := <-errorChan:
		return nil, fmt.Errorf("worker error: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// No immediate errors, continue
	}

	// Log any fetch errors but don't fail the entire operation
	if len(fetchErrors) > 0 {
		log.Debugf("Failed to fetch %d log entries (continuing with %d successful): %v",
			len(fetchErrors), len(entries), fetchErrors)
	}

	return entries, nil
}

// fetchResult represents the result of a single UUID fetch operation
type fetchResult struct {
	entry *models.LogEntryAnon
	err   error
}

// worker processes UUIDs from the input channel and sends results to the output channel
func (rc *rekorClient) worker(ctx context.Context, uuidChan <-chan string, resultChan chan<- fetchResult, errorChan chan<- error, workerID int) {

	for uuid := range uuidChan {
		select {
		case <-ctx.Done():
			return
		default:
			// Continue processing
		}

		// Fetch the log entry
		entry, err := rc.GetLogEntryByUUID(ctx, uuid)
		if err != nil {
			log.Debugf("Worker %d: Failed to fetch log entry for UUID %s: %v", workerID, uuid, err)
			select {
			case resultChan <- fetchResult{entry: nil, err: err}:
			case <-ctx.Done():
				return
			}
			continue
		}

		// Send successful result
		select {
		case resultChan <- fetchResult{entry: entry, err: nil}:
		case <-ctx.Done():
			return
		}
	}
}

// getWorkerCount returns the number of workers to use for parallel operations
func (rc *rekorClient) getWorkerCount() int {
	// Default to 8 workers
	defaultWorkers := 8

	// Check environment variable
	if workerStr := os.Getenv("EC_REKOR_WORKERS"); workerStr != "" {
		if workers, err := strconv.Atoi(workerStr); err == nil && workers > 0 {
			// Cap at reasonable maximum to prevent resource exhaustion
			if workers > 64 {
				log.Warnf("EC_REKOR_WORKERS=%d exceeds maximum, capping at 64", workers)
				workers = 64
			}
			return workers
		}
		log.Warnf("Invalid EC_REKOR_WORKERS value '%s', using default %d", workerStr, defaultWorkers)
	}

	return defaultWorkers
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
