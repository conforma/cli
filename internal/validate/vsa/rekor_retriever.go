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
	"os"
	"strconv"
	"strings"
	"sync"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
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

	entries, err := r.client.SearchIndex(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search Rekor index: %w", err)
	}

	log.Debugf("Search returned %d entries", len(entries))

	// The search index should return only entries containing our image digest
	// No need for additional filtering
	return entries, nil
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

// classifyEntryKind determines the kind of a Rekor entry (intoto, intoto-v002, dsse, etc.)
func (r *RekorVSARetriever) classifyEntryKind(entry models.LogEntryAnon) string {
	// Prefer Body structure from the decoded Rekor body
	body, err := r.decodeBodyJSON(entry)
	if err == nil {
		// Check for the top-level "kind" field which indicates the entry type
		if kind, ok := body["kind"].(string); ok {
			switch strings.ToLower(kind) {
			case "intoto":
				// Check API version to distinguish between 0.0.1 and 0.0.2
				if apiVersion, ok := body["apiVersion"].(string); ok {
					switch apiVersion {
					case "0.0.2":
						return "intoto-v002"
					case "0.0.1":
						return "intoto"
					default:
						// Default to 0.0.1 for backward compatibility
						return "intoto"
					}
				}
				// If no API version specified, check for embedded DSSE envelope structure
				if spec, ok := body["spec"].(map[string]any); ok {
					if content, ok := spec["content"].(map[string]any); ok {
						if envelope, ok := content["envelope"].(map[string]any); ok {
							// Check if this has both payload and signatures (0.0.2) or just payload (0.0.1)
							if _, hasPayload := envelope["payload"]; hasPayload {
								if _, hasSignatures := envelope["signatures"]; hasSignatures {
									return "intoto-v002"
								}
								return "intoto"
							}
						}
					}
				}
				return "intoto"
			case "dsse":
				return "dsse"
			}
		}

		// Check for spec structure (in-toto 0.0.2 entries)
		if spec, ok := body["spec"].(map[string]any); ok {
			if content, ok := spec["content"].(map[string]any); ok {
				if envelope, ok := content["envelope"].(map[string]any); ok {
					// Check if this has both payloadType and signatures (0.0.2)
					if _, hasPayloadType := envelope["payloadType"]; hasPayloadType {
						if _, hasSignatures := envelope["signatures"]; hasSignatures {
							return "intoto-v002"
						}
					}
				}
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

// RetrieveVSA retrieves the latest VSA data as a DSSE envelope for a given image digest
// This is the main method used by validation functions to get VSA data for signature verification
func (r *RekorVSARetriever) RetrieveVSA(ctx context.Context, imageDigest string) (*ssldsse.Envelope, error) {
	log.Debugf("RekorVSARetriever.RetrieveVSA called with digest: %s - DEBUG LOG ADDED", imageDigest)
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

	log.Debugf("Getting VSA with signatures for image digest: %s", imageDigest)

	// Search for entries containing the image digest
	entries, err := r.searchForImageDigest(ctx, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to search Rekor for image digest: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries found in Rekor for image digest: %s", imageDigest)
	}

	// Find all in-toto 0.0.2 entries
	var intotoV002Entries []models.LogEntryAnon
	for _, entry := range entries {
		entryKind := r.classifyEntryKind(entry)
		if entryKind == "intoto-v002" {
			intotoV002Entries = append(intotoV002Entries, entry)
			// Log the UUID and IntegratedTime for each entry
			uuid := "unknown"
			if entry.LogID != nil {
				uuid = *entry.LogID
			}
			// Try to get the actual UUID from the entry body
			if body, err := r.decodeBodyJSON(entry); err == nil {
				if actualUUID, ok := body["uuid"].(string); ok {
					uuid = actualUUID
				}
			}
			integratedTime := "unknown"
			if entry.IntegratedTime != nil {
				integratedTime = fmt.Sprintf("%d", *entry.IntegratedTime)
			}
			log.Debugf("Found intoto-v002 entry: UUID=%s, LogID=%s, IntegratedTime=%s", uuid, *entry.LogID, integratedTime)
		}
	}

	if len(intotoV002Entries) == 0 {
		return nil, fmt.Errorf("no in-toto 0.0.2 entry found for image digest: %s", imageDigest)
	}

	log.Debugf("Found %d intoto-v002 entries, selecting latest by IntegratedTime", len(intotoV002Entries))

	// Select the latest entry by IntegratedTime
	intotoV002Entry := r.findLatestEntryByIntegratedTime(intotoV002Entries)
	if intotoV002Entry == nil {
		return nil, fmt.Errorf("failed to select latest in-toto 0.0.2 entry for image digest: %s", imageDigest)
	}

	// Note: Removed hardcoded UUID workaround - let normal selection logic work

	// Log the selected entry details
	selectedUUID := "unknown"
	if intotoV002Entry.LogID != nil {
		selectedUUID = *intotoV002Entry.LogID
	}
	selectedIntegratedTime := "unknown"
	if intotoV002Entry.IntegratedTime != nil {
		selectedIntegratedTime = fmt.Sprintf("%d", *intotoV002Entry.IntegratedTime)
	}
	log.Debugf("Selected entry: UUID=%s, IntegratedTime=%s", selectedUUID, selectedIntegratedTime)

	// Build ssldsse.Envelope directly from in-toto entry
	log.Debugf("About to call buildDSSEEnvelopeFromIntotoV002 - DEBUG LOG ADDED")
	envelope, err := r.buildDSSEEnvelopeFromIntotoV002(*intotoV002Entry)
	if err != nil {
		return nil, fmt.Errorf("failed to build DSSE envelope: %w", err)
	}

	log.Debugf("Successfully retrieved VSA with %d signatures for image digest: %s", len(envelope.Signatures), imageDigest)
	return envelope, nil
}

// buildDSSEEnvelopeFromIntotoV002 builds an ssldsse.Envelope directly from an in-toto 0.0.2 entry
// This eliminates the need for intermediate JSON marshaling/unmarshaling
func (r *RekorVSARetriever) buildDSSEEnvelopeFromIntotoV002(entry models.LogEntryAnon) (*ssldsse.Envelope, error) {
	log.Debugf("buildDSSEEnvelopeFromIntotoV002 called - DEBUG LOG ADDED")
	// Decode the entry body
	body, err := r.decodeBodyJSON(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode entry body: %w", err)
	}

	// Navigate to the in-toto 0.0.2 structure
	spec, ok := body["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("entry does not contain spec")
	}

	content, ok := spec["content"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("spec does not contain content")
	}

	envelopeData, ok := content["envelope"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("content does not contain envelope")
	}

	// Extract payloadType
	payloadType, ok := envelopeData["payloadType"].(string)
	if !ok {
		return nil, fmt.Errorf("envelope does not contain payloadType")
	}

	// Prefer Attestation.Data (already base64-encoded); fallback to content.envelope.payload
	var payloadB64 string

	// First, try to get payload from Attestation.Data (needs to be base64-encoded)
	if entry.Attestation != nil && entry.Attestation.Data != nil {
		log.Debugf("Using payload from Attestation.Data (length: %d)", len(entry.Attestation.Data))
		// Preview first 100 characters to see what we're dealing with
		previewLen := 100
		if len(entry.Attestation.Data) < previewLen {
			previewLen = len(entry.Attestation.Data)
		}
		log.Debugf("Attestation.Data preview (first %d chars): %s", previewLen, string(entry.Attestation.Data[:previewLen]))
		// Attestation.Data contains raw JSON, need to base64-encode it
		payloadB64 = base64.StdEncoding.EncodeToString(entry.Attestation.Data)
		log.Debugf("Base64-encoded payload length: %d", len(payloadB64))
	} else if payload, ok := envelopeData["payload"].(string); ok && payload != "" {
		// Fallback to content.envelope.payload
		log.Debugf("Using payload from envelope.payload (length: %d)", len(payload))
		// Check if the payload is already base64-encoded
		if _, err := base64.StdEncoding.DecodeString(payload); err == nil {
			// Already base64-encoded
			payloadB64 = payload
		} else {
			// Not base64-encoded, encode it
			payloadB64 = base64.StdEncoding.EncodeToString([]byte(payload))
		}
	} else {
		return nil, fmt.Errorf("no payload found in attestation data or envelope")
	}

	// Debug: Try to decode the payload to see if it's valid base64
	if _, err := base64.StdEncoding.DecodeString(payloadB64); err != nil {
		log.Debugf("Payload is not valid base64: %v", err)
		previewLen := 100
		if len(payloadB64) < previewLen {
			previewLen = len(payloadB64)
		}
		log.Debugf("Payload preview (first %d chars): %s", previewLen, payloadB64[:previewLen])

		// Try URL encoding as well
		if _, err := base64.URLEncoding.DecodeString(payloadB64); err != nil {
			log.Debugf("Payload is also not valid URL base64: %v", err)
		} else {
			log.Debugf("Payload is valid URL base64")
		}
	} else {
		log.Debugf("Payload is valid base64")
		// Decode and preview the decoded content
		decoded, _ := base64.StdEncoding.DecodeString(payloadB64)
		previewLen := 100
		if len(decoded) < previewLen {
			previewLen = len(decoded)
		}
		log.Debugf("Decoded payload preview (first %d chars): %s", previewLen, string(decoded[:previewLen]))
	}

	// Extract and convert signatures
	signaturesInterface, ok := envelopeData["signatures"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("envelope does not contain signatures")
	}

	if len(signaturesInterface) == 0 {
		return nil, fmt.Errorf("envelope contains empty signatures array")
	}

	var signatures []ssldsse.Signature
	for i, sigInterface := range signaturesInterface {
		sigMap, ok := sigInterface.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("signature %d is not a valid object", i)
		}

		sig := ssldsse.Signature{}

		// Extract sig field (required) - only support standard field
		if sigHex, ok := sigMap["sig"].(string); ok {
			// The signature in the in-toto entry is double-base64-encoded
			// We need to decode it twice to get the actual ASN.1 DER signature
			// Then re-encode it once for the DSSE library

			// First decode
			firstDecode, err := base64.StdEncoding.DecodeString(sigHex)
			if err != nil {
				return nil, fmt.Errorf("failed to decode signature %d: %w", i, err)
			}

			// Second decode (the first decode result is base64-encoded)
			decodedString := string(firstDecode)
			paddingNeeded := (4 - len(decodedString)%4) % 4
			paddedString := decodedString
			for j := 0; j < paddingNeeded; j++ {
				paddedString += "="
			}

			actualSignature, err := base64.StdEncoding.DecodeString(paddedString)
			if err != nil {
				return nil, fmt.Errorf("failed to double-decode signature %d: %w", i, err)
			}

			// Re-encode once for the DSSE library
			sig.Sig = base64.StdEncoding.EncodeToString(actualSignature)
		} else {
			return nil, fmt.Errorf("signature %d missing required 'sig' field", i)
		}

		// Extract keyid field (optional)
		if keyid, ok := sigMap["keyid"].(string); ok {
			sig.KeyID = keyid
		} else {
			// If no KeyID is provided, set a default one to help with verification
			// This might help the DSSE library match the signature to the public key
			sig.KeyID = "default"
		}

		signatures = append(signatures, sig)
	}

	// Validate that we have at least one valid signature
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no valid signatures found in envelope")
	}

	// Build the ssldsse.Envelope
	envelope := &ssldsse.Envelope{
		PayloadType: payloadType,
		Payload:     payloadB64,
		Signatures:  signatures,
	}

	return envelope, nil
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
			rc.worker(ctx, uuidChan, resultChan, workerID)
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
func (rc *rekorClient) worker(ctx context.Context, uuidChan <-chan string, resultChan chan<- fetchResult, workerID int) {

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

// RetrieveVSA retrieves VSA data as a DSSE envelope
func (r *RekorVSADataRetriever) RetrieveVSA(ctx context.Context, imageDigest string) (*ssldsse.Envelope, error) {
	log.Debugf("RekorVSADataRetriever.RetrieveVSA called with digest: %s - DEBUG LOG ADDED", imageDigest)
	return r.rekorRetriever.RetrieveVSA(ctx, imageDigest)
}
