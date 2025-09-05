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
		}
	}

	if len(intotoV002Entries) == 0 {
		return nil, fmt.Errorf("no in-toto 0.0.2 entry found for image digest: %s", imageDigest)
	}

	// Select the latest entry by IntegratedTime
	intotoV002Entry := r.findLatestEntryByIntegratedTime(intotoV002Entries)
	if intotoV002Entry == nil {
		return nil, fmt.Errorf("failed to select latest in-toto 0.0.2 entry for image digest: %s", imageDigest)
	}

	// Build ssldsse.Envelope directly from in-toto entry
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

	// Prefer payload from content.envelope.payload when present; fallback to Attestation.Data
	var payloadB64 string

	// First, try to get payload from content.envelope.payload
	if payload, ok := envelopeData["payload"].(string); ok && payload != "" {
		payloadB64 = payload
	} else if entry.Attestation != nil && entry.Attestation.Data != nil {
		// Fallback to Attestation.Data (already base64-encoded)
		payloadB64 = string(entry.Attestation.Data)
	} else {
		return nil, fmt.Errorf("no payload found in envelope or attestation data")
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
			sig.Sig = sigHex
		} else {
			return nil, fmt.Errorf("signature %d missing required 'sig' field", i)
		}

		// Extract keyid field (optional)
		if keyid, ok := sigMap["keyid"].(string); ok {
			sig.KeyID = keyid
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

// RetrieveVSAData retrieves VSA data from Rekor and returns it as a string
func (r *RekorVSADataRetriever) RetrieveVSAData(ctx context.Context) (string, error) {
	// Get all entries for the image digest (without VSA filtering)
	allEntries, err := r.rekorRetriever.GetAllEntriesForImageDigest(ctx, r.imageDigest)
	if err != nil {
		return "", fmt.Errorf("failed to get all entries for image digest: %w", err)
	}

	if len(allEntries) == 0 {
		return "", fmt.Errorf("no entries found for image digest: %s", r.imageDigest)
	}

	// Find the latest matching pair where intoto has attestation and DSSE matches
	latestPair := r.rekorRetriever.FindLatestMatchingPair(ctx, allEntries)
	if latestPair == nil || latestPair.IntotoEntry == nil || latestPair.DSSEEntry == nil {
		return "", fmt.Errorf("no complete intoto/DSSE pair found for image digest: %s", r.imageDigest)
	}

	// Always reconstruct the complete DSSE envelope
	envelope, err := r.reconstructDSSEEnvelope(latestPair)
	if err != nil {
		return "", fmt.Errorf("failed to reconstruct DSSE envelope: %w", err)
	}

	return envelope, nil
}

// extractStatementFromIntotoEntry extracts the in-toto Statement JSON from an intoto entry
// This method handles the actual structure of intoto entries from Rekor
func (r *RekorVSADataRetriever) extractStatementFromIntotoEntry(entry models.LogEntryAnon) ([]byte, error) {
	// For intoto entries, the VSA data is in the Attestation field, not in Body.spec.content
	if entry.Attestation != nil && entry.Attestation.Data != nil {
		// The attestation data contains the actual in-toto Statement JSON
		return entry.Attestation.Data, nil
	}

	// Fallback: try to extract from body structure (though this shouldn't be needed)
	body, err := r.rekorRetriever.decodeBodyJSON(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode entry body: %w", err)
	}

	// Check if this is an intoto entry
	if kind, ok := body["kind"].(string); !ok || kind != "intoto" {
		return nil, fmt.Errorf("entry is not an intoto entry (kind: %s)", kind)
	}

	// Extract the content from spec.content
	spec, ok := body["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("spec field not found in intoto entry")
	}

	content, ok := spec["content"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("content field not found in intoto entry spec")
	}

	// The content should contain the in-toto Statement JSON
	// Convert to JSON bytes
	stmtBytes, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal in-toto Statement content: %w", err)
	}

	return stmtBytes, nil
}

// reconstructDSSEEnvelope reconstructs the complete DSSE envelope from the latest intoto/DSSE pair.
func (r *RekorVSADataRetriever) reconstructDSSEEnvelope(pair *DualEntryPair) (string, error) {

	// 1) Extract the actual in-toto Statement JSON from the intoto entry
	//    For intoto entries, we need to extract from spec.content structure, not from a DSSE envelope
	stmtPayload, err := r.extractStatementFromIntotoEntry(*pair.IntotoEntry)
	if err != nil {
		return "", fmt.Errorf("failed to extract in-toto Statement payload: %w", err)
	}

	// 2) Optional but recommended: confirm the payload hash matches Rekor's recorded payloadHash
	if pair.PayloadHash != "" {
		h := sha256.Sum256(stmtPayload)
		if fmt.Sprintf("%x", h[:]) != strings.ToLower(pair.PayloadHash) {
			return "", fmt.Errorf("payload hash mismatch: computed sha256=%x, rekor payloadHash=%s", h[:], pair.PayloadHash)
		}
	}

	// 3) Extract signatures from the DSSE entry (Rekor dsse.spec.signatures[])
	sigObjs, err := r.rekorRetriever.extractSignaturesAndPublicKey(*pair.DSSEEntry)
	if err != nil {
		return "", fmt.Errorf("failed to extract signatures from DSSE entry: %w", err)
	}

	// 4) Use the standard in-toto payload type for VSA attestations
	payloadType := "application/vnd.in-toto+json"

	// 5) Build a canonical DSSE envelope with the original payload + signatures
	envelope := DSSEEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(stmtPayload),
		Signatures:  make([]Signature, 0, len(sigObjs)),
	}
	for _, s := range sigObjs {
		var sigHex string
		if v, ok := s["signature"].(string); ok {
			sigHex = v
		} else if v, ok := s["sig"].(string); ok {
			sigHex = v
		} else {
			continue
		}
		keyid := ""
		if v, ok := s["keyid"].(string); ok {
			keyid = v
		}
		envelope.Signatures = append(envelope.Signatures, Signature{
			KeyID: keyid,
			Sig:   sigHex,
		})
	}
	if len(envelope.Signatures) == 0 {
		return "", fmt.Errorf("no usable signatures found in DSSE entry")
	}

	// 6) Return as JSON
	out, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("failed to marshal reconstructed DSSE envelope: %w", err)
	}
	return string(out), nil
}
