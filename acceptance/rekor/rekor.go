// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package rekor is a stub implementation of Rekord
package rekor

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/strfmt"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/rekor/pkg/generated/models"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	intoto "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/conforma/cli/acceptance/crypto"
	"github.com/conforma/cli/acceptance/testenv"
	"github.com/conforma/cli/acceptance/wiremock"
)

type key int

const rekorStateKey = key(0) // we store the gitState struct under this key in Context and when persisted

type rekorState struct {
	KeyPair *cosign.KeysBytes
}

func (r rekorState) Key() any {
	return rekorStateKey
}

// stubRekordRunning starts the stub apiserver using WireMock
func stubRekordRunning(ctx context.Context) (context.Context, error) {
	var state *rekorState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.KeyPair == nil {
		// not used for any signing, we just need the public key in PEM for the
		// in-toto schema below
		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			return ctx, err
		}

		state.KeyPair = keyPair
	}

	ctx, err = wiremock.StartWiremock(ctx)
	if err != nil {
		return ctx, err
	}

	if err = wiremock.StubFor(ctx, wiremock.Get(wiremock.URLPathEqualTo("/api/v1/log/publicKey")).
		WillReturnResponse(
			wiremock.NewResponse().WithBody(
				string(state.KeyPair.PublicBytes),
			).WithHeaders(
				map[string]string{"Content-Type": "application/x-pem-file"},
			).WithStatus(200))); err != nil {
		return ctx, err
	}

	return ctx, nil
}

// ComputeLogID returns a hex-encoded SHA-256 digest of the
// SubjectPublicKeyInfo ASN.1 structure for the given
// PEM-encoded public key
func ComputeLogID(publicKey []byte) (string, error) {
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:]), nil
}

// computeLogEntryForSignature constructs a Rekor log entry and provides its UUID
// for the provided public key, data, and signature
func computeLogEntryForSignature(ctx context.Context, publicKey, data, signature []byte) (logEntry *models.LogEntryAnon, entryUUID []byte, err error) {
	// the body of the log entry is a hashedrekord payload
	logBody := hashedrekord.NewEntry()

	algorithm := models.HashedrekordV001SchemaDataHashAlgorithmSha256

	// compute the actual hash of the payload data for proper verification
	payloadHash := sha256.Sum256(data)
	hash := hex.EncodeToString(payloadHash[:])

	publicKeyBase64 := strfmt.Base64(publicKey)
	signatureBase64 := strfmt.Base64(signature)

	// the only way to set fields of the hashedrekord Entry
	err = logBody.Unmarshal(&models.Hashedrekord{
		Spec: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: &algorithm,
					Value:     &hash,
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: signatureBase64,
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: publicKeyBase64,
				},
			},
		},
	})
	if err != nil {
		return nil, nil, err
	}

	logBodyBytes, err := logBody.Canonicalize(ctx)
	if err != nil {
		return nil, nil, err
	}

	hasher := rfc6962.DefaultHasher

	// needs to match the hash over body bytes
	entryUUID = hasher.HashLeaf(logBodyBytes)

	// create simplest Merkle tree
	entryHash := hasher.HashChildren(hasher.EmptyRoot(), entryUUID)
	hashes := []string{
		hex.EncodeToString(entryHash),
	}
	rootHash := hasher.HashChildren(entryHash, entryUUID)
	rootHashHex := hex.EncodeToString(rootHash)

	// simplest possible tree has the size of 2
	logIndex := int64(1)
	treeSize := int64(2)

	// Use Rekor public key for logID computation
	state := testenv.FetchState[rekorState](ctx)
	logID, err := ComputeLogID(state.KeyPair.PublicBytes)
	if err != nil {
		return nil, nil, err
	}

	// Use current Unix timestamp for integrated time
	time := time.Now().Unix()

	// fill in the entry with the attestation and in-toto entry for the log
	// and add the verification
	logEntry = &models.LogEntryAnon{
		Attestation: &models.LogEntryAnonAttestation{
			Data: data,
		},
		Body: base64.StdEncoding.EncodeToString(logBodyBytes),
		Verification: &models.LogEntryAnonVerification{
			InclusionProof: &models.InclusionProof{
				RootHash: &rootHashHex,
				Hashes:   hashes,
				LogIndex: &logIndex,
				TreeSize: &treeSize,
			},
		},
		IntegratedTime: &time,
		LogIndex:       &logIndex,
		LogID:          &logID,
	}

	return logEntry, entryUUID, nil
}

// computeLogEntryForAttestation constructs a Rekor log entry using intoto format
// for attestations, providing the entry's UUID
func computeLogEntryForAttestation(ctx context.Context, publicKey []byte, attestationData []byte) (logEntry *models.LogEntryAnon, entryUUID []byte, err error) {
	// the body of the log entry is an intoto payload for attestations
	logBody := intoto.NewEntry()

	// Parse the DSSE envelope that was created by attestation.SignStatement
	var dsseEnvelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Keyid string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}

	err = json.Unmarshal(attestationData, &dsseEnvelope)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DSSE envelope: %w", err)
	}

	// Convert public key to base64
	publicKeyBase64 := strfmt.Base64(publicKey)

	// Create signature structure for the envelope
	sigBase64 := strfmt.Base64(dsseEnvelope.Signatures[0].Sig)
	signatures := []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
		{
			PublicKey: &publicKeyBase64,
			Sig:       &sigBase64,
		},
	}

	// For intoto v0.0.2, create the proper envelope structure
	algorithm := models.IntotoV002SchemaContentPayloadHashAlgorithmSha256

	// compute hash of the entire attestation data (the DSSE envelope)
	// This matches what cosign verification expects for attestations
	payloadHash := sha256.Sum256(attestationData)
	hash := hex.EncodeToString(payloadHash[:])

	err = logBody.Unmarshal(&models.Intoto{
		Spec: models.IntotoV002Schema{
			Content: &models.IntotoV002SchemaContent{
				Envelope: &models.IntotoV002SchemaContentEnvelope{
					Payload:     strfmt.Base64(dsseEnvelope.Payload),
					PayloadType: &dsseEnvelope.PayloadType,
					Signatures:  signatures,
				},
				Hash: &models.IntotoV002SchemaContentHash{
					Algorithm: &algorithm,
					Value:     &hash,
				},
				PayloadHash: &models.IntotoV002SchemaContentPayloadHash{
					Algorithm: &algorithm,
					Value:     &hash,
				},
			},
		},
	})
	if err != nil {
		return nil, nil, err
	}

	logBodyBytes, err := logBody.Canonicalize(ctx)
	if err != nil {
		return nil, nil, err
	}

	hasher := rfc6962.DefaultHasher

	// needs to match the hash over body bytes
	entryUUID = hasher.HashLeaf(logBodyBytes)

	// create simplest Merkle tree
	entryHash := hasher.HashChildren(hasher.EmptyRoot(), entryUUID)
	hashes := []string{
		hex.EncodeToString(entryHash),
	}
	rootHash := hasher.HashChildren(entryHash, entryUUID)
	rootHashHex := hex.EncodeToString(rootHash)

	// simplest possible tree has the size of 2
	logIndex := int64(1)
	treeSize := int64(2)

	// Use the Rekor public key for logID computation, not the signing key
	state := testenv.FetchState[rekorState](ctx)
	logID, err := ComputeLogID(state.KeyPair.PublicBytes)
	if err != nil {
		return nil, nil, err
	}

	// Use current Unix timestamp for integrated time
	time := time.Now().Unix()

	// fill in the entry with the attestation and in-toto entry for the log
	// and add the verification
	logEntry = &models.LogEntryAnon{
		Attestation: &models.LogEntryAnonAttestation{
			Data: attestationData,
		},
		Body: base64.StdEncoding.EncodeToString(logBodyBytes),
		Verification: &models.LogEntryAnonVerification{
			InclusionProof: &models.InclusionProof{
				RootHash: &rootHashHex,
				Hashes:   hashes,
				LogIndex: &logIndex,
				TreeSize: &treeSize,
			},
		},
		IntegratedTime: &time,
		LogIndex:       &logIndex,
		LogID:          &logID,
	}

	return logEntry, entryUUID, nil
}

// ComputeEntryTimestamp signs Rekor log entryies body, integrated timestam,
// log index and log ID with the provided private key encrypted by the given
// password
func ComputeEntryTimestamp(privateKey, password []byte, logEntry models.LogEntryAnon) ([]byte, error) {
	encryptedPrivateKey, _ := pem.Decode(privateKey)
	if encryptedPrivateKey == nil {
		return nil, errors.New("unable to decode PEM encoded private key")
	}

	derPrivateKey, err := encrypted.Decrypt(encryptedPrivateKey.Bytes, password)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(derPrivateKey)
	if err != nil {
		return nil, err
	}

	payload := bundle.EntryToBundle(&logEntry)

	payloadBytes, err := json.Marshal(payload.Payload)
	if err != nil {
		return nil, err
	}

	canonicalizedPayload, err := jsoncanonicalizer.Transform(payloadBytes)
	if err != nil {
		return nil, err
	}

	payloadHash := sha256.Sum256(canonicalizedPayload)

	return ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), payloadHash[:])
}

// StubRekorEntryCreationForSignature creates WireMock stubs for both Rekor entry creation and retrieval endpoints
// This handles both POST /api/v1/log/entries (creation) and POST /api/v1/log/entries/retrieve (retrieval)
func StubRekorEntryCreationForSignature(ctx context.Context, data []byte, signature []byte, signatureJSON []byte, publicKey []byte) error {
	state := testenv.FetchState[rekorState](ctx)

	logEntry, entryUUID, err := computeLogEntryForSignature(ctx, publicKey, data, signature)
	if err != nil {
		return err
	}

	// Compute the signed entry timestamp using the Rekor private key
	signedTimestamp, err := ComputeEntryTimestamp(state.KeyPair.PrivateBytes, state.KeyPair.Password(), *logEntry)
	if err != nil {
		return fmt.Errorf("failed to compute signed entry timestamp: %w", err)
	}

	// Add the verification section with the signed entry timestamp
	logEntry.Verification = &models.LogEntryAnonVerification{
		SignedEntryTimestamp: strfmt.Base64(signedTimestamp),
	}

	// Create the response format that Rekor creation endpoint returns: {uuid: logEntry}
	response := map[string]*models.LogEntryAnon{
		hex.EncodeToString(entryUUID): logEntry,
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal rekor response: %w", err)
	}

	// Create WireMock stub for POST /api/v1/log/entries (creation)
	err = wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/log/entries")).
		WillReturnResponse(wiremock.NewResponse().
			WithBody(string(responseBody)).
			WithHeaders(map[string]string{
				"Content-Type": "application/json",
			}).
			WithStatus(201))) // Rekor returns 201 Created for successful entry creation
	if err != nil {
		return fmt.Errorf("failed to create creation endpoint stub: %w", err)
	}

	// Extract signature content for JSON path matching
	jsonPathQueryValue, err := JsonPathFromSignature(signatureJSON)
	if err != nil {
		return fmt.Errorf("failed to extract JSON path from signature: %w", err)
	}

	// Create array response format for retrieval endpoint
	retrievalResponse := []map[string]*models.LogEntryAnon{response}
	retrievalResponseBody, err := json.Marshal(retrievalResponse)
	if err != nil {
		return fmt.Errorf("failed to marshal retrieval response: %w", err)
	}

	// Create WireMock stub for POST /api/v1/log/entries/retrieve (retrieval)
	return wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/log/entries/retrieve")).
		WithBodyPattern(wiremock.MatchingJsonPath(jsonPathQueryValue)).
		WillReturnResponse(wiremock.NewResponse().
			WithBody(string(retrievalResponseBody)).
			WithHeaders(map[string]string{
				"Content-Type": "application/json",
			}).
			WithStatus(200))) // Rekor returns 200 OK for successful retrieval
}

// StubRekorEntryCreationForAttestation creates WireMock stubs for both Rekor entry creation and retrieval endpoints
// specifically for attestations using intoto entry type
func StubRekorEntryCreationForAttestation(ctx context.Context, attestationData []byte, publicKey []byte) error {
	state := testenv.FetchState[rekorState](ctx)

	logEntry, entryUUID, err := computeLogEntryForAttestation(ctx, publicKey, attestationData)
	if err != nil {
		return err
	}

	// Compute the signed entry timestamp using the Rekor private key
	signedTimestamp, err := ComputeEntryTimestamp(state.KeyPair.PrivateBytes, state.KeyPair.Password(), *logEntry)
	if err != nil {
		return fmt.Errorf("failed to compute signed entry timestamp: %w", err)
	}

	// Add the verification section with the signed entry timestamp
	logEntry.Verification = &models.LogEntryAnonVerification{
		SignedEntryTimestamp: strfmt.Base64(signedTimestamp),
	}

	// Create the response format that Rekor creation endpoint returns: {uuid: logEntry}
	response := map[string]*models.LogEntryAnon{
		hex.EncodeToString(entryUUID): logEntry,
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal rekor response: %w", err)
	}

	// Create WireMock stub for POST /api/v1/log/entries (creation)
	err = wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/log/entries")).
		WillReturnResponse(wiremock.NewResponse().
			WithBody(string(responseBody)).
			WithHeaders(map[string]string{
				"Content-Type": "application/json",
			}).
			WithStatus(201))) // Rekor returns 201 Created for successful entry creation
	if err != nil {
		return fmt.Errorf("failed to create creation endpoint stub: %w", err)
	}

	// Extract attestation content for JSON path matching - compute the same hash as in computeLogEntryForAttestation
	// Hash the entire DSSE envelope, not just the payload
	payloadHash := sha256.Sum256(attestationData)
	hash := hex.EncodeToString(payloadHash[:])

	jsonPathQueryValue := fmt.Sprintf("$..[?(@.value=='%s')]", hash)

	// Create array response format for retrieval endpoint
	retrievalResponse := []map[string]*models.LogEntryAnon{response}
	retrievalResponseBody, err := json.Marshal(retrievalResponse)
	if err != nil {
		return fmt.Errorf("failed to marshal retrieval response: %w", err)
	}

	// Create WireMock stub for POST /api/v1/log/entries/retrieve (retrieval)
	return wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/log/entries/retrieve")).
		WithBodyPattern(wiremock.MatchingJsonPath(jsonPathQueryValue)).
		WillReturnResponse(wiremock.NewResponse().
			WithBody(string(retrievalResponseBody)).
			WithHeaders(map[string]string{
				"Content-Type": "application/json",
			}).
			WithStatus(200))) // Rekor returns 200 OK for successful retrieval
}

// JsonPathFromSignature returns the JSON Path expression to be used in the wiremock stub
// for a signature query. The expression matches the value of the signature's content.
func JsonPathFromSignature(data []byte) (string, error) {
	signature := cosign.Signatures{}
	if err := json.Unmarshal(data, &signature); err != nil {
		return "", fmt.Errorf("unmarshalling signature: %w", err)
	}

	if signature.Sig == "" {
		return "", fmt.Errorf("data missing 'sig' key: %s", data)
	}

	return fmt.Sprintf("$..[?(@.content=='%s')]", signature.Sig), nil
}

// StubRekor returns the `http://host:port` of the stubbed Rekord
func StubRekor(ctx context.Context) (string, error) {
	endpoint, err := wiremock.Endpoint(ctx)
	if err != nil {
		return "", err
	}

	return strings.Replace(endpoint, "localhost", "rekor.localhost", 1), nil
}

// PublicKey returns the public key of the Rekor signing key
func PublicKey(ctx context.Context) []byte {
	state := testenv.FetchState[rekorState](ctx)

	return state.KeyPair.PublicBytes
}

func IsRunning(ctx context.Context) bool {
	return testenv.HasState[rekorState](ctx)
}

// ClearRekorEntries removes all Rekor entries by overriding
// the retrieval endpoint to return an error
func ClearRekorEntries(ctx context.Context) error {
	// Create a stub that returns an error for any Rekor entry retrieval
	// This simulates the case where Rekor entries are required but not available
	return wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/log/entries/retrieve")).
		WillReturnResponse(wiremock.NewResponse().
			WithStatus(404).
			WithHeader("Content-Type", "application/json").
			WithBody(`{"message": "no entries found"}`))) // Error response
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^stub rekord running$`, stubRekordRunning)
	sc.Step(`^rekor entries are cleared$`, ClearRekorEntries)
	sc.Step(`^VSA upload to Rekor should be expected$`, expectVSAUploadToRekor)
	sc.Step(`^VSA should be uploaded to Rekor successfully$`, vsaShouldBeUploadedToRekor)
	sc.Step(`^VSA index search should return no results$`, stubVSAIndexSearch)
	sc.Step(`^VSA index search should return valid VSA$`, stubVSAIndexSearchWithResult)
}

// expectVSAUploadToRekor creates WireMock stubs to expect VSA upload requests to Rekor
func expectVSAUploadToRekor(ctx context.Context) error {
	// Create a stub that accepts any VSA upload request to /api/v1/log/entries
	// and returns a successful Rekor entry response using the same format as existing stubs
	entryUUID := "24296fb24b8ad77a12345678901234567890abcd"

	// Create a minimal valid base64 envelope for the response
	// This represents a basic in-toto attestation structure
	envelope := map[string]interface{}{
		"payload":     "eyJzdWJqZWN0IjpudWxsLCJwcmVkaWNhdGUiOnsidmVyaWZpZWRMZXZlbHMiOltdLCJkZXBlbmRlbmN5TGV2ZWxzIjp7fSwidGltZVZlcmlmaWVkIjoiMjAyNC0wMS0wMVQwMDowMDowMFoifX0=",
		"payloadType": "application/vnd.in-toto+json",
		"signatures": []map[string]string{
			{"sig": "MEUCIQDexample123456789", "keyid": ""},
		},
	}

	envelopeBytes, _ := json.Marshal(envelope)
	envelopeB64 := base64.StdEncoding.EncodeToString(envelopeBytes)

	response := map[string]interface{}{
		entryUUID: map[string]interface{}{
			"body":           envelopeB64,
			"integratedTime": 1674049693,
			"logID":          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
			"logIndex":       9876543,
			"verification": map[string]interface{}{
				"signedEntryTimestamp": "MEUCIQDexampleTimestamp123456789abcdefghijklmnopqrstuvwxyz==",
			},
		},
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal Rekor response: %w", err)
	}

	return wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/log/entries")).
		WillReturnResponse(wiremock.NewResponse().
			WithStatus(201).
			WithHeaders(map[string]string{
				"Content-Type": "application/json",
				"Location":     fmt.Sprintf("/api/v1/log/entries/%s", entryUUID),
			}).
			WithBody(string(responseBody))))
}

// vsaShouldBeUploadedToRekor verifies that VSA uploads to Rekor occurred successfully.
// This relies on WireMock's automatic verification - if VSA uploads didn't happen or
// didn't match our stub, WireMock will report unmatched requests/stubs in its After hook.
func vsaShouldBeUploadedToRekor(ctx context.Context) error {
	if !wiremock.IsRunning(ctx) {
		return fmt.Errorf("WireMock is not running - cannot verify VSA uploads")
	}

	// WireMock automatically verifies that our expectVSAUploadToRekor stub was matched
	// by actual VSA upload requests. No explicit verification needed here.
	return nil
}

// stubVSAIndexSearch creates WireMock stubs for VSA index search requests
// This handles the /api/v1/index/retrieve endpoint used by VSA expiration tests
func stubVSAIndexSearch(ctx context.Context) error {
	// Create a stub that returns an empty array for VSA index search requests
	// This simulates the case where no existing VSA records are found
	emptyResponse := []interface{}{}

	responseBody, err := json.Marshal(emptyResponse)
	if err != nil {
		return fmt.Errorf("failed to marshal empty VSA search response: %w", err)
	}

	return wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/index/retrieve")).
		WillReturnResponse(wiremock.NewResponse().
			WithStatus(200).
			WithHeaders(map[string]string{
				"Content-Type": "application/json",
			}).
			WithBody(string(responseBody))))
}

// stubVSAIndexSearchWithResult creates WireMock stubs for VSA index search requests that return a valid VSA
// This handles the /api/v1/index/retrieve endpoint for tests that expect to find existing VSAs
func stubVSAIndexSearchWithResult(ctx context.Context) error {
	// Create a stub that returns a valid VSA entry for VSA index search requests
	// This simulates the case where an existing VSA record is found
	vsaEntry := map[string]interface{}{
		"attestation": map[string]interface{}{
			"data": "eyJzdWJqZWN0IjpudWxsLCJwcmVkaWNhdGUiOnsidmVyaWZpZWRMZXZlbHMiOltdLCJkZXBlbmRlbmN5TGV2ZWxzIjp7fSwidGltZVZlcmlmaWVkIjoiMjAyNC0wMS0wMVQwMDowMDowMFoifX0=",
		},
		"integratedTime": time.Now().Unix(), // Recent timestamp (within 24h threshold)
		"logID":          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
		"logIndex":       9876543,
		"verification": map[string]interface{}{
			"signedEntryTimestamp": "MEUCIQDexampleTimestamp123456789abcdefghijklmnopqrstuvwxyz==",
		},
	}

	responseBody, err := json.Marshal([]interface{}{vsaEntry})
	if err != nil {
		return fmt.Errorf("failed to marshal VSA search response: %w", err)
	}

	return wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/index/retrieve")).
		WillReturnResponse(wiremock.NewResponse().
			WithStatus(200).
			WithHeaders(map[string]string{
				"Content-Type": "application/json",
			}).
			WithBody(string(responseBody))))
}
