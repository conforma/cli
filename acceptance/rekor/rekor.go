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
	intoto "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/conforma/cli/acceptance/crypto"
	"github.com/conforma/cli/acceptance/image"
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

// randomHex generates a random hex string of the given length
func randomHex(len int) string {
	b := make([]byte, len/2)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}

// computeLogID returns a hex-encoded SHA-256 digest of the
// SubjectPublicKeyInfo ASN.1 structure for the given
// PEM-encoded public key
func computeLogID(publicKey []byte) (string, error) {
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

// computeLogEntry constructs a Rekor log entry and provides it's UUID
// for the provided public key and data
func computeLogEntry(ctx context.Context, publicKey, data []byte) (logEntry *models.LogEntryAnon, entryUUID []byte, err error) {
	// the body of the log entry is an in-toto payload
	logBody := intoto.NewEntry()

	algorithm := models.IntotoV001SchemaContentPayloadHashAlgorithmSha256

	// the contentHash should relate to other entries but since we're faking a single
	// entry, not related to other entries -- any random contentHash-like hex will be
	// okay. Similarly, for testing purposes, any payload hash will do.
	hash := randomHex(64)

	publicKeyBase64 := strfmt.Base64(publicKey)

	// the only way to set fields of the intoto Entry
	err = logBody.Unmarshal(&models.Intoto{
		Spec: models.IntotoV001Schema{
			Content: &models.IntotoV001SchemaContent{
				Hash: &models.IntotoV001SchemaContentHash{
					Algorithm: &algorithm,
					Value:     &hash,
				},
				PayloadHash: &models.IntotoV001SchemaContentPayloadHash{
					Algorithm: &algorithm,
					Value:     &hash,
				},
			},
			PublicKey: &publicKeyBase64,
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
	time := int64(0)
	logID, err := computeLogID(publicKey)
	if err != nil {
		return nil, nil, err
	}

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

// computeEntryTimestamp signs Rekor log entryies body, integrated timestam,
// log index and log ID with the provided private key encrypted by the given
// password
func computeEntryTimestamp(privateKey, password []byte, logEntry models.LogEntryAnon) ([]byte, error) {
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

// stubRekorEntryFor instructs WireMock to return a bespoke Rekor log entry
// for the given bytes, the entry is timestamped using the key stored in
// state.KeyPair and a fake Merkle tree is created with an empty root
// and this entries' hash
func stubRekorEntryFor(ctx context.Context, data []byte, fn jsonPathExtractor) error {
	state := testenv.FetchState[rekorState](ctx)

	logEntry, entryUUID, err := computeLogEntry(ctx, state.KeyPair.PublicBytes, data)
	if err != nil {
		return err
	}

	set, err := computeEntryTimestamp(state.KeyPair.PrivateBytes, state.KeyPair.Password(), *logEntry)
	if err != nil {
		return err
	}

	// this is what will be returned, albeit in an array
	var logEntries models.LogEntry = models.LogEntry{}
	entryID := hex.EncodeToString(entryUUID)
	logEntries[entryID] = *logEntry

	logEntry.Verification.SignedEntryTimestamp = strfmt.Base64(set)

	// the response is in application/json
	body, err := json.Marshal([]models.LogEntry{logEntries})
	if err != nil {
		return err
	}

	jsonPath, err := fn(data)
	if err != nil {
		return fmt.Errorf("failed to extract JSON path: %w", err)
	}

	// return this entry for any lookup in Rekor
	return wiremock.StubFor(ctx, wiremock.Post(wiremock.URLPathEqualTo("/api/v1/log/entries/retrieve")).
		WithBodyPattern(wiremock.MatchingJsonPath(jsonPath)).
		WillReturnResponse(wiremock.NewResponse().WithBody(string(body)).WithHeaders(
			map[string]string{"Content-Type": "application/json"},
		).WithStatus(200)))
}

type jsonPathExtractor func([]byte) (string, error)

// jsonPathFromSignature returns the JSON Path expression to be used in the wiremock stub
// for a signature query. The expression matches the value of the signature's content.
func jsonPathFromSignature(data []byte) (string, error) {
	signature := cosign.Signatures{}
	if err := json.Unmarshal(data, &signature); err != nil {
		return "", fmt.Errorf("unmarshalling signature: %w", err)
	}

	if signature.Sig == "" {
		return "", fmt.Errorf("data missing 'sig' key: %s", data)
	}

	return fmt.Sprintf("$..[?(@.content=='%s')]", signature.Sig), nil
}

// jsonPathFromSignature returns the JSON Path expression to be used in the wiremock stub
// for an attestaion query. The expression matches the value of the attestation's digest.
func jsonPathFromAttestation(data []byte) (string, error) {
	return fmt.Sprintf("$..[?(@.value=='%x')]", sha256.Sum256(data)), nil
}

// RekorEntryForAttestation given an image name for which attestation has been
// previously performed via image.createAndPushAttestation, creates stub for a
// mostly empty attestation log entry in Rekor
func RekorEntryForAttestation(ctx context.Context, imageName string) error {
	attestation, err := image.AttestationFrom(ctx, imageName)
	if err != nil {
		return err
	}

	return stubRekorEntryFor(ctx, attestation, jsonPathFromAttestation)
}

// RekorEntryForImageSignature given an image name for which signature has been
// previously performed via image.createAndPushImageSignature, creates stub
// log entry in Rekor
func RekorEntryForImageSignature(ctx context.Context, imageName string) error {
	signature, err := image.ImageSignatureFrom(ctx, imageName)
	if err != nil {
		return err
	}

	return stubRekorEntryFor(ctx, signature, jsonPathFromSignature)
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

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^stub rekord running$`, stubRekordRunning)
	sc.Step(`^a valid Rekor entry for attestation of "([^"]*)"$`, RekorEntryForAttestation)
	sc.Step(`^a valid Rekor entry for image signature of "([^"]*)"$`, RekorEntryForImageSignature)
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
