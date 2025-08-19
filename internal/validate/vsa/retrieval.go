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
	"time"

	"github.com/sigstore/rekor/pkg/generated/models"
)

// VSARetriever defines the interface for retrieving VSA records from Rekor
type VSARetriever interface {
	// RetrieveVSA retrieves VSA records for a given image digest
	RetrieveVSA(ctx context.Context, imageDigest string) ([]VSARecord, error)
	// FindByPayloadHash retrieves dual entries by payload hash
	FindByPayloadHash(ctx context.Context, payloadHashHex string) (*DualEntryPair, error)
	// GetPairedVSAWithSignatures retrieves a VSA with its corresponding signatures by payloadHash
	// This ensures the signatures actually correspond to the VSA Statement being evaluated
	GetPairedVSAWithSignatures(ctx context.Context, payloadHashHex string) (*PairedVSAWithSignatures, error)
	// FindLatestMatchingPair finds the latest pair where intoto has attestation and DSSE matches
	FindLatestMatchingPair(ctx context.Context, entries []models.LogEntryAnon) *DualEntryPair
}

// VSARecord represents a VSA record retrieved from Rekor
type VSARecord struct {
	LogIndex       int64                            `json:"logIndex"`
	LogID          string                           `json:"logID"`
	IntegratedTime int64                            `json:"integratedTime"`
	UUID           string                           `json:"uuid"`
	Body           string                           `json:"body"`
	Attestation    *models.LogEntryAnonAttestation  `json:"attestation,omitempty"`
	Verification   *models.LogEntryAnonVerification `json:"verification,omitempty"`
}

// DualEntryPair represents a pair of DSSE and in-toto entries for the same payload
type DualEntryPair struct {
	PayloadHash string
	IntotoEntry *models.LogEntryAnon
	DSSEEntry   *models.LogEntryAnon
}

// PairedVSAWithSignatures represents a VSA with its corresponding signatures
// This ensures the signatures actually correspond to the VSA Statement being evaluated
type PairedVSAWithSignatures struct {
	PayloadHash   string                   `json:"payloadHash"`
	VSAStatement  []byte                   `json:"vsaStatement"`
	Signatures    []map[string]interface{} `json:"signatures"`
	IntotoEntry   *models.LogEntryAnon     `json:"intotoEntry"`
	DSSEEntry     *models.LogEntryAnon     `json:"dsseEntry"`
	PredicateType string                   `json:"predicateType"`
}

// RetrievalOptions configures VSA retrieval behavior
type RetrievalOptions struct {
	URL     string
	Timeout time.Duration
}

// DefaultRetrievalOptions returns default options for VSA retrieval
func DefaultRetrievalOptions() RetrievalOptions {
	return RetrievalOptions{
		URL:     "https://rekor.sigstore.dev",
		Timeout: 30 * time.Second,
	}
}
