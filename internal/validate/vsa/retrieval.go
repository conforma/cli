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
