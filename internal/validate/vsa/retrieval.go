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

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// VSARetriever defines the interface for retrieving VSA records from various sources
type VSARetriever interface {
	// RetrieveVSA retrieves VSA data as a DSSE envelope for a given image digest
	// This is the main method used by validation functions to get VSA data for signature verification
	RetrieveVSA(ctx context.Context, imageDigest string) (*ssldsse.Envelope, error)
}

// RetrievalOptions configures VSA retrieval behavior
type RetrievalOptions struct {
	URL     string
	Timeout time.Duration
}

// DefaultRetrievalOptions returns default options for VSA retrieval
func DefaultRetrievalOptions() RetrievalOptions {
	return RetrievalOptions{
		URL:     "https://rekor-server-trusted-artifact-signer.apps.rosa.rekor-stage.ic5w.p3.openshiftapps.com",
		Timeout: 30 * time.Second,
	}
}
