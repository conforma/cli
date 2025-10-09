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

package vsa

import (
	"fmt"
)

// CreateVSARetriever creates the VSA retriever based on flags and identifier type
func CreateVSARetriever(vsaRetrieval []string, vsaIdentifier string, images string) (VSARetriever, error) {
	// If explicit retrieval backends are specified, use VSA library
	if len(vsaRetrieval) > 0 {
		retriever := CreateRetrieverFromUploadFlags(vsaRetrieval)
		if retriever == nil {
			return nil, fmt.Errorf("no valid retriever found from flags: %v", vsaRetrieval)
		}
		return retriever, nil
	}

	// Auto-detect retriever based on identifier type
	if vsaIdentifier != "" {
		identifierType := DetectIdentifierType(vsaIdentifier)
		switch identifierType {
		case IdentifierFile:
			return NewFileVSARetrieverWithOSFs("."), nil
		case IdentifierImageDigest, IdentifierImageReference:
			// Use VSA library to create Rekor retriever for image-based identifiers
			retriever := CreateRetrieverFromUploadFlags([]string{"rekor"})
			if retriever == nil {
				return nil, fmt.Errorf("failed to create Rekor retriever")
			}
			return retriever, nil
		default:
			return nil, fmt.Errorf("unsupported identifier type for VSA: %s", vsaIdentifier)
		}
	}

	// For snapshot validation, always use Rekor retriever
	if images != "" {
		retriever := CreateRetrieverFromUploadFlags([]string{"rekor"})
		if retriever == nil {
			return nil, fmt.Errorf("failed to create Rekor retriever")
		}
		return retriever, nil
	}

	// Default to file retriever for backward compatibility
	return NewFileVSARetrieverWithOSFs("."), nil
}
