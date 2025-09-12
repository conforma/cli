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
	"encoding/json"
	"fmt"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/afero"
)

// FileVSARetriever removed - no longer used by current implementation

// FileVSADataRetriever implements VSADataRetriever for file-based VSA files
type FileVSADataRetriever struct {
	fs      afero.Fs
	vsaPath string
}

// NewFileVSADataRetriever creates a new file-based VSA data retriever
func NewFileVSADataRetriever(fs afero.Fs, vsaPath string) *FileVSADataRetriever {
	return &FileVSADataRetriever{
		fs:      fs,
		vsaPath: vsaPath,
	}
}

// RetrieveVSA reads and returns VSA data as a DSSE envelope
func (f *FileVSADataRetriever) RetrieveVSA(ctx context.Context, imageDigest string) (*ssldsse.Envelope, error) {
	// Validate file path
	if f.vsaPath == "" {
		return nil, fmt.Errorf("failed to read VSA file: file path is empty")
	}

	// Read VSA file
	data, err := afero.ReadFile(f.fs, f.vsaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read VSA file: %w", err)
	}

	// Try to parse as DSSE envelope first
	var envelope ssldsse.Envelope
	if err := json.Unmarshal(data, &envelope); err == nil {
		// Successfully parsed as DSSE envelope
		// Check if the envelope has valid DSSE fields
		if envelope.PayloadType != "" && envelope.Payload != "" {
			return &envelope, nil
		}
		// If it parsed but doesn't have valid DSSE fields, treat as raw content
	}

	// If not a DSSE envelope, wrap the content in a DSSE envelope
	// Base64 encode the payload as expected by DSSE format
	payload := base64.StdEncoding.EncodeToString(data)
	envelope = ssldsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     payload,
		Signatures:  []ssldsse.Signature{},
	}

	return &envelope, nil
}
