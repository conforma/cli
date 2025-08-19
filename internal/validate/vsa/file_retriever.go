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
	"encoding/json"
	"fmt"

	"github.com/spf13/afero"
)

// FileVSARetriever implements VSARetriever for file-based VSA records
type FileVSARetriever struct {
	fs afero.Fs
}

// NewFileVSARetriever creates a new file-based VSA retriever
func NewFileVSARetriever(fs afero.Fs) *FileVSARetriever {
	return &FileVSARetriever{fs: fs}
}

// RetrieveVSA reads VSA records from a file
func (f *FileVSARetriever) RetrieveVSA(ctx context.Context, vsaPath string) ([]VSARecord, error) {
	data, err := afero.ReadFile(f.fs, vsaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read VSA file: %w", err)
	}

	var records []VSARecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("failed to parse VSA file: %w", err)
	}

	return records, nil
}

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

// RetrieveVSAData reads and parses a VSA file
func (f *FileVSADataRetriever) RetrieveVSAData(ctx context.Context) (*VSAFile, error) {
	// Read and parse VSA file
	data, err := afero.ReadFile(f.fs, f.vsaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read VSA file: %w", err)
	}

	var vsaFile VSAFile
	if err := json.Unmarshal(data, &vsaFile); err != nil {
		return nil, fmt.Errorf("failed to parse VSA file: %w", err)
	}

	return &vsaFile, nil
}
