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
	"fmt"

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

// RetrieveVSAData reads and returns VSA data as a string
func (f *FileVSADataRetriever) RetrieveVSAData(ctx context.Context) (string, error) {
	// Validate file path
	if f.vsaPath == "" {
		return "", fmt.Errorf("failed to read VSA file: file path is empty")
	}

	// Read VSA file
	data, err := afero.ReadFile(f.fs, f.vsaPath)
	if err != nil {
		return "", fmt.Errorf("failed to read VSA file: %w", err)
	}

	return string(data), nil
}
