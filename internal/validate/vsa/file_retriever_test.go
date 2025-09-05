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
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileVSARetriever(t *testing.T) {
	fs := afero.NewMemMapFs()

	t.Run("successfully reads VSA records from file", func(t *testing.T) {
		// Create test VSA records
		testRecords := []VSARecord{
			{
				LogIndex:       1,
				LogID:          "test-log-id-1",
				IntegratedTime: 1234567890,
				Body:           "test-body-1",
			},
			{
				LogIndex:       2,
				LogID:          "test-log-id-2",
				IntegratedTime: 1234567891,
				Body:           "test-body-2",
			},
		}

		// Write test data to file
		data, err := json.Marshal(testRecords)
		require.NoError(t, err)
		err = afero.WriteFile(fs, "/test-vsa.json", data, 0644)
		require.NoError(t, err)

		// Create retriever and test
		retriever := NewFileVSARetriever(fs)
		records, err := retriever.RetrieveVSA(context.Background(), "/test-vsa.json")

		assert.NoError(t, err)
		assert.Len(t, records, 2)
		assert.Equal(t, testRecords[0].LogIndex, records[0].LogIndex)
		assert.Equal(t, testRecords[0].LogID, records[0].LogID)
		assert.Equal(t, testRecords[1].LogIndex, records[1].LogIndex)
		assert.Equal(t, testRecords[1].LogID, records[1].LogID)
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		retriever := NewFileVSARetriever(fs)
		records, err := retriever.RetrieveVSA(context.Background(), "/nonexistent.json")

		assert.Error(t, err)
		assert.Nil(t, records)
		assert.Contains(t, err.Error(), "failed to read VSA file")
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		// Write invalid JSON to file
		err := afero.WriteFile(fs, "/invalid.json", []byte("invalid json"), 0644)
		require.NoError(t, err)

		retriever := NewFileVSARetriever(fs)
		records, err := retriever.RetrieveVSA(context.Background(), "/invalid.json")

		assert.Error(t, err)
		assert.Nil(t, records)
		assert.Contains(t, err.Error(), "failed to parse VSA file")
	})
}
