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

//go:build unit

package timeutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVolatileTime(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectTime  time.Time
	}{
		{
			name:        "valid RFC3339",
			input:       "2025-08-18T12:00:00Z",
			expectError: false,
			expectTime:  time.Date(2025, 8, 18, 12, 0, 0, 0, time.UTC),
		},
		{
			name:        "valid date-only falls back to YYYY-MM-DD",
			input:       "2025-08-18",
			expectError: false,
			expectTime:  time.Date(2025, 8, 18, 0, 0, 0, 0, time.UTC),
		},
		{
			name:        "garbage string returns error",
			input:       "not-a-date",
			expectError: true,
		},
		{
			name:        "empty string returns error",
			input:       "",
			expectError: true,
		},
		{
			name:        "partial date returns error",
			input:       "2025-08",
			expectError: true,
		},
		{
			name:        "RFC3339 with offset",
			input:       "2025-08-18T12:00:00+02:00",
			expectError: false,
			expectTime:  time.Date(2025, 8, 18, 10, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseVolatileTime(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.True(t, tt.expectTime.Equal(result), "expected %v, got %v", tt.expectTime, result)
			}
		})
	}
}
