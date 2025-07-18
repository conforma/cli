// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
package validate

import (
	"context"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/utils"
)

func TestGetPolicyConfig(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	fileName := "/tmp/policy.yaml"
	fileContent := "foo: bar"
	emptyFile := "/tmp/empty.yaml"
	err := afero.WriteFile(fs, fileName, []byte(fileContent), 0644)
	require.NoError(t, err)
	err = afero.WriteFile(fs, emptyFile, []byte{}, 0644)
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
		errMsg  string
	}{
		{"inline string", "{\"foo\": \"bar\"}", "{\"foo\": \"bar\"}", false, ""},
		{"file", fileName, fileContent, false, ""},
		{"empty file", emptyFile, "", true, "empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetPolicyConfig(ctx, tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestReadFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := utils.WithFS(context.Background(), fs)
	err := afero.WriteFile(fs, "/tmp/testfile.txt", []byte("hello world"), 0644)
	require.NoError(t, err)
	err = afero.WriteFile(fs, "/tmp/emptyfile.txt", []byte{}, 0644)
	require.NoError(t, err)

	tests := []struct {
		name    string
		file    string
		want    string
		wantErr bool
		errMsg  string
	}{
		{"valid file", "/tmp/testfile.txt", "hello world", false, ""},
		{"empty file", "/tmp/emptyfile.txt", "", true, "empty"},
		{"missing file", "/tmp/doesnotexist.txt", "", true, "file does not exist"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadFile(ctx, tt.file)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
