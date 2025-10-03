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

package utils

import (
	"context"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestCreateWorkDir(t *testing.T) {
	temp, err := CreateWorkDir(afero.NewMemMapFs())

	assert.NoError(t, err)
	assert.Regexpf(t, `.*ec-work-\d+`, temp, "Did not expect temp directory at: %s", temp)
}

func TestWriteTempFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	data := "file contents"
	ctx := WithFS(context.Background(), fs)
	path, err := WriteTempFile(ctx, data, "ec")
	assert.NoError(t, err)
	contents, err := afero.ReadFile(fs, path)
	assert.NoError(t, err)
	assert.Equal(t, data, string(contents))
}

func TestIsJson(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "valid JSON",
			data: `{"name": "ec"}`,
			want: true,
		},
		{
			name: "invalid JSON",
			data: `{"name": "ec"`,
			want: false,
		},
		{
			name: "empty string",
			data: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsJson(tt.data)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsYamlMap(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "valid YAML",
			data: `name: ec`,
			want: true,
		},
		{
			name: "invalid YAML",
			data: `name: ec\nblah:`,
			want: false,
		},
		{
			name: "empty string",
			data: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsYamlMap(tt.data)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	ctx := WithFS(context.Background(), fs)

	testFilePath := "/test-file.txt"
	err := afero.WriteFile(fs, testFilePath, []byte("test"), 0644)
	assert.NoError(t, err)

	isFile, err := IsFile(ctx, testFilePath)
	assert.True(t, isFile)
	assert.Nil(t, err)

	isFile, err = IsFile(context.Background(), "/non-existent-file.txt")
	assert.False(t, isFile)
	assert.Nil(t, err)
}

func TestHasJsonOrYamlExt(t *testing.T) {
	tests := []struct {
		src  string
		want bool
	}{
		{src: "foo.json", want: true},
		{src: "foo.yml", want: true},
		{src: "foo.bson", want: false},
		{src: "foo", want: false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, HasJsonOrYamlExt(tt.src))
	}
}
