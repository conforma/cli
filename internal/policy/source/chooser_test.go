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

package source

import (
	"context"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/utils"
)

func TestChoosePolicyFile(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		want    string
		wantErr bool
		errText string
	}{
		{
			name:    "No files",
			files:   []string{},
			wantErr: true,
			errText: "no suitable config file found",
		},
		{
			name:  "One policy.json file",
			files: []string{"/policy.json"},
			want:  "/policy.json",
		},
		{
			name:  "One .ec/policy.yaml file",
			files: []string{"/.ec/policy.yaml"},
			want:  "/.ec/policy.yaml",
		},
		{
			name:  "Multiple files with basename precedence",
			files: []string{"/.ec/policy.yml", "/policy.yaml"},
			want:  "/.ec/policy.yml",
		},
		{
			name:  "Multiple files with extension precedence",
			files: []string{"/policy.yml", "/policy.yaml", "/policy.json"},
			want:  "/policy.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)

			for _, f := range tt.files {
				err := afero.WriteFile(fs, f, []byte(""), 0o644)
				assert.NoError(t, err)
			}

			ff, err := choosePolicyFile(ctx, "/")
			if tt.wantErr {
				assert.Equal(t, "", ff)
				assert.ErrorContains(t, err, tt.errText)
			} else {
				assert.Equal(t, tt.want, ff)
				assert.NoError(t, err)
			}
		})
	}
}
