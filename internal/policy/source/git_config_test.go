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
	"errors"
	"path"
	"testing"

	fileMetadata "github.com/conforma/go-gather/gather/file"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/utils"
)

func TestSourceIsFile(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected bool
	}{
		// File path scenarios
		{
			name:     "absolute file path is detected as file",
			src:      "/file/path/to/foo/policy.yaml",
			expected: true,
		},
		{
			name:     "relative file path is detected as file",
			src:      "../../file/path/to/foo/policy.yaml",
			expected: true,
		},
		{
			name:     "current directory file is detected as file",
			src:      "./config.yaml",
			expected: true,
		},

		// URL scenarios that should not be files
		{
			name:     "https url is not detected as file",
			src:      "https://foo.bar/asdf",
			expected: false,
		},
		{
			name:     "git protocol url is not detected as file",
			src:      "git::https://foo.bar/asdf",
			expected: false,
		},
		{
			name:     "github repository is not detected as file",
			src:      "github.com/foo/bar",
			expected: false,
		},
		{
			name:     "gitlab repository is not detected as file",
			src:      "gitlab.com/foo/bar",
			expected: false,
		},
		{
			name:     "raw github url is not detected as file",
			src:      "https://raw.githubusercontent.com/foo/bar",
			expected: false,
		},
		{
			name:     "s3 protocol url is not detected as file",
			src:      "s3::github.com/foo/bar",
			expected: false,
		},

		// Edge cases
		{
			name:     "empty string is not detected as file",
			src:      "",
			expected: false,
		},
		{
			name:     "simple name is not detected as file",
			src:      "foo",
			expected: false,
		},
		{
			name:     "git repository with git protocol is not detected as file",
			src:      "git::github.com/foo/bar",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SourceIsFile(tt.src)
			assert.Equal(t, tt.expected, result,
				"SourceIsFile(%q) = %v, expected %v", tt.src, result, tt.expected)
		})
	}
}

func TestSourceIsGit(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected bool
	}{
		// Git URLs that should be detected
		{
			name:     "git protocol with https url is detected as git",
			src:      "git::https://foo.bar/asdf",
			expected: true,
		},
		{
			name:     "git protocol with github repository is detected as git",
			src:      "git::github.com/foo/bar",
			expected: true,
		},
		{
			name:     "github repository path is detected as git",
			src:      "github.com/foo/bar",
			expected: true,
		},
		{
			name:     "gitlab repository path is detected as git",
			src:      "gitlab.com/foo/bar",
			expected: true,
		},
		{
			name:     "bitbucket repository path is detected as git",
			src:      "bitbucket.org/user/repo",
			expected: true,
		},
		{
			name:     "git ssh url is detected as git",
			src:      "git@github.com:user/repo.git",
			expected: true,
		},

		// Non-Git URLs that should not be detected
		{
			name:     "https raw url is not detected as git",
			src:      "https://raw.githubusercontent.com/foo/bar",
			expected: false,
		},
		{
			name:     "s3 protocol url is not detected as git",
			src:      "s3::github.com/foo/bar",
			expected: false,
		},
		{
			name:     "https regular url is not detected as git",
			src:      "https://example.com/file.yaml",
			expected: false,
		},

		// Edge cases
		{
			name:     "empty string is not detected as git",
			src:      "",
			expected: false,
		},
		{
			name:     "simple name is not detected as git",
			src:      "foo",
			expected: false,
		},
		{
			name:     "domain without repository path is not detected as git",
			src:      "foo.bar/asdf",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SourceIsGit(tt.src)
			assert.Equal(t, tt.expected, result,
				"SourceIsGit(%q) = %v, expected %v", tt.src, result, tt.expected)
		})
	}
}

func TestSourceIsHttp(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected bool
	}{
		// HTTP/HTTPS URLs that should be detected
		{
			name:     "https url is detected as http",
			src:      "https://raw.githubusercontent.com/foo/bar",
			expected: true,
		},
		{
			name:     "http url is detected as http",
			src:      "http://example.com/file.yaml",
			expected: true,
		},
		{
			name:     "https with simple path is detected as http",
			src:      "https://example.com/config.yaml",
			expected: true,
		},

		// Non-HTTP URLs that should not be detected
		{
			name:     "git protocol url is not detected as http",
			src:      "git::https://foo.bar/asdf",
			expected: false,
		},
		{
			name:     "git repository without protocol is not detected as http",
			src:      "git::github.com/foo/bar",
			expected: false,
		},
		{
			name:     "github repository path is not detected as http",
			src:      "github.com/foo/bar",
			expected: false,
		},
		{
			name:     "gitlab repository path is not detected as http",
			src:      "gitlab.com/foo/bar",
			expected: false,
		},
		{
			name:     "s3 protocol url is not detected as http",
			src:      "s3::github.com/foo/bar",
			expected: false,
		},
		{
			name:     "raw github without protocol is not detected as http",
			src:      "raw.githubusercontent.com/foo/bar",
			expected: false,
		},

		// Edge cases
		{
			name:     "empty string is not detected as http",
			src:      "",
			expected: false,
		},
		{
			name:     "simple name is not detected as http",
			src:      "foo",
			expected: false,
		},
		{
			name:     "domain without protocol is not detected as http",
			src:      "foo.bar/asdf",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SourceIsHttp(tt.src)
			assert.Equal(t, tt.expected, result,
				"SourceIsHttp(%q) = %v, expected %v", tt.src, result, tt.expected)
		})
	}
}

func TestGoGetterDownload(t *testing.T) {
	tests := []struct {
		name           string
		src            string
		tmpDir         string
		setupFS        func(fs afero.Fs, destDir string) error
		mockDownloader func(*mockDownloader, string)
		expectError    bool
		errorMsg       string
	}{
		{
			name:   "successful download with policy.yaml file",
			src:    "https://github.com/example/policy",
			tmpDir: "/tmp/test",
			setupFS: func(fs afero.Fs, destDir string) error {
				// Create the downloaded directory structure
				if err := fs.MkdirAll(destDir, 0o755); err != nil {
					return err
				}
				// Create a policy.yaml file that choosePolicyFile can find
				return afero.WriteFile(fs, path.Join(destDir, "policy.yaml"), []byte("test config"), 0o644)
			},
			mockDownloader: func(m *mockDownloader, destDir string) {
				// Mock successful download
				m.On("Download", mock.Anything, destDir, "https://github.com/example/policy", false).
					Return(&fileMetadata.FSMetadata{Path: destDir}, nil)
			},
			expectError: false,
		},
		{
			name:   "successful download with .ec/policy.json file",
			src:    "https://github.com/example/policy2",
			tmpDir: "/tmp/test2",
			setupFS: func(fs afero.Fs, destDir string) error {
				if err := fs.MkdirAll(destDir, 0o755); err != nil {
					return err
				}
				// Create .ec/policy.json file (higher priority)
				return afero.WriteFile(fs, path.Join(destDir, ".ec/policy.json"), []byte(`{"policy": "config"}`), 0o644)
			},
			mockDownloader: func(m *mockDownloader, destDir string) {
				m.On("Download", mock.Anything, destDir, "https://github.com/example/policy2", false).
					Return(&fileMetadata.FSMetadata{Path: destDir}, nil)
			},
			expectError: false,
		},
		{
			name:   "download failure",
			src:    "https://github.com/example/nonexistent",
			tmpDir: "/tmp/test3",
			setupFS: func(fs afero.Fs, destDir string) error {
				// No filesystem setup needed for download failure
				return nil
			},
			mockDownloader: func(m *mockDownloader, destDir string) {
				m.On("Download", mock.Anything, destDir, "https://github.com/example/nonexistent", false).
					Return(nil, errors.New("failed to download: repository not found"))
			},
			expectError: true,
			errorMsg:    "failed to download: repository not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock filesystem
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)

			// Calculate the expected destination directory using the same logic as the function
			destDir := path.Join(tt.tmpDir, "config", uniqueDir(tt.src))

			// Set up filesystem state
			if tt.setupFS != nil {
				err := tt.setupFS(fs, destDir)
				require.NoError(t, err, "failed to setup filesystem")
			}

			// Create and configure mock downloader
			mockDownloader := &mockDownloader{}
			if tt.mockDownloader != nil {
				tt.mockDownloader(mockDownloader, destDir)
			}
			ctx = usingDownloader(ctx, mockDownloader)

			// Clear download cache to ensure fresh test
			ClearDownloadCache()

			result, err := GoGetterDownload(ctx, tt.tmpDir, tt.src)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}

			require.NoError(t, err)
			// The result should be a policy file within the destDir
			assert.Contains(t, result, destDir, "result should be within the destination directory")

			// Verify the file exists and is readable
			exists, err := afero.Exists(fs, result)
			require.NoError(t, err)
			assert.True(t, exists, "result file should exist")

			// Verify it's actually a file, not a directory
			stat, err := fs.Stat(result)
			require.NoError(t, err)
			assert.False(t, stat.IsDir(), "result should be a file, not a directory")

			// Verify all mock expectations were met
			mockDownloader.AssertExpectations(t)
		})
	}
}
