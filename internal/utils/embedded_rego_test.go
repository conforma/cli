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
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteEmbeddedRego(t *testing.T) {
	// Test that embedded rego files are written correctly to filesystem
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	// Create a temporary policy directory
	policyDir := "/tmp/policy"
	err := fs.MkdirAll(policyDir, 0o755)
	require.NoError(t, err)

	// Call WriteEmbeddedRego
	err = WriteEmbeddedRego(ctx, fs, policyDir)
	require.NoError(t, err, "WriteEmbeddedRego should succeed")

	// Verify embedded directory was created
	embeddedDir := filepath.Join(policyDir, "embedded")
	exists, err := afero.DirExists(fs, embeddedDir)
	require.NoError(t, err)
	assert.True(t, exists, "embedded directory should be created")

	// Verify hello_world.rego file was written
	helloWorldPath := filepath.Join(embeddedDir, "ec_lib", "hello_world.rego")
	exists, err = afero.Exists(fs, helloWorldPath)
	require.NoError(t, err)
	assert.True(t, exists, "hello_world.rego should be written")

	// Verify file content is correct
	content, err := afero.ReadFile(fs, helloWorldPath)
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, "package ec_lib")
	assert.Contains(t, contentStr, "hello_world(name)")
	assert.Contains(t, contentStr, "from embedded rego")
}

func TestWriteEmbeddedRegoMaintainsDirectoryStructure(t *testing.T) {
	// Test that directory structure from embedded files is maintained
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	policyDir := "/tmp/policy"
	err := fs.MkdirAll(policyDir, 0o755)
	require.NoError(t, err)

	err = WriteEmbeddedRego(ctx, fs, policyDir)
	require.NoError(t, err)

	// Verify the full directory structure: policy/embedded/ec_lib/hello_world.rego
	expectedPath := filepath.Join(policyDir, "embedded", "ec_lib", "hello_world.rego")
	exists, err := afero.Exists(fs, expectedPath)
	require.NoError(t, err)
	assert.True(t, exists, "Full directory structure should be maintained")

	// Verify ec_lib directory exists
	ecLibDir := filepath.Join(policyDir, "embedded", "ec_lib")
	exists, err = afero.DirExists(fs, ecLibDir)
	require.NoError(t, err)
	assert.True(t, exists, "ec_lib subdirectory should be created")
}

func TestWriteEmbeddedRegoFilePermissions(t *testing.T) {
	// Test that files are written with correct permissions
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	policyDir := "/tmp/policy"
	err := fs.MkdirAll(policyDir, 0o755)
	require.NoError(t, err)

	err = WriteEmbeddedRego(ctx, fs, policyDir)
	require.NoError(t, err)

	// Check file permissions
	helloWorldPath := filepath.Join(policyDir, "embedded", "ec_lib", "hello_world.rego")
	info, err := fs.Stat(helloWorldPath)
	require.NoError(t, err)

	// Should be readable and writable by owner, readable by group and others
	assert.Equal(t, "-rw-r--r--", info.Mode().String())
}

func TestWriteEmbeddedRegoNonExistentPolicyDir(t *testing.T) {
	// Test behavior when policy directory doesn't exist
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	// Don't create the policy directory
	policyDir := "/tmp/nonexistent/policy"

	// WriteEmbeddedRego should create necessary directories
	err := WriteEmbeddedRego(ctx, fs, policyDir)
	require.NoError(t, err, "Should create necessary directories")

	// Verify the embedded directory was created
	embeddedDir := filepath.Join(policyDir, "embedded")
	exists, err := afero.DirExists(fs, embeddedDir)
	require.NoError(t, err)
	assert.True(t, exists, "Should create embedded directory and parents")
}

func TestWriteEmbeddedRegoIdempotent(t *testing.T) {
	// Test that calling WriteEmbeddedRego multiple times is safe
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	policyDir := "/tmp/policy"
	err := fs.MkdirAll(policyDir, 0o755)
	require.NoError(t, err)

	// Call WriteEmbeddedRego twice
	err = WriteEmbeddedRego(ctx, fs, policyDir)
	require.NoError(t, err, "First call should succeed")

	err = WriteEmbeddedRego(ctx, fs, policyDir)
	require.NoError(t, err, "Second call should succeed (idempotent)")

	// Verify file still exists and has correct content
	helloWorldPath := filepath.Join(policyDir, "embedded", "ec_lib", "hello_world.rego")
	content, err := afero.ReadFile(fs, helloWorldPath)
	require.NoError(t, err)

	contentStr := string(content)
	assert.Contains(t, contentStr, "package ec_lib")
	assert.Contains(t, contentStr, "hello_world(name)")
}
