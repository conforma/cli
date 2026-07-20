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

package asciidoc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveAbandonedPages(t *testing.T) {
	t.Run("removes stale generated file", func(t *testing.T) {
		module := t.TempDir()
		pagesDir := filepath.Join(module, "pages")
		require.NoError(t, os.MkdirAll(pagesDir, 0755))

		// Create a stale generated file (has marker but was not regenerated)
		stalePath := filepath.Join(pagesDir, "ec_old_command.adoc")
		require.NoError(t, os.WriteFile(stalePath, []byte(GeneratedMarker+"\n= ec old command\n"), 0600))

		// Create a current generated file
		currentPath := filepath.Join(pagesDir, "ec_current.adoc")
		require.NoError(t, os.WriteFile(currentPath, []byte(GeneratedMarker+"\n= ec current\n"), 0600))

		err := removeAbandonedPages(module, []string{currentPath})
		require.NoError(t, err)

		assert.NoFileExists(t, stalePath, "stale generated file should be removed")
		assert.FileExists(t, currentPath, "current generated file should be kept")
	})

	t.Run("keeps handwritten files", func(t *testing.T) {
		module := t.TempDir()
		pagesDir := filepath.Join(module, "pages")
		require.NoError(t, os.MkdirAll(pagesDir, 0755))

		// Create a handwritten file (no marker)
		handwrittenPath := filepath.Join(pagesDir, "index.adoc")
		require.NoError(t, os.WriteFile(handwrittenPath, []byte("= Conforma CLI\n\nSome handwritten content.\n"), 0600))

		err := removeAbandonedPages(module, []string{})
		require.NoError(t, err)

		assert.FileExists(t, handwrittenPath, "handwritten file should not be removed")
	})

	t.Run("keeps non-adoc files", func(t *testing.T) {
		module := t.TempDir()
		pagesDir := filepath.Join(module, "pages")
		require.NoError(t, os.MkdirAll(pagesDir, 0755))

		// Create a non-adoc file
		otherPath := filepath.Join(pagesDir, "notes.txt")
		require.NoError(t, os.WriteFile(otherPath, []byte("some notes"), 0600))

		err := removeAbandonedPages(module, []string{})
		require.NoError(t, err)

		assert.FileExists(t, otherPath, "non-adoc file should not be removed")
	})

	t.Run("mixed scenario", func(t *testing.T) {
		module := t.TempDir()
		pagesDir := filepath.Join(module, "pages")
		require.NoError(t, os.MkdirAll(pagesDir, 0755))

		// Handwritten file
		handwrittenPath := filepath.Join(pagesDir, "configuration.adoc")
		require.NoError(t, os.WriteFile(handwrittenPath, []byte("= Policy Configuration\n\nHandwritten docs.\n"), 0600))

		// Generated file that still exists
		currentGenPath := filepath.Join(pagesDir, "ec_validate.adoc")
		require.NoError(t, os.WriteFile(currentGenPath, []byte(GeneratedMarker+"\n= ec validate\n"), 0600))

		// Stale generated file (command was removed)
		stalePath := filepath.Join(pagesDir, "ec_removed_cmd.adoc")
		require.NoError(t, os.WriteFile(stalePath, []byte(GeneratedMarker+"\n= ec removed cmd\n"), 0600))

		// Another stale generated file
		stalePath2 := filepath.Join(pagesDir, "ec_old_builtin.adoc")
		require.NoError(t, os.WriteFile(stalePath2, []byte(GeneratedMarker+"\n= ec.old.builtin\n"), 0600))

		generated := []string{currentGenPath}
		err := removeAbandonedPages(module, generated)
		require.NoError(t, err)

		assert.FileExists(t, handwrittenPath, "handwritten file should be kept")
		assert.FileExists(t, currentGenPath, "current generated file should be kept")
		assert.NoFileExists(t, stalePath, "stale generated file should be removed")
		assert.NoFileExists(t, stalePath2, "stale generated file should be removed")
	})

	t.Run("empty pages directory", func(t *testing.T) {
		module := t.TempDir()
		pagesDir := filepath.Join(module, "pages")
		require.NoError(t, os.MkdirAll(pagesDir, 0755))

		err := removeAbandonedPages(module, []string{})
		require.NoError(t, err)
	})

	t.Run("returns error for non-existent directory", func(t *testing.T) {
		module := filepath.Join(t.TempDir(), "nonexistent")

		err := removeAbandonedPages(module, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading pages directory")
	})
}

func TestHasGeneratedMarker(t *testing.T) {
	t.Run("file with marker", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.adoc")
		require.NoError(t, os.WriteFile(path, []byte(GeneratedMarker+"\n= Some Title\n"), 0600))

		result, err := hasGeneratedMarker(path)
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("file without marker", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.adoc")
		require.NoError(t, os.WriteFile(path, []byte("= Some Title\n\nHandwritten content.\n"), 0600))

		result, err := hasGeneratedMarker(path)
		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.adoc")
		require.NoError(t, os.WriteFile(path, []byte(""), 0600))

		result, err := hasGeneratedMarker(path)
		require.NoError(t, err)
		assert.False(t, result)
	})
}
