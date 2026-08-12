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

package rego

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHelloWorldRegoContent(t *testing.T) {
	// Test that the hello_world.rego file can be read and has expected content
	content, err := fs.ReadFile(EmbeddedRego, "ec_lib/hello_world.rego")
	require.NoError(t, err, "Should be able to read hello_world.rego")

	contentStr := string(content)
	assert.Contains(t, contentStr, "package ec_lib")
	assert.Contains(t, contentStr, "hello_world(name)")
	assert.Contains(t, contentStr, "from embedded rego")
}
