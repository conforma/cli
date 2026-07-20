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

package evaluator

import (
	"errors"
	"fmt"
	dbg "runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsRegoCompilationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "rego_type_error",
			err:      errors.New("rego_type_error: undefined function opa.runtime"),
			expected: true,
		},
		{
			name:     "rego_parse_error",
			err:      errors.New("rego_parse_error: unexpected token"),
			expected: true,
		},
		{
			name:     "rego_type_error in longer message",
			err:      fmt.Errorf("3 errors occurred: /tmp/main.rego:14: rego_type_error: undefined function opa.runtime"),
			expected: true,
		},
		{
			name:     "rego_compile_error",
			err:      errors.New("rego_compile_error: some compile error"),
			expected: true,
		},
		{
			name:     "non-rego error",
			err:      errors.New("file not found"),
			expected: false,
		},
		{
			name:     "empty error",
			err:      errors.New(""),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isRegoCompilationError(tt.err))
		})
	}
}

func TestBundledOPAVersion(t *testing.T) {
	t.Run("returns version from build info", func(t *testing.T) {
		original := readBuildInfo
		t.Cleanup(func() { readBuildInfo = original })

		readBuildInfo = func() (*dbg.BuildInfo, bool) {
			return &dbg.BuildInfo{
				Deps: []*dbg.Module{
					{Path: "github.com/open-policy-agent/opa", Version: "v1.15.2"},
					{Path: "github.com/other/dep", Version: "v2.0.0"},
				},
			}, true
		}

		assert.Equal(t, "v1.15.2", bundledOPAVersion())
	})

	t.Run("returns unknown when build info unavailable", func(t *testing.T) {
		original := readBuildInfo
		t.Cleanup(func() { readBuildInfo = original })

		readBuildInfo = func() (*dbg.BuildInfo, bool) {
			return nil, false
		}

		assert.Equal(t, "unknown", bundledOPAVersion())
	})

	t.Run("returns unknown when OPA not in deps", func(t *testing.T) {
		original := readBuildInfo
		t.Cleanup(func() { readBuildInfo = original })

		readBuildInfo = func() (*dbg.BuildInfo, bool) {
			return &dbg.BuildInfo{
				Deps: []*dbg.Module{
					{Path: "github.com/other/dep", Version: "v1.0.0"},
				},
			}, true
		}

		assert.Equal(t, "unknown", bundledOPAVersion())
	})
}

func TestWrapRegoError(t *testing.T) {
	original := readBuildInfo
	t.Cleanup(func() { readBuildInfo = original })

	readBuildInfo = func() (*dbg.BuildInfo, bool) {
		return &dbg.BuildInfo{
			Deps: []*dbg.Module{
				{Path: "github.com/open-policy-agent/opa", Version: "v1.15.2"},
			},
		}, true
	}

	t.Run("wraps rego_type_error with version and guidance", func(t *testing.T) {
		origErr := errors.New("rego_type_error: undefined function opa.runtime")
		wrapped := wrapRegoError(origErr)

		require.NotEqual(t, origErr, wrapped, "error should be wrapped")
		msg := wrapped.Error()
		assert.Contains(t, msg, "v1.15.2", "should contain OPA version")
		assert.Contains(t, msg, "policy compilation error", "should contain user-friendly prefix")
		assert.Contains(t, msg, "Conforma CLI (v1.15.2)", "should show version in context")
		assert.Contains(t, msg, "Upgrade Conforma CLI", "should lead with upgrade suggestion")
		assert.Contains(t, msg, "less common causes", "should mention less common causes section")
		assert.Contains(t, msg, "disables certain built-in functions for security", "should mention security restrictions")
		assert.Contains(t, msg, "opa.runtime", "should list restricted built-in functions")
		assert.Contains(t, msg, "http.send", "should list restricted built-in functions")
		assert.Contains(t, msg, "net.lookup_ip_addr", "should list restricted built-in functions")
		assert.Contains(t, msg, "Adjust the policy to target OPA v1.15.2 or earlier", "should contain version-specific adjust suggestion")
		assert.Contains(t, msg, "Details:", "should use Details label for original error")
		assert.Contains(t, msg, "rego_type_error: undefined function opa.runtime", "should preserve original error text")

		// Verify the original error is preserved via errors.Unwrap
		assert.ErrorIs(t, wrapped, origErr, "should preserve original error via wrapping")
	})

	t.Run("wraps rego_parse_error with version and guidance", func(t *testing.T) {
		origErr := errors.New("rego_parse_error: unexpected token")
		wrapped := wrapRegoError(origErr)

		require.NotEqual(t, origErr, wrapped)
		msg := wrapped.Error()
		assert.Contains(t, msg, "v1.15.2")
		assert.Contains(t, msg, "policy compilation error")
		assert.Contains(t, msg, "rego_parse_error: unexpected token")
		assert.ErrorIs(t, wrapped, origErr)
	})

	t.Run("passes through non-rego errors unchanged", func(t *testing.T) {
		origErr := errors.New("file not found")
		result := wrapRegoError(origErr)

		assert.Equal(t, origErr, result, "non-rego errors should pass through unchanged")
	})

	t.Run("passes through nil error", func(t *testing.T) {
		assert.Nil(t, wrapRegoError(nil))
	})

	t.Run("wraps rego_compile_error with version and guidance", func(t *testing.T) {
		origErr := errors.New("rego_compile_error: some compile error")
		wrapped := wrapRegoError(origErr)

		require.NotEqual(t, origErr, wrapped)
		msg := wrapped.Error()
		assert.Contains(t, msg, "v1.15.2")
		assert.Contains(t, msg, "policy compilation error")
		assert.Contains(t, msg, "rego_compile_error: some compile error")
		assert.ErrorIs(t, wrapped, origErr)
	})

	t.Run("handles multi-error with rego_type_error", func(t *testing.T) {
		origErr := fmt.Errorf("load: loading policies: get compiler: 3 errors occurred: rego_type_error: undefined function opa.runtime")
		wrapped := wrapRegoError(origErr)

		msg := wrapped.Error()
		assert.Contains(t, msg, "v1.15.2")
		assert.Contains(t, msg, "policy compilation error")
		assert.Contains(t, msg, "rego_type_error")
		assert.ErrorIs(t, wrapped, origErr, "should preserve original error via wrapping")
	})

	t.Run("adjusts message when version is unknown (build info unavailable)", func(t *testing.T) {
		original := readBuildInfo
		t.Cleanup(func() { readBuildInfo = original })

		readBuildInfo = func() (*dbg.BuildInfo, bool) {
			return nil, false
		}

		origErr := errors.New("rego_type_error: undefined function opa.runtime")
		wrapped := wrapRegoError(origErr)

		require.NotEqual(t, origErr, wrapped, "error should be wrapped")
		msg := wrapped.Error()
		assert.Contains(t, msg, "policy compilation error", "should contain user-friendly prefix")
		assert.Contains(t, msg, "Upgrade Conforma CLI", "should still suggest upgrading")
		assert.Contains(t, msg, "less common causes", "should mention less common causes")
		assert.Contains(t, msg, "disables certain built-in functions for security", "should mention security restrictions")
		assert.NotContains(t, msg, "(unknown)", "should not show unknown in parentheses")
		assert.NotContains(t, msg, "OPA unknown", "should not reference OPA unknown")
		assert.NotContains(t, msg, "Adjust the policy", "should omit version-specific suggestion when version is unknown")
		assert.Contains(t, msg, "Details:", "should use Details label for original error")
		assert.ErrorIs(t, wrapped, origErr, "should preserve original error via wrapping")
	})

	t.Run("adjusts message when version is unknown (OPA not in deps)", func(t *testing.T) {
		original := readBuildInfo
		t.Cleanup(func() { readBuildInfo = original })

		readBuildInfo = func() (*dbg.BuildInfo, bool) {
			return &dbg.BuildInfo{
				Deps: []*dbg.Module{
					{Path: "github.com/other/dep", Version: "v1.0.0"},
				},
			}, true
		}

		origErr := errors.New("rego_parse_error: unexpected token")
		wrapped := wrapRegoError(origErr)

		require.NotEqual(t, origErr, wrapped, "error should be wrapped")
		msg := wrapped.Error()
		assert.Contains(t, msg, "policy compilation error", "should contain user-friendly prefix")
		assert.NotContains(t, msg, "(unknown)", "should not show unknown in parentheses")
		assert.NotContains(t, msg, "OPA unknown", "should not reference OPA unknown")
		assert.NotContains(t, msg, "Adjust the policy", "should omit version-specific suggestion when version is unknown")
		assert.ErrorIs(t, wrapped, origErr, "should preserve original error via wrapping")
	})
}
