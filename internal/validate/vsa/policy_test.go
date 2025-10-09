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

package vsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParsePolicySpec tests the ParsePolicySpec function
func TestParsePolicySpec(t *testing.T) {
	tests := []struct {
		name         string
		policyConfig string
		expectError  bool
		checkResult  func(t *testing.T, result interface{})
	}{
		{
			name: "valid YAML policy spec",
			policyConfig: `
sources:
  - name: policy
`,
			expectError: false,
			checkResult: func(t *testing.T, result interface{}) {
				// Just verify it parsed successfully
				assert.NotNil(t, result)
			},
		},
		{
			name: "valid JSON policy spec",
			policyConfig: `{
  "sources": [
    {
      "name": "policy"
    }
  ]
}`,
			expectError: false,
			checkResult: func(t *testing.T, result interface{}) {
				assert.NotNil(t, result)
			},
		},
		{
			name: "valid YAML with CRD wrapper",
			policyConfig: `
apiVersion: appstudio.redhat.com/v1alpha1
kind: EnterpriseContractPolicy
metadata:
  name: test-policy
spec:
  sources:
    - name: policy
`,
			expectError: false,
			checkResult: func(t *testing.T, result interface{}) {
				assert.NotNil(t, result)
			},
		},
		{
			name: "invalid YAML",
			policyConfig: `
invalid: yaml: content: [unclosed
`,
			expectError: true,
		},
		{
			name: "invalid JSON",
			policyConfig: `{
  "sources": [
    {
      "name": "policy"
    }
  ]
  // missing closing brace
`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePolicySpec(tt.policyConfig)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, result)
				}
			}
		})
	}
}
