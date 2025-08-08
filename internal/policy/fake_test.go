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

package policy

import (
	"context"
	"testing"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func TestFetchEnterpriseContractPolicy(t *testing.T) {
	cases := []struct {
		name           string
		ref            string
		fetchError     bool
		policySpec     ecc.EnterpriseContractPolicySpec
		expectedResult *ecc.EnterpriseContractPolicy
		expectErr      bool
		errMsg         string
	}{
		{
			name:       "successful fetch with public key and sources",
			ref:        "test-policy",
			fetchError: false,
			policySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: "-----BEGIN PUBLIC KEY-----\ntest-public-key\n-----END PUBLIC KEY-----",
				Sources: []ecc.Source{
					{
						Policy: []string{"https://example.com/policy.yaml"},
						Data:   []string{"https://example.com/data.yaml"},
					},
				},
			},
			expectedResult: &ecc.EnterpriseContractPolicy{
				Spec: ecc.EnterpriseContractPolicySpec{
					PublicKey: "-----BEGIN PUBLIC KEY-----\ntest-public-key\n-----END PUBLIC KEY-----",
					Sources: []ecc.Source{
						{
							Policy: []string{"https://example.com/policy.yaml"},
							Data:   []string{"https://example.com/data.yaml"},
						},
					},
				},
			},
			expectErr: false,
		},
		{
			name:       "failed fetch with error",
			ref:        "error-policy",
			fetchError: true,
			policySpec: ecc.EnterpriseContractPolicySpec{
				PublicKey: "ignored-key",
				Sources: []ecc.Source{
					{
						Policy: []string{"https://example.com/policy.yaml"},
					},
				},
			},
			expectedResult: nil,
			expectErr:      true,
			errMsg:         "no fetching for you",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			client := &FakeKubernetesClient{
				Policy:     c.policySpec,
				FetchError: c.fetchError,
			}

			result, err := client.FetchEnterpriseContractPolicy(ctx, c.ref)

			if c.expectErr {
				assert.Error(t, err, "Expected error for fetch failure")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
				assert.Nil(t, result, "Result should be nil when error occurs")
			} else {
				assert.NoError(t, err, "Expected no error for successful fetch")
				assert.NotNil(t, result, "Result should not be nil for successful fetch")
				assert.Equal(t, c.expectedResult.Spec, result.Spec, "Policy spec should match expected")

				// Verify public key is correctly copied
				assert.Equal(t, c.expectedResult.Spec.PublicKey, result.Spec.PublicKey, "Public key should match")

				// Verify sources are correctly copied
				if len(c.expectedResult.Spec.Sources) > 0 {
					assert.Equal(t, len(c.expectedResult.Spec.Sources), len(result.Spec.Sources), "Number of sources should match")
					for i, expectedSource := range c.expectedResult.Spec.Sources {
						assert.Equal(t, expectedSource.Policy, result.Spec.Sources[i].Policy, "Source policy should match")
						assert.Equal(t, expectedSource.Data, result.Spec.Sources[i].Data, "Source data should match")
					}
				} else {
					assert.Empty(t, result.Spec.Sources, "Sources should be empty when expected")
				}
			}
		})
	}
}

func TestFetchSnapshot(t *testing.T) {
	cases := []struct {
		name           string
		ref            string
		fetchError     bool
		snapshotSpec   app.SnapshotSpec
		expectedResult *app.Snapshot
		expectErr      bool
		errMsg         string
	}{
		{
			name:       "successful fetch with component data",
			ref:        "component-snapshot",
			fetchError: false,
			snapshotSpec: app.SnapshotSpec{
				Components: []app.SnapshotComponent{
					{
						Name:           "web-app",
						ContainerImage: "quay.io/myorg/web-app:1.2.3",
					},
					{
						//fetch with special characters in reference
						Name:           "special-component",
						ContainerImage: "registry.io/repo/special@latest",
					},
				},
			},
			expectedResult: &app.Snapshot{
				Spec: app.SnapshotSpec{
					Components: []app.SnapshotComponent{
						{
							Name:           "web-app",
							ContainerImage: "quay.io/myorg/web-app:1.2.3",
						},
						{
							Name:           "special-component",
							ContainerImage: "registry.io/repo/special@latest",
						},
					},
				},
			},
			expectErr: false,
		},
		{
			name:       "fetch error with empty reference",
			ref:        "",
			fetchError: true,
			snapshotSpec: app.SnapshotSpec{
				Components: []app.SnapshotComponent{},
			},
			expectedResult: nil,
			expectErr:      true,
			errMsg:         "no fetching for you",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			client := &FakeKubernetesClient{
				Snapshot:   c.snapshotSpec,
				FetchError: c.fetchError,
			}

			result, err := client.FetchSnapshot(ctx, c.ref)

			if c.expectErr {
				assert.Error(t, err, "Expected error for fetch failure")
				if c.errMsg != "" {
					assert.Contains(t, err.Error(), c.errMsg, "Error message should contain expected text")
				}
				assert.Nil(t, result, "Result should be nil when error occurs")
			} else {
				assert.NoError(t, err, "Expected no error for successful fetch")
				assert.NotNil(t, result, "Result should not be nil for successful fetch")
				assert.Equal(t, c.expectedResult.Spec, result.Spec, "Snapshot spec should match expected")

				// Verify components are correctly copied
				if len(c.expectedResult.Spec.Components) > 0 {
					assert.Equal(t, len(c.expectedResult.Spec.Components), len(result.Spec.Components), "Number of components should match")
					for i, expectedComp := range c.expectedResult.Spec.Components {
						assert.Equal(t, expectedComp.Name, result.Spec.Components[i].Name, "Component name should match")
						assert.Equal(t, expectedComp.ContainerImage, result.Spec.Components[i].ContainerImage, "Container image should match")
					}
				}
			}
		})
	}
}
