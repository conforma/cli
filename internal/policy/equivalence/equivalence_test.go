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

package equivalence

import (
	"testing"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestEquivalenceChecker_AreEquivalent(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name     string
		spec1    ecc.EnterpriseContractPolicySpec
		spec2    ecc.EnterpriseContractPolicySpec
		expected bool
	}{
		{
			name: "identical simple specs",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Name: "Test Source",
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
						},
						Data: []string{
							"github.com/release-engineering/rhtap-ec-policy//data",
						},
						Config: &ecc.SourceConfig{
							Include: []string{"@redhat"},
							Exclude: []string{"cve"},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Name: "Different Name", // Name should not affect equivalence
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
						},
						Data: []string{
							"github.com/release-engineering/rhtap-ec-policy//data",
						},
						Config: &ecc.SourceConfig{
							Include: []string{"@redhat"},
							Exclude: []string{"cve"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "different policy URIs",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:latest",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "different data URIs",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"github.com/release-engineering/rhtap-ec-policy//data",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "different include matchers",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Include: []string{"@redhat"},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Include: []string{"@slsa3"},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "different exclude matchers",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"hermetic"},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "matcher normalization - pkg.* to pkg",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Include: []string{"cve.*"},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Include: []string{"cve"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "matcher deduplication",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Include: []string{"@redhat", "@redhat", "cve"},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Include: []string{"cve", "@redhat"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "multiple sources with same policy/data sets",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Name: "Source 1",
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
						},
						Data: []string{
							"github.com/release-engineering/rhtap-ec-policy//data",
						},
						Config: &ecc.SourceConfig{
							Include: []string{"@redhat"},
						},
					},
					{
						Name: "Source 2",
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
						},
						Data: []string{
							"github.com/release-engineering/rhtap-ec-policy//data",
						},
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Name: "Combined Source",
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
						},
						Data: []string{
							"github.com/release-engineering/rhtap-ec-policy//data",
						},
						Config: &ecc.SourceConfig{
							Include: []string{"@redhat"},
							Exclude: []string{"cve"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "different RuleData",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						RuleData: &extv1.JSON{Raw: []byte(`{"allowed_registry_prefixes":["registry.redhat.io/"]}`)},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						RuleData: &extv1.JSON{Raw: []byte(`{"allowed_registry_prefixes":["registry.access.redhat.com/"]}`)},
					},
				},
			},
			expected: false,
		},
		{
			name: "identical RuleData with different key order",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						RuleData: &extv1.JSON{Raw: []byte(`{"allowed_registry_prefixes":["registry.redhat.io/","registry.access.redhat.com/"],"other_setting":"value"}`)},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						RuleData: &extv1.JSON{Raw: []byte(`{"other_setting":"value","allowed_registry_prefixes":["registry.redhat.io/","registry.access.redhat.com/"]}`)},
					},
				},
			},
			expected: true,
		},
		{
			name: "global configuration merging",
			spec1: ecc.EnterpriseContractPolicySpec{
				Configuration: &ecc.EnterpriseContractPolicyConfiguration{
					Include: []string{"@redhat"},
					Exclude: []string{"cve"},
				},
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Include: []string{"@slsa3"},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Include: []string{"@redhat", "@slsa3"},
							Exclude: []string{"cve"},
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checker.AreEquivalent(tt.spec1, tt.spec2)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result, "Expected equivalence: %v, got: %v", tt.expected, result)
		})
	}
}

func TestEquivalenceChecker_VolatileConfig(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name     string
		spec1    ecc.EnterpriseContractPolicySpec
		spec2    ecc.EnterpriseContractPolicySpec
		expected bool
	}{
		{
			name: "active volatile config",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
						VolatileConfig: &ecc.VolatileSourceConfig{
							Exclude: []ecc.VolatileCriteria{
								{
									Value:          "hermetic",
									EffectiveOn:    "2024-01-01T00:00:00Z",
									EffectiveUntil: "2024-12-31T23:59:59Z",
								},
							},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve", "hermetic"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "expired volatile config",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
						VolatileConfig: &ecc.VolatileSourceConfig{
							Exclude: []ecc.VolatileCriteria{
								{
									Value:          "hermetic",
									EffectiveUntil: "2024-01-01T00:00:00Z", // Expired
								},
							},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "future volatile config",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
						VolatileConfig: &ecc.VolatileSourceConfig{
							Exclude: []ecc.VolatileCriteria{
								{
									Value:       "hermetic",
									EffectiveOn: "2024-06-01T00:00:00Z", // Future
								},
							},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checker.AreEquivalent(tt.spec1, tt.spec2)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result, "Expected equivalence: %v, got: %v", tt.expected, result)
		})
	}
}

func TestEquivalenceChecker_ImageMatching(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	imageInfo := &ImageInfo{
		Digest: "sha256:abc123",
		Ref:    "registry.redhat.io/ubi8/ubi:latest",
		URL:    "registry.redhat.io/ubi8/ubi@sha256:abc123",
	}
	checker := NewEquivalenceChecker(effectiveTime, imageInfo)

	tests := []struct {
		name     string
		spec1    ecc.EnterpriseContractPolicySpec
		spec2    ecc.EnterpriseContractPolicySpec
		expected bool
	}{
		{
			name: "matching image digest",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
						VolatileConfig: &ecc.VolatileSourceConfig{
							Exclude: []ecc.VolatileCriteria{
								{
									Value:       "hermetic",
									ImageDigest: "sha256:abc123",
								},
							},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve", "hermetic"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "non-matching image digest",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
						VolatileConfig: &ecc.VolatileSourceConfig{
							Exclude: []ecc.VolatileCriteria{
								{
									Value:       "hermetic",
									ImageDigest: "sha256:def456", // Different digest
								},
							},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "matching image ref",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve"},
						},
						VolatileConfig: &ecc.VolatileSourceConfig{
							Exclude: []ecc.VolatileCriteria{
								{
									Value:    "hermetic",
									ImageRef: "registry.redhat.io/ubi8/ubi:latest",
								},
							},
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Config: &ecc.SourceConfig{
							Exclude: []string{"cve", "hermetic"},
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checker.AreEquivalent(tt.spec1, tt.spec2)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result, "Expected equivalence: %v, got: %v", tt.expected, result)
		})
	}
}

func TestEquivalenceChecker_RealWorldExamples(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	// Test case based on ecps/example.yaml and ecps/ec-policy.yaml
	t.Run("example vs ec-policy", func(t *testing.T) {
		exampleSpec := ecc.EnterpriseContractPolicySpec{
			Sources: []ecc.Source{
				{
					Name: "Release Policies",
					Data: []string{
						"github.com/release-engineering/rhtap-ec-policy//data",
						"oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest",
						"oci::quay.io/konflux-ci/integration-service-catalog/data-acceptable-bundles:latest",
					},
					Policy: []string{
						"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
					},
					VolatileConfig: &ecc.VolatileSourceConfig{
						Exclude: []ecc.VolatileCriteria{},
					},
					Config: &ecc.SourceConfig{
						Include: []string{"@slsa3"},
						Exclude: []string{"cve.cve_blockers"},
					},
				},
			},
		}

		ecPolicySpec := ecc.EnterpriseContractPolicySpec{
			Sources: []ecc.Source{
				{
					Name: "Release Policies",
					Data: []string{
						"github.com/release-engineering/rhtap-ec-policy//data",
						"oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest",
					},
					Policy: []string{
						"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
					},
					Config: &ecc.SourceConfig{
						Exclude: []string{
							"hermetic_build_task",
							"hermetic_task",
							"step_image_registries",
							"tasks.required_tasks_found:prefetch-dependencies",
						},
						Include: []string{"@redhat"},
					},
				},
			},
		}

		result, err := checker.AreEquivalent(exampleSpec, ecPolicySpec)
		require.NoError(t, err)
		assert.False(t, result, "These specs should not be equivalent due to different data sources and matchers")
	})

	// Test case with RuleData (based on fbc-standard.yaml)
	t.Run("with RuleData", func(t *testing.T) {
		spec1 := ecc.EnterpriseContractPolicySpec{
			Sources: []ecc.Source{
				{
					Name:     "Release Policies",
					RuleData: &extv1.JSON{Raw: []byte(`{"allowed_registry_prefixes":["registry.redhat.io/","registry.access.redhat.com/","brew.registry.redhat.io/rh-osbs/openshift-ose-operator-registry-rhel9"]}`)},
					Data: []string{
						"github.com/release-engineering/rhtap-ec-policy//data",
						"oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest",
					},
					Policy: []string{
						"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
					},
					Config: &ecc.SourceConfig{
						Include: []string{"@redhat"},
						Exclude: []string{"cve", "step_image_registries", "source_image.exists"},
					},
				},
			},
		}

		spec2 := ecc.EnterpriseContractPolicySpec{
			Sources: []ecc.Source{
				{
					Name:     "Release Policies",
					RuleData: &extv1.JSON{Raw: []byte(`{"allowed_registry_prefixes":["registry.redhat.io/","registry.access.redhat.com/","brew.registry.redhat.io/rh-osbs/openshift-ose-operator-registry-rhel9"]}`)},
					Data: []string{
						"github.com/release-engineering/rhtap-ec-policy//data",
						"oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest",
					},
					Policy: []string{
						"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
					},
					Config: &ecc.SourceConfig{
						Include: []string{"@redhat"},
						Exclude: []string{"cve", "step_image_registries", "source_image.exists"},
					},
				},
			},
		}

		result, err := checker.AreEquivalent(spec1, spec2)
		require.NoError(t, err)
		assert.True(t, result, "These specs should be equivalent")
	})
}

func TestEquivalenceChecker_DigestStripping(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name     string
		spec1    ecc.EnterpriseContractPolicySpec
		spec2    ecc.EnterpriseContractPolicySpec
		expected bool
	}{
		{
			name: "policy URI with and without digest should be equivalent",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:latest",
						},
						Data: []string{
							"oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:latest@sha256:40a767fc4df3aa5bacd9fc8d16435b3bbb3edfe5db2e6b3c17d396f4ba38d711",
						},
						Data: []string{
							"oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "data URI with and without digest should be equivalent",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:latest",
						},
						Data: []string{
							"oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:latest",
						},
						Data: []string{
							"oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest@sha256:abc123def456",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "both policy and data URIs with different digests should be equivalent",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:latest@sha256:digest1",
						},
						Data: []string{
							"oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest@sha256:digest2",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:latest@sha256:differentdigest1",
						},
						Data: []string{
							"oci::quay.io/redhat-appstudio-tekton-catalog/data-acceptable-bundles:latest@sha256:differentdigest2",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "sha512 digest should also be stripped",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:latest",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:latest@sha512:abcdef123456",
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checker.AreEquivalent(tt.spec1, tt.spec2)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result, "Expected equivalence: %v, got: %v", tt.expected, result)
		})
	}
}

func TestEquivalenceChecker_ProtocolNormalization(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name     string
		spec1    ecc.EnterpriseContractPolicySpec
		spec2    ecc.EnterpriseContractPolicySpec
		expected bool
	}{
		{
			name: "file protocol should be ignored",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Name: "test",
						Policy: []string{
							"file::/Users/jstuart/Documents/repos/ec-policies/policy/release",
							"file::/Users/jstuart/Documents/repos/ec-policies/policy/lib",
						},
						Data: []string{
							"oci::quay.io/example/data:latest",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Name: "test",
						Policy: []string{
							"/Users/jstuart/Documents/repos/ec-policies/policy/release",
							"/Users/jstuart/Documents/repos/ec-policies/policy/lib",
						},
						Data: []string{
							"quay.io/example/data:latest",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "git protocol should be ignored",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"git::github.com/release-engineering/rhtap-ec-policy//data",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"github.com/release-engineering/rhtap-ec-policy//data",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "http protocol should be ignored",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"http::example.com/data",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"example.com/data",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "https protocol should be ignored",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"https::secure.example.com/data",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"secure.example.com/data",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "multiple protocols should be ignored",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"file::/path/to/policy",
							"oci::registry.com/policy:latest",
						},
						Data: []string{
							"git::github.com/org/repo//data",
							"http::example.com/data",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"/path/to/policy",
							"registry.com/policy:latest",
						},
						Data: []string{
							"github.com/org/repo//data",
							"example.com/data",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "protocols with digests should be normalized",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"file::/path/to/policy",
						},
						Data: []string{
							"oci::registry.com/repo:latest@sha256:abc123",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"/path/to/policy",
						},
						Data: []string{
							"registry.com/repo:latest",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "various digest formats should be stripped",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"registry.com/repo:latest@sha256:abc123def456",
							"registry.com/repo:latest@sha512:xyz789",
							"registry.com/repo:latest@sha1:def456",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"registry.com/repo:latest",
							"registry.com/repo:latest",
							"registry.com/repo:latest",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "various protocols should be stripped",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"custom::/path/to/policy",
							"another::registry.com/policy:latest",
						},
						Data: []string{
							"protocol::example.com/data",
							"test::github.com/org/repo//data",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{
							"/path/to/policy",
							"registry.com/policy:latest",
						},
						Data: []string{
							"example.com/data",
							"github.com/org/repo//data",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "complex URIs with protocols and digests should be normalized",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"custom::registry.com/repo:latest@sha256:abc123",
							"another::github.com/org/repo//data@sha512:def456",
						},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Data: []string{
							"registry.com/repo:latest",
							"github.com/org/repo//data",
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checker.AreEquivalent(tt.spec1, tt.spec2)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result, "Expected equivalence: %v, got: %v", tt.expected, result)
		})
	}
}
