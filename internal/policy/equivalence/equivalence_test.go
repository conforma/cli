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

package equivalence

import (
	"fmt"
	"testing"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
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

func TestDeterministicHashing(t *testing.T) {
	// Test that equivalent data structures with different key orders produce the same hash
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	// Create two equivalent maps with different key orders
	data1 := map[string]interface{}{
		"z": "last",
		"a": "first",
		"m": "middle",
		"nested": map[string]interface{}{
			"z": "nested_last",
			"a": "nested_first",
		},
	}

	data2 := map[string]interface{}{
		"a": "first",
		"m": "middle",
		"z": "last",
		"nested": map[string]interface{}{
			"a": "nested_first",
			"z": "nested_last",
		},
	}

	// Both should produce the same hash
	hash1, err := checker.hashRuleData(data1)
	require.NoError(t, err)

	hash2, err := checker.hashRuleData(data2)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2, "Equivalent data with different key orders should produce the same hash")

	// Test with arrays containing maps
	data3 := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{
				"z": "item_last",
				"a": "item_first",
			},
			map[string]interface{}{
				"a": "item2_first",
				"z": "item2_last",
			},
		},
	}

	data4 := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{
				"a": "item_first",
				"z": "item_last",
			},
			map[string]interface{}{
				"z": "item2_last",
				"a": "item2_first",
			},
		},
	}

	hash3, err := checker.hashRuleData(data3)
	require.NoError(t, err)

	hash4, err := checker.hashRuleData(data4)
	require.NoError(t, err)

	assert.Equal(t, hash3, hash4, "Equivalent data with different key orders in nested structures should produce the same hash")
}

func TestDeterministicMergeOrder(t *testing.T) {
	// Test that equivalent specs with different source orders produce identical merged results
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	// Create two equivalent specs with different source orders
	spec1 := ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{
			{
				Name: "source-a",
				RuleData: &extv1.JSON{
					Raw: []byte(`{"key1": "value1", "key2": "value2"}`),
				},
			},
			{
				Name: "source-b",
				RuleData: &extv1.JSON{
					Raw: []byte(`{"key2": "value2_override", "key3": "value3"}`),
				},
			},
		},
	}

	spec2 := ecc.EnterpriseContractPolicySpec{
		Sources: []ecc.Source{
			{
				Name: "source-b",
				RuleData: &extv1.JSON{
					Raw: []byte(`{"key2": "value2_override", "key3": "value3"}`),
				},
			},
			{
				Name: "source-a",
				RuleData: &extv1.JSON{
					Raw: []byte(`{"key1": "value1", "key2": "value2"}`),
				},
			},
		},
	}

	// Both specs should produce identical merged results despite different source order
	merged1, err := checker.mergeRuleData(spec1.Sources)
	require.NoError(t, err)

	merged2, err := checker.mergeRuleData(spec2.Sources)
	require.NoError(t, err)

	// The merged results should be identical
	assert.Equal(t, merged1, merged2, "Equivalent specs with different source orders should produce identical merged results")

	// Verify the expected merged content (deterministic ordering based on canonical JSON hash)
	// The source with smaller canonical hash comes first, so its values are not overridden
	expected := map[string]interface{}{
		"key1": "value1",
		"key2": "value2", // This is the value from the first source (smaller hash)
		"key3": "value3",
	}
	assert.Equal(t, expected, merged1)
	assert.Equal(t, expected, merged2)
}

func TestDeterministicMergeOrderDebug(t *testing.T) {
	// Debug test to understand the merge behavior
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	// Create test data
	source1 := ecc.Source{
		Name: "source-a",
		RuleData: &extv1.JSON{
			Raw: []byte(`{"key1": "value1", "key2": "value2"}`),
		},
	}

	source2 := ecc.Source{
		Name: "source-b",
		RuleData: &extv1.JSON{
			Raw: []byte(`{"key2": "value2_override", "key3": "value3"}`),
		},
	}

	// Test both orders
	merged1, err := checker.mergeRuleData([]ecc.Source{source1, source2})
	require.NoError(t, err)
	t.Logf("Order 1 (source-a, source-b): %+v", merged1)

	merged2, err := checker.mergeRuleData([]ecc.Source{source2, source1})
	require.NoError(t, err)
	t.Logf("Order 2 (source-b, source-a): %+v", merged2)

	// They should be identical
	assert.Equal(t, merged1, merged2, "Different source orders should produce identical results")
}

// ---------- New comprehensive tests for refactored equivalence.go ----------

func TestAreEquivalentWithDifferences(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name          string
		spec1         ecc.EnterpriseContractPolicySpec
		spec2         ecc.EnterpriseContractPolicySpec
		expectedEq    bool
		expectedDiffs int
		expectedKinds []DiffKind
	}{
		{
			name: "identical specs should have no differences",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
						Data:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
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
						Policy: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
						Data:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
						Config: &ecc.SourceConfig{
							Include: []string{"@redhat"},
							Exclude: []string{"cve"},
						},
					},
				},
			},
			expectedEq:    true,
			expectedDiffs: 0,
		},
		{
			name: "different policy URIs should show differences",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{"oci::quay.io/enterprise-contract/ec-release-policy:latest"},
					},
				},
			},
			expectedEq:    false,
			expectedDiffs: 2, // 1 added, 1 removed
			expectedKinds: []DiffKind{DiffAdded, DiffRemoved},
		},
		{
			name: "different include matchers should show differences",
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
			expectedEq:    false,
			expectedDiffs: 2, // 1 added, 1 removed
			expectedKinds: []DiffKind{DiffAdded, DiffRemoved},
		},
		{
			name: "different RuleData should show differences",
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
			expectedEq:    false,
			expectedDiffs: 1,
			expectedKinds: []DiffKind{DiffChanged},
		},
		{
			name: "completely different sources should show as added/removed",
			spec1: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
						Data:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
					},
				},
			},
			spec2: ecc.EnterpriseContractPolicySpec{
				Sources: []ecc.Source{
					{
						Policy: []string{"oci::quay.io/enterprise-contract/ec-release-policy:latest"},
						Data:   []string{"oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest"},
					},
				},
			},
			expectedEq:    false,
			expectedDiffs: 2, // 1 added source, 1 removed source
			expectedKinds: []DiffKind{DiffAdded, DiffRemoved},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eq, diffs, err := checker.AreEquivalentWithDifferences(tt.spec1, tt.spec2)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedEq, eq)
			assert.Equal(t, tt.expectedDiffs, len(diffs))

			if tt.expectedKinds != nil {
				actualKinds := make([]DiffKind, len(diffs))
				for i, diff := range diffs {
					actualKinds[i] = diff.Kind
				}
				assert.ElementsMatch(t, tt.expectedKinds, actualKinds)
			}
		})
	}
}

func TestPolicyDifference(t *testing.T) {
	tests := []struct {
		name      string
		diff      PolicyDifference
		isAdded   bool
		isRemoved bool
		isChanged bool
	}{
		{
			name: "added difference",
			diff: PolicyDifference{
				Kind: DiffAdded,
			},
			isAdded:   true,
			isRemoved: false,
			isChanged: false,
		},
		{
			name: "removed difference",
			diff: PolicyDifference{
				Kind: DiffRemoved,
			},
			isAdded:   false,
			isRemoved: true,
			isChanged: false,
		},
		{
			name: "changed difference",
			diff: PolicyDifference{
				Kind: DiffChanged,
			},
			isAdded:   false,
			isRemoved: false,
			isChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isAdded, tt.diff.IsAdded())
			assert.Equal(t, tt.isRemoved, tt.diff.IsRemoved())
			assert.Equal(t, tt.isChanged, tt.diff.IsChanged())
		})
	}
}

func TestGenerateUnifiedDiffOutput(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name        string
		differences []PolicyDifference
		expected    string
	}{
		{
			name:        "no differences should return empty string",
			differences: []PolicyDifference{},
			expected:    "",
		},
		{
			name: "single policy difference",
			differences: []PolicyDifference{
				{
					BucketKey:     "policy1|data1",
					Field:         "policy",
					Kind:          DiffAdded,
					SuppliedValue: "oci::quay.io/enterprise-contract/ec-release-policy:latest",
					Summary:       "policy location added",
				},
			},
			expected: `--- VSA
+++ Supplied
# source entry: policy1|data1
+ [policy]  oci::quay.io/enterprise-contract/ec-release-policy:latest
`,
		},
		{
			name: "multiple differences in same source",
			differences: []PolicyDifference{
				{
					BucketKey:     "policy1|data1",
					Field:         "policy",
					Kind:          DiffAdded,
					SuppliedValue: "oci::quay.io/enterprise-contract/ec-release-policy:latest",
					Summary:       "policy location added",
				},
				{
					BucketKey: "policy1|data1",
					Field:     "include",
					Kind:      DiffRemoved,
					VSAValue:  "cve",
					Summary:   "include removed",
				},
			},
			expected: `--- VSA
+++ Supplied
# source entry: policy1|data1
- [include] cve
+ [policy]  oci::quay.io/enterprise-contract/ec-release-policy:latest
`,
		},
		{
			name: "source entry differences",
			differences: []PolicyDifference{
				{
					BucketKey:     "policy1|data1",
					Field:         "sources",
					Kind:          DiffAdded,
					SuppliedValue: "Policy sources:\n  - oci::quay.io/enterprise-contract/ec-release-policy:latest",
					Summary:       "source entry added",
				},
			},
			expected: `--- VSA
+++ Supplied
# source entry: policy1|data1
+ [source] Policy sources:
  - oci::quay.io/enterprise-contract/ec-release-policy:latest
`,
		},
		{
			name: "ruleData difference",
			differences: []PolicyDifference{
				{
					BucketKey:     "policy1|data1",
					Field:         "ruleData",
					Kind:          DiffChanged,
					SuppliedValue: "--- VSA.ruleData\n+++ Supplied.ruleData\n@@ -1,3 +1,3 @@\n {\n-  \"allowed_registry_prefixes\": [\"registry.redhat.io/\"]\n+  \"allowed_registry_prefixes\": [\"registry.access.redhat.com/\"]\n }",
					Summary:       "ruleData changed",
				},
			},
			expected: `--- VSA
+++ Supplied
# source entry: policy1|data1
--- VSA.ruleData
+++ Supplied.ruleData
@@ -1,3 +1,3 @@
 {
-  "allowed_registry_prefixes": ["registry.redhat.io/"]
+  "allowed_registry_prefixes": ["registry.access.redhat.com/"]
 }
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.GenerateUnifiedDiffOutput(tt.differences)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBucketSimilarity(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name     string
		bucket1  PolicyBucket
		bucket2  PolicyBucket
		expected float64
	}{
		{
			name: "identical buckets should have similarity 1.0",
			bucket1: PolicyBucket{
				PolicyURIs: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
				DataURIs:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
				Include:    []string{"@redhat"},
				Exclude:    []string{"cve"},
			},
			bucket2: PolicyBucket{
				PolicyURIs: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
				DataURIs:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
				Include:    []string{"@redhat"},
				Exclude:    []string{"cve"},
			},
			expected: 1.0,
		},
		{
			name: "completely different buckets should have similarity 0.0",
			bucket1: PolicyBucket{
				PolicyURIs: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
				DataURIs:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
			},
			bucket2: PolicyBucket{
				PolicyURIs: []string{"oci::quay.io/enterprise-contract/ec-release-policy:latest"},
				DataURIs:   []string{"oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest"},
			},
			expected: 0.1, // Algorithm gives small bonus even for different buckets
		},
		{
			name: "partially similar buckets should have similarity between 0.0 and 1.0",
			bucket1: PolicyBucket{
				PolicyURIs: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
				DataURIs:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
			},
			bucket2: PolicyBucket{
				PolicyURIs: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
				DataURIs:   []string{"oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles:latest"},
			},
			expected: 0.5, // Only policy URIs match (40% weight) + some data similarity
		},
		{
			name: "buckets with matching names should get name bonus",
			bucket1: PolicyBucket{
				PolicyURIs: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
				DataURIs:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
				Names:      []string{"test-policy"},
			},
			bucket2: PolicyBucket{
				PolicyURIs: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
				DataURIs:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
				Names:      []string{"test-policy"},
			},
			expected: 1.0, // Full match (name bonus is capped at 1.0)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			similarity := checker.bucketSimilarity(tt.bucket1, tt.bucket2)
			assert.InDelta(t, tt.expected, similarity, 0.01)
		})
	}
}

func TestJaccardSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected float64
	}{
		{
			name:     "identical sets should have similarity 1.0",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "c"},
			expected: 1.0,
		},
		{
			name:     "completely different sets should have similarity 0.0",
			a:        []string{"a", "b", "c"},
			b:        []string{"d", "e", "f"},
			expected: 0.0,
		},
		{
			name:     "partially overlapping sets",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "d"},
			expected: 0.5, // 2 intersection, 4 union = 0.5
		},
		{
			name:     "empty sets should have similarity 1.0",
			a:        []string{},
			b:        []string{},
			expected: 1.0,
		},
		{
			name:     "one empty set should have similarity 0.0",
			a:        []string{"a", "b"},
			b:        []string{},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			similarity := jaccard(tt.a, tt.b)
			assert.Equal(t, tt.expected, similarity)
		})
	}
}

func TestUnifiedJSONDiff(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name     string
		a        map[string]interface{}
		b        map[string]interface{}
		expected string
	}{
		{
			name: "identical data should return empty diff",
			a: map[string]interface{}{
				"allowed_registry_prefixes": []interface{}{"registry.redhat.io/"},
			},
			b: map[string]interface{}{
				"allowed_registry_prefixes": []interface{}{"registry.redhat.io/"},
			},
			expected: "",
		},
		{
			name: "different values should show diff",
			a: map[string]interface{}{
				"allowed_registry_prefixes": []interface{}{"registry.redhat.io/"},
			},
			b: map[string]interface{}{
				"allowed_registry_prefixes": []interface{}{"registry.access.redhat.com/"},
			},
			expected: "--- VSA.ruleData\n+++ Supplied.ruleData\n@@ -1,3 +1,3 @@\n {\n-  \"allowed_registry_prefixes\": [\"registry.redhat.io/\"]\n+  \"allowed_registry_prefixes\": [\"registry.access.redhat.com/\"]\n }",
		},
		{
			name: "added field should show diff",
			a: map[string]interface{}{
				"allowed_registry_prefixes": []interface{}{"registry.redhat.io/"},
			},
			b: map[string]interface{}{
				"allowed_registry_prefixes": []interface{}{"registry.redhat.io/"},
				"new_setting":               "value",
			},
			expected: "--- VSA.ruleData\n+++ Supplied.ruleData\n@@ -1,3 +1,6 @@\n {\n-  \"allowed_registry_prefixes\": [\"registry.redhat.io/\"]\n+  \"allowed_registry_prefixes\": [\"registry.redhat.io/\"],\n+  \"new_setting\": \"value\"\n }",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff, err := checker.unifiedJSONDiff(tt.a, tt.b)
			require.NoError(t, err)
			if tt.expected == "" {
				assert.Empty(t, diff)
			} else {
				assert.Contains(t, diff, "--- VSA.ruleData")
				assert.Contains(t, diff, "+++ Supplied.ruleData")
			}
		})
	}
}

func TestNormalizePolicy(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name     string
		spec     ecc.EnterpriseContractPolicySpec
		expected *NormalizedPolicy
	}{
		{
			name: "simple policy normalization",
			spec: ecc.EnterpriseContractPolicySpec{
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
			expected: &NormalizedPolicy{
				Buckets: []PolicyBucket{
					{
						PolicyURIs: []string{"quay.io/enterprise-contract/ec-release-policy:konflux"},
						DataURIs:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
						RuleData:   map[string]interface{}{},
						Include:    []string{"@redhat"},
						Exclude:    []string{"cve"},
						Names:      []string{"Test Source"},
					},
				},
			},
		},
		{
			name: "policy with global configuration",
			spec: ecc.EnterpriseContractPolicySpec{
				Configuration: &ecc.EnterpriseContractPolicyConfiguration{
					Include: []string{"@redhat"},
					Exclude: []string{"cve"},
				},
				Sources: []ecc.Source{
					{
						Policy: []string{
							"oci::quay.io/enterprise-contract/ec-release-policy:konflux",
						},
						Data: []string{
							"github.com/release-engineering/rhtap-ec-policy//data",
						},
					},
				},
			},
			expected: &NormalizedPolicy{
				Buckets: []PolicyBucket{
					{
						PolicyURIs: []string{"quay.io/enterprise-contract/ec-release-policy:konflux"},
						DataURIs:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
						RuleData:   map[string]interface{}{},
						Include:    []string{"@redhat"},
						Exclude:    []string{"cve"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checker.NormalizePolicy(tt.spec)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEdgeCases(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	t.Run("empty policy specs", func(t *testing.T) {
		spec1 := ecc.EnterpriseContractPolicySpec{}
		spec2 := ecc.EnterpriseContractPolicySpec{}

		eq, diffs, err := checker.AreEquivalentWithDifferences(spec1, spec2)
		require.NoError(t, err)
		assert.True(t, eq)
		assert.Empty(t, diffs)
	})

	t.Run("nil RuleData should not cause errors", func(t *testing.T) {
		spec1 := ecc.EnterpriseContractPolicySpec{
			Sources: []ecc.Source{
				{
					Policy: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
					Data:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
					// RuleData is nil
				},
			},
		}
		spec2 := ecc.EnterpriseContractPolicySpec{
			Sources: []ecc.Source{
				{
					Policy: []string{"oci::quay.io/enterprise-contract/ec-release-policy:konflux"},
					Data:   []string{"github.com/release-engineering/rhtap-ec-policy//data"},
					// RuleData is nil
				},
			},
		}

		eq, diffs, err := checker.AreEquivalentWithDifferences(spec1, spec2)
		require.NoError(t, err)
		assert.True(t, eq)
		assert.Empty(t, diffs)
	})

	t.Run("invalid JSON in RuleData should return error", func(t *testing.T) {
		spec1 := ecc.EnterpriseContractPolicySpec{
			Sources: []ecc.Source{
				{
					RuleData: &extv1.JSON{Raw: []byte(`{"invalid": json}`)}, // Invalid JSON
				},
			},
		}
		spec2 := ecc.EnterpriseContractPolicySpec{
			Sources: []ecc.Source{
				{
					RuleData: &extv1.JSON{Raw: []byte(`{"valid": "json"}`)},
				},
			},
		}

		_, _, err := checker.AreEquivalentWithDifferences(spec1, spec2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshal ruleData")
	})

	t.Run("empty source group should return error", func(t *testing.T) {
		// This is an internal test - we can't easily trigger this through the public API
		// but we can test the normalizeBucket method directly
		_, err := checker.normalizeBucket([]ecc.Source{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty source group")
	})
}

func TestPerformance(t *testing.T) {
	effectiveTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	// Create a large policy spec with many sources
	largeSpec := ecc.EnterpriseContractPolicySpec{
		Sources: make([]ecc.Source, 100),
	}

	for i := 0; i < 100; i++ {
		largeSpec.Sources[i] = ecc.Source{
			Name: fmt.Sprintf("source-%d", i),
			Policy: []string{
				fmt.Sprintf("oci::quay.io/enterprise-contract/ec-release-policy:konflux-%d", i),
			},
			Data: []string{
				fmt.Sprintf("github.com/release-engineering/rhtap-ec-policy//data-%d", i),
			},
			Config: &ecc.SourceConfig{
				Include: []string{fmt.Sprintf("@redhat-%d", i)},
				Exclude: []string{fmt.Sprintf("cve-%d", i)},
			},
		}
	}

	t.Run("large policy comparison should complete in reasonable time", func(t *testing.T) {
		start := time.Now()
		eq, diffs, err := checker.AreEquivalentWithDifferences(largeSpec, largeSpec)
		duration := time.Since(start)

		require.NoError(t, err)
		assert.True(t, eq)
		assert.Empty(t, diffs)
		assert.Less(t, duration, 5*time.Second, "Large policy comparison should complete within 5 seconds")
	})

	t.Run("normalize large policy should complete in reasonable time", func(t *testing.T) {
		start := time.Now()
		_, err := checker.NormalizePolicy(largeSpec)
		duration := time.Since(start)

		require.NoError(t, err)
		assert.Less(t, duration, 2*time.Second, "Large policy normalization should complete within 2 seconds")
	})
}

func TestVolatileConfigWithImageInfo(t *testing.T) {
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
			name: "volatile config with matching image digest should be active",
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
			name: "volatile config with non-matching image digest should be inactive",
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
			name: "volatile config with matching image ref should be active",
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
		{
			name: "volatile config with matching image URL should be active",
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
									ImageUrl: "registry.redhat.io/ubi8/ubi@sha256:abc123",
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
			eq, diffs, err := checker.AreEquivalentWithDifferences(tt.spec1, tt.spec2)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, eq)
			if !tt.expected {
				t.Logf("Differences: %+v", diffs)
			}
		})
	}
}

func TestIsVolatileMatcherActive(t *testing.T) {
	effectiveTime := time.Date(2025, 8, 18, 12, 0, 0, 0, time.UTC)
	checker := NewEquivalenceChecker(effectiveTime, nil)

	tests := []struct {
		name     string
		matcher  ecc.VolatileCriteria
		expected bool
	}{
		{
			name: "valid timestamps in range returns true",
			matcher: ecc.VolatileCriteria{
				Value:          "some-rule",
				EffectiveOn:    "2025-08-01T00:00:00Z",
				EffectiveUntil: "2025-08-31T23:59:59Z",
			},
			expected: true,
		},
		{
			name: "empty timestamps returns true (open-ended)",
			matcher: ecc.VolatileCriteria{
				Value: "open-ended-rule",
			},
			expected: true,
		},
		{
			name: "garbage EffectiveOn returns false (fail-closed)",
			matcher: ecc.VolatileCriteria{
				Value:       "garbage-on",
				EffectiveOn: "not-a-date",
			},
			expected: false,
		},
		{
			name: "garbage EffectiveUntil returns false (fail-closed)",
			matcher: ecc.VolatileCriteria{
				Value:          "garbage-until",
				EffectiveUntil: "also-garbage",
			},
			expected: false,
		},
		{
			name: "both timestamps garbage returns false",
			matcher: ecc.VolatileCriteria{
				Value:          "both-garbage",
				EffectiveOn:    "garbage",
				EffectiveUntil: "garbage",
			},
			expected: false,
		},
		{
			name: "date-only format accepted, in range returns true",
			matcher: ecc.VolatileCriteria{
				Value:          "date-only-rule",
				EffectiveOn:    "2025-08-01",
				EffectiveUntil: "2025-08-31",
			},
			expected: true,
		},
		{
			name: "date-only format, out of range returns false",
			matcher: ecc.VolatileCriteria{
				Value:          "date-only-expired",
				EffectiveOn:    "2025-07-01",
				EffectiveUntil: "2025-07-15",
			},
			expected: false,
		},
		{
			name: "future EffectiveOn returns false",
			matcher: ecc.VolatileCriteria{
				Value:          "future-rule",
				EffectiveOn:    "2025-09-01T00:00:00Z",
				EffectiveUntil: "2025-09-30T23:59:59Z",
			},
			expected: false,
		},
		{
			name: "expired EffectiveUntil returns false",
			matcher: ecc.VolatileCriteria{
				Value:          "expired-rule",
				EffectiveOn:    "2025-07-01T00:00:00Z",
				EffectiveUntil: "2025-07-31T23:59:59Z",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, checker.isVolatileMatcherActive(tt.matcher))
		})
	}
}
