// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"context"
	"testing"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
)

func TestService_ProcessComponentVSA(t *testing.T) {
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	// Create test data
	report := applicationsnapshot.Report{
		Success: true,
		Policy:  ecc.EnterpriseContractPolicySpec{},
	}

	comp := applicationsnapshot.Component{
		SnapshotComponent: app.SnapshotComponent{
			Name:           "test-component",
			ContainerImage: "quay.io/test/image:tag",
		},
		Success:    true,
		Violations: []evaluator.Result{},
		Warnings:   []evaluator.Result{},
		Successes:  []evaluator.Result{{Message: "test success"}},
	}

	// Create test signer
	signer := testSigner("/test.key", fs)
	service := NewServiceWithFS(signer, fs)

	// Test successful processing
	envelopePath, err := service.ProcessComponentVSA(ctx, report, comp, "https://github.com/test/repo", "sha256:testdigest")

	assert.NoError(t, err)
	assert.NotEmpty(t, envelopePath)
	assert.Contains(t, envelopePath, ".intoto.jsonl")
}

func TestService_ProcessSnapshotVSA(t *testing.T) {
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	// Create test data
	report := applicationsnapshot.Report{
		Success: true,
		Policy:  ecc.EnterpriseContractPolicySpec{},
		Components: []applicationsnapshot.Component{
			{
				SnapshotComponent: app.SnapshotComponent{
					Name:           "test-component",
					ContainerImage: "quay.io/test/image:tag",
				},
				Success: true,
			},
		},
	}

	// Create test signer
	signer := testSigner("/test.key", fs)
	service := NewServiceWithFS(signer, fs)

	// Test successful processing
	envelopePath, err := service.ProcessSnapshotVSA(ctx, report)

	assert.NoError(t, err)
	assert.NotEmpty(t, envelopePath)
	assert.Contains(t, envelopePath, ".intoto.jsonl")
}

func TestService_ProcessAllVSAs(t *testing.T) {
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	// Create test data
	report := applicationsnapshot.Report{
		Success: true,
		Policy:  ecc.EnterpriseContractPolicySpec{},
		Components: []applicationsnapshot.Component{
			{
				SnapshotComponent: app.SnapshotComponent{
					Name:           "test-component-1",
					ContainerImage: "quay.io/test/image1:tag",
				},
				Success: true,
			},
			{
				SnapshotComponent: app.SnapshotComponent{
					Name:           "test-component-2",
					ContainerImage: "quay.io/test/image2:tag",
				},
				Success: true,
			},
		},
	}

	// Create test signer
	signer := testSigner("/test.key", fs)
	service := NewServiceWithFS(signer, fs)

	// Define helper functions
	getGitURL := func(comp applicationsnapshot.Component) string {
		return "https://github.com/test/repo"
	}

	getDigest := func(comp applicationsnapshot.Component) (string, error) {
		return "sha256:testdigest", nil
	}

	// Test successful processing
	result, err := service.ProcessAllVSAs(ctx, report, getGitURL, getDigest)

	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Test ComponentEnvelopes field
	assert.NotNil(t, result.ComponentEnvelopes, "ComponentEnvelopes should not be nil")
	assert.Len(t, result.ComponentEnvelopes, 2, "Should have envelope paths for 2 components")

	// Verify component envelope paths are set and valid
	assert.Contains(t, result.ComponentEnvelopes, "quay.io/test/image1:tag", "Should have envelope for first component")
	assert.Contains(t, result.ComponentEnvelopes, "quay.io/test/image2:tag", "Should have envelope for second component")

	envelope1 := result.ComponentEnvelopes["quay.io/test/image1:tag"]
	envelope2 := result.ComponentEnvelopes["quay.io/test/image2:tag"]

	assert.NotEmpty(t, envelope1, "Component 1 envelope path should not be empty")
	assert.NotEmpty(t, envelope2, "Component 2 envelope path should not be empty")
	assert.Contains(t, envelope1, ".intoto.jsonl", "Component 1 envelope should be a .intoto.jsonl file")
	assert.Contains(t, envelope2, ".intoto.jsonl", "Component 2 envelope should be a .intoto.jsonl file")

	// Test SnapshotEnvelope field
	assert.NotEmpty(t, result.SnapshotEnvelope, "SnapshotEnvelope should not be empty")
	assert.Contains(t, result.SnapshotEnvelope, ".intoto.jsonl", "Snapshot envelope should be a .intoto.jsonl file")
}

func TestService_ProcessAllVSAs_WithErrors(t *testing.T) {
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	// Create test data
	report := applicationsnapshot.Report{
		Success: true,
		Policy:  ecc.EnterpriseContractPolicySpec{},
		Components: []applicationsnapshot.Component{
			{
				SnapshotComponent: app.SnapshotComponent{
					Name:           "test-component-1",
					ContainerImage: "quay.io/test/image1:tag",
				},
				Success: true,
			},
		},
	}

	// Create test signer
	signer := testSigner("/test.key", fs)
	service := NewServiceWithFS(signer, fs)

	// Define helper functions that return errors
	getGitURL := func(comp applicationsnapshot.Component) string {
		return "https://github.com/test/repo"
	}

	getDigest := func(comp applicationsnapshot.Component) (string, error) {
		return "", assert.AnError
	}

	// Test processing with errors (should continue processing other components)
	result, err := service.ProcessAllVSAs(ctx, report, getGitURL, getDigest)

	// Should still succeed overall, but log errors for individual components
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Test ComponentEnvelopes field with error scenario
	assert.NotNil(t, result.ComponentEnvelopes, "ComponentEnvelopes should not be nil even with errors")
	// Component processing should fail due to getDigest error, so map should be empty
	assert.Empty(t, result.ComponentEnvelopes, "ComponentEnvelopes should be empty when component processing fails")

	// Test SnapshotEnvelope field - should still be processed
	assert.NotEmpty(t, result.SnapshotEnvelope, "SnapshotEnvelope should be processed even when components fail")
	assert.Contains(t, result.SnapshotEnvelope, ".intoto.jsonl", "Snapshot envelope should be a .intoto.jsonl file")
}

func TestService_ProcessAllVSAs_PartialSuccess(t *testing.T) {
	ctx := context.Background()
	fs := afero.NewMemMapFs()

	// Create test data with multiple components
	report := applicationsnapshot.Report{
		Success: true,
		Policy:  ecc.EnterpriseContractPolicySpec{},
		Components: []applicationsnapshot.Component{
			{
				SnapshotComponent: app.SnapshotComponent{
					Name:           "success-component",
					ContainerImage: "quay.io/test/success:tag",
				},
				Success: true,
			},
			{
				SnapshotComponent: app.SnapshotComponent{
					Name:           "fail-component",
					ContainerImage: "quay.io/test/fail:tag",
				},
				Success: true,
			},
		},
	}

	// Create test signer
	signer := testSigner("/test.key", fs)
	service := NewServiceWithFS(signer, fs)

	// Define helper functions - fail for specific component
	getGitURL := func(comp applicationsnapshot.Component) string {
		return "https://github.com/test/repo"
	}

	getDigest := func(comp applicationsnapshot.Component) (string, error) {
		if comp.ContainerImage == "quay.io/test/fail:tag" {
			return "", assert.AnError // Fail for this component
		}
		return "sha256:testdigest", nil // Succeed for others
	}

	// Test partial success processing
	result, err := service.ProcessAllVSAs(ctx, report, getGitURL, getDigest)

	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Test ComponentEnvelopes field with partial success
	assert.NotNil(t, result.ComponentEnvelopes, "ComponentEnvelopes should not be nil")
	assert.Len(t, result.ComponentEnvelopes, 1, "Should have envelope for 1 successful component")

	// Verify only successful component is in the map
	assert.Contains(t, result.ComponentEnvelopes, "quay.io/test/success:tag", "Should have envelope for successful component")
	assert.NotContains(t, result.ComponentEnvelopes, "quay.io/test/fail:tag", "Should not have envelope for failed component")

	successEnvelope := result.ComponentEnvelopes["quay.io/test/success:tag"]
	assert.NotEmpty(t, successEnvelope, "Successful component envelope path should not be empty")
	assert.Contains(t, successEnvelope, ".intoto.jsonl", "Successful component envelope should be a .intoto.jsonl file")

	// Test SnapshotEnvelope field - should still be processed
	assert.NotEmpty(t, result.SnapshotEnvelope, "SnapshotEnvelope should be processed even with component failures")
	assert.Contains(t, result.SnapshotEnvelope, ".intoto.jsonl", "Snapshot envelope should be a .intoto.jsonl file")
}
