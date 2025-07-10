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
	err := service.ProcessAllVSAs(ctx, report, getGitURL, getDigest)

	assert.NoError(t, err)
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
	err := service.ProcessAllVSAs(ctx, report, getGitURL, getDigest)

	// Should still succeed overall, but log errors for individual components
	assert.NoError(t, err)
}
