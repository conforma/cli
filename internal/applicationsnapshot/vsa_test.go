// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package applicationsnapshot

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/evaluator"
)

func TestSnapshotVSAGenerator_GeneratePredicate(t *testing.T) {
	ctx := context.Background()

	// Create a test report
	report := Report{
		Components: []Component{
			{
				SnapshotComponent: app.SnapshotComponent{
					Name:           "test-component",
					ContainerImage: "test-image:latest",
				},
				Success:    true,
				Violations: []evaluator.Result{},
				Warnings:   []evaluator.Result{},
				Successes:  []evaluator.Result{},
			},
		},
		Policy: ecc.EnterpriseContractPolicySpec{
			Name: "test-policy",
		},
	}

	generator := NewSnapshotVSAGenerator(report)

	predicate, err := generator.GeneratePredicate(ctx)
	require.NoError(t, err)

	// Verify the predicate is the same as the report
	assert.Equal(t, report, predicate)
}

func TestSnapshotVSAWriter_WritePredicate(t *testing.T) {
	// Create a test report
	report := Report{
		Components: []Component{
			{
				SnapshotComponent: app.SnapshotComponent{
					Name:           "test-component",
					ContainerImage: "test-image:latest",
				},
				Success: true,
			},
		},
	}

	writer := NewSnapshotVSAWriter()

	path, err := writer.WritePredicate(report)
	require.NoError(t, err)

	// Verify the file was created and contains valid JSON
	assert.Contains(t, path, "snapshot-vsa-")
	assert.Contains(t, path, "application-snapshot-vsa.json")

	// Clean up
	os.RemoveAll(filepath.Dir(path))
}
