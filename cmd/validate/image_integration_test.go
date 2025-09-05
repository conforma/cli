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

//go:build integration

package validate

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	ociMetadata "github.com/conforma/go-gather/gather/oci"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/output"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/internal/utils/oci/fake"
)

func TestEvaluatorLifecycle(t *testing.T) {
	noEvaluators := 100

	ctx := utils.WithFS(context.Background(), afero.NewMemMapFs())
	client := fake.FakeClient{}
	commonMockClient(&client)
	ctx = oci.WithClient(ctx, &client)
	mdl := MockDownloader{}
	// The downloader should be called twice per policy source: once during PreProcessPolicy and once during evaluator evaluation
	mdl.On("Download", mock.Anything, mock.Anything, false).Return(&ociMetadata.OCIMetadata{Digest: "sha256:da54bca5477bf4e3449bc37de1822888fa0fbb8d89c640218cb31b987374d357"}, nil).Times(noEvaluators * 2)
	ctx = context.WithValue(ctx, source.DownloaderFuncKey, &mdl)

	// Use a mock validation function that doesn't actually call the evaluators
	validate := func(_ context.Context, component app.SnapshotComponent, _ *app.SnapshotSpec, _ policy.Policy, evaluators []evaluator.Evaluator, _ bool) (*output.Output, error) {
		// Just verify that the correct number of evaluators were created
		if len(evaluators) != noEvaluators {
			return nil, fmt.Errorf("expected %d evaluators, got %d", noEvaluators, len(evaluators))
		}

		return &output.Output{ImageURL: component.ContainerImage}, nil
	}

	validateImageCmd := validateImageCmd(validate)
	cmd := setUpCobra(validateImageCmd)

	sources := make([]string, 0, noEvaluators)
	for i := 0; i < noEvaluators; i++ {
		sources = append(sources, fmt.Sprintf(`{"policy": ["oci::registry.example.com/policy/%d@sha256:4b825dc642cb6eb9a060e54bf8d69288fbee4904c1c2a3b11a0a99f14f9b9c11"]}`, i))
	}

	policyConfig := fmt.Sprintf(`{"publicKey": %s, "sources": [%s]}`, utils.TestPublicKeyJSON, strings.Join(sources, ", "))
	// // log the policyConfig
	// t.Logf("Policy config length: %d", len(policyConfig))
	// t.Logf("Policy config: %s", policyConfig)

	effectiveTimeTest := time.Now().UTC().Format(time.RFC3339Nano)

	// Set the context with the mock downloader
	cmd.SetContext(ctx)

	cmd.SetArgs([]string{
		"validate",
		"image",
		"--image",
		"registry/image:tag",
		"--policy",
		policyConfig,
		"--effective-time",
		effectiveTimeTest,
		"--ignore-rekor",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
}
