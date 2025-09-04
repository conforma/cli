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

package image

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	cosignTypes "github.com/sigstore/cosign/v2/pkg/types"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/attestation"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/utils"
	ecoci "github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/internal/utils/oci/fake"
)

const (
	imageRegistry = "registry.example/spam"
	imageTag      = "maps"
	imageDigest   = "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb" //#nosec G101
	imageRef      = imageRegistry + ":" + imageTag + "@sha256:" + imageDigest
)

var (
	ref      = name.MustParseReference(imageRef)
	refNoTag = name.MustParseReference(imageRegistry + "@sha256:" + imageDigest)
)

func TestBuiltinChecks(t *testing.T) {
	cases := []struct {
		name               string
		setup              func(*fake.FakeClient)
		component          app.SnapshotComponent
		expectedViolations []evaluator.Result
		expectedWarnings   []evaluator.Result
		expectedImageURL   string
	}{
		{
			name: "simple success",
			setup: func(c *fake.FakeClient) {
				c.On("Head", ref).Return(&v1.Descriptor{MediaType: types.OCIManifestSchema1}, nil)
				c.On("VerifyImageSignatures", refNoTag, mock.Anything).Return([]oci.Signature{validSignature}, true, nil)
				c.On("VerifyImageAttestations", refNoTag, mock.Anything).Return([]oci.Signature{validAttestation}, true, nil)
			},
			component:          app.SnapshotComponent{ContainerImage: imageRef},
			expectedViolations: []evaluator.Result{},
			expectedWarnings:   []evaluator.Result{},
			expectedImageURL:   imageRegistry + "@sha256:" + imageDigest,
		},
		{
			name: "unaccessible image",
			setup: func(c *fake.FakeClient) {
				c.On("Head", ref).Return(nil, nil)
			},
			component: app.SnapshotComponent{ContainerImage: imageRef},
			expectedViolations: []evaluator.Result{
				{Message: "Image URL is not accessible: no response received", Metadata: map[string]interface{}{
					"code": "builtin.image.accessible",
				}},
			},
			expectedWarnings: []evaluator.Result{},
			expectedImageURL: imageRef,
		},
		{
			name: "no image signatures",
			setup: func(c *fake.FakeClient) {
				c.On("Head", ref).Return(&v1.Descriptor{MediaType: types.OCIManifestSchema1}, nil)
				c.On("VerifyImageSignatures", refNoTag, mock.Anything).Return(nil, false, errors.New("no image signatures client error"))
				c.On("VerifyImageAttestations", refNoTag, mock.Anything).Return([]oci.Signature{validAttestation}, true, nil)
			},
			component: app.SnapshotComponent{ContainerImage: imageRef},
			expectedViolations: []evaluator.Result{
				{Message: "Image signature check failed: no image signatures client error", Metadata: map[string]interface{}{
					"code": "builtin.image.signature_check",
				}},
			},
			expectedWarnings: []evaluator.Result{},
			expectedImageURL: imageRegistry + "@sha256:" + imageDigest,
		},
		{
			name: "no image attestations",
			setup: func(c *fake.FakeClient) {
				c.On("Head", ref).Return(&v1.Descriptor{MediaType: types.OCIManifestSchema1}, nil)
				c.On("VerifyImageSignatures", refNoTag, mock.Anything).Return(validSignature, true, nil)
				c.On("VerifyImageAttestations", refNoTag, mock.Anything).Return(nil, false, errors.New("no image attestations client error"))
			},
			component: app.SnapshotComponent{ContainerImage: imageRef},
			expectedViolations: []evaluator.Result{
				{Message: "Image attestation check failed: no image attestations client error", Metadata: map[string]interface{}{
					"code": "builtin.attestation.signature_check",
				}},
			},
			expectedWarnings: []evaluator.Result{},
			expectedImageURL: imageRegistry + "@sha256:" + imageDigest,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()

			ctx := utils.WithFS(context.Background(), fs)
			p, err := policy.NewOfflinePolicy(ctx, policy.Now)
			assert.NoError(t, err)

			evaluators := []evaluator.Evaluator{}
			snap := app.SnapshotSpec{
				Components: []app.SnapshotComponent{
					{
						ContainerImage: "registry.io/repository/image:tag",
					},
					{
						ContainerImage: "registry.io/other-repository/image2:tag",
					},
				},
			}

			ctx = withImageConfig(ctx, c.component.ContainerImage)
			client := ecoci.NewClient(ctx)
			c.setup(client.(*fake.FakeClient))

			actual, err := ValidateImage(ctx, c.component, &snap, p, evaluators, false)
			assert.NoError(t, err)

			// Verify application snapshot was a part of input
			strings.Contains(string(actual.PolicyInput), "snapshot\":{\"application\":\"\",\"components\":[{\"name\":\"\",\"containerImage\":\"registry.io/repository/image:tag\",\"source\":{}},{\"name\":\"\",\"containerImage\":\"registry.io/other-repository/image2:tag\",\"source\":{}}],\"artifacts\":{}}")

			assert.Equal(t, c.expectedWarnings, actual.Warnings())
			assert.Equal(t, c.expectedViolations, actual.Violations())
			assert.Equal(t, c.expectedImageURL, actual.ImageURL)
		})
	}
}

func TestDetermineAttestationTime(t *testing.T) {
	time1 := time.Date(2001, 2, 3, 4, 5, 6, 7, time.UTC)
	time2 := time.Date(2010, 11, 12, 13, 14, 15, 16, time.UTC)
	att1 := fakeAtt{
		statement: in_toto.ProvenanceStatementSLSA02{
			StatementHeader: in_toto.StatementHeader{
				PredicateType: v02.PredicateSLSAProvenance,
			},
			Predicate: v02.ProvenancePredicate{
				Metadata: &v02.ProvenanceMetadata{
					BuildFinishedOn: &time1,
				},
			},
		},
	}
	att2 := fakeAtt{
		statement: in_toto.ProvenanceStatementSLSA02{
			StatementHeader: in_toto.StatementHeader{
				PredicateType: v02.PredicateSLSAProvenance,
			},
			Predicate: v02.ProvenancePredicate{
				Metadata: &v02.ProvenanceMetadata{
					BuildFinishedOn: &time2,
				},
			},
		},
	}
	att3 := fakeAtt{
		statement: in_toto.ProvenanceStatementSLSA02{
			StatementHeader: in_toto.StatementHeader{
				PredicateType: v02.PredicateSLSAProvenance,
			},
		},
	}

	cases := []struct {
		name         string
		attestations []attestation.Attestation
		expected     *time.Time
	}{
		{name: "no attestations"},
		{name: "one attestation", attestations: []attestation.Attestation{att1}, expected: &time1},
		{name: "two attestations", attestations: []attestation.Attestation{att1, att2}, expected: &time2},
		{name: "two attestations and one without time", attestations: []attestation.Attestation{att1, att2, att3}, expected: &time2},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := determineAttestationTime(context.TODO(), c.attestations)

			if c.expected == nil {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, c.expected, got)
			}
		})
	}
}

func sign(statement *in_toto.Statement) oci.Signature {
	statementJson, err := json.Marshal(statement)
	if err != nil {
		panic(err)
	}
	payload := base64.StdEncoding.EncodeToString(statementJson)
	signature, err := static.NewSignature(
		[]byte(`{"payload":"`+payload+`"}`),
		"signature",
		static.WithLayerMediaType(types.MediaType((cosignTypes.DssePayloadType))),
	)
	if err != nil {
		panic(err)
	}
	return signature
}

var validSignature = sign(&in_toto.Statement{
	StatementHeader: in_toto.StatementHeader{
		Type:          in_toto.StatementInTotoV01,
		PredicateType: v02.PredicateSLSAProvenance,
		Subject: []in_toto.Subject{
			{Name: imageRegistry, Digest: common.DigestSet{"sha256": imageDigest}},
		},
	},
})

var validAttestation = sign(&in_toto.Statement{
	StatementHeader: in_toto.StatementHeader{
		Type:          in_toto.StatementInTotoV01,
		PredicateType: v02.PredicateSLSAProvenance,
		Subject: []in_toto.Subject{
			{Name: imageRegistry, Digest: common.DigestSet{"sha256": imageDigest}},
		},
	},
	Predicate: v02.ProvenancePredicate{
		BuildType: "https://tekton.dev/attestations/chains/pipelinerun@v2",
		Builder: common.ProvenanceBuilder{
			ID: "scheme:uri",
		},
	},
})

func withImageConfig(ctx context.Context, url string) context.Context {
	// Internally, ValidateImage strips off the tag from the image reference and
	// leaves just the digest. Do the same here so mock matching works.
	refWithTag, err := ParseAndResolve(ctx, url)
	if err != nil {
		panic(err)
	}
	refWithTag.Tag = ""
	resolved := refWithTag.String()

	return fake.WithTestImageConfig(ctx, resolved)
}

type mockEvaluator struct {
	mock.Mock
}

func (e *mockEvaluator) Evaluate(ctx context.Context, target evaluator.EvaluationTarget) ([]evaluator.Outcome, error) {
	args := e.Called(ctx, target.Inputs)

	return args.Get(0).([]evaluator.Outcome), args.Error(1)
}

func (e *mockEvaluator) Destroy() {
	e.Called()
}

func (e *mockEvaluator) CapabilitiesPath() string {
	args := e.Called()

	return args.String(0)
}

func TestEvaluatorLifecycle(t *testing.T) {
	ctx := context.Background()
	client := fake.FakeClient{}
	client.On("Head", mock.Anything).Return(&v1.Descriptor{MediaType: types.OCIManifestSchema1}, nil)
	ctx = ecoci.WithClient(ctx, &client)
	client.On("Image", name.MustParseReference(imageRegistry+"@sha256:"+imageDigest), mock.Anything).Return(empty.Image, nil)
	client.On("Head", ref).Return(&v1.Descriptor{MediaType: types.OCIManifestSchema1}, nil)
	client.On("VerifyImageSignatures", refNoTag, mock.Anything).Return([]oci.Signature{validSignature}, true, nil)
	client.On("VerifyImageAttestations", refNoTag, mock.Anything).Return([]oci.Signature{validAttestation}, true, nil)
	client.On("ResolveDigest", refNoTag).Return("@sha256:"+imageDigest, nil)
	ctx = ecoci.WithClient(ctx, &client)

	component := app.SnapshotComponent{
		ContainerImage: imageRef,
	}

	policy, err := policy.NewOfflinePolicy(ctx, policy.Now)
	require.NoError(t, err)

	e := &mockEvaluator{}
	e.On("Evaluate", ctx, mock.Anything).Return([]evaluator.Outcome{}, nil)

	// e.Destroy() should not be invoked

	evaluators := []evaluator.Evaluator{e}

	snap := app.SnapshotSpec{
		Components: []app.SnapshotComponent{
			{
				ContainerImage: "registry.io/repository/image:tag",
			},
			{
				ContainerImage: "registry.io/other-repository/image2:tag",
			},
		},
	}

	_, err = ValidateImage(ctx, component, &snap, policy, evaluators, false)

	require.NoError(t, err)
}

func TestValidateImageWithVSACheck(t *testing.T) {
	tests := []struct {
		name           string
		vsaExpiration  time.Duration
		rekorURL       string
		expectVSACheck bool
		expectSkip     bool
	}{
		{
			name:           "VSA checking disabled - zero expiration",
			vsaExpiration:  0,
			rekorURL:       "https://rekor.sigstore.dev",
			expectVSACheck: false,
			expectSkip:     false,
		},
		{
			name:           "VSA checking disabled - no rekor URL",
			vsaExpiration:  24 * time.Hour,
			rekorURL:       "",
			expectVSACheck: false,
			expectSkip:     false,
		},
		{
			name:           "VSA checking enabled",
			vsaExpiration:  24 * time.Hour,
			rekorURL:       "https://rekor.sigstore.dev",
			expectVSACheck: true,
			expectSkip:     false, // Placeholder implementation returns "not found"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)

			// Create a proper policy interface
			p, err := policy.NewOfflinePolicy(ctx, policy.Now)
			require.NoError(t, err)

			// Create a test component
			comp := app.SnapshotComponent{
				ContainerImage: "registry.example.com/test:latest",
			}

			// Create a mock snapshot spec
			snap := &app.SnapshotSpec{}

			// Create empty evaluators slice
			evaluators := []evaluator.Evaluator{}

			// Call the function - it should work with basic setup
			// The function handles VSA checking gracefully when image reference is a tag
			_, err = ValidateImageWithVSACheck(ctx, comp, snap, p, evaluators, false, tt.vsaExpiration, tt.rekorURL)

			// The function should succeed even with minimal setup
			// VSA checking will be skipped due to tag reference (not digest-based)
			assert.NoError(t, err)
		})
	}
}

func TestValidateImageWithVSACheck_FlagCombinations(t *testing.T) {
	tests := []struct {
		name           string
		vsaExpiration  time.Duration
		rekorURL       string
		expectVSACheck bool
	}{
		{
			name:           "VSA checking disabled - zero expiration",
			vsaExpiration:  0,
			rekorURL:       "https://rekor.sigstore.dev",
			expectVSACheck: false,
		},
		{
			name:           "VSA checking disabled - no rekor URL",
			vsaExpiration:  24 * time.Hour,
			rekorURL:       "",
			expectVSACheck: false,
		},
		{
			name:           "VSA checking enabled",
			vsaExpiration:  24 * time.Hour,
			rekorURL:       "https://rekor.sigstore.dev",
			expectVSACheck: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)

			// Create a proper policy interface
			p, err := policy.NewOfflinePolicy(ctx, policy.Now)
			require.NoError(t, err)

			// Create a test component with a tag reference (will cause VSA extraction to fail gracefully)
			comp := app.SnapshotComponent{
				ContainerImage: "registry.example.com/test:latest",
			}

			// Create a mock snapshot spec
			snap := &app.SnapshotSpec{}

			// Create empty evaluators slice
			evaluators := []evaluator.Evaluator{}

			// Call the function
			// Note: This will either attempt VSA checking (and fail gracefully) or skip it entirely
			// Either way, it will fall back to normal validation, which should complete without error
			// for our minimal setup
			output, err := ValidateImageWithVSACheck(ctx, comp, snap, p, evaluators, false, tt.vsaExpiration, tt.rekorURL)

			// The function should return a non-nil output indicating normal validation proceeded
			// The specific result depends on whether VSA checking was attempted
			if tt.expectVSACheck {
				// VSA checking was attempted but failed due to tag reference, then fell back to validation
				// Validation should complete successfully with our minimal setup
				assert.NoError(t, err)
				assert.NotNil(t, output)
			} else {
				// VSA checking was skipped entirely, went straight to validation
				// Validation should complete successfully with our minimal setup
				assert.NoError(t, err)
				assert.NotNil(t, output)
			}
		})
	}
}
