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
	"fmt"
	"strings"
	"testing"
	"time"

	ecapi "github.com/conforma/crds/api/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	cosignTypes "github.com/sigstore/cosign/v3/pkg/types"
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
	"github.com/conforma/cli/internal/validate/vsa"
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
				c.On("HasBundles", mock.Anything, refNoTag).Return(false, nil)
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
				c.On("HasBundles", mock.Anything, refNoTag).Return(false, nil)
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
				c.On("HasBundles", mock.Anything, refNoTag).Return(false, nil)
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
			//nolint:staticcheck
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
			//nolint:staticcheck
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
			//nolint:staticcheck
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

//nolint:staticcheck
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

//nolint:staticcheck
var validSignature = sign(&in_toto.Statement{
	//nolint:staticcheck
	StatementHeader: in_toto.StatementHeader{
		Type:          in_toto.StatementInTotoV01,
		PredicateType: v02.PredicateSLSAProvenance,
		//nolint:staticcheck
		Subject: []in_toto.Subject{
			{Name: imageRegistry, Digest: common.DigestSet{"sha256": imageDigest}},
		},
	},
})

//nolint:staticcheck
var validAttestation = sign(&in_toto.Statement{
	//nolint:staticcheck
	StatementHeader: in_toto.StatementHeader{
		Type:          in_toto.StatementInTotoV01,
		PredicateType: v02.PredicateSLSAProvenance,
		//nolint:staticcheck
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
	client.On("HasBundles", mock.Anything, refNoTag).Return(false, nil)
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

// TestComponentNamePassedToEvaluator verifies that the component name from SnapshotComponent
// is correctly passed to the evaluator via EvaluationTarget.ComponentName
func TestComponentNamePassedToEvaluator(t *testing.T) {
	ctx := context.Background()
	client := fake.FakeClient{}
	client.On("Head", mock.Anything).Return(&v1.Descriptor{MediaType: types.OCIManifestSchema1}, nil)
	client.On("Image", name.MustParseReference(imageRegistry+"@sha256:"+imageDigest), mock.Anything).Return(empty.Image, nil)
	client.On("HasBundles", mock.Anything, refNoTag).Return(false, nil)
	client.On("VerifyImageSignatures", refNoTag, mock.Anything).Return([]oci.Signature{validSignature}, true, nil)
	client.On("VerifyImageAttestations", refNoTag, mock.Anything).Return([]oci.Signature{validAttestation}, true, nil)
	client.On("ResolveDigest", refNoTag).Return("@sha256:"+imageDigest, nil)
	ctx = ecoci.WithClient(ctx, &client)

	expectedComponentName := "my-test-component"
	component := app.SnapshotComponent{
		Name:           expectedComponentName,
		ContainerImage: imageRef,
	}

	p, err := policy.NewOfflinePolicy(ctx, policy.Now)
	require.NoError(t, err)

	// Create a mock evaluator that captures the EvaluationTarget
	var capturedTarget evaluator.EvaluationTarget
	e := &mockEvaluatorWithCapture{
		captureFunc: func(target evaluator.EvaluationTarget) {
			capturedTarget = target
		},
	}

	evaluators := []evaluator.Evaluator{e}

	snap := app.SnapshotSpec{
		Components: []app.SnapshotComponent{component},
	}

	_, err = ValidateImage(ctx, component, &snap, p, evaluators, false)
	require.NoError(t, err)

	// Verify that ComponentName was correctly passed to the evaluator
	assert.Equal(t, expectedComponentName, capturedTarget.ComponentName,
		"ComponentName should be passed from SnapshotComponent.Name to EvaluationTarget.ComponentName")
}

// mockEvaluatorWithCapture is a mock evaluator that captures the EvaluationTarget for verification
type mockEvaluatorWithCapture struct {
	captureFunc func(target evaluator.EvaluationTarget)
}

func (e *mockEvaluatorWithCapture) Evaluate(ctx context.Context, target evaluator.EvaluationTarget) ([]evaluator.Outcome, error) {
	if e.captureFunc != nil {
		e.captureFunc(target)
	}
	return []evaluator.Outcome{}, nil
}

func (e *mockEvaluatorWithCapture) Destroy() {}

func (e *mockEvaluatorWithCapture) CapabilitiesPath() string {
	return ""
}

// mockVSARetriever is a mock implementation of VSARetriever for testing
type mockVSARetriever struct {
	envelope *ssldsse.Envelope
	err      error
}

func (m *mockVSARetriever) RetrieveVSA(ctx context.Context, imageDigest string) (*ssldsse.Envelope, error) {
	return m.envelope, m.err
}

// createMockVSAConfig creates a VSAValidationConfig with a retriever that returns an error (no VSA found)
func createMockVSAConfig(expiration time.Duration) *vsa.VSAValidationConfig {
	return &vsa.VSAValidationConfig{
		Retriever:                   &mockVSARetriever{err: fmt.Errorf("no VSA found")},
		VSAExpiration:               expiration,
		IgnoreSignatureVerification: true,
		EffectiveTime:               "now",
	}
}

// createPassingVSAEnvelope creates a DSSE envelope containing a VSA predicate with "passed" status
// and a recent timestamp so it won't be expired.
func createPassingVSAEnvelope() *ssldsse.Envelope {
	payload := `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-image","digest":{"sha256":"abc123"}}],"predicateType":"https://conforma.dev/verification_summary/v1","predicate":{"policy":{"sources":[{"name":"test-source","policy":["test-policy"]}]},"timestamp":"` + time.Now().Add(-1*time.Hour).Format(time.RFC3339) + `","status":"passed"}}`
	return &ssldsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(payload)),
		Signatures:  []ssldsse.Signature{{KeyID: "test", Sig: "test"}},
	}
}

// createFailedVSAEnvelope creates a DSSE envelope containing a VSA predicate with "failed" status.
func createFailedVSAEnvelope() *ssldsse.Envelope {
	payload := `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-image","digest":{"sha256":"abc123"}}],"predicateType":"https://conforma.dev/verification_summary/v1","predicate":{"policy":{"sources":[{"name":"test-source","policy":["test-policy"]}]},"timestamp":"` + time.Now().Add(-1*time.Hour).Format(time.RFC3339) + `","status":"failed"}}`
	return &ssldsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(payload)),
		Signatures:  []ssldsse.Signature{{KeyID: "test", Sig: "test"}},
	}
}

func TestValidateImageWithVSACheck(t *testing.T) {
	tests := []struct {
		name       string
		vsaConfig  *vsa.VSAValidationConfig
		expectSkip bool
	}{
		{
			name:       "no VSA found - falls back to full validation",
			vsaConfig:  createMockVSAConfig(24 * time.Hour),
			expectSkip: false,
		},
		{
			name: "VSA passed - skip validation",
			vsaConfig: &vsa.VSAValidationConfig{
				Retriever:                   &mockVSARetriever{envelope: createPassingVSAEnvelope()},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
				EffectiveTime:               "now",
				PolicySpec: ecapi.EnterpriseContractPolicySpec{
					Sources: []ecapi.Source{
						{Name: "test-source", Policy: []string{"test-policy"}},
					},
				},
			},
			expectSkip: true,
		},
		{
			name: "VSA predicate failed - falls back to full validation",
			vsaConfig: &vsa.VSAValidationConfig{
				Retriever:                   &mockVSARetriever{envelope: createFailedVSAEnvelope()},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
				EffectiveTime:               "now",
			},
			expectSkip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)

			p, err := policy.NewOfflinePolicy(ctx, policy.Now)
			require.NoError(t, err)

			comp := app.SnapshotComponent{
				ContainerImage: "registry.example.com/test:latest",
			}
			snap := &app.SnapshotSpec{}
			evaluators := []evaluator.Evaluator{}

			out, err := ValidateImageWithVSACheck(ctx, comp, snap, p, evaluators, false, tt.vsaConfig)

			if tt.expectSkip {
				// VSA validation passed, output is nil (skip)
				assert.NoError(t, err)
				assert.Nil(t, out)
			} else {
				// VSA validation failed or errored, falls back to full validation
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateImageWithVSACheck_FlagCombinations(t *testing.T) {
	tests := []struct {
		name      string
		vsaConfig *vsa.VSAValidationConfig
	}{
		{
			name:      "retriever returns error - graceful fallback",
			vsaConfig: createMockVSAConfig(24 * time.Hour),
		},
		{
			name: "retriever returns nil envelope - no VSA found",
			vsaConfig: &vsa.VSAValidationConfig{
				Retriever:                   &mockVSARetriever{envelope: nil, err: nil},
				VSAExpiration:               24 * time.Hour,
				IgnoreSignatureVerification: true,
				EffectiveTime:               "now",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)

			p, err := policy.NewOfflinePolicy(ctx, policy.Now)
			require.NoError(t, err)

			comp := app.SnapshotComponent{
				ContainerImage: "registry.example.com/test:latest",
			}
			snap := &app.SnapshotSpec{}
			evaluators := []evaluator.Evaluator{}

			// All cases should fall back to full validation without error
			_, err = ValidateImageWithVSACheck(ctx, comp, snap, p, evaluators, false, tt.vsaConfig)
			assert.NoError(t, err)
		})
	}
}

func TestValidateImageSkipImageSigCheck(t *testing.T) {
	tests := []struct {
		name                 string
		skipImageSigCheck    bool
		expectImageSigResult bool
	}{
		{
			name:                 "skip image signature check disabled (default)",
			skipImageSigCheck:    false,
			expectImageSigResult: true,
		},
		{
			name:                 "skip image signature check enabled",
			skipImageSigCheck:    true,
			expectImageSigResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)

			// Create a test component with a valid SHA256 digest
			comp := app.SnapshotComponent{
				ContainerImage: imageRef, // Use the existing imageRef constant
			}

			// Set up mock image infrastructure like other tests
			ctx = withImageConfig(ctx, comp.ContainerImage)
			client := ecoci.NewClient(ctx)
			fakeClient := client.(*fake.FakeClient)

			// Set up minimal fake data for image to pass accessibility check
			// and signature/attestation checks (they will fail but create results)
			fakeClient.On("Head", ref).Return(&v1.Descriptor{MediaType: types.OCIManifestSchema1}, nil)
			fakeClient.On("HasBundles", mock.Anything, refNoTag).Return(false, nil)
			fakeClient.On("VerifyImageSignatures", refNoTag, mock.Anything).Return([]oci.Signature{}, false, fmt.Errorf("no signatures found"))
			fakeClient.On("VerifyImageAttestations", refNoTag, mock.Anything).Return([]oci.Signature{}, false, fmt.Errorf("no attestations found"))

			// Create policy options to set SkipImageSigCheck
			opts := policy.Options{
				EffectiveTime:     policy.Now,
				SkipImageSigCheck: tt.skipImageSigCheck,
				Identity: cosign.Identity{
					Issuer:  "https://example.com/oidc",
					Subject: "test@example.com",
				},
			}

			// Apply the options to create the policy
			updatedPolicy, _, err := policy.PreProcessPolicy(ctx, opts)
			require.NoError(t, err)

			// Create a mock snapshot spec
			snap := &app.SnapshotSpec{}

			// Create empty evaluators slice
			evaluators := []evaluator.Evaluator{}

			// Call ValidateImage
			output, err := ValidateImage(ctx, comp, snap, updatedPolicy, evaluators, false)

			// Validation should complete without error
			require.NoError(t, err)
			require.NotNil(t, output)

			if tt.expectImageSigResult {
				assert.NotNil(t, output.ImageSignatureCheck.Result, "Expected ImageSignatureCheck to have a result")
			} else {
				assert.Nil(t, output.ImageSignatureCheck.Result, "Expected no ImageSignatureCheck result when skipped")
			}

			assert.NotNil(t, output.AttestationSignatureCheck.Result, "AttestationSignatureCheck should always have a result")

			if tt.skipImageSigCheck {
				fakeClient.AssertNotCalled(t, "VerifyImageSignatures", mock.Anything, mock.Anything)
			} else {
				fakeClient.AssertCalled(t, "VerifyImageSignatures", refNoTag, mock.Anything)
			}
		})
	}
}

func TestValidateImageSkipAttSigCheck(t *testing.T) {
	tests := []struct {
		name               string
		skipAttSigCheck    bool
		skipImageSigCheck  bool
		fetchAttErr        error
		expectAttSigResult bool
		expectImgSigResult bool
	}{
		{
			name:               "skip attestation signature check disabled (default)",
			skipAttSigCheck:    false,
			expectAttSigResult: true,
			expectImgSigResult: true,
		},
		{
			name:               "skip attestation signature check enabled",
			skipAttSigCheck:    true,
			expectAttSigResult: false,
			expectImgSigResult: true,
		},
		{
			name:               "skip attestation signature check with fetch error",
			skipAttSigCheck:    true,
			fetchAttErr:        fmt.Errorf("registry unavailable"),
			expectAttSigResult: true,
			expectImgSigResult: true,
		},
		{
			name:               "skip both image and attestation signature checks",
			skipAttSigCheck:    true,
			skipImageSigCheck:  true,
			expectAttSigResult: false,
			expectImgSigResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := utils.WithFS(context.Background(), fs)

			comp := app.SnapshotComponent{
				ContainerImage: imageRef,
			}

			ctx = withImageConfig(ctx, comp.ContainerImage)
			client := ecoci.NewClient(ctx)
			fakeClient := client.(*fake.FakeClient)

			fakeClient.On("Head", ref).Return(&v1.Descriptor{MediaType: types.OCIManifestSchema1}, nil)
			fakeClient.On("HasBundles", mock.Anything, refNoTag).Return(false, nil)
			fakeClient.On("VerifyImageSignatures", refNoTag, mock.Anything).Return([]oci.Signature{}, false, fmt.Errorf("no signatures found"))
			fakeClient.On("VerifyImageAttestations", refNoTag, mock.Anything).Return([]oci.Signature{}, false, fmt.Errorf("no attestations found"))
			if tt.fetchAttErr != nil {
				fakeClient.On("FetchAttestationLayers", refNoTag).Return([]oci.Signature(nil), tt.fetchAttErr)
			} else {
				fakeClient.On("FetchAttestationLayers", refNoTag).Return([]oci.Signature{validAttestation}, nil)
			}

			opts := policy.Options{
				EffectiveTime:     policy.Now,
				SkipAttSigCheck:   tt.skipAttSigCheck,
				SkipImageSigCheck: tt.skipImageSigCheck,
				Identity: cosign.Identity{
					Issuer:  "https://example.com/oidc",
					Subject: "test@example.com",
				},
			}

			updatedPolicy, _, err := policy.PreProcessPolicy(ctx, opts)
			require.NoError(t, err)

			snap := &app.SnapshotSpec{}
			evaluators := []evaluator.Evaluator{}

			output, err := ValidateImage(ctx, comp, snap, updatedPolicy, evaluators, false)

			require.NoError(t, err)
			require.NotNil(t, output)

			if tt.expectAttSigResult {
				assert.NotNil(t, output.AttestationSignatureCheck.Result, "Expected AttestationSignatureCheck to have a result")
			} else {
				assert.Nil(t, output.AttestationSignatureCheck.Result, "Expected no AttestationSignatureCheck result when skipped")
			}

			if tt.expectImgSigResult {
				assert.NotNil(t, output.ImageSignatureCheck.Result, "Expected ImageSignatureCheck to have a result")
			} else {
				assert.Nil(t, output.ImageSignatureCheck.Result, "Expected no ImageSignatureCheck result when skipped")
			}

			if tt.skipAttSigCheck {
				fakeClient.AssertCalled(t, "FetchAttestationLayers", refNoTag)
				fakeClient.AssertNotCalled(t, "VerifyImageAttestations", mock.Anything, mock.Anything)
			} else {
				fakeClient.AssertCalled(t, "VerifyImageAttestations", refNoTag, mock.Anything)
				fakeClient.AssertNotCalled(t, "FetchAttestationLayers", mock.Anything)
			}
		})
	}
}
