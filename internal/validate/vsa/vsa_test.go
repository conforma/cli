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
	"crypto/x509"
	"encoding/json"
	"io"
	"testing"
	"time"

	ecapi "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	appapi "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/applicationsnapshot"
	"github.com/conforma/cli/internal/evaluator"
)

// TestSignVSA tests the signing functionality using the new Signer structure from attest.go.
func TestSignVSA(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "") // key is unencrypted

	// Create test key content
	testKey := `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----
eyJrZGYiOnsibmFtZSI6InNjcnlwdCIsInBhcmFtcyI6eyJOIjo2NTUzNiwiciI6
OCwicCI6MX0sInNhbHQiOiJLYU9OQzduQVJLOVgxM1FoaWFucjAwTTBGYys2Sitr
dnAxN1FuanpiVk9nPSJ9LCJjaXBoZXIiOnsibmFtZSI6Im5hY2wvc2VjcmV0Ym94
Iiwibm9uY2UiOiJVOHZqWWtqMlZOUFZGdlZFZWZ3bXZ5VGloUERrelBoaCJ9LCJj
aXBoZXJ0ZXh0IjoidWNWMnQ4TTZVNFJvb29FOXc0d3dkc3E1RDYrS2RKY245dERT
KzFwRDRGN040SVJOWEgzSTBua3h1a3NackFOUHR1emIvTkVYQ201dUp3Zjh3Qzl1
VlprbXdwNU5jRUZ6b3ZNS3JCZmNvdXdjaEkrMzkrQ0NhbVZPbzBucmRnZjhvcmpK
dXdrWDBYL1phY0RUTERGaUxyc1laMWVMMmlqMGU1MVRpZmVQNTl4WXNPK1FnM1Jv
OURRVjNQMk9ndDFDaVFHeGg1VXhUZytGc3c9PSJ9
-----END ENCRYPTED SIGSTORE PRIVATE KEY-----`

	// Set up test filesystem
	fs := afero.NewMemMapFs()

	// Create test predicate
	pred := &Predicate{
		ImageRef:         "quay.io/test/image:tag",
		ValidationResult: "passed",
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Verifier:         "Conforma",
		PolicySource:     "mock-policy",
		Component: map[string]interface{}{
			"name":           "test-component",
			"containerImage": "quay.io/test/image:tag",
			"source":         map[string]interface{}{"git": "repo"},
		},
		RuleResults: []evaluator.Result{{Message: "violation1"}},
	}

	// Write test files
	vsaPath := "/test.vsa.json"
	data, _ := json.Marshal(pred)
	err := afero.WriteFile(fs, vsaPath, data, 0600)
	assert.NoError(t, err)

	keyPath := "/test.key"
	err = afero.WriteFile(fs, keyPath, []byte(testKey), 0600)
	assert.NoError(t, err)

	// Test successful signing
	t.Run("successful signing", func(t *testing.T) {
		signer := testSigner(keyPath, fs)

		opts, err := NewAttestOptions(vsaPath, "quay.io/test/image", "sha256:abcd1234", signer)
		require.NoError(t, err)

		env, err := opts.AttestPredicate(context.Background())
		assert.NoError(t, err)
		assert.NotEmpty(t, env)
	})

	// Test missing predicate file
	t.Run("missing predicate file", func(t *testing.T) {
		signer := testSigner(keyPath, fs)

		opts, err := NewAttestOptions("/nonexistent.json", "quay.io/test/image", "sha256:abcd1234", signer)
		require.NoError(t, err)

		_, err = opts.AttestPredicate(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "open predicate")
	})
}

func TestUploadVSAAttestation(t *testing.T) {
	fakeAtt := &mockAttestation{}
	imageRef := "quay.io/test/image:tag"
	ctx := context.Background()

	t.Run("calls provided uploader and returns result", func(t *testing.T) {
		uploaderCalled := false
		uploader := func(ctx context.Context, att oci.Signature, img string) (string, error) {
			uploaderCalled = true
			assert.Equal(t, fakeAtt, att)
			assert.Equal(t, imageRef, img)
			return "digest123", nil
		}
		result, err := uploader(ctx, fakeAtt, imageRef)
		assert.NoError(t, err)
		assert.Equal(t, "digest123", result)
		assert.True(t, uploaderCalled)
	})

	t.Run("propagates error from uploader", func(t *testing.T) {
		uploader := func(ctx context.Context, att oci.Signature, img string) (string, error) {
			return "", assert.AnError
		}
		result, err := uploader(ctx, fakeAtt, imageRef)
		assert.Error(t, err)
		assert.Equal(t, "", result)
		assert.Contains(t, err.Error(), assert.AnError.Error())
	})
}

func TestNoopUploader(t *testing.T) {
	result, err := NoopUploader(context.Background(), &mockAttestation{}, "img")
	assert.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestOCIUploader(t *testing.T) {
	result, err := OCIUploader(context.Background(), &mockAttestation{}, "img")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OCI upload not implemented")
	assert.Equal(t, "", result)
}

func TestRekorUploader(t *testing.T) {
	result, err := RekorUploader(context.Background(), &mockAttestation{}, "img")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rekor upload not implemented")
	assert.Equal(t, "", result)
}

type mockAttestation struct{}

func (m *mockAttestation) Digest() (v1.Hash, error)                            { return v1.Hash{}, nil }
func (m *mockAttestation) Payload() ([]byte, error)                            { return nil, nil }
func (m *mockAttestation) SetAnnotations(map[string]string) error              { return nil }
func (m *mockAttestation) Annotations() (map[string]string, error)             { return nil, nil }
func (m *mockAttestation) SetLayerMediaType(string) error                      { return nil }
func (m *mockAttestation) LayerMediaType() (string, error)                     { return "", nil }
func (m *mockAttestation) SetPayload([]byte, string) error                     { return nil }
func (m *mockAttestation) SetSignature([]byte) error                           { return nil }
func (m *mockAttestation) Signature() ([]byte, error)                          { return nil, nil }
func (m *mockAttestation) SetCert([]byte) error                                { return nil }
func (m *mockAttestation) Cert() (*x509.Certificate, error)                    { return nil, nil }
func (m *mockAttestation) SetChain([][]byte) error                             { return nil }
func (m *mockAttestation) Chain() ([]*x509.Certificate, error)                 { return nil, nil }
func (m *mockAttestation) SetBundle([]byte) error                              { return nil }
func (m *mockAttestation) Bundle() (*bundle.RekorBundle, error)                { return nil, nil }
func (m *mockAttestation) SetDSSEEnvelope([]byte) error                        { return nil }
func (m *mockAttestation) DSSEEnvelope() ([]byte, error)                       { return nil, nil }
func (m *mockAttestation) Base64Signature() (string, error)                    { return "", nil }
func (m *mockAttestation) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) { return nil, nil }
func (m *mockAttestation) Compressed() (io.ReadCloser, error)                  { return nil, nil }
func (m *mockAttestation) Uncompressed() (io.ReadCloser, error)                { return nil, nil }
func (m *mockAttestation) Size() (int64, error)                                { return 0, nil }
func (m *mockAttestation) DiffID() (v1.Hash, error)                            { return v1.Hash{}, nil }
func (m *mockAttestation) MediaType() (v1types.MediaType, error)               { return v1types.MediaType(""), nil }

func TestWriteVSA(t *testing.T) {
	// Set up test filesystem
	FS := afero.NewMemMapFs()

	// Create test predicate
	pred := &Predicate{
		ImageRef:         "test-image:tag",
		ValidationResult: "passed",
		Timestamp:        "2024-03-21T12:00:00Z",
		Verifier:         "ec-cli",
		PolicySource:     "test-policy",
		Component: map[string]interface{}{
			"name":           "test-component",
			"containerImage": "test-image:tag",
			"source":         nil,
		},
		RuleResults: []evaluator.Result{
			{
				Message:  "Test rule passed",
				Metadata: map[string]interface{}{"code": "TEST-001"},
			},
		},
	}
	writer := Writer{
		FS:            FS,
		TempDirPrefix: "vsa-",
		FilePerm:      0o600,
	}

	// Write VSA
	vsaPath, err := writer.WriteVSA(pred)
	require.NoError(t, err)

	// Verify path format
	assert.Contains(t, vsaPath, "vsa-")

	// Read and verify contents
	data, err := afero.ReadFile(FS, vsaPath)
	require.NoError(t, err)

	var output Predicate
	err = json.Unmarshal(data, &output)
	require.NoError(t, err)

	// Verify fields
	assert.Equal(t, pred.ImageRef, output.ImageRef)
	assert.Equal(t, pred.ValidationResult, output.ValidationResult)
	assert.Equal(t, pred.Timestamp, output.Timestamp)
	assert.Equal(t, pred.Verifier, output.Verifier)
	assert.Equal(t, pred.PolicySource, output.PolicySource)
	assert.Equal(t, pred.Component, output.Component)
	assert.Equal(t, pred.RuleResults, output.RuleResults)
}

func TestGeneratePredicate(t *testing.T) {
	// Create test data
	report := applicationsnapshot.Report{
		Policy: ecapi.EnterpriseContractPolicySpec{
			Name: "test-policy",
		},
	}

	comp := applicationsnapshot.Component{
		SnapshotComponent: appapi.SnapshotComponent{
			Name:           "test-component",
			ContainerImage: "test-image:tag",
			Source:         appapi.ComponentSource{},
		},
		Success:    true,
		Violations: []evaluator.Result{},
		Warnings:   []evaluator.Result{},
		Successes: []evaluator.Result{
			{
				Message:  "Test rule passed",
				Metadata: map[string]interface{}{"code": "TEST-001"},
			},
		},
	}

	// Create generator and generate predicate
	generator := NewGenerator(report)
	pred, err := generator.GeneratePredicate(context.Background(), comp)
	require.NoError(t, err)

	// Verify predicate fields
	assert.Equal(t, comp.ContainerImage, pred.ImageRef)
	assert.Equal(t, "passed", pred.ValidationResult)
	assert.NotEmpty(t, pred.Timestamp)
	assert.Equal(t, "ec-cli", pred.Verifier)
	assert.Equal(t, report.Policy.Name, pred.PolicySource)
	assert.Equal(t, comp.Name, pred.Component["name"])
	assert.Equal(t, comp.ContainerImage, pred.Component["containerImage"])
	assert.Equal(t, comp.Source, pred.Component["source"])
	assert.Equal(t, comp.Successes, pred.RuleResults)
}
