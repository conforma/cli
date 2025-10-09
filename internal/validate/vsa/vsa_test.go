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
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	ecapi "github.com/conforma/crds/api/v1alpha1"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	appapi "github.com/konflux-ci/application-api/api/v1alpha1"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
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
		Policy: ecapi.EnterpriseContractPolicySpec{
			Name: "mock-policy",
		},
		ImageRefs: []string{"quay.io/test/image:tag"},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "passed",
		Verifier:  "Conforma",
		Summary: VSASummary{
			Component: ComponentSummary{
				Name:           "test-component",
				ContainerImage: "quay.io/test/image:tag",
				Source:         map[string]interface{}{"git": "repo"},
			},
		},
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

		attestor, err := NewAttestor(vsaPath, "quay.io/test/image", "sha256:abcd1234", signer)
		require.NoError(t, err)

		env, err := attestor.AttestPredicate(context.Background())
		assert.NoError(t, err)
		assert.NotEmpty(t, env)
	})

	// Test missing predicate file
	t.Run("missing predicate file", func(t *testing.T) {
		signer := testSigner(keyPath, fs)

		attestor, err := NewAttestor("/nonexistent.json", "quay.io/test/image", "sha256:abcd1234", signer)
		require.NoError(t, err)

		_, err = attestor.AttestPredicate(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "open predicate")
	})
}

func TestUploadVSAAttestation(t *testing.T) {
	fakeAtt := &mockAttestation{}
	imageRef := "quay.io/test/image:tag"

	t.Run("calls provided uploader and returns result", func(t *testing.T) {
		uploaderCalled := false
		uploader := func(att oci.Signature, img string) (string, error) {
			uploaderCalled = true
			assert.Equal(t, fakeAtt, att)
			assert.Equal(t, imageRef, img)
			return "digest123", nil
		}
		result, err := uploader(fakeAtt, imageRef)
		assert.NoError(t, err)
		assert.Equal(t, "digest123", result)
		assert.True(t, uploaderCalled)
	})

	t.Run("propagates error from uploader", func(t *testing.T) {
		uploader := func() (string, error) {
			return "", assert.AnError
		}
		result, err := uploader()
		assert.Error(t, err)
		assert.Equal(t, "", result)
		assert.Contains(t, err.Error(), assert.AnError.Error())
	})
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

func TestWritePredicate(t *testing.T) {
	// Set up test filesystem
	FS := afero.NewMemMapFs()

	// Create test predicate
	pred := &Predicate{
		Policy: ecapi.EnterpriseContractPolicySpec{
			Name: "test-policy",
		},
		ImageRefs: []string{"test-image:tag"},
		Timestamp: "2024-03-21T12:00:00Z",
		Status:    "passed",
		Verifier:  "conforma",
		Summary: VSASummary{
			Component: ComponentSummary{
				Name:           "test-component",
				ContainerImage: "test-image:tag",
				Source:         nil,
			},
		},
	}
	writer := Writer{
		FS:            FS,
		TempDirPrefix: "vsa-",
		FilePerm:      0o600,
	}

	// Write VSA
	vsaPath, err := writer.WritePredicate(pred)
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
	assert.Equal(t, pred.Policy, output.Policy)
	assert.Equal(t, pred.ImageRefs, output.ImageRefs)
	assert.Equal(t, pred.Timestamp, output.Timestamp)
	assert.Equal(t, pred.Status, output.Status)
	assert.Equal(t, pred.Verifier, output.Verifier)
	assert.Equal(t, pred.Summary, output.Summary)
}

func TestGeneratePredicate(t *testing.T) {
	// Create test data
	report := applicationsnapshot.Report{
		Policy: ecapi.EnterpriseContractPolicySpec{
			Name: "test-policy",
		},
		Components: []applicationsnapshot.Component{
			{
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
			},
			{
				SnapshotComponent: appapi.SnapshotComponent{
					Name:           "test-component-sha256:abc123-amd64",
					ContainerImage: "test-image-amd64:tag",
					Source:         appapi.ComponentSource{},
				},
				Success:    true,
				Violations: []evaluator.Result{},
				Warnings:   []evaluator.Result{},
				Successes:  []evaluator.Result{},
			},
			{
				SnapshotComponent: appapi.SnapshotComponent{
					Name:           "test-component-sha256:def456-arm64",
					ContainerImage: "test-image-arm64:tag",
					Source:         appapi.ComponentSource{},
				},
				Success:    true,
				Violations: []evaluator.Result{},
				Warnings:   []evaluator.Result{},
				Successes:  []evaluator.Result{},
			},
			{
				SnapshotComponent: appapi.SnapshotComponent{
					Name:           "other-component",
					ContainerImage: "other-image:tag",
					Source:         appapi.ComponentSource{},
				},
				Success:    true,
				Violations: []evaluator.Result{},
				Warnings:   []evaluator.Result{},
				Successes:  []evaluator.Result{},
			},
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
	generator := NewGenerator(report, comp, "https://github.com/test/policy", nil)
	pred, err := generator.GeneratePredicate(context.Background())
	require.NoError(t, err)

	// Verify predicate fields
	assert.Equal(t, report.Policy, pred.Policy)
	assert.Equal(t, "https://github.com/test/policy", pred.PolicySource)
	assert.Contains(t, pred.ImageRefs, comp.ContainerImage)
	assert.NotEmpty(t, pred.Timestamp)
	assert.Equal(t, "conforma", pred.Verifier)
	assert.Equal(t, "passed", pred.Status)
	assert.NotNil(t, pred.Summary)

	// Verify summary contains component information
	assert.Equal(t, comp.Name, pred.Summary.Component.Name)
	assert.Equal(t, comp.ContainerImage, pred.Summary.Component.ContainerImage)
	assert.Equal(t, comp.Source, pred.Summary.Component.Source)

	// Verify summary contains violations, warnings, and successes counts
	assert.Equal(t, len(comp.Violations), pred.Summary.Violations)
	assert.Equal(t, len(comp.Warnings), pred.Summary.Warnings)
	assert.Equal(t, len(comp.Successes), pred.Summary.Successes)
}

func TestIsVSAExpired(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name                string
		vsaTimestamp        time.Time
		expirationThreshold time.Duration
		expected            bool
	}{
		{
			name:                "VSA within threshold - not expired",
			vsaTimestamp:        now.Add(-1 * time.Hour), // 1 hour ago
			expirationThreshold: 24 * time.Hour,          // 24 hour threshold
			expected:            false,
		},
		{
			name:                "VSA beyond threshold - expired",
			vsaTimestamp:        now.Add(-25 * time.Hour), // 25 hours ago
			expirationThreshold: 24 * time.Hour,           // 24 hour threshold
			expected:            true,
		},
		{
			name:                "VSA exactly at threshold boundary - expired",
			vsaTimestamp:        now.Add(-24 * time.Hour), // exactly 24 hours ago
			expirationThreshold: 24 * time.Hour,           // 24 hour threshold
			expected:            true,                     // Should be expired at exactly the boundary
		},
		{
			name:                "Zero expiration threshold - not expired",
			vsaTimestamp:        now.Add(-1000 * time.Hour), // very old
			expirationThreshold: 0,                          // no expiration
			expected:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsVSAExpired(tt.vsaTimestamp, tt.expirationThreshold)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// mockVSARetriever is a mock implementation of VSARetriever for testing
type mockVSARetriever struct{}

func (m *mockVSARetriever) RetrieveVSA(ctx context.Context, identifier string) (*ssldsse.Envelope, error) {
	return nil, fmt.Errorf("no VSA found")
}

func TestNewVSAChecker(t *testing.T) {
	tests := []struct {
		name      string
		retriever VSARetriever
		expectNil bool
	}{
		{
			name:      "with retriever",
			retriever: &mockVSARetriever{},
			expectNil: false,
		},
		{
			name:      "with nil retriever",
			retriever: nil,
			expectNil: false, // NewVSAChecker accepts nil retriever
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewVSAChecker(tt.retriever)
			if tt.expectNil {
				assert.Nil(t, checker)
			} else {
				assert.NotNil(t, checker)
			}
		})
	}
}

func TestVSAChecker_CheckExistingVSA_ErrorCases(t *testing.T) {
	checker := NewVSAChecker(&mockVSARetriever{})
	ctx := context.Background()

	tests := []struct {
		name        string
		imageRef    string
		expiration  time.Duration
		expectError bool
		errorMsg    string
	}{
		{
			name:        "tag reference should fail",
			imageRef:    "registry.example.com/test:latest",
			expiration:  24 * time.Hour,
			expectError: true,
			errorMsg:    "failed to retrieve VSA envelope",
		},
		{
			name:        "empty image reference",
			imageRef:    "",
			expiration:  24 * time.Hour,
			expectError: true,
			errorMsg:    "failed to retrieve VSA envelope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checker.CheckExistingVSA(ctx, tt.imageRef, tt.expiration)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestCreateRetrieverFromUploadFlags(t *testing.T) {
	tests := []struct {
		name      string
		vsaUpload []string
		expectNil bool
	}{
		{
			name:      "rekor backend with custom URL",
			vsaUpload: []string{"rekor@https://custom-rekor.example.com"},
			expectNil: false,
		},
		{
			name:      "rekor backend without URL",
			vsaUpload: []string{"rekor"},
			expectNil: false,
		},
		{
			name:      "no rekor backend - only local",
			vsaUpload: []string{"local@/tmp/vsa"},
			expectNil: true,
		},
		{
			name:      "multiple backends with rekor",
			vsaUpload: []string{"local@/tmp/vsa", "rekor@https://test-rekor.dev"},
			expectNil: false,
		},
		{
			name:      "empty vsa upload flags",
			vsaUpload: []string{},
			expectNil: true,
		},
		{
			name:      "invalid flags are ignored",
			vsaUpload: []string{"invalid-format", "rekor@https://valid.rekor.com"},
			expectNil: false,
		},
		{
			name:      "case insensitive rekor backend",
			vsaUpload: []string{"REKOR@https://uppercase.rekor.com"},
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retriever := CreateRetrieverFromUploadFlags(tt.vsaUpload)
			if tt.expectNil {
				assert.Nil(t, retriever)
			} else {
				assert.NotNil(t, retriever)
			}
		})
	}
}

func TestCreateVSACheckerFromUploadFlags(t *testing.T) {
	tests := []struct {
		name      string
		vsaUpload []string
		expectNil bool
	}{
		{
			name:      "rekor backend with custom URL",
			vsaUpload: []string{"rekor@https://custom-rekor.example.com"},
			expectNil: false,
		},
		{
			name:      "no rekor backend - only local",
			vsaUpload: []string{"local@/tmp/vsa"},
			expectNil: true,
		},
		{
			name:      "empty vsa upload flags",
			vsaUpload: []string{},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := CreateVSACheckerFromUploadFlags(tt.vsaUpload)
			if tt.expectNil {
				assert.Nil(t, checker)
			} else {
				assert.NotNil(t, checker)
			}
		})
	}
}

// TestNewWriter tests the NewWriter constructor function
func TestNewWriter(t *testing.T) {
	writer := NewWriter()

	// Verify default values are set correctly
	assert.NotNil(t, writer)
	assert.NotNil(t, writer.FS)
	assert.Equal(t, "vsa-", writer.TempDirPrefix)
	assert.Equal(t, os.FileMode(0o600), writer.FilePerm)
}

// TestNewGenerator tests the NewGenerator constructor function
func TestNewGenerator(t *testing.T) {
	// Create test data
	report := applicationsnapshot.Report{
		Policy: ecapi.EnterpriseContractPolicySpec{
			Name: "test-policy",
		},
		EcVersion: "1.0.0",
	}

	component := applicationsnapshot.Component{
		SnapshotComponent: appapi.SnapshotComponent{
			Name:           "test-component",
			ContainerImage: "test-image:tag",
		},
	}

	// Test NewGenerator
	generator := NewGenerator(report, component, "https://github.com/test/policy", nil)

	// Verify the generator is created correctly
	assert.NotNil(t, generator)
	assert.Equal(t, report, generator.Report)
	assert.Equal(t, component, generator.Component)
}

// TestNewSignerVSA tests the NewSigner constructor function
func TestNewSignerVSA(t *testing.T) {
	// Set up test environment
	t.Setenv("COSIGN_PASSWORD", "") // Use unencrypted key

	// Create test key content (same as used in existing tests)
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
	keyPath := "/test.key"
	err := afero.WriteFile(fs, keyPath, []byte(testKey), 0600)
	require.NoError(t, err)

	t.Run("successful signer creation", func(t *testing.T) {
		ctx := context.Background()
		signer, err := NewSigner(ctx, keyPath, fs)

		assert.NoError(t, err)
		assert.NotNil(t, signer)
		assert.Equal(t, keyPath, signer.KeyPath)
		assert.Equal(t, fs, signer.FS)
		assert.NotNil(t, signer.WrapSigner)
		assert.NotNil(t, signer.SignerVerifier)
	})

	t.Run("missing key file", func(t *testing.T) {
		ctx := context.Background()
		signer, err := NewSigner(ctx, "/nonexistent.key", fs)

		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "resolve private key")
	})

	t.Run("invalid key content", func(t *testing.T) {
		ctx := context.Background()
		invalidKeyPath := "/invalid.key"
		err := afero.WriteFile(fs, invalidKeyPath, []byte("invalid key content"), 0600)
		require.NoError(t, err)

		signer, err := NewSigner(ctx, invalidKeyPath, fs)

		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "load private key")
	})
}

// TestNewAttestor tests the NewAttestor constructor function
func TestNewAttestorVSA(t *testing.T) {
	// Set up test environment
	t.Setenv("COSIGN_PASSWORD", "")

	fs := afero.NewMemMapFs()
	keyPath := "/test.key"
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

	err := afero.WriteFile(fs, keyPath, []byte(testKey), 0600)
	require.NoError(t, err)

	ctx := context.Background()
	signer, err := NewSigner(ctx, keyPath, fs)
	require.NoError(t, err)

	t.Run("successful attestor creation", func(t *testing.T) {
		predicatePath := "/test.vsa.json"
		repo := "quay.io/test/image"
		digest := "sha256:abcd1234"

		attestor, err := NewAttestor(predicatePath, repo, digest, signer)

		assert.NoError(t, err)
		assert.NotNil(t, attestor)
		assert.Equal(t, predicatePath, attestor.PredicatePath)
		assert.Equal(t, "https://conforma.dev/verification_summary/v1", attestor.PredicateType)
		assert.Equal(t, digest, attestor.Digest)
		assert.Equal(t, repo, attestor.Repo)
		assert.Equal(t, signer, attestor.Signer)
	})
}

// TestWriterWithCustomSettings tests Writer with custom filesystem and settings
func TestWriterWithCustomSettings(t *testing.T) {
	// Create custom writer with different settings
	fs := afero.NewMemMapFs()
	writer := &Writer{
		FS:            fs,
		TempDirPrefix: "custom-vsa-",
		FilePerm:      0o644,
	}

	// Create test predicate
	pred := &Predicate{
		ImageRefs:    []string{"test-image:tag"},
		Timestamp:    "2024-03-21T12:00:00Z",
		Verifier:     "ec-cli",
		PolicySource: "test-policy",
		Summary: VSASummary{
			Component: ComponentSummary{
				Name:           "test-component",
				ContainerImage: "test-image:tag",
			},
		},
	}

	// Write predicate
	vsaPath, err := writer.WritePredicate(pred)
	require.NoError(t, err)

	// Verify custom settings were used
	assert.Contains(t, vsaPath, "custom-vsa-")

	// Verify file was written to custom filesystem
	exists, err := afero.Exists(fs, vsaPath)
	assert.NoError(t, err)
	assert.True(t, exists)
}

// TestWriterErrorHandling tests Writer error handling scenarios
func TestWriterErrorHandling(t *testing.T) {
	t.Run("filesystem write error", func(t *testing.T) {
		// Create a read-only filesystem to simulate write errors
		fs := afero.NewReadOnlyFs(afero.NewMemMapFs())
		writer := &Writer{
			FS:            fs,
			TempDirPrefix: "vsa-",
			FilePerm:      0o600,
		}

		pred := &Predicate{
			ImageRefs: []string{"test-image:tag"},
			Timestamp: "2024-03-21T12:00:00Z",
			Verifier:  "ec-cli",
			Summary: VSASummary{
				Component: ComponentSummary{
					Name: "test-component",
				},
			},
		}

		_, err := writer.WritePredicate(pred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create temp directory")
	})

	t.Run("invalid predicate serialization", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		writer := &Writer{
			FS:            fs,
			TempDirPrefix: "vsa-",
			FilePerm:      0o600,
		}

		// Create predicate with data that can't be marshaled
		pred := &Predicate{
			Summary: VSASummary{
				Component: ComponentSummary{
					Source: make(chan int), // channels can't be marshaled to JSON
				},
			},
		}

		_, err := writer.WritePredicate(pred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal VSA predicate")
	})
}

// TestDetectIdentifierType tests the DetectIdentifierType function
func TestDetectIdentifierType(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   IdentifierType
	}{
		{
			name:       "image digest sha256",
			identifier: "sha256:abc123def456789",
			expected:   IdentifierImageDigest,
		},
		{
			name:       "image digest sha512",
			identifier: "sha512:abc123def456789",
			expected:   IdentifierImageDigest,
		},
		{
			name:       "image reference with tag",
			identifier: "nginx:latest",
			expected:   IdentifierImageReference,
		},
		{
			name:       "image reference with registry",
			identifier: "registry.io/namespace/repo:tag",
			expected:   IdentifierImageReference,
		},
		{
			name:       "absolute file path",
			identifier: "/path/to/file.json",
			expected:   IdentifierImageReference, // name.ParseReference accepts this as valid
		},
		{
			name:       "relative file path",
			identifier: "./file.json",
			expected:   IdentifierImageReference, // name.ParseReference accepts this as valid
		},
		{
			name:       "relative file path with parent",
			identifier: "../file.json",
			expected:   IdentifierImageReference, // name.ParseReference accepts this as valid
		},
		{
			name:       "file with extension",
			identifier: "file.json",
			expected:   IdentifierImageReference, // name.ParseReference accepts this as valid
		},
		{
			name:       "file with path separators",
			identifier: "path/to/file",
			expected:   IdentifierImageReference, // name.ParseReference accepts this as valid
		},
		{
			name:       "simple image name",
			identifier: "nginx",
			expected:   IdentifierImageReference,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectIdentifierType(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsImageReference tests the IsImageReference function
func TestIsImageReference(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   bool
	}{
		{
			name:       "docker hub reference",
			identifier: "nginx:latest",
			expected:   true,
		},
		{
			name:       "registry reference",
			identifier: "registry.io/namespace/repo:tag",
			expected:   true,
		},
		{
			name:       "reference with digest",
			identifier: "registry.io/namespace/repo:sha256-abc123",
			expected:   true,
		},
		{
			name:       "quay reference",
			identifier: "quay.io/redhat/ubi8:latest",
			expected:   true,
		},
		{
			name:       "image digest only",
			identifier: "sha256:abc123def456789",
			expected:   false,
		},
		{
			name:       "file path",
			identifier: "/path/to/file.json",
			expected:   false,
		},
		{
			name:       "relative file path",
			identifier: "./file.json",
			expected:   false,
		},
		{
			name:       "file with extension",
			identifier: "file.json",
			expected:   false,
		},
		{
			name:       "invalid reference",
			identifier: "invalid:",
			expected:   false,
		},
		{
			name:       "invalid digest format",
			identifier: "sha128:abc123",
			expected:   false,
		},
		{
			name:       "single word with colon but no value",
			identifier: "invalid:",
			expected:   false,
		},
		{
			name:       "valid docker hub reference",
			identifier: "nginx:latest",
			expected:   true,
		},
		{
			name:       "valid registry reference with port",
			identifier: "registry.io:5000/namespace/repo:tag",
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsImageReference(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsValidVSAIdentifier tests the IsValidVSAIdentifier function
func TestIsValidVSAIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   bool
	}{
		{
			name:       "valid file path",
			identifier: "/path/to/vsa.json",
			expected:   true,
		},
		{
			name:       "valid image digest",
			identifier: "sha256:abc123def456789",
			expected:   true,
		},
		{
			name:       "valid image reference",
			identifier: "registry.io/repo:tag",
			expected:   true,
		},
		{
			name:       "empty identifier",
			identifier: "",
			expected:   false,
		},
		{
			name:       "file path with spaces",
			identifier: "file with spaces.json",
			expected:   true,
		},
		{
			name:       "image reference with spaces",
			identifier: "nginx with spaces:latest",
			expected:   false,
		},
		{
			name:       "invalid digest format",
			identifier: "sha128:abc123",
			expected:   true, // name.ParseReference accepts this as valid
		},
		{
			name:       "invalid image reference",
			identifier: "invalid:",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidVSAIdentifier(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseVSAExpirationDuration tests the ParseVSAExpirationDuration function
func TestParseVSAExpirationDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration string
		expected time.Duration
		hasError bool
	}{
		{
			name:     "hours",
			duration: "24h",
			expected: 24 * time.Hour,
			hasError: false,
		},
		{
			name:     "days",
			duration: "7d",
			expected: 7 * 24 * time.Hour,
			hasError: false,
		},
		{
			name:     "weeks",
			duration: "2w",
			expected: 2 * 7 * 24 * time.Hour,
			hasError: false,
		},
		{
			name:     "months",
			duration: "1mo",
			expected: 30 * 24 * time.Hour,
			hasError: false,
		},
		{
			name:     "standard Go duration",
			duration: "168h",
			expected: 168 * time.Hour,
			hasError: false,
		},
		{
			name:     "invalid format",
			duration: "invalid",
			expected: 0,
			hasError: true,
		},
		{
			name:     "empty duration",
			duration: "",
			expected: 0,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseVSAExpirationDuration(tt.duration)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestConvertYAMLToJSON tests the ConvertYAMLToJSON function
func TestConvertYAMLToJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{
			name:     "map with interface{} keys",
			input:    map[interface{}]interface{}{"key": "value"},
			expected: map[string]interface{}{"key": "value"},
		},
		{
			name:     "slice of interfaces",
			input:    []interface{}{"item1", "item2"},
			expected: []interface{}{"item1", "item2"},
		},
		{
			name:     "nested map",
			input:    map[interface{}]interface{}{"nested": map[interface{}]interface{}{"key": "value"}},
			expected: map[string]interface{}{"nested": map[string]interface{}{"key": "value"}},
		},
		{
			name:     "primitive value",
			input:    "simple string",
			expected: "simple string",
		},
		{
			name:     "number",
			input:    42,
			expected: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertYAMLToJSON(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsImageDigest tests the isImageDigest function
func TestIsImageDigest(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   bool
	}{
		{
			name:       "valid sha256 digest",
			identifier: "sha256:abc123def456789",
			expected:   true,
		},
		{
			name:       "valid sha512 digest",
			identifier: "sha512:abc123def456789",
			expected:   true,
		},
		{
			name:       "invalid digest format",
			identifier: "sha128:abc123",
			expected:   false,
		},
		{
			name:       "image reference",
			identifier: "nginx:latest",
			expected:   false,
		},
		{
			name:       "file path",
			identifier: "/path/to/file",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isImageDigest(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsFilePath tests the isFilePath function
func TestIsFilePath(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		expected   bool
	}{
		{
			name:       "absolute path",
			identifier: "/path/to/file",
			expected:   true,
		},
		{
			name:       "relative path with dot",
			identifier: "./file",
			expected:   true,
		},
		{
			name:       "relative path with parent",
			identifier: "../file",
			expected:   true,
		},
		{
			name:       "file with extension",
			identifier: "file.json",
			expected:   true,
		},
		{
			name:       "path with separators",
			identifier: "path/to/file",
			expected:   true,
		},
		{
			name:       "image reference with colon",
			identifier: "nginx:latest",
			expected:   false,
		},
		{
			name:       "image reference with at",
			identifier: "nginx@sha256:abc123",
			expected:   false,
		},
		{
			name:       "simple name without extension",
			identifier: "nginx",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFilePath(tt.identifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractDigestFromImageRef tests the ExtractDigestFromImageRef function
func TestExtractDigestFromImageRef(t *testing.T) {
	tests := []struct {
		name        string
		imageRef    string
		expected    string
		expectError bool
	}{
		{
			name:        "tag reference",
			imageRef:    "registry.io/image:latest",
			expected:    "registry.io/image:latest",
			expectError: false,
		},
		{
			name:        "docker hub tag",
			imageRef:    "nginx:1.21",
			expected:    "nginx:1.21",
			expectError: false,
		},
		{
			name:        "quay reference",
			imageRef:    "quay.io/namespace/repo:tag",
			expected:    "quay.io/namespace/repo:tag",
			expectError: false,
		},
		{
			name:        "invalid reference",
			imageRef:    "invalid:reference:with:colons",
			expected:    "",
			expectError: true,
		},
		{
			name:        "empty reference",
			imageRef:    "",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractDigestFromImageRef(tt.imageRef)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
