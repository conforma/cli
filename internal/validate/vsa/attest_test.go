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

// internal/validate/vsa/attest_test.go
package vsa

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/afero"
)

// testSigner creates a mock signer for testing that bypasses expensive crypto operations
func testSigner(keyPath string, fs afero.Fs) *Signer {
	return &Signer{
		KeyPath:        keyPath,
		FS:             fs,
		WrapSigner:     &fakeSigner{},
		SignerVerifier: &fakeSigner{},
	}
}

// fakeSigner implements signature.SignerVerifier for fast in-memory signing.
type fakeSigner struct{}

func (f *fakeSigner) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	// Return a mock ECDSA public key for testing
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(1),
		Y:     big.NewInt(1),
	}, nil
}

// SignMessage must match signature.SignerVerifier:
//
//	SignMessage(io.Reader, ...SignOption) ([]byte, error)
func (f *fakeSigner) SignMessage(rawMessage io.Reader, opts ...signature.SignOption) ([]byte, error) {
	env := struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	}{
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"predicateType":"https://conforma.dev/verification_summary/v1"}`)),
		PayloadType: types.IntotoPayloadType,
	}
	return json.Marshal(env)
}

// VerifySignature must match signature.SignerVerifier:
//
//	VerifySignature(signature, message io.Reader, ...VerifyOption) error
func (f *fakeSigner) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	return nil
}

// Unencrypted test key for testing (proper SIGSTORE format)
const testECKey = `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----
eyJrZGYiOnsibmFtZSI6InNjcnlwdCIsInBhcmFtcyI6eyJOIjo2NTUzNiwiciI6
OCwicCI6MX0sInNhbHQiOiJKK0NwVkQ3RnE5OVhNNjdScFFweG1QUlBIWFZxMVpS
a0RuN0hva1V4aDl3PSJ9LCJjaXBoZXIiOnsibmFtZSI6Im5hY2wvc2VjcmV0Ym94
Iiwibm9uY2UiOiJhVHdJeEdrOHMvaUdHUGJqRW9wUkJackM4K0xHVmFEOSJ9LCJj
aXBoZXJ0ZXh0IjoiRyt1eFU4K0tvMnpCdklRajhWc0d2bnZ2MDFHaVladU9zR3pY
OW1kTGNGZGRlYUNEcnFkc2UrQk4wR0lROERmNWtQV2JuQWxXMnhqcTNCL1piZzNH
VmJYSEhwK0o5NGxKc1RFQ0U4U1hpTkxaOGVJSGFwQkVrTDc1Mk5xMCtZMkRSbjVy
azNoSXRYaHBLYWxueEY5S0lqNFR1YkRiRHo1MGlWd1I2MkdSWlJPaFRYa0dEOXNr
RGNWMnRvTWdxSVlNQ2N6bzVMRU4weEhEM3c9PSJ9
-----END ENCRYPTED SIGSTORE PRIVATE KEY-----`

const (
	digest = "sha256:000000000000000000000000000000000000000000000000000000000000d00d"
	repo   = "example.com/acme/widget"
)

func TestNewSigner(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "")

	cases := []struct {
		name      string
		prepare   func(tmp string) (afero.Fs, string)
		expectErr bool
	}{
		{
			name: "success",
			prepare: func(tmp string) (afero.Fs, string) {
				fs := afero.NewMemMapFs()
				key := filepath.Join(tmp, "cosign.key")
				err := afero.WriteFile(fs, key, []byte(testECKey), 0o600)
				if err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return fs, key
			},
		},
		{
			name: "missing-key",
			prepare: func(tmp string) (afero.Fs, string) {
				fs := afero.NewMemMapFs()
				return fs, filepath.Join(tmp, "no.key")
			},
			expectErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			fs, keyPath := tc.prepare(tmp)

			if tc.expectErr {
				_, err := NewSigner(keyPath, fs)
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			// Mock the loadPrivateKey function for success cases to avoid expensive decryption
			originalLoadPrivateKey := LoadPrivateKey
			defer func() { LoadPrivateKey = originalLoadPrivateKey }()

			LoadPrivateKey = func(keyBytes, password []byte, defaultLoadOptions *[]signature.LoadOption) (signature.SignerVerifier, error) {
				return &fakeSigner{}, nil
			}

			signer, err := NewSigner(keyPath, fs)

			// For success cases, verify all fields are properly set
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if signer.WrapSigner == nil {
				t.Errorf("WrapSigner should not be nil")
			}

			if signer.SignerVerifier == nil {
				t.Errorf("SignerVerifier should not be nil")
			}

			if signer.KeyPath != keyPath {
				t.Errorf("KeyPath mismatch: got %s, want %s", signer.KeyPath, keyPath)
			}

			if signer.FS != fs {
				t.Errorf("FS should be set")
			}

			// Verify SignerVerifier can be used to get public key
			pubKey, err := signer.SignerVerifier.PublicKey()
			if err != nil {
				t.Errorf("SignerVerifier.PublicKey() failed: %v", err)
			}
			if pubKey == nil {
				t.Errorf("SignerVerifier.PublicKey() returned nil")
			}
		})
	}
}

func TestNewAttestor(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "")

	tmp := t.TempDir()
	fs := afero.NewMemMapFs()
	key := filepath.Join(tmp, "cosign.key")
	err := afero.WriteFile(fs, key, []byte(testECKey), 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	pred := filepath.Join(tmp, "vsa.json")

	signer := testSigner(key, fs)
	attestor, err := NewAttestor(pred, repo, digest, signer)
	if err != nil {
		t.Fatalf("NewAttestor: %v", err)
	}
	if attestor.PredicatePath != pred {
		t.Errorf("PredicatePath=%q, want %q", attestor.PredicatePath, pred)
	}
}

func TestAttestPredicate(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "")

	cases := []struct {
		name      string
		prepare   func(tmp string) (Attestor, error)
		expectErr bool
	}{
		{
			name: "success",
			prepare: func(tmp string) (Attestor, error) {
				fs := afero.NewMemMapFs()
				pred := filepath.Join(tmp, "vsa.json")
				err := afero.WriteFile(fs, pred, []byte(`{"hello":"world"}`), 0o600)
				if err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				key := filepath.Join(tmp, "cosign.key")
				err = afero.WriteFile(fs, key, []byte(testECKey), 0o600)
				if err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				signer := testSigner(key, fs)
				return Attestor{
					PredicatePath: pred,
					PredicateType: "https://enterprisecontract.dev/attestations/vsa/v1",
					Digest:        digest,
					Repo:          repo,
					Signer:        signer,
				}, nil
			},
		},
		{
			name: "missing-predicate",
			prepare: func(tmp string) (Attestor, error) {
				fs := afero.NewMemMapFs()
				key := filepath.Join(tmp, "cosign.key")
				err := afero.WriteFile(fs, key, []byte(testECKey), 0o600)
				if err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				signer := testSigner(key, fs)
				return Attestor{
					PredicatePath: filepath.Join(tmp, "no.json"),
					PredicateType: "https://enterprisecontract.dev/attestations/vsa/v1",
					Digest:        digest,
					Repo:          repo,
					Signer:        signer,
				}, nil
			},
			expectErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			opts, err := tc.prepare(tmp)
			if err != nil {
				t.Fatalf("test preparation failed: %v", err)
			}

			env, err := opts.AttestPredicate(context.Background())
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error from AttestPredicate")
				}
				return
			}
			if err != nil {
				t.Fatalf("AttestPredicate: %v", err)
			}
			if len(env) == 0 {
				t.Fatal("empty envelope")
			}
			var e struct {
				Payload     string `json:"payload"`
				PayloadType string `json:"payloadType"`
			}
			if err := json.Unmarshal(env, &e); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
		})
	}
}

func TestTargetDigest(t *testing.T) {
	tests := []struct {
		name           string
		attestor       Attestor
		expectedDigest string
	}{
		{
			name: "valid sha256 digest",
			attestor: Attestor{
				Digest: "sha256:abc123def456789012345678901234567890123456789012345678901234567890",
			},
			expectedDigest: "sha256:abc123def456789012345678901234567890123456789012345678901234567890",
		},
		{
			name: "different valid digest",
			attestor: Attestor{
				Digest: "sha256:fedcba0987654321098765432109876543210987654321098765432109876543",
			},
			expectedDigest: "sha256:fedcba0987654321098765432109876543210987654321098765432109876543",
		},
		{
			name: "empty digest",
			attestor: Attestor{
				Digest: "",
			},
			expectedDigest: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attestor.TargetDigest()
			if result != tt.expectedDigest {
				t.Errorf("TargetDigest() = %q, want %q", result, tt.expectedDigest)
			}
		})
	}
}

func TestWriteEnvelope(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "")

	tmp := t.TempDir()
	fs := afero.NewMemMapFs()
	pred := filepath.Join(tmp, "vsa.json")
	err := afero.WriteFile(fs, pred, []byte(`{"hello":"world"}`), 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	key := filepath.Join(tmp, "cosign.key")
	err = afero.WriteFile(fs, key, []byte(testECKey), 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	signer := testSigner(key, fs)
	attestor, _ := NewAttestor(pred, repo, digest, signer)
	env, _ := attestor.AttestPredicate(context.Background())

	out, err := attestor.WriteEnvelope(env)
	if err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}
	if !filepath.IsAbs(out) {
		t.Errorf("expected abs path, got %q", out)
	}
}
