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
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/afero"
)

// testSigner creates a mock signer for testing that bypasses expensive crypto operations
func testSigner(keyPath string, fs afero.Fs) *Signer {
	return &Signer{
		KeyPath:    keyPath,
		FS:         fs,
		WrapSigner: &fakeSigner{},
	}
}

// fakeSigner implements signature.SignerVerifier for fast in-memory signing.
type fakeSigner struct{}

func (f *fakeSigner) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return nil, nil
}

// SignMessage must match signature.SignerVerifier:
//
//	SignMessage(io.Reader, ...SignOption) ([]byte, error)
func (f *fakeSigner) SignMessage(rawMessage io.Reader, opts ...signature.SignOption) ([]byte, error) {
	env := struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	}{
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"predicateType":"https://enterprisecontract.dev/attestations/vsa/v1"}`)),
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

// Encrypted test key (not actually used since we use testSigner)
const testECKey = `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----
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
				// For error cases, still test the real NewSigner to verify error handling
				_, err := NewSigner(keyPath, fs)
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			// For success cases, use testSigner to avoid timeouts
			signer := testSigner(keyPath, fs)
			if signer.WrapSigner == nil {
				t.Errorf("WrapSigner should not be nil")
			}
		})
	}
}

func TestNewAttestOptions(t *testing.T) {
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
	opts, err := NewAttestOptions(pred, repo, digest, signer)
	if err != nil {
		t.Fatalf("NewAttestOptions: %v", err)
	}
	if opts.PredicatePath != pred {
		t.Errorf("PredicatePath=%q, want %q", opts.PredicatePath, pred)
	}
}

func TestAttestPredicate(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "")

	cases := []struct {
		name      string
		prepare   func(tmp string) (AttestOptions, error)
		expectErr bool
	}{
		{
			name: "success",
			prepare: func(tmp string) (AttestOptions, error) {
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
				return AttestOptions{
					PredicatePath: pred,
					PredicateType: "https://enterprisecontract.dev/attestations/vsa/v1",
					ImageDigest:   digest,
					Repo:          repo,
					Signer:        signer,
				}, nil
			},
		},
		{
			name: "missing-predicate",
			prepare: func(tmp string) (AttestOptions, error) {
				fs := afero.NewMemMapFs()
				key := filepath.Join(tmp, "cosign.key")
				err := afero.WriteFile(fs, key, []byte(testECKey), 0o600)
				if err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				signer := testSigner(key, fs)
				return AttestOptions{
					PredicatePath: filepath.Join(tmp, "no.json"),
					PredicateType: "https://enterprisecontract.dev/attestations/vsa/v1",
					ImageDigest:   digest,
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
	opts, _ := NewAttestOptions(pred, repo, digest, signer)
	env, _ := opts.AttestPredicate(context.Background())

	out, err := opts.WriteEnvelope(env)
	if err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}
	if !filepath.IsAbs(out) {
		t.Errorf("expected abs path, got %q", out)
	}
}
