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

package utils

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPrivateKeyFromKeyRef(t *testing.T) {
	tests := []struct {
		name      string
		keyRef    string
		setup     func(fs afero.Fs, ctx context.Context)
		expectErr bool
		errMsg    string
	}{
		{
			name:   "file path",
			keyRef: "/path/to/key.pem",
			setup: func(fs afero.Fs, ctx context.Context) {
				err := afero.WriteFile(fs, "/path/to/key.pem", []byte("test key content"), 0o600)
				require.NoError(t, err)
			},
			expectErr: false,
		},
		{
			name:   "k8s secret with explicit key field",
			keyRef: "k8s://test-namespace/test-secret/private-key",
			setup: func(fs afero.Fs, ctx context.Context) {
				// This will be handled in the test loop
			},
			expectErr: false,
		},
		{
			name:   "k8s secret with single key (auto-select)",
			keyRef: "k8s://test-namespace/single-key-secret",
			setup: func(fs afero.Fs, ctx context.Context) {
				// This will be handled in the test loop
			},
			expectErr: false,
		},
		{
			name:   "k8s secret with multiple keys (no key field specified, defaults to cosign.key)",
			keyRef: "k8s://test-namespace/multi-key-secret",
			setup: func(fs afero.Fs, ctx context.Context) {
				// This will be handled in the test loop
			},
			expectErr: true,
			errMsg:    "key field \"cosign.key\" not found in secret",
		},
		{
			name:   "k8s secret with default cosign.key field",
			keyRef: "k8s://test-namespace/cosign-key-secret",
			setup: func(fs afero.Fs, ctx context.Context) {
				// This will be handled in the test loop
			},
			expectErr: false,
		},
		{
			name:   "k8s secret with cosign.key among multiple keys (defaults to cosign.key)",
			keyRef: "k8s://test-namespace/mixed-secret",
			setup: func(fs afero.Fs, ctx context.Context) {
				// This will be handled in the test loop
			},
			expectErr: false,
		},
		{
			name:      "invalid k8s format",
			keyRef:    "k8s://invalid-format",
			setup:     func(fs afero.Fs, ctx context.Context) {},
			expectErr: true,
			errMsg:    "invalid k8s key reference format",
		},
		{
			name:      "file not found",
			keyRef:    "/nonexistent/key.pem",
			setup:     func(fs afero.Fs, ctx context.Context) {},
			expectErr: true,
			errMsg:    "read key from file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := context.Background()

			// Setup Kubernetes client for k8s tests
			if strings.HasPrefix(tt.keyRef, "k8s://") {
				var secrets []*v1.Secret

				if tt.keyRef == "k8s://test-namespace/test-secret/private-key" {
					secrets = append(secrets, &v1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-secret",
							Namespace: "test-namespace",
						},
						Data: map[string][]byte{
							"private-key": []byte("test private key content"),
						},
					})
				} else if tt.keyRef == "k8s://test-namespace/single-key-secret" {
					secrets = append(secrets, &v1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "single-key-secret",
							Namespace: "test-namespace",
						},
						Data: map[string][]byte{
							"cosign.key": []byte("single key content"),
						},
					})
				} else if tt.keyRef == "k8s://test-namespace/multi-key-secret" {
					secrets = append(secrets, &v1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "multi-key-secret",
							Namespace: "test-namespace",
						},
						Data: map[string][]byte{
							"key1": []byte("key1 content"),
							"key2": []byte("key2 content"),
						},
					})
				} else if tt.keyRef == "k8s://test-namespace/cosign-key-secret" {
					secrets = append(secrets, &v1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "cosign-key-secret",
							Namespace: "test-namespace",
						},
						Data: map[string][]byte{
							"cosign.key": []byte("default cosign key content"),
						},
					})
				} else if tt.keyRef == "k8s://test-namespace/mixed-secret" {
					secrets = append(secrets, &v1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "mixed-secret",
							Namespace: "test-namespace",
						},
						Data: map[string][]byte{
							"cosign.key":  []byte("mixed secret cosign key content"),
							"other-key":   []byte("other key content"),
							"another-key": []byte("another key content"),
						},
					})
				}

				if len(secrets) > 0 {
					client := fake.NewClientset()
					for _, secret := range secrets {
						_, err := client.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
						require.NoError(t, err)
					}
					ctx = context.WithValue(ctx, K8sClientKey, client)
				}
			}

			tt.setup(fs, ctx)

			keyBytes, err := PrivateKeyFromKeyRef(ctx, tt.keyRef, fs)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, keyBytes)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, keyBytes)

				// Verify expected content for specific test cases
				if tt.keyRef == "k8s://test-namespace/single-key-secret" {
					assert.Equal(t, []byte("single key content"), keyBytes)
				} else if tt.keyRef == "k8s://test-namespace/test-secret/private-key" {
					assert.Equal(t, []byte("test private key content"), keyBytes)
				} else if tt.keyRef == "k8s://test-namespace/cosign-key-secret" {
					assert.Equal(t, []byte("default cosign key content"), keyBytes)
				} else if tt.keyRef == "k8s://test-namespace/mixed-secret" {
					assert.Equal(t, []byte("mixed secret cosign key content"), keyBytes)
				}
			}
		})
	}
}

func TestPublicKeyFromKeyRef(t *testing.T) {
	tests := []struct {
		name      string
		keyRef    string
		setup     func(fs afero.Fs, ctx context.Context)
		expectErr bool
		errMsg    string
	}{
		{
			name:   "file path",
			keyRef: "/path/to/public-key.pem",
			setup: func(fs afero.Fs, ctx context.Context) {
				err := afero.WriteFile(fs, "/path/to/public-key.pem", []byte("test public key content"), 0o600)
				require.NoError(t, err)
			},
			expectErr: false,
		},
		{
			name:   "k8s secret with explicit key field",
			keyRef: "k8s://test-namespace/test-secret/public-key",
			setup: func(fs afero.Fs, ctx context.Context) {
				// This will be handled in the test loop
			},
			expectErr: false,
		},
		{
			name:   "k8s secret with single key (auto-select)",
			keyRef: "k8s://test-namespace/single-key-secret",
			setup: func(fs afero.Fs, ctx context.Context) {
				// This will be handled in the test loop
			},
			expectErr: false,
		},
		{
			name:   "k8s secret with multiple keys (no key field specified)",
			keyRef: "k8s://test-namespace/multi-key-secret",
			setup: func(fs afero.Fs, ctx context.Context) {
				// This will be handled in the test loop
			},
			expectErr: true,
			errMsg:    "contains multiple keys, please specify the key field",
		},
		{
			name:      "invalid k8s format",
			keyRef:    "k8s://invalid-format",
			setup:     func(fs afero.Fs, ctx context.Context) {},
			expectErr: true,
			errMsg:    "invalid k8s key reference format",
		},
		{
			name:      "file not found",
			keyRef:    "/nonexistent/public-key.pem",
			setup:     func(fs afero.Fs, ctx context.Context) {},
			expectErr: true,
			errMsg:    "read key from file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			ctx := context.Background()

			// Setup Kubernetes client for k8s tests
			if strings.HasPrefix(tt.keyRef, "k8s://") {
				var secrets []*v1.Secret

				if tt.keyRef == "k8s://test-namespace/test-secret/public-key" {
					secrets = append(secrets, &v1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-secret",
							Namespace: "test-namespace",
						},
						Data: map[string][]byte{
							"public-key": []byte("test public key content"),
						},
					})
				} else if tt.keyRef == "k8s://test-namespace/single-key-secret" {
					secrets = append(secrets, &v1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "single-key-secret",
							Namespace: "test-namespace",
						},
						Data: map[string][]byte{
							"cosign.pub": []byte("single key content"),
						},
					})
				} else if tt.keyRef == "k8s://test-namespace/multi-key-secret" {
					secrets = append(secrets, &v1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "multi-key-secret",
							Namespace: "test-namespace",
						},
						Data: map[string][]byte{
							"key1": []byte("key1 content"),
							"key2": []byte("key2 content"),
						},
					})
				}

				if len(secrets) > 0 {
					client := fake.NewClientset()
					for _, secret := range secrets {
						_, err := client.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
						require.NoError(t, err)
					}
					ctx = context.WithValue(ctx, K8sClientKey, client)
				}
			}

			tt.setup(fs, ctx)

			result, err := PublicKeyFromKeyRef(ctx, tt.keyRef, fs)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)

				// Verify expected content for specific test cases
				if tt.keyRef == "k8s://test-namespace/single-key-secret" {
					assert.Equal(t, []byte("single key content"), result)
				} else if tt.keyRef == "k8s://test-namespace/test-secret/public-key" {
					assert.Equal(t, []byte("test public key content"), result)
				} else {
					assert.NotNil(t, result)
				}
			}
		})
	}
}
