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

package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1fake "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/internal/utils/oci/fake"
)

func TestOCIBlob(t *testing.T) {
	t.Cleanup(ClearCaches)
	ClearCaches() // Clear before test to avoid interference from previous tests

	cases := []struct {
		name      string
		data      string
		uri       *ast.Term
		err       bool
		remoteErr error
	}{
		{
			name: "success",
			data: `{"spam": "maps"}`,
			uri:  ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
		},
		{
			name: "unexpected uri type",
			data: `{"spam": "maps"}`,
			uri:  ast.IntNumberTerm(42),
			err:  true,
		},
		{
			name: "missing digest",
			data: `{"spam": "maps"}`,
			uri:  ast.StringTerm("registry.local/spam:latest"),
			err:  true,
		},
		{
			name: "invalid digest size",
			data: `{"spam": "maps"}`,
			uri:  ast.StringTerm("registry.local/spam@sha256:4e388ab"),
			err:  true,
		},
		{
			name:      "remote error",
			data:      `{"spam": "maps"}`,
			uri:       ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
			remoteErr: errors.New("boom!"),
			err:       true,
		},
		{
			name: "unexpected digest",
			data: `{"spam": "mapssssss"}`,
			uri:  ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
			err:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ClearCaches() // Clear cache before each subtest

			client := fake.FakeClient{}
			if c.remoteErr != nil {
				client.On("Layer", mock.Anything, mock.Anything).Return(nil, c.remoteErr)
			} else {
				layer := static.NewLayer([]byte(c.data), types.OCIUncompressedLayer)
				client.On("Layer", mock.Anything, mock.Anything).Return(layer, nil)
			}
			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			blob, err := ociBlob(bctx, c.uri)
			require.NoError(t, err)
			if c.err {
				require.Nil(t, blob)
			} else {
				require.NotNil(t, blob)
				data, ok := blob.Value.(ast.String)
				require.True(t, ok)
				require.Equal(t, c.data, string(data))
			}
		})
	}
}

func TestOCIBlobFiles(t *testing.T) {
	t.Cleanup(ClearCaches)
	ClearCaches() // Clear before test to avoid interference from previous tests

	// Helper function to create a tar archive with test files and compute its digest
	createTarArchiveWithDigest := func(files map[string]string) ([]byte, string) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)

		for path, content := range files {
			header := &tar.Header{
				Name: path,
				Size: int64(len(content)),
			}
			require.NoError(t, tw.WriteHeader(header))
			_, err := tw.Write([]byte(content))
			require.NoError(t, err)
		}
		require.NoError(t, tw.Close())

		data := buf.Bytes()
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
		return data, digest
	}

	cases := []struct {
		name        string
		tarFiles    map[string]string
		paths       []string
		expectedLen int
		err         bool
		remoteErr   error
		invalidRef  bool
		nilPaths    bool
		invalidPath bool
		oversized   bool
	}{
		{
			name: "success with yaml file",
			tarFiles: map[string]string{
				"task.yaml": `apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: example-task`,
				"other.txt": "not a yaml file",
			},
			paths:       []string{"task.yaml"},
			expectedLen: 1,
		},
		{
			name: "success with multiple files",
			tarFiles: map[string]string{
				"task.yaml":     `{"apiVersion": "tekton.dev/v1beta1", "kind": "Task"}`,
				"pipeline.json": `{"apiVersion": "tekton.dev/v1beta1", "kind": "Pipeline"}`,
				"other.txt":     "not structured",
			},
			paths:       []string{"task.yaml", "pipeline.json"},
			expectedLen: 2,
		},
		{
			name: "no matching files",
			tarFiles: map[string]string{
				"other.txt": "not a yaml file",
			},
			paths:       []string{"task.yaml"},
			expectedLen: 0,
		},
		{
			name:       "invalid ref type",
			tarFiles:   map[string]string{},
			paths:      []string{"task.yaml"},
			invalidRef: true,
			err:        true,
		},
		{
			name:     "nil paths term",
			tarFiles: map[string]string{},
			nilPaths: true,
			err:      true,
		},
		{
			name:      "remote error",
			tarFiles:  map[string]string{},
			paths:     []string{"task.yaml"},
			remoteErr: errors.New("blob fetch failed"),
			err:       true,
		},
		{
			name: "invalid path type in array",
			tarFiles: map[string]string{
				"task.yaml": `{"apiVersion": "tekton.dev/v1beta1"}`,
			},
			invalidPath: true,
			err:         true,
		},
		{
			name: "invalid json file ignored",
			tarFiles: map[string]string{
				"task.yaml":    `{"apiVersion": "tekton.dev/v1beta1", "kind": "Task"}`,
				"invalid.json": `{{{malformed content that can't be parsed as JSON or YAML`,
				"valid.json":   `{"apiVersion": "tekton.dev/v1beta1", "kind": "Pipeline"}`,
			},
			paths:       []string{"task.yaml", "invalid.json", "valid.json"},
			expectedLen: 2, // Only task.yaml and valid.json should be extracted, invalid.json is ignored
		},
		{
			name: "empty paths array",
			tarFiles: map[string]string{
				"task.yaml": `{"apiVersion": "tekton.dev/v1beta1", "kind": "Task"}`,
			},
			paths:       []string{}, // Empty paths array
			expectedLen: 0,          // Should return empty object
		},
		{
			name: "file without supported extension",
			tarFiles: map[string]string{
				"config":     `{"apiVersion": "v1", "kind": "ConfigMap"}`, // No file extension but valid JSON
				"task.yaml":  `{"apiVersion": "tekton.dev/v1beta1", "kind": "Task"}`,
				"readme.txt": `This is just text, not structured data`,
			},
			paths:       []string{"config", "task.yaml"}, // Explicitly request the extensionless file
			expectedLen: 2,                               // Both config and task.yaml should be extracted
		},
		{
			name: "oversized tar entry skipped",
			tarFiles: map[string]string{
				"small.yaml": `{"ok": true}`,                                  // 12 bytes
				"large.json": `{"data": "this will be considered oversized"}`, // 43 bytes, will be "too large" with limit set to 20 bytes
			},
			paths:       []string{"small.yaml", "large.json"},
			expectedLen: 1, // Only small.yaml should be extracted, large.json should be skipped due to temp limit
			oversized:   true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ClearCaches() // Clear cache before each subtest

			// Create test data and compute digest dynamically
			var refTerm *ast.Term
			var pathsTerm *ast.Term

			if c.invalidRef {
				refTerm = ast.IntNumberTerm(42)
			} else if c.nilPaths {
				refTerm = ast.StringTerm("registry.local/bundle@sha256:dummy")
				pathsTerm = nil
			} else if c.invalidPath {
				tarData, digest := createTarArchiveWithDigest(c.tarFiles)
				refTerm = ast.StringTerm(fmt.Sprintf("registry.local/bundle@%s", digest))
				pathsTerm = ast.ArrayTerm(ast.IntNumberTerm(123)) // invalid path type

				client := fake.FakeClient{}
				layer := static.NewLayer(tarData, types.OCIUncompressedLayer)
				client.On("Layer", mock.Anything, mock.Anything).Return(layer, nil)
				ctx := oci.WithClient(context.Background(), &client)
				bctx := rego.BuiltinContext{Context: ctx}

				result, err := ociBlobFiles(bctx, refTerm, pathsTerm)
				require.NoError(t, err)
				require.Nil(t, result)
				return
			} else if c.oversized {
				// Temporarily override the size limit to make the test feasible with small files
				originalLimit := maxTarEntrySize
				maxTarEntrySize = 20 // Set a very small limit of 20 bytes
				defer func() {
					maxTarEntrySize = originalLimit // Restore original limit
				}()

				// Create normal tar archive
				tarData, digest := createTarArchiveWithDigest(c.tarFiles)
				refTerm = ast.StringTerm(fmt.Sprintf("registry.local/bundle@%s", digest))

				pathTerms := make([]*ast.Term, len(c.paths))
				for i, path := range c.paths {
					pathTerms[i] = ast.StringTerm(path)
				}
				pathsTerm = ast.ArrayTerm(pathTerms...)

				client := fake.FakeClient{}
				layer := static.NewLayer(tarData, types.OCIUncompressedLayer)
				client.On("Layer", mock.Anything, mock.Anything).Return(layer, nil)
				ctx := oci.WithClient(context.Background(), &client)
				bctx := rego.BuiltinContext{Context: ctx}

				result, err := ociBlobFiles(bctx, refTerm, pathsTerm)
				require.NoError(t, err)
				require.NotNil(t, result)

				// Verify the result is an object
				obj, ok := result.Value.(ast.Object)
				require.True(t, ok, "result should be an object")

				// Check that only the small file was extracted (large file should be skipped)
				require.Equal(t, c.expectedLen, obj.Len(), "unexpected number of extracted files")
				return
			} else {
				// Normal test cases
				tarData, digest := createTarArchiveWithDigest(c.tarFiles)
				refTerm = ast.StringTerm(fmt.Sprintf("registry.local/bundle@%s", digest))

				pathTerms := make([]*ast.Term, len(c.paths))
				for i, path := range c.paths {
					pathTerms[i] = ast.StringTerm(path)
				}
				pathsTerm = ast.ArrayTerm(pathTerms...)

				client := fake.FakeClient{}
				if c.remoteErr != nil {
					client.On("Layer", mock.Anything, mock.Anything).Return(nil, c.remoteErr)
				} else {
					layer := static.NewLayer(tarData, types.OCIUncompressedLayer)
					client.On("Layer", mock.Anything, mock.Anything).Return(layer, nil)
				}
				ctx := oci.WithClient(context.Background(), &client)
				bctx := rego.BuiltinContext{Context: ctx}

				result, err := ociBlobFiles(bctx, refTerm, pathsTerm)
				require.NoError(t, err)

				if c.err {
					require.Nil(t, result)
				} else {
					require.NotNil(t, result)

					// Verify the result is an object
					obj, ok := result.Value.(ast.Object)
					require.True(t, ok, "result should be an object")

					// Check the number of extracted files
					require.Equal(t, c.expectedLen, obj.Len(), "unexpected number of extracted files")

					// For success cases with files, verify basic structure
					if c.expectedLen > 0 {
						// Iterate through the object using Keys() and Get()
						keys := obj.Keys()
						require.Len(t, keys, c.expectedLen, "unexpected number of keys")

						for _, key := range keys {
							keyStr, ok := key.Value.(ast.String)
							require.True(t, ok, "file path should be a string")

							// Verify it's one of the expected files
							_, exists := c.tarFiles[string(keyStr)]
							require.True(t, exists, "unexpected file: %s", string(keyStr))

							// Get the value and verify it was parsed
							value := obj.Get(key)
							require.NotNil(t, value, "file content should not be nil")

							// For structured files, just verify the content exists and was processed
							if strings.HasSuffix(string(keyStr), ".yaml") || strings.HasSuffix(string(keyStr), ".yml") || strings.HasSuffix(string(keyStr), ".json") {
								// The content should be present (exact type checking is complex with AST)
								require.NotNil(t, value.Value, "structured file should have parsed content")
							}
						}
					}
				}
				return
			}

			// Handle special cases (invalid ref, nil paths)
			ctx := oci.WithClient(context.Background(), &fake.FakeClient{})
			bctx := rego.BuiltinContext{Context: ctx}

			result, err := ociBlobFiles(bctx, refTerm, pathsTerm)
			require.NoError(t, err)
			require.Nil(t, result)
		})
	}
}

func TestOCIDescriptorManifest(t *testing.T) {
	t.Cleanup(ClearCaches)
	ClearCaches()

	cases := []struct {
		name           string
		ref            *ast.Term
		descriptor     *v1.Descriptor
		resolvedDigest string
		resolveErr     error
		headErr        error
		wantErr        bool
	}{
		{
			name: "complete image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			descriptor: &v1.Descriptor{
				MediaType: types.OCIManifestSchema1,
				Size:      123,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
				},
				Data: []byte(`{"data": "config"}`),
				URLs: []string{"https://config-1.local/spam", "https://config-2.local/spam"},
				Annotations: map[string]string{
					"config.annotation.1": "config.annotation.value.1",
					"config.annotation.2": "config.annotation.value.2",
				},
				Platform: &v1.Platform{
					Architecture: "arch",
					OS:           "os",
					OSVersion:    "os-version",
					OSFeatures:   []string{"os-feature-1", "os-feature-2"},
					Variant:      "variant",
					Features:     []string{"feature-1", "feature-2"},
				},
				ArtifactType: "artifact-type",
			},
		},
		{
			name: "minimal image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			descriptor: &v1.Descriptor{
				MediaType: types.OCIManifestSchema1,
				Size:      123,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
				},
			},
		},
		{
			name: "minimal image index",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			descriptor: &v1.Descriptor{
				MediaType: types.OCIImageIndex,
				Size:      123,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
				},
			},
		},
		{
			name:           "missing digest",
			ref:            ast.StringTerm("registry.local/spam:latest"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			descriptor: &v1.Descriptor{
				MediaType: types.OCIManifestSchema1,
				Size:      123,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
				},
			},
		},
		{
			name:           "tag-based URI with error",
			ref:            ast.StringTerm("registry.local/spam:latest"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			headErr:        errors.New("tag error"),
			wantErr:        true,
		},
		{
			name:       "resolve error",
			ref:        ast.StringTerm("registry.local/spam:latest"),
			resolveErr: errors.New("kaboom!"),
			wantErr:    true,
		},
		{
			name:           "unsupported digest algorithm",
			ref:            ast.StringTerm("registry.local/spam@sha512:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			wantErr:        true,
		},
		{
			name:           "malformed digest with extra @",
			ref:            ast.StringTerm("registry.local/spam@@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			wantErr:        true,
		},
		{
			name:           "invalid tag after digest fallback",
			ref:            ast.StringTerm("registry.local/spam:!nv@lid"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			wantErr:        true,
		},
		{
			name:    "invalid digest format",
			ref:     ast.StringTerm("registry.local/spam@sha256:invalid-digest-format"),
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ClearCaches() // Clear cache before each subtest

			client := fake.FakeClient{}
			if c.headErr != nil {
				client.On("Head", mock.Anything).Return(nil, c.headErr)
			} else {
				client.On("Head", mock.Anything).Return(c.descriptor, nil)
			}
			if c.resolveErr != nil {
				client.On("ResolveDigest", mock.Anything).Return("", c.resolveErr)
			} else if c.resolvedDigest != "" {
				client.On("ResolveDigest", mock.Anything).Return(c.resolvedDigest, nil)
			}
			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			got, err := ociDescriptor(bctx, c.ref)
			require.NoError(t, err)
			if c.wantErr {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				snaps.MatchJSON(t, got)
			}
		})
	}
}

func TestOCIDescriptorErrors(t *testing.T) {
	t.Cleanup(ClearCaches)
	ClearCaches()

	cases := []struct {
		name string
		ref  *ast.Term
	}{
		{
			name: "bad image ref",
			ref:  ast.StringTerm("......registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
		},
		{
			name: "bad image ref without digest",
			ref:  ast.StringTerm("."),
		},
		{
			name: "invalid ref type",
			ref:  ast.IntNumberTerm(42),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ClearCaches() // Clear cache before each subtest

			client := fake.FakeClient{}
			client.On("Head", mock.Anything, mock.Anything).Return(nil, errors.New("expected"))
			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			got, err := ociDescriptor(bctx, c.ref)
			require.NoError(t, err)
			require.Nil(t, got)
		})
	}
}

func TestOCIImageManifest(t *testing.T) {
	t.Cleanup(ClearCaches)
	ClearCaches()

	cases := []struct {
		name           string
		ref            *ast.Term
		manifest       *v1.Manifest
		resolvedDigest string
		resolveErr     error
		imageErr       error
		manifestErr    error
		wantErr        bool
	}{
		{
			name: "complete image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			manifest: &v1.Manifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Config: v1.Descriptor{
					MediaType: types.OCIConfigJSON,
					Size:      123,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
					},
					Data: []byte(`{"data": "config"}`),
					URLs: []string{"https://config-1.local/spam", "https://config-2.local/spam"},
					Annotations: map[string]string{
						"config.annotation.1": "config.annotation.value.1",
						"config.annotation.2": "config.annotation.value.2",
					},
					Platform: &v1.Platform{
						Architecture: "arch",
						OS:           "os",
						OSVersion:    "os-version",
						OSFeatures:   []string{"os-feature-1", "os-feature-2"},
						Variant:      "variant",
						Features:     []string{"feature-1", "feature-2"},
					},
					ArtifactType: "artifact-type",
				},
				Layers: []v1.Descriptor{
					{
						MediaType: types.OCILayer,
						Size:      9999,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "325392e8dd2826a53a9a35b7a7f8d71683cd27ebc2c73fee85dab673bc909b67",
						},
						Data: []byte(`{"data": "layer"}`),
						URLs: []string{"https://layer-1.local/spam", "https://layer-2.local/spam"},
						Annotations: map[string]string{
							"layer.annotation.1": "layer.annotation.value.1",
							"layer.annotation.2": "layer.annotation.value.2",
						},
						Platform: &v1.Platform{
							Architecture: "arch",
							OS:           "os",
							OSVersion:    "os-version",
							OSFeatures:   []string{"os-feature-1", "os-feature-2"},
							Variant:      "variant",
							Features:     []string{"feature-1", "feature-2"},
						},
						ArtifactType: "artifact-type",
					},
				},
				Annotations: map[string]string{
					"manifest.annotation.1": "config.annotation.value.1",
					"manifest.annotation.2": "config.annotation.value.2",
				},
				Subject: &v1.Descriptor{
					MediaType: types.OCIManifestSchema1,
					Size:      8888,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "d9298a10d1b0735837dc4bd85dac641b0f3cef27a47e5d53a54f2f3f5b2fcffa",
					},
					Data: []byte(`{"data": "subject"}`),
					URLs: []string{"https://subject-1.local/spam", "https://subject-2.local/spam"},
					Annotations: map[string]string{
						"subject.annotation.1": "subject.annotation.value.1",
						"subject.annotation.2": "subject.annotation.value.2",
					},
					Platform: &v1.Platform{
						Architecture: "arch",
						OS:           "os",
						OSVersion:    "os-version",
						OSFeatures:   []string{"os-feature-1", "os-feature-2"},
						Variant:      "variant",
						Features:     []string{"feature-1", "feature-2"},
					},
					ArtifactType: "artifact-type",
				},
			},
		},
		{
			name: "minimal image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			manifest: &v1.Manifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Config: v1.Descriptor{
					MediaType: types.OCIConfigJSON,
					Size:      123,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
					},
				},
				Layers: []v1.Descriptor{
					{
						MediaType: types.OCILayer,
						Size:      9999,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "325392e8dd2826a53a9a35b7a7f8d71683cd27ebc2c73fee85dab673bc909b67",
						},
					},
				},
			},
		},
		{
			name:           "missing digest",
			ref:            ast.StringTerm("registry.local/spam:latest"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			manifest: &v1.Manifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Config: v1.Descriptor{
					MediaType: types.OCIConfigJSON,
					Size:      123,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
					},
				},
				Layers: []v1.Descriptor{
					{
						MediaType: types.OCILayer,
						Size:      9999,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "325392e8dd2826a53a9a35b7a7f8d71683cd27ebc2c73fee85dab673bc909b67",
						},
					},
				},
			},
		},
		{
			name:    "bad image ref",
			ref:     ast.StringTerm("......registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			wantErr: true,
		},
		{
			name:    "bad image ref without digest",
			ref:     ast.StringTerm("."),
			wantErr: true,
		},
		{
			name:    "invalid ref type",
			ref:     ast.IntNumberTerm(42),
			wantErr: true,
		},
		{
			name:        "image error",
			ref:         ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			manifestErr: errors.New("kaboom!"),
			wantErr:     true,
		},
		{
			name:       "resolve error",
			ref:        ast.StringTerm("registry.local/spam:latest"),
			resolveErr: errors.New("kaboom!"),
			wantErr:    true,
		},
		{
			name:     "nil manifest",
			ref:      ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			manifest: nil,
			wantErr:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ClearCaches() // Clear cache before each subtest

			client := fake.FakeClient{}
			if c.imageErr != nil {
				client.On("Image", mock.Anything, mock.Anything).Return(nil, c.imageErr)
			} else {
				imageManifest := v1fake.FakeImage{}
				imageManifest.ManifestReturns(c.manifest, c.manifestErr)
				client.On("Image", mock.Anything, mock.Anything).Return(&imageManifest, nil)
			}
			if c.resolveErr != nil {
				client.On("ResolveDigest", mock.Anything).Return("", c.resolveErr)
			} else if c.resolvedDigest != "" {
				client.On("ResolveDigest", mock.Anything).Return(c.resolvedDigest, nil)
			}
			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			got, err := ociImageManifest(bctx, c.ref)
			require.NoError(t, err)
			if c.wantErr {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				snaps.MatchJSON(t, got)
			}
		})
	}
}

func TestOCIImageManifestsBatch(t *testing.T) {
	t.Cleanup(ClearCaches)
	ClearCaches()

	minimalManifest := &v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config: v1.Descriptor{
			MediaType: types.OCIConfigJSON,
			Size:      123,
			Digest: v1.Hash{
				Algorithm: "sha256",
				Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
			},
		},
		Layers: []v1.Descriptor{
			{
				MediaType: types.OCILayer,
				Size:      9999,
				Digest: v1.Hash{
					Algorithm: "sha256",
					Hex:       "325392e8dd2826a53a9a35b7a7f8d71683cd27ebc2c73fee85dab673bc909b67",
				},
			},
		},
	}

	cases := []struct {
		name        string
		refs        *ast.Term
		manifest    *v1.Manifest
		manifestErr error
		wantErr     bool
		wantCount   int
		wantKeys    []string
	}{
		{
			name: "single ref success",
			refs: ast.NewTerm(ast.NewSet(
				ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			)),
			manifest:  minimalManifest,
			wantCount: 1,
			wantKeys:  []string{"registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"},
		},
		{
			name: "multiple refs success",
			refs: ast.NewTerm(ast.NewSet(
				ast.StringTerm("registry.local/img1:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
				ast.StringTerm("registry.local/img2:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
				ast.StringTerm("registry.local/img3:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			)),
			manifest:  minimalManifest,
			wantCount: 3,
		},
		{
			name:      "empty set",
			refs:      ast.NewTerm(ast.NewSet()),
			manifest:  minimalManifest,
			wantCount: 0,
		},
		{
			name:    "invalid input type",
			refs:    ast.StringTerm("not-a-set"),
			wantErr: true,
		},
		{
			name: "non-string ref in set",
			refs: ast.NewTerm(ast.NewSet(
				ast.IntNumberTerm(42),
			)),
			wantErr: true,
		},
		{
			name: "manifest fetch error excludes ref from result",
			refs: ast.NewTerm(ast.NewSet(
				ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			)),
			manifestErr: errors.New("fetch error"),
			wantCount:   0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ClearCaches() // Clear cache before each subtest

			client := fake.FakeClient{}
			if c.manifestErr != nil {
				imageManifest := v1fake.FakeImage{}
				imageManifest.ManifestReturns(nil, c.manifestErr)
				client.On("Image", mock.Anything, mock.Anything).Return(&imageManifest, nil)
			} else {
				imageManifest := v1fake.FakeImage{}
				imageManifest.ManifestReturns(c.manifest, nil)
				client.On("Image", mock.Anything, mock.Anything).Return(&imageManifest, nil)
			}

			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			got, err := ociImageManifestsBatch(bctx, c.refs)
			require.NoError(t, err)

			if c.wantErr {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				obj, ok := got.Value.(ast.Object)
				require.True(t, ok, "result should be an object")
				require.Equal(t, c.wantCount, obj.Len(), "unexpected number of results")

				if len(c.wantKeys) > 0 {
					for _, key := range c.wantKeys {
						val := obj.Get(ast.StringTerm(key))
						require.NotNil(t, val, "expected key %s not found", key)
					}
				}
			}
		})
	}
}

func TestOCIImageManifestsBatchConcurrency(t *testing.T) {
	t.Cleanup(ClearCaches)
	ClearCaches()

	// Save and restore the original value
	original := maxParallelManifestFetches
	defer func() { maxParallelManifestFetches = original }()

	// Set a low concurrency limit for testing
	maxParallelManifestFetches = 2

	minimalManifest := &v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config: v1.Descriptor{
			MediaType: types.OCIConfigJSON,
			Size:      123,
			Digest: v1.Hash{
				Algorithm: "sha256",
				Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
			},
		},
		Layers: []v1.Descriptor{},
	}

	// Create more refs than the concurrency limit to test bounded concurrency
	refsSet := ast.NewSet()
	for i := 0; i < 10; i++ {
		refsSet.Add(ast.StringTerm(fmt.Sprintf("registry.local/img%d:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b", i)))
	}

	client := fake.FakeClient{}
	imageManifest := v1fake.FakeImage{}
	imageManifest.ManifestReturns(minimalManifest, nil)
	client.On("Image", mock.Anything, mock.Anything).Return(&imageManifest, nil)

	ctx := oci.WithClient(context.Background(), &client)
	bctx := rego.BuiltinContext{Context: ctx}

	got, err := ociImageManifestsBatch(bctx, ast.NewTerm(refsSet))
	require.NoError(t, err)
	require.NotNil(t, got)

	obj, ok := got.Value.(ast.Object)
	require.True(t, ok)
	require.Equal(t, 10, obj.Len(), "all refs should be processed")
}

func TestOCIImageFiles(t *testing.T) {
	t.Cleanup(ClearCaches)
	ClearCaches()

	image, err := crane.Image(map[string][]byte{
		"autoexec.bat":              []byte(`@ECHO OFF`),
		"manifests/a.json":          []byte(`{"a":1}`),
		"manifests/b.yaml":          []byte(`b: 2`),
		"manifests/c.xml":           []byte(`<?xml version="1.0" encoding="UTF-8"?>`),
		"manifests/unreadable.yaml": []byte(`***`),
		"manifests/unreadable.json": []byte(`***`),
	})
	require.NoError(t, err)

	cases := []struct {
		name      string
		paths     *ast.Term
		expected  string
		uri       *ast.Term
		err       bool
		remoteErr error
	}{
		{
			name:     "success",
			paths:    ast.ArrayTerm(ast.StringTerm("manifests")),
			expected: `{"manifests/a.json": {"a": 1}, "manifests/b.yaml": {"b": 2}}`,
			uri:      ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
		},
		{
			name: "non string URI",
			uri:  ast.BooleanTerm(true),
		},
		{
			name: "unpinned",
			uri:  ast.StringTerm("registry.local/spam:latest"),
		},
		{
			name:  "paths not an Array",
			paths: ast.BooleanTerm(true),
			uri:   ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
		},
		{
			name:  "path not a String",
			paths: ast.ArrayTerm(ast.BooleanTerm(true)),
			uri:   ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
		},
		{
			name:      "remote error",
			paths:     ast.ArrayTerm(ast.StringTerm("manifests")),
			uri:       ast.StringTerm("registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b"),
			remoteErr: errors.New("kaboom!"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ClearCaches() // Clear cache before each subtest

			client := fake.FakeClient{}
			if c.remoteErr != nil {
				client.On("Image", mock.Anything).Return(nil, c.remoteErr)
			} else {
				client.On("Image", mock.Anything).Return(image, nil)
			}

			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			files, err := ociImageFiles(bctx, c.uri, c.paths)
			require.NoError(t, err)
			if c.err || c.expected == "" {
				require.Nil(t, files)
			} else {
				require.NotNil(t, files)
				require.JSONEq(t, c.expected, files.String())
			}
		})
	}
}

func TestOCIImageIndex(t *testing.T) {
	t.Cleanup(ClearCaches)
	ClearCaches()

	cases := []struct {
		name             string
		ref              *ast.Term
		indexManifest    *v1.IndexManifest
		resolvedDigest   string
		resolveErr       error
		indexErr         error
		indexManifestErr error
		wantErr          bool
	}{
		{
			name: "complete image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifest: &v1.IndexManifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Manifests: []v1.Descriptor{
					{
						MediaType: types.OCIConfigJSON,
						Size:      123,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
						},
						Data: []byte(`{"data": "config"}`),
						URLs: []string{"https://config-1.local/spam", "https://config-2.local/spam"},
						Annotations: map[string]string{
							"config.annotation.1": "config.annotation.value.1",
							"config.annotation.2": "config.annotation.value.2",
						},
						Platform: &v1.Platform{
							Architecture: "arch",
							OS:           "os",
							OSVersion:    "os-version",
							OSFeatures:   []string{"os-feature-1", "os-feature-2"},
							Variant:      "variant",
							Features:     []string{"feature-1", "feature-2"},
						},
						ArtifactType: "artifact-type",
					},
				},
				Annotations: map[string]string{
					"manifest.annotation.1": "config.annotation.value.1",
					"manifest.annotation.2": "config.annotation.value.2",
				},
				Subject: &v1.Descriptor{
					MediaType: types.OCIManifestSchema1,
					Size:      8888,
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "d9298a10d1b0735837dc4bd85dac641b0f3cef27a47e5d53a54f2f3f5b2fcffa",
					},
					Data: []byte(`{"data": "subject"}`),
					URLs: []string{"https://subject-1.local/spam", "https://subject-2.local/spam"},
					Annotations: map[string]string{
						"subject.annotation.1": "subject.annotation.value.1",
						"subject.annotation.2": "subject.annotation.value.2",
					},
					Platform: &v1.Platform{
						Architecture: "arch",
						OS:           "os",
						OSVersion:    "os-version",
						OSFeatures:   []string{"os-feature-1", "os-feature-2"},
						Variant:      "variant",
						Features:     []string{"feature-1", "feature-2"},
					},
					ArtifactType: "artifact-type",
				},
			},
		},
		{
			name: "minimal image manifest",
			ref:  ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifest: &v1.IndexManifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Manifests: []v1.Descriptor{
					{
						MediaType: types.OCIConfigJSON,
						Size:      123,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
						},
					},
				},
			},
		},
		{
			name:           "missing digest",
			ref:            ast.StringTerm("registry.local/spam:latest"),
			resolvedDigest: "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
			indexManifest: &v1.IndexManifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				Manifests: []v1.Descriptor{
					{
						MediaType: types.OCIConfigJSON,
						Size:      123,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
						},
					},
				},
			},
		},
		{
			name:    "bad image ref",
			ref:     ast.StringTerm("......registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			wantErr: true,
		},
		{
			name:    "bad image ref without digest",
			ref:     ast.StringTerm("."),
			wantErr: true,
		},
		{
			name:    "invalid ref type",
			ref:     ast.IntNumberTerm(42),
			wantErr: true,
		},
		{
			name:             "image error",
			ref:              ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifestErr: errors.New("kaboom!"),
			wantErr:          true,
		},
		{
			name:       "resolve error",
			ref:        ast.StringTerm("registry.local/spam:latest"),
			resolveErr: errors.New("kaboom!"),
			wantErr:    true,
		},
		{
			name:          "nil manifest",
			ref:           ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifest: nil,
			wantErr:       true,
		},
		{
			name:          "nil manifest",
			ref:           ast.StringTerm("registry.local/spam:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			indexManifest: nil,
			indexErr:      errors.New("they say nothing is impossible, but i do nothing everyday"),
			wantErr:       true,
		},
		{
			name:    "invalid ref type",
			ref:     ast.StringTerm("registry.local/spam:latest@sha256@:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ClearCaches() // Clear cache before each subtest

			client := fake.FakeClient{}

			if c.indexErr != nil {
				client.On("Index", mock.Anything, mock.Anything).Return(nil, c.indexErr)
			} else {
				imageIndex := v1fake.FakeImageIndex{}
				imageIndex.IndexManifestReturns(c.indexManifest, c.indexManifestErr)
				client.On("Index", mock.Anything, mock.Anything).Return(&imageIndex, nil)
			}

			if c.resolveErr != nil {
				client.On("ResolveDigest", mock.Anything).Return("", c.resolveErr)
			} else if c.resolvedDigest != "" {
				client.On("ResolveDigest", mock.Anything).Return(c.resolvedDigest, nil)
			}

			ctx := oci.WithClient(context.Background(), &client)
			bctx := rego.BuiltinContext{Context: ctx}

			got, _ := ociImageIndex(bctx, c.ref)

			if c.wantErr {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				snaps.MatchJSON(t, got)
			}
		})
	}
}

func TestFunctionsRegistered(t *testing.T) {
	names := []string{
		ociBlobName,
		ociBlobFilesName,
		ociDescriptorName,
		ociImageFilesName,
		ociImageManifestName,
		ociImageManifestsBatchName,
		ociImageIndexName,
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			for _, builtin := range ast.Builtins {
				if builtin.Name == name {
					return
				}
			}
			t.Fatalf("%s builtin not registered", name)
		})
	}
}

func TestParseReference(t *testing.T) {
	cases := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{
			name: "valid digest",
			uri:  "registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b",
		},
		{
			name: "valid tag",
			uri:  "registry.local/spam:latest",
		},
		{
			name:    "invalid digest format",
			uri:     "registry.local/spam@sha256:invalid",
			wantErr: true,
		},
		{
			name:    "invalid tag format",
			uri:     "registry.local/spam:!nv@lid",
			wantErr: true,
		},
		{
			name:    "trailing @",
			uri:     "registry.local/spam@",
			wantErr: true,
		},
		{
			name:    "multiple @",
			uri:     "registry.local/spam@@sha256:abc123",
			wantErr: true,
		},
		{
			name:    "empty string",
			uri:     "",
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref, err := parseReference(c.uri)
			if c.wantErr {
				require.Error(t, err)
				require.Nil(t, ref)
			} else {
				require.NoError(t, err)
				require.NotNil(t, ref)
			}
		})
	}
}

func TestResolveIfNeeded(t *testing.T) {
	cases := []struct {
		name           string
		uri            string
		resolvedDigest string
		resolveErr     error
		wantErr        bool
	}{
		{
			name: "digest reference unchanged",
			uri:  "registry.local/spam@sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b",
		},
		{
			name:           "tag reference resolved",
			uri:            "registry.local/spam:latest",
			resolvedDigest: "sha256:4bbf56a3a9231f752d3b9c174637975f0f83ed2b15e65799837c571e4ef3374b",
		},
		{
			name:       "resolve error",
			uri:        "registry.local/spam:latest",
			resolveErr: errors.New("resolve error"),
			wantErr:    true,
		},
		{
			name:    "invalid reference",
			uri:     "registry.local/spam@",
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := fake.FakeClient{}
			if c.resolveErr != nil {
				client.On("ResolveDigest", mock.Anything).Return("", c.resolveErr)
			} else if c.resolvedDigest != "" {
				client.On("ResolveDigest", mock.Anything).Return(c.resolvedDigest, nil)
			}

			uri, ref, err := resolveIfNeeded(&client, c.uri)
			if c.wantErr {
				require.Error(t, err)
				require.Empty(t, uri)
				require.Nil(t, ref)
			} else {
				require.NoError(t, err)
				require.NotNil(t, ref)
				if c.resolvedDigest != "" {
					require.Contains(t, uri, c.resolvedDigest)
				} else {
					require.Equal(t, c.uri, uri)
				}
			}
		})
	}
}
