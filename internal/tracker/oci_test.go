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

package tracker

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func val[T any](t *testing.T, fn func() (T, error)) T {
	val, err := fn()
	assert.NoError(t, err)

	return val
}

type mockRegistry struct {
	mock.Mock
}

func (m *mockRegistry) write(ref name.Reference, image v1.Image, options ...remote.Option) error {
	args := m.Called(ref, image, options)

	return args.Error(0)
}

func (m *mockRegistry) read(ref name.Reference, options ...remote.Option) (v1.Image, error) {
	args := m.Called(ref, options)

	return args.Get(0).(v1.Image), args.Error(1)
}

func TestPushImage(t *testing.T) {
	yaml := []byte("data: blah")
	digest := fmt.Sprintf("%x", sha256.Sum256(yaml))

	imageRef := "registry.io/repository/image:tag"
	invocation := "ec track bundle --bundle xyz --output " + imageRef

	registry := mockRegistry{}
	registry.On("write", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	ctx := context.WithValue(context.Background(), registryKey, &registry)

	err := PushImage(ctx, imageRef, yaml, invocation)
	assert.NoError(t, err)

	registry.AssertExpectations(t)

	argImageRef := registry.Calls[0].Arguments[0].(name.Reference)
	assert.Equal(t, imageRef, argImageRef.String())

	argImage := registry.Calls[0].Arguments[1].(v1.Image)
	assert.Equal(t, types.OCIManifestSchema1, val(t, argImage.MediaType))
	assert.Equal(t, &v1.ConfigFile{
		History: []v1.History{
			{CreatedBy: invocation},
		},
		RootFS: v1.RootFS{
			Type: "layers",
			DiffIDs: []v1.Hash{
				{
					Algorithm: "sha256",
					Hex:       digest,
				},
			},
		},
	}, val(t, argImage.ConfigFile))

	hash, err := v1.NewHash("sha256:cd192c2103529715b6be90d66fb6b5b795c267fc9cb3139c5cbc60616020d17e")
	assert.NoError(t, err)

	layer, err := argImage.LayerByDiffID(hash)
	assert.NoError(t, err)
	assert.NotNil(t, layer)

	in, err := layer.Uncompressed()
	assert.NoError(t, err)
	defer in.Close()

	content, err := io.ReadAll(in)
	assert.NoError(t, err)
	assert.Equal(t, yaml, content)
}

func TestPullImage(t *testing.T) {
	imageRef := "registry.io/repository/image:tag"
	yaml := []byte("data: blah")

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	img, err := mutate.Append(img, mutate.Addendum{
		MediaType: openPolicyAgentData,
		Layer:     static.NewLayer(yaml, openPolicyAgentData),
		Annotations: map[string]string{
			title: dataFileTitle,
		},
	})
	assert.NoError(t, err)

	registry := mockRegistry{}
	registry.On("read", mock.Anything, mock.Anything).Return(img, nil)

	ctx := context.WithValue(context.Background(), registryKey, &registry)

	got, err := PullImage(ctx, imageRef)
	assert.NoError(t, err)

	assert.Equal(t, yaml, got)
}
