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

//go:build unit || integration

// The contents of this file are meant to assist in writing unit tests. It requires the "unit" build
// tag which is not included when building the ec binary.
package fake

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cosignoci "github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/stretchr/testify/mock"

	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/utils/oci"
)

func WithTestImageConfig(ctx context.Context, url string) context.Context {
	ref, err := name.NewDigest(url)
	if err != nil {
		panic(err)
	}

	// Setup parent/base image mock
	parentURL := utils.WithDigest("registry.local/base-image")
	parentRef, err := name.ParseReference(parentURL)
	if err != nil {
		panic(err)
	}
	parentImage, err := mutate.Config(empty.Image, v1.Config{
		Labels: map[string]string{
			"io.k8s.display-name": "Base Image",
		},
	})
	if err != nil {
		panic(err)
	}

	// Setup child image mock
	image := mutate.Annotations(empty.Image, map[string]string{
		oci.BaseImageNameAnnotation: parentURL,
	}).(v1.Image)
	image, err = mutate.Config(image, v1.Config{
		Labels: map[string]string{
			"io.k8s.display-name": "Test Image",
		},
	})
	if err != nil {
		panic(err)
	}

	// Setup client
	client := &FakeClient{}
	client.On("Image", ref, mock.Anything).Return(image, nil)
	client.On("Image", parentRef, mock.Anything).Return(parentImage, nil)

	return oci.WithClient(ctx, client)
}

var _ oci.Client = &FakeClient{}

type FakeClient struct {
	mock.Mock
}

func (m *FakeClient) VerifyImageSignatures(ref name.Reference, opts *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
	args := m.Called(ref, opts)
	var sigs []cosignoci.Signature
	if maybeSigs, ok := args.Get(0).([]cosignoci.Signature); ok {
		sigs = maybeSigs
	}
	return sigs, args.Bool(1), args.Error(2)
}

func (m *FakeClient) VerifyImageAttestations(ref name.Reference, opts *cosign.CheckOpts) ([]cosignoci.Signature, bool, error) {
	args := m.Called(ref, opts)
	var sigs []cosignoci.Signature
	if maybeSigs, ok := args.Get(0).([]cosignoci.Signature); ok {
		sigs = maybeSigs
	}
	return sigs, args.Bool(1), args.Error(2)
}

func (m *FakeClient) FetchAttestationLayers(ref name.Reference) ([]cosignoci.Signature, error) {
	args := m.Called(ref)
	var sigs []cosignoci.Signature
	if maybeSigs, ok := args.Get(0).([]cosignoci.Signature); ok {
		sigs = maybeSigs
	}
	return sigs, args.Error(1)
}

func (m *FakeClient) HasBundles(ctx context.Context, ref name.Reference) (bool, error) {
	args := m.Called(ctx, ref)
	return args.Bool(0), args.Error(1)
}

func (m *FakeClient) Head(ref name.Reference) (*v1.Descriptor, error) {
	args := m.Called(ref)
	var desc *v1.Descriptor
	if maybeDesc, ok := args.Get(0).(*v1.Descriptor); ok {
		desc = maybeDesc
	}

	return desc, args.Error(1)
}

func (m *FakeClient) ResolveDigest(ref name.Reference) (string, error) {
	args := m.Called(ref)

	return args.String(0), args.Error(1)
}

func (m *FakeClient) Image(ref name.Reference) (v1.Image, error) {
	args := m.Called(ref)
	var img v1.Image
	if maybeImg, ok := args.Get(0).(v1.Image); ok {
		img = maybeImg
	}
	return img, args.Error(1)
}

func (m *FakeClient) Layer(ref name.Digest) (v1.Layer, error) {
	args := m.Called(ref)
	var layer v1.Layer
	if maybeLayer, ok := args.Get(0).(v1.Layer); ok {
		layer = maybeLayer
	}
	return layer, args.Error(1)
}

func (m *FakeClient) Index(ref name.Reference) (v1.ImageIndex, error) {
	args := m.Called(ref)
	var index v1.ImageIndex
	if maybeIndex, ok := args.Get(0).(v1.ImageIndex); ok {
		index = maybeIndex
	}
	return index, args.Error(1)
}
