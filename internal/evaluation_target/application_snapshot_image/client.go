// Copyright The Enterprise Contract Contributors
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

package application_snapshot_image

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	gcr "github.com/google/go-containerregistry/pkg/v1"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

type contextKey string

const clientContextKey contextKey = "ec.appliation-snapshot-image.client"

// Client is an interface that contains all the external calls used by the
// application_snapshot_image package.
type Client interface {
	VerifyImageSignatures(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
	VerifyImageAttestations(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
	Head(name.Reference, ...remote.Option) (*gcr.Descriptor, error)
	ResolveDigest(name.Reference, *cosign.CheckOpts) (string, error)
}

func WithClient(ctx context.Context, client Client) context.Context {
	return context.WithValue(ctx, clientContextKey, client)
}

// NewClient constructs a new application_snapshot_image with the default client.
func NewClient(ctx context.Context) Client {
	client, ok := ctx.Value(clientContextKey).(Client)
	if ok && client != nil {
		return client
	}

	return &defaultClient{}
}

type defaultClient struct {
}

func (c *defaultClient) VerifyImageSignatures(ctx context.Context, ref name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	return cosign.VerifyImageSignatures(ctx, ref, opts)
}

func (c *defaultClient) VerifyImageAttestations(ctx context.Context, ref name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	return cosign.VerifyImageAttestations(ctx, ref, opts)
}

func (c *defaultClient) Head(ref name.Reference, opts ...remote.Option) (*gcr.Descriptor, error) {
	return remote.Head(ref, opts...)
}

// gather all attestation uris and digests associated with an image
func (c *defaultClient) AttestationUri(img string) (string, error) {
	imgRef, err := name.ParseReference(img)
	if err != nil {
		return "", err
	}

	opts := cosign.CheckOpts{}
	digest, err := ociremote.ResolveDigest(imgRef, opts.RegistryClientOpts...)
	if err != nil {
		return "", err
	}

	st, err := ociremote.AttestationTag(digest, opts.RegistryClientOpts...)
	if err != nil {
		return "", err
	}

	// parse st.Name() reference
	// ResolveDigest

	return st.Name(), nil
}

func (c *defaultClient) ResolveDigest(ref name.Reference, opts *cosign.CheckOpts) (string, error) {
	digest, err := ociremote.ResolveDigest(ref, opts.RegistryClientOpts...)
	if err != nil {
		return "", err
	}
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return "", err
	}
	return h.String(), nil
}
