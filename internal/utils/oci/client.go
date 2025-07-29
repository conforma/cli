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

package oci

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"runtime/trace"
	"strconv"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	log "github.com/sirupsen/logrus"

	echttp "github.com/conforma/cli/internal/http"
)

type contextKey string

const clientContextKey contextKey = "ec.oci.client"

var imgCache = sync.OnceValue(initCache)

func init() {
	// if log.IsLevelEnabled(log.TraceLevel) {
	// 	// imageRefTransport = remote.WithTransport(echttp.NewTracingRoundTripper(remote.DefaultTransport))
	// }
}

func initCache() cache.Cache {
	// if a value was set and it is parsed as false, turn the cache off
	if v, err := strconv.ParseBool(os.Getenv("EC_CACHE")); err == nil && !v {
		return nil
	}

	if userCache, err := os.UserCacheDir(); err != nil {
		log.Debug("unable to find user cache directory")
		return nil
	} else {
		imgCacheDir := path.Join(userCache, "ec", "images")
		if err := os.MkdirAll(imgCacheDir, 0700); err != nil {
			log.Debugf("unable to create temporary directory for image cache in %q: %v", imgCacheDir, err)
			return nil
		}
		log.Debugf("using %q directory to store image cache", imgCacheDir)
		return cache.NewFilesystemCache(imgCacheDir)
	}
}

func createRemoteOptions(ctx context.Context) []remote.Option {
	backoff := remote.Backoff{
		Duration: echttp.DefaultBackoff.Duration,
		Factor:   echttp.DefaultBackoff.Factor,
		Jitter:   echttp.DefaultBackoff.Jitter,
		Steps:    echttp.DefaultRetry.MaxRetry,
	}

	// Create a transport that handles transient errors with exponential backoff
	var transport http.RoundTripper
	if log.IsLevelEnabled(log.TraceLevel) {
		transport = echttp.NewTracingRoundTripper(echttp.NewRetryTransport(remote.DefaultTransport))
	} else {
		transport = echttp.NewRetryTransport(remote.DefaultTransport)
	}

	return []remote.Option{
		remote.WithTransport(transport),
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithRetryBackoff(backoff),
	}
}

type Client interface {
	VerifyImageSignatures(name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
	VerifyImageAttestations(name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
	Head(name.Reference) (*v1.Descriptor, error)
	ResolveDigest(name.Reference) (string, error)
	Image(name.Reference) (v1.Image, error)
	Layer(name.Digest) (v1.Layer, error)
	Index(name.Reference) (v1.ImageIndex, error)
}

func WithClient(ctx context.Context, client Client) context.Context {
	return context.WithValue(ctx, clientContextKey, client)
}

// NewClient constructs a new application_snapshot_image with the default client.
func NewClient(ctx context.Context, opts ...remote.Option) Client {
	client, ok := ctx.Value(clientContextKey).(Client)
	if ok && client != nil {
		return client
	}

	o := opts
	if len(opts) == 0 {
		o = createRemoteOptions(ctx)
	}

	return &defaultClient{ctx, o}
}

type defaultClient struct {
	ctx  context.Context
	opts []remote.Option
}

func (c *defaultClient) VerifyImageSignatures(ref name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(c.ctx, "ec:validate-image-signatures")
		defer region.End()
		trace.Logf(c.ctx, "", "image=%q", ref)
	}

	opts.RegistryClientOpts = append(opts.RegistryClientOpts, ociremote.WithRemoteOptions(c.opts...))
	return cosign.VerifyImageSignatures(c.ctx, ref, opts)
}

func (c *defaultClient) VerifyImageAttestations(ref name.Reference, opts *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(c.ctx, "ec:validate-image-attestations")
		defer region.End()
		trace.Logf(c.ctx, "", "image=%q", ref)
	}

	opts.RegistryClientOpts = append(opts.RegistryClientOpts, ociremote.WithRemoteOptions(c.opts...))
	return cosign.VerifyImageAttestations(c.ctx, ref, opts)
}

func (c *defaultClient) Head(ref name.Reference) (*v1.Descriptor, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(c.ctx, "ec:oci-head")
		defer region.End()
		trace.Logf(c.ctx, "", "image=%q", ref)
	}

	return remote.Head(ref, c.opts...)
}

// gather all attestation uris and digests associated with an image
func (c *defaultClient) AttestationUri(img string) (string, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(c.ctx, "ec:oci-attestation-uri")
		defer region.End()
		trace.Logf(c.ctx, "", "image=%q", img)
	}

	imgRef, err := name.ParseReference(img)
	if err != nil {
		return "", err
	}

	digest, err := ociremote.ResolveDigest(imgRef, ociremote.WithRemoteOptions(c.opts...))
	if err != nil {
		return "", err
	}

	st, err := ociremote.AttestationTag(digest, ociremote.WithRemoteOptions(c.opts...))
	if err != nil {
		return "", err
	}

	return st.Name(), nil
}

func (c *defaultClient) ResolveDigest(ref name.Reference) (string, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(c.ctx, "ec:oci-resolve-digest")
		defer region.End()
		trace.Logf(c.ctx, "", "image=%q", ref)
	}

	digest, err := ociremote.ResolveDigest(ref, ociremote.WithRemoteOptions(c.opts...))
	if err != nil {
		return "", err
	}
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return "", err
	}
	return h.String(), nil
}

func (c *defaultClient) Image(ref name.Reference) (v1.Image, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(c.ctx, "ec:oci-fetch-image")
		defer region.End()
		trace.Logf(c.ctx, "", "image=%q", ref)
	}

	img, err := remote.Image(ref, c.opts...)
	if err != nil {
		return nil, err
	}

	if c := imgCache(); c != nil {
		img = cache.Image(img, c)
	}

	return img, nil
}

func (c *defaultClient) Layer(ref name.Digest) (v1.Layer, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(c.ctx, "ec:oci-fetch-layer")
		defer region.End()
		trace.Logf(c.ctx, "", "image=%q", ref)
	}

	// TODO: Caching a layer directly is difficult and may not be possible, see:
	//   https://github.com/google/go-containerregistry/issues/1821
	layer, err := remote.Layer(ref, c.opts...)
	if err != nil {
		return nil, fmt.Errorf("fetching layer: %w", err)
	}
	return layer, nil
}

func (c *defaultClient) Index(ref name.Reference) (v1.ImageIndex, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(c.ctx, "ec:oci-fetch-index")
		defer region.End()
		trace.Logf(c.ctx, "", "image=%q", ref)
	}

	index, err := remote.Index(ref, c.opts...)
	if err != nil {
		return nil, fmt.Errorf("fetching index: %w", err)
	}

	return index, nil
}
