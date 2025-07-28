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

package tracker

import (
	"context"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	echttp "github.com/conforma/cli/internal/http"
)

const (
	unknownConfig       = "application/vnd.unknown.config.v1+json"
	openPolicyAgentData = "application/vnd.cncf.openpolicyagent.data.layer.v1+json"
	title               = "org.opencontainers.image.title"
	dataFileTitle       = "data/data/trusted_tekton_tasks.yml"
)

type ctxKey int

const registryKey ctxKey = 0

type registry interface {
	write(name.Reference, v1.Image, ...remote.Option) error
	read(name.Reference, ...remote.Option) (v1.Image, error)
}

type containerRegistry struct{}

func (containerRegistry) write(ref name.Reference, image v1.Image, options ...remote.Option) error {
	return remote.Write(ref, image, options...)
}

func (containerRegistry) read(ref name.Reference, options ...remote.Option) (v1.Image, error) {
	options = append(options, remote.WithTransport(echttp.NewRetryTransport(remote.DefaultTransport)))
	return remote.Image(ref, options...)
}

var defaultRegistry = containerRegistry{}

func PullImage(ctx context.Context, imageRef string) ([]byte, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	img, err := r(ctx).read(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}

	var data []byte
	for i, layer := range layers {
		mediaType, err := layer.MediaType()
		if err != nil {
			return nil, err
		}

		if mediaType != openPolicyAgentData {
			continue
		}

		if i > 0 {
			data = append(data, []byte("\n---\n")...)
		}

		in, err := layer.Uncompressed()
		if err != nil {
			return nil, err
		}
		defer in.Close()

		bytes, err := io.ReadAll(in)
		if err != nil {
			return nil, err
		}

		data = append(data, bytes...)
	}

	return data, nil
}

func PushImage(ctx context.Context, imageRef string, data []byte, invocation string) (err error) {
	var ref name.Reference
	ref, err = name.ParseReference(imageRef)
	if err != nil {
		return
	}

	bundle := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	bundle = mutate.ConfigMediaType(bundle, unknownConfig)
	if bundle, err = mutate.Append(bundle, mutate.Addendum{
		History: v1.History{
			CreatedBy: invocation,
		},
		MediaType: openPolicyAgentData,
		Layer:     static.NewLayer(data, openPolicyAgentData),
		Annotations: map[string]string{
			title: dataFileTitle,
		},
	}); err != nil {
		return
	}

	return r(ctx).write(ref, bundle, remote.WithAuthFromKeychain(authn.DefaultKeychain))
}

func r(ctx context.Context) registry {
	r, ok := ctx.Value(registryKey).(registry)
	if !ok {
		r = defaultRegistry
	}

	return r
}
