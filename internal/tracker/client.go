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

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/tektoncd/pipeline/pkg/remote/oci"
	"k8s.io/apimachinery/pkg/runtime"

	echttp "github.com/conforma/cli/internal/http"
)

type Client interface {
	GetTektonObject(ctx context.Context, bundle, kind, name string) (runtime.Object, error)
	GetImage(ctx context.Context, ref name.Reference) (v1.Image, error)
}

type contextKey string

const clientContextKey contextKey = "ec.tracker.client"

// WithClient returns a copy of given context with the included client.
func WithClient(ctx context.Context, client Client) context.Context {
	return context.WithValue(ctx, clientContextKey, client)
}

// NewClient returns the client from the context if set, otherwise a new instance.
func NewClient(ctx context.Context) Client {
	if client, ok := ctx.Value(clientContextKey).(Client); ok && client != nil {
		return client
	}
	return exoClient{}
}

type exoClient struct{}

func (c exoClient) GetTektonObject(ctx context.Context, bundle, kind, name string) (o runtime.Object, err error) {
	o, _, err = oci.NewResolver(bundle, nil).Get(ctx, kind, name)
	return
}

func (c exoClient) GetImage(ctx context.Context, ref name.Reference) (v1.Image, error) {
	return remote.Image(ref, remote.WithContext(ctx), remote.WithTransport(echttp.NewRetryTransport(remote.DefaultTransport)))
}
