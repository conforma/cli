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

// Package registry is a stub implementation of a container registry
package registry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/diff"
	"github.com/pkg/errors"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/conforma/cli/acceptance/log"
	"github.com/conforma/cli/acceptance/testenv"
)

// the image we're using to launch the stub image registry
// Using Zot which has proper OCI Referrers API support
const registryImage = "ghcr.io/project-zot/zot:v2.1.15"

type key int

// key to store the host:port of the stubbed registry in Context and persisted environment
const registryStateKey = key(0)

type registryState struct {
	HostAndPort string
	Container   testcontainers.Container `json:"-"`
}

func (g registryState) Key() any {
	return registryStateKey
}

func (g registryState) Up() bool {
	return g.HostAndPort != ""
}

// startStubRegistry creates and starts the stub image registry
func startStubRegistry(ctx context.Context) (context.Context, error) {
	var state *registryState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Up() {
		return ctx, nil
	}

	// Create a minimal Zot configuration with error-only logging to reduce I/O overhead
	// This dramatically reduces disk I/O and prevents DNS timeouts under load
	// Using the exact same structure as Zot's minimal example config but with error-level logging
	// The "compat": ["docker2s2"] enables Docker v2 Schema 2 manifest compatibility
	zotConfig := `{
		"distSpecVersion": "1.1.1",
		"storage": {
			"rootDirectory": "/var/lib/registry"
		},
		"http": {
			"address": "0.0.0.0",
			"port": "5000",
			"compat": ["docker2s2"]
		},
		"log": {
			"level": "error"
		}
	}`

	req := testenv.TestContainersRequest(ctx, testcontainers.ContainerRequest{
		Image:        registryImage,
		ExposedPorts: []string{"0.0.0.0::5000/tcp"},
		WaitingFor:   wait.ForHTTP("/v2/").WithPort("5000/tcp"),
		Cmd:          []string{"serve", "/config/config.json"},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      "",
				ContainerFilePath: "/config/config.json",
				FileMode:          0644,
				Reader:            strings.NewReader(zotConfig),
			},
		},
	})

	logger, ctx := log.LoggerFor(ctx)

	registry, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           logger,
	})
	if err != nil {
		return ctx, err
	}

	state.Container = registry

	port, err := registry.MappedPort(ctx, "5000/tcp")
	if err != nil {
		return ctx, err
	}

	state.HostAndPort = fmt.Sprintf("localhost:%d", port.Int())

	return ctx, nil
}

// ImageReferenceInStubRegistry returns a reference for an image constructed by concatenating
// the host:port/`imageName`
func ImageReferenceInStubRegistry(ctx context.Context, imageName string) (name.Reference, error) {
	registry, err := StubRegistry(ctx)
	if err != nil {
		return nil, err
	}

	imageRef := registry + "/" + imageName

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		panic(errors.Wrapf(err, "unable to parse image reference: %s", imageRef))
	}

	return ref, nil
}

// StubRegistry returns the host:port of the stubbed registry from the Context
func StubRegistry(ctx context.Context) (string, error) {
	state := testenv.FetchState[registryState](ctx)

	if !state.Up() {
		return "", errors.New("no state setup, did you start the registry stub server?")
	}

	return state.HostAndPort, nil
}

func IsRunning(ctx context.Context) bool {
	if !testenv.HasState[registryState](ctx) {
		return false
	}

	state := testenv.FetchState[registryState](ctx)
	return state.Up()
}

// Url returns the host:port needed to interact with the registry
func Url(ctx context.Context) (string, error) {
	if !testenv.HasState[registryState](ctx) {
		return "", errors.New("no state setup, did you start the registry stub server?")
	}

	state := testenv.FetchState[registryState](ctx)
	return state.HostAndPort, nil
}

// AllDigests returns a map of image digests keyed by `repository:tag` for all
// images stored in the registry
func AllDigests(ctx context.Context) (map[string]string, error) {
	url, err := StubRegistry(ctx)
	if err != nil {
		return nil, err
	}

	registry, err := name.NewRegistry(url)
	if err != nil {
		return nil, err
	}

	repositories, err := remote.Catalog(ctx, registry, remote.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	vars := map[string]string{}
	refsByDigest := map[string][]string{}
	for _, repository := range repositories {
		r, err := name.NewRepository(repository, name.WithDefaultRegistry(url))
		if err != nil {
			return nil, err
		}

		tags, err := remote.List(r, remote.WithContext(ctx))
		if err != nil {
			return nil, err
		}

		for _, tag := range tags {
			ref, err := name.ParseReference(repository+":"+tag, name.WithDefaultRegistry(url))
			if err != nil {
				return nil, err
			}

			descriptor, err := remote.Get(ref, remote.WithContext(ctx))
			if err != nil {
				return nil, err
			}

			digest := descriptor.Digest.Hex
			imgRef := repository + ":" + tag
			vars[imgRef] = digest
			refsByDigest[digest] = append(refsByDigest[digest], imgRef)
		}
	}

	// images could have same hashes, then our matching fails as we could
	// reversly map a digest to either of the two or more references, with this
	// we remove the references with the same digest and map to a synthetic
	// "IMAGE_ref1|ref2|..." reference
	for _, digest := range vars {
		if len(refsByDigest[digest]) == 1 {
			// unique digest
			continue
		}

		for _, sameDigestRef := range refsByDigest[digest] {
			delete(vars, sameDigestRef)
		}

		sort.Strings(refsByDigest[digest])
		refs := strings.Join(refsByDigest[digest], "|")
		vars["IMAGE_"+refs] = digest
	}

	return vars, nil
}

func assertImageContent(ctx context.Context, imageRef string, data *godog.DocString) error {
	state := testenv.FetchState[registryState](ctx)

	ref, err := name.ParseReference(fmt.Sprintf("%s/%s", state.HostAndPort, imageRef))
	if err != nil {
		return err
	}

	img, err := remote.Image(ref)
	if err != nil {
		return err
	}

	layers, err := img.Layers()
	if err != nil {
		return err
	}

	if len(layers) != 1 {
		return fmt.Errorf("unexpected number of layers: %d, expecting only one", len(layers))
	}

	in, err := layers[0].Uncompressed()
	if err != nil {
		return err
	}
	defer in.Close()

	content, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	vals := map[string]string{
		"REGISTRY":           state.HostAndPort,
		"TODAY_PLUS_30_DAYS": time.Now().Round(time.Hour*24).UTC().AddDate(0, 0, 30).Format(time.RFC3339),
	}

	expected := os.Expand(data.Content, func(key string) string {
		return vals[key]
	})

	got := string(content)

	if expected == got {
		return nil
	}

	var b bytes.Buffer
	err = diff.Text("layer", "expected", got, expected, &b)
	if err != nil {
		return err
	}

	return fmt.Errorf("expected image layer and actual image layer differ:\n%s", b.String())
}

func Register(ctx context.Context, hostAndPort string) (context.Context, error) {
	var state *registryState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Up() {
		return ctx, errors.New("A registry has already been stubbed in this context")
	}

	state.HostAndPort = hostAndPort

	return ctx, nil
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^stub registry running$`, startStubRegistry)
	sc.Step(`^registry image "([^"]*)" should contain a layer with$`, assertImageContent)

	sc.After(func(ctx context.Context, finished *godog.Scenario, scenarioErr error) (context.Context, error) {
		if testenv.Persisted(ctx) {
			return ctx, nil
		}

		if !testenv.HasState[registryState](ctx) {
			return ctx, nil
		}

		state := testenv.FetchState[registryState](ctx)
		if state.Container != nil {
			if err := state.Container.Terminate(ctx); err != nil {
				logger, _ := log.LoggerFor(ctx)
				logger.Warnf("failed to terminate registry container: %v", err)
			}
		}

		return ctx, nil
	})
}
