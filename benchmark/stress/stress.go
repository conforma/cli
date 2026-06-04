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

// Stress benchmark validating a multi-component snapshot with a configurable
// number of workers, simulating real-world release pipeline workloads. The
// component count and worker count are controlled via the EC_STRESS_COMPONENTS
// and EC_STRESS_WORKERS environment variables respectively. Uses the same
// golden-container image data as the simple benchmark, duplicated across
// components to create memory pressure. The prepare_data.sh script can be used
// to re-populate the data directory.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"

	"golang.org/x/benchmarks/driver"

	"github.com/conforma/cli/benchmark/internal/registry"
	"github.com/conforma/cli/benchmark/internal/suite"
	"github.com/conforma/cli/benchmark/internal/untar"
)

const (
	defaultComponents = 10
	defaultWorkers    = 35
)

func main() {
	driver.Main("Stress", benchmark)
}

func envInt(name string, fallback int) int {
	v, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		panic(fmt.Sprintf("invalid %s value %q: %v", name, v, err))
	}
	return n
}

func setup() (string, suite.Closer) {
	dir, err := untar.UnTar("data.tar.gz")
	if err != nil {
		panic(err)
	}

	closer, err := registry.Launch(path.Join(dir, "data/registry/data"))
	if err != nil {
		panic(err)
	}

	return dir, func() {
		closer()
		os.RemoveAll(dir)
	}
}

type component struct {
	Name           string     `json:"name"`
	ContainerImage string     `json:"containerImage"`
	Source         *source    `json:"source,omitempty"`
}

type source struct {
	Git gitSource `json:"git"`
}

type gitSource struct {
	URL      string `json:"url"`
	Revision string `json:"revision"`
}

type snapshot struct {
	Components []component `json:"components"`
}

func buildSnapshot(n int) string {
	s := snapshot{Components: make([]component, n)}
	for i := range s.Components {
		s.Components[i] = component{
			Name:           fmt.Sprintf("golden-container-%d", i),
			ContainerImage: "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:166e38c156fa81d577a7ba7a948b68c79005a06e302779d1bebc7d31e8bea315",
			Source: &source{
				Git: gitSource{
					URL:      "https://github.com/enterprise-contract/golden-container.git",
					Revision: "8327c1ce7472b017b9396fe26d5d5e1ed0eb61cc",
				},
			},
		}
	}

	data, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func benchmark() driver.Result {
	dir, closer := setup()
	defer closer()

	components := envInt("EC_STRESS_COMPONENTS", defaultComponents)
	workers := envInt("EC_STRESS_WORKERS", defaultWorkers)

	return driver.Benchmark(run(dir, components, workers))
}

func ec(dir string, components, workers int) func() {
	snap := buildSnapshot(components)

	policy := fmt.Sprintf(`{
"publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZP/0htjhVt2y0ohjgtIIgICOtQtA\nnaYJRuLprwIv6FDhZ5yFjYUEtsmoNcW7rx2KM6FOXGsCX3BNc7qhHELT+g==\n-----END PUBLIC KEY-----",
"sources": [
{
  "data": [
    "git::file://%s/data/git/rhtap-ec-policy.git//data?ref=a524ee2f2f7774f6f360eb64c4cb24004de52aae",
    "oci::quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles@sha256:1e70b8f672388838f20a7d45e145e31e99dab06cefa1c5514d6ce41c8bbea1b0"
  ],
  "policy": [
    "oci::quay.io/enterprise-contract/ec-release-policy@sha256:64617f0c45689ef7152c5cfbd4cd5709a3126e4ab7482eb6acd994387fe2d4ba"
  ],
  "config": {
    "include": [
      "@redhat"
    ]
  }
}
]
}`, dir)

	return func() {
		if err := suite.Execute([]string{
			"validate",
			"image",
			"--json-input",
			snap,
			"--policy",
			policy,
			"--ignore-rekor",
			"--workers",
			strconv.Itoa(workers),
			"--effective-time",
			"2024-12-10T00:00:00Z",
		}); err != nil {
			panic(err)
		}
	}
}

func run(dir string, components, workers int) func(n uint64) {
	return func(n uint64) {
		driver.Parallel(n, 1, ec(dir, components, workers))
	}
}
