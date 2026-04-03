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

// Simple benchmark running the @redhat collection policy at a fixed point in
// time with the state of the container image registry contained within the
// data/registry and git state within data/git. The prepare_data.sh script can
// be used to re-populate the data directory.
package main

import (
	"fmt"
	"os"
	"path"

	"golang.org/x/benchmarks/driver"

	"github.com/conforma/cli/benchmark/internal/registry"
	"github.com/conforma/cli/benchmark/internal/suite"
	"github.com/conforma/cli/benchmark/internal/untar"
)

func main() {
	driver.Main("Simple", benchmark)
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

func benchmark() driver.Result {
	dir, closer := setup()
	defer closer()

	return driver.Benchmark(run(dir))
}

func ec(dir string) func() {
	snapshot := `{
"components": [
{
  "name": "golden-container",
  "containerImage": "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:166e38c156fa81d577a7ba7a948b68c79005a06e302779d1bebc7d31e8bea315",
  "source": {
	"git": {
	  "url": "https://github.com/conforma/golden-container",
	  "revision": "2dec8f515a64ef2f21ee3e7b1ed41da77a5c5a9a"
	}
  }
}
]
}`

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
	],
  },
}
]
}`, dir)

	return func() {
		if err := suite.Execute([]string{
			"validate",
			"image",
			"--json-input",
			snapshot,
			"--policy",
			policy,
			"--ignore-rekor",
			"--effective-time",
			"2024-12-10T00:00:00Z",
		}); err != nil {
			panic(err)
		}
	}
}

func run(dir string) func(n uint64) {
	return func(n uint64) {
		driver.Parallel(n, 1, ec(dir))
	}
}
