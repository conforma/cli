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

package tekton

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	"github.com/tektoncd/pipeline/pkg/remote/oci"

	"github.com/conforma/cli/acceptance/registry"
)

const version = "v1"

func createTektonBundle(ctx context.Context, name string, data *godog.Table) (context.Context, error) {
	img := empty.Image

	for _, row := range data.Rows {
		kind := row.Cells[0].Value
		name := row.Cells[1].Value

		content := contentFor(kind, name)

		data := bytes.Buffer{}
		writer := tar.NewWriter(&data)
		if err := writer.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o600,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			return ctx, err
		}
		if _, err := writer.Write(content); err != nil {
			return ctx, err
		}
		if err := writer.Close(); err != nil {
			return ctx, err
		}

		layer := stream.NewLayer(io.NopCloser(&data))

		var err error
		img, err = mutate.Append(img, mutate.Addendum{
			Layer: layer,
			Annotations: map[string]string{
				oci.APIVersionAnnotation: version,
				oci.KindAnnotation:       strings.ToLower(kind),
				oci.TitleAnnotation:      name,
			},
		})
		if err != nil {
			return ctx, err
		}
	}

	ref, err := registry.ImageReferenceInStubRegistry(ctx, name)
	if err != nil {
		return ctx, err
	}

	err = remote.Write(ref, img)
	if err != nil {
		return ctx, err
	}

	return ctx, nil
}

func contentFor(kind, name string) []byte {
	switch kind {
	case "Pipeline":
		return contentForPipeline(name)
	case "Task":
		return contentForTask(name)
	default:
		panic(fmt.Sprintf("Unexpected kind %q", kind))
	}
}

func contentForPipeline(name string) []byte {
	content := fmt.Sprintf(`apiVersion: tekton.dev/%s
kind: Pipeline
metadata:
  name: %s
spec:
  tasks:
  - taskRef:
      kind: Task
      name: git-clone
`, version, name)

	return []byte(content)
}

func contentForTask(name string) []byte {
	content := fmt.Sprintf(`apiVersion: tekton.dev/%s
kind: Task
metadata:
  name: %s
spec:`, version, name)

	return []byte(content)
}

func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^a tekton bundle image named "([^"]*)" containing$`, createTektonBundle)
}
