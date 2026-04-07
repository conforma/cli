//go:build benchmark

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

package main

import (
	"encoding/json"
	"strconv"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spdx/tools-golang/spdx"
)

func baseImages(ref name.Reference) ([]name.Reference, error) {
	sbomRef := digestTag(ref, "sbom")

	img, err := remote.Image(sbomRef)
	if err != nil {
		return nil, err
	}

	refs := make([]name.Reference, 0, 5)
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}

	fromCycloneDX := func(layer v1.Layer) ([]name.Reference, error) {
		var refs = make([]name.Reference, 0, 5)

		data, err := layer.Uncompressed()
		if err != nil {
			return nil, err
		}
		defer data.Close()

		decoder := cyclonedx.NewBOMDecoder(data, cyclonedx.BOMFileFormatJSON)

		var bom cyclonedx.BOM
		if err := decoder.Decode(&bom); err != nil {
			return nil, err
		}

		isNumber := func(s string) bool {
			_, err := strconv.ParseUint(s, 10, 64)
			return err == nil
		}

		for _, formulation := range nab(bom.Formulation) {
			for _, component := range nab(formulation.Components) {
				if component.Type != cyclonedx.ComponentTypeContainer {
					continue
				}

				for _, property := range nab(component.Properties) {
					isBase := property.Name == "konflux:container:is_base_image" && property.Value == "true"
					isStage := property.Name == "konflux:container:is_builder_image:for_stage" && isNumber(property.Value)
					if !isBase && !isStage {
						continue
					}

					if r, err := name.ParseReference(component.Name); err == nil {
						refs = append(refs, r)
					}
				}
			}
		}

		return refs, nil
	}

	fromSPDX := func(layer v1.Layer) ([]name.Reference, error) {
		var refs = make([]name.Reference, 0, 5)

		data, err := layer.Uncompressed()
		if err != nil {
			return nil, err
		}
		defer data.Close()

		decoder := json.NewDecoder(data)

		var bom spdx.Document
		if err := decoder.Decode(&bom); err != nil {
			return nil, err
		}

		// TODO missing the rest of the implementation here, lacking SPDX
		// examples currently. Missing parsing and extracting base images from
		// SPDX, similarly to how it is done for CycloneDX

		return refs, nil
	}

	for _, layer := range layers {
		mt, err := layer.MediaType()
		if err != nil {
			return nil, err
		}

		var fetch func(v1.Layer) ([]name.Reference, error) = func(l v1.Layer) ([]name.Reference, error) { return nil, nil }
		switch mt {
		case "application/vnd.cyclonedx+json":
			fetch = fromCycloneDX
		case "text/spdx+json":
			fetch = fromSPDX
		}

		if more, err := fetch(layer); err != nil {
			return nil, err
		} else {
			refs = append(refs, more...)
		}
	}

	return refs, nil
}
