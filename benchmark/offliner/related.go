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
	"log"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type relatedFn func(ref name.Reference) ([]name.Reference, error)

func related(ref name.Reference) ([]name.Reference, error) {
	references := []name.Reference{ref}

	for _, r := range []name.Reference{
		signature(ref),
		attestation(ref),
		sbom(ref),
	} {
		if _, err := remote.Image(r); err == nil {
			references = append(references, r)
		} else {
			log.Printf("Can't dereference %q: %v", r, err)
		}
	}

	related := []relatedFn{
		referrers,
		baseImages,
		scanReports,
		subjects,
	}

	for _, rel := range related {
		refs, err := rel(ref)
		if err != nil {
			log.Printf("Can't fetch related image for %q: %v", ref, err)
			continue
		}
		references = append(references, refs...)
	}

	cmp := func(a, b name.Reference) int {
		return strings.Compare(a.String(), b.String())
	}

	for _, ref := range references {
		if _, ok := ref.(name.Digest); !ok {
			img, err := remote.Image(ref)
			if err != nil {
				return nil, err
			}

			digest, err := img.Digest()
			if err != nil {
				return nil, err
			}

			ref = ref.Context().Digest(digest.String())
		}

		ref := signature(ref)
		if _, err := remote.Image(ref); err == nil {
			references = append(references, ref)
		} else {
			log.Printf("Can't dereference %q: %v", ref, err)
		}
	}

	slices.SortFunc(references, cmp)

	return slices.Compact(references), nil
}
