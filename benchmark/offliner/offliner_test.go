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
	"maps"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func TestItems(t *testing.T) {
	dest, err := name.NewRegistry("newregistry.io")
	if err != nil {
		t.Fatal(err)
	}

	imgs := []name.Reference{
		name.MustParseReference("registry.io/repository/image"),
		name.MustParseReference("registry.io/repository/image:tag"),
		name.MustParseReference("registry.io/repository/image@sha256:9f80b4f7506d2799298a685162723482cac160abf701e029ee5cbaa6c74967ea"),
	}

	got := items(imgs, dest)

	expected := map[string]string{
		"registry.io/repository/image":     "newregistry.io/repository/image:latest",
		"registry.io/repository/image:tag": "newregistry.io/repository/image:tag",
		"registry.io/repository/image@sha256:9f80b4f7506d2799298a685162723482cac160abf701e029ee5cbaa6c74967ea": "newregistry.io/repository/image@sha256:9f80b4f7506d2799298a685162723482cac160abf701e029ee5cbaa6c74967ea",
	}

	if !maps.Equal(expected, got) {
		t.Errorf("expected and got images differ: %v != %v", expected, got)
	}
}
