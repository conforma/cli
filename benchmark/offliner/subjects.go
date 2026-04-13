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
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func subjects(ref name.Reference) ([]name.Reference, error) {
	att := attestation(ref)

	img, err := remote.Image(att)
	if err != nil {
		return nil, err
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}

	refs := make([]name.Reference, 0, 5)
	for _, layer := range layers {
		if mt, err := layer.MediaType(); err != nil || mt != "application/vnd.dsse.envelope.v1+json" {
			continue
		}

		data, err := layer.Uncompressed()
		if err != nil {
			return nil, err
		}
		defer data.Close()

		var envelope dsse.Envelope
		decoder := json.NewDecoder(data)
		if err := decoder.Decode(&envelope); err != nil {
			return nil, err
		}

		if envelope.PayloadType != "application/vnd.in-toto+json" {
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			return nil, err
		}

		var statement in_toto.ProvenanceStatementSLSA02
		if err := json.Unmarshal(raw, &statement); err != nil {
			return nil, err
		}

		if statement.PredicateType != "https://slsa.dev/provenance/v0.2" {
			continue
		}

		for _, subject := range statement.Subject {
			ref, err := name.NewRepository(subject.Name)
			if err != nil {
				return nil, err
			}
			refs = append(refs, ref.Digest(fmt.Sprintf("sha256:%s", subject.Digest["sha256"])))
		}

	}

	return refs, nil
}
