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

// Package evidence collects authenticated, image-bound attestations independently
// of their storage location. It does not decide whether their predicates pass policy.
package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/types"

	"github.com/conforma/cli/internal/attestation"
)

const imageSignaturePredicate = "https://sigstore.dev/cosign/sign/v1"

// AttestationSource returns only verified attestations whose signed subjects match
// ref. An empty result is absence; errors must not be hidden by another source.
// Implementations support concurrent calls. Callers must treat results as read-only.
type AttestationSource interface {
	Collect(context.Context, name.Digest) ([]attestation.Attestation, error)
}

// parse preserves the existing SLSA-specific implementations used by reports.
// The caller MUST verify the envelope before admitting the returned object.
func parse(sig oci.Signature) (attestation.Attestation, error) {
	payload, err := sig.Payload()
	if err != nil {
		return nil, err
	}
	a, err := attestation.ProvenanceFromBundlePayload(sig, payload)
	if err != nil {
		return nil, err
	}
	if err := requireStatement(a.Statement()); err != nil {
		return nil, err
	}
	// Normalize the OCI wrapper media type, without changing the signed payload.
	mediaType, err := sig.MediaType()
	if err != nil {
		return nil, err
	}
	normalized := sig
	if mediaType != types.DssePayloadType {
		normalized, err = static.NewAttestation(payload)
		if err != nil {
			return nil, err
		}
	}
	switch a.PredicateType() {
	case attestation.PredicateSLSAProvenance:
		return attestation.SLSAProvenanceFromSignature(normalized)
	case attestation.PredicateSLSAProvenanceV1:
		return attestation.SLSAProvenanceFromSignatureV1(normalized)
	default:
		return a, nil
	}
}

func requireStatement(payload []byte) error {
	if err := unambiguousJSON(payload); err != nil {
		return err
	}
	// encoding/json matches struct fields case-insensitively, while Rego and
	// in-toto use exact names. Do not allow an alias to select another signer.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return err
	}
	for key := range fields {
		for _, canonical := range []string{"_type", "predicateType", "predicate", "subject"} {
			if key != canonical && strings.EqualFold(key, canonical) {
				return fmt.Errorf("noncanonical statement field %q", key)
			}
		}
	}
	var s struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
		Subject       []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payload, &s); err != nil {
		return err
	}
	if s.Type != "https://in-toto.io/Statement/v1" && s.Type != "https://in-toto.io/Statement/v0.1" {
		return fmt.Errorf("unsupported in-toto statement type %q", s.Type)
	}
	if s.PredicateType == "" || len(s.Predicate) == 0 || string(s.Predicate) == "null" || len(s.Subject) == 0 {
		return fmt.Errorf("statement requires predicateType, predicate and subjects")
	}
	return nil
}
