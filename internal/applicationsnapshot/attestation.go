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

package applicationsnapshot

import (
	"bytes"
	"encoding/json"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/conforma/cli/internal/attestation"
	"github.com/conforma/cli/internal/signature"
)

type SLSAProvenance interface {
	attestation.Attestation
	PredicateBuildType() string
}

type AttestationResult struct {
	Type               string                      `json:"type,omitempty"`
	PredicateType      string                      `json:"predicateType,omitempty"`
	PredicateBuildType string                      `json:"predicateBuildType,omitempty"`
	Signatures         []signature.EntitySignature `json:"signatures,omitempty"`
	Statement          []byte                      `json:"-"`
}

func NewAttestationResult(att attestation.Attestation) AttestationResult {
	attResult := AttestationResult{
		Type:          att.Type(),
		PredicateType: att.PredicateType(),
		Signatures:    att.Signatures(),
	}
	if value, ok := att.(SLSAProvenance); ok {
		attResult.PredicateBuildType = value.PredicateBuildType()

	}
	return attResult
}

func (r *Report) renderAttestations() []byte {
	byts := make([][]byte, 0, len(r.Components)*2)

	for _, c := range r.Components {
		for _, a := range c.Attestations {
			byts = append(byts, a.Statement)
		}
	}

	return bytes.Join(byts, []byte{'\n'})
}

//nolint:staticcheck
func (r *Report) attestations() ([]in_toto.Statement, error) {
	//nolint:staticcheck
	var statements []in_toto.Statement
	for _, c := range r.Components {
		for _, a := range c.Attestations {
			//nolint:staticcheck
			var statement in_toto.Statement
			err := json.Unmarshal(a.Statement, &statement)
			if err != nil {
				//nolint:staticcheck
				return []in_toto.Statement{}, nil
			}
			statements = append(statements, statement)
		}
	}
	return statements, nil
}
