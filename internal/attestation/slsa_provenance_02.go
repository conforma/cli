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

package attestation

import (
	"encoding/json"
	"fmt"

	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sigstore/cosign/v3/pkg/oci"

	"github.com/conforma/cli/internal/signature"
)

const (
	// Make it visible elsewhere
	PredicateSLSAProvenance = v02.PredicateSLSAProvenance
)

// SLSAProvenanceFromSignature parses the SLSA Provenance v0.2 from the provided OCI
// layer. Expects that the layer contains DSSE JSON with the embedded SLSA
// Provenance v0.2 payload.
func SLSAProvenanceFromSignature(sig oci.Signature) (Attestation, error) {
	payload, err := payloadFromSig(sig)
	if err != nil {
		return nil, err
	}

	embedded, err := decodedPayload(payload)
	if err != nil {
		return nil, err
	}

	var statement in_toto.ProvenanceStatementSLSA02
	if err := json.Unmarshal(embedded, &statement); err != nil {
		return nil, fmt.Errorf("malformed attestation data: %w", err)
	}

	if statement.Type != in_toto.StatementInTotoV01 {
		return nil, fmt.Errorf("unsupported attestation type: %s", statement.Type)
	}

	if statement.PredicateType != v02.PredicateSLSAProvenance {
		return nil, fmt.Errorf("unsupported attestation predicate type: %s", statement.PredicateType)
	}

	signatures, err := createEntitySignatures(sig, payload)
	if err != nil {
		return nil, fmt.Errorf("cannot create signed entity: %w", err)
	}

	return slsaProvenance{statement: statement, data: embedded, signatures: signatures}, nil
}

type slsaProvenance struct {
	statement  in_toto.ProvenanceStatementSLSA02
	data       []byte
	signatures []signature.EntitySignature
}

func (a slsaProvenance) Type() string {
	return in_toto.StatementInTotoV01
}

func (a slsaProvenance) PredicateType() string {
	return v02.PredicateSLSAProvenance
}

// This returns the raw json, not the content of a.statement
func (a slsaProvenance) Statement() []byte {
	return a.data
}

func (a slsaProvenance) PredicateBuildType() string {
	return a.statement.Predicate.BuildType
}

func (a slsaProvenance) Signatures() []signature.EntitySignature {
	return a.signatures
}

func (a slsaProvenance) Subject() []in_toto.Subject {
	return a.statement.Subject
}

// Todo: It seems odd that this does not contain the statement.
// (See also the equivalent method in attestation.go)
func (a slsaProvenance) MarshalJSON() ([]byte, error) {
	val := struct {
		Type               string                      `json:"type"`
		PredicateType      string                      `json:"predicateType"`
		PredicateBuildType string                      `json:"predicateBuildType"`
		Signatures         []signature.EntitySignature `json:"signatures"`
	}{
		Type:               a.statement.Type,
		PredicateType:      a.statement.PredicateType,
		PredicateBuildType: a.statement.Predicate.BuildType,
		Signatures:         a.signatures,
	}

	return json.Marshal(val)
}
