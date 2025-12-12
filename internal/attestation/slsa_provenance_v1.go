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
	v1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"github.com/sigstore/cosign/v2/pkg/oci"

	"github.com/conforma/cli/internal/signature"
	"github.com/conforma/cli/pkg/schema"
)

const (
	// Make it visible elsewhere
	PredicateSLSAProvenanceV1 = v1.PredicateSLSAProvenance
)

// SLSAProvenanceFromSignatureV1 parses the SLSA Provenance v1 from the provided OCI
// layer. Expects that the layer contains DSSE JSON with the embedded SLSA
// Provenance v1 payload.
func SLSAProvenanceFromSignatureV1(sig oci.Signature) (Attestation, error) {
	payload, err := payloadFromSig(sig)
	if err != nil {
		return nil, err
	}

	embedded, err := decodedPayload(payload)
	if err != nil {
		return nil, err
	}

	var statement in_toto.ProvenanceStatementSLSA1
	if err := json.Unmarshal(embedded, &statement); err != nil {
		return nil, fmt.Errorf("malformed attestation data: %w", err)
	}

	if statement.Type != in_toto.StatementInTotoV01 {
		return nil, fmt.Errorf("unsupported attestation type: %s", statement.Type)
	}

	if statement.PredicateType != v1.PredicateSLSAProvenance {
		return nil, fmt.Errorf("unsupported attestation predicate type: %s", statement.PredicateType)
	}

	signatures, err := createEntitySignatures(sig, payload)
	if err != nil {
		return nil, fmt.Errorf("cannot create signed entity: %w", err)
	}

	// Validate against SLSA v1 schema
	var schemaValidation any
	if err := json.Unmarshal(embedded, &schemaValidation); err == nil {
		if err := schema.SLSA_Provenance_v1.Validate(schemaValidation); err != nil {
			return nil, fmt.Errorf("attestation does not conform to SLSA v1.0 schema: %w", err)
		}
	}

	return slsaProvenanceV1{statement: statement, data: embedded, signatures: signatures}, nil
}

type slsaProvenanceV1 struct {
	statement  in_toto.ProvenanceStatementSLSA1
	data       []byte
	signatures []signature.EntitySignature
}

func (a slsaProvenanceV1) Type() string {
	return in_toto.StatementInTotoV01
}

func (a slsaProvenanceV1) PredicateType() string {
	return v1.PredicateSLSAProvenance
}

// This returns the raw json, not the content of a.statement
func (a slsaProvenanceV1) Statement() []byte {
	return a.data
}

func (a slsaProvenanceV1) PredicateBuildType() string {
	return a.statement.Predicate.BuildDefinition.BuildType
}

func (a slsaProvenanceV1) Signatures() []signature.EntitySignature {
	return a.signatures
}

func (a slsaProvenanceV1) Subject() []in_toto.Subject {
	return a.statement.Subject
}
