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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/types"

	"github.com/conforma/cli/internal/signature"
)

// Attestation holds the raw attestation data, usually fetched from the
// signature envelope's payload; statement of a particular type and any
// signing information.
type Attestation interface {
	Type() string
	PredicateType() string
	Statement() []byte
	Signatures() []signature.EntitySignature
	//nolint:staticcheck
	Subject() []in_toto.Subject
}

// Extract the payload from a DSSE signature OCI layer
func payloadFromSig(sig oci.Signature) (cosign.AttestationPayload, error) {
	var payload cosign.AttestationPayload

	if sig == nil {
		return payload, errors.New("no attestation found")
	}

	typ, err := sig.MediaType()
	if err != nil {
		return payload, fmt.Errorf("malformed attestation data: %w", err)
	}

	if typ != types.DssePayloadType {
		return payload, fmt.Errorf("malformed attestation data: expecting media type of `%s`, received: `%s`", types.DssePayloadType, typ)
	}

	reader, err := sig.Uncompressed()
	if err != nil {
		return payload, fmt.Errorf("malformed attestation data: %w", err)
	}
	defer reader.Close()

	err = json.NewDecoder(reader).Decode(&payload)
	if err != nil {
		return payload, fmt.Errorf("malformed attestation data: %w", err)
	}

	if payload.PayLoad == "" {
		return payload, errors.New("no `payload` data found")
	}

	return payload, nil
}

// Decode and return the base64 encoded payload string. Usually it contains
// json ready to be unmarshaled.
func decodedPayload(payload cosign.AttestationPayload) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(payload.PayLoad)
	if err != nil {
		return nil, fmt.Errorf("malformed attestation data: %w", err)
	}

	return decoded, nil
}

// Return details about the signatures used
func createEntitySignatures(sig oci.Signature, payload cosign.AttestationPayload) ([]signature.EntitySignature, error) {
	es, err := signature.NewEntitySignature(sig)
	if err != nil {
		return nil, err
	}

	var out []signature.EntitySignature
	for _, s := range payload.Signatures {
		esNew := es
		// The Signature and KeyID can come from two locations, the oci.Signature or
		// the cosign.Signature. In some cases, both are filled in, while in others
		// only one location contains the value. The discrepancy can be seen when
		// comparing signatures created via keyless vs long-lived key workflows. Here
		// we prioritize the information from oci.Signature, but fallback when needed
		// to cosign.Signature. (This inconsistency is likely a bug in cosign)
		if esNew.Signature == "" {
			esNew.Signature = s.Sig
		}
		if esNew.KeyID == "" {
			esNew.KeyID = s.KeyID
		}
		out = append(out, esNew)
	}
	return out, nil
}

// ProvenanceFromSignature parses an attestation layer from the provided OCI
// layer. Expects that the layer contains DSSE JSON with an embedded attestation
// of some type or other.
func ProvenanceFromSignature(sig oci.Signature) (Attestation, error) {
	payload, err := payloadFromSig(sig)
	if err != nil {
		return nil, err
	}

	embedded, err := decodedPayload(payload)
	if err != nil {
		return nil, err
	}

	//nolint:staticcheck
	var statement in_toto.Statement
	if err := json.Unmarshal(embedded, &statement); err != nil {
		return nil, fmt.Errorf("malformed attestation data: %w", err)
	}

	signatures, err := createEntitySignatures(sig, payload)
	if err != nil {
		return nil, fmt.Errorf("cannot create signed entity: %w", err)
	}

	return provenance{statement: statement, data: embedded, signatures: signatures}, nil
}

// ProvenanceFromBundlePayload parses an attestation from a raw DSSE envelope
// JSON payload as returned by the Sigstore bundle verification path.
func ProvenanceFromBundlePayload(dsseJSON []byte) (Attestation, error) {
	var payload cosign.AttestationPayload
	if err := json.Unmarshal(dsseJSON, &payload); err != nil {
		return nil, fmt.Errorf("malformed bundle attestation: %w", err)
	}

	if payload.PayLoad == "" {
		return nil, errors.New("no `payload` data found in bundle attestation")
	}

	embedded, err := decodedPayload(payload)
	if err != nil {
		return nil, err
	}

	//nolint:staticcheck
	var statement in_toto.Statement
	if err := json.Unmarshal(embedded, &statement); err != nil {
		return nil, fmt.Errorf("malformed bundle attestation: %w", err)
	}

	return provenance{statement: statement, data: embedded}, nil
}

type provenance struct {
	//nolint:staticcheck
	statement  in_toto.Statement
	data       []byte
	signatures []signature.EntitySignature
}

func (p provenance) Type() string {
	return in_toto.StatementInTotoV01
}

func (p provenance) PredicateType() string {
	return p.statement.StatementHeader.PredicateType
}

func (p provenance) Statement() []byte {
	return p.data
}

func (p provenance) Signatures() []signature.EntitySignature {
	return p.signatures
}

//nolint:staticcheck
func (p provenance) Subject() []in_toto.Subject {
	return p.statement.Subject
}
