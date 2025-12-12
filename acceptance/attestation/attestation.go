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

// Package attestation helps create SLSA provenance attestations in-toto format, simulating what
// Tekton Chains would perform.
package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"

	"github.com/conforma/cli/acceptance/crypto"
)

const (
	PredicateBuilderID   = "https://tekton.dev/chains/v2"
	PredicateBuilderType = "https://tekton.dev/attestations/chains/pipelinerun@v2"
	PredicateType        = "slsaprovenance"
	PredicateTypeV1      = "slsaprovenance1"
)

// CreateStatementFor creates an empty statement that can be further customized
// to add and subsequently signed by SignStatement.
func CreateStatementFor(imageName string, image v1.Image) (*in_toto.ProvenanceStatementSLSA02, error) {
	digest, err := image.Digest()
	if err != nil {
		return nil, err
	}

	obj, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: bytes.NewReader([]byte(fmt.Sprintf(`{
			"builder": {
				"id": "%s"
			},
			"buildType": "%s"
		}`, PredicateBuilderID, PredicateBuilderType))),
		Type:   PredicateType,
		Digest: digest.Hex,
		Repo:   imageName,
	})
	if err != nil {
		return nil, err
	}

	if statement, ok := obj.(in_toto.ProvenanceStatementSLSA02); ok {
		return &statement, nil
	}

	return nil, fmt.Errorf("received statement of unsupported type: %v", obj)
}

// CreateV1StatementFor creates an empty SLSA v1.0 statement that can be further customized
// and subsequently signed by SignStatement.
func CreateV1StatementFor(imageName string, image v1.Image) (*in_toto.ProvenanceStatementSLSA1, error) {
	digest, err := image.Digest()
	if err != nil {
		return nil, err
	}

	obj, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: bytes.NewReader([]byte(fmt.Sprintf(`{
			"buildDefinition": {
				"buildType": "%s",
				"externalParameters": {}
			},
			"runDetails": {
				"builder": {
					"id": "%s"
				}
			}
		}`, PredicateBuilderType, PredicateBuilderID))),
		Type:   PredicateTypeV1,
		Digest: digest.Hex,
		Repo:   imageName,
	})
	if err != nil {
		return nil, err
	}

	if statement, ok := obj.(in_toto.ProvenanceStatementSLSA1); ok {
		return &statement, nil
	}

	return nil, fmt.Errorf("received statement of unsupported type: %v", obj)
}

// SignStatement signs the provided statement with the named key. The key needs
// to be previously generated with the functionality from the crypto package.
func SignStatement(ctx context.Context, keyName string, statement any) ([]byte, error) {
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}

	signer, err := crypto.SignerWithKey(ctx, keyName)
	if err != nil {
		return nil, err
	}

	dsseSigner := dsse.WrapSigner(signer, types.IntotoPayloadType)

	return dsseSigner.SignMessage(bytes.NewReader(payload), options.WithContext(ctx))
}
