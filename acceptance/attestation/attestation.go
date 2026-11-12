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

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"

	"github.com/conforma/cli/acceptance/crypto"
)

const (
	PredicateBuilderID   = "https://tekton.dev/chains/v2"
	PredicateBuilderType = "https://tekton.dev/attestations/chains/pipelinerun@v2"
)

// CreateStatementFor creates an empty statement that can be further customized
// to add and subsequently signed by SignStatement.
func CreateStatementFor(imageName string, image v1.Image) (*in_toto.ProvenanceStatementSLSA02, error) {
	digest, err := image.Digest()
	if err != nil {
		return nil, err
	}

	return &in_toto.ProvenanceStatementSLSA02{
		StatementHeader: statementHeader(imageName, digest, v02.PredicateSLSAProvenance),
		Predicate: v02.ProvenancePredicate{
			Builder: common.ProvenanceBuilder{
				ID: PredicateBuilderID,
			},
			BuildType: PredicateBuilderType,
		},
	}, nil
}

// CreateV1StatementFor creates an empty SLSA v1.0 statement that can be further customized
// and subsequently signed by SignStatement.
//
//nolint:staticcheck // Using deprecated ProvenanceStatementSLSA1 for acceptance testing
func CreateV1StatementFor(imageName string, image v1.Image) (*in_toto.ProvenanceStatementSLSA1, error) {
	digest, err := image.Digest()
	if err != nil {
		return nil, err
	}

	//nolint:staticcheck // Using deprecated ProvenanceStatementSLSA1 for acceptance testing
	return &in_toto.ProvenanceStatementSLSA1{
		StatementHeader: statementHeader(imageName, digest, slsa1.PredicateSLSAProvenance),
		Predicate: slsa1.ProvenancePredicate{
			BuildDefinition: slsa1.ProvenanceBuildDefinition{
				BuildType:          PredicateBuilderType,
				ExternalParameters: map[string]any{},
			},
			RunDetails: slsa1.ProvenanceRunDetails{
				Builder: slsa1.Builder{
					ID: PredicateBuilderID,
				},
			},
		},
	}, nil
}

//nolint:staticcheck // Using deprecated in-toto StatementHeader for acceptance testing
func statementHeader(imageName string, digest v1.Hash, predicateType string) in_toto.StatementHeader {
	return in_toto.StatementHeader{
		Type:          in_toto.StatementInTotoV01,
		PredicateType: predicateType,
		Subject: []in_toto.Subject{
			{
				Name: imageName,
				Digest: common.DigestSet{
					"sha256": digest.Hex,
				},
			},
		},
	}
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
