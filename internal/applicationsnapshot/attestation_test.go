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

//go:build unit

package applicationsnapshot

import (
	"encoding/json"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/in-toto/in-toto-golang/in_toto"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/stretchr/testify/assert"

	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/signature"
)

func TestAttestationReport(t *testing.T) {
	cases := []struct {
		name       string
		components []Component
	}{
		{
			name:       "no components",
			components: []Component{},
		},
		{
			name: "no attestations",
			components: []Component{
				{},
				{},
			},
		},
		{
			name: "one attestation",
			components: []Component{
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image:tag",
					},
					Attestations: []AttestationResult{
						att("attestation1"),
					},
				},
			},
		},
		{
			name: "two components two attestations",
			components: []Component{
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image1:tag",
					},
					Attestations: []AttestationResult{
						att("attestation1"),
						att("attestation2"),
					},
				},
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image2:tag",
					},
					Attestations: []AttestationResult{
						att("attestation3"),
						att("attestation4"),
					},
				},
			},
		},
		{
			name: "mix of components and attestations",
			components: []Component{
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image1:tag",
					},
					Attestations: []AttestationResult{
						att("attestation1"),
					},
				},
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image2:tag",
					},
				},
				{
					SnapshotComponent: app.SnapshotComponent{
						ContainerImage: "registry.io/repository/image3:tag",
					},
					Attestations: []AttestationResult{
						att("attestation2"),
						att("attestation3"),
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Report{
				Components: c.components,
			}
			b := r.renderAttestations()

			snaps.MatchSnapshot(t, string(b))
		})
	}
}

func TestAttestations(t *testing.T) {
	//nolint:staticcheck
	statement := in_toto.Statement{
		//nolint:staticcheck
		StatementHeader: in_toto.StatementHeader{
			Type:          "my-type",
			PredicateType: "my-predicate-type",
			//nolint:staticcheck
			Subject: []in_toto.Subject{},
		},
	}
	data, err := json.Marshal(statement)
	assert.NoError(t, err)

	components := []Component{
		{
			SnapshotComponent: app.SnapshotComponent{Name: "component1"},
			Violations: []evaluator.Result{
				{
					Message: "violation1",
				},
			},
			Attestations: []AttestationResult{
				{
					Statement: data,
				},
			},
		},
	}

	report := Report{Components: components}
	att, err := report.attestations()
	assert.NoError(t, err)
	//nolint:staticcheck
	assert.Equal(t, []in_toto.Statement{statement}, att)
}

func att(data string) AttestationResult {
	return AttestationResult{
		Statement: []byte(data),
	}
}

//nolint:staticcheck
type provenance struct {
	//nolint:staticcheck
	statement  in_toto.Statement
	data       []byte
	signatures []signature.EntitySignature
}

func (p provenance) Type() string {
	return "generic-provenance-type"
}

func (p provenance) PredicateType() string {
	return "generic-predicate-type"
}

func (p provenance) Signatures() []signature.EntitySignature {
	return p.signatures
}

func (p provenance) Statement() []byte {
	return p.data
}

//nolint:staticcheck
func (p provenance) Subject() []in_toto.Subject {
	return p.statement.Subject
}

type slsaProvenance struct {
	statement  in_toto.ProvenanceStatementSLSA02
	data       []byte
	signatures []signature.EntitySignature
}

func (s slsaProvenance) Type() string {
	return "slsa-type"
}

func (s slsaProvenance) Statement() []byte {
	return s.data
}

//nolint:staticcheck
func (s slsaProvenance) Subject() []in_toto.Subject {
	return s.statement.Subject
}

func (s slsaProvenance) PredicateType() string {
	return "slsa-predicate-type"
}

func (s slsaProvenance) Signatures() []signature.EntitySignature {
	return s.signatures
}

// PredicateBuildType implements SLSAProvenance
func (s slsaProvenance) PredicateBuildType() string {
	return "slsa-build-type"
}

func TestNewAttestationResultWithProvenanceOnly(t *testing.T) {
	//nolint:staticcheck
	p := provenance{
		//nolint:staticcheck
		statement:  in_toto.Statement{},
		data:       []byte("some data"),
		signatures: []signature.EntitySignature{{KeyID: "key1"}},
	}

	result := NewAttestationResult(p) // p implements attestation.Attestation

	assert.Equal(t, "generic-provenance-type", result.Type)
	assert.Equal(t, "generic-predicate-type", result.PredicateType)
	assert.Len(t, result.Signatures, 1)
	assert.Empty(t, result.PredicateBuildType, "expected PredicateBuildType to be empty for non-SLSAProvenance attestation")
}

func TestNewAttestationResultWithSLSAProvenance(t *testing.T) {
	s := slsaProvenance{
		statement:  in_toto.ProvenanceStatementSLSA02{},
		data:       []byte("some slsa data"),
		signatures: []signature.EntitySignature{{KeyID: "key-slsa"}},
	}

	result := NewAttestationResult(s) // s implements SLSAProvenance

	assert.Equal(t, "slsa-type", result.Type)
	assert.Equal(t, "slsa-predicate-type", result.PredicateType)
	assert.Len(t, result.Signatures, 1)
	assert.Equal(t, "slsa-build-type", result.PredicateBuildType, "expected PredicateBuildType to be set for SLSAProvenance attestation")
}
