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

package attestation

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/in-toto-golang/in_toto"
	v1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	ct "github.com/sigstore/cosign/v2/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/signature"
)

func TestSLSAProvenanceFromSignatureV1NilSignature(t *testing.T) {
	sp, err := SLSAProvenanceFromSignatureV1(nil)
	assert.True(t, assert.ErrorContains(t, err, "no attestation found"), "Expecting `%v` to be alike: `%v`", err, "no attestation found")
	assert.Nil(t, sp)
}

func TestSLSAProvenanceFromSignatureV1(t *testing.T) {
	cases := []struct {
		name  string
		setup func(l *mockSignature)
		data  string
		err   error
	}{
		{
			name: "media type error",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType(""), errors.New("expected"))
			},
			err: errors.New("malformed attestation data: expected"),
		},
		{
			name: "no media type",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType(""), nil)
			},
			err: errors.New("malformed attestation data: expecting media type of `application/vnd.dsse.envelope.v1+json`, received: ``"),
		},
		{
			name: "unsupported media type",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType("xxx"), nil)
			},
			err: errors.New("malformed attestation data: expecting media type of `application/vnd.dsse.envelope.v1+json`, received: `xxx`"),
		},
		{
			name: "no payload JSON",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(""), nil)
			},
			err: errors.New("malformed attestation data: EOF"),
		},
		{
			name: "empty payload JSON",
			data: "{}",
			setup: func(l *mockSignature) {
				payload := encode("{}")
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(fmt.Sprintf(`{"payload":"%s"}`, payload)), nil)
			},
			err: errors.New("unsupported attestation type: "),
		},
		{
			name: "invalid attestation payload JSON",
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				payload := fmt.Sprintf(`{{"signatures": [%s]}`, sig1)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(payload), nil)
			},
			err: errors.New("malformed attestation data: invalid character '{' looking for beginning of object key string"),
		},
		{
			name: "invalid statement JSON base64",
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(
					fmt.Sprintf(`{"signatures": [%s], "payload": "not-base64"}`, sig1),
				), nil)
			},
			err: errors.New("malformed attestation data: illegal base64 data at input byte 3"),
		},
		{
			name: "invalid statement JSON",
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				payload := encode(`{{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType":"https://slsa.dev/provenance/v1",
					"predicate":{"buildDefinition":{"buildType":"https://my.build.type","externalParameters":{}},"runDetails":{"builder":{"id":"https://my.builder"}}} }
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(
					fmt.Sprintf(`{"signatures": [%s], "payload": "%s"}`, sig1, payload),
				), nil)
			},
			err: errors.New("malformed attestation data: invalid character '{' looking for beginning of object key string"),
		},
		{
			name: "unexpected predicate type",
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType":"kaboom"
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(
					fmt.Sprintf(`{"signatures": [%s], "payload": "%s"}`, sig1, payload),
				), nil)
			},
			err: errors.New("unsupported attestation predicate type: kaboom"),
		},
		{
			name: "schema validation fails - missing subject",
			setup: func(l *mockSignature) {
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v1",
					"predicate": {
						"buildDefinition": {
							"buildType": "https://my.build.type",
							"externalParameters": {}
						},
						"runDetails": {
							"builder": {"id": "https://my.builder"}
						}
					}
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(fmt.Sprintf(`{"payload":"%s"}`, payload)), nil)
				l.On("Base64Signature").Return("", nil)
				l.On("Cert").Return(signature.ParseChainguardReleaseCert(), nil)
				l.On("Chain").Return(signature.ParseSigstoreChainCert(), nil)
			},
			err: errors.New("attestation does not conform to SLSA v1.0 schema: jsonschema: '' does not validate with https://slsa.dev/provenance/v1#/required: missing properties: 'subject'"),
		},
		{
			name: "schema validation fails - missing buildDefinition",
			setup: func(l *mockSignature) {
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"subject": [{"name": "example.com/test", "digest": {"sha256": "abc123"}}],
					"predicateType": "https://slsa.dev/provenance/v1",
					"predicate": {
						"runDetails": {
							"builder": {"id": "https://my.builder"}
						}
					}
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(fmt.Sprintf(`{"payload":"%s"}`, payload)), nil)
				l.On("Base64Signature").Return("", nil)
				l.On("Cert").Return(signature.ParseChainguardReleaseCert(), nil)
				l.On("Chain").Return(signature.ParseSigstoreChainCert(), nil)
			},
			err: errors.New("attestation does not conform to SLSA v1.0 schema: jsonschema: '/predicate' does not validate with https://slsa.dev/provenance/v1#/properties/predicate/required: missing properties: 'buildDefinition'"),
		},
		{
			name: "cannot create entity signature",
			data: `{
				"_type": "https://in-toto.io/Statement/v0.1",
				"subject": [{"name": "example.com/test", "digest": {"sha256": "abc123"}}],
				"predicateType": "https://slsa.dev/provenance/v1",
				"predicate": {
					"buildDefinition": {
						"buildType": "https://my.build.type",
						"externalParameters": {}
					},
					"runDetails": {
						"builder": {"id": "https://my.builder"}
					}
				}
			}`,
			setup: func(l *mockSignature) {
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"subject": [{"name": "example.com/test", "digest": {"sha256": "abc123"}}],
					"predicateType": "https://slsa.dev/provenance/v1",
					"predicate": {
						"buildDefinition": {
							"buildType": "https://my.build.type",
							"externalParameters": {}
						},
						"runDetails": {
							"builder": {"id": "https://my.builder"}
						}
					}
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(fmt.Sprintf(`{"payload":"%s"}`, payload)), nil)
				l.On("Base64Signature").Return("", errors.New("kaboom"))
			},
			err: fmt.Errorf("cannot create signed entity: %s", "kaboom"),
		},
		{
			name: "valid with signature from payload",
			data: `{
				"_type": "https://in-toto.io/Statement/v0.1",
				"subject": [{"name": "example.com/test", "digest": {"sha256": "abc123"}}],
				"predicateType": "https://slsa.dev/provenance/v1",
				"predicate": {
					"buildDefinition": {
						"buildType": "https://my.build.type",
						"externalParameters": {}
					},
					"runDetails": {
						"builder": {"id": "https://my.builder"}
					}
				}
			}`,
			setup: func(l *mockSignature) {
				sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`
				sig2 := `{"keyid": "key-id-2", "sig": "sig-2"}`
				payload := encode(`{
					"_type": "https://in-toto.io/Statement/v0.1",
					"subject": [{"name": "example.com/test", "digest": {"sha256": "abc123"}}],
					"predicateType": "https://slsa.dev/provenance/v1",
					"predicate": {
						"buildDefinition": {
							"buildType": "https://my.build.type",
							"externalParameters": {}
						},
						"runDetails": {
							"builder": {"id": "https://my.builder"}
						}
					}
				}`)
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(
					fmt.Sprintf(`{"payload": "%s", "signatures": [%s, %s]}`, payload, sig1, sig2),
				), nil)
				l.On("Base64Signature").Return("", nil)
				l.On("Cert").Return(signature.ParseChainguardReleaseCert(), nil)
				l.On("Chain").Return(signature.ParseSigstoreChainCert(), nil)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sig := mockSignature{&mock.Mock{}}

			if c.setup != nil {
				c.setup(&sig)
			}

			sp, err := SLSAProvenanceFromSignatureV1(sig)
			if c.err == nil {
				require.Nil(t, err)
				require.NotNil(t, sp)
			} else {
				require.Nil(t, sp)
				assert.True(t, c.err.Error() == err.Error(), "Expecting `%v` to be alike: `%v`", err, c.err)
				return
			}

			if c.data == "" {
				assert.Nil(t, sp.Statement())
			} else {
				assert.JSONEq(t, c.data, string(sp.Statement()))
			}
			snaps.MatchSnapshot(t, sp.Type(), sp.Signatures())
		})
	}
}

func TestSLSAProvenanceV1_Subject(t *testing.T) {
	mockSubject1 := in_toto.Subject{
		Name: "registry.io/example/image@sha256:abc123",
		Digest: map[string]string{
			"sha256": "abc123def456",
		},
	}
	mockSubject2 := in_toto.Subject{
		Name: "registry.io/example/artifact@sha256:def456",
		Digest: map[string]string{
			"sha256": "def456abc123",
			"sha512": "fea789bcd012",
		},
	}

	tests := []struct {
		name      string
		statement in_toto.ProvenanceStatementSLSA1
		expected  []in_toto.Subject
		wantPanic bool
	}{
		{
			name: "returns single subject successfully",
			statement: in_toto.ProvenanceStatementSLSA1{
				StatementHeader: in_toto.StatementHeader{
					Subject: []in_toto.Subject{mockSubject1},
				},
			},
			expected: []in_toto.Subject{mockSubject1},
		},
		{
			name: "returns multiple subjects successfully",
			statement: in_toto.ProvenanceStatementSLSA1{
				StatementHeader: in_toto.StatementHeader{
					Subject: []in_toto.Subject{mockSubject1, mockSubject2},
				},
			},
			expected: []in_toto.Subject{mockSubject1, mockSubject2},
		},
		{
			name: "returns empty slice when no subjects",
			statement: in_toto.ProvenanceStatementSLSA1{
				StatementHeader: in_toto.StatementHeader{
					Subject: []in_toto.Subject{},
				},
			},
			expected: []in_toto.Subject{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("expected panic but none occurred")
					}
				}()
			}

			slsa := slsaProvenanceV1{statement: tt.statement}
			result := slsa.Subject()

			if !tt.wantPanic {
				assert.Equal(t, tt.expected, result)
				// Verify that the returned slice is independent of the original
				if len(result) > 0 && len(tt.expected) > 0 {
					assert.Equal(t, tt.expected[0].Name, result[0].Name)
					assert.Equal(t, tt.expected[0].Digest, result[0].Digest)
				}
			}
		})
	}
}

func TestSLSAProvenanceV1_Type(t *testing.T) {
	slsa := slsaProvenanceV1{
		statement: in_toto.ProvenanceStatementSLSA1{
			StatementHeader: in_toto.StatementHeader{
				Type:          in_toto.StatementInTotoV01,
				PredicateType: PredicateSLSAProvenanceV1,
			},
		},
	}

	result := slsa.Type()
	assert.Equal(t, in_toto.StatementInTotoV01, result)
}

func TestSLSAProvenanceV1_PredicateType(t *testing.T) {
	slsa := slsaProvenanceV1{
		statement: in_toto.ProvenanceStatementSLSA1{
			StatementHeader: in_toto.StatementHeader{
				Type:          in_toto.StatementInTotoV01,
				PredicateType: PredicateSLSAProvenanceV1,
			},
		},
	}

	result := slsa.PredicateType()
	assert.Equal(t, v1.PredicateSLSAProvenance, result)
}

func TestSLSAProvenanceV1_PredicateBuildType(t *testing.T) {
	tests := []struct {
		name      string
		buildType string
	}{
		{
			name:      "returns buildType from buildDefinition",
			buildType: "https://tekton.dev/chains/v2/slsa-tekton",
		},
		{
			name:      "returns empty buildType",
			buildType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slsa := slsaProvenanceV1{
				statement: in_toto.ProvenanceStatementSLSA1{
					StatementHeader: in_toto.StatementHeader{
						Type:          in_toto.StatementInTotoV01,
						PredicateType: PredicateSLSAProvenanceV1,
					},
					Predicate: v1.ProvenancePredicate{
						BuildDefinition: v1.ProvenanceBuildDefinition{
							BuildType:          tt.buildType,
							ExternalParameters: map[string]interface{}{},
						},
						RunDetails: v1.ProvenanceRunDetails{
							Builder: v1.Builder{
								ID: "https://my.builder",
							},
						},
					},
				},
			}

			result := slsa.PredicateBuildType()
			assert.Equal(t, tt.buildType, result)
		})
	}
}

func TestSLSAProvenanceV1_Statement(t *testing.T) {
	expectedData := []byte(`{"test":"data"}`)
	slsa := slsaProvenanceV1{
		data: expectedData,
	}

	result := slsa.Statement()
	assert.Equal(t, expectedData, result)
}

func TestSLSAProvenanceV1_Signatures(t *testing.T) {
	expectedSigs := []signature.EntitySignature{
		{
			Signature: "sig1",
			KeyID:     "key1",
		},
		{
			Signature: "sig2",
			KeyID:     "key2",
		},
	}

	slsa := slsaProvenanceV1{
		signatures: expectedSigs,
	}

	result := slsa.Signatures()
	assert.Equal(t, expectedSigs, result)
}
