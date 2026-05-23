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
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ct "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/conforma/cli/internal/signature"
)

// The mockSignature struct plus all its methods are defined in
// internal/attestation/slsa_provenance_02_test.go

func TestProvenanceFromSignature(t *testing.T) {
	sig1 := `{"keyid": "key-id-1", "sig": "sig-1"}`

	payloadJson1 := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://cool-type.example.io/Amazing/v2.0",
		"predicate": {
			"secure": "very",
			"hacks": "none"
		}
	}`

	fullAtt1 := fmt.Sprintf(`{"signatures": [%s], "payload": "%s"}`, sig1, encode(payloadJson1))

	// It appears that cosign creates attestations like this in some cases.
	// At one point I was intending to marshal them into a json object, but
	// currently the will remain as strings. I'll leave this here to demonstrate
	// the current behavior and since it will be handy if we do decide to unmarshal.
	payloadJson2 := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://cool-type.example.io/Amazing/v2.0",
		"predicate": "{\"secure\": \"very\", \"hacks\": \"none\"}"
	}`

	fullAtt2 := fmt.Sprintf(`{"signatures": [%s], "payload": "%s"}`, sig1, encode(payloadJson2))

	cases := []struct {
		name  string
		setup func(l *mockSignature)
		data  string
	}{
		// Note: A lot of the testing already done for SLSAProvenanceFromSignature
		// in particular the error handling is covering code that is now in the
		// payloadFromSig function, which is also used by ProvenanceFromSignature.
		// So I don't think we should duplicate that error handling test coverage here.
		// Additionally I don't want to refactor the existing SLSAProvenanceFromSignature
		// testing, e.g. to split it up and move it around. So that's why the tests here
		// are covering only some "happy path" scenarios and not the error handling.

		{
			name: "unknown predicate type with signature from payload",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(fullAtt1), nil)
				l.On("Base64Signature").Return("", nil)
				l.On("Cert").Return(&x509.Certificate{}, nil)
				l.On("Chain").Return([]*x509.Certificate{}, nil)
			},
			data: payloadJson1,
		},
		{
			name: "unknown predicate type with signature from certificate",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(fullAtt1), nil)
				l.On("Base64Signature").Return("sig-from-cert", nil)
				l.On("Cert").Return(signature.ParseChainguardReleaseCert(), nil)
				l.On("Chain").Return(signature.ParseSigstoreChainCert(), nil)
			},
			data: payloadJson1,
		},
		{
			name: "unknown predicate type with string predicate and signature from certificate",
			setup: func(l *mockSignature) {
				l.On("MediaType").Return(types.MediaType(ct.DssePayloadType), nil)
				l.On("Uncompressed").Return(buffy(fullAtt2), nil)
				l.On("Base64Signature").Return("sig-from-cert", nil)
				l.On("Cert").Return(signature.ParseChainguardReleaseCert(), nil)
				l.On("Chain").Return(signature.ParseSigstoreChainCert(), nil)
			},
			data: payloadJson2, // String payload remains as a string
			// data: payloadJson1, // String payload is marshaled
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sig := mockSignature{&mock.Mock{}}
			c.setup(&sig)

			p, err := ProvenanceFromSignature(sig)
			assert.NoError(t, err)
			assert.JSONEq(t, c.data, string(p.Statement()))

			assert.Equal(t, "https://cool-type.example.io/Amazing/v2.0", p.PredicateType())

			snaps.MatchJSON(t, string(p.Statement()))
		})
	}
}
