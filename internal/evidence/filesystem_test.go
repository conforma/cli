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

package evidence

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/stretchr/testify/require"
)

const predicateType = "https://example.invalid/chi/v1"

func signer(t *testing.T) signature.SignerVerifier {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sv, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	require.NoError(t, err)
	return sv
}

func signedBundle(t *testing.T, sv signature.SignerVerifier, predicate, digest string) json.RawMessage {
	t.Helper()
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"image","digest":{"sha256":"` + digest + `"}}],"predicateType":"` + predicate + `","predicate":{"scanComplete":true,"findings":[]}}`)
	return bundleWithPayload(t, sv, statement)
}

func bundleWithPayload(t *testing.T, sv signature.SignerVerifier, statement []byte) json.RawMessage {
	t.Helper()
	env, err := dsse.WrapSigner(sv, "application/vnd.in-toto+json").SignMessage(bytes.NewReader(statement))
	require.NoError(t, err)
	b, err := json.Marshal(map[string]any{
		"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{"publicKey": map[string]string{"hint": "not-a-trust-root"}},
		"dsseEnvelope":         json.RawMessage(env),
	})
	require.NoError(t, err)
	return b
}

func evidenceFile(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "evidence.json")
	require.NoError(t, os.WriteFile(p, data, 0600))
	return p
}

func trustFor(sv signature.SignerVerifier) KeyTrust {
	return KeyTrust{predicateType: {{SigVerifier: sv, IgnoreTlog: true}}}
}

func TestFilesystemBatchMatching(t *testing.T) {
	sv := signer(t)
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	batch, err := json.Marshal([]json.RawMessage{signedBundle(t, sv, predicateType, c), signedBundle(t, sv, predicateType, a)})
	require.NoError(t, err)
	path := evidenceFile(t, batch)
	source, err := NewFilesystem(context.Background(), path, trustFor(sv))
	require.NoError(t, err)
	// Changing the file after construction cannot alter admitted evidence.
	require.NoError(t, os.WriteFile(path, []byte("tampered"), 0600))
	for _, digest := range []string{a, b, c} {
		t.Run(digest[:1], func(t *testing.T) {
			t.Parallel()
			ref, err := name.NewDigest("example.com/another-repository@sha256:" + digest)
			require.NoError(t, err)
			atts, err := source.Collect(context.Background(), ref)
			require.NoError(t, err)
			if digest == b {
				require.Empty(t, atts)
				return
			}
			require.Len(t, atts, 1)
			require.Equal(t, digest, atts[0].Subject()[0].Digest["sha256"])
			require.NotEmpty(t, atts[0].Signatures()[0].Signature)
		})
	}
}

func TestFilesystemAdmission(t *testing.T) {
	sv, other := signer(t), signer(t)
	good := signedBundle(t, sv, predicateType, strings.Repeat("a", 64))
	var tampered map[string]any
	require.NoError(t, json.Unmarshal(good, &tampered))
	env := tampered["dsseEnvelope"].(map[string]any)
	payload, err := base64.StdEncoding.DecodeString(env["payload"].(string))
	require.NoError(t, err)
	env["payload"] = base64.StdEncoding.EncodeToString(bytes.Replace(payload, []byte(`"scanComplete":true`), []byte(`"scanComplete":false`), 1))
	bad, err := json.Marshal(tampered)
	require.NoError(t, err)
	mixed, err := json.Marshal([]json.RawMessage{good, bad})
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		data  []byte
		trust KeyTrust
		want  string
	}{
		{"valid", good, trustFor(sv), ""},
		{"wrong key", good, trustFor(other), "failed verification"},
		{"no authority", good, KeyTrust{}, "no authorized key"},
		{"tampering", bad, trustFor(sv), "failed verification"},
		{"good cannot mask bad", mixed, trustFor(sv), "record 2"},
		{"raw predicate", []byte(`{"scanComplete":true}`), trustFor(sv), "expected a Sigstore"},
		{"unsigned statement", payload, trustFor(sv), "expected a Sigstore"},
		{"duplicate key", []byte(`{"mediaType":"a","mediaType":"b"}`), trustFor(sv), "duplicate"},
		{"trailing document", append(append([]byte{}, good...), good...), trustFor(sv), "trailing"},
		{"wrong predicate", signedBundle(t, sv, "https://slsa.dev/provenance/v1", strings.Repeat("a", 64)), trustFor(sv), "no authorized key"},
		{"empty source", []byte(`[]`), trustFor(sv), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := NewFilesystem(context.Background(), evidenceFile(t, tc.data), tc.trust)
			if tc.want == "" {
				require.NoError(t, err)
				require.NotNil(t, source)
			} else {
				require.ErrorContains(t, err, tc.want)
				require.Nil(t, source)
			}
		})
	}
	rotation := KeyTrust{predicateType: {{SigVerifier: other, IgnoreTlog: true}, {SigVerifier: sv, IgnoreTlog: true}}}
	_, err = NewFilesystem(context.Background(), evidenceFile(t, good), rotation)
	require.NoError(t, err)
	// Log verification is required unless the caller explicitly opts out.
	_, err = NewFilesystem(context.Background(), evidenceFile(t, good), KeyTrust{predicateType: {{SigVerifier: sv}}})
	require.Error(t, err)
}

func TestPredicateKeyIsolation(t *testing.T) {
	ctx := context.Background()
	chi, other := signer(t), signer(t)
	keyFile := func(sv signature.SignerVerifier) string {
		pub, err := sv.PublicKey()
		require.NoError(t, err)
		pem, err := cryptoutils.MarshalPublicKeyToPEM(pub)
		require.NoError(t, err)
		return evidenceFile(t, pem)
	}
	chiPath, otherPath := keyFile(chi), keyFile(other)
	otherType := "https://example.invalid/other/v1"
	trust, err := LoadKeyTrust(ctx, []string{predicateType + "=" + chiPath, otherType + "=" + otherPath}, cosign.CheckOpts{IgnoreTlog: true})
	require.NoError(t, err)
	digest := strings.Repeat("a", 64)
	batch, err := json.Marshal([]json.RawMessage{signedBundle(t, chi, predicateType, digest), signedBundle(t, other, otherType, digest)})
	require.NoError(t, err)
	_, err = NewFilesystem(ctx, evidenceFile(t, batch), trust)
	require.NoError(t, err)
	_, err = NewFilesystem(ctx, evidenceFile(t, signedBundle(t, chi, otherType, digest)), trust)
	require.ErrorContains(t, err, "failed verification")
	for _, bindings := range [][]string{nil, {"missing-equals"}, {"relative=" + chiPath}, {predicateType + "="}, {imageSignaturePredicate + "=" + chiPath}} {
		_, err = LoadKeyTrust(ctx, bindings, cosign.CheckOpts{})
		require.Error(t, err)
	}
	// A signed alternate-casing field must not make Go and Rego disagree.
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + digest + `"}}],"predicateType":"` + otherType + `","PredicateType":"` + predicateType + `","predicate":{}}`)
	_, err = NewFilesystem(ctx, evidenceFile(t, bundleWithPayload(t, chi, payload)), trust)
	require.ErrorContains(t, err, "noncanonical statement field")
}
