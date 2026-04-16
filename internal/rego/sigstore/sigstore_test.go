// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package sigstore

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	cosignTypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/utils"
	o "github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/internal/utils/oci/fake"
)

func TestSigstoreVerifyImage(t *testing.T) {
	goodImage := name.MustParseReference(
		"registry.local/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
	)

	cases := []struct {
		name         string
		success      *ast.Term
		errors       *ast.Term
		uri          *ast.Term
		opts         options
		optsVerifier func(mock.Arguments)
		sigError     error
	}{
		{
			name:    "long lived key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{ignoreRekor: true, publicKey: utils.TestPublicKey},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.True(t, checkOpts.IgnoreTlog)
				require.Nil(t, checkOpts.RekorClient)
				require.Empty(t, checkOpts.Identities)
			},
		},
		{
			name:    "long lived key with rekor",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{publicKey: utils.TestPublicKey, rekorURL: "https://rekor.local"},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.Empty(t, checkOpts.Identities)
				require.NotNil(t, checkOpts.RekorClient)
			},
		},
		{
			name:    "fulcio key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts: options{
				certificateIdentity:   "subject",
				certificateOIDCIssuer: "issuer",
				rekorURL:              "https://rekor.local",
			},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.NotNil(t, checkOpts.RekorClient)
				identities := []cosign.Identity{{Issuer: "issuer", Subject: "subject"}}
				require.Equal(t, checkOpts.Identities, identities)
			},
		},
		{
			name:    "long lived key with rekor public key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{publicKey: utils.TestPublicKey, rekorPublicKey: utils.TestRekorPublicKey},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.Empty(t, checkOpts.Identities)
				require.Nil(t, checkOpts.RekorClient)
				require.NotEmpty(t, checkOpts.RekorPubKeys.Keys[utils.TestRekorURLLogID])
			},
		},
		{
			name:    "fulcio key regex",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts: options{
				certificateIdentityRegExp:   `subject.*`,
				certificateOIDCIssuerRegExp: `issuer.*`,
				rekorURL:                    "https://rekor.local",
			},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.NotNil(t, checkOpts.RekorClient)
				identities := []cosign.Identity{{IssuerRegExp: `issuer.*`, SubjectRegExp: `subject.*`}}
				require.Equal(t, checkOpts.Identities, identities)
			},
		},
		{
			name:    "bad public key",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("opts parameter: new policy: loading URL: unrecognized scheme: spam://"),
			),
			uri:  ast.StringTerm(goodImage.String()),
			opts: options{publicKey: "spam://this-key-does-not-exist"},
		},
		{
			name:    "insufficient options",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("opts parameter: new policy: certificate OIDC issuer must be provided for keyless workflow\ncertificate identity must be provided for keyless workflow"),
			),
			uri: ast.StringTerm(goodImage.String()),
		},
		{
			name:    "image ref without digest",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("new digest: a digest must contain exactly one '@' separator (e.g. registry/repository@digest) saw: registry.local/spam:latest"),
			),
			uri: ast.StringTerm("registry.local/spam:latest"),
		},
		{
			name:    "verification failure",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("verify image signature: kaboom!"),
			),
			uri:      ast.StringTerm(goodImage.String()),
			opts:     options{ignoreRekor: true, publicKey: utils.TestPublicKey},
			sigError: errors.New("kaboom!"),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ClearCaches()
			utils.SetTestRekorPublicKey(t)
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			c := fake.FakeClient{}
			ctx := o.WithClient(context.Background(), &c)

			sig, err := static.NewSignature(
				[]byte(`image`),
				"signature",
				static.WithLayerMediaType(types.MediaType((cosignTypes.DssePayloadType))),
			)
			require.NoError(t, err)

			verifyCall := c.On(
				"VerifyImageSignatures", goodImage, mock.Anything,
			).Return([]oci.Signature{sig}, false, tt.sigError)

			if tt.optsVerifier != nil {
				verifyCall.Run(tt.optsVerifier)
			}

			bctx := rego.BuiltinContext{Context: ctx}

			result, err := sigstoreVerifyImage(bctx, tt.uri, tt.opts.toTerm())
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, tt.errors, result.Get(ast.StringTerm("errors")))
			require.Equal(t, tt.success, result.Get(ast.StringTerm("success")))
		})
	}
}

func TestVerifyImageCache(t *testing.T) {
	image1 := name.MustParseReference(
		"registry.local/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
	)
	image2 := name.MustParseReference(
		"registry.local/eggs@sha256:5e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
	)
	opts1 := options{ignoreRekor: true, publicKey: utils.TestPublicKey}
	opts2 := options{publicKey: utils.TestPublicKey, rekorURL: "https://rekor.local"}

	newFakeContext := func(t *testing.T) (*fake.FakeClient, rego.BuiltinContext) {
		t.Helper()
		utils.SetTestRekorPublicKey(t)
		utils.SetTestFulcioRoots(t)
		utils.SetTestCTLogPublicKey(t)

		sig, err := static.NewSignature(
			[]byte(`image`),
			"signature",
			static.WithLayerMediaType(types.MediaType(cosignTypes.DssePayloadType)),
		)
		require.NoError(t, err)

		c := &fake.FakeClient{}
		c.On("VerifyImageSignatures", mock.Anything, mock.Anything).Return([]oci.Signature{sig}, false, nil)
		ctx := o.WithClient(context.Background(), c)
		return c, rego.BuiltinContext{Context: ctx}
	}

	t.Run("same ref and opts returns cached result", func(t *testing.T) {
		ClearCaches()
		c, bctx := newFakeContext(t)

		r1, err := sigstoreVerifyImage(bctx, ast.StringTerm(image1.String()), opts1.toTerm())
		require.NoError(t, err)

		r2, err := sigstoreVerifyImage(bctx, ast.StringTerm(image1.String()), opts1.toTerm())
		require.NoError(t, err)

		require.Equal(t, r1, r2)
		c.AssertNumberOfCalls(t, "VerifyImageSignatures", 1)
	})

	t.Run("different ref is a cache miss", func(t *testing.T) {
		ClearCaches()
		c, bctx := newFakeContext(t)

		_, err := sigstoreVerifyImage(bctx, ast.StringTerm(image1.String()), opts1.toTerm())
		require.NoError(t, err)

		_, err = sigstoreVerifyImage(bctx, ast.StringTerm(image2.String()), opts1.toTerm())
		require.NoError(t, err)

		c.AssertNumberOfCalls(t, "VerifyImageSignatures", 2)
	})

	t.Run("different opts is a cache miss", func(t *testing.T) {
		ClearCaches()
		c, bctx := newFakeContext(t)

		_, err := sigstoreVerifyImage(bctx, ast.StringTerm(image1.String()), opts1.toTerm())
		require.NoError(t, err)

		_, err = sigstoreVerifyImage(bctx, ast.StringTerm(image1.String()), opts2.toTerm())
		require.NoError(t, err)

		c.AssertNumberOfCalls(t, "VerifyImageSignatures", 2)
	})

	t.Run("ClearCaches forces re-verification", func(t *testing.T) {
		ClearCaches()
		c, bctx := newFakeContext(t)

		_, err := sigstoreVerifyImage(bctx, ast.StringTerm(image1.String()), opts1.toTerm())
		require.NoError(t, err)
		c.AssertNumberOfCalls(t, "VerifyImageSignatures", 1)

		ClearCaches()

		_, err = sigstoreVerifyImage(bctx, ast.StringTerm(image1.String()), opts1.toTerm())
		require.NoError(t, err)
		c.AssertNumberOfCalls(t, "VerifyImageSignatures", 2)
	})
}

func TestSigstoreVerifyAttestation(t *testing.T) {
	goodImage := name.MustParseReference(
		"registry.local/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
	)

	goodSig, err := static.NewSignature(
		[]byte(fmt.Sprintf(`{"payload": "%s"}`, base64.StdEncoding.EncodeToString([]byte("{}")))),
		"signature",
		static.WithLayerMediaType(types.MediaType((cosignTypes.DssePayloadType))),
	)
	require.NoError(t, err)

	badSig, err := static.NewSignature(
		[]byte(`{"payload": "bad-base64"}`),
		"signature",
		static.WithLayerMediaType(types.MediaType((cosignTypes.DssePayloadType))),
	)
	require.NoError(t, err)

	cases := []struct {
		name         string
		success      *ast.Term
		errors       *ast.Term
		uri          *ast.Term
		opts         options
		optsVerifier func(mock.Arguments)
		sigError     error
		sigs         []oci.Signature
	}{
		{
			name:    "long lived key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{ignoreRekor: true, publicKey: utils.TestPublicKey},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.True(t, checkOpts.IgnoreTlog)
				require.Nil(t, checkOpts.RekorClient)
				require.Empty(t, checkOpts.Identities)
			},
			sigs: []oci.Signature{goodSig},
		},
		{
			name:    "long lived key with rekor",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{publicKey: utils.TestPublicKey, rekorURL: "https://rekor.local"},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.Empty(t, checkOpts.Identities)
				require.NotNil(t, checkOpts.RekorClient)
			},
			sigs: []oci.Signature{goodSig},
		},
		{
			name:    "long lived key with rekor public key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts:    options{publicKey: utils.TestPublicKey, rekorPublicKey: utils.TestRekorPublicKey},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.Empty(t, checkOpts.Identities)
				require.Nil(t, checkOpts.RekorClient)
				require.NotEmpty(t, checkOpts.RekorPubKeys.Keys[utils.TestRekorURLLogID])
			},
		},
		{
			name:    "fulcio key",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts: options{
				certificateIdentity:   "subject",
				certificateOIDCIssuer: "issuer",
				rekorURL:              "https://rekor.local",
			},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.NotNil(t, checkOpts.RekorClient)
				identities := []cosign.Identity{{Issuer: "issuer", Subject: "subject"}}
				require.Equal(t, checkOpts.Identities, identities)
			},
			sigs: []oci.Signature{goodSig},
		},
		{
			name:    "fulcio key regex",
			success: ast.BooleanTerm(true),
			errors:  ast.ArrayTerm(),
			uri:     ast.StringTerm(goodImage.String()),
			opts: options{
				certificateIdentityRegExp:   `subject.*`,
				certificateOIDCIssuerRegExp: `issuer.*`,
				rekorURL:                    "https://rekor.local",
			},
			optsVerifier: func(args mock.Arguments) {
				checkOpts := args.Get(1).(*cosign.CheckOpts)
				require.NotNil(t, checkOpts)
				require.False(t, checkOpts.IgnoreTlog)
				require.NotNil(t, checkOpts.RekorClient)
				identities := []cosign.Identity{{IssuerRegExp: `issuer.*`, SubjectRegExp: `subject.*`}}
				require.Equal(t, checkOpts.Identities, identities)
			},
			sigs: []oci.Signature{goodSig},
		},
		{
			name:    "bad public key",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("opts parameter: new policy: loading URL: unrecognized scheme: spam://"),
			),
			uri:  ast.StringTerm(goodImage.String()),
			opts: options{publicKey: "spam://this-key-does-not-exist"},
		},
		{
			name:    "insufficient options",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("opts parameter: new policy: certificate OIDC issuer must be provided for keyless workflow\ncertificate identity must be provided for keyless workflow"),
			),
			uri: ast.StringTerm(goodImage.String()),
		},
		{
			name:    "image ref without digest",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("new digest: a digest must contain exactly one '@' separator (e.g. registry/repository@digest) saw: registry.local/spam:latest"),
			),
			uri: ast.StringTerm("registry.local/spam:latest"),
		},
		{
			name:    "verification failure",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("verify image attestation signature: kaboom!"),
			),
			uri:      ast.StringTerm(goodImage.String()),
			opts:     options{ignoreRekor: true, publicKey: utils.TestPublicKey},
			sigError: errors.New("kaboom!"),
		},
		{
			name:    "bad attestation",
			success: ast.BooleanTerm(false),
			errors: ast.ArrayTerm(
				ast.StringTerm("parsing attestation: malformed attestation data: illegal base64 data at input byte 3"),
			),
			uri:  ast.StringTerm(goodImage.String()),
			opts: options{ignoreRekor: true, publicKey: utils.TestPublicKey},
			sigs: []oci.Signature{badSig},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			utils.SetTestRekorPublicKey(t)
			utils.SetTestFulcioRoots(t)
			utils.SetTestCTLogPublicKey(t)

			c := fake.FakeClient{}
			ctx := o.WithClient(context.Background(), &c)

			verifyCall := c.On(
				"VerifyImageAttestations", goodImage, mock.Anything,
			).Return(tt.sigs, false, tt.sigError)

			if tt.optsVerifier != nil {
				verifyCall.Run(tt.optsVerifier)
			}

			bctx := rego.BuiltinContext{Context: ctx}

			result, err := sigstoreVerifyAttestation(bctx, tt.uri, tt.opts.toTerm())
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, tt.errors, result.Get(ast.StringTerm("errors")))
			require.Equal(t, tt.success, result.Get(ast.StringTerm("success")))
		})
	}
}
