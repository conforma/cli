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

// IMPORTANT: The rego functions in this file never return an error. Instead, they return no value
// when an error is encountered. If they did return an error, opa would exit abruptly and it would
// not produce a report of which policy rules succeeded/failed.

package sigstore

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/sigstore/pkg/tuf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/conforma/cli/internal/attestation"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/signature"
	ecoci "github.com/conforma/cli/internal/utils/oci"
)

const (
	sigstoreVerifyImageName       = "ec.sigstore.verify_image"
	sigstoreVerifyAttestationName = "ec.sigstore.verify_attestation"
)

const (
	certificateIdentityAttribute         = "certificate_identity"
	certificateIdentityRegExpAttribute   = "certificate_identity_regexp"
	certificateOIDCIssuerAttribute       = "certificate_oidc_issuer"
	certificateOIDCIssuerRegExpAttribute = "certificate_oidc_issuer_regexp"
	ignoreRekorAttribute                 = "ignore_rekor"
	publicKeyAttribute                   = "public_key"
	rekorURLAttribute                    = "rekor_url"
	rekorPublicKeyAttribute              = "rekor_public_key"
)

var (
	verifyImageCache  sync.Map
	verifyImageFlight singleflight.Group
)

var ociImageReferenceParameter = types.Named("ref", types.S).Description("OCI image reference")

var sigstoreOptsParameter = types.Named("opts",
	// The definition below helps the compiler determine if the rego code is valid without having to
	// execute it. This is very helpful for policy authors as it integrates nicely with IDEs, but
	// getting this right is tricky. StaticProperties are always required, while DynamicProperties
	// are restricted to a single type. The approach below is a compromise. Not all parameters are
	// required, unless it's not a string which is currently just the `ignore_rekor` parameter. This
	// makes adding new parameters not a breaking change, unless, of course, it's not of type
	// string.
	types.NewObject(
		[]*types.StaticProperty{
			{Key: ignoreRekorAttribute, Value: types.B},
		},
		types.NewDynamicProperty(types.S, types.S),
	)).Description(
	fmt.Sprintf("Sigstore verification options. Dynamic string properties: `%s`.",
		strings.Join([]string{
			certificateIdentityAttribute,
			certificateIdentityRegExpAttribute,
			certificateOIDCIssuerAttribute,
			certificateOIDCIssuerRegExpAttribute,
			publicKeyAttribute,
			rekorURLAttribute,
			rekorPublicKeyAttribute,
		}, "`, `"),
	))

func registerSigstoreVerifyImage() {
	result := types.Named(
		"result",
		types.NewObject([]*types.StaticProperty{
			{Key: "success", Value: types.Named("success", types.B).Description("true when verification is successful")},
			{Key: "errors", Value: types.Named("errors", types.NewArray([]types.Type{types.S}, nil)).Description("verification errors")},
			{Key: "signatures", Value: types.Named("signatures", types.NewArray([]types.Type{signatureType}, nil)).Description("matching signatures")},
		}, nil),
	).Description("the result of the verification request")

	decl := rego.Function{
		Name:        sigstoreVerifyImageName,
		Description: "Use sigstore to verify the signature of an image.",
		Decl: types.NewFunction(
			types.Args(ociImageReferenceParameter, sigstoreOptsParameter),
			result,
		),
		Memoize:          true,
		Nondeterministic: true,
	}
	rego.RegisterBuiltin2(&decl, sigstoreVerifyImage)
}

func sigstoreVerifyImage(bctx rego.BuiltinContext, refTerm *ast.Term, optsTerm *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", sigstoreVerifyImageName)

	uri, err := builtins.StringOperand(refTerm.Value, 0)
	if err != nil {
		logger.WithField("error", err).Debug("failed to get ref parameter")
		return signatureFailedResult(fmt.Errorf("ref parameter: %w", err))
	}
	logger = logger.WithField("ref", string(uri))

	// Build cache key from ref + opts hash
	cacheKey := buildCacheKey(string(uri), optsTerm)

	// Check cache first
	if cached, ok := verifyImageCache.Load(cacheKey); ok {
		logger.Debug("using cached image signature verification result")
		return cached.(*ast.Term), nil
	}

	// Use singleflight to deduplicate concurrent requests. doVerifyImage never returns a Go
	// error — failures are embedded in the result term — so the error is intentionally discarded.
	resultIface, _, _ := verifyImageFlight.Do(cacheKey, func() (interface{}, error) {
		return doVerifyImage(bctx, logger, uri, optsTerm)
	})

	result := resultIface.(*ast.Term)
	verifyImageCache.Store(cacheKey, result)
	return result, nil
}

func doVerifyImage(bctx rego.BuiltinContext, logger *log.Entry, uri ast.String, optsTerm *ast.Term) (*ast.Term, error) {
	ctx := bctx.Context

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		logger.WithField("error", err).Debug("failed to create new digest")
		return signatureFailedResult(fmt.Errorf("new digest: %w", err))
	}

	checkOpts, err := parseCheckOpts(ctx, optsTerm)
	if err != nil {
		logger.WithField("error", err).Debug("failed to parse check opts")
		return signatureFailedResult(fmt.Errorf("opts parameter: %w", err))
	}
	checkOpts.ClaimVerifier = cosign.SimpleClaimVerifier

	logger.Debug("verifying image signatures")
	signatures, _, err := ecoci.NewClient(ctx).VerifyImageSignatures(ref, checkOpts)
	if err != nil {
		logger.WithField("error", err).Debug("failed to verify image signature")
		return signatureFailedResult(fmt.Errorf("verify image signature: %w", err))
	}

	logger.WithField("signatures_count", len(signatures)).Debug("image signature verification complete")
	return signatureResult(signatures, nil)
}

func buildCacheKey(ref string, optsTerm *ast.Term) string {
	h := sha512.Sum512([]byte(optsTerm.String()))
	optsHash := hex.EncodeToString(h[:])
	return ref + "|" + optsHash
}

func registerSigstoreVerifyAttestation() {
	attestationType := types.Named("attestation", types.NewObject([]*types.StaticProperty{
		{Key: "statement", Value: types.Named("statement", types.A).Description("statement from attestation")},
		{Key: "signatures", Value: types.Named(
			"signatures",
			types.NewArray([]types.Type{signatureType}, nil),
		).Description("signatures associated with attestation")},
	}, nil)).Description("attestation matching provided identity/key")

	result := types.Named(
		"result",
		types.NewObject([]*types.StaticProperty{
			{Key: "success", Value: types.Named("success", types.B).Description("true when verification is successful")},
			{Key: "errors", Value: types.Named("errors", types.NewArray([]types.Type{types.S}, nil)).Description("verification errors")},
			{Key: "attestations", Value: types.Named("attestations", types.NewArray([]types.Type{attestationType}, nil)).Description("matching attestations")},
		}, nil),
	).Description("the result of the verification request")

	decl := rego.Function{
		Name:        sigstoreVerifyAttestationName,
		Description: "Use sigstore to verify the attestation of an image.",
		Decl: types.NewFunction(
			types.Args(ociImageReferenceParameter, sigstoreOptsParameter),
			result,
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}
	rego.RegisterBuiltin2(&decl, sigstoreVerifyAttestation)
}

func sigstoreVerifyAttestation(bctx rego.BuiltinContext, refTerm *ast.Term, optsTerm *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", sigstoreVerifyAttestationName)
	ctx := bctx.Context

	uri, err := builtins.StringOperand(refTerm.Value, 0)
	if err != nil {
		logger.WithField("error", err).Debug("failed to get ref parameter")
		return attestationFailedResult(fmt.Errorf("ref parameter: %w", err))
	}
	logger = logger.WithField("ref", string(uri))

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		logger.WithField("error", err).Debug("failed to create new digest")
		return attestationFailedResult(fmt.Errorf("new digest: %w", err))
	}

	checkOpts, err := parseCheckOpts(ctx, optsTerm)
	if err != nil {
		logger.WithField("error", err).Debug("failed to parse check opts")
		return attestationFailedResult(fmt.Errorf("opts parameter: %w", err))
	}
	checkOpts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier

	logger.Debug("verifying image attestations")
	attestations, _, err := ecoci.NewClient(ctx).VerifyImageAttestations(ref, checkOpts)
	if err != nil {
		logger.WithField("error", err).Debug("failed to verify image attestation signature")
		return attestationFailedResult(fmt.Errorf("verify image attestation signature: %w", err))
	}

	logger.WithField("attestations_count", len(attestations)).Debug("attestation verification complete")
	return attestationResult(attestations, nil)
}

func parseCheckOpts(ctx context.Context, optsTerm *ast.Term) (*cosign.CheckOpts, error) {
	if _, err := builtins.ObjectOperand(optsTerm.Value, 1); err != nil {
		return nil, fmt.Errorf("opts parameter: %s", err)
	}
	opts := optionsFromTerm(optsTerm)

	policyOpts := policy.Options{
		// TODO: EffectiveTime is not actually used in this context, but it is required to be set
		// by policy.NewPolicy.
		EffectiveTime: "now",
		Identity: cosign.Identity{
			Subject:       opts.certificateIdentity,
			SubjectRegExp: opts.certificateIdentityRegExp,
			Issuer:        opts.certificateOIDCIssuer,
			IssuerRegExp:  opts.certificateOIDCIssuerRegExp,
		},
		IgnoreRekor: opts.ignoreRekor,
		PublicKey:   opts.publicKey,
		RekorURL:    opts.rekorURL,
	}

	policy, err := policy.NewPolicy(ctx, policyOpts)
	if err != nil {
		return nil, fmt.Errorf("new policy: %s", err)
	}

	checkOpts, err := policy.CheckOpts()
	if err != nil {
		return nil, fmt.Errorf("getting checkops: %w", err)
	}

	if opts.rekorPublicKey != "" {
		rekorPublicKeys := cosign.NewTrustedTransparencyLogPubKeys()
		if err := rekorPublicKeys.AddTransparencyLogPubKey([]byte(opts.rekorPublicKey), tuf.Active); err != nil {
			return nil, fmt.Errorf("adding rekor public key: %w", err)
		}
		checkOpts.RekorPubKeys = &rekorPublicKeys
	}

	return checkOpts, nil
}

type options struct {
	certificateIdentity         string
	certificateIdentityRegExp   string
	certificateOIDCIssuer       string
	certificateOIDCIssuerRegExp string
	ignoreRekor                 bool
	publicKey                   string
	rekorURL                    string
	rekorPublicKey              string
}

func (o options) toTerm() *ast.Term {
	return ast.ObjectTerm(
		ast.Item(ast.StringTerm(certificateIdentityAttribute), ast.StringTerm(o.certificateIdentity)),
		ast.Item(ast.StringTerm(certificateIdentityRegExpAttribute), ast.StringTerm(o.certificateIdentityRegExp)),
		ast.Item(ast.StringTerm(certificateOIDCIssuerAttribute), ast.StringTerm(o.certificateOIDCIssuer)),
		ast.Item(ast.StringTerm(certificateOIDCIssuerRegExpAttribute), ast.StringTerm(o.certificateOIDCIssuerRegExp)),
		ast.Item(ast.StringTerm(ignoreRekorAttribute), ast.BooleanTerm(o.ignoreRekor)),
		ast.Item(ast.StringTerm(publicKeyAttribute), ast.StringTerm(o.publicKey)),
		ast.Item(ast.StringTerm(rekorURLAttribute), ast.StringTerm(o.rekorURL)),
		ast.Item(ast.StringTerm(rekorPublicKeyAttribute), ast.StringTerm(o.rekorPublicKey)),
	)
}

func optionsFromTerm(term *ast.Term) options {
	opts := options{}

	opts.certificateIdentity = stringPropertyFromTerm(term, certificateIdentityAttribute)
	opts.certificateIdentityRegExp = stringPropertyFromTerm(term, certificateIdentityRegExpAttribute)
	opts.certificateOIDCIssuer = stringPropertyFromTerm(term, certificateOIDCIssuerAttribute)
	opts.certificateOIDCIssuerRegExp = stringPropertyFromTerm(term, certificateOIDCIssuerRegExpAttribute)
	opts.publicKey = stringPropertyFromTerm(term, publicKeyAttribute)
	opts.rekorPublicKey = stringPropertyFromTerm(term, rekorPublicKeyAttribute)
	opts.rekorURL = stringPropertyFromTerm(term, rekorURLAttribute)

	// nil check not required because this attribute is a static property. It will always have a value.
	if v, ok := term.Get(ast.StringTerm(ignoreRekorAttribute)).Value.(ast.Boolean); ok {
		opts.ignoreRekor = bool(v)
	}

	return opts
}

func stringPropertyFromTerm(term *ast.Term, propertyName string) string {
	propertyTerm := term.Get(ast.StringTerm(propertyName))
	if propertyTerm != nil {
		if v, ok := propertyTerm.Value.(ast.String); ok {
			return string(v)
		}
	}
	return ""
}

func signatureFailedResult(err error) (*ast.Term, error) {
	return signatureResult(nil, err)
}

func signatureResult(signatures []oci.Signature, err error) (*ast.Term, error) {
	var errorTerms []*ast.Term
	var sigTerms []*ast.Term

	if err != nil {
		errorTerms = append(errorTerms, ast.StringTerm(err.Error()))
	}

	for _, s := range signatures {
		sig, err := signature.NewEntitySignature(s)
		if err != nil {
			errorTerms = append(errorTerms, ast.StringTerm(fmt.Sprintf("parsing signature: %s", err)))
			continue
		}

		sigTerms = append(sigTerms, toSignatureTerm(sig))
	}

	success := len(errorTerms) == 0

	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("success"), ast.BooleanTerm(success)),
		ast.Item(ast.StringTerm("errors"), ast.ArrayTerm(errorTerms...)),
		ast.Item(ast.StringTerm("signatures"), ast.ArrayTerm(sigTerms...)),
	), nil
}

func attestationFailedResult(err error) (*ast.Term, error) {
	return attestationResult(nil, err)
}

func attestationResult(attestations []oci.Signature, err error) (*ast.Term, error) {
	var errorTerms []*ast.Term
	var attestationTerms []*ast.Term

	if err != nil {
		errorTerms = append(errorTerms, ast.StringTerm(err.Error()))
	}

	for _, s := range attestations {
		att, err := attestation.ProvenanceFromSignature(s)
		if err != nil {
			errorTerms = append(errorTerms, ast.StringTerm(fmt.Sprintf("parsing attestation: %s", err)))
			continue
		}

		var statement any
		if err := json.Unmarshal(att.Statement(), &statement); err != nil {
			errorTerms = append(errorTerms, ast.StringTerm(fmt.Sprintf("unmarshalling statement: %s", err)))
			continue
		}

		statementValue, err := ast.InterfaceToValue(statement)
		if err != nil {
			errorTerms = append(errorTerms, ast.StringTerm(fmt.Sprintf("interface to value: %s", err)))
			continue
		}

		var sigsTerm []*ast.Term
		for _, sig := range att.Signatures() {
			sigsTerm = append(sigsTerm, toSignatureTerm(sig))
		}

		attestationTerms = append(attestationTerms, ast.ObjectTerm(
			ast.Item(ast.StringTerm("statement"), ast.NewTerm(statementValue)),
			ast.Item(ast.StringTerm("signatures"), ast.ArrayTerm(sigsTerm...)),
		))
	}

	success := len(errorTerms) == 0

	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("success"), ast.BooleanTerm(success)),
		ast.Item(ast.StringTerm("errors"), ast.ArrayTerm(errorTerms...)),
		ast.Item(ast.StringTerm("attestations"), ast.ArrayTerm(attestationTerms...)),
	), nil
}

// ClearCaches clears the verify_image cache. Used for testing.
func ClearCaches() {
	verifyImageCache = sync.Map{}
}

func init() {
	registerSigstoreVerifyImage()
	registerSigstoreVerifyAttestation()
}
