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

package policy

import (
	"context"
	"crypto"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cosignSig "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoreSig "github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/kubernetes"
	"github.com/conforma/cli/internal/policy/cache"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

const (
	Now           = "now"
	AtAttestation = "attestation"
	DateFormat    = "2006-01-02"
)

// allows controlling time in tests
var now = time.Now

var PolicySourcesFrom = source.PolicySourcesFrom

func ValidatePolicy(ctx context.Context, policyConfig string) error {
	return validatePolicyConfig(policyConfig)
}

type SigstoreOpts struct {
	CertificateIdentity         string `json:"certificate_identity"`
	CertificateIdentityRegExp   string `json:"certificate_identity_regexp"`
	CertificateOIDCIssuer       string `json:"certificate_oidc_issuer"`
	CertificateOIDCIssuerRegExp string `json:"certificate_oidc_issuer_regexp"`
	IgnoreRekor                 bool   `json:"ignore_rekor"`
	PublicKey                   string `json:"public_key"`
	RekorURL                    string `json:"rekor_url"`
}

type Policy interface {
	PublicKeyPEM() ([]byte, error)
	CheckOpts() (*cosign.CheckOpts, error)
	WithSpec(spec ecc.EnterpriseContractPolicySpec) Policy
	Spec() ecc.EnterpriseContractPolicySpec
	EffectiveTime() time.Time
	AttestationTime(time.Time)
	Identity() cosign.Identity
	Keyless() bool
	SigstoreOpts() (SigstoreOpts, error)
}

type policy struct {
	ecc.EnterpriseContractPolicySpec
	checkOpts       *cosign.CheckOpts
	choosenTime     string
	effectiveTime   *time.Time
	attestationTime *time.Time
	identity        cosign.Identity
	ignoreRekor     bool
}

// PublicKeyPEM returns the PublicKey in PEM format.
func (p *policy) PublicKeyPEM() ([]byte, error) {
	// Public key is not involved when using keyless verification
	if p.Keyless() {
		return []byte{}, nil
	}
	if p.checkOpts == nil || p.checkOpts.SigVerifier == nil {
		return nil, errors.New("no check options or sig verifier configured")
	}
	pk, err := p.checkOpts.SigVerifier.PublicKey()
	if err != nil {
		return nil, err
	}
	return cryptoutils.MarshalPublicKeyToPEM(pk)
}

func (p *policy) CheckOpts() (*cosign.CheckOpts, error) {
	if p.checkOpts == nil {
		return nil, errors.New("no check options configured")
	}
	return p.checkOpts, nil
}

func (p *policy) Spec() ecc.EnterpriseContractPolicySpec {
	return p.EnterpriseContractPolicySpec
}

func (p *policy) Identity() cosign.Identity {
	return p.identity
}

// Keyless returns whether or not the Policy uses the keyless workflow for verification.
func (p *policy) Keyless() bool {
	return p.PublicKey == ""
}

func (p *policy) SigstoreOpts() (SigstoreOpts, error) {
	pk, err := p.PublicKeyPEM()
	if err != nil {
		return SigstoreOpts{}, err
	}

	opts := SigstoreOpts{
		CertificateIdentity:         p.identity.Subject,
		CertificateIdentityRegExp:   p.identity.SubjectRegExp,
		CertificateOIDCIssuer:       p.identity.Issuer,
		CertificateOIDCIssuerRegExp: p.identity.IssuerRegExp,
		IgnoreRekor:                 p.ignoreRekor,
		PublicKey:                   string(pk),
		RekorURL:                    p.RekorUrl,
	}

	return opts, nil
}

type Options struct {
	EffectiveTime string
	Identity      cosign.Identity
	IgnoreRekor   bool
	PolicyRef     string
	PublicKey     string
	RekorURL      string
}

// NewOfflinePolicy construct and return a new instance of Policy that is used
// in offline scenarios, i.e. without cluster or specific services access, and
// no signature verification being performed.
func NewOfflinePolicy(ctx context.Context, effectiveTime string) (Policy, error) {
	if efn, err := parseEffectiveTime(effectiveTime); err == nil {
		return &policy{
			effectiveTime: efn,
			choosenTime:   effectiveTime,
			checkOpts:     &cosign.CheckOpts{},
		}, nil
	} else {
		return nil, err
	}
}

// NewInertPolicy construct and return a new instance of Policy that doesn't
// perform strict checks on the consistency of the policy.
//
// The policyRef parameter is expected to be either a JSON-encoded instance of
// EnterpriseContractPolicySpec, or reference to the location of the EnterpriseContractPolicy
// resource in Kubernetes using the format: [namespace/]name
//
// If policyRef is blank, an empty EnterpriseContractPolicySpec is used.
func NewInertPolicy(ctx context.Context, policyRef string) (Policy, error) {
	p := policy{}

	if err := p.loadPolicy(ctx, policyRef); err != nil {
		return nil, err
	}

	return &p, nil
}

// NewInputPolicy constructs and returns a new instance of Policy that doesn't
// perform strict checks on the consistency of the policy, but can evaluate based on
// provided effectiveTime
//
// The policyRef parameter is expected to be either a YAML/JSON-encoded instance of
// EnterpriseContractPolicySpec, or reference to the location of the EnterpriseContractPolicy
// resource in Kubernetes using the format: [namespace/]name
//
// If policyRef is blank, an empty EnterpriseContractPolicySpec is used.
func NewInputPolicy(ctx context.Context, policyRef string, effectiveTime string) (Policy, error) {
	if efn, err := parseEffectiveTime(effectiveTime); err == nil {
		p := policy{
			choosenTime: effectiveTime,
			checkOpts:   &cosign.CheckOpts{},
		}
		if err := p.loadPolicy(ctx, policyRef); err != nil {
			return nil, err
		}
		p.effectiveTime = efn
		return &p, nil
	} else {
		return nil, err
	}
}

// NewPolicy construct and return a new instance of Policy.
//
// The policyRef parameter is expected to be either a JSON-encoded instance of
// EnterpriseContractPolicySpec, or reference to the location of the EnterpriseContractPolicy
// resource in Kubernetes using the format: [namespace/]name
//
// If policyRef is blank, an empty EnterpriseContractPolicySpec is used.
//
// rekorUrl and publicKey provide a mechanism to overwrite the attributes, of same name, in the
// EnterpriseContractPolicySpec.
//
// The public key is resolved as part of object construction. If the public key is a reference
// to a kubernetes resource, for example, the cluster will be contacted.
func NewPolicy(ctx context.Context, opts Options) (Policy, error) {
	p := policy{
		choosenTime: opts.EffectiveTime,
	}

	if err := p.loadPolicy(ctx, opts.PolicyRef); err != nil {
		return nil, err
	}

	if opts.RekorURL != "" && opts.RekorURL != p.RekorUrl {
		p.RekorUrl = opts.RekorURL
		log.Debugf("Updated rekor URL in policy to %q", opts.RekorURL)
	}

	p.ignoreRekor = opts.IgnoreRekor

	if opts.PublicKey != "" && opts.PublicKey != p.PublicKey {
		p.PublicKey = opts.PublicKey
		log.Debugf("Updated public key in policy to %q", opts.PublicKey)
	}

	if p.PublicKey == "" {
		if opts.Identity != (cosign.Identity{}) {
			p.identity = opts.Identity
		} else if p.EnterpriseContractPolicySpec.Identity != nil {
			identity := cosign.Identity{
				Issuer:        p.EnterpriseContractPolicySpec.Identity.Issuer,
				Subject:       p.EnterpriseContractPolicySpec.Identity.Subject,
				IssuerRegExp:  p.EnterpriseContractPolicySpec.Identity.IssuerRegExp,
				SubjectRegExp: p.EnterpriseContractPolicySpec.Identity.SubjectRegExp,
			}
			p.identity = identity
		}

		if err := validateIdentity(p.identity); err != nil {
			return nil, err
		}
	}

	if efn, err := parseEffectiveTime(opts.EffectiveTime); err != nil {
		return nil, err
	} else {
		p.effectiveTime = efn
	}

	if opts, err := checkOpts(ctx, &p); err != nil {
		return nil, err
	} else {
		p.checkOpts = opts
	}

	return &p, nil
}

func (p *policy) loadPolicy(ctx context.Context, policyRef string) error {
	if policyRef == "" {
		log.Debug("Using an empty EnterpriseContractPolicy")
		// Default to an empty policy instead of returning an error because the required
		// values, e.g. PublicKey, may be provided via other means, e.g.
		// publicKey param.
		return nil
	}
	/*
		Note: by the time we arrive here, if our policyRef was originally a URI for a
		JSON / YAML the document will have already opened / downloaded and it would be
		a JSON / YAML string which is why we can use `yaml.Unmarshal` below.

		Before we unmarshal we need to check if the policyRef text conforms to the
		EnprerpriseContractPolicySpec schema. If it does, we can proceed to unmarshal
		it. If it does not conform to the spec, we should return an error.
	*/
	if strings.Contains(policyRef, ":") { // Should detect JSON or YAML objects 🤞
		log.Debug("Read EnterpriseContractPolicy as YAML")
		ecp := ecc.EnterpriseContractPolicy{}
		if err := yaml.Unmarshal([]byte(policyRef), &ecp); err == nil && ecp.APIVersion != "" {
			p.EnterpriseContractPolicySpec = ecp.Spec
		} else {
			log.Debugf("Unable to parse EnterpriseContractPolicy from %q", policyRef)
			log.Debug("Attempting to parse as EnterpriseContractPolicySpec")
			if err := yaml.Unmarshal([]byte(policyRef), &p.EnterpriseContractPolicySpec); err != nil {
				log.Debugf("Unable to parse EnterpriseContractPolicySpec from %q", policyRef)
				return fmt.Errorf("unable to parse EnterpriseContractPolicySpec: %w", err)
			}
		}
		// Check if the policyRef is conformant to the schema
		if policyRef != "" {
			ok, err := p.isConformant(policyRef)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("policy does not conform to the schema")
			}
		}
	} else {
		log.Debug("Read EnterpriseContractPolicy as k8s resource")
		k8s, err := kubernetes.NewClient(ctx)
		if err != nil {
			log.Debug("Failed to initialize Kubernetes client")
			return fmt.Errorf("cannot initialize Kubernetes client: %w", err)
		}
		log.Debug("Initialized Kubernetes client")

		ecp, err := k8s.FetchEnterpriseContractPolicy(ctx, policyRef)
		if err != nil {
			log.Debug("Failed to fetch the enterprise contract policy from the cluster!")
			return fmt.Errorf("unable to fetch EnterpriseContractPolicy: %w", err)
		}
		p.EnterpriseContractPolicySpec = ecp.Spec
	}
	return nil
}

// isConformant checks if the given policy conforms to the Enterprise Contract
// Policy schema. It returns a boolean indicating conformance and an error if any
// occurred during the validation process.
func (p *policy) isConformant(policyRef string) (bool, error) {
	err := validatePolicyConfig(policyRef)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (p *policy) WithSpec(spec ecc.EnterpriseContractPolicySpec) Policy {
	p.EnterpriseContractPolicySpec = spec

	return p
}

func (p *policy) AttestationTime(attestationTime time.Time) {
	p.attestationTime = &attestationTime
	if p.choosenTime == AtAttestation {
		p.effectiveTime = &attestationTime
	}
}

func (p policy) EffectiveTime() time.Time {
	if p.effectiveTime == nil {
		now := now().UTC()
		log.Debugf("No effective time chosen using current time: %s", now.Format(time.RFC3339))
		p.effectiveTime = &now
	} else {
		log.Debugf("Using effective time: %s", p.effectiveTime.Format(time.RFC3339))
	}

	return *p.effectiveTime
}

func isNow(choosenTime string) bool {
	return strings.EqualFold(choosenTime, Now)
}

func parseEffectiveTime(choosenTime string) (*time.Time, error) {
	switch {
	case isNow(choosenTime):
		now := now().UTC()
		log.Debugf("Chosen to use effective time of `now`, using current time %s", now.Format(time.RFC3339))
		return &now, nil
	case strings.EqualFold(choosenTime, AtAttestation):
		log.Debugf("Chosen to use effective time of `attestation`")
		return nil, nil
	default:
		var err error
		if when, err := time.Parse(time.RFC3339, choosenTime); err == nil {
			log.Debugf("Using provided effective time %s", when.Format(time.RFC3339))
			whenUTC := when.UTC()
			return &whenUTC, nil
		}

		log.Debugf("Unable to parse provided effective time `%s` using RFC3339", choosenTime)
		errs := err

		if when, err := time.Parse(DateFormat, choosenTime); err == nil {
			log.Debugf("Using provided effective time %s", when.Format(time.RFC3339))
			whenUTC := when.UTC()
			return &whenUTC, nil
		}
		log.Debugf("Unable to parse provided effective time string `%s` using %s format", choosenTime, DateFormat)
		errs = errors.Join(errs, err)

		return nil, fmt.Errorf("invalid policy time argument: %s", errs)
	}
}

// checkOpts returns an instance based on attributes of the Policy.
func checkOpts(ctx context.Context, p *policy) (*cosign.CheckOpts, error) {
	var err error
	opts := cosign.CheckOpts{}

	if p.PublicKey != "" {
		log.Debug("Using long-lived key workflow")
		if opts.SigVerifier, err = signatureVerifier(ctx, p); err != nil {
			return nil, err
		}
	} else {
		log.Debug("Using keyless workflow")
		log.Debugf("TUF_ROOT=%s", os.Getenv("TUF_ROOT"))
		opts.Identities = []cosign.Identity{p.identity}

		// Get Fulcio certificates
		if opts.RootCerts, err = fulcio.GetRoots(); err != nil {
			return nil, err
		}
		if opts.IntermediateCerts, err = fulcio.GetIntermediates(); err != nil {
			return nil, err
		}

		// Get Certificate Transparency Log public keys
		if opts.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx); err != nil {
			return nil, err
		}
		log.Debug("Retrieved Rekor public keys")
	}

	opts.IgnoreTlog = p.ignoreRekor

	if !opts.IgnoreTlog {
		// NOTE: The value of the RekorURL may not be used by cosign during verification.
		// If the image signature/attestation contains a SignedEntryTimestamp, then cosign
		// takes on an offline verification approach. In this case, it does not query Rekor
		// for the existence of records. Instead, it ensures the SignedEntryTimestamp maps
		// to the Rekor public keys. The Rekor public keys may be already loaded on the
		// local copy of the TUF root. Otherwise, they are fetched from the TUF mirror.
		// In either case, the RekorURL is completely ignored. cosign always adds a
		// SignedEntryTimestamp to the signatures and attestations it creates.
		rekorURL := p.RekorUrl
		// NOTE: A Rekor client is only needed when a SignedEntryTimestamp is not available
		// on the signature/attestation.
		if rekorURL != "" {
			if opts.RekorClient, err = rekor.NewClient(rekorURL); err != nil {
				log.Debugf("Problem creating a rekor client using url %q", rekorURL)
				return nil, err
			}
			log.Debugf("Rekor client created, url %q", rekorURL)
		}

		if opts.RekorPubKeys, err = cosign.GetRekorPubs(ctx); err != nil {
			return nil, err
		}
		log.Debug("Retrieved Rekor public keys")
	}

	return &opts, nil
}

type signatureClient interface {
	publicKeyFromKeyRef(context.Context, string) (sigstoreSig.Verifier, error)
}

type cosignClient struct{}

func (c *cosignClient) publicKeyFromKeyRef(ctx context.Context, publicKey string) (sigstoreSig.Verifier, error) {
	return cosignSig.PublicKeyFromKeyRef(ctx, publicKey)
}

type contextKey string

const signatureClientContextKey contextKey = "ec.policy.signature.client"

func withSignatureClient(ctx context.Context, client signatureClient) context.Context {
	return context.WithValue(ctx, signatureClientContextKey, client)
}

func newSignatureClient(ctx context.Context) signatureClient {
	client, ok := ctx.Value(signatureClientContextKey).(signatureClient)
	if ok && client != nil {
		return client
	}

	return &cosignClient{}
}

// signatureVerifier creates a new instance based on the PublicKey from the Policy.
func signatureVerifier(ctx context.Context, p *policy) (sigstoreSig.Verifier, error) {
	publicKey := p.PublicKey

	if strings.Contains(publicKey, "-----BEGIN PUBLIC KEY-----") {
		verifier, err := cosignSig.LoadPublicKeyRaw([]byte(publicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return verifier, nil
	}

	verifier, err := newSignatureClient(ctx).publicKeyFromKeyRef(ctx, publicKey)
	if err != nil {
		return nil, err
	}
	return verifier, nil
}

func validateIdentity(identity cosign.Identity) error {
	var errs error

	if identity.Issuer == "" && identity.IssuerRegExp == "" {
		errs = errors.Join(errs, errors.New(
			"certificate OIDC issuer must be provided for keyless workflow"))
	}

	if identity.Subject == "" && identity.SubjectRegExp == "" {
		errs = errors.Join(errs, errors.New(
			"certificate identity must be provided for keyless workflow"))
	}

	return errs
}

func validatePolicyConfig(policyConfig string) error {
	policySchema, err := jsonschema.CompileString("schema.json", ecc.Schema)
	if err != nil {
		log.Errorf("Failed to compile schema: %s", err)
		return err
	}

	var v map[string]interface{}

	// Since JSON is a subset of YAML, yaml.Unmarshal can be used directly.
	if err := yaml.Unmarshal([]byte(policyConfig), &v); err != nil {
		log.Errorf("yaml.Unmarshal failed: %v", err)
		return err
	}

	// Extract the "spec" key from YAML, if present, to use as the policy.
	if spec, ok := v["spec"]; ok {
		v, ok = spec.(map[string]interface{})
		if !ok {
			return fmt.Errorf("spec is not a valid map structure")
		}
	}

	// Validate the policy against the schema.
	if err := policySchema.Validate(v); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

// PreProcessPolicy fetches policy sources and returns a policy object with
// pinned SHA/image digest URL where applicable, along with a policy cache object.
func PreProcessPolicy(ctx context.Context, policyOptions Options) (Policy, *cache.PolicyCache, error) {
	var policyCache *cache.PolicyCache
	pinnedPolicyUrls := map[string][]string{}
	policyCache = cache.NewPolicyCache(ctx)

	p, err := NewPolicy(ctx, policyOptions)
	if err != nil {
		return nil, nil, err
	}

	sources := p.Spec().Sources
	for i, sourceGroup := range sources {
		log.Debugf("Fetching policy source group '%+v'\n", sourceGroup.Name)
		policySources := PolicySourcesFrom(sourceGroup)

		fs := utils.FS(ctx)
		dir, err := utils.CreateWorkDir(fs)
		if err != nil {
			log.Debug("Failed to create work dir!")
			return nil, nil, err
		}

		for _, policySource := range policySources {
			if strings.HasPrefix(policySource.PolicyUrl(), "data:") {
				continue
			}

			destDir, err := policySource.GetPolicy(ctx, dir, false)
			if err != nil {
				log.Debugf("Unable to download source from %s!", policySource.PolicyUrl())
				return nil, nil, err
			}
			log.Debugf("Downloaded policy source from %s to %s\n", policySource.PolicyUrl(), destDir)

			url := policySource.PolicyUrl()

			if _, found := policyCache.Get(policySource.PolicyUrl()); !found {
				log.Debugf("Cache miss for: %s, adding to cache", url)
				policyCache.Set(url, destDir, nil)
				pinnedPolicyUrls[policySource.Subdir()] = append(pinnedPolicyUrls[policySource.Subdir()], url)
				log.Debugf("Added %s to the pinnedPolicyUrls in \"%s\"", url, policySource.Subdir())
			} else {
				log.Debugf("Cache hit for: %s", url)
			}
		}

		sources[i] = ecc.Source{
			Name:           sourceGroup.Name,
			Policy:         urls(policySources, source.PolicyKind),
			Data:           urls(policySources, source.DataKind),
			RuleData:       sourceGroup.RuleData,
			Config:         sourceGroup.Config,
			VolatileConfig: sourceGroup.VolatileConfig,
		}
	}

	return p, policyCache, err
}

func urls(s []source.PolicySource, kind source.PolicyType) []string {
	ret := make([]string, 0, len(s))
	for _, u := range s {
		if u.Type() == kind {
			ret = append(ret, u.PolicyUrl())
		}
	}

	return ret
}
