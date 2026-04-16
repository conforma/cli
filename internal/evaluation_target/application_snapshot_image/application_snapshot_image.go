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

package application_snapshot_image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime/trace"

	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cosignOCI "github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/attestation"
	"github.com/conforma/cli/internal/evaluator"
	"github.com/conforma/cli/internal/fetchers/oci/config"
	"github.com/conforma/cli/internal/fetchers/oci/files"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/signature"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/utils/oci"
	"github.com/conforma/cli/pkg/schema"
)

var attestationSchemas = map[string]*jsonschema.Schema{
	"https://slsa.dev/provenance/v0.2": schema.SLSA_Provenance_v0_2,
	"https://slsa.dev/provenance/v1":   schema.SLSA_Provenance_v1,
}

// ApplicationSnapshotImage represents the structure needed to evaluate an Application Snapshot Image
type ApplicationSnapshotImage struct {
	reference        name.Reference
	checkOpts        cosign.CheckOpts
	signatures       []signature.EntitySignature
	configJSON       json.RawMessage
	parentConfigJSON json.RawMessage
	parentRef        name.Reference
	attestations     []attestation.Attestation
	Evaluators       []evaluator.Evaluator
	files            map[string]json.RawMessage
	component        app.SnapshotComponent
	snapshot         app.SnapshotSpec
	policySpec       ecc.EnterpriseContractPolicySpec
}

// NewApplicationSnapshotImage returns an ApplicationSnapshotImage struct with reference, checkOpts, and evaluator ready to use.
func NewApplicationSnapshotImage(ctx context.Context, component app.SnapshotComponent, p policy.Policy, snap app.SnapshotSpec) (*ApplicationSnapshotImage, error) {
	opts, err := p.CheckOpts()
	if err != nil {
		return nil, err
	}
	a := &ApplicationSnapshotImage{
		checkOpts:  *opts,
		component:  component,
		snapshot:   snap,
		policySpec: p.Spec(),
	}

	if err := a.SetImageURL(component.ContainerImage); err != nil {
		return nil, err
	}

	return a, nil
}

// ValidateImageAccess executes the remote.Head method on the ApplicationSnapshotImage image ref
func (a *ApplicationSnapshotImage) ValidateImageAccess(ctx context.Context) error {
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:validate-image-access")
		defer region.End()
	}

	resp, err := oci.NewClient(ctx).Head(a.reference)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("no response received")
	}
	log.Debugf("Resp: %+v", resp)
	return nil
}

func (a *ApplicationSnapshotImage) SetImageURL(url string) error {
	ref, err := name.ParseReference(url)
	if err != nil {
		log.Debugf("Failed to parse image url %s", url)
		return err
	}
	log.Debugf("Parsed image url %s", ref)
	a.reference = ref

	// Reset internal state relevant to the image
	a.attestations = []attestation.Attestation{}
	a.signatures = []signature.EntitySignature{}

	return nil
}

func (a *ApplicationSnapshotImage) hasBundles(ctx context.Context) bool {
	regOpts := []ociremote.Option{ociremote.WithRemoteOptions(oci.CreateRemoteOptions(ctx)...)}
	bundles, _, err := cosign.GetBundles(ctx, a.reference, regOpts)
	return err == nil && len(bundles) > 0
}

func (a *ApplicationSnapshotImage) FetchImageConfig(ctx context.Context) error {
	var err error
	a.configJSON, err = config.FetchImageConfig(ctx, a.reference)
	return err
}

func (a *ApplicationSnapshotImage) FetchParentImageConfig(ctx context.Context) error {
	var err error
	a.parentRef, err = config.FetchParentImage(ctx, a.reference)
	if err != nil {
		return err
	}
	a.parentConfigJSON, err = config.FetchImageConfig(ctx, a.parentRef)
	return err
}

func (a *ApplicationSnapshotImage) FetchImageFiles(ctx context.Context) error {
	var err error
	extractors := []files.Extractor{files.OLMManifest{}}
	a.files, err = files.ImageFiles(ctx, a.reference, extractors)
	return err
}

// ValidateImageSignature verifies the image signature. For images with Sigstore
// bundles (OCI referrers) the new bundle path is used; otherwise the legacy
// tag-based path is used.
func (a *ApplicationSnapshotImage) ValidateImageSignature(ctx context.Context) error {
	opts := a.checkOpts
	client := oci.NewClient(ctx)
	useBundles := a.hasBundles(ctx)

	var sigs []cosignOCI.Signature
	var err error

	if useBundles {
		// For v3 bundles, both image signatures and attestations are stored as
		// "attestations" in the unified bundle format. So we use VerifyImageAttestations
		// to extract image signatures from the bundle, even though it seems unintuitive.
		// This is different from v2 where image signatures and attestations were separate.
		//
		// The certificate extraction requires different handling for bundles and
		// should be addressed in future work to achieve full v2 parity.
		opts.NewBundleFormat = true
		opts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
		sigs, _, err = client.VerifyImageAttestations(a.reference, &opts)
	} else {
		opts.ClaimVerifier = cosign.SimpleClaimVerifier
		sigs, _, err = client.VerifyImageSignatures(a.reference, &opts)
	}
	if err != nil {
		return err
	}

	for _, s := range sigs {
		if useBundles {
			// This will appears in the output under "signatures" so filter out
			// the sigs that are provenance attestations leaving only the sigs
			// that are image signatures. Note: This does seems confusing and
			// I'm not 100% sure we're doing the right thing here. Maybe revisit
			// once we have a better idea about sigstore bundles and how they're
			// handled by cosign itself.
			if !isImageSignatureAttestation(s) {
				log.Debugf("Skipping non-image signature attestation")
				continue
			}

			// For bundle image signatures produced by cosign v3, the old
			// method of accessing the signatures doesn't work. Instead we have
			// to extract them from the bundle. And the bundle actually has
			// signatures for both the image itself and the attestation.
			signatures, err := extractSignaturesFromBundle(s)
			if err != nil {
				return fmt.Errorf("cannot extract signatures from bundle: %w", err)
			}
			a.signatures = append(a.signatures, signatures...)
		} else {
			// For older non-bundle image signatures produced by cosign v2.
			// Note that filtering isn't needed, since we have only image sigs here.
			es, err := signature.NewEntitySignature(s)
			if err != nil {
				return err
			}
			a.signatures = append(a.signatures, es)
		}
	}
	return nil
}

// ValidateAttestationSignature verifies and collects in-toto attestations
// attached to the image.
func (a *ApplicationSnapshotImage) ValidateAttestationSignature(ctx context.Context) error {
	opts := a.checkOpts
	opts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier

	useBundles := a.hasBundles(ctx)
	if useBundles {
		opts.NewBundleFormat = true
	}

	layers, _, err := oci.NewClient(ctx).VerifyImageAttestations(a.reference, &opts)
	if err != nil {
		return err
	}

	// Todo:
	// - For the non-bundle code path we actually check the syntax.
	//   We should do that for bundles as well probably.
	// - Doing an early return like thi shere seems untidy, refactor
	//   maybe?
	if useBundles {
		return a.parseAttestationsFromBundles(layers)
	}

	// Extract the signatures from the attestations here in order to also validate that
	// the signatures do exist in the expected format.
	for _, sig := range layers {
		att, err := attestation.ProvenanceFromSignature(sig)
		if err != nil {
			return fmt.Errorf("unable to parse untyped provenance: %w", err)
		}
		t := att.PredicateType()
		log.Debugf("Found attestation with predicateType: %s", t)
		switch t {
		case attestation.PredicateSLSAProvenance:
			// SLSAProvenanceFromSignature does the payload extraction
			// and decoding that was done in ProvenanceFromSignature
			// over again. We could refactor so we're not doing that twice,
			// but it's not super important IMO.
			sp, err := attestation.SLSAProvenanceFromSignature(sig)
			if err != nil {
				return fmt.Errorf("unable to parse as SLSA v0.2: %w", err)
			}
			a.attestations = append(a.attestations, sp)

		case attestation.PredicateSLSAProvenanceV1:
			// SLSA Provenance v1.0
			sp, err := attestation.SLSAProvenanceFromSignatureV1(sig)
			if err != nil {
				return fmt.Errorf("unable to parse as SLSA v1: %w", err)
			}
			a.attestations = append(a.attestations, sp)

		case attestation.PredicateSpdxDocument:
			// It's an SPDX format SBOM
			// Todo maybe: We could unmarshal it into a suitable SPDX struct
			// similar to how it's done for SLSA above
			a.attestations = append(a.attestations, att)

		// Todo: CycloneDX format SBOM

		default:
			// It's some other kind of attestation
			a.attestations = append(a.attestations, att)
		}
	}
	return nil
}

// parseAttestationsFromBundles extracts attestations from Sigstore bundles.
// Bundle-wrapped layers report an incorrect media type, so we unmarshal the
// DSSE envelope from the raw payload directly.
//
// Note: For v3 bundles, this function filters out image signature attestations
// (https://sigstore.dev/cosign/sign/v1) since those are handled in ValidateImageSignature.
// Only provenance and other attestations are added to the attestations array.
func (a *ApplicationSnapshotImage) parseAttestationsFromBundles(layers []cosignOCI.Signature) error {
	for _, sig := range layers {
		// For v3 bundles, filter out image signature attestations - those are handled
		// in ValidateImageSignature. Only add provenance attestations here.
		if isImageSignatureAttestation(sig) {
			log.Debugf("Skipping image signature attestation - handled in ValidateImageSignature")
			continue
		}

		payload, err := sig.Payload()
		if err != nil {
			log.Debugf("Skipping bundle entry: cannot read payload: %v", err)
			continue
		}
		var dsseEnvelope struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
		}
		if err := json.Unmarshal(payload, &dsseEnvelope); err != nil {
			log.Debugf("Skipping bundle entry: not a valid DSSE envelope: %v", err)
			continue
		}
		if dsseEnvelope.PayloadType != "application/vnd.in-toto+json" {
			log.Debugf("Skipping bundle entry with payloadType: %s", dsseEnvelope.PayloadType)
			continue
		}

		att, err := attestation.ProvenanceFromBundlePayload(sig, payload)
		if err != nil {
			return fmt.Errorf("unable to parse bundle attestation: %w", err)
		}
		log.Debugf("Found bundle attestation with predicateType: %s", att.PredicateType())

		a.attestations = append(a.attestations, att)
	}
	return nil
}

// ValidateAttestationSyntax validates the attestations against known JSON
// schemas, errors out if there are no attestations to check to prevent
// successful syntax check of no inputs, must invoke
// [ValidateAttestationSignature] to prefill the attestations.
func (a ApplicationSnapshotImage) ValidateAttestationSyntax(ctx context.Context) error {
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:validate-attestation-syntax")
		defer region.End()
	}

	if len(a.attestations) == 0 {
		log.Debug("No attestation data found, possibly due to attestation image signature not being validated beforehand")
		return errors.New("no attestation data")
	}

	var validationErr error
	for _, sp := range a.attestations {
		pt := sp.PredicateType()
		if schema, ok := attestationSchemas[pt]; ok {
			// Found a validator for this predicate type so let's use it
			log.Debugf("Attempting to validate an attestation with predicateType %s", pt)

			var statement any
			if err := json.Unmarshal(sp.Statement(), &statement); err != nil {
				return fmt.Errorf("unable to decode attestation data from attestation image: %w", err)
			}

			if err := schema.Validate(statement); err != nil {
				if _, ok = err.(*jsonschema.ValidationError); !ok {
					// Error while trying to validate
					return fmt.Errorf("unable to validate attestation data from attestation image: %w", err)
				}

				validationErr = errors.Join(validationErr, err)
			} else {
				log.Debugf("Statement schema was validated successfully against the %s schema", pt)
			}
		} else {
			log.Debugf("No schema validation found for predicateType %s", pt)
		}
	}

	if validationErr == nil {
		// TODO another option might be to filter out invalid statement JSONs
		// and keep only the valid ones
		return nil
	}

	log.Debug("Failed to validate statements from the attestation image against all known schemas")
	return fmt.Errorf("attestation syntax validation failed: %s", validationErr.Error())
}

// Attestations returns the value of the attestations field of the ApplicationSnapshotImage struct
func (a *ApplicationSnapshotImage) Attestations() []attestation.Attestation {
	return a.attestations
}

func (a *ApplicationSnapshotImage) Signatures() []signature.EntitySignature {
	return a.signatures
}

func (a *ApplicationSnapshotImage) ResolveDigest(ctx context.Context) (string, error) {
	digest, err := oci.NewClient(ctx).ResolveDigest(a.reference)
	if err != nil {
		return "", err
	}
	return digest, nil
}

func (a *ApplicationSnapshotImage) ImageReference(ctx context.Context) string {
	return a.reference.String()
}

type attestationData struct {
	Statement  json.RawMessage             `json:"statement"`
	Signatures []signature.EntitySignature `json:"signatures,omitempty"`
}

// MarshalJSON returns a JSON representation of the attestationData. It is customized to take into
// account that attestationData extends json.RawMessage. Leveraging the underlying MarshalJSON from
// json.RawMessage is problematic because its implementation excludes the additional attributes in
// attestationData. Instead, this method assumes the data being represented is a JSON object and it
// adds the additional attributes to it. Once the deprecated options of attestationData are removed,
// a standard process for Marshaling the JSON can be used, thus removing the need for this method.
func (a attestationData) MarshalJSON() ([]byte, error) {
	buffy := bytes.Buffer{}

	_, err := buffy.WriteString(`{"statement":`)
	if err != nil {
		return nil, fmt.Errorf("write statement key: %w", err)
	}
	statement, err := a.Statement.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal json statement: %w", err)
	}
	if _, err := buffy.Write(statement); err != nil {
		return nil, fmt.Errorf("write statement value: %w", err)
	}

	if len(a.Signatures) > 0 {
		_, err = buffy.WriteString(`, "signatures":`)
		if err != nil {
			return nil, fmt.Errorf("write signatures key: %w", err)
		}
		signatures, err := json.Marshal(a.Signatures)
		if err != nil {
			return nil, fmt.Errorf("marshal json signatures: %w", err)
		}
		if _, err := buffy.Write(signatures); err != nil {
			return nil, fmt.Errorf("write signatues value: %w", err)
		}
	}

	if err := buffy.WriteByte('}'); err != nil {
		return nil, fmt.Errorf("close json: %w", err)
	}

	return buffy.Bytes(), nil
}

type image struct {
	Ref        string                      `json:"ref"`
	Signatures []signature.EntitySignature `json:"signatures,omitempty"`
	Config     json.RawMessage             `json:"config,omitempty"`
	Parent     any                         `json:"parent,omitempty"`
	Files      map[string]json.RawMessage  `json:"files,omitempty"`
	Source     any                         `json:"source,omitempty"`
}

type Input struct {
	Attestations  []attestationData                `json:"attestations"`
	Image         image                            `json:"image"`
	AppSnapshot   app.SnapshotSpec                 `json:"snapshot"`
	ComponentName string                           `json:"component_name,omitempty"`
	PolicySpec    ecc.EnterpriseContractPolicySpec `json:"policy_spec,omitempty"`
}

// WriteInputFile writes the JSON from the attestations to input.json in a random temp dir
func (a *ApplicationSnapshotImage) WriteInputFile(ctx context.Context) (string, []byte, error) {
	log.Debugf("Attempting to write %d attestations to input file", len(a.attestations))

	var attestations []attestationData
	for _, a := range a.attestations {
		attestations = append(attestations, attestationData{
			Statement:  a.Statement(),
			Signatures: a.Signatures(),
		})
	}

	input := Input{
		Attestations: attestations,
		Image: image{
			Ref:        a.reference.String(),
			Signatures: a.signatures,
			Config:     a.configJSON,
			Files:      a.files,
			Source:     a.component.Source,
		},
		AppSnapshot:   a.snapshot,
		ComponentName: a.component.Name,
		PolicySpec:    a.policySpec,
	}

	if a.parentRef != nil {
		input.Image.Parent = image{
			Ref:    a.parentRef.String(),
			Config: a.parentConfigJSON,
		}
	}

	fs := utils.FS(ctx)
	inputDir, err := afero.TempDir(fs, "", "ecp_input.")
	if err != nil {
		log.Debug("Problem making temp dir!")
		return "", nil, err
	}
	log.Debugf("Created dir %s", inputDir)
	inputJSONPath := path.Join(inputDir, "input.json")

	f, err := fs.OpenFile(inputJSONPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		log.Debugf("Problem creating file in %s", inputDir)
		return "", nil, err
	}
	defer f.Close()

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return "", nil, fmt.Errorf("input to JSON: %w", err)
	}

	if _, err := f.Write(inputJSON); err != nil {
		return "", nil, fmt.Errorf("write input to file: %w", err)
	}

	log.Debugf("Done preparing input file:\n%s", inputJSONPath)
	return inputJSONPath, inputJSON, nil
}

// extractPredicateType extracts the predicateType field from a JSON
// payload lazily, i.e. without unmarshalling all the other fields
func extractPredicateType(payload []byte) (string, error) {
	var attestation struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(payload, &attestation); err != nil {
		return "", err
	}
	return attestation.PredicateType, nil
}

// hasPredicateType checks if a JSON payload has the specified predicate type.
func hasPredicateType(payload []byte, expectedType string) bool {
	predicateType, err := extractPredicateType(payload)
	if err != nil {
		log.Debugf("Cannot parse JSON payload: %v", err)
		return false
	}
	return predicateType == expectedType
}

const cosignSignPredicateType = "https://sigstore.dev/cosign/sign/v1"

// isImageSignatureAttestation checks if a signature from a bundle represents
// an image signature attestation (vs. a provenance attestation).
func isImageSignatureAttestation(sig cosignOCI.Signature) bool {
	payload, err := sig.Payload()
	if err != nil {
		log.Debugf("Cannot read signature payload: %v", err)
		return false
	}

	// Image signature attestations use the cosign/sign predicate type
	return hasPredicateType(payload, cosignSignPredicateType)
}

// extractSignaturesFromBundle extracts signature information from a bundle
// image signature attestation, using the same pattern as createEntitySignatures.
//
// TODO: This currently only extracts the signature value from the DSSE envelope.
// Certificate information (keyid, certificate, chain, metadata) is not being
// extracted because it requires different handling for v3 bundles compared to v2.
// Future work should investigate how to access certificate data from bundle
// attestations to achieve full parity with v2 signature output. Also, there might
// be some cosign methods we can use instead of doing it ourselves here.
func extractSignaturesFromBundle(sig cosignOCI.Signature) ([]signature.EntitySignature, error) {
	reader, err := sig.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("cannot read signature data: %w", err)
	}
	defer reader.Close()

	var attestationPayload cosign.AttestationPayload
	if err := json.NewDecoder(reader).Decode(&attestationPayload); err != nil {
		return nil, fmt.Errorf("cannot parse DSSE envelope: %w", err)
	}

	// Create the base EntitySignature from the oci.Signature (for certificate info)
	es, err := signature.NewEntitySignature(sig)
	if err != nil {
		return nil, fmt.Errorf("cannot create base signature: %w", err)
	}

	var results []signature.EntitySignature
	for _, s := range attestationPayload.Signatures {
		esNew := es
		// The Signature and KeyID can come from two locations, the oci.Signature or
		// the cosign.Signature. Prioritize information from oci.Signature, but fallback
		// to cosign.Signature when needed (same pattern as createEntitySignatures)
		//
		// Todo: Actually the above comment might be stale and/or wrong since I belive
		// it was copied from similar code in internal/attestation/attestation.go. Let's
		// review this later. As far as I can tell this code always produces an empty
		// string for the KeyId.
		//
		if esNew.Signature == "" {
			esNew.Signature = s.Sig
		}
		if esNew.KeyID == "" {
			esNew.KeyID = s.KeyID
		}
		results = append(results, esNew)
	}

	return results, nil
}
