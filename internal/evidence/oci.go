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

package evidence

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/conforma/cli/internal/attestation"
	"github.com/conforma/cli/internal/utils/oci"
)

// OCI uses the existing image/provenance key configuration. Predicate-specific
// OCI trust configuration is outside this POC; --evidence-key governs files only.
type OCI struct{ opts cosign.CheckOpts }

func NewOCI(opts cosign.CheckOpts) *OCI { return &OCI{opts: opts} }
func (s *OCI) String() string           { return "oci" }

func (s *OCI) Collect(ctx context.Context, ref name.Digest) ([]attestation.Attestation, error) {
	opts := s.opts
	opts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	opts.RegistryClientOpts = append(append([]ociremote.Option(nil), s.opts.RegistryClientOpts...), ociremote.WithRemoteOptions(oci.CreateRemoteOptions(ctx)...))
	h, err := v1.NewHash(ref.DigestStr())
	if err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(h.Hex)
	if err != nil {
		return nil, err
	}
	var result []attestation.Attestation
	// A malformed object claiming to be a Sigstore bundle is a failure, while
	// unrelated referrers are not evidence candidates. Some registries return a
	// config media type in the descriptor, so inspect the manifest as well.
	index, err := ociremote.Referrers(ref, "", opts.RegistryClientOpts...)
	if err != nil {
		return nil, fmt.Errorf("OCI referrers %s: %w", ref, err)
	}
	for _, descriptor := range index.Manifests {
		bundleRef := ref.Context().Digest(descriptor.Digest.String())
		img, err := oci.NewClient(ctx).Image(bundleRef)
		if err != nil {
			return nil, fmt.Errorf("OCI referrer %s: %w", descriptor.Digest, err)
		}
		manifest, err := img.Manifest()
		if err != nil {
			return nil, fmt.Errorf("OCI referrer %s: %w", descriptor.Digest, err)
		}
		isBundle := strings.HasPrefix(descriptor.ArtifactType, "application/vnd.dev.sigstore.bundle") ||
			strings.HasPrefix(manifest.ArtifactType, "application/vnd.dev.sigstore.bundle")
		for _, layer := range manifest.Layers {
			isBundle = isBundle || strings.HasPrefix(string(layer.MediaType), "application/vnd.dev.sigstore.bundle")
		}
		if !isBundle {
			continue
		}
		b, err := ociremote.Bundle(bundleRef, opts.RegistryClientOpts...)
		if err != nil {
			return nil, fmt.Errorf("OCI bundle %s: %w", descriptor.Digest, err)
		}
		env := b.GetDsseEnvelope()
		if env == nil || env.PayloadType != "application/vnd.in-toto+json" {
			return nil, fmt.Errorf("OCI bundle %s lacks an in-toto envelope", descriptor.Digest)
		}
		if err := requireStatement(env.Payload); err != nil {
			return nil, err
		}
		var statement struct {
			PredicateType string `json:"predicateType"`
		}
		if err := json.Unmarshal(env.Payload, &statement); err != nil {
			return nil, err
		}
		if statement.PredicateType == imageSignaturePredicate {
			continue
		}
		if _, err := cosign.VerifyNewBundle(ctx, &opts, verify.WithArtifactDigest(h.Algorithm, digest), b); err != nil {
			return nil, fmt.Errorf("OCI bundle %s: %w", descriptor.Digest, err)
		}
		payload, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		sig, err := static.NewAttestation(payload)
		if err != nil {
			return nil, err
		}
		a, err := parse(sig)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	// Also collect legacy tag-based attestations. Verify each candidate so a
	// passing record cannot hide a bad record in Cosign's aggregate API.
	sigs, err := oci.NewClient(ctx).FetchAttestationLayers(ref)
	if err != nil {
		return nil, err
	}
	for i, sig := range sigs {
		if _, err := cosign.VerifyBlobAttestation(ctx, sig, h, &opts); err != nil {
			return nil, fmt.Errorf("OCI attestation %d: %w", i+1, err)
		}
		a, err := parse(sig)
		if err != nil {
			return nil, err
		}
		if a.PredicateType() != imageSignaturePredicate {
			result = append(result, a)
		}
	}
	return result, nil
}
