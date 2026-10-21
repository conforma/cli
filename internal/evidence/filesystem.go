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
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	cosignsignature "github.com/sigstore/cosign/v3/pkg/signature"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/attestation"
	"github.com/conforma/cli/internal/utils"
)

// KeyTrust is the POC's explicit predicate-to-key binding. This deliberately does
// not extend the policy CRD. Each predicate may authorize multiple rotation keys.
type KeyTrust map[string][]cosign.CheckOpts

func LoadKeyTrust(ctx context.Context, bindings []string, base cosign.CheckOpts) (KeyTrust, error) {
	trust := KeyTrust{}
	for _, binding := range bindings {
		predicate, path, ok := strings.Cut(binding, "=")
		u, err := url.Parse(predicate)
		if !ok || path == "" || err != nil || u.Scheme == "" || predicate == imageSignaturePredicate {
			return nil, fmt.Errorf("invalid --evidence-key %q: expected predicateURI=publicKeyFile", binding)
		}
		pem, err := afero.ReadFile(utils.FS(ctx), path)
		if err != nil {
			return nil, fmt.Errorf("evidence key %s: %w", path, err)
		}
		verifier, err := cosignsignature.LoadPublicKeyRaw(pem, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("evidence key %s: %w", path, err)
		}
		// Carry common proof requirements, but never inherit an image signer identity.
		opts := cosign.CheckOpts{
			SigVerifier: verifier, TrustedMaterial: base.TrustedMaterial,
			IgnoreTlog: base.IgnoreTlog, IgnoreSCT: base.IgnoreSCT,
			UseSignedTimestamps: base.UseSignedTimestamps,
		}
		trust[predicate] = append(trust[predicate], opts)
	}
	if len(trust) == 0 {
		return nil, fmt.Errorf("--evidence requires at least one --evidence-key predicateURI=publicKeyFile")
	}
	return trust, nil
}

type Filesystem struct {
	path     string
	byDigest map[string][]attestation.Attestation
}

// NewFilesystem reads and verifies the entire batch once, before image workers
// start. No partial source is returned if any record fails authentication.
func NewFilesystem(ctx context.Context, path string, trust KeyTrust) (*Filesystem, error) {
	f, err := utils.FS(ctx).Open(path)
	if err != nil {
		return nil, fmt.Errorf("evidence %s: %w", path, err)
	}
	defer f.Close()
	const maxSize = 32 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("evidence %s: %w", path, err)
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("evidence %s exceeds 32 MiB", path)
	}
	if err := unambiguousJSON(data); err != nil {
		return nil, fmt.Errorf("evidence %s: %w", path, err)
	}
	records := []json.RawMessage{data}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, err
		}
	}
	s := &Filesystem{path: path, byDigest: map[string][]attestation.Attestation{}}
	for i, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a, err := verifyRecord(ctx, record, trust)
		if err != nil {
			return nil, fmt.Errorf("evidence %s record %d: %w", path, i+1, err)
		}
		seen := map[string]bool{}
		for _, subject := range a.Subject() {
			// name.Digest currently accepts SHA-256 image references.
			h := subject.Digest["sha256"]
			if len(h) != 64 || h != strings.ToLower(h) {
				return nil, fmt.Errorf("evidence %s record %d: subject requires a canonical sha256 image digest", path, i+1)
			}
			if _, err := hex.DecodeString(h); err != nil {
				return nil, fmt.Errorf("evidence %s record %d: invalid sha256 subject: %w", path, i+1, err)
			}
			digest := "sha256:" + h
			if !seen[digest] {
				s.byDigest[digest] = append(s.byDigest[digest], a)
				seen[digest] = true
			}
		}
	}
	return s, nil
}

func (s *Filesystem) Collect(ctx context.Context, ref name.Digest) ([]attestation.Attestation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]attestation.Attestation(nil), s.byDigest[ref.DigestStr()]...), nil
}

func (s *Filesystem) String() string { return "filesystem:" + s.path }

func verifyRecord(ctx context.Context, record []byte, trust KeyTrust) (attestation.Attestation, error) {
	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON(record); err != nil {
		return nil, fmt.Errorf("expected a Sigstore attestation bundle: %w", err)
	}
	if !b.MinVersion("v0.3") {
		return nil, fmt.Errorf("Sigstore bundle v0.3 or later required")
	}
	env := b.GetDsseEnvelope()
	if env == nil || env.PayloadType != "application/vnd.in-toto+json" {
		return nil, fmt.Errorf("bundle must contain an in-toto DSSE envelope")
	}
	if err := requireStatement(env.Payload); err != nil {
		return nil, err
	}
	// Read the untrusted predicate solely to choose an authorized verifier. The
	// verifier authenticates these exact payload bytes, including predicateType.
	var statement struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(env.Payload, &statement); err != nil {
		return nil, err
	}
	opts := trust[statement.PredicateType]
	if len(opts) == 0 {
		return nil, fmt.Errorf("no authorized key for predicate %q", statement.PredicateType)
	}
	h, err := hex.DecodeString(statement.Subject[0].Digest["sha256"])
	if err != nil || len(h) != 32 {
		return nil, fmt.Errorf("subject requires a sha256 image digest")
	}
	var verificationErrors error
	verified := false
	for _, option := range opts {
		if _, err := cosign.VerifyNewBundle(ctx, &option, verify.WithArtifactDigest("sha256", h), b); err != nil {
			verificationErrors = errors.Join(verificationErrors, err)
		} else {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("predicate %q failed verification against authorized keys: %w", statement.PredicateType, verificationErrors)
	}
	// Re-encoding the envelope does not change the original signed payload bytes.
	payload, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	sig, err := static.NewAttestation(payload)
	if err != nil {
		return nil, err
	}
	return parse(sig)
}
