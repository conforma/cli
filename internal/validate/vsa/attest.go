// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// attest.go
package vsa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	att "github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	cosigntypes "github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	sigopts "github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/spf13/afero"
)

// LoadPrivateKey is aliased to allow easy testing.
var LoadPrivateKey = cosign.LoadPrivateKey

type Attestor struct {
	PredicatePath string  // path to the raw VSA (predicate) JSON
	PredicateType string  // e.g. "https://enterprisecontract.dev/attestations/vsa/v1" // TODO: make this configurable
	Digest        string  // sha256:abcd…  (as returned by `skopeo inspect --format {{.Digest}}`)
	Repo          string  // "quay.io/acme/widget" (hostname/namespace/repo)
	Signer        *Signer // Signer is the signer used to sign the VSA
}

type Signer struct {
	KeyPath        string
	FS             afero.Fs
	WrapSigner     signature.Signer
	SignerVerifier signature.SignerVerifier // Store the original signer for public key access
}

func NewSigner(keyPath string, fs afero.Fs) (*Signer, error) {
	keyBytes, err := afero.ReadFile(fs, keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %q: %w", keyPath, err)
	}

	signerVerifier, err := LoadPrivateKey(keyBytes, []byte(os.Getenv("COSIGN_PASSWORD")))
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	return &Signer{
		KeyPath:        keyPath,
		FS:             fs,
		WrapSigner:     dsse.WrapSigner(signerVerifier, cosigntypes.IntotoPayloadType),
		SignerVerifier: signerVerifier,
	}, nil
}

// Add a constructor with sensible defaults
func NewAttestor(predicatePath, repo, digest string, signer *Signer) (*Attestor, error) {
	return &Attestor{
		PredicatePath: predicatePath,
		PredicateType: "https://conforma.dev/verification_summary/v1",
		Digest:        digest,
		Repo:          repo,
		Signer:        signer,
	}, nil
}

func (a Attestor) TargetDigest() string {
	return a.Digest
}

// AttestPredicate builds an in‑toto Statement around the predicate and
// returns the fully‑signed **DSSE envelope** (identical to cosign's
// --no-upload output).  Nothing is pushed to a registry or the TLog.
func (a Attestor) AttestPredicate(ctx context.Context) ([]byte, error) {
	//-------------------------------------------------------------------- 1. read predicate
	predFile, err := a.Signer.FS.Open(a.PredicatePath)
	if err != nil {
		return nil, fmt.Errorf("open predicate: %w", err)
	}
	defer predFile.Close()

	//-------------------------------------------------------------------- 2. make the in‑toto statement
	stmt, err := att.GenerateStatement(att.GenerateOpts{
		Predicate: predFile,
		Type:      a.PredicateType,
		Digest:    strings.TrimPrefix(a.TargetDigest(), "sha256:"),
		Repo:      a.Repo,
		Time:      time.Now, // keeps tests deterministic
	})
	if err != nil {
		return nil, fmt.Errorf("wrap predicate: %w", err)
	}
	payload, _ := json.Marshal(stmt) // canonicalised by dsse later

	//-------------------------------------------------------------------- 3. sign -> DSSE envelope
	env, err := a.Signer.WrapSigner.SignMessage(bytes.NewReader(payload), sigopts.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to sign VSA: %w", err)
	}

	return env, nil
}

// WriteEnvelope is an optional convenience that mirrors cosign's
// --output‑signature flag; it emits <predicate>.intoto.jsonl next to the file.
func (a Attestor) WriteEnvelope(data []byte) (string, error) {
	out := a.PredicatePath + ".intoto.jsonl"
	if err := afero.WriteFile(a.Signer.FS, out, data, 0o644); err != nil {
		return "", err
	}

	abs, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	return abs, nil
}
