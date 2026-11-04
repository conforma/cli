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
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/stretchr/testify/require"
)

func TestOCICollect(t *testing.T) {
	sv, wrong := signer(t), signer(t)
	for _, kind := range []string{"absent", "legacy", "bundle", "wrong subject", "bad legacy alongside good", "bad bundle alongside good", "invalid claimed bundle", "image signature"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewServer(registry.New(registry.WithReferrersSupport(true), registry.Logger(log.New(io.Discard, "", 0))))
			defer server.Close()
			tag, err := name.NewTag(strings.TrimPrefix(server.URL, "http://") + "/image:latest")
			require.NoError(t, err)
			require.NoError(t, remote.Write(tag, empty.Image))
			hash, err := empty.Image.Digest()
			require.NoError(t, err)
			ref := tag.Context().Digest(hash.String())
			good := signedBundle(t, sv, predicateType, hash.Hex)
			if kind == "wrong subject" {
				good = signedBundle(t, sv, predicateType, strings.Repeat("0", 64))
			}
			if kind == "image signature" {
				good = signedBundle(t, wrong, imageSignaturePredicate, hash.Hex)
			}
			switch kind {
			case "legacy", "bad legacy alongside good", "wrong subject":
				var envelope struct {
					DSSE json.RawMessage `json:"dsseEnvelope"`
				}
				require.NoError(t, json.Unmarshal(good, &envelope))
				sig, err := static.NewAttestation(envelope.DSSE)
				require.NoError(t, err)
				img, err := mutate.AttachAttestationToImage(signed.Image(empty.Image), sig)
				require.NoError(t, err)
				if kind == "bad legacy alongside good" {
					require.NoError(t, json.Unmarshal(signedBundle(t, wrong, predicateType, hash.Hex), &envelope))
					bad, err := static.NewAttestation(envelope.DSSE)
					require.NoError(t, err)
					img, err = mutate.AttachAttestationToImage(img, bad)
					require.NoError(t, err)
				}
				require.NoError(t, ociremote.WriteAttestations(ref.Context(), img))
			case "bundle", "bad bundle alongside good", "invalid claimed bundle", "image signature":
				require.NoError(t, ociremote.WriteAttestationNewBundleFormat(ref, good, predicateType))
				if kind == "bad bundle alongside good" {
					require.NoError(t, ociremote.WriteAttestationNewBundleFormat(ref, signedBundle(t, wrong, predicateType, hash.Hex), predicateType))
				}
				if kind == "invalid claimed bundle" {
					require.NoError(t, ociremote.WriteAttestationNewBundleFormat(ref, []byte(`{"malformed":true}`), predicateType))
				}
			}
			records, err := NewOCI(cosign.CheckOpts{SigVerifier: sv, IgnoreTlog: true}).Collect(context.Background(), ref)
			if strings.HasPrefix(kind, "bad ") || kind == "invalid claimed bundle" || kind == "wrong subject" {
				require.Error(t, err)
				require.Nil(t, records)
				return
			}
			require.NoError(t, err)
			if kind == "absent" || kind == "image signature" {
				require.Empty(t, records)
			} else {
				require.Len(t, records, 1)
				require.Equal(t, hash.Hex, records[0].Subject()[0].Digest["sha256"])
			}
		})
	}
}
