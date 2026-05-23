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

package signature

import (
	"encoding/hex"
	"encoding/pem"

	"github.com/sigstore/cosign/v3/pkg/oci"
)

type EntitySignature struct {
	KeyID       string            `json:"keyid"`
	Signature   string            `json:"sig"`
	Certificate string            `json:"certificate,omitempty"`
	Chain       []string          `json:"chain,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// NewEntitySignature creates a new EntitySignature from the given Signature.
func NewEntitySignature(sig oci.Signature) (EntitySignature, error) {
	es := EntitySignature{
		Metadata: map[string]string{},
	}

	var err error
	es.Signature, err = sig.Base64Signature()
	if err != nil {
		return EntitySignature{}, err
	}

	cert, err := sig.Cert()
	if err != nil {
		return EntitySignature{}, err
	}
	if cert != nil && len(cert.Raw) > 0 {
		es.Certificate = string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
		es.KeyID = hex.EncodeToString(cert.SubjectKeyId)

		if err := addCertificateMetadataTo(&es.Metadata, cert); err != nil {
			return EntitySignature{}, err
		}
	}

	chain, err := sig.Chain()
	if err != nil {
		return EntitySignature{}, err
	}
	for _, c := range chain {
		if len(c.Raw) == 0 {
			continue
		}
		es.Chain = append(es.Chain, string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})))
	}
	return es, nil
}
