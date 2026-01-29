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

// Package image handles image operations, like creating a random image, image signature
// or attestation images
package image

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/cucumber/godog"
	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	s "github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/layout"
	cosignRemote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	cosigntypes "github.com/sigstore/cosign/v2/pkg/types"
	rc "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"gopkg.in/go-jose/go-jose.v2/json"

	"github.com/conforma/cli/acceptance/attestation"
	"github.com/conforma/cli/acceptance/crypto"
	"github.com/conforma/cli/acceptance/registry"
	"github.com/conforma/cli/acceptance/rekor"
	"github.com/conforma/cli/acceptance/testenv"
)

type key int

const (
	imageStateKey key = iota // Key to imageState struct within context
)

const (
	openPolicyAgentData = "application/vnd.cncf.openpolicyagent.data.layer.v1+json"
	title               = "org.opencontainers.image.title"
)

// Signature is the information about the signature of the image
type Signature struct {
	KeyID       string            `json:"keyid"`
	Signature   string            `json:"sig"`
	Certificate string            `json:"certificate,omitempty"`
	Chain       []string          `json:"chain,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// imageState holds the state of images used in acceptance tests keyed by the
// short image name, a name without the registry or the digest, e.g.
// "acceptance/hello-world". string values hold the concrete references, e.g.
// "registry:port/acceptance/sha256-hash.att" and the Signature values hold more
// information about the signature of the image/data itself.
type imageState struct {
	AttestationSignatures map[string]Signature
	Attestations          map[string]string
	Images                map[string]string
	ImageSignatures       map[string]Signature
	Signatures            map[string]string
}

func (i *imageState) Initialize() {
	if i.AttestationSignatures == nil {
		i.AttestationSignatures = map[string]Signature{}
	}
	if i.Attestations == nil {
		i.Attestations = map[string]string{}
	}
	if i.Images == nil {
		i.Images = map[string]string{}
	}
	if i.ImageSignatures == nil {
		i.ImageSignatures = map[string]Signature{}
	}
	if i.Signatures == nil {
		i.Signatures = map[string]string{}
	}
}

func (i imageState) Key() any {
	return imageStateKey
}

// imageFrom returns the named image from the Context
func imageFrom(ctx context.Context, imageName string) (v1.Image, error) {
	state := testenv.FetchState[imageState](ctx)

	if state.Images[imageName] == "" {
		return nil, fmt.Errorf("can't find image info for image named %s, did you create the image beforehand", imageName)
	}

	ref, err := name.ParseReference(state.Images[imageName])
	if err != nil {
		return nil, err
	}

	return remote.Image(ref)
}

// CreateAndPushImageSignature for a named image in the Context creates a signature
// image, same as `cosign sign` or Tekton Chains would, of that named image and pushes it
// to the stub registry as a new tag for that image akin to how cosign and Tekton Chains
// do it. This implementation includes transparency log upload to generate bundle information.
func CreateAndPushImageSignature(ctx context.Context, imageName string, keyName string) (context.Context, error) {
	var state *imageState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if _, ok := state.Signatures[imageName]; ok {
		// we already created the signature
		return ctx, nil
	}

	image, err := imageFrom(ctx, imageName)
	if err != nil {
		return ctx, err
	}

	digest, err := image.Digest()
	if err != nil {
		return ctx, err
	}

	// the name of the image to sign referenced by the digest
	digestImage, err := name.NewDigest(fmt.Sprintf("%s@%s", imageName, digest.String()))
	if err != nil {
		return ctx, err
	}

	signer, err := crypto.SignerWithKey(ctx, keyName)
	if err != nil {
		return ctx, err
	}

	// Create the cosign signature payload and sign it
	payload, rawSignature, err := signature.SignImage(signer, digestImage, map[string]interface{}{})
	if err != nil {
		return ctx, err
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(rawSignature)

	// Create the signature structure for the stub rekor entry
	signature := Signature{
		KeyID:     "",
		Signature: signatureBase64,
	}

	signatureJSON, err := json.Marshal(signature)
	if err != nil {
		return ctx, fmt.Errorf("failed to marshal signature structure: %w", err)
	}

	// Get the public key from the signer for hashedrekord validation
	publicKey, err := signer.PublicKey()
	if err != nil {
		return ctx, fmt.Errorf("failed to get public key: %w", err)
	}

	publicKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return ctx, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create stubs for both Rekor entry signature creation and retrieval endpoints
	err = rekor.StubRekorEntryCreationForSignature(ctx, payload, rawSignature, signatureJSON, publicKeyBytes)
	if err != nil {
		return ctx, fmt.Errorf("error stubbing rekor endpoints: %w", err)
	}

	// Upload to transparency log to get bundle information like Tekton Chains does
	rekorURL, err := rekor.StubRekor(ctx)
	if err != nil {
		return ctx, fmt.Errorf("failed to get stub rekor URL: %w", err)
	}

	rekorClient, err := rc.GetRekorClient(rekorURL)
	if err != nil {
		return ctx, fmt.Errorf("failed to get rekor client: %w", err)
	}

	// Get public key or cert for transparency log upload
	pkoc, err := getPublicKeyOrCert(signer)
	if err != nil {
		return ctx, fmt.Errorf("failed to get public key or cert: %w", err)
	}

	// Compute payload checksum
	checksum := sha256.New()
	if _, err := checksum.Write(payload); err != nil {
		return ctx, fmt.Errorf("error checksuming payload: %w", err)
	}

	tlogEntry, err := cosign.TLogUpload(ctx, rekorClient, rawSignature, checksum, pkoc)
	if err != nil {
		return ctx, fmt.Errorf("failed to upload to transparency log: %w", err)
	}

	// Create bundle from the actual transparency log entry
	rekorBundle := bundle.EntryToBundle(tlogEntry)
	if rekorBundle == nil {
		return ctx, fmt.Errorf("rekorBundle is nil after EntryToBundle")
	}

	// Create the signature layer with bundle information using static.WithBundle
	signatureLayer, err := static.NewSignature(payload, signatureBase64, static.WithBundle(rekorBundle))
	if err != nil {
		return ctx, err
	}

	// Extract bundle information from signatureLayer to include in annotations
	annotations := map[string]string{
		static.SignatureAnnotationKey: signatureBase64,
	}

	// Add bundle annotation if bundle information exists
	bundleJSON, err := json.Marshal(rekorBundle)
	if err != nil {
		return ctx, fmt.Errorf("failed to marshal bundle for annotation: %w", err)
	}
	annotations[static.BundleAnnotationKey] = string(bundleJSON)

	// creates the signature image with the correct media type and config and appends
	// the signature layer to it
	signatureImage := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	signatureImage = mutate.ConfigMediaType(signatureImage, types.OCIConfigJSON)
	signatureImage, err = mutate.Append(signatureImage, mutate.Addendum{
		Layer:       signatureLayer,
		Annotations: annotations,
	})
	if err != nil {
		return ctx, err
	}

	// the name of the image + the <hash>.sig tag
	ref, err := registry.ImageReferenceInStubRegistry(ctx, fmt.Sprintf("%s:%s-%s.sig", imageName, digest.Algorithm, digest.Hex))
	if err != nil {
		return ctx, err
	}

	// push to the registry
	err = remote.Write(ref, signatureImage)
	if err != nil {
		return ctx, err
	}

	state.Signatures[imageName] = ref.String()
	state.ImageSignatures[imageName] = signature

	return ctx, nil
}

// CreateAndPushAttestation for a named image in the Context creates an attestation
// image, same as `cosign attest` or Tekton Chains would, and pushes it to the stub
// registry as a new tag for that image akin to how cosign and Tekton Chains do it
func CreateAndPushAttestation(ctx context.Context, imageName, keyName string) (context.Context, error) {
	return createAndPushAttestationInternal(ctx, imageName, keyName, nil, false)
}

// createAndPushAttestation for a named image in the Context creates an attestation
// image, same as `cosign attest` or Tekton Chains would, and pushes it to the stub
// registry as a new tag for that image akin to how cosign and Tekton Chains do
// it; this variant applies additional JSON Patch patches to the SLSA provenance
// statement as required by the tests. This implementation now includes transparency
// log upload to generate bundle information like Tekton Chains does for attestations.
func createAndPushAttestationWithPatches(ctx context.Context, imageName, keyName string, patches *godog.Table) (context.Context, error) {
	return createAndPushAttestationInternal(ctx, imageName, keyName, patches, false)
}

// createAndPushAttestationInternal is the internal implementation that supports both SLSA v0.2 and v1
func createAndPushAttestationInternal(ctx context.Context, imageName, keyName string, patches *godog.Table, useV1 bool) (context.Context, error) {
	var state *imageState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Attestations[imageName] != "" {
		// we already created the attestation
		return ctx, nil
	}

	image, err := imageFrom(ctx, imageName)
	if err != nil {
		return ctx, err
	}

	var statement any

	if useV1 {
		// SLSA v1.0
		statement, err = attestation.CreateV1StatementFor(imageName, image)
		if err != nil {
			return ctx, err
		}
	} else {
		// SLSA v0.2
		v02Statement, err := attestation.CreateStatementFor(imageName, image)
		if err != nil {
			return ctx, err
		}

		statement, err = applyPatches(v02Statement, patches)
		if err != nil {
			return ctx, err
		}
	}

	signedAttestation, err := attestation.SignStatement(ctx, keyName, statement)
	if err != nil {
		return ctx, err
	}

	// Extract signature information from the signed attestation
	var sig *cosign.Signatures
	sig, err = unmarshallSignatures(signedAttestation)
	if err != nil {
		return ctx, err
	}
	if sig == nil {
		return ctx, fmt.Errorf("failed to extract signature from attestation: no signatures found")
	}

	state.AttestationSignatures[imageName] = Signature{
		KeyID:     sig.KeyID,
		Signature: sig.Sig,
	}

	// Extract raw signature from the signed attestation for transparency log upload
	var rawSignature []byte
	if sig.Sig != "" {
		rawSignature, err = base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			return ctx, fmt.Errorf("failed to decode signature: %w", err)
		}
	}

	// Get the signer for transparency log operations
	signer, err := crypto.SignerWithKey(ctx, keyName)
	if err != nil {
		return ctx, err
	}

	// Get the public key from the signer for intoto validation
	publicKey, err := signer.PublicKey()
	if err != nil {
		return ctx, fmt.Errorf("failed to get public key: %w", err)
	}

	publicKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return ctx, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create stubs for both Rekor entry creation and retrieval endpoints for attestations
	err = rekor.StubRekorEntryCreationForAttestation(ctx, signedAttestation, publicKeyBytes)
	if err != nil {
		return ctx, fmt.Errorf("error stubbing rekor endpoints for attestation: %w", err)
	}

	// Upload to transparency log to get bundle information like Tekton Chains does
	rekorURL, err := rekor.StubRekor(ctx)
	if err != nil {
		return ctx, fmt.Errorf("failed to get stub rekor URL: %w", err)
	}

	rekorClient, err := rc.GetRekorClient(rekorURL)
	if err != nil {
		return ctx, fmt.Errorf("failed to get rekor client: %w", err)
	}

	// Get public key or cert for transparency log upload
	pkoc, err := getPublicKeyOrCert(signer)
	if err != nil {
		return ctx, fmt.Errorf("failed to get public key or cert: %w", err)
	}

	// Compute payload checksum
	checksum := sha256.New()
	if _, err := checksum.Write(signedAttestation); err != nil {
		return ctx, fmt.Errorf("error checksuming attestation: %w", err)
	}

	tlogEntry, err := cosign.TLogUpload(ctx, rekorClient, rawSignature, checksum, pkoc)
	if err != nil {
		return ctx, fmt.Errorf("failed to upload attestation to transparency log: %w", err)
	}

	// Create bundle from the actual transparency log entry
	rekorBundle := bundle.EntryToBundle(tlogEntry)
	if rekorBundle == nil {
		return ctx, fmt.Errorf("rekorBundle is nil after EntryToBundle")
	}

	// Create the attestation layer with bundle information using static.WithBundle
	attestationLayer, err := static.NewAttestation(signedAttestation, static.WithBundle(rekorBundle))
	if err != nil {
		return ctx, err
	}

	// Extract bundle information from attestationLayer to include in annotations
	annotations := map[string]string{
		// When cosign creates an attestation, it sets this annotation to an empty
		// string, as seen here:
		// https://github.com/sigstore/cosign/blob/34afd5240ce8490a4fa427c3f46523246643047c/pkg/oci/static/signature.go#L52-L55
		// We choose to mimic the cosign behavior to avoid inconsistencies in the tests.
		static.SignatureAnnotationKey: "",
	}

	// Add bundle annotation if bundle information exists
	bundleJSON, err := json.Marshal(rekorBundle)
	if err != nil {
		return ctx, fmt.Errorf("failed to marshal bundle for annotation: %w", err)
	}
	annotations[static.BundleAnnotationKey] = string(bundleJSON)

	// creates the attestation image with the correct media type and config and appends
	// the attestation layer to it
	attestationImage := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	attestationImage = mutate.ConfigMediaType(attestationImage, types.OCIConfigJSON)
	attestationImage, err = mutate.Append(attestationImage, mutate.Addendum{
		MediaType:   cosigntypes.DssePayloadType,
		Layer:       attestationLayer,
		Annotations: annotations,
	})
	if err != nil {
		return ctx, err
	}

	digest, err := image.Digest()
	if err != nil {
		return ctx, err
	}

	// the name of the image + the <hash>.att tag
	ref, err := registry.ImageReferenceInStubRegistry(ctx, fmt.Sprintf("%s:%s-%s.att", imageName, digest.Algorithm, digest.Hex))
	if err != nil {
		return ctx, err
	}

	// push to the registry
	err = remote.Write(ref, attestationImage)
	if err != nil {
		return ctx, err
	}

	if state.Attestations == nil {
		state.Attestations = make(map[string]string)
	}

	state.Attestations[imageName] = ref.String()

	return ctx, nil
}

// CreateAndPushV1Attestation for a named image creates a SLSA v1.0 attestation
// and pushes it to the stub registry
func CreateAndPushV1Attestation(ctx context.Context, imageName, keyName string) (context.Context, error) {
	return createAndPushAttestationInternal(ctx, imageName, keyName, nil, true)
}

// CreateAndPushImageWithParent creates a parent image and a test image for the given imageName.
func CreateAndPushImageWithParent(ctx context.Context, imageName string) (context.Context, error) {
	var err error

	parentName := fmt.Sprintf("%s/parent", imageName)
	ctx, parentRef, err := createAndPushPlainImage(ctx, parentName, nil)
	if err != nil {
		return ctx, err
	}

	parentURL, err := resolveRefDigest(parentRef)
	if err != nil {
		return ctx, err
	}

	ctx, _, err = createAndPushPlainImage(ctx, imageName, func(img v1.Image) (v1.Image, error) {
		return mutate.Annotations(img, map[string]string{
			"org.opencontainers.image.base.name": parentURL,
		}).(v1.Image), nil
	})
	if err != nil {
		return ctx, err
	}

	return ctx, nil
}

// createAndPushImageWithLayer creates a image containing a layer with the
// provided files
func createAndPushImageWithLayer(ctx context.Context, imageName string, files *godog.Table) (context.Context, error) {
	ctx, _, err := createAndPushPlainImage(ctx, imageName, func(img v1.Image) (v1.Image, error) {
		if files == nil || len(files.Rows) == 0 {
			return img, nil
		}

		buffy := bytes.Buffer{}
		t := tar.NewWriter(&buffy)

		for _, r := range files.Rows {
			f := r.Cells[1].Value
			content, err := os.ReadFile(path.Join("acceptance", f))
			if err != nil {
				return nil, err
			}

			name := r.Cells[0].Value
			if err := t.WriteHeader(&tar.Header{
				Name: name,
				Mode: 0644,
				Size: int64(len(content)),
			}); err != nil {
				return nil, err
			}

			if _, err := t.Write(content); err != nil {
				return nil, err
			}
		}

		if err := t.Close(); err != nil {
			return nil, err
		}

		return mutate.AppendLayers(img, s.NewLayer(buffy.Bytes(), types.OCIUncompressedLayer))
	})
	if err != nil {
		return ctx, err
	}

	return ctx, nil
}

func createAndPushLayer(ctx context.Context, content string, imageName string) (context.Context, error) {
	l := s.NewLayer([]byte(content), types.OCIUncompressedLayer)

	ref, err := registry.ImageReferenceInStubRegistry(ctx, imageName)
	if err != nil {
		return ctx, err
	}

	repo, err := name.NewRepository(ref.String())
	if err != nil {
		return ctx, err
	}

	return ctx, remote.WriteLayer(repo, l)
}

func labelImage(ctx context.Context, imageName string, labels *godog.Table) (context.Context, error) {
	state := testenv.FetchState[imageState](ctx)

	imageRef, ok := state.Images[imageName]
	if !ok {
		return ctx, fmt.Errorf("no such image exists: %s", imageName)
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return ctx, err
	}

	img, err := remote.Image(ref)
	if err != nil {
		return ctx, err
	}
	config, err := img.ConfigFile()
	if err != nil {
		return ctx, err
	}

	for _, r := range labels.Rows {
		name := r.Cells[0].Value
		value := r.Cells[1].Value

		config.Config.Labels[name] = value
	}

	img, err = mutate.Config(img, config.Config)
	if err != nil {
		return ctx, err
	}

	return ctx, remote.Push(ref, img)
}

type patchFn func(v1.Image) (v1.Image, error)

// createAndPushImage creates a small 4K random image with 2 layers and pushes it to
// the stub image registry. It returns a new context with an updated state containing
// information about the newly created image, the image URL, and an error if any are
// encountered.
func createAndPushPlainImage(ctx context.Context, imageName string, patch patchFn) (context.Context, string, error) {
	var state *imageState
	ctx, err := testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, "", err
	}

	if state.Attestations[imageName] != "" {
		// we already created the image
		return ctx, state.Images[imageName], nil
	}

	img, err := random.Image(4096, 2)
	if err != nil {
		return ctx, "", err
	}

	if patch != nil {
		if img, err = patch(img); err != nil {
			return ctx, "", err
		}
	}

	img, err = mutate.Config(img, v1.Config{
		Labels: map[string]string{
			"org.opencontainers.image.title": imageName,
		},
	})
	if err != nil {
		return ctx, "", err
	}

	ref, err := registry.ImageReferenceInStubRegistry(ctx, imageName)
	if err != nil {
		return ctx, "", err
	}

	// push to the registry
	err = remote.Write(ref, img)
	if err != nil {
		return ctx, "", err
	}

	if state.Images == nil {
		state.Images = make(map[string]string)
	}

	state.Images[imageName] = ref.String()

	return ctx, ref.String(), nil
}

// resolveRefDigest returns an image reference that is guaranteed to have a digest.
func resolveRefDigest(url string) (string, error) {
	ref, err := name.ParseReference(url)
	if err != nil {
		return "", err
	}

	if d, ok := ref.(name.Digest); ok {
		return d.String(), nil
	}

	descriptor, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}
	digest := descriptor.Digest.String()
	if digest == "" {
		return "", fmt.Errorf("digest for image %q is empty", url)
	}

	return fmt.Sprintf("%s@%s", ref.Name(), digest), nil
}

// createAndPushKeylessImage loads an existing image from disk, along its signature and attestation
// into the docker registry.
func createAndPushKeylessImage(ctx context.Context, imageName string) (context.Context, error) {
	ref, err := registry.ImageReferenceInStubRegistry(ctx, imageName)
	if err != nil {
		return ctx, err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return ctx, err
	}

	imageDir := path.Join(cwd, "acceptance", "image", "testimage")
	// get the signed image from disk
	sii, err := layout.SignedImageIndex(imageDir)
	if err != nil {
		return ctx, err
	}

	if err := cosignRemote.WriteSignedImageIndexImages(ref, sii); err != nil {
		return ctx, err
	}

	var state *imageState
	ctx, err = testenv.SetupState(ctx, &state)
	if err != nil {
		return ctx, err
	}

	if state.Images == nil {
		state.Images = make(map[string]string)
	}
	state.Images[imageName] = ref.String()

	storeSignatureData := func(where map[string]Signature, f func() (oci.Signatures, error)) error {
		sigs, err := f()
		if err != nil {
			return err
		}

		m, err := sigs.Manifest()
		if err != nil {
			return err
		}

		// read the signature from the layer annotations
		for _, l := range m.Layers {
			// just check for a single annotation
			var signature string
			var ok bool
			if signature, ok = l.Annotations[static.SignatureAnnotationKey]; !ok {
				continue
			}

			sig := Signature{
				Signature: signature,
			}

			if certPEM, ok := l.Annotations[static.CertificateAnnotationKey]; ok {
				certDER, _ := pem.Decode([]byte(certPEM))

				cert, err := x509.ParseCertificate(certDER.Bytes)
				if err != nil {
					return err
				}

				sig.KeyID = hex.EncodeToString(cert.SubjectKeyId)
				sig.Certificate = certPEM
			}

			if cert, ok := l.Annotations[static.ChainAnnotationKey]; ok {
				if strings.Contains(cert, "-\n-") {
					return errors.New("thus far we have only seen chain of length 1, fix the test to support more than one certificate in chain")
				}
				if !strings.HasSuffix(cert, "\n") { // for whatever reason the trailing newline is missing in the annotation
					cert += "\n"
				}
				sig.Chain = []string{cert} // TODO hmm
			}

			where[imageName] = sig

			return nil // TODO: support more than one signature

		}

		layers, err := sigs.Layers()
		if err != nil {
			return err
		}

		// read the signature from the layer content
		for _, l := range layers {
			r, err := l.Uncompressed()
			if err != nil {
				return err
			}

			raw, err := io.ReadAll(r)
			if err != nil {
				return err
			}

			sig, err := unmarshallSignatures(raw)
			if err != nil {
				return err
			}

			if sig != nil {
				where[imageName] = Signature{
					KeyID:     sig.KeyID,
					Signature: sig.Sig,
				}

				return nil // TODO: support more than one signature
			}
		}

		return nil
	}

	if sig, err := cosignRemote.SignatureTag(ref); err != nil {
		return ctx, err
	} else {
		state.Signatures[imageName] = sig.String()
	}

	if err := storeSignatureData(state.ImageSignatures, sii.Signatures); err != nil {
		return ctx, err
	}

	if att, err := cosignRemote.AttestationTag(ref); err != nil {
		return ctx, err
	} else {
		state.Attestations[imageName] = att.String()
	}

	if err := storeSignatureData(state.AttestationSignatures, sii.Attestations); err != nil {
		return ctx, err
	}

	return ctx, nil
}

// createAndPushPolicyBundle creates a OCI policy bundle with the given files as
// layers
func createAndPushPolicyBundle(ctx context.Context, imageName string, files *godog.Table) (context.Context, error) {
	bundle := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	bundle = mutate.ConfigMediaType(bundle, types.OCIConfigJSON)

	// add each row as a layer to the bundle
	for _, row := range files.Rows {
		file := row.Cells[0].Value

		source := row.Cells[1].Value

		bytes, err := os.ReadFile(path.Join("acceptance", source))
		if err != nil {
			return ctx, err
		}

		if bundle, err = mutate.Append(bundle, mutate.Addendum{
			MediaType: openPolicyAgentData,
			Layer:     s.NewLayer(bytes, openPolicyAgentData),
			Annotations: map[string]string{
				title: file,
			},
		}); err != nil {
			return ctx, err
		}
	}

	ref, err := registry.ImageReferenceInStubRegistry(ctx, imageName)
	if err != nil {
		return ctx, err
	}

	// push to the registry
	err = remote.Write(ref, bundle)
	if err != nil {
		return ctx, err
	}

	return ctx, nil
}

// AttestationFrom finds the raw attestation created by the createAndPushAttestation
func AttestationFrom(ctx context.Context, imageName string) ([]byte, error) {
	state := testenv.FetchState[imageState](ctx)

	refStr := state.Attestations[imageName]

	if refStr == "" {
		return nil, fmt.Errorf("no attestation found for image %s, did you create a attestation beforehand", imageName)
	}

	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, err
	}

	image, err := remote.Image(ref)
	if err != nil {
		return nil, err
	}

	layers, err := image.Layers()
	if err != nil {
		return nil, err
	}

	for _, layer := range layers {
		if mediaType, err := layer.MediaType(); err != nil {
			return nil, err
		} else if mediaType == cosigntypes.DssePayloadType {
			blob, err := layer.Uncompressed()
			if err != nil {
				return nil, err
			}
			defer blob.Close()

			return io.ReadAll(blob)
		}
	}

	return nil, fmt.Errorf("no attestation found for image %s, did you create a attestation beforehand", imageName)
}

// ImageSignatureFrom returns the image signature previously created by createAndPushImageSignature
func ImageSignatureFrom(ctx context.Context, imageName string) ([]byte, error) {
	state := testenv.FetchState[imageState](ctx)

	if sig, ok := state.ImageSignatures[imageName]; !ok {
		return nil, fmt.Errorf("no image signature found for image %s, did you create it beforehand?", imageName)
	} else {
		return json.Marshal(sig)
	}
}

// unmarshallSignatures extracts the signatures from the raw attestation
func unmarshallSignatures(rawCosignSignature []byte) (*cosign.Signatures, error) {
	var attestationPayload cosign.AttestationPayload
	if err := json.Unmarshal(rawCosignSignature, &attestationPayload); err != nil {
		return nil, err
	}

	l := len(attestationPayload.Signatures)
	switch {
	case l == 0:
		return nil, nil
	case l > 1:
		return nil, fmt.Errorf("received %d signatures, not expecting more than 1", l)
	default:
		return &attestationPayload.Signatures[0], nil
	}
}

// AttestationSignaturesFrom returns the list of attestation signatures found in the context in
// JSON format. If not found, and empty JSON array is returned.
func AttestationSignaturesFrom(ctx context.Context, prefix string) (map[string]string, error) {
	if !testenv.HasState[imageState](ctx) {
		return nil, nil
	}

	state := testenv.FetchState[imageState](ctx)

	signatures := map[string]string{}
	for name, signature := range state.AttestationSignatures {
		if signature.KeyID != "" {
			signatures[fmt.Sprintf("%s_KEY_ID_%s", prefix, name)] = signature.KeyID
		}
		if signature.Signature != "" {
			signatures[fmt.Sprintf("%s_%s", prefix, name)] = signature.Signature
		}
	}

	return signatures, nil
}

func RawAttestationSignaturesFrom(ctx context.Context) map[string]string {
	if !testenv.HasState[imageState](ctx) {
		return nil
	}

	state := testenv.FetchState[imageState](ctx)

	ret := map[string]string{}
	for ref, signature := range state.AttestationSignatures {
		ret[fmt.Sprintf("ATTESTATION_SIGNATURE_%s", ref)] = signature.Signature
	}

	return ret
}

func ImageSignaturesFrom(ctx context.Context, prefix string) (map[string]string, error) {
	if !testenv.HasState[imageState](ctx) {
		return nil, nil
	}

	state := testenv.FetchState[imageState](ctx)

	ret := map[string]string{}
	for name, signature := range state.ImageSignatures {
		if signature.KeyID != "" {
			ret[fmt.Sprintf("%s_KEY_ID_%s", prefix, name)] = signature.KeyID
		}
		if signature.Signature != "" {
			ret[fmt.Sprintf("%s_%s", prefix, name)] = signature.Signature
		}
	}

	return ret, nil
}

func RawImageSignaturesFrom(ctx context.Context) map[string]string {
	if !testenv.HasState[imageState](ctx) {
		return nil
	}

	state := testenv.FetchState[imageState](ctx)

	ret := map[string]string{}
	for ref, signature := range state.ImageSignatures {
		ret[fmt.Sprintf("IMAGE_SIGNATURE_%s", ref)] = signature.Signature
	}

	return ret
}

// getPublicKeyOrCert returns the cert if we have it, otherwise return public key
// This mimics the same logic used in Tekton Chains
func getPublicKeyOrCert(signer signature.SignerVerifier) ([]byte, error) {
	// For now, we'll always use the public key since we're using test keys
	// In a real scenario with certificates, we'd check for cert first
	pub, err := signer.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}
	pem, err := cryptoutils.MarshalPublicKeyToPEM(pub)
	if err != nil {
		return nil, fmt.Errorf("key to pem: %w", err)
	}
	return pem, nil
}

func applyPatches(statement *in_toto.ProvenanceStatementSLSA02, patches *godog.Table) (*in_toto.ProvenanceStatementSLSA02, error) {
	if statement == nil || patches == nil || len(patches.Rows) == 0 {
		return statement, nil
	}

	stmt, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}

	for _, patch := range patches.Rows {
		val := patch.Cells[0].Value
		jp, err := jsonpatch.DecodePatch([]byte(val))
		if err != nil {
			return nil, err
		}

		stmt, err = jp.Apply(stmt)
		if err != nil {
			return nil, err
		}
	}

	var modified in_toto.ProvenanceStatementSLSA02
	if err := json.Unmarshal(stmt, &modified); err != nil {
		return nil, err
	}

	return &modified, nil
}

// steal creates an image using createAndPushImage and steals the signature
// ("sig") or attestation ("att")
func steal(what string) func(context.Context, string, string) (context.Context, error) {
	return func(ctx context.Context, imageName string, signatureFrom string) (context.Context, error) {
		ctx, err := CreateAndPushImageWithParent(ctx, imageName)
		if err != nil {
			return ctx, err
		}

		fromImg, err := imageFrom(ctx, signatureFrom)
		if err != nil {
			return ctx, err
		}

		fromDigest, err := fromImg.Digest()
		if err != nil {
			return ctx, err
		}

		fromRef, err := registry.ImageReferenceInStubRegistry(ctx, fmt.Sprintf("%s:%s-%s.%s", signatureFrom, fromDigest.Algorithm, fromDigest.Hex, what))
		if err != nil {
			return ctx, err
		}

		stolen, err := remote.Image(fromRef)
		if err != nil {
			return ctx, err
		}

		toImg, err := imageFrom(ctx, imageName)
		if err != nil {
			return ctx, err
		}

		toDigest, err := toImg.Digest()
		if err != nil {
			return ctx, err
		}

		toRef, err := registry.ImageReferenceInStubRegistry(ctx, fmt.Sprintf("%s:%s-%s.%s", imageName, toDigest.Algorithm, toDigest.Hex, what))
		if err != nil {
			return ctx, err
		}

		return ctx, remote.Write(toRef, stolen)
	}
}

func copyAllImages(ctx context.Context, source, destination string) (context.Context, error) {
	state := testenv.FetchState[imageState](ctx)

	pusher, err := remote.NewPusher()
	if err != nil {
		return ctx, err
	}

	for _, imgs := range []map[string]string{state.Images, state.Signatures, state.Attestations} {
		var sourceStr string
		var ok bool
		if sourceStr, ok = imgs[source]; !ok {
			continue
		}

		sourceRef, err := name.ParseReference(sourceStr)
		if err != nil {
			return ctx, err
		}

		destStr := strings.ReplaceAll(sourceStr, source, destination)
		destRef, err := name.ParseReference(destStr)
		if err != nil {
			return ctx, err
		}

		desc, err := remote.Get(sourceRef)
		if err != nil {
			return ctx, err
		}

		if err := pusher.Push(ctx, destRef, desc); err != nil {
			return ctx, err
		}

		imgs[destination] = destStr
	}

	return ctx, nil
}

// AddStepsTo adds Gherkin steps to the godog ScenarioContext
func AddStepsTo(sc *godog.ScenarioContext) {
	sc.Step(`^an image named "([^"]*)"$`, CreateAndPushImageWithParent)
	sc.Step(`^an image named "([^"]*)" containing a layer with:$`, createAndPushImageWithLayer)
	sc.Step(`^the image "([^"]*)" has labels:$`, labelImage)
	sc.Step(`^a valid image signature of "([^"]*)" image signed by the "([^"]*)" key$`, CreateAndPushImageSignature)
	sc.Step(`^a valid attestation of "([^"]*)" signed by the "([^"]*)" key$`, CreateAndPushAttestation)
	sc.Step(`^a valid attestation of "([^"]*)" signed by the "([^"]*)" key, patched with$`, createAndPushAttestationWithPatches)
	sc.Step(`^a valid slsa v1 attestation of "([^"]*)" signed by the "([^"]*)" key$`, CreateAndPushV1Attestation)
	sc.Step(`^a signed and attested keyless image named "([^"]*)"$`, createAndPushKeylessImage)
	sc.Step(`^a OCI policy bundle named "([^"]*)" with$`, createAndPushPolicyBundle)
	sc.Step(`^an image named "([^"]*)" with signature from "([^"]*)"$`, steal("sig"))
	sc.Step(`^an image named "([^"]*)" with attestation from "([^"]*)"$`, steal("att"))
	sc.Step(`^all images relating to "([^"]*)" are copied to "([^"]*)"$`, copyAllImages)
	sc.Step(`^an OCI blob with content "([^"]*)" in the repo "([^"]*)"$`, createAndPushLayer)
}
