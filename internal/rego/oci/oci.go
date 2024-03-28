// Copyright The Enterprise Contract Contributors
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

package oci

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	log "github.com/sirupsen/logrus"

	"github.com/enterprise-contract/ec-cli/internal/fetchers/oci"
	"github.com/enterprise-contract/ec-cli/internal/rego/testing"
)

const (
	ociBlobName          = "ec.oci.blob"
	ociImageManifestName = "ec.oci.image_manifest"
)

func registerOCIBlob() {
	decl := rego.Function{
		Name: ociBlobName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI blob reference"),
			),
			types.Named("blob", types.S).Description("the OCI blob"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociBlob)
	// Due to https://github.com/open-policy-agent/opa/issues/6449, we cannot set a description for
	// the custom function through the call above. As a workaround we re-register the function with
	// a declaration that does include the description.
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch a blob from an OCI registry.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

func registerOCIImageManifest() {
	platform := types.NewObject(
		[]*types.StaticProperty{
			{Key: "architecture", Value: types.S},
			{Key: "os", Value: types.S},
			{Key: "os.version", Value: types.S},
			{Key: "os.features", Value: types.NewArray([]types.Type{types.S}, nil)},
			{Key: "variant", Value: types.S},
			{Key: "features", Value: types.NewArray([]types.Type{types.S}, nil)},
		},
		nil,
	)

	// annotations represents the map[string]string rego type
	annotations := types.NewObject(nil, types.NewDynamicProperty(types.S, types.S))

	descriptor := types.NewObject(
		[]*types.StaticProperty{
			{Key: "mediaType", Value: types.S},
			{Key: "size", Value: types.N},
			{Key: "digest", Value: types.S},
			{Key: "data", Value: types.S},
			{Key: "urls", Value: types.NewArray(
				[]types.Type{types.S}, nil,
			)},
			{Key: "annotations", Value: annotations},
			{Key: "platform", Value: platform},
			{Key: "artifactType", Value: types.S},
		},
		nil,
	)

	manifest := types.NewObject(
		[]*types.StaticProperty{
			// Specifying the properties like this ensure the compiler catches typos when
			// evaluating rego functions.
			{Key: "schemaVersion", Value: types.N},
			{Key: "mediaType", Value: types.S},
			{Key: "config", Value: descriptor},
			{Key: "layers", Value: types.NewArray(
				[]types.Type{descriptor}, nil,
			)},
			{Key: "annotations", Value: annotations},
			{Key: "subject", Value: descriptor},
		},
		nil,
	)

	decl := rego.Function{
		Name: ociImageManifestName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI image reference"),
			),
			types.Named("object", manifest).Description("the Image Manifest object"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociImageManifest)
	// Due to https://github.com/open-policy-agent/opa/issues/6449, we cannot set a description for
	// the custom function through the call above. As a workaround we re-register the function with
	// a declaration that does include the description.
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch an Image Manifest from an OCI registry.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

const maxBytes = 10 * 1024 * 1024 // 10 MB

func ociBlob(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	uri, ok := a.Value.(ast.String)
	if !ok {
		return nil, nil
	}

	if mocked, ok := testing.Mocked(bctx, ociBlobName, ast.NewTerm(ast.NewArray(a))); ok {
		return mocked, nil
	}

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		log.Errorf("%s new digest: %s", ociBlobName, err)
		return nil, nil
	}

	opts := []remote.Option{
		remote.WithTransport(remote.DefaultTransport),
		remote.WithContext(bctx.Context),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	rawLayer, err := oci.NewClient(bctx.Context).Layer(ref, opts...)
	if err != nil {
		log.Errorf("%s fetch layer: %s", ociBlobName, err)
		return nil, nil
	}

	layer, err := rawLayer.Uncompressed()
	if err != nil {
		log.Errorf("%s layer uncompressed: %s", ociBlobName, err)
		return nil, nil
	}
	defer layer.Close()

	// TODO: Other algorithms are technically supported, e.g. sha512. However, support for those is
	// not complete in the go-containerregistry library, e.g. name.NewDigest throws an error if
	// sha256 is not used. This is good for now, but may need revisiting later.
	hasher := sha256.New()
	// Setup some safeguards. First, use LimitReader to avoid an unbounded amount of data from being
	// read. Second, use TeeReader so we can compute the digest of the content read.
	reader := io.TeeReader(io.LimitReader(layer, maxBytes), hasher)

	var blob bytes.Buffer
	if _, err := io.Copy(&blob, reader); err != nil {
		log.Errorf("%s copy buffer: %s", ociBlobName, err)
		return nil, nil
	}

	sum := fmt.Sprintf("sha256:%x", hasher.Sum(nil))
	// io.LimitReader truncates the layer if it exceeds its limit. The condition below catches this
	// scenario in order to avoid unexpected behavior caused by partial data being returned.
	if sum != ref.DigestStr() {
		log.Errorf(
			"%s computed digest, %q, not as expected, %q. Content may have been truncated at %d bytes",
			ociBlobName, sum, ref.DigestStr(), maxBytes)
		return nil, nil
	}

	return ast.StringTerm(blob.String()), nil
}

func ociImageManifest(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	log := log.WithField("rego", ociImageManifestName)
	uri, ok := a.Value.(ast.String)
	if !ok {
		return nil, nil
	}

	ref, err := name.NewDigest(string(uri))
	if err != nil {
		log.Errorf("new digest: %s", err)
		return nil, nil
	}

	opts := []remote.Option{
		remote.WithTransport(remote.DefaultTransport),
		remote.WithContext(bctx.Context),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	image, err := oci.NewClient(bctx.Context).Image(ref, opts...)
	if err != nil {
		log.Errorf("fetch image: %s", err)
		return nil, nil
	}

	manifest, err := image.Manifest()
	if err != nil {
		log.Errorf("fetch manifest: %s", err)
		return nil, nil
	}

	if manifest == nil {
		log.Error("manifest is nil")
		return nil, nil
	}

	layers := []*ast.Term{}
	for _, layer := range manifest.Layers {
		layers = append(layers, newDescriptorTerm(layer))
	}

	manifestTerms := [][2]*ast.Term{
		ast.Item(ast.StringTerm("schemaVersion"), ast.NumberTerm(json.Number(fmt.Sprintf("%d", manifest.SchemaVersion)))),
		ast.Item(ast.StringTerm("mediaType"), ast.StringTerm(string(manifest.MediaType))),
		ast.Item(ast.StringTerm("config"), newDescriptorTerm(manifest.Config)),
		ast.Item(ast.StringTerm("layers"), ast.ArrayTerm(layers...)),
		ast.Item(ast.StringTerm("annotations"), newAnnotationsTerm(manifest.Annotations)),
	}

	if s := manifest.Subject; s != nil {
		manifestTerms = append(manifestTerms, ast.Item(ast.StringTerm("subject"), newDescriptorTerm(*s)))
	}

	return ast.ObjectTerm(manifestTerms...), nil
}

func newPlatformTerm(p v1.Platform) *ast.Term {
	osFeatures := []*ast.Term{}
	for _, f := range p.OSFeatures {
		osFeatures = append(osFeatures, ast.StringTerm(f))
	}

	features := []*ast.Term{}
	for _, f := range p.Features {
		features = append(features, ast.StringTerm(f))
	}

	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("architecture"), ast.StringTerm(p.Architecture)),
		ast.Item(ast.StringTerm("os"), ast.StringTerm(p.OS)),
		ast.Item(ast.StringTerm("os.version"), ast.StringTerm(p.OSVersion)),
		ast.Item(ast.StringTerm("os.features"), ast.ArrayTerm(osFeatures...)),
		ast.Item(ast.StringTerm("variant"), ast.StringTerm(p.Variant)),
		ast.Item(ast.StringTerm("features"), ast.ArrayTerm(features...)),
	)
}

func newDescriptorTerm(d v1.Descriptor) *ast.Term {
	urls := []*ast.Term{}
	for _, url := range d.URLs {
		urls = append(urls, ast.StringTerm(url))
	}

	dTerms := [][2]*ast.Term{
		ast.Item(ast.StringTerm("mediaType"), ast.StringTerm(string(d.MediaType))),
		ast.Item(ast.StringTerm("size"), ast.NumberTerm(json.Number(fmt.Sprintf("%d", d.Size)))),
		ast.Item(ast.StringTerm("digest"), ast.StringTerm(d.Digest.String())),
		ast.Item(ast.StringTerm("data"), ast.StringTerm(string(d.Data))),
		ast.Item(ast.StringTerm("urls"), ast.ArrayTerm(urls...)),
		ast.Item(ast.StringTerm("annotations"), newAnnotationsTerm(d.Annotations)),
		ast.Item(ast.StringTerm("artifactType"), ast.StringTerm(d.ArtifactType)),
	}

	if d.Platform != nil {
		dTerms = append(dTerms, ast.Item(ast.StringTerm("platform"), newPlatformTerm(*d.Platform)))
	}

	return ast.ObjectTerm(dTerms...)
}

func newAnnotationsTerm(annotations map[string]string) *ast.Term {
	annotationTerms := [][2]*ast.Term{}
	for key, value := range annotations {
		annotationTerms = append(annotationTerms, ast.Item(ast.StringTerm(key), ast.StringTerm(value)))
	}
	return ast.ObjectTerm(annotationTerms...)
}

func init() {
	registerOCIBlob()
	registerOCIImageManifest()
}
