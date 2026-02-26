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

package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/fetchers/oci/files"
	"github.com/conforma/cli/internal/utils/oci"
)

const (
	ociBlobName                = "ec.oci.blob"
	ociBlobFilesName           = "ec.oci.blob_files"
	ociDescriptorName          = "ec.oci.descriptor"
	ociImageManifestName       = "ec.oci.image_manifest"
	ociImageManifestsBatchName = "ec.oci.image_manifests"
	ociImageFilesName          = "ec.oci.image_files"
	ociImageIndexName          = "ec.oci.image_index"
	maxTarEntrySizeConst       = 500 * 1024 * 1024 // 500MB
)

var maxTarEntrySize int64 = maxTarEntrySizeConst // Use var to allow override in tests

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

func registerOCIDescriptor() {
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
	manifest := types.NewObject(
		[]*types.StaticProperty{
			// Specifying the properties like this ensure the compiler catches typos when
			// evaluating rego functions.
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

	decl := rego.Function{
		Name: ociDescriptorName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI descriptor reference"),
			),
			types.Named("object", manifest).Description("the OCI descriptor object"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociDescriptor)
	// Due to https://github.com/open-policy-agent/opa/issues/6449, we cannot set a description for
	// the custom function through the call above. As a workaround we re-register the function with
	// a declaration that does include the description.
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch a raw Image from an OCI registry.",
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

func registerOCIImageManifestsBatch() {
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

	// Return type is an object mapping ref strings to manifests
	resultType := types.NewObject(nil, types.NewDynamicProperty(
		types.Named("ref", types.S).Description("the OCI image reference"),
		types.Named("manifest", manifest).Description("the Image Manifest object"),
	))

	decl := rego.Function{
		Name: ociImageManifestsBatchName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("refs", types.NewSet(types.S)).Description("set of OCI image references"),
			),
			types.Named("manifests", resultType).Description("object mapping refs to their Image Manifest objects"),
		),
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociImageManifestsBatch)
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch Image Manifests from an OCI registry in parallel.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

func registerOCIImageFiles() {
	filesObject := types.NewObject(
		nil,
		types.NewDynamicProperty(
			types.Named("path", types.S).Description("the full path of the file within the image"),
			types.Named("content", types.A).Description("the file contents"),
		),
	)

	decl := rego.Function{
		Name:        ociImageFilesName,
		Description: "Fetch structured files (YAML or JSON) from within an image.",
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI image reference"),
				types.Named("paths", types.NewArray([]types.Type{types.S}, nil)).Description("the list of paths"),
			),
			types.Named("files", filesObject).Description("object representing the extracted files"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin2(&decl, ociImageFiles)
}

func registerOCIBlobFiles() {
	filesObject := types.NewObject(
		nil,
		types.NewDynamicProperty(
			types.Named("path", types.S).Description("the full path of the file within the blob"),
			types.Named("content", types.A).Description("the file contents"),
		),
	)

	decl := rego.Function{
		Name:        ociBlobFilesName,
		Description: "Fetch structured files (YAML or JSON) from within a blob tar archive.",
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI blob reference"),
				types.Named("paths", types.NewArray([]types.Type{types.S}, nil)).Description("the list of paths"),
			),
			types.Named("files", filesObject).Description("object representing the extracted files"),
		),
		// As per the documentation, enable memoization to ensure function evaluation is
		// deterministic. But also mark it as non-deterministic because it does rely on external
		// entities, i.e. OCI registry. https://www.openpolicyagent.org/docs/latest/extensions/
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin2(&decl, ociBlobFiles)
}

func registerOCIImageIndex() {
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

	annotations := types.NewObject(nil, types.NewDynamicProperty(types.S, types.S))

	descriptor := types.NewObject(
		[]*types.StaticProperty{
			{Key: "mediaType", Value: types.S},
			{Key: "size", Value: types.N},
			{Key: "digest", Value: types.S},
			{Key: "data", Value: types.S},
			{Key: "urls", Value: types.NewArray([]types.Type{types.S}, nil)},
			{Key: "annotations", Value: annotations},
			{Key: "platform", Value: platform},
		},
		nil,
	)

	imageIndex := types.NewObject(
		[]*types.StaticProperty{
			{Key: "schemaVersion", Value: types.N},
			{Key: "mediaType", Value: types.S},
			{Key: "manifests", Value: types.NewArray([]types.Type{descriptor}, nil)},
			{Key: "annotations", Value: annotations},
		},
		nil,
	)

	decl := rego.Function{
		Name: ociImageIndexName,
		Decl: types.NewFunction(
			types.Args(
				types.Named("ref", types.S).Description("OCI image index reference"),
			),
			types.Named("object", imageIndex).Description("the Image Index object"),
		),
		Memoize:          true,
		Nondeterministic: true,
	}

	rego.RegisterBuiltin1(&decl, ociImageIndex)

	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      "Fetch an Image Index from an OCI registry.",
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
}

func ociBlob(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	return ociBlobInternal(bctx, a, true)
}

func ociBlobInternal(bctx rego.BuiltinContext, a *ast.Term, verifyDigest bool) (*ast.Term, error) {
	logger := log.WithField("function", ociBlobName)

	uri, ok := a.Value.(ast.String)
	if !ok {
		logger.Error("input is not a string")
		return nil, nil
	}
	refStr := string(uri)
	logger = logger.WithField("ref", refStr)

	// Use component-scoped cache if available, otherwise fall back to global.
	// Blob data is heavy (1-10 MB each) and unique per component, so scoping
	// prevents unbounded memory growth across many components.
	cc := componentCacheFromContext(bctx.Context)

	// Check cache first (fast path)
	if cached, found := cc.blobCache.Load(refStr); found {
		logger.Debug("Blob served from cache")
		return cached.(*ast.Term), nil
	}

	// Use singleflight to prevent thundering herd - only one goroutine fetches per key
	result, err, _ := cc.blobFlight.Do(refStr, func() (any, error) {
		// Double-check cache inside singleflight (another goroutine may have populated it)
		if cached, found := cc.blobCache.Load(refStr); found {
			logger.Debug("Blob served from cache (after singleflight)")
			return cached, nil
		}
		logger.Debug("Starting blob retrieval")

		ref, err := name.NewDigest(refStr)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "new digest",
				"error":  err,
			}).Error("failed to create new digest")
			return nil, nil //nolint:nilerr // intentional: return nil to signal failure without OPA error
		}

		rawLayer, err := oci.NewClient(bctx.Context).Layer(ref)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "fetch layer",
				"error":  err,
			}).Error("failed to fetch OCI layer")
			return nil, nil //nolint:nilerr
		}

		layer, err := rawLayer.Uncompressed()
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "uncompress layer",
				"error":  err,
			}).Error("failed to uncompress OCI layer")
			return nil, nil //nolint:nilerr
		}
		defer layer.Close()

		// TODO: Other algorithms are technically supported, e.g. sha512. However, support for those is
		// not complete in the go-containerregistry library, e.g. name.NewDigest throws an error if
		// sha256 is not used. This is good for now, but may need revisiting later.
		hasher := sha256.New()
		reader := io.TeeReader(layer, hasher)

		var blob bytes.Buffer
		if _, err := io.Copy(&blob, reader); err != nil {
			logger.WithFields(log.Fields{
				"action": "copy buffer",
				"error":  err,
			}).Error("failed to copy data into buffer")
			return nil, nil //nolint:nilerr
		}

		// In the past we used io.LimitReader which might truncate the layer if it
		// exceeds its limit. The condition below catches this scenario in order
		// to avoid unexpected behavior caused by partial data being returned. We
		// don't actually use io.LimitReader here any more, but it seems like a
		// reasonable idea to keep this digest check anyhow. Todo: Consider if we
		// could/should remove the digest check entirely now.
		//
		// For ociBlobFiles, we skip the digest verification because there's a
		// good chance we'd be calculating the digest of the uncompressed layer
		// data which would not match. It might be possible to calculate the
		// checksum on the layer data before it is uncompressed, but I think
		// that's not as easy as it sounds, since it may require another
		// io.Copy which could be inefficient. For now let's just skip it.
		//
		expectedDigest := ref.DigestStr()
		if verifyDigest {
			computedDigest := fmt.Sprintf("sha256:%x", hasher.Sum(nil))
			if computedDigest != expectedDigest {
				logger.WithFields(log.Fields{
					"action":          "verify digest",
					"computed_digest": computedDigest,
					"expected_digest": expectedDigest,
				}).Error("computed digest does not match expected digest")
				return nil, nil
			}
		}

		logger.WithFields(log.Fields{
			"action": "complete",
			"digest": expectedDigest,
		}).Debug("Successfully retrieved blob")

		term := ast.StringTerm(blob.String())
		cc.blobCache.Store(refStr, term)
		return term, nil
	})

	if err != nil || result == nil {
		return nil, nil
	}
	return result.(*ast.Term), nil
}

func ociDescriptor(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociDescriptorName)

	uriValue, ok := a.Value.(ast.String)
	if !ok {
		logger.Error("input is not a string")
		return nil, nil
	}
	refStr := string(uriValue)
	logger = logger.WithField("input_ref", refStr)

	// Check cache first (fast path)
	if cached, found := descriptorCache.Load(refStr); found {
		logger.Debug("Descriptor served from cache")
		return cached.(*ast.Term), nil
	}

	// Use singleflight to prevent thundering herd
	result, err, _ := descriptorFlight.Do(refStr, func() (any, error) {
		// Double-check cache inside singleflight
		if cached, found := descriptorCache.Load(refStr); found {
			logger.Debug("Descriptor served from cache (after singleflight)")
			return cached, nil
		}
		logger.Debug("Starting descriptor retrieval")

		client := oci.NewClient(bctx.Context)

		uri, ref, err := resolveIfNeeded(client, refStr)
		if err != nil {
			logger.WithField("action", "resolveIfNeeded").Error(err)
			return nil, nil //nolint:nilerr
		}
		logger.WithField("ref", uri).Debug("Resolved reference")

		descriptor, err := client.Head(ref)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "fetch head",
				"error":  err,
			}).Error("failed to fetch image descriptor")
			return nil, nil //nolint:nilerr
		}

		logger.Debug("Successfully retrieved descriptor")
		term := newDescriptorTerm(*descriptor)
		descriptorCache.Store(refStr, term)
		return term, nil
	})

	if err != nil || result == nil {
		return nil, nil
	}
	return result.(*ast.Term), nil
}

func ociImageManifest(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociImageManifestName)

	uriValue, ok := a.Value.(ast.String)
	if !ok {
		logger.Error("input is not a string")
		return nil, nil
	}
	refStr := string(uriValue)
	logger = logger.WithField("input_ref", refStr)

	// Check cache first (fast path)
	if cached, found := manifestCache.Load(refStr); found {
		logger.Debug("Image manifest served from cache")
		return cached.(*ast.Term), nil
	}

	// Use singleflight to prevent thundering herd
	result, err, _ := manifestFlight.Do(refStr, func() (any, error) {
		// Double-check cache inside singleflight
		if cached, found := manifestCache.Load(refStr); found {
			logger.Debug("Image manifest served from cache (after singleflight)")
			return cached, nil
		}
		logger.Debug("Starting image manifest retrieval")

		client := oci.NewClient(bctx.Context)

		uri, ref, err := resolveIfNeeded(client, refStr)
		if err != nil {
			logger.WithField("action", "resolveIfNeeded").Error(err)
			return nil, nil //nolint:nilerr
		}
		logger.WithField("ref", uri).Debug("Resolved reference")

		var image v1.Image
		err = retry.OnError(retry.DefaultRetry, func(_ error) bool { return true }, func() error {
			image, err = client.Image(ref)
			return err
		})
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "fetch image",
				"error":  err,
			}).Error("failed to fetch image")
			return nil, nil //nolint:nilerr
		}

		manifest, err := image.Manifest()
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "fetch manifest",
				"error":  err,
			}).Error("failed to fetch manifest")
			return nil, nil //nolint:nilerr
		}

		if manifest == nil {
			logger.Error("manifest is nil")
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

		logger.Debug("Successfully retrieved image manifest")
		term := ast.ObjectTerm(manifestTerms...)
		manifestCache.Store(refStr, term)
		return term, nil
	})

	if err != nil || result == nil {
		return nil, nil
	}
	return result.(*ast.Term), nil
}

// manifestResult holds the result of fetching a single manifest
type manifestResult struct {
	ref      string
	manifest *ast.Term
}

// maxParallelManifestFetches limits concurrent manifest fetches to avoid overwhelming registries.
// Defaults to GOMAXPROCS * 4, which provides good parallelism while being respectful of resources.
var maxParallelManifestFetches = runtime.GOMAXPROCS(0) * 4

// Package-level caches for OCI operations.
// OPA's Memoize only works within a single Eval() call, but we validate multiple
// images in separate Eval() calls. These caches persist for the lifetime of the process.
//
// We use singleflight.Group alongside sync.Map to prevent thundering herd:
// - sync.Map stores the cached results
// - singleflight.Group ensures only one goroutine fetches a given key at a time
//
// Blob and imageFiles caches are component-scoped when a ComponentCache is present
// in the context (via WithComponentCache). This prevents unbounded memory growth
// when validating many components, since blob/imageFiles data is large and unique
// per component. defaultComponentCache serves as the fallback when no ComponentCache
// is set. Manifests, descriptors, and image indexes remain global because they are
// small and benefit from cross-component sharing (e.g., shared task bundle manifests).
var (
	defaultComponentCache = &ComponentCache{} // fallback for blob/imageFiles when no context cache

	descriptorCache  sync.Map // map[string]*ast.Term - for ociDescriptor (always global)
	descriptorFlight singleflight.Group
	manifestCache    sync.Map // map[string]*ast.Term - for ociImageManifest (always global)
	manifestFlight   singleflight.Group
	imageIndexCache  sync.Map // map[string]*ast.Term - for ociImageIndex (always global)
	imageIndexFlight singleflight.Group
)

// batchCallCounter tracks how many times ociImageManifestsBatch is called (for debugging)
var batchCallCounter uint64

// ClearCaches clears all package-level caches. This is primarily used for testing
// to ensure tests don't interfere with each other via cached values.
// Note: This only clears global caches. Component-scoped caches (blob, imageFiles)
// are automatically released when the component's context goes out of scope.
func ClearCaches() {
	defaultComponentCache = &ComponentCache{}
	descriptorCache = sync.Map{}
	manifestCache = sync.Map{}
	imageIndexCache = sync.Map{}
}

// ComponentCache holds per-component caches for heavy OCI data (blobs and image files).
// These are the two largest cache types — blobs can be 1-10 MB each, and image files
// can also be substantial. Scoping them per-component prevents unbounded memory growth
// when validating many components with unique image refs.
//
// Lighter caches (manifests, descriptors, image indexes) remain global because they
// are small and benefit from cross-component sharing (e.g., shared task bundle manifests).
type ComponentCache struct {
	blobCache        sync.Map
	blobFlight       singleflight.Group
	imageFilesCache  sync.Map
	imageFilesFlight singleflight.Group
}

type componentCacheKey struct{}

// WithComponentCache returns a new context with a fresh component-scoped cache.
// Use this to scope blob and image files caches to a single component evaluation.
// When the context goes out of scope, the cached data becomes eligible for GC.
func WithComponentCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, componentCacheKey{}, &ComponentCache{})
}

// componentCacheFromContext returns the ComponentCache from the context,
// falling back to the global default if none is set.
func componentCacheFromContext(ctx context.Context) *ComponentCache {
	if cc, ok := ctx.Value(componentCacheKey{}).(*ComponentCache); ok && cc != nil {
		return cc
	}
	return defaultComponentCache
}

func ociImageManifestsBatch(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	callNum := atomic.AddUint64(&batchCallCounter, 1)
	logger := log.WithField("function", ociImageManifestsBatchName)

	refsSet, err := builtins.SetOperand(a.Value, 1)
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "convert refs",
			"error":  err,
		}).Error("failed to convert refs to set operand")
		return nil, nil
	}

	// Collect all ref terms and check cache
	var uncachedTerms []*ast.Term
	cachedResults := make(map[string]*ast.Term)

	err = refsSet.Iter(func(refTerm *ast.Term) error {
		refStr, ok := refTerm.Value.(ast.String)
		if !ok {
			return fmt.Errorf("ref is not a string: %#v", refTerm)
		}
		ref := string(refStr)

		// Check cache first
		if cached, found := manifestCache.Load(ref); found {
			cachedResults[ref] = cached.(*ast.Term)
		} else {
			uncachedTerms = append(uncachedTerms, refTerm)
		}
		return nil
	})
	if err != nil {
		logger.WithFields(log.Fields{
			"action": "iterate refs",
			"error":  err,
		}).Error("failed iterating refs")
		return nil, nil
	}

	totalRefs := len(cachedResults) + len(uncachedTerms)
	logger.WithFields(log.Fields{
		"call_number":   callNum,
		"total_refs":    totalRefs,
		"cached_refs":   len(cachedResults),
		"uncached_refs": len(uncachedTerms),
		"concurrency":   maxParallelManifestFetches,
	}).Debug("Starting parallel image manifest retrieval with caching")

	if totalRefs == 0 {
		return ast.ObjectTerm(), nil
	}

	// Build result from cached entries
	resultTerms := make([][2]*ast.Term, 0, totalRefs)
	for ref, manifest := range cachedResults {
		resultTerms = append(resultTerms, ast.Item(ast.StringTerm(ref), manifest))
	}

	// If everything was cached, return early
	if len(uncachedTerms) == 0 {
		logger.WithField("success_count", len(resultTerms)).Debug("All manifests served from cache")
		return ast.ObjectTerm(resultTerms...), nil
	}

	// Fetch uncached refs in parallel
	g, ctx := errgroup.WithContext(bctx.Context)
	g.SetLimit(maxParallelManifestFetches)

	results := make(chan manifestResult, len(uncachedTerms))

	bctxWithCancel := rego.BuiltinContext{
		Context:  ctx,
		Cancel:   bctx.Cancel,
		Runtime:  bctx.Runtime,
		Time:     bctx.Time,
		Seed:     bctx.Seed,
		Metrics:  bctx.Metrics,
		Location: bctx.Location,
		Tracers:  bctx.Tracers,
	}

	for _, refTerm := range uncachedTerms {
		term := refTerm
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			ref := string(term.Value.(ast.String))
			manifest, err := ociImageManifest(bctxWithCancel, term)
			if err != nil {
				logger.WithFields(log.Fields{
					"ref":   ref,
					"error": err,
				}).Error("failed to fetch manifest in batch")
				results <- manifestResult{ref: ref, manifest: nil}
				return nil
			}

			// Store in cache (even nil results to avoid re-fetching failures)
			if manifest != nil {
				manifestCache.Store(ref, manifest)
			}

			results <- manifestResult{ref: ref, manifest: manifest}
			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(results)
	}()

	// Collect newly fetched results
	var mu sync.Mutex
	for result := range results {
		if result.manifest != nil {
			mu.Lock()
			resultTerms = append(resultTerms, ast.Item(ast.StringTerm(result.ref), result.manifest))
			mu.Unlock()
		}
	}

	logger.WithFields(log.Fields{
		"success_count": len(resultTerms),
		"from_cache":    len(cachedResults),
		"newly_fetched": len(resultTerms) - len(cachedResults),
	}).Debug("Completed parallel image manifest retrieval")

	return ast.ObjectTerm(resultTerms...), nil
}

func ociImageFiles(bctx rego.BuiltinContext, refTerm *ast.Term, pathsTerm *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociImageFilesName)

	uri, ok := refTerm.Value.(ast.String)
	if !ok {
		logger.Error("input ref is not a string")
		return nil, nil
	}
	refStr := string(uri)
	logger = logger.WithField("ref", refStr)

	if pathsTerm == nil {
		logger.Error("paths term is nil")
		return nil, nil
	}

	// Build cache key from ref + paths (hash the paths for a stable key)
	pathsHash := fmt.Sprintf("%x", sha256.Sum256([]byte(pathsTerm.String())))[:12]
	cacheKey := "image:" + refStr + ":" + pathsHash

	// Use component-scoped cache if available, otherwise fall back to global.
	// Image files data can be substantial and is unique per component.
	cc := componentCacheFromContext(bctx.Context)

	// Check cache first (fast path)
	if cached, found := cc.imageFilesCache.Load(cacheKey); found {
		logger.Debug("Image files served from cache")
		return cached.(*ast.Term), nil
	}

	// Use singleflight to prevent thundering herd
	result, err, _ := cc.imageFilesFlight.Do(cacheKey, func() (any, error) {
		// Double-check cache inside singleflight
		if cached, found := cc.imageFilesCache.Load(cacheKey); found {
			logger.Debug("Image files served from cache (after singleflight)")
			return cached, nil
		}
		logger.Debug("Starting image files extraction")

		ref, err := name.NewDigest(refStr)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "new digest",
				"error":  err,
			}).Error("failed to create new digest")
			return nil, nil //nolint:nilerr
		}

		pathsArray, err := builtins.ArrayOperand(pathsTerm.Value, 1)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "convert paths",
				"error":  err,
			}).Error("failed to convert paths to array operand")
			return nil, nil //nolint:nilerr
		}

		var extractors []files.Extractor
		err = pathsArray.Iter(func(pathTerm *ast.Term) error {
			pathString, ok := pathTerm.Value.(ast.String)
			if !ok {
				return fmt.Errorf("path is not a string: %#v", pathTerm)
			}
			extractors = append(extractors, files.PathExtractor{Path: string(pathString)})
			return nil
		})
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "iterate paths",
				"error":  err,
			}).Error("failed iterating paths")
			return nil, nil //nolint:nilerr
		}

		filesResult, err := files.ImageFiles(bctx.Context, ref, extractors)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "extract files",
				"error":  err,
			}).Error("failed to extract image files")
			return nil, nil //nolint:nilerr
		}

		filesValue, err := ast.InterfaceToValue(filesResult)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "convert files",
				"error":  err,
			}).Error("failed to convert files object to value")
			return nil, nil //nolint:nilerr
		}

		logger.Debug("Successfully extracted image files")
		term := ast.NewTerm(filesValue)
		cc.imageFilesCache.Store(cacheKey, term)
		return term, nil
	})

	if err != nil || result == nil {
		return nil, nil
	}
	return result.(*ast.Term), nil
}

func ociBlobFiles(bctx rego.BuiltinContext, refTerm *ast.Term, pathsTerm *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociBlobFilesName)

	uri, ok := refTerm.Value.(ast.String)
	if !ok {
		logger.Error("input ref is not a string")
		return nil, nil
	}
	refStr := string(uri)
	logger = logger.WithField("ref", refStr)

	if pathsTerm == nil {
		logger.Error("paths term is nil")
		return nil, nil
	}

	// Build cache key from ref + paths (hash the paths for a stable key)
	pathsHash := fmt.Sprintf("%x", sha256.Sum256([]byte(pathsTerm.String())))[:12]
	cacheKey := "blob:" + refStr + ":" + pathsHash

	// Use component-scoped cache if available, otherwise fall back to global.
	// Blob files data can be substantial and is unique per component.
	cc := componentCacheFromContext(bctx.Context)

	// Check cache first (fast path)
	if cached, found := cc.imageFilesCache.Load(cacheKey); found {
		logger.Debug("Blob files served from cache")
		return cached.(*ast.Term), nil
	}

	// Use singleflight to prevent thundering herd
	result, err, _ := cc.imageFilesFlight.Do(cacheKey, func() (any, error) {
		// Double-check cache inside singleflight
		if cached, found := cc.imageFilesCache.Load(cacheKey); found {
			logger.Debug("Blob files served from cache (after singleflight)")
			return cached, nil
		}
		logger.Debug("Starting blob files extraction")

		// Get the blob content first (skip digest verification due to compressed/uncompressed mismatch)
		blobTerm, err := ociBlobInternal(bctx, refTerm, false)
		if err != nil || blobTerm == nil {
			logger.WithFields(log.Fields{
				"action": "fetch blob",
				"error":  err,
			}).Error("failed to fetch blob content")
			return nil, nil //nolint:nilerr
		}

		blobContent, ok := blobTerm.Value.(ast.String)
		if !ok {
			logger.Error("blob content is not a string")
			return nil, nil
		}

		pathsArray, err := builtins.ArrayOperand(pathsTerm.Value, 1)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "convert paths",
				"error":  err,
			}).Error("failed to convert paths to array operand")
			return nil, nil //nolint:nilerr
		}

		// Collect target paths for exact file matching
		var targetPaths []string
		err = pathsArray.Iter(func(pathTerm *ast.Term) error {
			pathString, ok := pathTerm.Value.(ast.String)
			if !ok {
				return fmt.Errorf("path is not a string: %#v", pathTerm)
			}
			targetPaths = append(targetPaths, string(pathString))
			return nil
		})
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "iterate paths",
				"error":  err,
			}).Error("failed iterating paths")
			return nil, nil //nolint:nilerr
		}

		if len(targetPaths) == 0 {
			logger.Debug("No paths specified, returning empty result")
			term := ast.NewTerm(ast.NewObject())
			cc.imageFilesCache.Store(cacheKey, term)
			return term, nil
		}

		// Create a tar reader from the blob content
		blobReader := strings.NewReader(string(blobContent))
		archive := tar.NewReader(blobReader)

		// Create a set for fast lookup of target paths
		targetPathSet := make(map[string]bool)
		for _, path := range targetPaths {
			targetPathSet[path] = true
		}

		extractedFiles := map[string]json.RawMessage{}
		for {
			header, err := archive.Next()
			if err != nil {
				if err == io.EOF {
					break
				}
				logger.WithFields(log.Fields{
					"action": "read tar header",
					"error":  err,
				}).Error("failed to read tar archive")
				return nil, nil //nolint:nilerr
			}

			// Check if this file matches any of our target paths
			if !targetPathSet[header.Name] {
				continue
			}

			// Check if the file has a supported extension or is explicitly requested
			ext := path.Ext(header.Name)
			supportedExt := false
			for _, e := range []string{".yaml", ".yml", ".json"} {
				if strings.EqualFold(ext, e) {
					supportedExt = true
					break
				}
			}

			// If no supported extension, only process if file is explicitly in target paths
			// This allows processing files without extensions that contain structured data
			if !supportedExt {
				logger.WithField("file", header.Name).Debug("file has no supported extension, attempting to parse anyway since it was explicitly requested")
			}

			// Check file size to prevent memory exhaustion attacks
			if header.Size > maxTarEntrySize {
				logger.WithFields(log.Fields{
					"file":    header.Name,
					"size":    header.Size,
					"maxSize": maxTarEntrySize,
				}).Error("tar entry too large, skipping to prevent memory exhaustion")
				continue
			}

			// Read the file content with size limit protection
			limitedReader := io.LimitReader(archive, maxTarEntrySize)
			data, err := io.ReadAll(limitedReader)
			if err != nil {
				logger.WithFields(log.Fields{
					"action": "read file content",
					"file":   header.Name,
					"error":  err,
				}).Error("failed to read file content")
				return nil, nil //nolint:nilerr
			}

			// Verify we didn't hit the size limit (which would indicate truncation)
			if int64(len(data)) == maxTarEntrySize && header.Size > maxTarEntrySize {
				logger.WithFields(log.Fields{
					"file":    header.Name,
					"size":    header.Size,
					"maxSize": maxTarEntrySize,
				}).Error("tar entry was truncated due to size limit")
				continue
			}

			// Convert YAML to JSON if needed
			data, err = yaml.YAMLToJSON(data)
			if err != nil {
				logger.WithFields(log.Fields{
					"action": "convert to json",
					"file":   header.Name,
					"error":  err,
				}).Debug("unable to read file as JSON or YAML, ignoring")
				continue
			}

			extractedFiles[header.Name] = data
		}

		filesValue, err := ast.InterfaceToValue(extractedFiles)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "convert files",
				"error":  err,
			}).Error("failed to convert files object to value")
			return nil, nil //nolint:nilerr
		}

		logger.WithField("file_count", len(extractedFiles)).Debug("Successfully extracted blob files")
		term := ast.NewTerm(filesValue)
		cc.imageFilesCache.Store(cacheKey, term)
		return term, nil
	})

	if err != nil || result == nil {
		return nil, nil
	}
	return result.(*ast.Term), nil
}

func ociImageIndex(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	logger := log.WithField("function", ociImageIndexName)

	uriValue, ok := a.Value.(ast.String)
	if !ok {
		logger.Error("input is not a string")
		return nil, nil
	}
	refStr := string(uriValue)
	logger = logger.WithField("input_ref", refStr)

	// Check cache first (fast path)
	if cached, found := imageIndexCache.Load(refStr); found {
		logger.Debug("Image index served from cache")
		return cached.(*ast.Term), nil
	}

	// Use singleflight to prevent thundering herd
	result, err, _ := imageIndexFlight.Do(refStr, func() (any, error) {
		// Double-check cache inside singleflight
		if cached, found := imageIndexCache.Load(refStr); found {
			logger.Debug("Image index served from cache (after singleflight)")
			return cached, nil
		}
		logger.Debug("Starting image index retrieval")

		client := oci.NewClient(bctx.Context)

		uri, ref, err := resolveIfNeeded(client, refStr)
		if err != nil {
			logger.WithField("action", "resolveIfNeeded").Error(err)
			return nil, nil //nolint:nilerr
		}
		logger.WithField("ref", uri).Debug("Resolved reference")

		imageIndex, err := client.Index(ref)
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "fetch image index",
				"error":  err,
			}).Error("failed to fetch image index")
			return nil, nil //nolint:nilerr
		}

		indexManifest, err := imageIndex.IndexManifest()
		if err != nil {
			logger.WithFields(log.Fields{
				"action": "fetch index manifest",
				"error":  err,
			}).Error("failed to fetch index manifest")
			return nil, nil //nolint:nilerr
		}

		if indexManifest == nil {
			logger.Error("index manifest is nil")
			return nil, nil
		}

		manifestTerms := []*ast.Term{}
		for _, manifest := range indexManifest.Manifests {
			manifestTerms = append(manifestTerms, newDescriptorTerm(manifest))
		}

		imageIndexTerms := [][2]*ast.Term{
			ast.Item(ast.StringTerm("schemaVersion"), ast.NumberTerm(json.Number(fmt.Sprintf("%d", indexManifest.SchemaVersion)))),
			ast.Item(ast.StringTerm("mediaType"), ast.StringTerm(string(indexManifest.MediaType))),
			ast.Item(ast.StringTerm("manifests"), ast.ArrayTerm(manifestTerms...)),
			ast.Item(ast.StringTerm("annotations"), newAnnotationsTerm(indexManifest.Annotations)),
		}

		if s := indexManifest.Subject; s != nil {
			imageIndexTerms = append(imageIndexTerms, ast.Item(ast.StringTerm("subject"), newDescriptorTerm(*s)))
		}

		logger.Debug("Successfully retrieved image index")
		term := ast.ObjectTerm(imageIndexTerms...)
		imageIndexCache.Store(refStr, term)
		return term, nil
	})

	if err != nil || result == nil {
		return nil, nil
	}
	return result.(*ast.Term), nil
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

func resolveIfNeeded(client oci.Client, uri string) (string, name.Reference, error) {
	ref, err := parseReference(uri)
	if err != nil {
		return "", nil, fmt.Errorf("unable to parse reference: %w", err)
	}

	// If it's already a digest reference, return as is
	if _, ok := ref.(name.Digest); ok {
		return uri, ref, nil
	}

	// For tag references, resolve to digest
	digest, err := client.ResolveDigest(ref)
	if err != nil {
		return "", nil, fmt.Errorf("unable to resolve digest: %w", err)
	}

	resolved := fmt.Sprintf("%s@%s", uri, digest)
	log.Debugf("resolved image reference %q to %q", uri, resolved)
	return resolved, ref, nil
}

func parseReference(uri string) (name.Reference, error) {
	// Try to parse as digest first, if that fails with ErrBadName, try as tag
	ref, err := name.NewDigest(uri)
	if err != nil {
		if errors.Is(err, &name.ErrBadName{}) {
			tag, err := name.NewTag(uri)
			if err != nil {
				return nil, fmt.Errorf("invalid reference format: %w", err)
			}
			return tag, nil
		} else {
			return nil, fmt.Errorf("invalid digest format: %w", err)
		}
	}
	return ref, nil
}

func init() {
	registerOCIBlob()
	registerOCIBlobFiles()
	registerOCIDescriptor()
	registerOCIImageFiles()
	registerOCIImageManifest()
	registerOCIImageManifestsBatch()
	registerOCIImageIndex()
}
