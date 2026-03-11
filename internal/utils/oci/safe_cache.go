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

package oci

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/singleflight"
)

// cachePath returns the filesystem path for a cached layer by hash.
// Matches go-containerregistry pkg/v1/cache layout for compatibility.
func cachePath(basePath string, h v1.Hash) string {
	var file string
	if runtime.GOOS == "windows" {
		file = fmt.Sprintf("%s-%s", h.Algorithm, h.Hex)
	} else {
		file = h.String()
	}
	return filepath.Join(basePath, file)
}

// safeCache wraps a cache.Cache so that concurrent access to the same layer
// (same digest or diffID) is serialized. This prevents races when multiple
// goroutines validate images that share layers (e.g. same base image).
// See https://github.com/conforma/cli/issues/1109.
type safeCache struct {
	inner     cache.Cache
	path      string
	putFlight singleflight.Group
}

// NewSafeCache returns a cache.Cache that delegates to inner but ensures
// only one goroutine populates a given digest at a time. basePath must be
// the same path used by the inner filesystem cache so that written files
// are found by Get.
func NewSafeCache(inner cache.Cache, basePath string) cache.Cache {
	if inner == nil {
		return nil
	}
	return &safeCache{inner: inner, path: basePath}
}

// Get implements cache.Cache. Successful results are wrapped in safeLayer so
// Compressed()/Uncompressed() use the same stream serialization as layers from Put.
func (s *safeCache) Get(h v1.Hash) (v1.Layer, error) {
	layer, err := s.inner.Get(h)
	if err != nil {
		return nil, err
	}
	return &safeLayer{inner: layer, path: s.path, flight: &s.putFlight}, nil
}

// Put implements cache.Cache. Only one goroutine runs inner.Put for a given
// digest; others wait and receive the same result. The returned layer is
// wrapped so that Compressed() and Uncompressed() are also singleflighted,
// ensuring only one writer fills each cache file.
func (s *safeCache) Put(l v1.Layer) (v1.Layer, error) {
	digest, err := l.Digest()
	if err != nil {
		return nil, err
	}
	v, err, _ := s.putFlight.Do(digest.String(), func() (any, error) {
		layer, err := s.inner.Get(digest)
		if err == nil {
			return &safeLayer{inner: layer, path: s.path, flight: &s.putFlight}, nil
		}
		if !errors.Is(err, cache.ErrNotFound) {
			return nil, err
		}
		layer, err = s.inner.Put(l)
		if err != nil {
			return nil, err
		}
		return &safeLayer{inner: layer, path: s.path, flight: &s.putFlight}, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(v1.Layer), nil
}

// Delete implements cache.Cache.
func (s *safeCache) Delete(h v1.Hash) error {
	return s.inner.Delete(h)
}

// safeLayer wraps a layer that may write to the cache on first read.
// Compressed() and Uncompressed() use digest-scoped singleflight so only one
// goroutine runs the inner stream per digest (across all safeLayer instances,
// e.g. from concurrent Get(digest) callers). Waiters block until the cache file
// is ready, then open it—no dependency on the first caller closing a reader,
// avoiding deadlock and cross-instance races.
type safeLayer struct {
	inner  v1.Layer
	path   string
	flight *singleflight.Group
}

func (l *safeLayer) Digest() (v1.Hash, error)            { return l.inner.Digest() }
func (l *safeLayer) DiffID() (v1.Hash, error)            { return l.inner.DiffID() }
func (l *safeLayer) Size() (int64, error)                { return l.inner.Size() }
func (l *safeLayer) MediaType() (types.MediaType, error) { return l.inner.MediaType() }

// Compressed returns a reader for the layer's compressed bytes. If the layer is
// already cached on disk (by digest), it opens and returns that file. Otherwise
// it uses singleflight so only one goroutine calls the inner Compressed(),
// drains the stream synchronously (allowing the inner cache to write the file),
// and returns only after the file is written; all callers then open the file.
// Errors from the drain or Close are propagated.
func (l *safeLayer) Compressed() (io.ReadCloser, error) {
	digest, err := l.inner.Digest()
	if err != nil {
		return nil, err
	}
	path := cachePath(l.path, digest)
	if _, err := os.Stat(path); err == nil {
		return os.Open(path)
	}
	// Only one goroutine runs the inner work; others block on the same key.
	key := "compressed:" + digest.String()
	_, err, _ = l.flight.Do(key, func() (any, error) {
		rc, err := l.inner.Compressed()
		if err != nil {
			return nil, err
		}
		// Drain synchronously so the inner cache writes the file before we return.
		if _, err := io.Copy(io.Discard, rc); err != nil {
			_ = rc.Close()
			return nil, err
		}
		if err := rc.Close(); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

// Uncompressed returns a reader for the layer's uncompressed bytes. Same pattern
// as Compressed but uses diffID for the cache path and singleflight key, since
// uncompressed content is keyed by diffID rather than digest.
func (l *safeLayer) Uncompressed() (io.ReadCloser, error) {
	diffID, err := l.inner.DiffID()
	if err != nil {
		return nil, err
	}
	path := cachePath(l.path, diffID)
	if _, err := os.Stat(path); err == nil {
		return os.Open(path)
	}
	// Only one goroutine runs the inner work; others block on the same key.
	key := "uncompressed:" + diffID.String()
	_, err, _ = l.flight.Do(key, func() (any, error) {
		rc, err := l.inner.Uncompressed()
		if err != nil {
			return nil, err
		}
		// Drain synchronously so the inner cache writes the file before we return.
		if _, err := io.Copy(io.Discard, rc); err != nil {
			_ = rc.Close()
			return nil, err
		}
		if err := rc.Close(); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}
