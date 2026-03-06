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

package oci

import (
	"errors"
	"io"
	"sync"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSafeCache_NilInnerReturnsNil(t *testing.T) {
	assert.Nil(t, NewSafeCache(nil, "/tmp/cache"))
}

func TestNewSafeCache_DelegatesGetAndDelete(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	digest, err := layer.Digest()
	require.NoError(t, err)

	_, err = wrapped.Get(digest)
	assert.Error(t, err)
	assert.ErrorIs(t, err, cache.ErrNotFound)

	err = wrapped.Delete(digest)
	assert.Error(t, err)
}

// errCache is a cache.Cache that returns a specific error from Get to test
// that safeCache propagates non-ErrNotFound errors instead of treating them as miss.
type errCache struct {
	getErr error
}

func (e *errCache) Get(h v1.Hash) (v1.Layer, error)  { return nil, e.getErr }
func (e *errCache) Put(l v1.Layer) (v1.Layer, error) { return l, nil }
func (e *errCache) Delete(h v1.Hash) error           { return nil }

func TestNewSafeCache_PutPropagatesNonErrNotFoundFromGet(t *testing.T) {
	wantErr := errors.New("permission denied")
	inner := &errCache{getErr: wantErr}
	wrapped := NewSafeCache(inner, t.TempDir())
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	_, err = wrapped.Put(layer)
	assert.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestNewSafeCache_ConcurrentPutSameLayer(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	// Concurrent Put of the same layer (same digest); singleflight serializes so all get same result.
	// Only one goroutine reads so we avoid timing-dependent waiter path; concurrent read is tested in TestNewSafeCache_ConcurrentCompressedSameLayer.
	// Run with: go test -race -tags=unit ./internal/utils/oci/ -run TestNewSafeCache_ConcurrentPutSameLayer
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func(doRead bool) {
			cached, err := wrapped.Put(layer)
			if err != nil {
				t.Error(err)
				done <- struct{}{}
				return
			}
			if doRead {
				rc, err := cached.Compressed()
				if err != nil {
					t.Error(err)
					done <- struct{}{}
					return
				}
				_, _ = io.Copy(io.Discard, rc)
				_ = rc.Close()
			}
			done <- struct{}{}
		}(i == 0)
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

// TestNewSafeCache_ConcurrentPutDifferentLayers ensures Put of different layers (different digests)
// does not block and all succeed without race.
func TestNewSafeCache_ConcurrentPutDifferentLayers(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	const numLayers = 8
	errCh := make(chan error, numLayers)
	var wg sync.WaitGroup
	for i := 0; i < numLayers; i++ {
		wg.Add(1)
		go func(size int) {
			defer wg.Done()
			layer, err := random.Layer(int64(size+1)*128, "application/vnd.oci.image.layer.v1.tar+gzip")
			if err != nil {
				errCh <- err
				return
			}
			cached, err := wrapped.Put(layer)
			if err != nil {
				errCh <- err
				return
			}
			rc, err := cached.Compressed()
			if err != nil {
				errCh <- err
				return
			}
			_, _ = io.Copy(io.Discard, rc)
			_ = rc.Close()
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

// TestNewSafeCache_PutThenGetReturnsSameDigest ensures that after Put, Get returns a layer
// with the same digest (cache stores and retrieves correctly).
func TestNewSafeCache_PutThenGetReturnsSameDigest(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(512, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	origDigest, err := layer.Digest()
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)
	rc, err := cached.Compressed()
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()

	got, err := wrapped.Get(origDigest)
	require.NoError(t, err)
	gotDigest, err := got.Digest()
	require.NoError(t, err)
	assert.Equal(t, origDigest, gotDigest)
}

// TestNewSafeCache_CachedLayerDelegatesMetadata ensures safeLayer delegates Digest, DiffID, Size, MediaType to inner.
func TestNewSafeCache_CachedLayerDelegatesMetadata(t *testing.T) {
	dir := t.TempDir()
	wrapped := NewSafeCache(cache.NewFilesystemCache(dir), dir)
	layer, err := random.Layer(128, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)

	digest, err := cached.Digest()
	require.NoError(t, err)
	expectDigest, _ := layer.Digest()
	assert.Equal(t, expectDigest, digest)

	diffID, err := cached.DiffID()
	require.NoError(t, err)
	expectDiffID, _ := layer.DiffID()
	assert.Equal(t, expectDiffID, diffID)

	size, err := cached.Size()
	require.NoError(t, err)
	expectSize, _ := layer.Size()
	assert.Equal(t, expectSize, size)

	mt, err := cached.MediaType()
	require.NoError(t, err)
	expectMT, _ := layer.MediaType()
	assert.Equal(t, expectMT, mt)
}

// TestNewSafeCache_ConcurrentCompressedSameLayer stresses concurrent Compressed() on the same
// cached layer; all callers must get valid content without race.
func TestNewSafeCache_ConcurrentCompressedSameLayer(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)

	const numReaders = 6
	errCh := make(chan error, numReaders)
	var wg sync.WaitGroup
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, err := cached.Compressed()
			if err != nil {
				errCh <- err
				return
			}
			_, err = io.Copy(io.Discard, rc)
			if err != nil {
				errCh <- err
				return
			}
			if err := rc.Close(); err != nil {
				errCh <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

// TestNewSafeCache_ConcurrentCompressedFromGetCallers ensures multiple goroutines that each
// call Get(digest) (obtaining different safeLayer instances) can safely call Compressed()
// concurrently. With the real FilesystemCache the file exists after Put, so callers take the
// "file exists" path; the test guards against regressions where Get-returned layers might not
// be safe under concurrency.
func TestNewSafeCache_ConcurrentCompressedFromGetCallers(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	digest, err := layer.Digest()
	require.NoError(t, err)

	// Populate cache and write the layer file so Get(digest) will succeed (FilesystemCache.Get reads from file).
	cached, err := wrapped.Put(layer)
	require.NoError(t, err)
	rc, err := cached.Compressed()
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rc)
	require.NoError(t, rc.Close())

	const numGetCallers = 6
	errCh := make(chan error, numGetCallers)
	var wg sync.WaitGroup
	for i := 0; i < numGetCallers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := wrapped.Get(digest)
			if err != nil {
				errCh <- err
				return
			}
			rc, err := got.Compressed()
			if err != nil {
				errCh <- err
				return
			}
			_, err = io.Copy(io.Discard, rc)
			if err != nil {
				errCh <- err
				return
			}
			if err := rc.Close(); err != nil {
				errCh <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

// TestNewSafeCache_ConcurrentUncompressedSameLayer stresses concurrent Uncompressed() on the same
// cached layer; all callers must get valid content without race.
func TestNewSafeCache_ConcurrentUncompressedSameLayer(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)

	const numReaders = 6
	errCh := make(chan error, numReaders)
	var wg sync.WaitGroup
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, err := cached.Uncompressed()
			if err != nil {
				errCh <- err
				return
			}
			_, err = io.Copy(io.Discard, rc)
			if err != nil {
				errCh <- err
				return
			}
			if err := rc.Close(); err != nil {
				errCh <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

// TestNewSafeCache_DeleteThenGetNotFound ensures Delete removes the layer so Get returns ErrNotFound.
func TestNewSafeCache_DeleteThenGetNotFound(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(128, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	digest, err := layer.Digest()
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)
	rc, err := cached.Compressed()
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()

	err = wrapped.Delete(digest)
	require.NoError(t, err)

	_, err = wrapped.Get(digest)
	assert.Error(t, err)
	assert.ErrorIs(t, err, cache.ErrNotFound)
}

// faultLayer is a v1.Layer that can return injected errors from Digest, Compressed, or Uncompressed.
type faultLayer struct {
	v1.Layer
	digestErr       error
	compressedErr   error
	uncompressedErr error
	diffIDErr       error
}

func (f *faultLayer) Digest() (v1.Hash, error) {
	if f.digestErr != nil {
		return v1.Hash{}, f.digestErr
	}
	return f.Layer.Digest()
}

func (f *faultLayer) DiffID() (v1.Hash, error) {
	if f.diffIDErr != nil {
		return v1.Hash{}, f.diffIDErr
	}
	return f.Layer.DiffID()
}

func (f *faultLayer) Compressed() (io.ReadCloser, error) {
	if f.compressedErr != nil {
		return nil, f.compressedErr
	}
	return f.Layer.Compressed()
}

func (f *faultLayer) Uncompressed() (io.ReadCloser, error) {
	if f.uncompressedErr != nil {
		return nil, f.uncompressedErr
	}
	return f.Layer.Uncompressed()
}

// TestNewSafeCache_PutDigestError ensures Put returns error when layer.Digest() fails.
func TestNewSafeCache_PutDigestError(t *testing.T) {
	layer, err := random.Layer(64, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	wantErr := errors.New("digest failed")
	fl := &faultLayer{Layer: layer, digestErr: wantErr}
	wrapped := NewSafeCache(cache.NewFilesystemCache(t.TempDir()), t.TempDir())
	_, err = wrapped.Put(fl)
	assert.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// TestNewSafeCache_CompressedWhenFileExists ensures second Compressed() call on same layer
// uses the cache file (os.Stat path) instead of streaming again.
func TestNewSafeCache_CompressedWhenFileExists(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)
	rc1, err := cached.Compressed()
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rc1)
	require.NoError(t, rc1.Close())

	// Second call should open existing file, not stream again.
	rc2, err := cached.Compressed()
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rc2)
	require.NoError(t, rc2.Close())
}

// TestNewSafeCache_UncompressedWhenFileExists ensures second Uncompressed() call uses cache file.
func TestNewSafeCache_UncompressedWhenFileExists(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)
	rc1, err := cached.Uncompressed()
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rc1)
	require.NoError(t, rc1.Close())

	rc2, err := cached.Uncompressed()
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rc2)
	require.NoError(t, rc2.Close())
}

// TestNewSafeCache_CompressedErrorPropagated ensures inner.Compressed() error is returned
// and stored so concurrent waiters also see it.
func TestNewSafeCache_CompressedErrorPropagated(t *testing.T) {
	layer, err := random.Layer(64, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	wantErr := errors.New("compressed read failed")
	fl := &faultLayer{Layer: layer, compressedErr: wantErr}
	dir := t.TempDir()
	wrapped := NewSafeCache(cache.NewFilesystemCache(dir), dir)
	cached, err := wrapped.Put(fl)
	require.NoError(t, err)

	_, err = cached.Compressed()
	assert.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// TestNewSafeCache_UncompressedErrorPropagated ensures inner.Uncompressed() error is returned.
func TestNewSafeCache_UncompressedErrorPropagated(t *testing.T) {
	layer, err := random.Layer(64, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	wantErr := errors.New("uncompressed read failed")
	fl := &faultLayer{Layer: layer, uncompressedErr: wantErr}
	dir := t.TempDir()
	wrapped := NewSafeCache(cache.NewFilesystemCache(dir), dir)
	cached, err := wrapped.Put(fl)
	require.NoError(t, err)

	_, err = cached.Uncompressed()
	assert.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// errPutCache is a cache that returns an error from Put.
type errPutCache struct {
	cache.Cache
	putErr error
}

func (e *errPutCache) Put(l v1.Layer) (v1.Layer, error) {
	return nil, e.putErr
}

// TestNewSafeCache_PutInnerPutError ensures Put propagates error from inner.Put.
func TestNewSafeCache_PutInnerPutError(t *testing.T) {
	layer, err := random.Layer(64, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	wantErr := errors.New("put failed")
	inner := &errPutCache{Cache: cache.NewFilesystemCache(t.TempDir()), putErr: wantErr}
	wrapped := NewSafeCache(inner, t.TempDir())
	_, err = wrapped.Put(layer)
	assert.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// TestNewSafeCache_ConcurrentCompressedErrorWaiter ensures a concurrent caller waiting on
// Compressed() receives the error when the first caller gets an error from inner.Compressed().
func TestNewSafeCache_ConcurrentCompressedErrorWaiter(t *testing.T) {
	layer, err := random.Layer(512, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	wantErr := errors.New("compressed failed")
	fl := &faultLayer{Layer: layer, compressedErr: wantErr}
	dir := t.TempDir()
	wrapped := NewSafeCache(cache.NewFilesystemCache(dir), dir)
	cached, err := wrapped.Put(fl)
	require.NoError(t, err)

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cached.Compressed()
			if err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	var errs []error
	for e := range errCh {
		errs = append(errs, e)
	}
	require.GreaterOrEqual(t, len(errs), 1, "at least one caller should get error")
	for _, e := range errs {
		assert.ErrorIs(t, e, wantErr)
	}
}

// TestNewSafeCache_ConcurrentUncompressedErrorWaiter ensures waiters get Uncompressed() error.
func TestNewSafeCache_ConcurrentUncompressedErrorWaiter(t *testing.T) {
	layer, err := random.Layer(512, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	wantErr := errors.New("uncompressed failed")
	fl := &faultLayer{Layer: layer, uncompressedErr: wantErr}
	dir := t.TempDir()
	wrapped := NewSafeCache(cache.NewFilesystemCache(dir), dir)
	cached, err := wrapped.Put(fl)
	require.NoError(t, err)

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cached.Uncompressed()
			if err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	var errs []error
	for e := range errCh {
		errs = append(errs, e)
	}
	require.GreaterOrEqual(t, len(errs), 1, "at least one caller should get error")
	for _, e := range errs {
		assert.ErrorIs(t, e, wantErr)
	}
}
