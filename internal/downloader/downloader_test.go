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

package downloader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"regexp"
	"runtime/trace"
	"sync"
	"testing"

	ghttp "github.com/conforma/go-gather/gather/http"
	goci "github.com/conforma/go-gather/gather/oci"
	"github.com/conforma/go-gather/metadata"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	xtrace "golang.org/x/exp/trace"
	"oras.land/oras-go/v2/registry/remote/retry"

	echttp "github.com/conforma/cli/internal/http"
)

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(ctx context.Context, dest string, sourceUrls []string) error {
	args := m.Called(ctx, dest, sourceUrls)

	return args.Error(0)
}

func TestDownloader_Download(t *testing.T) {
	tests := []struct {
		name        string
		dest        string
		source      string
		errExpected bool
		err         error
	}{
		{
			name:   "Downloads",
			dest:   "dir",
			source: "https://example.com/org/repo.git",
		},
		{
			name:        "Fails to download",
			dest:        "dir",
			source:      "https://example.com/org/repo.git",
			errExpected: true,
			err:         errors.New("expected error"),
		},
		{
			name:        "insecure download",
			dest:        "dir",
			source:      "http://example.com/org/repo.git",
			errExpected: true,
			err:         errors.New("attempting to download from insecure source: http://example.com/org/repo.git"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := mockDownloader{}
			ctx := WithDownloadImpl(context.TODO(), &d)

			originalGatherFunction := gatherFunc
			defer func() {
				gatherFunc = originalGatherFunction
			}()

			gatherFunc = func(_ context.Context, _ string, _ string) (metadata.Metadata, error) {
				return nil, tt.err
			}

			_, err := Download(ctx, tt.dest, tt.source, false)

			if tt.errExpected {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				mock.AssertExpectationsForObjects(t, &d)
			}
		})
	}
}

func TestIsSecure(t *testing.T) {
	secure := []string{
		"./foo",
		"github.com/mitchellh/vagrant",
		"gitlab.com/inkscape/inkscape",
		"bitbucket.org/mitchellh/vagrant",
		"git::https://github.com/mitchellh/vagrant.git",
		"git::ssh://git@example.com/foo/bar",
		"git::git@example.com/foo/bar",
		"https://Aladdin:OpenSesame@www.example.com/index.html", // gitleaks:allow
		"s3::https://s3.amazonaws.com/bucket/foo",
		"s3::https://s3-eu-west-1.amazonaws.com/bucket/foo",
		"bucket.s3.amazonaws.com/foo",
		"bucket.s3-eu-west-1.amazonaws.com/foo/bar",
		"gcs::https://www.googleapis.com/storage/v1/bucket",
		"gcs::https://www.googleapis.com/storage/v1/bucket/foo.zip",
		"www.googleapis.com/storage/v1/bucket/foo",
		"oci::registry.io/repository/image:tag",
	}

	for _, u := range secure {
		assert.True(t, isSecure(u), `Expecting isSecure("%s") = true, but it was false`, u)
	}

	insecure := []string{
		"http://example.com",
		"git::http://github.com/org/repository",
		"hg::http://github.com/org/repository",
		"http::http://github.com/org/repository",
		"s3::http://127.0.0.1:9000/test-bucket/hello.txt?aws_access_key_id=KEYID&aws_access_key_secret=SECRETKEY&region=us-east-2",
	}

	for _, u := range insecure {
		assert.False(t, isSecure(u), `Expecting isSecure("%s") = false, but it was true`, u)
	}
}

func TestOCITracing(t *testing.T) {
	traceOutput := bytes.Buffer{}
	require.NoError(t, trace.Start(&traceOutput))
	t.Cleanup(trace.Stop)

	log.Level = logrus.TraceLevel
	t.Cleanup(func() {
		log.Level = logrus.InfoLevel
		initialize = sync.OnceFunc(_initialize)
		ociGatherer = nil
		httpGatherer = nil
	})
	registry := httptest.NewServer(registry.New())
	t.Cleanup(registry.Close)

	u, err := url.Parse(registry.URL)
	require.NoError(t, err)

	ref, err := name.ParseReference(fmt.Sprintf("localhost:%s/repository/image:tag", u.Port()))
	require.NoError(t, err)

	img, err := random.Image(4096, 2)
	require.NoError(t, err)
	require.NoError(t, remote.Push(ref, img))

	// Initialize directly then call ociGatherer.Gather to test the OCI
	// tracing path. Bare localhost refs fall through to the registry's
	// default gatherer (no tracing), so we invoke the gatherer directly.
	_initialize()

	_, err = ociGatherer.Gather(context.Background(), ref.String(), t.TempDir())
	require.NoError(t, err)

	trace.Stop()

	traceReader, err := xtrace.NewReader(&traceOutput)
	require.NoError(t, err)

	logs := []xtrace.Log{}
	for err == nil {
		var e xtrace.Event
		e, err = traceReader.ReadEvent()
		if err == nil && e.Kind() == xtrace.EventLog {
			logs = append(logs, e.Log())
		}
	}
	assert.NotZero(t, len(logs))

	expected := regexp.MustCompile(`^(method="GET")|(?:url="` + registry.URL + `(/v2/repository/image/manifests/tag|/v2/repository/image/blobs/sha256:[0-9a-f]{64})")|(received=\d+)$`)

	found := 0
	for _, l := range logs {
		assert.Regexp(t, expected, l.Message)
		found++
	}

	// 12 log messages for 4 requests, 3 per request
	assert.Equal(t, 12, found)
}

func TestHTTPTracing(t *testing.T) {
	traceOutput := bytes.Buffer{}
	require.NoError(t, trace.Start(&traceOutput))
	t.Cleanup(trace.Stop)

	log.Level = logrus.TraceLevel
	initialize = _initialize
	t.Cleanup(func() {
		log.Level = logrus.InfoLevel
		initialize = sync.OnceFunc(_initialize)
		ociGatherer = nil
		httpGatherer = nil
	})
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, fmt.Sprintf("%s %s", r.Method, r.URL))
		fmt.Fprintln(w, "body")
	}))
	t.Cleanup(server.Close)

	_, err := gatherFunc(context.Background(), fmt.Sprintf("%s/foo", server.URL), path.Join(t.TempDir(), "dl"))
	require.NoError(t, err)

	trace.Stop()

	traceReader, err := xtrace.NewReader(&traceOutput)
	require.NoError(t, err)

	logs := []xtrace.Log{}
	for err == nil {
		var e xtrace.Event
		e, err = traceReader.ReadEvent()
		if err == nil && e.Kind() == xtrace.EventLog {
			logs = append(logs, e.Log())
		}
	}
	assert.NotZero(t, len(logs))

	assert.Equal(t, []string{"GET /foo"}, requests)

	expected := regexp.MustCompile(`^(method="GET")|(?:url="` + fmt.Sprintf("%s/foo", server.URL) + `")|(received=\d+)$`)

	found := 0
	for _, l := range logs {
		assert.Regexp(t, expected, l.Message)
		found++
	}

	// 3 log messages per request
	assert.Equal(t, 3, found)
}

// TestOCIClientConfiguration verifies _initialize constructs an OCI gatherer.
// OCIGatherer.transport is unexported, so we cannot verify the retry transport
// directly (unlike TestHTTPClientConfiguration). TestOCITracing provides
// integration-level verification that the transport stack is wired correctly.
func TestOCIClientConfiguration(t *testing.T) {
	t.Cleanup(func() {
		ociGatherer = nil
		httpGatherer = nil
	})

	_initialize()

	assert.IsType(t, &goci.OCIGatherer{}, ociGatherer)
}

func TestHTTPClientConfiguration(t *testing.T) {
	defaultMaxRetry := echttp.DefaultRetry.MaxRetry
	t.Cleanup(func() {
		echttp.DefaultRetry.MaxRetry = defaultMaxRetry
		ociGatherer = nil
		httpGatherer = nil
	})
	echttp.DefaultRetry.MaxRetry = rand.Int() //nolint:gosec // G404 - no need for a secure random here

	_initialize()

	require.IsType(t, &ghttp.HTTPGatherer{}, httpGatherer)
	assert.IsType(t, &retry.Transport{}, httpGatherer.Client.Transport)

	transport := httpGatherer.Client.Transport.(*retry.Transport)
	assert.Equal(t, echttp.DefaultRetry.MaxRetry, transport.Policy().(*retry.GenericPolicy).MaxRetry)
}
