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

package downloader

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	ghttp "github.com/conforma/go-gather/gather/http"
	goci "github.com/conforma/go-gather/gather/oci"
	"github.com/conforma/go-gather/metadata"
	"github.com/conforma/go-gather/registry"
	"github.com/sirupsen/logrus"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/conforma/cli/internal/http"
)

type key int

const downloadImplKey key = 0

type downloadImpl interface {
	Download(context.Context, string, []string) error
}

var log = logrus.StandardLogger()

var gatherFunc = func(ctx context.Context, source, destination string) (metadata.Metadata, error) {
	initialize()
	g, err := registry.GetGatherer(source)
	if err != nil {
		return nil, err
	}
	return g.Gather(ctx, source, destination)
}

var _initialize = func() {
	if log.IsLevelEnabled(logrus.TraceLevel) {
		goci.Transport = http.NewTracingRoundTripperWithLogger(goci.Transport)
		ghttp.Transport = http.NewTracingRoundTripperWithLogger(ghttp.Transport)
	}

	backoff := retry.ExponentialBackoff(http.DefaultBackoff.Duration, http.DefaultBackoff.Factor, http.DefaultBackoff.Jitter)
	policy := &retry.GenericPolicy{
		Retryable: retry.DefaultPredicate,
		Backoff:   backoff,
		MaxWait:   http.DefaultRetry.MaxWait,
		MaxRetry:  http.DefaultRetry.MaxRetry,
	}
	policyfn := func() retry.Policy {
		return policy
	}

	ociTransport := retry.NewTransport(goci.Transport)
	ociTransport.Policy = policyfn
	goci.Transport = ociTransport

	httpTransport := retry.NewTransport(ghttp.Transport)
	httpTransport.Policy = policyfn
	ghttp.Transport = httpTransport
}

var initialize = sync.OnceFunc(_initialize)

// WithDownloadImpl replaces the downloadImpl implementation used
func WithDownloadImpl(ctx context.Context, d downloadImpl) context.Context {
	return context.WithValue(ctx, downloadImplKey, d)
}

// Download is used to download files from various sources.
func Download(ctx context.Context, destDir string, sourceUrl string, showMsg bool) (metadata.Metadata, error) {
	if !isSecure(sourceUrl) {
		return nil, fmt.Errorf("attempting to download from insecure source: %s", sourceUrl)
	}

	msg := fmt.Sprintf("Downloading %s to %s", sourceUrl, destDir)
	log.Debug(msg)
	if showMsg {
		fmt.Println(msg)
	}

	m, err := gatherFunc(ctx, sourceUrl, destDir)
	if err != nil {
		log.Debug("Download failed!")
	}
	return m, err
}

// matches insecure protocols, such as `git::http://...`
var insecure = regexp.MustCompile("^[A-Za-z0-9]*::http:")

// isSecure returns true if the provided url is using network transport security
// if provided to Conftest downloader. The Conftest downloader supports the
// following protocols:
//   - file  -- deemed secure as it is not accessing over network
//   - git   -- deemed secure if plaintext HTTP is not used
//   - gcs   -- always uses HTTP+TLS
//   - hg    -- deemed secure if plaintext HTTP is not used
//   - s3    -- deemed secure if plaintext HTTP is not used
//   - oci   -- always uses HTTP+TLS
//   - http  -- not deemed secure
//   - https -- deemed secure
func isSecure(url string) bool {
	return !strings.HasPrefix(url, "http:") && !insecure.MatchString(url)
}
