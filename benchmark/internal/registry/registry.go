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
//type Closer func()
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/smarty/cproxy/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/registry"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/conforma/cli/benchmark/internal/suite"
)

//go:embed fake_quay.cer
var certificate []byte

//go:embed fake_quay.key
var key []byte

type registryCloser struct {
	tempDir   string
	container *registry.RegistryContainer
	proxy     *httptest.Server
}

func (r *registryCloser) Close() {
	if r == nil {
		return
	}

	if r.tempDir != "" {
		_ = os.RemoveAll(r.tempDir)
	}

	if r.container != nil {
		_ = r.container.Terminate(context.Background())
	}

	if r.proxy != nil {
		r.proxy.Close()
	}
}

type registryProxy struct {
	registry string
}

func (f *registryProxy) IsAuthorized(_ http.ResponseWriter, req *http.Request) bool {
	req.RequestURI = fmt.Sprintf("https://%s/", f.registry)
	req.URL, _ = url.Parse(req.RequestURI)
	req.Host = f.registry

	return true
}

func Launch(data string) (suite.Closer, error) {
	ctx := context.Background()

	env := testcontainers.WithEnv(map[string]string{
		"REGISTRY_HTTP_TLS_CERTIFICATE": "/tls/fake_quay.cer",
		"REGISTRY_HTTP_TLS_KEY":         "/tls/fake_quay.key",
	})

	dir, err := os.MkdirTemp("", "ec-benchmark-tls-*")
	if err != nil {
		return nil, err
	}
	closer := &registryCloser{dir, nil, nil}

	if err := os.Setenv("https_proxy", "http://localhost:3128"); err != nil {
		return nil, err
	}

	if err := os.Chmod(dir, 0o755); err != nil {
		return closer.Close, err
	}

	certPath := path.Join(dir, "fake_quay.cer")
	if err := os.WriteFile(certPath, certificate, 0o600); err != nil {
		return closer.Close, err
	}

	if err := os.Setenv("SSL_CERT_FILE", certPath); err != nil {
		return closer.Close, err
	}

	if err := os.WriteFile(path.Join(dir, "fake_quay.key"), key, 0o600); err != nil {
		return closer.Close, err
	}

	rp := registryProxy{}
	proxy := cproxy.New(cproxy.Options.Filter(&rp), cproxy.Options.Logger(log.Default()))
	proxyServer := httptest.NewUnstartedServer(proxy)
	proxyServer.Listener, err = net.Listen("tcp", "127.0.0.1:3128")
	if err != nil {
		return closer.Close, err
	}
	proxyServer.Config.ErrorLog = log.Default()
	proxyServer.Start()
	closer.proxy = proxyServer

	tlsMount := testcontainers.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
		hostConfig.Binds = append(hostConfig.Binds, fmt.Sprintf("%s:/tls:ro,Z", dir))
	})

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certificate)
	waitStrategy := testcontainers.WithWaitStrategy(wait.ForHTTP("/").
		WithPort("5000/tcp").
		WithTLS(true, &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
		}).
		WithStartupTimeout(10 * time.Second))

	opts := []testcontainers.ContainerCustomizer{
		registry.WithData(data),
		env,
		tlsMount,
		waitStrategy,
	}

	if false {
		opts = append(opts,
			testcontainers.WithConfigModifier(func(config *container.Config) {
				config.AttachStdout = true
			}),
			testcontainers.WithLogger(log.Default()))
	}

	r, err := registry.Run(ctx, "registry:2.8.3", opts...)
	if err != nil {
		return closer.Close, err
	}
	closer.container = r

	rp.registry = r.RegistryName

	return closer.Close, nil
}
