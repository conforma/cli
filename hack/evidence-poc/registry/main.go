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

// A disposable, loopback-only OCI registry for the evidence demonstration.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func main() {
	port := flag.Int("port", 55087, "loopback registry port")
	dir := flag.String("dir", "hack/evidence-poc/generated", "output directory")
	flag.Parse()
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: registry.New(registry.WithReferrersSupport(true), registry.Logger(log.New(io.Discard, "", 0))), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil {
			log.Fatal(err)
		}
	}()
	if err := os.MkdirAll(*dir, 0700); err != nil {
		log.Fatal(err)
	}
	var components []map[string]string
	for _, component := range []string{"alpha", "beta"} {
		config, err := empty.Image.ConfigFile()
		if err != nil {
			log.Fatal(err)
		}
		config.Architecture, config.OS = "amd64", "linux"
		config.Config.Labels = map[string]string{"org.opencontainers.image.title": component}
		img, err := mutate.ConfigFile(empty.Image, config)
		if err != nil {
			log.Fatal(err)
		}
		tag, err := name.NewTag(fmt.Sprintf("localhost:%d/evidence-poc/%s:latest", *port, component))
		if err != nil {
			log.Fatal(err)
		}
		if err := remote.Write(tag, img); err != nil {
			log.Fatal(err)
		}
		digest, err := img.Digest()
		if err != nil {
			log.Fatal(err)
		}
		components = append(components, map[string]string{"name": component, "containerImage": tag.Context().Digest(digest.String()).Name()})
	}
	data, err := json.MarshalIndent(map[string]any{"components": components}, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "snapshot.json"), data, 0600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("POC registry listening on %s; snapshot written to %s\n", listener.Addr(), *dir)
	select {}
}
