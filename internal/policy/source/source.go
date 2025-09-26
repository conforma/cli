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

// This module is more of a general purpose wrapper for fetching files and
// saving them locally. It was originally used only for policy, i.e. rego and
// yaml files, from the policy repo, hence the name choice for PolicySource,
// but now it's also used for fetching configuration from a git url.

package source

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path"
	"path/filepath"
	"runtime/trace"
	"sync"

	ecc "github.com/conforma/crds/api/v1alpha1"
	fileMetadata "github.com/conforma/go-gather/gather/file"
	gitMetadata "github.com/conforma/go-gather/gather/git"
	ociMetadata "github.com/conforma/go-gather/gather/oci"
	"github.com/conforma/go-gather/metadata"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/conforma/cli/internal/downloader"
	"github.com/conforma/cli/internal/utils"
)

type (
	key        int
	PolicyType string
)

const (
	DownloaderFuncKey key        = 0
	PolicyKind        PolicyType = "policy"
	DataKind          PolicyType = "data"
	ConfigKind        PolicyType = "config"
	InlineDataKind    PolicyType = "inline-data"
)

type downloaderFunc interface {
	Download(context.Context, string, string, bool) (metadata.Metadata, error)
}

// PolicySource in an interface representing the location a policy source.
// Must implement the GetPolicy() method.
type PolicySource interface {
	GetPolicy(ctx context.Context, dest string, showMsg bool) (string, error)
	PolicyUrl() string
	Subdir() string
	Type() PolicyType
}

type PolicyUrl struct {
	// A string containing a go-getter style source url compatible with conftest pull
	Url  string
	Kind PolicyType
}

// downloadCache is a concurrent map used to cache downloaded files.
var downloadCache sync.Map

// symlinkMutexes provides per-destination synchronization for symlink creation
var symlinkMutexes sync.Map

// ClearDownloadCache clears the download cache. This is primarily used for testing.
func ClearDownloadCache() {
	downloadCache = sync.Map{}
	symlinkMutexes = sync.Map{}
}

type cacheContent struct {
	sourceUrl string
	metadata  metadata.Metadata
	err       error
}

func getPolicyThroughCache(ctx context.Context, s PolicySource, workDir string, dl func(string, string) (metadata.Metadata, error)) (string, metadata.Metadata, error) {
	sourceUrl := s.PolicyUrl()
	dest := uniqueDestination(workDir, s.Subdir(), sourceUrl)

	// Load or store the downloaded policy file from the given source URL.
	// If the file is already in the download cache, it is loaded from there.
	// Otherwise, it is downloaded from the source URL and stored in the cache.
	dfn, _ := downloadCache.LoadOrStore(sourceUrl, sync.OnceValues(func() (string, cacheContent) {
		log.Debugf("Download cache miss: %s", sourceUrl)
		// Checkout policy repo into work directory.
		log.Debugf("Downloading policy files from source url %s to destination %s", sourceUrl, dest)
		m, err := dl(sourceUrl, dest)
		c := &cacheContent{sourceUrl, m, err}
		return dest, *c
	}))

	d, c := dfn.(func() (string, cacheContent))()
	if c.err != nil {
		return "", c.metadata, c.err
	}

	fs := utils.FS(ctx)

	// If the destination directory is different from the source directory, we
	// need to symlink the source directory to the destination directory.
	// Use synchronization to prevent race conditions when multiple goroutines
	// try to create the same symlink simultaneously.
	if filepath.Dir(dest) != filepath.Dir(d) {
		// Get or create a mutex for this specific destination
		mutexValue, _ := symlinkMutexes.LoadOrStore(dest, &sync.Mutex{})
		mutex := mutexValue.(*sync.Mutex)

		mutex.Lock()
		defer mutex.Unlock()

		// Check again if the destination exists after acquiring the lock
		if _, err := fs.Stat(dest); err == nil {
			return dest, c.metadata, nil
		}

		base := filepath.Dir(dest)
		if err := fs.MkdirAll(base, 0755); err != nil {
			return "", nil, err
		}

		if symlinkableFS, ok := fs.(afero.Symlinker); ok {
			log.Debugf("Symlinking %s to %s", d, dest)
			if err := symlinkableFS.SymlinkIfPossible(d, dest); err != nil {
				return "", nil, err
			}
			logMetadata(c.metadata)
			return dest, c.metadata, nil
		} else {
			log.Debugf("Filesystem does not support symlinking: %q, re-downloading instead", fs.Name())
			m, err := dl(sourceUrl, dest)
			logMetadata(m)
			return dest, m, err
		}
	} else {
		// If dest and d are in the same directory, no symlink needed,
		// but still check if dest exists
		if _, err := fs.Stat(dest); err == nil {
			return dest, c.metadata, nil
		}
	}

	if c.metadata != nil {
		logMetadata(c.metadata)
	}
	return d, c.metadata, c.err
}

// GetPolicy clones the repository for a given PolicyUrl
func (p *PolicyUrl) GetPolicy(ctx context.Context, workDir string, showMsg bool) (string, error) {
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:get-policy")
		defer region.End()
		trace.Logf(ctx, "", "policy=%q", p.Url)
	}

	dl := func(source string, dest string) (metadata.Metadata, error) {
		x := ctx.Value(DownloaderFuncKey)
		if dl, ok := x.(downloaderFunc); ok {
			return dl.Download(ctx, dest, source, showMsg)
		}
		return downloader.Download(ctx, dest, source, showMsg)
	}

	dest, metadata, err := getPolicyThroughCache(ctx, p, workDir, dl)
	if err != nil {
		return "", err
	}

	p.Url, err = metadata.GetPinnedURL(p.Url)
	log.Debug("Pinned URL: ", p.Url)
	if err != nil {
		return "", err
	}

	return dest, err
}

func (p *PolicyUrl) PolicyUrl() string {
	return p.Url
}

func (p *PolicyUrl) Subdir() string {
	// Be lazy and assume the kind value is the same as the subdirectory we want
	return string(p.Kind)
}

func (p PolicyUrl) Type() PolicyType {
	return p.Kind
}

func logMetadata(m metadata.Metadata) {
	if m != nil {
		switch v := m.(type) {
		case *gitMetadata.GitMetadata:
			log.Debugf("SHA: %s\n", v.LatestCommit)
		case *ociMetadata.OCIMetadata:
			log.Debugf("Image digest: %s\n", v.Digest)
		case *fileMetadata.FSMetadata:
			log.Debugf("Path: %s\n", v.Path)
		}
	}
}

func uniqueDestination(rootDir string, subdir string, sourceUrl string) string {
	return path.Join(rootDir, subdir, uniqueDir(sourceUrl))
}

// uniqueDir generates a reasonably unique string using an SHA224 sum
func uniqueDir(input string) string {
	return fmt.Sprintf("%x", sha256.Sum224([]byte(input)))[:9]
}

type inlineData struct {
	source []byte
}

func InlineData(source []byte) PolicySource {
	return inlineData{source}
}

func (s inlineData) GetPolicy(ctx context.Context, workDir string, showMsg bool) (string, error) {
	dl := func(source string, dest string) (metadata.Metadata, error) {
		fs := utils.FS(ctx)

		if err := fs.MkdirAll(dest, 0755); err != nil {
			return nil, err
		}

		f := path.Join(dest, "rule_data.json")
		m := &fileMetadata.FSMetadata{
			URI:  source,
			Path: dest,
			Size: int64(len(dest)),
		}

		return m, afero.WriteFile(fs, f, s.source, 0400)
	}

	dest, _, err := getPolicyThroughCache(ctx, s, workDir, dl)
	return dest, err
}

func (s inlineData) PolicyUrl() string {
	return "data:application/json;base64," + base64.StdEncoding.EncodeToString(s.source)
}

func (s inlineData) Subdir() string {
	return "data"
}

func (inlineData) Type() PolicyType {
	return InlineDataKind
}

// PolicySourcesFrom returns an array of policy sources
func PolicySourcesFrom(s ecc.Source) []PolicySource {
	policySources := make([]PolicySource, 0, len(s.Policy)+len(s.Data))

	for _, policySourceUrl := range s.Policy {
		url := PolicyUrl{Url: policySourceUrl, Kind: PolicyKind}
		policySources = append(policySources, &url)
	}

	for _, dataSourceUrl := range s.Data {
		url := PolicyUrl{Url: dataSourceUrl, Kind: DataKind}
		policySources = append(policySources, &url)
	}

	if s.RuleData != nil {
		data := append(append([]byte(`{"rule_data__configuration__":`), s.RuleData.Raw...), '}')
		policySources = append(policySources, InlineData(data))
	}

	return policySources
}
