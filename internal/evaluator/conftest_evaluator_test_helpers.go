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

// This file contains shared test infrastructure, mock types, and helper functions
// used across all conftest evaluator test files. It includes:
// - Mock implementations (mockTestRunner, mockDownloader, mockConfigProvider)
// - Test policy source (testPolicySource)
// - Helper functions for test setup (withTestRunner, setupTestContext, rulesArchive, etc.)
// - Simple config provider for tests (simpleConfigProvider)
// - Global test capabilities (testCapabilities)
// - Embedded test policy files

//go:build unit || integration

package evaluator

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"embed"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
	ecc "github.com/conforma/crds/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/downloader"
	"github.com/conforma/cli/internal/policy"
	"github.com/conforma/cli/internal/policy/source"
	"github.com/conforma/cli/internal/utils"
)

//go:embed __testdir__/*/*.rego
var policies embed.FS

// Mock types
type mockTestRunner struct {
	mock.Mock
}

func (m *mockTestRunner) Run(ctx context.Context, inputs []string) ([]Outcome, error) {
	args := m.Called(ctx, inputs)
	return args.Get(0).([]Outcome), args.Error(2)
}

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(ctx context.Context, dest string, urls []string) error {
	args := m.Called(ctx, dest, urls)
	return args.Error(0)
}

type mockConfigProvider struct {
	mock.Mock
}

func (o *mockConfigProvider) EffectiveTime() time.Time {
	args := o.Called()
	return args.Get(0).(time.Time)
}

func (o *mockConfigProvider) SigstoreOpts() (policy.SigstoreOpts, error) {
	args := o.Called()
	return args.Get(0).(policy.SigstoreOpts), args.Error(1)
}

func (o *mockConfigProvider) Spec() ecc.EnterpriseContractPolicySpec {
	args := o.Called()
	return args.Get(0).(ecc.EnterpriseContractPolicySpec)
}

// Test policy source
type testPolicySource struct{}

func (t testPolicySource) GetPolicy(ctx context.Context, dest string, showMsg bool) (string, error) {
	return "/policy", nil
}

func (t testPolicySource) PolicyUrl() string {
	return "test-url"
}

func (t testPolicySource) Subdir() string {
	return "policy"
}

func (testPolicySource) Type() source.PolicyType {
	return source.PolicyKind
}

// Helper functions
func withTestRunner(ctx context.Context, clnt testRunner) context.Context {
	return context.WithValue(ctx, runnerKey, clnt)
}

func setupTestContext(r *mockTestRunner, dl *mockDownloader) context.Context {
	ctx := withTestRunner(context.Background(), r)
	ctx = downloader.WithDownloadImpl(ctx, dl)
	fs := afero.NewMemMapFs()
	ctx = utils.WithFS(ctx, fs)
	ctx = withCapabilities(ctx, testCapabilities)

	if err := afero.WriteFile(fs, "/policy/example.rego", []byte(heredoc.Doc(`# Simplest always-failing policy
	package main
	import rego.v1

	# METADATA
	# title: Reject rule
	# description: This rule will always fail
	deny contains result if {
		result := "Fails always"
	}`)), 0644); err != nil {
		panic(err)
	}

	return ctx
}

func rulesArchiveFromFS(t *testing.T, files fs.FS) (string, error) {
	t.Helper()

	dir := t.TempDir()
	rules := path.Join(dir, "rules.tar")

	f, err := os.Create(rules)
	if err != nil {
		return "", err
	}
	defer f.Close()
	ar := tar.NewWriter(f)
	defer ar.Close()

	rego, err := fs.ReadDir(files, ".")
	if err != nil {
		return "", err
	}

	for _, r := range rego {
		if r.IsDir() {
			continue
		}
		f, err := files.Open(r.Name())
		if err != nil {
			return "", err
		}

		bytes, err := io.ReadAll(f)
		if err != nil {
			return "", err
		}

		require.NoError(t, ar.WriteHeader(&tar.Header{
			Name: r.Name(),
			Mode: 0644,
			Size: int64(len(bytes)),
		}))

		if _, err = ar.Write(bytes); err != nil {
			return "", err
		}
	}

	return rules, nil
}

// createTestArchive tars and gzips the directory at srcDir into destTarGz.
// All files under srcDir are added with paths relative to srcDir.
//
// Usage in tests:
//
//	archivePath := filepath.Join(t.TempDir(), "rules.tar.gz")
//	createTestArchive(t, "/path/to/policy/dir", archivePath)
func createTestArchive(t *testing.T, srcDir, destTarGz string) {
	t.Helper()

	out, err := os.Create(destTarGz)
	require.NoError(t, err, "create archive file")
	defer func() { _ = out.Close() }()

	// If you already use gzip elsewhere, you can swap this for gzip.NewWriter(out)
	// and wrap tar.NewWriter(gzw). For most test archives, plain tar is fine too.
	gzw := gzip.NewWriter(out)
	defer func() { _ = gzw.Close() }()

	tw := tar.NewWriter(gzw)
	defer func() { _ = tw.Close() }()

	err = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		// Normalize to forward slashes inside tar
		rel = filepath.ToSlash(rel)

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()

		_, err = io.Copy(tw, f)
		return err
	})
	require.NoError(t, err, "write archive from %s", srcDir)
}

// Simple config provider for tests
type simpleConfigProvider struct {
	effectiveTime time.Time
}

func (s *simpleConfigProvider) EffectiveTime() time.Time {
	return s.effectiveTime
}

func (s *simpleConfigProvider) SigstoreOpts() (policy.SigstoreOpts, error) {
	return policy.SigstoreOpts{}, nil
}

func (s *simpleConfigProvider) Spec() ecc.EnterpriseContractPolicySpec {
	return ecc.EnterpriseContractPolicySpec{}
}

// Global test capabilities
var testCapabilities string

func init() {
	// Given the amount of tests in this file, creating the capabilities string
	// can add significant overhead. We do it here once for all the tests instead.
	data, err := strictCapabilities(context.Background())
	if err != nil {
		panic(err)
	}
	testCapabilities = data
}
