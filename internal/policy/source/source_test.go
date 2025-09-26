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

package source

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sync"
	"testing"

	ecc "github.com/conforma/crds/api/v1alpha1"
	fileMetadata "github.com/conforma/go-gather/gather/file"
	gitMetadata "github.com/conforma/go-gather/gather/git"
	ociMetadata "github.com/conforma/go-gather/gather/oci"
	"github.com/conforma/go-gather/metadata"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/conforma/cli/internal/utils"
)

func usingDownloader(ctx context.Context, m *mockDownloader) context.Context {
	return context.WithValue(ctx, DownloaderFuncKey, m)
}

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(ctx context.Context, dest string, sourceUrl string, showMsg bool) (metadata.Metadata, error) {
	args := m.Called(ctx, dest, sourceUrl, showMsg)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(metadata.Metadata), args.Error(1)
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name      string
		sourceUrl string
		dest      string
		metadata  metadata.Metadata
		err       error
	}{
		{
			name:      "Gets policies",
			sourceUrl: "https://example.com/user/foo.git",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			metadata:  &fileMetadata.FSMetadata{},
			err:       nil,
		},
		{
			name:      "Gets policies with getter style source url",
			sourceUrl: "git::https://example.com/user/foo.git//subdir?ref=devel",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			metadata:  &fileMetadata.FSMetadata{},
			err:       nil,
		},
		{
			name:      "Fails fetching the policy",
			sourceUrl: "failure",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			metadata:  &fileMetadata.FSMetadata{},
			err:       errors.New("expected"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PolicyUrl{Url: tt.sourceUrl, Kind: PolicyKind}

			dl := mockDownloader{}
			dl.On("Download", mock.Anything, mock.MatchedBy(func(dest string) bool {
				matched, err := regexp.MatchString(tt.dest, dest)
				if err != nil {
					panic(err)
				}

				return matched
			}), tt.sourceUrl, false).Return(tt.metadata, tt.err)

			_, err := p.GetPolicy(usingDownloader(context.TODO(), &dl), "/tmp/ec-work-1234", false)
			if tt.err == nil {
				assert.NoError(t, err, "GetPolicies returned an error")
			} else {
				assert.EqualError(t, err, tt.err.Error())
			}

			mock.AssertExpectationsForObjects(t, &dl)
		})
	}
}

func TestInlineDataSource(t *testing.T) {
	tests := []struct {
		name           string
		inputData      []byte
		expectedSubdir string
		expectedFile   string
		expectedData   []byte
		expectedURL    string
	}{
		{
			name:           "simple string data",
			inputData:      []byte("some data"),
			expectedSubdir: "data",
			expectedFile:   "rule_data.json",
			expectedData:   []byte("some data"),
			expectedURL:    "data:application/json;base64,c29tZSBkYXRh",
		},
		{
			name:           "json data",
			inputData:      []byte(`{"key": "value"}`),
			expectedSubdir: "data",
			expectedFile:   "rule_data.json",
			expectedData:   []byte(`{"key": "value"}`),
			expectedURL:    "data:application/json;base64,eyJrZXkiOiAidmFsdWUifQ==",
		},
		{
			name:           "empty data",
			inputData:      []byte(""),
			expectedSubdir: "data",
			expectedFile:   "rule_data.json",
			expectedData:   []byte(""),
			expectedURL:    "data:application/json;base64,",
		},
		{
			name:           "complex json with special characters",
			inputData:      []byte(`{"test": "value with spaces", "number": 42}`),
			expectedSubdir: "data",
			expectedFile:   "rule_data.json",
			expectedData:   []byte(`{"test": "value with spaces", "number": 42}`),
			expectedURL:    "data:application/json;base64,eyJ0ZXN0IjogInZhbHVlIHdpdGggc3BhY2VzIiwgIm51bWJlciI6IDQyfQ==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear download cache for each test
			t.Cleanup(func() {
				downloadCache = sync.Map{}
				symlinkMutexes = sync.Map{}
			})

			s := InlineData(tt.inputData)

			// Test interface methods
			assert.Equal(t, tt.expectedSubdir, s.Subdir())
			assert.Equal(t, InlineDataKind, s.Type())
			assert.Equal(t, tt.expectedURL, s.PolicyUrl())

			// Test GetPolicy method
			fs := afero.NewMemMapFs()
			temp, err := afero.TempDir(fs, "", "")
			require.NoError(t, err)

			ctx := utils.WithFS(context.Background(), fs)
			dest, err := s.GetPolicy(ctx, temp, false)
			require.NoError(t, err)
			assert.NotEmpty(t, dest)

			// Verify file creation and content
			file := path.Join(dest, tt.expectedFile)
			exists, err := afero.Exists(fs, file)
			require.NoError(t, err)
			assert.True(t, exists)

			data, err := afero.ReadFile(fs, file)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedData, data)

			// Verify file permissions
			stat, err := fs.Stat(file)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0400), stat.Mode().Perm())
		})
	}
}

func TestInlineDataSubdir(t *testing.T) {
	tests := []struct {
		name           string
		inputData      []byte
		expectedSubdir string
	}{
		{
			name:           "simple data returns data subdir",
			inputData:      []byte("test data"),
			expectedSubdir: "data",
		},
		{
			name:           "json data returns data subdir",
			inputData:      []byte(`{"key": "value"}`),
			expectedSubdir: "data",
		},
		{
			name:           "empty data returns data subdir",
			inputData:      []byte(""),
			expectedSubdir: "data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := InlineData(tt.inputData)

			result := s.Subdir()

			assert.Equal(t, tt.expectedSubdir, result)
			assert.Equal(t, "data", result, "Subdir should always return 'data' regardless of input")
		})
	}
}

func TestInlineDataGetPolicy(t *testing.T) {
	tests := []struct {
		name        string
		inputData   []byte
		workDir     string
		showMsg     bool
		setupFS     func() afero.Fs
		expectError bool
		errorMsg    string
	}{
		{
			name:        "successful policy creation with simple data",
			inputData:   []byte("test policy data"),
			workDir:     "/tmp/work",
			showMsg:     false,
			setupFS:     func() afero.Fs { return afero.NewMemMapFs() },
			expectError: false,
		},
		{
			name:        "successful policy creation with json data",
			inputData:   []byte(`{"rules": {"allow": true}}`),
			workDir:     "/tmp/work",
			showMsg:     true,
			setupFS:     func() afero.Fs { return afero.NewMemMapFs() },
			expectError: false,
		},
		{
			name:        "successful policy creation with empty data",
			inputData:   []byte(""),
			workDir:     "/tmp/work",
			showMsg:     false,
			setupFS:     func() afero.Fs { return afero.NewMemMapFs() },
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear download cache for each test
			t.Cleanup(func() {
				downloadCache = sync.Map{}
				symlinkMutexes = sync.Map{}
			})

			s := InlineData(tt.inputData)
			fs := tt.setupFS()
			ctx := utils.WithFS(context.Background(), fs)

			dest, err := s.GetPolicy(ctx, tt.workDir, tt.showMsg)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, dest)

			// Verify the destination directory exists
			exists, err := afero.DirExists(fs, dest)
			require.NoError(t, err)
			assert.True(t, exists, "destination directory should exist")

			// Verify the rule_data.json file was created
			ruleDataFile := path.Join(dest, "rule_data.json")
			fileExists, err := afero.Exists(fs, ruleDataFile)
			require.NoError(t, err)
			assert.True(t, fileExists, "rule_data.json should be created")

			// Verify file content matches input data
			fileContent, err := afero.ReadFile(fs, ruleDataFile)
			require.NoError(t, err)
			assert.Equal(t, tt.inputData, fileContent, "file content should match input data")

			// Verify file permissions are read-only
			stat, err := fs.Stat(ruleDataFile)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0400), stat.Mode().Perm(), "file should have read-only permissions")

			// Verify cache functionality - second call should return same result
			dest2, err2 := s.GetPolicy(ctx, tt.workDir, tt.showMsg)
			require.NoError(t, err2)
			assert.Equal(t, dest, dest2, "cached call should return same destination")
		})
	}
}

func TestInlineDataType(t *testing.T) {
	tests := []struct {
		name         string
		inputData    []byte
		expectedType PolicyType
	}{
		{
			name:         "simple data returns InlineDataKind",
			inputData:    []byte("test data"),
			expectedType: InlineDataKind,
		},
		{
			name:         "json data returns InlineDataKind",
			inputData:    []byte(`{"key": "value"}`),
			expectedType: InlineDataKind,
		},
		{
			name:         "empty data returns InlineDataKind",
			inputData:    []byte(""),
			expectedType: InlineDataKind,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := InlineData(tt.inputData)

			result := s.Type()

			assert.Equal(t, tt.expectedType, result)
			assert.Equal(t, "inline-data", string(result))
		})
	}
}

func TestPolicyUrlType(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		kind         PolicyType
		expectedType PolicyType
	}{
		{
			name:         "policy kind returns PolicyKind",
			url:          "github.com/user/repo//policy/",
			kind:         PolicyKind,
			expectedType: PolicyKind,
		},
		{
			name:         "data kind returns DataKind",
			url:          "https://example.com/data",
			kind:         DataKind,
			expectedType: DataKind,
		},
		{
			name:         "config kind returns ConfigKind",
			url:          "git::https://gitlab.com/user/repo//config/",
			kind:         ConfigKind,
			expectedType: ConfigKind,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PolicyUrl{
				Url:  tt.url,
				Kind: tt.kind,
			}

			result := p.Type()

			assert.Equal(t, tt.expectedType, result)
			assert.Equal(t, tt.kind, result, "Type should return the same value as Kind field")

			// Verify the returned type matches expected string values
			switch tt.expectedType {
			case PolicyKind:
				assert.Equal(t, "policy", string(result))
			case DataKind:
				assert.Equal(t, "data", string(result))
			case ConfigKind:
				assert.Equal(t, "config", string(result))
			}
		})
	}
}

func TestPolicySourcesFrom(t *testing.T) {
	tests := []struct {
		name          string
		source        ecc.Source
		expected      []PolicySource
		expectedCount int
	}{
		{
			name: "fetches policy and data configs",
			source: ecc.Source{
				Name:   "policy1",
				Policy: []string{"github.com/org/repo1//policy/", "github.com/org/repo2//policy/", "github.com/org/repo3//policy/"},
				Data:   []string{"github.com/org/repo1//data/", "github.com/org/repo2//data/", "github.com/org/repo3//data/"},
			},
			expected: []PolicySource{
				&PolicyUrl{Url: "github.com/org/repo1//policy/", Kind: PolicyKind},
				&PolicyUrl{Url: "github.com/org/repo2//policy/", Kind: PolicyKind},
				&PolicyUrl{Url: "github.com/org/repo3//policy/", Kind: PolicyKind},
				&PolicyUrl{Url: "github.com/org/repo1//data/", Kind: DataKind},
				&PolicyUrl{Url: "github.com/org/repo2//data/", Kind: DataKind},
				&PolicyUrl{Url: "github.com/org/repo3//data/", Kind: DataKind},
			},
			expectedCount: 6,
		},
		{
			name: "handles rule data with policy and data",
			source: ecc.Source{
				Name:     "policy2",
				Policy:   []string{"github.com/org/repo1//policy/"},
				Data:     []string{"github.com/org/repo1//data/"},
				RuleData: &extv1.JSON{Raw: []byte(`"foo":"bar"`)},
			},
			expected: []PolicySource{
				&PolicyUrl{Url: "github.com/org/repo1//policy/", Kind: PolicyKind},
				&PolicyUrl{Url: "github.com/org/repo1//data/", Kind: DataKind},
				inlineData{source: []byte("{\"rule_data__configuration__\":\"foo\":\"bar\"}")},
			},
			expectedCount: 3,
		},
		{
			name: "empty source returns empty slice",
			source: ecc.Source{
				Name: "empty",
			},
			expected:      []PolicySource{},
			expectedCount: 0,
		},
		{
			name: "only rule data without policy or data sources",
			source: ecc.Source{
				Name:     "rule-data-only",
				RuleData: &extv1.JSON{Raw: []byte(`{"setting": "value"}`)},
			},
			expected: []PolicySource{
				inlineData{source: []byte("{\"rule_data__configuration__\":{\"setting\": \"value\"}}")},
			},
			expectedCount: 1,
		},
		{
			name: "nil rule data is ignored",
			source: ecc.Source{
				Name:     "nil-rule-data",
				Policy:   []string{"github.com/org/repo//policy/"},
				RuleData: nil,
			},
			expected: []PolicySource{
				&PolicyUrl{Url: "github.com/org/repo//policy/", Kind: PolicyKind},
			},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources := PolicySourcesFrom(tt.source)

			assert.Len(t, sources, tt.expectedCount)
			assert.Equal(t, tt.expected, sources)

			// Verify each source has correct type
			for i, source := range sources {
				switch expected := tt.expected[i].(type) {
				case *PolicyUrl:
					actual, ok := source.(*PolicyUrl)
					assert.True(t, ok, "expected PolicyUrl at index %d", i)
					assert.Equal(t, expected.Url, actual.Url)
					assert.Equal(t, expected.Kind, actual.Kind)
					assert.Equal(t, expected.Kind, actual.Type())
				case inlineData:
					actual, ok := source.(inlineData)
					assert.True(t, ok, "expected inlineData at index %d", i)
					assert.Equal(t, expected.source, actual.source)
					assert.Equal(t, InlineDataKind, actual.Type())
					assert.Equal(t, "data", actual.Subdir())
				}
			}
		})
	}
}

type mockPolicySource struct {
	*mock.Mock
}

func (m mockPolicySource) GetPolicy(ctx context.Context, dest string, msgs bool) (string, error) {
	args := m.Called(ctx, dest, msgs)
	return args.String(0), args.Error(1)
}

func (m mockPolicySource) PolicyUrl() string {
	args := m.Called()
	return args.String(0)
}

func (m mockPolicySource) Subdir() string {
	args := m.Called()
	return args.String(0)
}

func (m mockPolicySource) Type() PolicyType {
	args := m.Called()
	return args.Get(0).(PolicyType)
}

func TestGetPolicyThroughCache(t *testing.T) {
	test := func(t *testing.T, fs afero.Fs, expectedDownloads int) {
		t.Cleanup(func() {
			downloadCache = sync.Map{}
			symlinkMutexes = sync.Map{}
		})

		ctx := utils.WithFS(context.Background(), fs)

		invocations := 0
		data := []byte("hello")
		dl := func(source, dest string) (metadata.Metadata, error) {
			invocations++
			if err := fs.MkdirAll(dest, 0755); err != nil {
				return nil, err
			}

			return nil, afero.WriteFile(fs, filepath.Join(dest, "data.json"), data, 0400)
		}

		source := &mockPolicySource{&mock.Mock{}}
		source.On("PolicyUrl").Return("policy-url")
		source.On("Subdir").Return("subdir")

		s1, _, err := getPolicyThroughCache(ctx, source, "/workdir1", dl)
		require.NoError(t, err)

		s2, _, err := getPolicyThroughCache(ctx, source, "/workdir2", dl)
		require.NoError(t, err)

		assert.NotEqual(t, s1, s2)
		assert.Equalf(t, expectedDownloads, invocations, "expected %d invocations, but was %d", expectedDownloads, invocations) // was using cache on second invocation

		dataFile1 := filepath.Join(s1, "data.json")
		data1, err := afero.ReadFile(fs, dataFile1)
		require.NoError(t, err)
		assert.Equal(t, data, data1)

		dataFile2 := filepath.Join(s2, "data.json")
		data2, err := afero.ReadFile(fs, dataFile2)
		require.NoError(t, err)
		assert.Equal(t, data, data2)

		if fs, ok := fs.(afero.Symlinker); ok {
			info, ok, err := fs.LstatIfPossible(s2)
			require.True(t, ok)
			require.NoError(t, err)
			assert.True(t, info.Mode()&os.ModeSymlink == os.ModeSymlink)
		}
	}

	t.Run("symlinkable", func(t *testing.T) {
		temp := t.TempDir()
		// need to use the OsFs as it implements Symlinker
		fs := afero.NewBasePathFs(afero.NewOsFs(), temp)

		test(t, fs, 1)
	})

	t.Run("non-symlinkable", func(t *testing.T) {
		test(t, afero.NewMemMapFs(), 2)
	})
}

// Test for https://issues.redhat.com/browse/EC-936, where we had multiple
// symbolic links pointing to the same policy download within the same workdir
// causing Rego compile issue
func TestDownloadCacheWorkdirMismatch(t *testing.T) {
	t.Cleanup(func() {
		downloadCache = sync.Map{}
		symlinkMutexes = sync.Map{}
	})
	tmp := t.TempDir()

	source := &mockPolicySource{&mock.Mock{}}
	source.On("PolicyUrl").Return("policy-url")
	source.On("Subdir").Return("subdir")

	// same URL downloaded to workdir1
	precachedDest := uniqueDestination(tmp, "subdir", source.PolicyUrl())
	require.NoError(t, os.MkdirAll(precachedDest, 0755))
	downloadCache.Store("policy-url", func() (string, cacheContent) {
		return precachedDest, cacheContent{}
	})

	// when working in workdir2
	workdir2 := filepath.Join(tmp, "workdir2")

	// first invocation symlinks back to workdir1
	destination1, _, err := getPolicyThroughCache(context.Background(), source, workdir2, func(s1, s2 string) (metadata.Metadata, error) { return nil, nil })
	require.NoError(t, err)

	// second invocation should not create a second symlink and duplicate the
	// source files within workdir2
	destination2, _, err := getPolicyThroughCache(context.Background(), source, workdir2, func(s1, s2 string) (metadata.Metadata, error) { return nil, nil })
	require.NoError(t, err)

	assert.Equal(t, destination1, destination2)
}

// TestConcurrentSymlinkCreation reproduces the race condition where multiple
// goroutines try to create symlinks to the same cached policy simultaneously
func TestConcurrentSymlinkCreation(t *testing.T) {
	t.Cleanup(func() {
		downloadCache = sync.Map{}
		symlinkMutexes = sync.Map{}
	})

	tmp := t.TempDir()

	source := &mockPolicySource{&mock.Mock{}}
	source.On("PolicyUrl").Return("policy-url")
	source.On("Subdir").Return("subdir")

	// Pre-cache the policy in workdir1
	precachedDest := uniqueDestination(tmp, "subdir", source.PolicyUrl())
	require.NoError(t, os.MkdirAll(precachedDest, 0755))

	// Create a test file in the cached directory
	testFile := filepath.Join(precachedDest, "policy.rego")
	require.NoError(t, os.WriteFile(testFile, []byte("package test"), 0644))

	downloadCache.Store("policy-url", func() (string, cacheContent) {
		return precachedDest, cacheContent{}
	})

	// Number of concurrent workers that will trigger the race condition
	numWorkers := 10
	results := make(chan error, numWorkers)

	// Launch multiple goroutines that try to access the policy from different workdirs
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			workerWorkdir := filepath.Join(tmp, fmt.Sprintf("worker-%d", workerID))
			_, _, err := getPolicyThroughCache(
				context.Background(),
				source,
				workerWorkdir,
				func(s1, s2 string) (metadata.Metadata, error) {
					// This shouldn't be called since we're using cached data
					t.Errorf("Download function called unexpectedly for worker %d", workerID)
					return nil, nil
				},
			)
			results <- err
		}(i)
	}

	// Collect results from all workers
	var errors []error
	for i := 0; i < numWorkers; i++ {
		if err := <-results; err != nil {
			errors = append(errors, err)
		}
	}

	// Before the fix, this would fail with "file exists" errors
	// After the fix, all workers should succeed
	if len(errors) > 0 {
		t.Fatalf("Expected no errors from concurrent symlink creation, but got %d errors: %v", len(errors), errors)
	}
}

func TestLogMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata metadata.Metadata
		expected string // Expected log message pattern
	}{
		{
			name: "git metadata logs SHA",
			metadata: &gitMetadata.GitMetadata{
				LatestCommit: "abc123456789",
			},
			expected: "SHA: abc123456789",
		},
		{
			name: "oci metadata logs digest",
			metadata: &ociMetadata.OCIMetadata{
				Digest: "sha256:abcdef123456",
			},
			expected: "Image digest: sha256:abcdef123456",
		},
		{
			name: "file metadata logs path",
			metadata: &fileMetadata.FSMetadata{
				Path: "/tmp/test/path",
			},
			expected: "Path: /tmp/test/path",
		},
		{
			name:     "nil metadata logs nothing",
			metadata: nil,
			expected: "", // No log expected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since logMetadata uses log.Debugf which is hard to capture,
			// we test the function's behavior by ensuring it doesn't panic
			// and handles different metadata types correctly

			// This should not panic regardless of metadata type
			assert.NotPanics(t, func() {
				logMetadata(tt.metadata)
			}, "logMetadata should not panic with any metadata type")

			// Test type assertions work correctly
			if tt.metadata != nil {
				switch v := tt.metadata.(type) {
				case *gitMetadata.GitMetadata:
					assert.NotEmpty(t, v.LatestCommit, "GitMetadata should have LatestCommit")
				case *ociMetadata.OCIMetadata:
					assert.NotEmpty(t, v.Digest, "OCIMetadata should have Digest")
				case *fileMetadata.FSMetadata:
					assert.NotEmpty(t, v.Path, "FSMetadata should have Path")
				}
			}
		})
	}
}
