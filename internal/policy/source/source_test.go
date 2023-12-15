// Copyright The Enterprise Contract Contributors
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
	"os"
	"path"
	"regexp"
	"testing"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func usingDownloader(ctx context.Context, m *mockDownloader) context.Context {
	return context.WithValue(ctx, DownloaderFuncKey, m)
}

type mockDownloader struct {
	mock.Mock
}

func (m *mockDownloader) Download(_ context.Context, dest string, sourceUrl string, showMsg bool) error {
	args := m.Called(dest, sourceUrl, showMsg)

	return args.Error(0)
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name      string
		sourceUrl string
		dest      string
		err       error
	}{
		{
			name:      "Gets policies",
			sourceUrl: "example.com/user/foo.git",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			err:       nil,
		},
		{
			name:      "Gets policies with getter style source url",
			sourceUrl: "git::https://example.com/user/foo.git//subdir?ref=devel",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			err:       nil,
		},
		{
			name:      "Fails fetching the policy",
			sourceUrl: "failure",
			dest:      "/tmp/ec-work-1234/policy/[0-9a-f]+",
			err:       errors.New("expected"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PolicyUrl{Url: tt.sourceUrl, Kind: "policy"}

			dl := mockDownloader{}
			dl.On("Download", mock.MatchedBy(func(dest string) bool {
				matched, err := regexp.MatchString(tt.dest, dest)
				if err != nil {
					panic(err)
				}

				return matched
			}), tt.sourceUrl, false).Return(tt.err)

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
	s := InlineData([]byte("some data"))

	temp := t.TempDir()

	assert.Equal(t, "data", s.Subdir())

	dest, err := s.GetPolicy(context.Background(), temp, false)
	assert.NoError(t, err)

	file := path.Join(dest, "rule_data.json")
	assert.FileExists(t, file)

	data, err := os.ReadFile(file)
	assert.NoError(t, err)
	assert.Equal(t, []byte("some data"), data)

	assert.Equal(t, "data:application/json;base64,c29tZSBkYXRh", s.PolicyUrl())
}

func TestFetchPolicySources(t *testing.T) {
	// var ruleData = &extv1.JSON{Raw: []byte("foo")}
	tests := []struct {
		name     string
		source   ecc.Source
		expected []PolicySource
		err      error
	}{
		{
			name: "fetches policy configs",
			source: ecc.Source{
				Name:   "policy1",
				Policy: []string{"github.com/org/repo1//policy/", "github.com/org/repo2//policy/", "github.com/org/repo3//policy/"},
				Data:   []string{"github.com/org/repo1//data/", "github.com/org/repo2//data/", "github.com/org/repo3//data/"},
			},
			expected: []PolicySource{
				&PolicyUrl{Url: "github.com/org/repo1//policy/", Kind: "policy"},
				&PolicyUrl{Url: "github.com/org/repo2//policy/", Kind: "policy"},
				&PolicyUrl{Url: "github.com/org/repo3//policy/", Kind: "policy"},
				&PolicyUrl{Url: "github.com/org/repo1//data/", Kind: "data"},
				&PolicyUrl{Url: "github.com/org/repo2//data/", Kind: "data"},
				&PolicyUrl{Url: "github.com/org/repo3//data/", Kind: "data"},
			},
			err: nil,
		},
		{
			name: "handles rule data",
			source: ecc.Source{
				Name:     "policy2",
				Policy:   []string{"github.com/org/repo1//policy/"},
				Data:     []string{"github.com/org/repo1//data/"},
				RuleData: &extv1.JSON{Raw: []byte(`"foo":"bar"`)},
			},
			expected: []PolicySource{
				&PolicyUrl{Url: "github.com/org/repo1//policy/", Kind: "policy"},
				&PolicyUrl{Url: "github.com/org/repo1//data/", Kind: "data"},
				inlineData{source: []byte("{\"rule_data__configuration__\":\"foo\":\"bar\"}")},
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources, err := FetchPolicySources(tt.source)
			if tt.err == nil {
				assert.NoError(t, err, "FetchPolicySources returned an error")
			} else {
				assert.EqualError(t, err, tt.err.Error())
			}
			assert.Equal(t, sources, tt.expected)
		})
	}
}
