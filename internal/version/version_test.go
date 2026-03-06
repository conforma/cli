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

package version

import (
	"fmt"
	dbg "runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestVersionInfoStringer(t *testing.T) {
	vi := VersionInfo{
		Version:   "v1",
		Commit:    "abc",
		ChangedOn: time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		Components: []ComponentInfo{
			{Name: "dep1", Version: "v1"},
			{Name: "dep2", Version: "v2"},
		},
	}

	assert.Regexp(t, `^Version      v1
Source ID    abc
Change date  2009-11-10 23:00:00 \+0o000 UTC \(\d{2} years ago\)
dep1         v1
dep2         v2
$`, fmt.Sprintf("%v", vi))
}

func TestComputeInfo(t *testing.T) {
	readBuildInfo = func() (info *dbg.BuildInfo, ok bool) {
		return &dbg.BuildInfo{
			Settings: []dbg.BuildSetting{
				{
					Key:   "vcs.revision",
					Value: "abc",
				},
				{
					Key:   "vcs.time",
					Value: "2009-11-10T23:00:00Z",
				},
			},
			Deps: []*dbg.Module{
				{Path: "github.com/conforma/crds/api", Version: "v1"},
				{Path: "github.com/open-policy-agent/opa", Version: "v2"},
				{Path: "github.com/open-policy-agent/conftest", Version: "v3"},
				{Path: "github.com/sigstore/cosign/v3", Version: "v4"},
				{Path: "github.com/sigstore/sigstore", Version: "v5"},
				{Path: "github.com/sigstore/rekor", Version: "v6"},
				{Path: "github.com/tektoncd/pipeline", Version: "v7"},
				{Path: "k8s.io/api", Version: "v8"},
			},
		}, true
	}
	Version = "v1"
	t.Cleanup(func() { readBuildInfo = dbg.ReadBuildInfo; Version = "" })

	vi, err := ComputeInfo()
	assert.NoError(t, err)
	assert.Equal(t, &VersionInfo{
		Version:   "v1",
		Commit:    "abc",
		ChangedOn: time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		Components: []ComponentInfo{
			{Name: "ECC", Version: "v1"},
			{Name: "OPA", Version: "v2"},
			{Name: "Conftest", Version: "v3"},
			{Name: "Cosign", Version: "v4"},
			{Name: "Sigstore", Version: "v5"},
			{Name: "Rekor", Version: "v6"},
			{Name: "Tekton Pipeline", Version: "v7"},
			{Name: "Kubernetes Client", Version: "v8"},
		},
	}, vi)
}

func TestDependencyVersion(t *testing.T) {
	assert.Equal(t, ComponentInfo{Name: "dep", Version: "N/A"}, dependencyVersion("dep", "path", nil))
	assert.Equal(t, ComponentInfo{Name: "dep", Version: "N/A"}, dependencyVersion("dep", "path", []*dbg.Module{}))
	assert.Equal(t, ComponentInfo{Name: "dep", Version: "v1.2.3"}, dependencyVersion("dep", "path", []*dbg.Module{
		{
			Path:    "path",
			Version: "v1.2.3",
		},
	}))
}
