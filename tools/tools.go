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

// Tracks tooling dependencies, i.e. those that are not used by the code directly
package tools

import (
	_ "github.com/daixiang0/gci"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/google/addlicense"
	_ "github.com/open-policy-agent/conftest"
	_ "github.com/tektoncd/chains/pkg/chains"
	_ "github.com/tektoncd/cli/cmd/tkn"
	_ "github.com/wadey/gocovmerge"
	_ "gotest.tools/gotestsum"
	_ "helm.sh/helm/v3/cmd/helm"
	_ "sigs.k8s.io/kustomize/kustomize/v5"
)
