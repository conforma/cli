#!/usr/bin/env bash
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Fetches the Tekton YAML descriptors for the version we depend on

set -o errexit
set -o pipefail
set -o nounset

TKN_VERSION="${TKN_VERSION:-$(cd "$(git rev-parse --show-toplevel)" && go list -f '{{.Version}}' -m github.com/tektoncd/pipeline)}"

# Try Google Cloud Storage first (for older versions)
if curl -fsSL "https://storage.googleapis.com/tekton-releases/pipeline/previous/${TKN_VERSION}/release.yaml" 2>/dev/null; then
    exit 0
fi

# Fall back to GitHub releases (for newer versions like v1.10.2+)
curl -fsSL "https://github.com/tektoncd/pipeline/releases/download/${TKN_VERSION}/release.yaml"
