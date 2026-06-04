#!/bin/bash
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Creates the files in the data directory that should contain all the data
# needed to run the benchmark, uses the ../offliner for images and plain git
# clone for the git data dependency. Uses the same golden-container image as the
# simple benchmark -- the stress benchmark duplicates it across components at
# runtime.
set -o errexit
set -o nounset
set -o pipefail

offliner="$(git rev-parse --show-toplevel)/benchmark/offliner"

dir="$(mktemp -d)"
trap 'rm -rf "${dir}"' EXIT

(
    cd "${dir}"

    imgs=(
        quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container@sha256:166e38c156fa81d577a7ba7a948b68c79005a06e302779d1bebc7d31e8bea315
        quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles@sha256:1e70b8f672388838f20a7d45e145e31e99dab06cefa1c5514d6ce41c8bbea1b0
        quay.io/enterprise-contract/ec-release-policy@sha256:64617f0c45689ef7152c5cfbd4cd5709a3126e4ab7482eb6acd994387fe2d4ba
    )

    for img in "${imgs[@]}"; do
        go run -C "${offliner}" . "${img}" "${dir}/data/registry/data"
    done

    git clone --no-checkout https://github.com/release-engineering/rhtap-ec-policy.git data/git/rhtap-ec-policy.git
)

tar czf data.tar.gz -C "${dir}" .
