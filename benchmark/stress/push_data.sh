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

# Pushes the local data.tar.gz to Quay as an OCI artifact. Requires prior
# authentication via `oras login quay.io`.
set -o errexit
set -o nounset
set -o pipefail

quay_ref="quay.io/conforma/benchmark-data:stress-v1"

if [[ ! -f data.tar.gz ]]; then
    echo "data.tar.gz not found, run prepare_data.sh first" >&2
    exit 1
fi

oras push "${quay_ref}" data.tar.gz
echo "Pushed data.tar.gz to ${quay_ref}"
