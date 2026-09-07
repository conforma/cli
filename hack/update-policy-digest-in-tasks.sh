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

# Update the POLICY_BUNDLE_DIGEST default value in the enterprise-contract
# pipeline definition and related docs/tests.

set -o errexit
set -o nounset
set -o pipefail

IMAGE="${IMAGE:-"quay.io/conforma/release-policy:konflux"}"

# The pipeline definition is the primary place where the digest default
# lives. The docs and test features also reference it and should be kept
# in sync.
FILES=(
  pipelines/enterprise-contract/0.1/enterprise-contract.yaml
  docs/modules/ROOT/pages/verify-conforma-konflux-ta.adoc
  docs/modules/ROOT/pages/verify-enterprise-contract.adoc
  features/__snapshots__/task_validate_image.snap
  features/task_validate_image.feature
)

MANIFEST=$(skopeo inspect --raw "docker://${IMAGE}")
HASH=$(echo -n "${MANIFEST}" | sha256sum | awk '{print $1}')
NEW_DIGEST="sha256:${HASH}"

OLD_DIGEST=$(sed -n '/- name: POLICY_BUNDLE_DIGEST$/,/- name: /{s/.*default: "\(sha256:[a-f0-9]*\)".*/\1/p;}' "${FILES[0]}")

echo "Old digest: ${OLD_DIGEST}"
echo "New digest: ${NEW_DIGEST}"

if [[ "${OLD_DIGEST}" == "${NEW_DIGEST}" ]]; then
  echo "Already up to date."
  exit 0
fi

for f in "${FILES[@]}"; do
  if [[ ! -f "${f}" ]]; then
    echo "Warning: ${f} not found, skipping" >&2
    continue
  fi
  sed -i "s|${OLD_DIGEST}|${NEW_DIGEST}|g" "${f}"
  echo "Updated ${f}"
done
