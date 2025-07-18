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

# Updates a local clone of redhat-appstudio/infra-deployments to use the latest
# packages produced by this repository.
# Usage:
#   update-infra-deployments.sh <PATH_TO_INFRA_DEPLOYMENTS> [<TAG>]

set -o errexit
set -o pipefail
set -o nounset

TARGET_DIR="${1}"
cd "${TARGET_DIR}" || exit 1

echo 'Resolving task bundle...'

# Task definition built and pushed from main branch in the cli
# repo by the Conforma Konflux build pipeline
TASK_BUNDLE_REPO=quay.io/conforma/tekton-task
TASK_BUNDLE_TAG="${2:-latest}"
TAG_PREFIX="kf-"

# The same but built and pushed by a GitHub Workflow. Now deprecated.
#TASK_BUNDLE_REPO=quay.io/conforma/tekton-task
#TASK_BUNDLE_TAG="${2:-snapshot}"
#TAG_PREFIX="gh-"

MANIFEST=$(mktemp --tmpdir)
function cleanup() {
    rm "${MANIFEST}"
}
trap cleanup EXIT
skopeo inspect "docker://${TASK_BUNDLE_REPO}:${TASK_BUNDLE_TAG}" --raw > "${MANIFEST}"
TASK_BUNDLE_DIGEST="$(skopeo manifest-digest "${MANIFEST}")"
REVISION="$(jq -r '.annotations["org.opencontainers.image.revision"]' "${MANIFEST}")"
if [[ -n "${REVISION}" && "${REVISION}" != null ]]; then
    # We push "kf-{{sha}}" tags for Konflux built task bundles and "gh-{{sha}}"
    # tags for GitHub built task bundles. That's why the $TAG_PREFIX is needded.
    TASK_BUNDLE_TAG="${TAG_PREFIX}${REVISION}"
fi
# Sanity check
diff \
    <(skopeo inspect --raw "docker://${TASK_BUNDLE_REPO}:${TASK_BUNDLE_TAG}") \
    <(skopeo inspect --raw "docker://${TASK_BUNDLE_REPO}@${TASK_BUNDLE_DIGEST}")

TASK_BUNDLE_REF="${TASK_BUNDLE_REPO}:${TASK_BUNDLE_TAG}@${TASK_BUNDLE_DIGEST}"
echo "Resolved bundle is ${TASK_BUNDLE_REF}"
echo "Resolved revision is ${REVISION}"

echo 'Updating infra-deployments...'
REF="${TASK_BUNDLE_REF}" REV="${REVISION}" yq e -i \
    '.configMapGenerator[] |=
        select(.name == "ec-defaults").literals = [
            "verify_ec_task_bundle=" + env(REF),
            "verify_ec_task_git_url=https://github.com/conforma/cli.git",
            "verify_ec_task_git_revision=" + env(REV),
            "verify_ec_task_git_pathInRepo=tasks/verify-enterprise-contract/0.1/verify-enterprise-contract.yaml",
            "verify_conforma_task_ta_git_pathInRepo=tasks/verify-conforma-konflux-ta/0.1/verify-conforma-konflux-ta.yaml"
        ]' \
    components/enterprise-contract/kustomization.yaml

echo 'infra-deployments updated successfully'
