#!/usr/bin/env bash
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
#
# This script resolves a policy configuration and replaces the release
# policy OCI tag references with a digest-pinned reference. Both the
# conforma repository and its enterprise-contract mirror are handled: the
# release process retags both in the same step, so either reference
# identifies the same policy image. It requires
# the following environment variables:
#
# - POLICY_CONFIGURATION: Policy reference (k8s name, inline JSON, or file path).
# - POLICY_BUNDLE_DIGEST: OCI digest to pin to (e.g. "sha256:abc123..." or "abc123...").
#   If empty, the script is a no-op.
# - HOME: Home directory (defaults to /tekton/home in Tekton tasks).
#
# Tests: bash hack/pin-konflux-policy-bundle_test.sh

set -o errexit
set -o nounset
set -o pipefail

if [[ -z "${POLICY_BUNDLE_DIGEST:-}" ]]; then
  echo "POLICY_BUNDLE_DIGEST is empty, skipping policy bundle digest override."
  exit 0
fi

# Normalize digest: prepend sha256: if not present
if [[ "${POLICY_BUNDLE_DIGEST}" != sha256:* ]]; then
  POLICY_BUNDLE_DIGEST="sha256:${POLICY_BUNDLE_DIGEST}"
fi

echo "Applying policy bundle digest override: ${POLICY_BUNDLE_DIGEST}"

WORKING_POLICY="$(mktemp /tmp/policy.XXXXXX)"

if [[ "${POLICY_CONFIGURATION}" == "{"* ]]; then
  # Inline JSON
  printf "%s" "${POLICY_CONFIGURATION}" > "$WORKING_POLICY"

elif [[ -f "${POLICY_CONFIGURATION}" ]]; then
  # File path
  cp "${POLICY_CONFIGURATION}" "$WORKING_POLICY"

else
  # Kubernetes resource names: DNS label, max 63 chars
  # ECP references are "name" or "namespace/name"
  VALID_ECP_REF='^[a-z0-9]([-a-z0-9]*[a-z0-9])?(/[a-z0-9]([-a-z0-9]*[a-z0-9])?)?$'
  if [[ "${POLICY_CONFIGURATION}" =~ $VALID_ECP_REF ]]; then
    if [[ "${POLICY_CONFIGURATION}" == *"/"* ]]; then
      NAMESPACE="${POLICY_CONFIGURATION%%/*}"
      NAME="${POLICY_CONFIGURATION##*/}"
      kubectl get enterprisecontractpolicy/"${NAME}" -n "${NAMESPACE}" -o json \
        | jq '.spec' > "$WORKING_POLICY" || \
        { echo "Failed to get EnterpriseContractPolicy: ${POLICY_CONFIGURATION}"; exit 1; }
    else
      kubectl get enterprisecontractpolicy/"${POLICY_CONFIGURATION}" -o json \
        | jq '.spec' > "$WORKING_POLICY" || \
        { echo "Failed to get EnterpriseContractPolicy: ${POLICY_CONFIGURATION}"; exit 1; }
    fi
  else
    echo "Unsupported POLICY_CONFIGURATION format: ${POLICY_CONFIGURATION}"
    echo "Policy bundle digest pinning is not supported for this format, skipping."
    exit 0
  fi
fi

REPLACEMENT="oci::quay.io/conforma/release-policy@${POLICY_BUNDLE_DIGEST}"

# The enterprise-contract repository mirrors the release policy: the
# release process copies the same digest to both tags, so either reference
# can be pinned to the canonical repository.
ORIGINALS=(
  "oci::quay.io/conforma/release-policy:konflux"
  "oci::quay.io/enterprise-contract/ec-release-policy:konflux"
)

REPLACED=0
for ORIGINAL in "${ORIGINALS[@]}"; do
  if ! grep -q "${ORIGINAL}" "$WORKING_POLICY"; then
    continue
  fi
  # Hide occurrences that are already pinned to a digest behind a marker
  # so that only floating references are replaced. A global sed alone
  # cannot distinguish them: ORIGINAL@sha256:<old> contains ORIGINAL.
  sed -i "s|${ORIGINAL}@sha256:|__PINNED_POLICY_REF__@sha256:|g" "$WORKING_POLICY"
  if grep -q "${ORIGINAL}" "$WORKING_POLICY"; then
    sed -i "s|${ORIGINAL}|${REPLACEMENT}|g" "$WORKING_POLICY"
    echo "Replaced: ${ORIGINAL}"
    echo "    with: ${REPLACEMENT}"
    REPLACED=1
  else
    echo "'${ORIGINAL}' already has a pinned digest, skipping override."
  fi
  # Restore the hidden pinned occurrences.
  sed -i "s|__PINNED_POLICY_REF__@sha256:|${ORIGINAL}@sha256:|g" "$WORKING_POLICY"
done

if [ "$REPLACED" -eq 0 ]; then
  echo "Release policy reference not found in policy configuration, nothing to do."
  exit 0
fi

POLICY_PATH="${HOME}/policy-with-pinned-bundle.yaml"
cp "$WORKING_POLICY" "${POLICY_PATH}"
echo "Modified policy written to: ${POLICY_PATH}"
