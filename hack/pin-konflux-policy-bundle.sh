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
# policy OCI tag reference with a digest-pinned reference. It requires
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

ORIGINAL="oci::quay.io/conforma/release-policy:konflux"
REPLACEMENT="oci::quay.io/conforma/release-policy@${POLICY_BUNDLE_DIGEST}"

if ! grep -q "${ORIGINAL}" "$WORKING_POLICY"; then
  echo "'${ORIGINAL}' not found in policy configuration, nothing to do."
  exit 0
fi

# If the reference is already digest-pinned (e.g. :konflux@sha256:...),
# respect the existing pin rather than overriding it.
if grep -q "${ORIGINAL}@sha256:" "$WORKING_POLICY"; then
  echo "'${ORIGINAL}' already has a pinned digest, skipping override."
  exit 0
fi

sed -i "s|${ORIGINAL}|${REPLACEMENT}|g" "$WORKING_POLICY"
echo "Replaced: ${ORIGINAL}"
echo "    with: ${REPLACEMENT}"

POLICY_PATH="${HOME}/policy-with-pinned-bundle.yaml"
cp "$WORKING_POLICY" "${POLICY_PATH}"
echo "Modified policy written to: ${POLICY_PATH}"
