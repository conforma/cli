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

# Creates (or deletes) the dummy IntegrationTestScenario for the EC-2011 POC.
#
# This script ONLY manages the IntegrationTestScenario object. The ITS pipeline's
# attest-test-result step also needs push access, which requires patching the
# shared konflux-integration-runner ServiceAccount — a separate, security-
# sensitive, namespace-wide change handled by hack/modify-sa-for-dummy-its.sh.
# Run that script after this one to grant push access.

set -euo pipefail

NAMESPACE="${NAMESPACE:-rhtap-contract-tenant}"
APPLICATION="${APPLICATION:-ec-main}"
ITS_NAME="${ITS_NAME:-reqd-task-poc-ec2011}"

GIT_URL="${GIT_URL:-https://github.com/simonbaird/conforma-cli}"
GIT_REVISION="${GIT_REVISION:-reqd-task-its-poc}"
PIPELINE_PATH="${PIPELINE_PATH:-pipelines/dummy-integration-test/0.1/dummy-integration-test.yaml}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--revert] [--help]

  (no args)   Create the dummy IntegrationTestScenario.
  --revert    Delete the dummy IntegrationTestScenario.

Grant/revoke the push access the ITS pipeline needs separately, with
hack/modify-sa-for-dummy-its.sh.

Environment overrides: NAMESPACE, APPLICATION, ITS_NAME, GIT_URL, GIT_REVISION,
PIPELINE_PATH.
EOF
}

create_its() {
  echo "Creating IntegrationTestScenario '${ITS_NAME}' in namespace '${NAMESPACE}'"
  echo "  Application: ${APPLICATION}"
  echo "  Git URL:     ${GIT_URL}"
  echo "  Revision:    ${GIT_REVISION}"
  echo "  Pipeline:    ${PIPELINE_PATH}"
  echo ""

  oc apply -f - <<EOF
apiVersion: appstudio.redhat.com/v1beta2
kind: IntegrationTestScenario
metadata:
  name: ${ITS_NAME}
  namespace: ${NAMESPACE}
  labels:
    test.appstudio.openshift.io/optional: "true"
spec:
  application: ${APPLICATION}
  contexts:
    - description: Application testing
      name: application
  resolverRef:
    resolver: git
    resourceKind: pipeline
    params:
      - name: url
        value: ${GIT_URL}
      - name: revision
        value: ${GIT_REVISION}
      - name: pathInRepo
        value: ${PIPELINE_PATH}
EOF

  echo ""
  echo "Done. Verify with:"
  echo "  oc get integrationtestscenario ${ITS_NAME} -n ${NAMESPACE} -o yaml"
  echo ""
  echo "Next: grant push access with hack/modify-sa-for-dummy-its.sh"
}

revert_its() {
  echo "Deleting IntegrationTestScenario '${ITS_NAME}' from namespace '${NAMESPACE}'"
  oc delete integrationtestscenario "${ITS_NAME}" -n "${NAMESPACE}" --ignore-not-found
  echo ""
  echo "Done. If push access was granted, revoke it with:"
  echo "  hack/modify-sa-for-dummy-its.sh --revert"
}

case "${1:-}" in
  --revert)     revert_its ;;
  --help | -h)  usage ;;
  "")           create_its ;;
  *)            echo "Unknown argument: $1" >&2; echo ""; usage; exit 1 ;;
esac
