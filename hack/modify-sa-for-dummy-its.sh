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

# Grants (or revokes) push access for the EC-2011 POC ITS pipeline by patching
# the shared konflux-integration-runner ServiceAccount.
#
# The integration service runs all ITS pipelines using the
# konflux-integration-runner ServiceAccount. There's currently no way to
# specify a per-ITS ServiceAccount, so we have to patch the shared SA to
# include the push secret needed by the attest-test-result step action.
#
# NOTE: This is a security hazard, not just a broad-scope inconvenience. ITS
# pipelines are BYO/arbitrary by design, so any secret on the shared runner SA
# is a secret handed to untrusted code. This patch is acceptable only for this
# POC under a "trusted pipeline" assumption; a real solution must keep push
# credentials off the runner SA entirely (e.g. platform-side push). It is kept
# in its own script (separate from create-dummy-its.sh) precisely because it is
# a shared, namespace-wide, security-sensitive change.
#
# TODO: Ideally only specific ITS pipelines that need push access should
# get it, not every ITS in the namespace. This requires either:
#   - A per-ITS ServiceAccount field in the IntegrationTestScenario spec
#     (integration-service is one field away: the `if ServiceAccountName == ""`
#     guard in tekton/integration_pipeline.go already exists, nothing feeds it)
#   - A dedicated SA created and wired up per pipeline
# For now we accept the broader scope for this POC.

set -euo pipefail

NAMESPACE="${NAMESPACE:-rhtap-contract-tenant}"
INTEGRATION_SA="konflux-integration-runner"
PUSH_SECRET="${PUSH_SECRET:-imagerepository-for-ec-main-cli-main-image-push}"

# The pull-only secret "ec-main-pull" covers the same registry path as the
# push secret. Tekton merges all SA secrets into a single docker config, and
# if the pull-only credential wins the merge for that registry, oras attach
# fails with "unauthorized". Removing the pull-only secret avoids the
# conflict — the push secret includes pull permission so nothing is lost.
#
# NOTE: select-oci-auth (used by the oras attach step action) does NOT avoid
# this. Both secrets key their auth at the identical repo path, so Tekton's
# merge keeps only one token; select-oci-auth only disambiguates across
# *different* keys and runs after the merge. So this removal is still required.
PULL_SECRET="${PULL_SECRET:-ec-main-pull}"

# The push secret must live in BOTH secret lists on the SA, because two
# different consumers read two different fields:
#
#   secrets          - Tekton's credential init mounts these into task steps as
#                      ~/.docker/config.json. This is what lets the oras attach
#                      step action push. (The original POC only touched this.)
#   imagePullSecrets - Tekton Chains authenticates to the registry via k8schain,
#                      which reads ONLY imagePullSecrets (not .secrets). Without
#                      the push secret here, Chains can't push the attestation and
#                      the run ends with chains.tekton.dev/signed=failed, so no
#                      attestation is ever created for the built artifact.
#
# The pull-only-secret removal (see above) applies to both fields for the same
# reason: co-located pull/push creds for the same repo collide in the merged
# docker config / keyring, and if the pull-only credential wins, the push fails.
SA_SECRET_FIELDS=(secrets imagePullSecrets)

usage() {
  cat <<EOF
Usage: $(basename "$0") [--revert] [--help]

  (no args)   Grant push access: remove the conflicting pull-only secret and add
              the push secret to the ${INTEGRATION_SA} ServiceAccount.
  --revert    Restore the pull-only state: remove the push secret and re-add the
              pull-only secret.

Environment overrides: NAMESPACE, PUSH_SECRET, PULL_SECRET.
EOF
}

# Returns 0 if the integration SA already lists the named secret in the given
# field (secrets or imagePullSecrets).
sa_has_secret() {
  local field="$1" secret="$2"
  oc get sa "${INTEGRATION_SA}" -n "${NAMESPACE}" -o json | python3 -c "
import json, sys
field, secret = sys.argv[1], sys.argv[2]
secrets = [s['name'] for s in json.load(sys.stdin).get(field, [])]
sys.exit(0 if secret in secrets else 1)
" "${field}" "${secret}"
}

# Link the named secret to the integration SA field (no-op if already present).
link_secret() {
  local field="$1" secret="$2"
  if sa_has_secret "${field}" "${secret}"; then
    echo "Secret '${secret}' already linked to SA '${INTEGRATION_SA}' (${field})"
  else
    echo "Adding secret '${secret}' to SA '${INTEGRATION_SA}' (${field})"
    oc patch sa "${INTEGRATION_SA}" -n "${NAMESPACE}" --type=json \
      -p="[{\"op\":\"add\",\"path\":\"/${field}/-\",\"value\":{\"name\":\"${secret}\"}}]"
  fi
}

# Unlink the named secret from the integration SA field (no-op if absent).
unlink_secret() {
  local field="$1" secret="$2"
  if ! sa_has_secret "${field}" "${secret}"; then
    echo "Secret '${secret}' not present on SA '${INTEGRATION_SA}' (${field}) (nothing to remove)"
    return
  fi
  echo "Removing secret '${secret}' from SA '${INTEGRATION_SA}' (${field})"
  local index
  index=$(oc get sa "${INTEGRATION_SA}" -n "${NAMESPACE}" -o json | python3 -c "
import json, sys
field, secret = sys.argv[1], sys.argv[2]
for i, s in enumerate(json.load(sys.stdin).get(field, [])):
    if s['name'] == secret:
        print(i)
        break
" "${field}" "${secret}")
  oc patch sa "${INTEGRATION_SA}" -n "${NAMESPACE}" --type=json \
    -p="[{\"op\":\"remove\",\"path\":\"/${field}/${index}\"}]"
}

grant_push() {
  echo "Granting push access on SA '${INTEGRATION_SA}' in namespace '${NAMESPACE}'"
  echo ""
  # Applied to every secret field so BOTH the oras attach step (.secrets) and
  # Tekton Chains (imagePullSecrets) can authenticate the push.
  for field in "${SA_SECRET_FIELDS[@]}"; do
    unlink_secret "${field}" "${PULL_SECRET}"
    link_secret "${field}" "${PUSH_SECRET}"
  done
  echo ""
  echo "Done. Verify with:"
  echo "  oc get sa ${INTEGRATION_SA} -n ${NAMESPACE} -o yaml"
}

revoke_push() {
  echo "Restoring pull-only state on SA '${INTEGRATION_SA}' in namespace '${NAMESPACE}'"
  echo ""
  # Exactly reverses grant_push over the same fields: drop the push secret and
  # restore the pull-only secret everywhere it was added.
  for field in "${SA_SECRET_FIELDS[@]}"; do
    unlink_secret "${field}" "${PUSH_SECRET}"
    link_secret "${field}" "${PULL_SECRET}"
  done
  echo ""
  echo "Done. Verify with:"
  echo "  oc get sa ${INTEGRATION_SA} -n ${NAMESPACE} -o yaml"
}

case "${1:-}" in
  --revert)     revoke_push ;;
  --help | -h)  usage ;;
  "")           grant_push ;;
  *)            echo "Unknown argument: $1" >&2; echo ""; usage; exit 1 ;;
esac
