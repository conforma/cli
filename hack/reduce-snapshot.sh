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
# This script attempts to reduce a snapshot to a single component
# It determines the component via a custom resource's labels.
# It requires that the following environment variables be defined:
#
# - SINGLE_COMPONENT: true if single component mode is enabled.
# - SNAPSHOT: Path to Snapshot json file
# - CUSTOM_RESOURCE: Custom Resource to query for built component in Snapshot
# - CUSTOM_RESOURCE_NAMESPACE: Namespace where Custom Resource is found
# - SNAPSHOT_PATH: Same path as SNAPSHOT. The reduced Snapshot will be stored here.

set -o errexit
set -o nounset
set -o pipefail


# Make sure to move snapshot contents to the WORKING_SNAPSHOT location. Then allow jq to
# work with it there and prevent truncating the original. This avoids having to read
# SNAPSHOT to memory.

if [[ -f "$SNAPSHOT" ]]; then
  WORKING_SNAPSHOT="$(mktemp "${HOME:-/tmp}/snapshot.XXXXXX")"
  cp "$SNAPSHOT" "$WORKING_SNAPSHOT"
else
  WORKING_SNAPSHOT="$(mktemp "${HOME:-/tmp}/snapshot.XXXXXX")"
  printf "%s" "$SNAPSHOT" > "$WORKING_SNAPSHOT"
fi
jq empty "$WORKING_SNAPSHOT" || { echo "JSON is invalid"; exit 1; }

echo "Single Component mode? ${SINGLE_COMPONENT}"
if [ "${SINGLE_COMPONENT}" == "true" ]; then

  CR_NAMESPACE_ARG=
  if [ "${CUSTOM_RESOURCE_NAMESPACE}" != "" ]; then
    CR_NAMESPACE_ARG="-n ${CUSTOM_RESOURCE_NAMESPACE}"
  fi

  SNAPSHOT_CREATION_TYPE=$(kubectl get "$CUSTOM_RESOURCE" ${CR_NAMESPACE_ARG:+$CR_NAMESPACE_ARG} -ojson \
      | jq -r '.metadata.labels."test.appstudio.openshift.io/type" // ""')
  SNAPSHOT_CREATION_COMPONENT=$(kubectl get "$CUSTOM_RESOURCE" ${CR_NAMESPACE_ARG:+$CR_NAMESPACE_ARG} -ojson \
      | jq -r '.metadata.labels."appstudio.openshift.io/component" // ""')

  echo "SNAPSHOT_CREATION_TYPE: ${SNAPSHOT_CREATION_TYPE}"
  echo "SNAPSHOT_CREATION_COMPONENT: ${SNAPSHOT_CREATION_COMPONENT}"
  if [ "${SNAPSHOT_CREATION_TYPE}" == "component" ] && [ "${SNAPSHOT_CREATION_COMPONENT}" != "" ]; then
    echo "Single Component mode is ${SINGLE_COMPONENT} and Snapshot type is component"

    REDUCED_SNAPSHOT="$(mktemp /tmp/snapshot_reduced.XXXXXX)"
    jq --arg component "${SNAPSHOT_CREATION_COMPONENT}" \
    'del(.components[] | select(.name != $component))' "$WORKING_SNAPSHOT" > "$REDUCED_SNAPSHOT"

    COMPONENT_COUNT=$(jq -r '[ .components[] ] | length' "$REDUCED_SNAPSHOT")
    if [ "${COMPONENT_COUNT}" == "1" ]; then
      mv "$REDUCED_SNAPSHOT" "$WORKING_SNAPSHOT"
    else
      echo "Error: Reduced Snapshot has ${COMPONENT_COUNT} components. It should contain 1"
      echo "       Verify that the Snapshot contains the built component: ${SNAPSHOT_CREATION_COMPONENT}"
      echo "Using original Snapshot"
      exit 1
    fi

  fi
fi

# we need to create snapshot file to be passed to later stages.
jq '.' "${WORKING_SNAPSHOT}" | tee "${SNAPSHOT_PATH}"
