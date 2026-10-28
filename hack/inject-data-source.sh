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

# Wrap a JSON file under the reserved rule_data__runtime__ namespace
# and a caller-supplied child key, then add it to sources[0].data (or
# spec.sources[0].data for a complete policy object) in a copy of the policy.
# This namespace is for untrusted runtime input, not trusted policy
# data. --policy accepts a JSON file, inline JSON, or ECP reference;
# YAML-formatted files and Git policy references are not supported here.
# The original policy is never modified.
#
# Usage:
#   hack/inject-data-source.sh --policy <ref> --policy-output <path> \
#     --data-file <path> --data-key <key>
#
# The output policy and generated data directory must remain available until evaluation finishes.
# If the evaluator runs in another Tekton step, set TMPDIR to a shared volume
# (e.g. /var/workdir). Use a distinct child key for each invocation to
# avoid data merge conflicts.

set -o errexit
set -o nounset
set -o pipefail

usage() {
  echo "Usage: $0 --policy <ref> --policy-output <path> --data-file <path> --data-key <key>"
}

POLICY_OUTPUT=""
POLICY=""
DATA_FILE=""
DATA_KEY=""
RUNTIME_DATA_NAMESPACE="rule_data__runtime__"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --policy|--policy-output|--data-file|--data-key)
      if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
        echo "Error: $1 requires a value." >&2
        usage >&2
        exit 1
      fi
      case "$1" in
        --policy-output) POLICY_OUTPUT="$2" ;;
        --policy) POLICY="$2" ;;
        --data-file) DATA_FILE="$2" ;;
        --data-key) DATA_KEY="$2" ;;
      esac
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Error: Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$POLICY" || -z "$POLICY_OUTPUT" || -z "$DATA_FILE" || -z "$DATA_KEY" ]]; then
  echo "Error: --policy, --policy-output, --data-file, and --data-key are required." >&2
  usage >&2
  exit 1
fi

if [[ ! -f "$DATA_FILE" ]]; then
  echo "Error: Data file does not exist: $DATA_FILE" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required to edit the policy file." >&2
  exit 1
fi

if [[ -f "$POLICY" ]]; then
  if [[ "$POLICY" -ef "$POLICY_OUTPUT" ]]; then
    echo "Error: --policy-output must differ from the input policy file." >&2
    exit 1
  fi
  cp "$POLICY" "$POLICY_OUTPUT"
elif [[ "$POLICY" =~ ^[[:space:]]*\{ ]]; then
  printf '%s' "$POLICY" > "$POLICY_OUTPUT"
else
  # Accept only DNS-label ECP references here. Dotted names or namespaces,
  # if supported by a cluster, cannot be resolved by this helper.
  valid_ecp_ref='^[a-z0-9]([-a-z0-9]*[a-z0-9])?(/[a-z0-9]([-a-z0-9]*[a-z0-9])?)?$'
  if [[ "$POLICY" =~ $valid_ecp_ref ]]; then
    if [[ "$POLICY" == */* ]]; then
      namespace="${POLICY%%/*}"
      name="${POLICY##*/}"
      kubectl get enterprisecontractpolicy/"$name" -n "$namespace" -o json | jq '.spec' > "$POLICY_OUTPUT"
    else
      kubectl get enterprisecontractpolicy/"$POLICY" -o json | jq '.spec' > "$POLICY_OUTPUT"
    fi
    if jq -e '. == null' "$POLICY_OUTPUT" >/dev/null; then
      echo "Error: ECP $POLICY has no spec" >&2
      exit 1
    fi
  else
    echo "Error: Cannot add data to unsupported policy reference: $POLICY" >&2
    exit 1
  fi
fi

if ! jq -es 'length == 1 and (.[0] | type == "object")' "$POLICY_OUTPUT" >/dev/null 2>&1; then
  echo "Error: Policy must contain a single JSON object: $POLICY_OUTPUT" >&2
  exit 1
fi

# Complete policy objects keep sources under spec; policy specs keep them at the root.
# Only the first source is updated; other policy sources are left unchanged.
if ! jq -e '(if has("spec") then .spec else . end | .sources[0] | type) == "object"' "$POLICY_OUTPUT" >/dev/null; then
  echo "Error: Policy file must contain a sources[0] entry (under spec for a complete policy): $POLICY_OUTPUT" >&2
  exit 1
fi

# Kubernetes omits an empty data list when serializing a policy spec.
if ! jq -e '(if has("spec") then .spec else . end | .sources[0].data) as $data | $data == null or ($data | type) == "array"' "$POLICY_OUTPUT" >/dev/null; then
  echo "Error: sources[0].data must be a list if present: $POLICY_OUTPUT" >&2
  exit 1
fi

DATA_DIR=$(mktemp -d "${TMPDIR:-/tmp}/data-source-XXXXXX")
trap 'rm -rf -- "$DATA_DIR"' EXIT
DATA_DIR=$(cd "$DATA_DIR" && pwd -P)

# Require exactly one JSON value; jq --arg handles arbitrary child key strings.
jq -s --arg namespace "$RUNTIME_DATA_NAMESPACE" --arg key "$DATA_KEY" \
  'if length == 1 then {($namespace): {($key): .[0]}} else error("expected exactly one JSON value") end' \
  "$DATA_FILE" > "$DATA_DIR/data.json"

DATA_SOURCE="file://$DATA_DIR"
# jq cannot safely read and write the same file; replace only the output copy.
POLICY_TMP=$(mktemp "${POLICY_OUTPUT}.XXXXXX")
trap 'rm -rf -- "$DATA_DIR"; rm -f -- "$POLICY_TMP"' EXIT
jq -e --arg source "$DATA_SOURCE" \
  'if has("spec") then
    .spec.sources[0].data = ((.spec.sources[0].data // []) + [$source])
  else
    .sources[0].data = ((.sources[0].data // []) + [$source])
  end' "$POLICY_OUTPUT" > "$POLICY_TMP"
mv -- "$POLICY_TMP" "$POLICY_OUTPUT"

# Keep the directory for the evaluator; the caller can remove it afterwards.
trap - EXIT
printf 'Data from %s written to %s\n' "$DATA_FILE" "$DATA_DIR/data.json"
printf 'Data source %s added to %s\n' "$DATA_SOURCE" "$POLICY_OUTPUT"
