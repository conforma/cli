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

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${SCRIPT_DIR}/inject-data-source.sh"
WORKDIR=$(mktemp -d)
trap 'rm -rf -- "$WORKDIR"' EXIT

printf '%s\n' '{"some_result":"whatever"}' > "$WORKDIR/runtime.json"

inject() {
  TMPDIR="$WORKDIR" bash "$SCRIPT" --policy "$1" --policy-output "$2" \
    --data-file "$WORKDIR/runtime.json" --top-level-key runtime_extra
}

# A JSON policy file is copied, not modified, and only the first source is updated.
printf '%s\n' '{"sources":[{"data":["existing"]},{"data":["other"]}]}' > "$WORKDIR/policy.json"
cp "$WORKDIR/policy.json" "$WORKDIR/original.json"
inject "$WORKDIR/policy.json" "$WORKDIR/output.json" > /dev/null
cmp "$WORKDIR/policy.json" "$WORKDIR/original.json"
jq -e '.sources[0].data[0] == "existing" and .sources[1].data == ["other"]' "$WORKDIR/output.json" > /dev/null
source_ref=$(jq -r '.sources[0].data[1]' "$WORKDIR/output.json")
[[ "$source_ref" == file://"$WORKDIR"/data-source-* ]]
jq -e '.runtime_extra.some_result == "whatever"' "${source_ref#file://}/data.json" > /dev/null

# Inline JSON and an omitted or null data list both produce a JSON policy.
inject '{"sources":[{}]}' "$WORKDIR/inline.json" > /dev/null
jq -e '.sources[0].data | length == 1' "$WORKDIR/inline.json" > /dev/null
printf '%s\n' '{"sources":[{"data":null}]}' > "$WORKDIR/null.json"
inject "$WORKDIR/null.json" "$WORKDIR/null-output.json" > /dev/null
jq -e '.sources[0].data | length == 1' "$WORKDIR/null-output.json" > /dev/null

# A local YAML file and a non-list data field fail with actionable errors.
printf 'sources:\n  - policy: []\n' > "$WORKDIR/policy.yaml"
if inject "$WORKDIR/policy.yaml" "$WORKDIR/yaml-output.json" > "$WORKDIR/stdout" 2> "$WORKDIR/stderr"; then
  echo 'Expected a YAML policy to be rejected' >&2
  exit 1
fi
grep -q 'Policy must contain a single JSON object' "$WORKDIR/stderr"
printf '%s\n' '{"sources":[{"data":{}}]}' > "$WORKDIR/bad-data.json"
if inject "$WORKDIR/bad-data.json" "$WORKDIR/bad-output.json" > "$WORKDIR/stdout" 2> "$WORKDIR/stderr"; then
  echo 'Expected a non-list data field to be rejected' >&2
  exit 1
fi
grep -q 'sources\[0\].data must be a list' "$WORKDIR/stderr"

printf 'inject-data-source.sh tests passed\n'
