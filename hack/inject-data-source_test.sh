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

printf '%s\n' '{"foo":"bar","zip":"zap"}' > "$WORKDIR/runtime.json"

inject() {
  TMPDIR="$WORKDIR" bash "$SCRIPT" --policy "$1" --policy-output "$2" \
    --data-file "$WORKDIR/runtime.json" --data-key collector_data
}

PASS=0
passed() {
  printf '  PASS: %s\n' "$1"
  ((PASS += 1))
}

echo 'Test 1: JSON policy spec is copied and only the first source is updated'
printf '%s\n' '{"sources":[{"data":["existing"]},{"data":["other"]}]}' > "$WORKDIR/policy.json"
cp "$WORKDIR/policy.json" "$WORKDIR/original.json"
inject "$WORKDIR/policy.json" "$WORKDIR/output.json" > /dev/null
cmp "$WORKDIR/policy.json" "$WORKDIR/original.json"
jq -e '.sources[0].data[0] == "existing" and .sources[1].data == ["other"]' "$WORKDIR/output.json" > /dev/null
source_ref=$(jq -r '.sources[0].data[1]' "$WORKDIR/output.json")
[[ "$source_ref" == file://"$WORKDIR"/data-source-* ]]
jq -e '
  (keys == ["rule_data__runtime__"]) and
  .rule_data__runtime__.collector_data.foo == "bar" and
  .rule_data__runtime__.collector_data.zip == "zap"
' "${source_ref#file://}/data.json" > /dev/null
passed 'original policy spec unchanged; untrusted input is confined to the reserved namespace'

echo 'Test 2: complete JSON EnterpriseContractPolicy is copied and spec.sources[0] is updated'
printf '%s\n' '{"apiVersion":"appstudio.redhat.com/v1alpha1","kind":"EnterpriseContractPolicy","metadata":{"name":"example"},"spec":{"sources":[{"data":["existing"]},{"data":["other"]}]}}' > "$WORKDIR/full-policy.json"
cp "$WORKDIR/full-policy.json" "$WORKDIR/full-original.json"
inject "$WORKDIR/full-policy.json" "$WORKDIR/full-output.json" > /dev/null
cmp "$WORKDIR/full-policy.json" "$WORKDIR/full-original.json"
jq -e '.kind == "EnterpriseContractPolicy" and .metadata.name == "example" and .spec.sources[0].data[0] == "existing" and .spec.sources[1].data == ["other"] and (has("sources") | not)' "$WORKDIR/full-output.json" > /dev/null
source_ref=$(jq -r '.spec.sources[0].data[1]' "$WORKDIR/full-output.json")
[[ "$source_ref" == file://"$WORKDIR"/data-source-* ]]
jq -e '.rule_data__runtime__.collector_data.foo == "bar"' "${source_ref#file://}/data.json" > /dev/null
passed 'complete policy retains metadata and updates only spec.sources[0].data'

echo 'Test 3: inline JSON policy spec with an omitted data list'
inject '{"sources":[{}]}' "$WORKDIR/inline.json" > /dev/null
jq -e '.sources[0].data | length == 1' "$WORKDIR/inline.json" > /dev/null
passed 'data list created'

echo 'Test 4: inline JSON policy with leading whitespace'
inject $'\n \t {"sources":[{}]}' "$WORKDIR/whitespace-inline.json" > /dev/null
jq -e '.sources[0].data | length == 1' "$WORKDIR/whitespace-inline.json" > /dev/null
passed 'whitespace-prefixed inline policy accepted'

echo 'Test 5: JSON policy spec with a null data list'
printf '%s\n' '{"sources":[{"data":null}]}' > "$WORKDIR/null.json"
inject "$WORKDIR/null.json" "$WORKDIR/null-output.json" > /dev/null
jq -e '.sources[0].data | length == 1' "$WORKDIR/null-output.json" > /dev/null
passed 'null data list replaced with a list'

echo 'Test 6: YAML-formatted policy is rejected'
printf 'sources:\n  - policy: []\n' > "$WORKDIR/policy.yaml"
if inject "$WORKDIR/policy.yaml" "$WORKDIR/yaml-output.json" > "$WORKDIR/stdout" 2> "$WORKDIR/stderr"; then
  echo 'Expected a YAML policy to be rejected' >&2
  exit 1
fi
grep -q 'Policy must contain a single JSON object' "$WORKDIR/stderr"
passed 'JSON-only error reported'

echo 'Test 7: non-list data field is rejected'
printf '%s\n' '{"sources":[{"data":{}}]}' > "$WORKDIR/bad-data.json"
if inject "$WORKDIR/bad-data.json" "$WORKDIR/bad-output.json" > "$WORKDIR/stdout" 2> "$WORKDIR/stderr"; then
  echo 'Expected a non-list data field to be rejected' >&2
  exit 1
fi
grep -q 'sources\[0\].data must be a list' "$WORKDIR/stderr"
passed 'invalid data field reported'

echo 'Test 8: the standalone helper requires a data key'
if TMPDIR="$WORKDIR" bash "$SCRIPT" --policy "$WORKDIR/policy.json" \
  --policy-output "$WORKDIR/no-key-output.json" --data-file "$WORKDIR/runtime.json" \
  > "$WORKDIR/stdout" 2> "$WORKDIR/stderr"; then
  echo 'Expected a missing data key to be rejected' >&2
  exit 1
fi
grep -qF -- '--data-key are required' "$WORKDIR/stderr"
passed 'missing data key reported'

echo 'Test 9: nonexistent data file is rejected'
status=0
TMPDIR="$WORKDIR" bash "$SCRIPT" --policy "$WORKDIR/policy.json" \
  --policy-output "$WORKDIR/missing-data-output.json" \
  --data-file "$WORKDIR/missing-runtime-data.json" --data-key collector_data \
  > "$WORKDIR/stdout" 2> "$WORKDIR/stderr" || status=$?
if [[ "$status" -ne 1 ]]; then
  echo "Expected exit 1 for a nonexistent data file, got $status" >&2
  exit 1
fi
grep -qF "Data file does not exist: $WORKDIR/missing-runtime-data.json" "$WORKDIR/stderr"
passed 'nonexistent data file exits 1 with a clear error'

echo 'Test 10: ECP references without a spec report a clear error'
mkdir "$WORKDIR/bin"
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\\n" "$MOCK_ECP"' > "$WORKDIR/bin/kubectl"
chmod +x "$WORKDIR/bin/kubectl"
for policy in example test-namespace/example; do
  for ecp in '{}' '{"spec":null}'; do
    status=0
    PATH="$WORKDIR/bin:$PATH" MOCK_ECP="$ecp" \
      inject "$policy" "$WORKDIR/no-spec-output.json" \
      > "$WORKDIR/stdout" 2> "$WORKDIR/stderr" || status=$?
    if [[ "$status" -ne 1 ]]; then
      echo "Expected exit 1 for ECP $policy without a spec, got $status" >&2
      exit 1
    fi
    grep -qxF "Error: ECP $policy has no spec" "$WORKDIR/stderr"
  done
done
passed 'missing and null specs are reported for plain and namespaced ECP references'

printf '\nResults: %d passed, 0 failed\n' "$PASS"
