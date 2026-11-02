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
# Tests for sync-build-definitions-pipeline.sh
#
# Run: bash hack/sync-build-definitions-pipeline_test.sh

set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${SCRIPT_DIR}/sync-build-definitions-pipeline.sh"

PASS=0
FAIL=0

assert_equals() {
  local actual="$1" expected="$2" label="$3"
  if [[ "${actual}" == "${expected}" ]]; then
    echo "  PASS: ${label}"
    (( PASS++ ))
  else
    echo "  FAIL: ${label}"
    echo "    expected: ${expected}"
    echo "    actual:   ${actual}"
    (( FAIL++ ))
  fi
}

assert_task_bundle() {
  local target="$1" task="$2" expected="$3" label="$4"
  local actual
  actual="$(task_bundle "${target}" "${task}")"
  assert_equals "${actual}" "${expected}" "${label}"
}

set_task_bundle() {
  local target="$1" task="$2" bundle="$3"
  TASK="${task}" BUNDLE="${bundle}" perl -0pi -e '
    my $task = quotemeta($ENV{TASK});
    my $bundle = $ENV{BUNDLE};
    s{
      (^ [ ]{4} - [ ] name: [ ] $task \n
      (?:(?!^ [ ]{4} - [ ] name: [ ]).)*?
      ^ [ ]+ - [ ] name: [ ] bundle \n
      ^ [ ]+ value: [ ] ) \S+
    }{$1$bundle}gmsx;
  ' "${target}"
}

run_check() {
  local build_definitions="$1"
  if bash "${SCRIPT}" --check "${build_definitions}" >/dev/null; then
    echo "  PASS: --check accepts preserved bundle pins"
    (( PASS++ ))
  else
    echo "  FAIL: --check should accept preserved bundle pins"
    (( FAIL++ ))
  fi
}

# -------------------------------------------------------------------
echo "Test 1: write mode and --check preserve distinct task bundle pins"
# -------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

BUILD_DEFINITIONS="${TMPDIR}/build-definitions"
BIN_DIR="${TMPDIR}/bin"
TARGET="${BUILD_DEFINITIONS}/pipelines/enterprise-contract.yaml"
FIRST_TASK="collect-keyless-params"
SECOND_TASK="verify"
FIRST_PIN="quay.io/enterprise-contract/tekton-task:first@sha256:1111111111111111111111111111111111111111111111111111111111111111"
SECOND_PIN="quay.io/enterprise-contract/tekton-task:second@sha256:2222222222222222222222222222222222222222222222222222222222222222"

task_bundle() {
  local target="$1" task="$2"
  TASK="${task}" perl -0ne '
    my $task = quotemeta($ENV{TASK});
    if (/
      ^ [ ]{4} - [ ] name: [ ] $task \n
      (?:(?!^ [ ]{4} - [ ] name: [ ]).)*?
      ^ [ ]+ - [ ] name: [ ] bundle \n
      ^ [ ]+ value: [ ] (\S+)
    /msx) {
      print "$1\n";
    }
  ' "${target}"
}

mkdir -p "${BUILD_DEFINITIONS}" "${BIN_DIR}"
cat > "${BIN_DIR}/yq" <<'EOF'
#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

expr="${3}"
file="${4}"

task_bundle() {
  TASK="${TASK}" perl -0ne '
    my $task = quotemeta($ENV{TASK});
    if (/
      ^ [ ]{4} - [ ] name: [ ] $task \n
      (?:(?!^ [ ]{4} - [ ] name: [ ]).)*?
      ^ [ ]+ - [ ] name: [ ] bundle \n
      ^ [ ]+ value: [ ] (\S+)
    /msx) {
      print "$1\n";
    }
  ' "${file}"
}

case "${expr}" in
  ".spec.tasks[].name")
    printf '%s\n' collect-keyless-params verify
    ;;
  '.spec.tasks[] | select(.name == env(TASK)) | .taskRef.params[]? | select(.name == "bundle") | .value')
    task_bundle
    ;;
  *)
    echo "unexpected yq expression in test: ${expr}" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${BIN_DIR}/yq"
export PATH="${BIN_DIR}:${PATH}"

bash "${SCRIPT}" --no-preserve-bundle-refs "${BUILD_DEFINITIONS}" >/dev/null

set_task_bundle "${TARGET}" "${FIRST_TASK}" "${FIRST_PIN}"
set_task_bundle "${TARGET}" "${SECOND_TASK}" "${SECOND_PIN}"

bash "${SCRIPT}" "${BUILD_DEFINITIONS}" >/dev/null

assert_task_bundle "${TARGET}" "${FIRST_TASK}" "${FIRST_PIN}" "write mode preserves first task pin"
assert_task_bundle "${TARGET}" "${SECOND_TASK}" "${SECOND_PIN}" "write mode preserves second task pin"
run_check "${BUILD_DEFINITIONS}"
assert_task_bundle "${TARGET}" "${FIRST_TASK}" "${FIRST_PIN}" "--check leaves first task pin unchanged"
assert_task_bundle "${TARGET}" "${SECOND_TASK}" "${SECOND_PIN}" "--check leaves second task pin unchanged"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if (( FAIL > 0 )); then
  exit 1
fi
