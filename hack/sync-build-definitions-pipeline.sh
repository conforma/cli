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

set -o errexit
set -o pipefail
set -o nounset

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly SOURCE="${ROOT}/pipelines/enterprise-contract/0.1/enterprise-contract.yaml"
readonly DEFAULT_TARGET="pipelines/enterprise-contract.yaml"

check=false
preserve_bundle_refs=true
target_file="${DEFAULT_TARGET}"

function usage() {
    cat <<EOF
Usage:
  $(basename "${0}") [--check] [--no-preserve-bundle-refs] [--target-file PATH] <PATH_TO_BUILD_DEFINITIONS>

Sync the deprecated build-definitions Enterprise Contract ITS pipeline copy from:
  ${SOURCE#${ROOT}/}

By default, existing task bundle references in the build-definitions copy are
preserved. This keeps release-promotion digest pins intact while still syncing
pipeline parameters, task wiring, results, comments, and other structure from
the Conforma CLI source of truth.

Options:
  --check                    Report drift without writing to build-definitions.
  --no-preserve-bundle-refs  Copy task bundle references exactly from Conforma CLI.
  --target-file PATH         Path inside build-definitions to update
                             (default: ${DEFAULT_TARGET}).
  -h, --help                 Show this help.
EOF
}

while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        --check)
            check=true
            shift
            ;;
        --no-preserve-bundle-refs)
            preserve_bundle_refs=false
            shift
            ;;
        --target-file)
            if [[ "${#}" -lt 2 ]]; then
                echo "error: --target-file requires a value" >&2
                exit 2
            fi
            target_file="${2}"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*)
            echo "error: unknown option: ${1}" >&2
            usage >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

if [[ "${#}" -ne 1 ]]; then
    usage >&2
    exit 2
fi

if ! command -v yq >/dev/null 2>&1; then
    echo "error: yq is required" >&2
    exit 1
fi

readonly target_dir="${1}"
readonly target="${target_dir%/}/${target_file}"

if [[ ! -d "${target_dir}" ]]; then
    echo "error: build-definitions checkout not found: ${target_dir}" >&2
    exit 1
fi

tmp="$(mktemp "${TMPDIR:-/tmp}/ec-build-definitions-pipeline.XXXXXX")"
function cleanup() {
    rm -f "${tmp}"
}
trap cleanup EXIT

cat > "${tmp}" <<'EOF'
# DEPRECATED: The source of truth for this pipeline has moved to:
#   https://github.com/conforma/cli/blob/main/pipelines/enterprise-contract/0.1/enterprise-contract.yaml
# It is also published to:
#   https://github.com/conforma/tekton-catalog/blob/main/pipelines/enterprise-contract/0.1/enterprise-contract.yaml
# This copy is retained for backward compatibility. Keep it in sync with the
# Conforma CLI source while consumers migrate to the new location.
#
EOF

awk '
    copy { print }
    /^# SPDX-License-Identifier: Apache-2.0$/ {
        getline
        copy = 1
    }
' "${SOURCE}" >> "${tmp}"

# The deprecated build-definitions copy can carry release-promotion digest pins
# that intentionally differ from the unpinned source-of-truth pipeline.
if [[ "${preserve_bundle_refs}" == true && -f "${target}" ]]; then
    while IFS= read -r task; do
        source_bundle="$(
            TASK="${task}" yq e -r \
                '.spec.tasks[] | select(.name == env(TASK)) | .taskRef.params[]? | select(.name == "bundle") | .value' \
                "${SOURCE}"
        )"
        bundle="$(
            TASK="${task}" yq e -r \
                '.spec.tasks[] | select(.name == env(TASK)) | .taskRef.params[]? | select(.name == "bundle") | .value' \
                "${target}"
        )"
        if [[ -n "${source_bundle}" && "${source_bundle}" != "null" && -n "${bundle}" && "${bundle}" != "null" ]]; then
            TASK="${task}" BUNDLE="${bundle}" perl -0pi -e '
                my $task = quotemeta($ENV{TASK});
                my $bundle = $ENV{BUNDLE};
                s{
                    (^ [ ]{4} - [ ] name: [ ] $task \n
                    (?:(?!^ [ ]{4} - [ ] name: [ ]).)*?
                    ^ [ ]+ - [ ] name: [ ] bundle \n
                    ^ [ ]+ value: [ ] ) \S+
                }{$1$bundle}gmsx;
            ' \
                "${tmp}"
        fi
    done < <(yq e -r '.spec.tasks[].name' "${SOURCE}")
fi

if [[ "${check}" == true ]]; then
    if [[ -f "${target}" ]] && cmp -s "${tmp}" "${target}"; then
        echo "${target_file} is in sync"
        exit 0
    fi

    echo "${target_file} is out of sync" >&2
    if [[ -f "${target}" ]]; then
        diff -u "${target}" "${tmp}" || true
    else
        echo "missing target file: ${target}" >&2
    fi
    exit 1
fi

mkdir -p "$(dirname "${target}")"
cp "${tmp}" "${target}"
echo "Updated ${target}"
