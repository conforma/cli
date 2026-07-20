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
# Tests for pin-konflux-policy-bundle.sh
#
# Run: bash hack/pin-konflux-policy-bundle_test.sh

set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${SCRIPT_DIR}/pin-konflux-policy-bundle.sh"

# On macOS, sed -i behaves differently. Use GNU sed if available.
if [[ "$(uname)" == "Darwin" ]] && command -v gsed &>/dev/null; then
  mkdir -p /tmp/pin-test-bin
  ln -sf "$(command -v gsed)" /tmp/pin-test-bin/sed
  export PATH="/tmp/pin-test-bin:${PATH}"
fi

PASS=0
FAIL=0

assert_contains() {
  local file="$1" expected="$2" label="$3"
  if grep -qF "$expected" "$file"; then
    echo "  PASS: $label"
    (( PASS++ ))
  else
    echo "  FAIL: $label"
    echo "    expected to contain: $expected"
    echo "    actual content: $(cat "$file")"
    (( FAIL++ ))
  fi
}

assert_not_contains() {
  local file="$1" unexpected="$2" label="$3"
  if grep -qF "$unexpected" "$file"; then
    echo "    FAIL: $label"
    echo "    should not contain: $unexpected"
    echo "    actual content: $(cat "$file")"
    (( FAIL++ ))
  else
    echo "  PASS: $label"
    (( PASS++ ))
  fi
}

NEW_DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OLD_DIGEST="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# -------------------------------------------------------------------
echo "Test 1: tag-only reference is replaced"
# -------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
export HOME="${TMPDIR}"
POLICY_FILE="${TMPDIR}/policy.json"
cat > "$POLICY_FILE" <<'EOF'
{"sources":[{"policy":["oci::quay.io/conforma/release-policy:konflux"]}]}
EOF
POLICY_CONFIGURATION="$POLICY_FILE" POLICY_BUNDLE_DIGEST="$NEW_DIGEST" \
  bash "$SCRIPT" > /dev/null

assert_contains "${HOME}/policy-with-pinned-bundle.yaml" \
  "oci::quay.io/conforma/release-policy@${NEW_DIGEST}" \
  "new digest present"
assert_not_contains "${HOME}/policy-with-pinned-bundle.yaml" \
  ":konflux" \
  "tag removed"
rm -rf "$TMPDIR"

# -------------------------------------------------------------------
echo "Test 2: already-pinned reference is left alone"
# -------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
export HOME="${TMPDIR}"
POLICY_FILE="${TMPDIR}/policy.json"
cat > "$POLICY_FILE" <<EOF
{"sources":[{"policy":["oci::quay.io/conforma/release-policy:konflux@${OLD_DIGEST}"]}]}
EOF
POLICY_CONFIGURATION="$POLICY_FILE" POLICY_BUNDLE_DIGEST="$NEW_DIGEST" \
  bash "$SCRIPT" > /dev/null

if [[ ! -f "${HOME}/policy-with-pinned-bundle.yaml" ]]; then
  echo "  PASS: no output file created (existing pin respected)"
  (( PASS++ ))
else
  echo "  FAIL: should not override an already-pinned digest"
  (( FAIL++ ))
fi
rm -rf "$TMPDIR"

# -------------------------------------------------------------------
echo "Test 3: unrelated policy references are not modified"
# -------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
export HOME="${TMPDIR}"
POLICY_FILE="${TMPDIR}/policy.json"
TASK_REF="oci::quay.io/conforma/task-policy:konflux@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
cat > "$POLICY_FILE" <<EOF
{"sources":[{"policy":["oci::quay.io/conforma/release-policy:konflux","${TASK_REF}"]}]}
EOF
POLICY_CONFIGURATION="$POLICY_FILE" POLICY_BUNDLE_DIGEST="$NEW_DIGEST" \
  bash "$SCRIPT" > /dev/null

assert_contains "${HOME}/policy-with-pinned-bundle.yaml" \
  "$TASK_REF" \
  "unrelated task-policy reference unchanged"
assert_contains "${HOME}/policy-with-pinned-bundle.yaml" \
  "oci::quay.io/conforma/release-policy@${NEW_DIGEST}" \
  "release-policy tag replaced"
rm -rf "$TMPDIR"

# -------------------------------------------------------------------
echo "Test 4: empty POLICY_BUNDLE_DIGEST is a no-op"
# -------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
export HOME="${TMPDIR}"
POLICY_FILE="${TMPDIR}/policy.json"
cat > "$POLICY_FILE" <<'EOF'
{"sources":[{"policy":["oci::quay.io/conforma/release-policy:konflux"]}]}
EOF
POLICY_CONFIGURATION="$POLICY_FILE" POLICY_BUNDLE_DIGEST="" \
  bash "$SCRIPT" > /dev/null

if [[ ! -f "${HOME}/policy-with-pinned-bundle.yaml" ]]; then
  echo "  PASS: no output file created"
  (( PASS++ ))
else
  echo "  FAIL: output file should not exist for empty digest"
  (( FAIL++ ))
fi
rm -rf "$TMPDIR"

# -------------------------------------------------------------------
echo "Test 5: digest without sha256: prefix is normalized"
# -------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
export HOME="${TMPDIR}"
POLICY_FILE="${TMPDIR}/policy.json"
BARE_HEX="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
cat > "$POLICY_FILE" <<'EOF'
{"sources":[{"policy":["oci::quay.io/conforma/release-policy:konflux"]}]}
EOF
POLICY_CONFIGURATION="$POLICY_FILE" POLICY_BUNDLE_DIGEST="$BARE_HEX" \
  bash "$SCRIPT" > /dev/null

assert_contains "${HOME}/policy-with-pinned-bundle.yaml" \
  "oci::quay.io/conforma/release-policy@sha256:${BARE_HEX}" \
  "sha256: prefix added"
rm -rf "$TMPDIR"

# -------------------------------------------------------------------
echo "Test 6: inline JSON with tag-only reference"
# -------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
export HOME="${TMPDIR}"
INLINE_JSON='{"sources":[{"policy":["oci::quay.io/conforma/release-policy:konflux"]}]}'
POLICY_CONFIGURATION="$INLINE_JSON" POLICY_BUNDLE_DIGEST="$NEW_DIGEST" \
  bash "$SCRIPT" > /dev/null

assert_contains "${HOME}/policy-with-pinned-bundle.yaml" \
  "oci::quay.io/conforma/release-policy@${NEW_DIGEST}" \
  "new digest present in inline JSON"
assert_not_contains "${HOME}/policy-with-pinned-bundle.yaml" \
  ":konflux" \
  "tag removed from inline JSON"
rm -rf "$TMPDIR"

# -------------------------------------------------------------------
echo "Test 7: inline JSON with already-pinned digest is a no-op"
# -------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
export HOME="${TMPDIR}"
INLINE_JSON='{"sources":[{"policy":["oci::quay.io/conforma/release-policy:konflux@'"${OLD_DIGEST}"'"]}]}'
POLICY_CONFIGURATION="$INLINE_JSON" POLICY_BUNDLE_DIGEST="$NEW_DIGEST" \
  bash "$SCRIPT" > /dev/null

if [[ ! -f "${HOME}/policy-with-pinned-bundle.yaml" ]]; then
  echo "  PASS: no output file created (existing pin respected in inline JSON)"
  (( PASS++ ))
else
  echo "  FAIL: should not override an already-pinned digest in inline JSON"
  (( FAIL++ ))
fi
rm -rf "$TMPDIR"

# -------------------------------------------------------------------
echo "Test 8: idempotent re-run after pinning"
# -------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
export HOME="${TMPDIR}"
POLICY_FILE="${TMPDIR}/policy.json"
# Simulate a policy file that was already processed: tag replaced with digest,
# no :konflux tag remains. The grep guard should cause a clean early exit.
cat > "$POLICY_FILE" <<EOF
{"sources":[{"policy":["oci::quay.io/conforma/release-policy@${OLD_DIGEST}"]}]}
EOF
POLICY_CONFIGURATION="$POLICY_FILE" POLICY_BUNDLE_DIGEST="$NEW_DIGEST" \
  bash "$SCRIPT" > /dev/null

if [[ ! -f "${HOME}/policy-with-pinned-bundle.yaml" ]]; then
  echo "  PASS: no output file created (no :konflux tag to match)"
  (( PASS++ ))
else
  echo "  FAIL: should not produce output when :konflux tag is absent"
  (( FAIL++ ))
fi
rm -rf "$TMPDIR"

# -------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if (( FAIL > 0 )); then
  exit 1
fi
