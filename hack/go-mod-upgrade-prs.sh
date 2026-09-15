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

#
# Create go module upgrade PRs for all active release branches.
#
# Usage:
#   hack/go-mod-upgrade-prs.sh github.com/sigstore/fulcio
#   hack/go-mod-upgrade-prs.sh github.com/sigstore/fulcio main
#   hack/go-mod-upgrade-prs.sh github.com/sigstore/fulcio release-v0.8 main
#   hack/go-mod-upgrade-prs.sh github.com/sigstore/fulcio --jira EC-1234
#   hack/go-mod-upgrade-prs.sh github.com/sigstore/fulcio --ignore-tidy-error
#
# The script is attended — it pauses for confirmation before creating each PR.
#

set -o errexit
set -o nounset
set -o pipefail

# --- Parse arguments ----------------------------------------------------------
JIRA=""
HELPER_ARGS=()
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --jira)
      if [[ $# -lt 2 ]]; then
        echo "Error: --jira requires a value, e.g. --jira EC-1234"
        exit 1
      fi
      JIRA="$2"
      shift 2
      ;;
    --ignore-tidy-error)
      HELPER_ARGS+=("--ignore-tidy-error")
      shift
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL[@]} -lt 1 ]]; then
  echo "Usage: $0 <go-module-path> [branch ...]"
  echo "  e.g. $0 github.com/sigstore/fulcio"
  echo "  e.g. $0 github.com/sigstore/fulcio --jira EC-1234 main"
  exit 1
fi

PKG="${POSITIONAL[0]}"
PKG_SHORT="${PKG##*/}"

if [[ ${#POSITIONAL[@]} -gt 1 ]]; then
  BRANCHES=("${POSITIONAL[@]:1}")
else
  BRANCHES=(release-v0.7 release-v0.8 main)
fi

# --- Configuration -----------------------------------------------------------

# Adjust as needed
UPSTREAM_REMOTE=upstream
PUSH_REMOTE=origin

# --- Prerequisites ------------------------------------------------------------

PREREQS=(go gh)

for cmd in "${PREREQS[@]}"; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: $cmd is required but not found."
    exit 1
  fi
done

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Error: working tree has uncommitted changes. Commit or stash first."
  exit 1
fi

# --- Setup --------------------------------------------------------------------

ORIGINAL_BRANCH=$(git rev-parse --abbrev-ref HEAD)
cleanup() { git checkout "$ORIGINAL_BRANCH" 2>/dev/null || true; }
trap cleanup EXIT

echo "=== Fetching $UPSTREAM_REMOTE ==="
git fetch "$UPSTREAM_REMOTE"
echo

CREATED_PRS=()

# --- Per-branch loop ----------------------------------------------------------

for BRANCH in "${BRANCHES[@]}"; do
  echo "============================================"
  echo "  $BRANCH - $PKG"
  echo "============================================"

  # Find all go.mod files on this branch and check which ones use the package
  unset OLD_VERSIONS
  declare -A OLD_VERSIONS
  MODULE_PATHS=()
  while IFS= read -r gomod_path; do
    if git show "$UPSTREAM_REMOTE/$BRANCH:$gomod_path" 2>/dev/null | grep -qF "$PKG"; then
      VERSION=$(git show "$UPSTREAM_REMOTE/$BRANCH:$gomod_path" \
        | sed -nE "s|.*${PKG} (v[^ ]+).*|\1|p" | head -1)
      MODULE_PATHS+=("$gomod_path")
      OLD_VERSIONS["$gomod_path"]="${VERSION:-unknown}"
    fi
  done < <(git ls-tree -r --name-only "$UPSTREAM_REMOTE/$BRANCH" | grep 'go\.mod$')

  if [[ ${#MODULE_PATHS[@]} -eq 0 ]]; then
    echo "$PKG not found in any go.mod on $BRANCH, skipping."
    echo
    continue
  fi

  echo "Current versions:"
  for path in "${MODULE_PATHS[@]}"; do
    echo "  $path: ${OLD_VERSIONS[$path]}"
  done

  # Checkout working branch
  WORK_BRANCH="go-mod-upgrade-${PKG_SHORT}-${BRANCH}"
  git checkout -B "$WORK_BRANCH" "$UPSTREAM_REMOTE/$BRANCH" --no-track
  echo

  # Run the upgrade helper (it creates its own commit)
  HELPER_CMD_ARGS=("$PKG")
  [[ -n "$JIRA" ]] && HELPER_CMD_ARGS+=("$JIRA")
  HELPER_CMD_ARGS+=("${HELPER_ARGS[@]}")

  HEAD_BEFORE=$(git rev-parse HEAD)
  if ! hack/go-mod-upgrade-helper.sh "${HELPER_CMD_ARGS[@]}"; then
    echo "go-mod-upgrade-helper.sh failed for $BRANCH, skipping."
    git reset --hard "$UPSTREAM_REMOTE/$BRANCH"
    echo
    continue
  fi
  HEAD_AFTER=$(git rev-parse HEAD)

  if [[ "$HEAD_BEFORE" == "$HEAD_AFTER" ]]; then
    echo "No changes produced for $BRANCH, skipping."
    echo
    continue
  fi

  # Extract new versions from each tracked module's go.mod
  unset NEW_VERSIONS
  declare -A NEW_VERSIONS
  for path in "${MODULE_PATHS[@]}"; do
    VERSION=$(sed -nE "s|.*${PKG} (v[^ ]+).*|\1|p" "$path" | head -1)
    NEW_VERSIONS["$path"]="${VERSION:-unknown}"
  done

  echo
  echo "Version changes:"
  for path in "${MODULE_PATHS[@]}"; do
    echo "  $path: ${OLD_VERSIONS[$path]} → ${NEW_VERSIONS[$path]}"
  done
  echo
  echo "Changes:"
  git log -1 --stat
  echo

  # --- Prompt ---------------------------------------------------------------

  read -rp ">>> Create PR for $BRANCH? [y/N] " answer
  echo
  case "$answer" in
    [yY]) ;;
    *)
      echo "Skipping $BRANCH."
      git reset --hard "$UPSTREAM_REMOTE/$BRANCH"
      echo
      continue
      ;;
  esac

  # --- Push -----------------------------------------------------------------

  if ! git push -u "$PUSH_REMOTE" "$WORK_BRANCH"; then
    echo
    echo "Push failed — remote branch may already exist."
    LEASE_SHA=$(git rev-parse "$PUSH_REMOTE/$WORK_BRANCH" 2>/dev/null || git rev-parse HEAD)
    read -rp ">>> Retry with --force-with-lease? [y/N] " force_answer
    case "$force_answer" in
    [yY])
      git push --force-with-lease="$WORK_BRANCH:$LEASE_SHA" -u "$PUSH_REMOTE" "$WORK_BRANCH"
      ;;
    *)
      echo "Skipping PR for $BRANCH."
      echo
      continue
      ;;
    esac
  fi

  # --- Create PR ------------------------------------------------------------

  PR_TITLE="chore(deps): Update ${PKG} (${BRANCH#release-})"
  PR_BODY="Update \`$PKG\` module dependency.

**Version changes:**"
  for path in "${MODULE_PATHS[@]}"; do
    PR_BODY="$PR_BODY
- \`$path\`: \`${OLD_VERSIONS[$path]}\` → \`${NEW_VERSIONS[$path]}\`"
  done

  if [[ -n "$JIRA" ]]; then
    PR_BODY="$PR_BODY

Ref: https://redhat.atlassian.net/browse/$JIRA"
  fi

  PR_URL=$(gh pr create \
    --base "$BRANCH" \
    --title "$PR_TITLE" \
    --body "$PR_BODY")

  CREATED_PRS+=("$BRANCH: $PR_URL")
  echo "Created: $PR_URL"
  echo
done

# --- Summary ------------------------------------------------------------------

echo
echo "============================================"
echo "  Summary"
echo "============================================"
if [[ ${#CREATED_PRS[@]} -gt 0 ]]; then
  for pr in "${CREATED_PRS[@]}"; do
    echo "  $pr"
  done
else
  echo "  No PRs created."
fi
echo
