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
# Create UBI base image bump PRs for all active release branches.
#
# Usage:
#   hack/ubi-bump-prs.sh                          # all default branches
#   hack/ubi-bump-prs.sh main                     # specific branch(es)
#   hack/ubi-bump-prs.sh release-v0.8 main        # multiple specific branches
#
# The script is attended — it pauses for confirmation before creating each PR.
#

set -o errexit
set -o nounset
set -o pipefail

# --- Parse arguments ----------------------------------------------------------
JIRA=""
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
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done


if [[ ${#POSITIONAL[@]} -gt 0 ]]; then
  BRANCHES=("${POSITIONAL[@]}")
else
  BRANCHES=(release-v0.7 release-v0.8 main)
fi

# --- Configuration -----------------------------------------------------------

# Adjust as needed
UPSTREAM_REMOTE=upstream
PUSH_REMOTE=origin

UBI_MINIMAL_REPO=registry.access.redhat.com/ubi9/ubi-minimal
UBI_MINIMAL="${UBI_MINIMAL_REPO}:latest"


# --- Prerequisites ------------------------------------------------------------

PREREQS=(skopeo podman sha256sum gh)

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

echo "=== Checking latest $UBI_MINIMAL digest ==="
LATEST_DIGEST=$(skopeo inspect --raw docker://"$UBI_MINIMAL" | sha256sum | awk '{print $1}')
echo "Latest: sha256:${LATEST_DIGEST:0:16}..."
echo

CREATED_PRS=()

# --- Per-branch loop ----------------------------------------------------------

for BRANCH in "${BRANCHES[@]}"; do
  echo "============================================"
  echo "  $BRANCH"
  echo "============================================"

  if ! OLD_DIGEST=$(git show "$UPSTREAM_REMOTE/$BRANCH:Dockerfile" 2>/dev/null \
    | sed -nE 's/.*ubi-minimal:latest@sha256:([0-9a-f]{64}).*/\1/p' | head -1) || [[ -z "$OLD_DIGEST" ]]; then
    echo "Could not extract current digest for $BRANCH, skipping."
    echo
    continue
  fi

  if [[ "$OLD_DIGEST" == "$LATEST_DIGEST" ]]; then
    echo "Already up to date on $BRANCH, skipping."
    echo
    continue
  fi

  echo "Old digest: sha256:${OLD_DIGEST:0:16}..."
  echo "New digest: sha256:${LATEST_DIGEST:0:16}..."
  echo

  # Checkout working branch
  WORK_BRANCH="ubi-bump-${BRANCH}"
  git checkout -B "$WORK_BRANCH" "$UPSTREAM_REMOTE/$BRANCH" --no-track
  echo

  # Run the existing bump script (no commit)
  if ! hack/ubi-base-image-bump.sh --no-commit; then
    echo "ubi-base-image-bump.sh failed for $BRANCH, skipping."
    git reset --hard "$UPSTREAM_REMOTE/$BRANCH"
    echo
    continue
  fi

  # Verify the new digest (use whatever the bump script actually wrote)
  NEW_DIGEST=$(sed -nE 's/.*ubi-minimal:latest@sha256:([0-9a-f]{64}).*/\1/p' Dockerfile | head -1)
  if [[ -z "$NEW_DIGEST" ]]; then
    echo "Error: could not extract ubi-minimal digest from Dockerfile after bump"
    git reset --hard "$UPSTREAM_REMOTE/$BRANCH"
    continue
  fi
  echo
  echo "Digest after bump: sha256:${NEW_DIGEST:0:16}..."

  # Generate RPM diff (will use the native arch of whoever runs this script)
  echo
  echo "Pulling images for RPM comparison..."
  OLD_RPMS=$(podman run --rm "${UBI_MINIMAL_REPO}@sha256:$OLD_DIGEST" rpm -qa | sort)
  NEW_RPMS=$(podman run --rm "${UBI_MINIMAL_REPO}@sha256:$NEW_DIGEST" rpm -qa | sort)

  RPM_DIFF=$(diff \
    --old-line-format='- %L' \
    --new-line-format='+ %L' \
    --unchanged-line-format='' \
    <(echo "$OLD_RPMS") <(echo "$NEW_RPMS") || true)

  echo
  if [[ -n "$RPM_DIFF" ]]; then
    echo "RPM changes:"
    echo "$RPM_DIFF"
  else
    echo "No RPM changes detected."
  fi

  echo
  echo "File changes:"
  git diff --stat
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

  # --- Commit ---------------------------------------------------------------

  COMMIT_MSG="chore(deps): Update ubi-minimal base image

Old digest: sha256:$OLD_DIGEST
New digest: sha256:$NEW_DIGEST"

  if [[ -n "$RPM_DIFF" ]]; then
    COMMIT_MSG="$COMMIT_MSG

RPM changes:

$RPM_DIFF"
  fi

  if [[ -n "$JIRA" ]]; then
    COMMIT_MSG="$COMMIT_MSG

Ref: https://redhat.atlassian.net/browse/$JIRA"
  fi

  FILES_MODIFIED=(Dockerfile Dockerfile.dist acceptance/kubernetes/kind/acceptance.Dockerfile rpms.lock.yaml)
  for d in "${FILES_MODIFIED[@]}"; do
    if [[ -f "$d" ]]; then
      git add "$d"
    fi
  done
  git commit -m "$COMMIT_MSG"

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

  PR_TITLE="chore(deps): Update ubi-minimal base image (${BRANCH#release-})"
  PR_BODY="Update ubi-minimal base image to latest digest.

Old digest: \`sha256:$OLD_DIGEST\`
New digest: \`sha256:$NEW_DIGEST\`"

  if [[ -n "$RPM_DIFF" ]]; then
    PR_BODY="$PR_BODY

### RPM changes

\`\`\`diff
$RPM_DIFF
\`\`\`"
  fi

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
