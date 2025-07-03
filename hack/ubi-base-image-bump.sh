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
# Renovate should do be generating a PR for this automatically, but there
# are times want to do it immediately, in which case you can use this script.
#

set -o errexit
set -o nounset
set -o pipefail

# Find latest digest
UBI_MINIMAL=registry.access.redhat.com/ubi9/ubi-minimal:latest
NEW_DIGEST=$(skopeo inspect --raw docker://$UBI_MINIMAL | sha256sum | awk '{print $1}')
echo "Found $UBI_MINIMAL:latest@$NEW_DIGEST"

# Update docker files
DOCKER_FILES=(Dockerfile Dockerfile.dist)
for d in "${DOCKER_FILES[@]}" ; do
  echo "Updating $d"
  sed -E "s!^FROM $UBI_MINIMAL@sha256:[0-9a-f]{64}\$!FROM $UBI_MINIMAL@sha256:$NEW_DIGEST!" -i $d
done

[[ ${1:-""} == "--sed-only" ]] && exit

# Update rpms.lock.yaml maybe
hack/update-rpm-lock.sh

[[ ${1:-""} == "--no-commit" ]] && exit

# Make a branch and a commit
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
PR_BRANCH="$CURRENT_BRANCH-ubi-bump-$(date +%y%m%d%H%M%S)"
git checkout -b $PR_BRANCH
git add ${DOCKER_FILES[@]} rpms.lock.yaml
# Todo maybe: Detect if there are no changes and handle it nicely
git commit -m "chore(deps): Update ubi-minimal base image"

[[ ${1:-""} == "--no-push" ]] && exit

# Push the branch ready to make a PR
git push origin $PR_BRANCH:$PR_BRANCH

# Todo maybe: gh pr create ...
echo ""
echo "***********************************************************************"
echo " Click the 'Create a pull request...' link above and create a PR"
echo " Be careful to choose the correct target branch: $CURRENT_BRANCH"
echo "***********************************************************************"
