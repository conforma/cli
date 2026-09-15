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
set -o nounset
set -o pipefail

# Instead of using the Konflux generated pipeline PR when we create a new
# release branch application and component, let's instead copy our main branch
# pipeline and to the small modifications required to make it work. Why? Even
# though we do like to "freshen" our pipelines with the newest Konflux
# defaults, it's weird to couple that with a release branch creation. We're
# better off to change as little as possible about the pipelines compared to
# the well known and trusted main branch pipelines at this stage in the release
# workflow.
#
# Also, this is a cleaner and easier way to ensure our pipeline customizations
# (like build-args files, prefetch options, etc), are maintained, since the
# freshly generated Konflux default pipeline resets back to the default which
# wipes out the customizations.
#
# Anyway, let's give this a try. I'm doing this for the first time while setting
# up the release v0.7 branch, see https://issues.redhat.com/browse/EC-1384
# and also https://issues.redhat.com/browse/EC-1165

VERSION=$(cat VERSION) # e.g. 0.7
VER=${VERSION/.} # e.g 07

MAIN_PR_PIPELINE=.tekton/cli-main-pull-request.yaml
MAIN_PUSH_PIPELINE=.tekton/cli-main-push.yaml

RELEASE_PR_PIPELINE=.tekton/cli-v$VER-pull-request.yaml
RELEASE_PUSH_PIPELINE=.tekton/cli-v$VER-push.yaml

OLD_VERSION="0.$((${VERSION#*.} - 1))"
OLD_VER=${OLD_VERSION/.}
OLD_RELEASE_PR_PIPELINE=.tekton/cli-v$OLD_VER-pull-request.yaml
OLD_RELEASE_PUSH_PIPELINE=.tekton/cli-v$OLD_VER-push.yaml

# If we use yq we get whitespace and ordering changes and it's really hard to
# look at diffs to compare the yaml. So use awk instead. It's less painful than
# dealing with the large yaml formatting/indenting  diffs.

awk_query=$(cat <<EOT
{
  # This is in the "pipelinesascode.tekton.dev/on-cel-expression"
  gsub(/== "main"/, "== \"release-v$VERSION\"");

  # We use different build args in the release branch
  gsub(/main-pre-merge-build-args.conf/, "\"\"");
  gsub(/main-build-args.conf/, "\"\"");

  # Replace "main" in several places
  gsub(/cli-main/, "cli-v$VER");
  gsub(/ec-main/, "ec-v$VER");

  # Remove the whole build-tekton-bundle task since we don't
  # build the tekton task in the release branch pipeline
  if (/^    - name: build-tekton-bundle/) { skip=1; next }
  if (/^    - name:/ && skip) { skip=0 }

  # And remove this param related to the build-tekton-bundle task
  if (/^  - name: bundle-cli-ref-repo/) { skip=1; next }
  if (/^  - name:/ && skip) { skip=0 }

  # This match is brittle but works currently. We're trying to
  # remove the whole "bundle-cli-ref-repo" param definition.
  # It is the only one that starts with description like this.
  if (/^    - description: >-/) { skip=1; next }
  if (/^    -/ && skip) { skip=0 }

  if (!skip) print
}
EOT
)

awk "$awk_query" <(git show main:$MAIN_PR_PIPELINE) > $RELEASE_PR_PIPELINE
awk "$awk_query" <(git show main:$MAIN_PUSH_PIPELINE) > $RELEASE_PUSH_PIPELINE

echo "To review the new pipeline definitions:"
echo "  vimdiff <(git show main:$MAIN_PR_PIPELINE) $RELEASE_PR_PIPELINE"
echo "  vimdiff <(git show main:$MAIN_PUSH_PIPELINE) $RELEASE_PUSH_PIPELINE"
echo "  vimdiff <(git show release-v$OLD_VERSION:$OLD_RELEASE_PR_PIPELINE) $RELEASE_PR_PIPELINE"
echo "  vimdiff <(git show release-v$OLD_VERSION:$OLD_RELEASE_PUSH_PIPELINE) $RELEASE_PUSH_PIPELINE"

echo ""
echo "If the above comparisons look good then you probably want to do this:"
echo "  git rm $MAIN_PR_PIPELINE $MAIN_PUSH_PIPELINE"
echo "  git add $RELEASE_PR_PIPELINE $RELEASE_PUSH_PIPELINE"
