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

SNAPSHOT=./large.yaml
PUBLIC_KEY=./key-rhel-osci.pub
POLICY_CONFIGURATION=github.com/enterprise-contract/config//redhat

#VERSIONS_TO_TEST=(
#  v0.6.94
#  v0.6.129
#  v0.6.138
#  v0.6.142
#)

#VERSIONS_TO_TEST=(v0.6.94)
VERSIONS_TO_TEST=(main)

#WORKERS=5
WORKERS=20

GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
EC=./dist/ec_${GOOS}_${GOARCH}

TIME=/usr/bin/time
TIME_FORMAT='User CPU time: %U\nSystem CPU time: %S\nElapsed time: %e\nPeak memory usage: %M kb'

for ref in ${VERSIONS_TO_TEST[@]}; do
  EC_REF=${EC}_${ref}

  if [[ ! -x "$EC_REF" ]]; then
    git reset --hard "${ref}"
    make ${EC}
    cp ${EC} ${EC_REF}
    cp ${EC}.sha256 ${EC_REF}.sha256
  fi

  title="Ref ${ref}"
  echo "$title"
  echo "$title" | tr '[:print:]' '='

  git log --format="Commit: %h %s%nDate: %cd" -n 1 ${ref}
  echo "Started: $(date)"

  ${TIME} --format "${TIME_FORMAT}" \
    ${EC_REF} validate image \
      --images large.yaml \
      --public-key key-rhel-osci.pub \
      --policy ${POLICY_CONFIGURATION} \
      --ignore-rekor \
      --output json=/dev/null \
      --output yaml=/dev/null \
      --show-successes \
      --timeout 60m \
      --workers ${WORKERS} \
      --info \
      2>&1 | tee "out-$ref.log"

  echo ""

done
