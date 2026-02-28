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

source "$(dirname ${BASH_SOURCE[0]})/helpers.sh"

# I want to create a keylessly signed image that can be used in acceptance
# tests. Ideally we would not rely on external images in the tests, but I had
# some difficulty making the keyless signature check work inside the tekton
# task with the cluster in the acceptance tests. Rather than be blocked on
# that, I want to get some usable tests working quickly. Also, we already have
# some other external images used in the tests, so I figure adding one more
# isn't such a big deal.
#
# Cosign v2 and v3 do a few things differently. Let's create two images
# so we can test older and newer signature bundle and linking methods.

REPO=quay.io/conforma/test

for ver in v2 v3; do
  COSIGN="go run github.com/sigstore/cosign/$ver/cmd/cosign@latest"
  LABEL="keyless_$ver"

  h1 "Creating image ($ver)"
  podman build -t "$REPO:$LABEL" -f - . <<EOF
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
RUN echo "hello from the conforma cosign $ver keyless signing test image" > /hello.txt
CMD ["cat", "/hello.txt"]
EOF

  h1 "Pushing image ($ver)"
  podman push "$REPO:$LABEL"

  h1 "Signing image ($ver)"
  # Use the digest otherwise cosign complains
  DIGEST=$(skopeo inspect "docker://quay.io/conforma/test:keyless_$ver" | jq -r .Digest)
  $COSIGN sign -y $REPO@$DIGEST

  h1 "Creating a signed attestation ($ver)"
  # Push a minimal attestation
  $COSIGN attest -y \
    --predicate - \
    --type "https://slsa.dev/provenance/v1" \
    $REPO@$DIGEST <<EOF
{
  "buildDefinition": {
    "buildType": "https://example.com/build-type/v1",
    "externalParameters": {},
    "internalParameters": {},
    "resolvedDependencies": []
  },
  "runDetails": {
    "builder": {
      "id": "https://example.com/builder"
    },
    "metadata": {}
  }
}
EOF

done
