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

# Verify the images created in create.sh

# I used my own Google auth when running create.sh
# Adjust as needed
CERT_ARGS=(
--certificate-identity=sbaird@redhat.com
--certificate-oidc-issuer=https://accounts.google.com
)

REPO=quay.io/conforma/test

SLSA=https://slsa.dev/provenance/v1

# Verify using the same version of cosign that created sigs and atts:

for ver in v2 v3; do
  COSIGN="go run github.com/sigstore/cosign/$ver/cmd/cosign@latest"
  IMAGE_REF="$REPO:keyless_$ver"

  h1 "cosign tree $IMAGE_REF"
  $COSIGN tree "$IMAGE_REF"
  pause

  h1 "cosign verify $IMAGE_REF"
  $COSIGN verify "$IMAGE_REF" "${CERT_ARGS[@]}" | jq
  pause

  h1 "cosign verify-attestation $IMAGE_REF"
  $COSIGN verify-attestation "$IMAGE_REF" --type "$SLSA" "${CERT_ARGS[@]}" | jq
  pause

  h1 "cosign download attestation $IMAGE_REF"
  $COSIGN download attestation "$IMAGE_REF" | jq
  pause
done

# Cross-version verification to demonstrate what happens:

IMAGE_V2="$REPO:keyless_v2"
IMAGE_V3="$REPO:keyless_v3"
COSIGN_V2="go run github.com/sigstore/cosign/v2/cmd/cosign@latest"
COSIGN_V3="go run github.com/sigstore/cosign/v3/cmd/cosign@latest"

h1 "Backwards compatibility works (v2 sig with v3 cosign)"
$COSIGN_V3 verify "$IMAGE_V2" "${CERT_ARGS[@]}" > /dev/null
$COSIGN_V3 verify-attestation "$IMAGE_V2" --type "$SLSA" "${CERT_ARGS[@]}" > /dev/null
pause

h1 "Forwards compatibility does not work (v3 sig with v2 cosign)"
set +e
$COSIGN_V2 verify "$IMAGE_V3" "${CERT_ARGS[@]}"
$COSIGN_V2 verify-attestation "$IMAGE_V3" --type "$SLSA" "${CERT_ARGS[@]}"
set -e
pause
