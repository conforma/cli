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

# This script is used to generate that OCI image used during the keyless acceptance tests. It
# bootstraps a new kind cluster and deploys all sigstore components on it. Then, it proceeds to
# generate an OCI image, sign it, and attest it. It also uses WireMock to record the interactions
# with TUF API. Finally, all data is copied over to the proper places in this git repo. Be sure
# to commit them.
#
# Usage:
#   ./hack/generate-test-signed-images.sh

set -euo pipefail

errors=false

function check_etc_hosts() {
    h="$(printf $1 | cut -d: -f2 | sed 's_//__')"
    set +e
    < /etc/hosts grep "${h}" > /dev/null
    exists="$?"
    set -e
    if [[ "${exists}" -ne "0" ]]; then
        echo "🛑 Add '127.0.0.1 ${h}' to /etc/hosts"
        errors=true
    fi
}

export REKOR_URL=http://rekor.rekor-system.svc:8088
export FULCIO_URL=http://fulcio.fulcio-system.svc:8088
export ISSUER_URL=http://gettoken.default.svc:8088
export TUF_MIRROR=http://tuf.tuf-system.svc:8088

# Check if the kind cluster already exists
set +e
kind get clusters 2> /dev/null | grep kind > /dev/null
cluster_exists="$?"
set -e
if [[ "${cluster_exists}" -eq "0" ]]; then
    echo '🛑 The kind cluster already exists. Delete it first:'
    echo -e '\tkind delete cluster --name kind'
    errors=true
fi

# Check if the docker registry already exists
set +e
docker inspect registry.local &> /dev/null
registry_exists="$?"
set -e
if [[ "${registry_exists}" -eq "0" ]]; then
    echo '🛑 The registry already exists. Delete it first:'
    echo -e '\tdocker rm -f registry.local'
    errors=true
fi

# Check if entries in /etc/hosts have been added
check_etc_hosts "${REKOR_URL}"
check_etc_hosts "${FULCIO_URL}"
check_etc_hosts "${ISSUER_URL}"
check_etc_hosts "${TUF_MIRROR}"
check_etc_hosts 'ctlog.ctlog-system.svc'
check_etc_hosts 'registry.local'

$errors && exit 1

function cleanup() {
    kill $(jobs -p) || true
    docker rm -f wiremock.local || true
}
trap cleanup EXIT

WORKDIR="$(mktemp -d)"
echo "Using WORKDIR at ${WORKDIR}"

scaffolding="${WORKDIR}/scaffolding"
mkdir -p "${scaffolding}"
git clone https://github.com/sigstore/scaffolding.git "${scaffolding}"
pushd "${scaffolding}" > /dev/null
git checkout v0.7.22
./hack/setup-kind.sh
export KO_DOCKER_REPO='registry.local:5001/sigstore'
./hack/setup-scaffolding.sh
# Setup the dummy OIDC issuer
LDFLAGS='' ko apply -BRf ./testdata/config/gettoken
popd > /dev/null

export TUF_ROOT="${WORKDIR}/tuf_root"
mkdir -p "${TUF_ROOT}"

function make_image() {
    repo='registry.local:5001/sigstore/testimage'
    container="$(buildah from scratch)"
    image="$(buildah commit "${container}")"
    digestfile="$(mktemp)"
    buildah push --tls-verify=false --digestfile "${digestfile}" \
        "${image}" "docker://${repo}:latest"
    printf "${repo}@$(< "${digestfile}")"
}

# Generate image
image="$(make_image)"
echo "✅ New image created: ${image}"

# Start kourier in the background to grant access to services
kubectl -n kourier-system port-forward service/kourier-internal 8088:80 &

# Wait a bit so the port-forward has a chance to start up
sleep 1

# Make cosign use the local sigstore deployment
cosign initialize --mirror $TUF_MIRROR --root "${scaffolding}/root.json"

echo "Waiting for OIDC Issuer"
while [[ -z "$(curl -s "${ISSUER_URL}")" ]]; do
    printf '.'
    sleep 1
done
echo
echo '✅ ODIC issuer up'

# Sign image
cosign sign --allow-insecure-registry -y \
    --rekor-url "${REKOR_URL}" \
    --fulcio-url "${FULCIO_URL}" \
    --identity-token "$(curl -s "${ISSUER_URL}")" \
    "${image}"
echo '✅ Image signed'

# Verify the signature is correct
cosign verify --allow-insecure-registry \
    --certificate-identity 'https://kubernetes.io/namespaces/default/serviceaccounts/default' \
    --certificate-oidc-issuer 'https://kubernetes.default.svc.cluster.local' \
    "${image}" > /dev/null
echo '✅ Image signature verified'

# Generate provenance for the image
provenance='
{
  "builder": {
    "id": "https://tekton.dev/chains/v2"
  },
  "buildType": "tekton.dev/v1/PipelineRun",
  "invocation": {},
  "metadata": {
    "buildStartedOn": "2023-03-22T19:38:01Z",
    "buildFinishedOn": "2023-03-22T19:41:05Z",
    "completeness": {
      "parameters": false,
      "environment": false,
      "materials": false
    },
    "reproducible": false
  },
  "materials": []
}
'

# Attest the image with SLSA Provenance
cosign attest --allow-insecure-registry -y \
    --predicate <(echo "${provenance}") \
    --type slsaprovenance \
    --fulcio-url $FULCIO_URL \
    --rekor-url $REKOR_URL \
    --identity-token "$(curl -s $ISSUER_URL)" \
    "${image}"
echo '✅ Image attested'

# Verify the attestation is correct
cosign verify-attestation --allow-insecure-registry \
    --type slsaprovenance \
    --certificate-identity 'https://kubernetes.io/namespaces/default/serviceaccounts/default' \
    --certificate-oidc-issuer 'https://kubernetes.default.svc.cluster.local' \
    "${image}"
echo '✅ Image attestation verified'

# Copy over required files for acceptance tests
rm -rf ./acceptance/image/testimage/*
cosign save "${image}" --dir ./acceptance/image/testimage
cp "${scaffolding}/root.json" ./acceptance/tuf/

recordings="${PWD}/acceptance/wiremock/recordings/tuf"
rm -rf "${recordings}"
docker run -d --rm --network=host -e uid="$(id -u)" \
    --name wiremock.local \
    -v "${recordings}:/home/wiremock:Z" \
    wiremock/wiremock:3.13.0-1 \
    --proxy-all="${TUF_MIRROR}" \
    --record-mappings \
    --verbose

# Wait a bit to make sure wiremock has a chance to come up
sleep 2

export TUF_ROOT="$(mktemp -d)"
cosign initialize --mirror http://localhost:8080 --root "${scaffolding}/root.json"

echo "
Image: ${image}
WORKDIR: ${WORKDIR}

You can safely remove the kind cluster and the docker registry:
    kind delete cluster --name kind && docker rm -f registry.local
"
