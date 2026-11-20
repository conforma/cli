#!/usr/bin/env bash
# Copyright The Conforma Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
demo="$root/hack/evidence-poc"
generated="$demo/generated"
mkdir -p "$generated"
chmod 700 "$generated"
cd "$root"
if [[ ! -x dist/ec ]]; then
  CGO_ENABLED=0 go build -o dist/ec .
fi

repository=quay.io/konflux-ci/ec-golden-image
digest=${1:-$(crane digest "$repository:latest")}
image="$repository@$digest"
crane manifest "$image" > "$generated/golden-image-manifest.json"
printf '%s\n' "$image" > "$generated/golden-image.txt"

# The Konflux production key already used by hack/simple-demo.sh.
cat > "$generated/golden-build.pub" <<'PEM'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZP/0htjhVt2y0ohjgtIIgICOtQtA
naYJRuLprwIv6FDhZ5yFjYUEtsmoNcW7rx2KM6FOXGsCX3BNc7qhHELT+g==
-----END PUBLIC KEY-----
PEM

export COSIGN_PASSWORD=''
if [[ ! -f "$generated/chi.key" ]]; then
  cosign generate-key-pair --output-key-prefix "$generated/chi"
  chmod 600 "$generated/chi.key"
fi

jq -n --arg image "$image" \
  '{components:[{name:"golden-container",containerImage:$image}]}' > "$generated/snapshot.json"

# The collector batch covers the index and all platform targets. Each predicate
# is signed separately with the corresponding image digest as its subject.
jq --arg image "$image" --arg repository "$repository" \
  --slurpfile predicate "$demo/chi-predicate.json" '
  [{image:$image,component:"golden-container",file:"golden-index"}] +
  [(.manifests // [] | to_entries[]) |
    (.value.platform.architecture // ("noarch-"+(.key|tostring))) as $arch |
    {image:($repository+"@"+.value.digest),
     component:("golden-container-"+.value.digest+"-"+$arch),
     file:("golden-manifest-"+(.key|tostring))}]
  | {images:map(. + {predicate:$predicate[0]})}
' "$generated/golden-image-manifest.json" > "$generated/collector.json"

bundles=()
while IFS=$'\t' read -r target file; do
  jq --arg image "$target" '.images[] | select(.image==$image) | .predicate' \
    "$generated/collector.json" > "$generated/$file-predicate.json"
  cosign attest-blob --yes --tlog-upload=false --new-bundle-format \
    --key "$generated/chi.key" --type https://example.invalid/chi/v1 \
    --predicate "$generated/$file-predicate.json" --hash "${target##*@sha256:}" \
    --bundle "$generated/$file.sigstore.json" "$target" > "$generated/$file.dsse.json"
  jq -r '.dsseEnvelope.payload | @base64d' "$generated/$file.sigstore.json" > "$generated/$file-statement.json"
  bundles+=("$generated/$file.sigstore.json")
done < <(jq -r '.images[] | [.image,.file] | @tsv' "$generated/collector.json")
jq -s 'reverse' "${bundles[@]}" > "$generated/chi-attestations.json"

# Keep the previous generated policy path usable; validate.sh reads the
# editable policy directly, so changing it does not require signing again.
cp "$demo/policy.yaml" "$generated/policy.yaml"

printf '\nPrepared CHI evidence for %s and its platform manifests.\nRun: %s/validate.sh\n' "$image" "$demo"
