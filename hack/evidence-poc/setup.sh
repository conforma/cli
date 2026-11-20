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

CGO_ENABLED=0 go build -o dist/ec .
CGO_ENABLED=0 go build -o dist/evidence-registry ./hack/evidence-poc/registry

if [[ ! -f "$generated/registry.pid" ]] || ! kill -0 "$(cat "$generated/registry.pid")" 2>/dev/null; then
  rm -f "$generated/snapshot.json"
  nohup "$root/dist/evidence-registry" --dir "$generated" > "$generated/registry.log" 2>&1 < /dev/null &
  echo "$!" > "$generated/registry.pid"
fi
for ((i=0; i<50; i++)); do
  [[ -s "$generated/snapshot.json" ]] && break
  sleep 0.2
done
[[ -s "$generated/snapshot.json" ]] || { cat "$generated/registry.log"; exit 1; }

# Disposable demonstration keys only. Neither keys nor generated artifacts are tracked.
export COSIGN_PASSWORD=''
for key in build chi wrong; do
  if [[ ! -f "$generated/$key.key" ]]; then
    cosign generate-key-pair --output-key-prefix "$generated/$key"
    chmod 600 "$generated/$key.key"
  fi
done

cat > "$generated/slsa.json" <<'JSON'
{
  "buildDefinition": {"buildType":"https://example.invalid/build/poc","externalParameters":{},"internalParameters":{},"resolvedDependencies":[]},
  "runDetails": {"builder":{"id":"https://example.invalid/builder/poc"}}
}
JSON

cat > "$generated/alpha-predicate.json" <<'JSON'
{
  "CRITICAL": {
    "RHSA-2099:0001": {
      "released_on":"2099-01-01T00:00:00Z",
      "safe_until":"2099-01-31T00:00:00Z",
      "blocked":false
    }
  },
  "IMPORTANT": {}
}
JSON
cat > "$generated/beta-predicate.json" <<'JSON'
{"CRITICAL":{},"IMPORTANT":{}}
JSON

# Raw mock collector output covers a list of images; this is never CLI evidence.
jq -n --slurpfile snapshot "$generated/snapshot.json" \
  --slurpfile alpha "$generated/alpha-predicate.json" --slurpfile beta "$generated/beta-predicate.json" \
  '{images:[$snapshot[0].components[] | . as $image | {image:$image.containerImage,predicate:(if .name=="alpha" then $alpha[0] else $beta[0] end)}]}' \
  > "$generated/collector.json"

while IFS=$'\t' read -r component image; do
  jq --arg image "$image" '.images[] | select(.image==$image) | .predicate' \
    "$generated/collector.json" > "$generated/$component-predicate.json"
  # Existing image signature and SLSA provenance: build key, stored in OCI.
  cosign sign --yes --tlog-upload=false --key "$generated/build.key" "$image"
  cosign attest --yes --replace --tlog-upload=false --key "$generated/build.key" \
    --type slsaprovenance1 --predicate "$generated/slsa.json" "$image" > "$generated/$component-oci-attestation.json"
  # CHI: separate key, signed image digest, written only to the filesystem.
  cosign attest-blob --yes --tlog-upload=false --new-bundle-format \
    --key "$generated/chi.key" --type https://example.invalid/chi/v1 \
    --predicate "$generated/$component-predicate.json" \
    --hash "${image##*@sha256:}" --bundle "$generated/$component.sigstore.json" "$component" > "$generated/$component.dsse.json"
done < <(jq -r '.components[] | [.name,.containerImage] | @tsv' "$generated/snapshot.json")

for component in alpha beta; do
  jq -r '.dsseEnvelope.payload | @base64d' "$generated/$component.sigstore.json" > "$generated/$component-statement.json"
done

# Deliberately reverse the batch order relative to the snapshot.
jq -s '.' "$generated/beta.sigstore.json" "$generated/alpha.sigstore.json" > "$generated/chi-attestations.json"
cat > "$generated/policy.yaml" <<YAML
publicKey: $generated/build.pub
sources:
  - name: evidence-poc
    policy:
      - $demo/policy
YAML

printf '\nPrepared two signed images and a CHI batch in %s\nRun: %s/validate.sh --policy %s/policy.yaml\n' "$generated" "$demo" "$generated"
