#!/usr/bin/env bash
# Copyright The Conforma Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
generated="$root/hack/evidence-poc/generated"
export COSIGN_PASSWORD=''
base=("$root/dist/ec" validate image --images "$generated/snapshot.json" --policy "$generated/policy.yaml" --ignore-rekor --effective-time now --vsa-expiration=0)
key=(--evidence-key "https://example.invalid/chi/v1=$generated/chi.pub")

expect_failure() {
  local case_name=$1
  shift
  if "${base[@]}" --output "json=$generated/check-$case_name.json" "$@" > "$generated/check-$case_name.log" 2>&1; then
    printf 'FAIL: %s unexpectedly passed\n' "$case_name" >&2
    exit 1
  fi
  printf 'PASS: %s rejected\n' "$case_name"
}

"$root/hack/evidence-poc/validate.sh" --policy "$generated/policy.yaml"
jq -e '.success and (.components|length==2)' "$generated/report.json" > /dev/null
jq -se 'length == 2 and all(.[]; . as $input | [.attestations[] | select(.statement.predicateType=="https://example.invalid/chi/v1")] as $chi | ($chi|length==1) and any($chi[0].statement.subject[]; .digest.sha256==($input.image.ref|split("@sha256:")[1])))' "$generated/policy-input.jsonl" > /dev/null
printf 'PASS: two images, OCI + filesystem evidence, correct per-image pairing\n'

expect_failure wrong-key --evidence "$generated/chi-attestations.json" --evidence-key "https://example.invalid/chi/v1=$generated/wrong.pub"
rg -q 'failed verification against authorized keys' "$generated/check-wrong-key.log"

jq '.[1].dsseEnvelope.payload |= (@base64d | fromjson | .predicate.CRITICAL["RHSA-2099:0001"].blocked=true | tojson | @base64)' "$generated/chi-attestations.json" > "$generated/tampered.json"
expect_failure tampered --evidence "$generated/tampered.json" "${key[@]}"
rg -q 'record 2.*failed verification' "$generated/check-tampered.log"

expect_failure missing-alpha --evidence "$generated/beta.sigstore.json" "${key[@]}"
jq -e '.success==false and any(.components[]; .name=="alpha" and any(.violations[]; .metadata.code=="chi.coverage")) and any(.components[]; .name=="beta" and .success)' "$generated/check-missing-alpha.json" > /dev/null

expect_failure omitted
jq -e 'all(.components[]; any(.violations[]; .metadata.code=="chi.coverage"))' "$generated/check-omitted.json" > /dev/null

expect_failure unsigned --evidence "$generated/alpha-predicate.json" "${key[@]}"
rg -q 'expected a Sigstore attestation bundle' "$generated/check-unsigned.log"

expect_failure bypass --evidence "$generated/chi-attestations.json" "${key[@]}" --skip-att-sig-check
rg -q 'cannot be used with --skip-att-sig-check' "$generated/check-bypass.log"

# A valid signature over a failing observation must reach Rego and fail policy.
jq '.CRITICAL["RHSA-2099:0001"] |= (.released_on="2000-01-01T00:00:00Z" | .safe_until="2000-01-31T00:00:00Z")' "$generated/alpha-predicate.json" > "$generated/expired-predicate.json"
image=$(jq -r '.components[]|select(.name=="alpha")|.containerImage' "$generated/snapshot.json")
cosign attest-blob --yes --tlog-upload=false --new-bundle-format \
  --key "$generated/chi.key" --type https://example.invalid/chi/v1 \
  --predicate "$generated/expired-predicate.json" --hash "${image##*@sha256:}" \
  --bundle "$generated/expired.sigstore.json" alpha > "$generated/expired.dsse.json"
jq -s '.' "$generated/beta.sigstore.json" "$generated/expired.sigstore.json" > "$generated/expired-batch.json"
expect_failure expired --evidence "$generated/expired-batch.json" "${key[@]}"
jq -e 'any(.components[]; .name=="alpha" and any(.violations[]; .metadata.code=="chi.release_gate"))' "$generated/check-expired.json" > /dev/null

printf 'All demonstration checks passed. Logs and reports: %s\n' "$generated"
