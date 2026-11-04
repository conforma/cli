#!/usr/bin/env bash
# Copyright The Conforma Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
generated="$root/hack/evidence-poc/generated"

exec "$root/dist/ec" validate image \
  --images "$generated/snapshot.json" \
  --policy "$root/hack/evidence-poc/policy.yaml" \
  --evidence "$generated/chi-attestations.json" \
  --evidence-key "https://example.invalid/chi/v1=$generated/chi.pub" \
  --ignore-rekor --effective-time now --vsa-expiration=0 \
  --output "json=$generated/report.json" \
  --output "policy-input=$generated/policy-input.jsonl" "$@"
