#!/usr/bin/env bash
# Copyright The Conforma Contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
demo="$root/hack/evidence-poc"
generated="$demo/generated"
proof="$generated/evidence-input-proof"
mkdir -p "$proof"

# Reuse the prepared example's verified OCI key. Run validate.sh first to
# refresh report.json when switching between golden and local fixtures.
jq --arg policy "$demo/probes" '
  {publicKey:.key,sources:[{name:"evidence-input-proof",policy:[$policy]}]}
' "$generated/report.json" > "$proof/policy.json"
for engine in conftest opa; do
  opa_enabled=0
  [[ "$engine" != opa ]] || opa_enabled=1
  # Remove old results so an earlier successful probe cannot mask a failed run.
  rm -f "$proof/$engine-report.json" "$proof/$engine-input.jsonl"
  if EC_USE_OPA="$opa_enabled" "$root/dist/ec" validate image \
    --images "$generated/snapshot.json" \
    --policy "$proof/policy.json" \
    --evidence "$generated/chi-attestations.json" \
    --evidence-key "https://example.invalid/chi/v1=$generated/chi.pub" \
    --ignore-rekor --effective-time now --vsa-expiration=0 \
    --output "json=$proof/$engine-report.json" \
    --output "policy-input=$proof/$engine-input.jsonl" \
    > "$proof/$engine.log" 2>&1; then
    printf 'FAIL: %s did not produce the intentional Rego observation failure\n' "$engine" >&2
    exit 1
  fi
done

python3 - "$generated" "$proof" <<'PY'
import base64
import json
from pathlib import Path
import sys

generated, proof = map(Path, sys.argv[1:])
bundles = json.loads((generated / "chi-attestations.json").read_text())
if isinstance(bundles, dict):
    bundles = [bundles]

# Expectations come from the supplied files, independently of the CLI's export.
expected = {}
for bundle in bundles:
    envelope = bundle["dsseEnvelope"]
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    assert statement["predicateType"] == "https://example.invalid/chi/v1"
    for subject in statement["subject"]:
        digest = "sha256:" + subject["digest"]["sha256"]
        assert digest not in expected, "Probe expects one CHI record per image digest"
        expected[digest] = (statement, envelope["signatures"])

def signatures(records):
    return sorted((s.get("keyid", ""), s["sig"]) for s in records)

summary = {"passed": True, "engines": {}}
observations_by_engine = {}
for engine in ("conftest", "opa"):
    report = json.loads((proof / f"{engine}-report.json").read_text())
    assert report["success"] is False, "Probe must deliberately deny"
    inputs = [json.loads(line) for line in (proof / f"{engine}-input.jsonl").read_text().splitlines() if line.strip()]
    inputs_by_image = {record["image"]["ref"]: record for record in inputs}
    observations = {}
    for component in report["components"]:
        image = component["containerImage"]
        digest = image.rsplit("@", 1)[1]
        violations = component.get("violations", [])
        assert len(violations) == 1, (engine, image, violations)
        assert violations[0]["metadata"]["code"] == "evidence_input.observed", violations
        observed = json.loads(violations[0]["msg"])
        # These values were emitted by actual Rego evaluation.
        assert observed["image"] == image
        assert observed["component"] == component["name"]
        assert observed["ociPredicates"], "OCI provenance must remain alongside CLI evidence"
        statement, original_signatures = expected[digest]
        assert observed["attestation"]["statement"] == statement, "Rego must read the complete original statement"
        assert signatures(observed["attestation"]["signatures"]) == signatures(original_signatures)
        # The saved policy input must describe the same data Rego just read.
        exported_chi = [a for a in inputs_by_image[image]["attestations"] if a["statement"]["predicateType"] == "https://example.invalid/chi/v1"]
        assert exported_chi == [observed["attestation"]]
        observations[image] = observed
    assert len(observations) == len(expected) == len(inputs_by_image), "Every signed target must be observed"
    observations_by_engine[engine] = observations
    summary["engines"][engine] = {
        "targets": len(observations),
        "originalStatementsAndSignaturesMatched": True,
        "ociProvenanceAlsoVisible": True,
        "policyInputExportMatchedRego": True,
    }
    print(f"PASS: {engine} Rego read the supplied evidence from input.attestations for all {len(observations)} targets")

assert observations_by_engine["conftest"] == observations_by_engine["opa"]
summary["evaluatorsAgree"] = True
(proof / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(f"Proof: {proof / 'summary.json'}")
PY
