# Filesystem attestation POC

This POC extends `ec validate image` with a filesystem attestation source alongside
OCI. Each snapshot image gets its registry provenance plus the local attestations
whose **signed subject digest** matches that image. Policies consume the existing
`input.attestations` array.

The worktree is `/Users/jstuart/scratch_pad/ec-cli-evidence-poc`, on branch
`poc/filesystem-attestations`, based on `d7152fd908654fd34e92f2d9cc4e2ee245f1d464`.
The original checkout is unchanged. Changes are uncommitted.

## Run the prepared example

The prepared example uses `quay.io/konflux-ci/ec-golden-image:latest`, resolved
on 2026-10-13 and pinned in the snapshot to:

```text
quay.io/konflux-ci/ec-golden-image@sha256:9dc171a302d42292a6094d8d9a106048547ad56cde7860b565fc5a2116499d36
```

The image is a multi-platform index. The CLI evaluates that index and its
amd64 and arm64 manifests. The CHI batch contains one freshly Cosign-signed
record for each of those three digests. Existing image signatures and SLSA v0.2
provenance are verified with the Konflux production public key from
`hack/simple-demo.sh`; filesystem CHI uses the separate POC key.

```sh
cd /Users/jstuart/scratch_pad/ec-cli-evidence-poc
poc="$PWD/hack/evidence-poc/generated"

./dist/ec validate image \
  --images "$poc/snapshot.json" \
  --policy "$PWD/hack/evidence-poc/policy.yaml" \
  --evidence "$poc/chi-attestations.json" \
  --evidence-key "https://example.invalid/chi/v1=$poc/chi.pub" \
  --ignore-rekor --effective-time now --vsa-expiration=0 \
  --output "json=$poc/report.json" \
  --output "policy-input=$poc/policy-input.jsonl"
```

Equivalent shortcut: `./hack/evidence-poc/validate.sh`.

The editable policy is `hack/evidence-poc/policy.yaml`, based on
`/Users/jstuart/ec_testing/golden/policy.yaml`. It includes:

* The published `quay.io/conforma/release-policy:konflux` bundle, the
  `release-engineering/rhtap-ec-policy` data, and the `@redhat` collection.
* A separate local CHI policy source selecting the `chi` package: per-image
  coverage, predicate format, OCI provenance present alongside CHI, and CRITICAL
  advisory deadlines.
* The supplied Konflux public key for image signatures and OCI attestations.
  The CHI key remains a separate CLI `--evidence-key` binding.

Keeping CHI in its own source ensures the `@redhat` selection does not filter it
out. Both policy sources receive the same per-image `input.attestations`.
The CHI source path is absolute for this worktree; update it if moving the POC.
The policy bundle tag and data branch follow the example and can change between
runs. Release-rule failures are reported normally; the policy has no exclusions.

Each line of `policy-input.jsonl` contains one target's SLSA attestation and
matching CHI attestation. There are three lines, covering the index and both
platforms. `report.json` records the combined release and CHI result.

The sample deliberately includes an expired CRITICAL advisory,
`RHSA-2026:58936`, with deadline `2026-09-02T14:37:22Z`. The expected result on
2026-10-13 is `chi.release_gate` for all three targets and exit status 1.
The other CRITICAL advisory remains within its window; IMPORTANT advisories do
not trigger this rule. The release policy also reports missing source-code
references for all targets and missing scanner CVE results for the platform
targets. The CHI predicate does not replace that scanner output. Findings are
retained in `generated/report.json`; the run log is `generated/real-policy.log`.

The CVE/RHSA identifiers and deadlines are synthetic demonstration data. These
POC CHI keys use an empty password. The demo does not publish to Rekor;
`--ignore-rekor` explicitly disables log checks while signature verification
remains required. The OCI public key comes from `policy.yaml`; the CHI public
key comes from `--evidence-key`. No Rekor public key is needed for this run.

## CHI predicate and rule

`chi-predicate.json` contains the normalized example used by `setup-golden.sh`.
Its top-level `CRITICAL` and `IMPORTANT` objects map RHSA IDs to records containing
`released_on`, `safe_until`, and a boolean `blocked`. Dates are concrete RFC3339
timestamps: the sample uses release date plus 30 days for CRITICAL and 90 days
for IMPORTANT. The producer calculates these dates before signing; the rule
uses the attested `safe_until` value.

`policy/chi/chi.rego` follows the release rules' annotation and result-helper
conventions. The local `policy/lib` directory supplies the metadata and time
helpers because the CHI source is evaluated independently of the release
bundle. It selects only statements with predicate type
`https://example.invalid/chi/v1` (the existing POC URI). It denies each CRITICAL
advisory when the evaluation time is **at or after** `safe_until`. It honors
Conforma's effective time (`--effective-time now` in the demo). `blocked` is the
collector's observation and does not override this time comparison.

Exactly one CHI attestation is required per image. Missing or malformed CRITICAL
data fails policy rather than silently passing; an empty `CRITICAL: {}` reports
no critical advisories. This schema does not carry scan-completeness or freshness
metadata. Component names are no longer part of the predicate: the signed
Statement subject digest binds it to its image. RHSA IDs identify advisories;
individual CVE IDs are not present in this schema.

## Recreate and inspect

Prerequisites: Go, Cosign, crane, and jq. Tested with Go 1.26.7 and Cosign 2.5.3.
Quay and GitHub access are required; no container engine or local registry is needed.

```sh
./hack/evidence-poc/setup-golden.sh  # resolve latest, pin snapshot, sign CHI for all targets
./hack/evidence-poc/validate.sh
```

`setup-golden.sh` regenerates the synthetic collector data and signatures for the
current tag. Pass a `sha256:...` digest as its first argument to reuse a specific
golden image without resolving `latest`. The validation command always uses the
saved immutable digest. Edit `chi-predicate.json` and rerun setup to re-sign a
changed observation; the same sample predicate is signed for each target.
Edit `hack/evidence-poc/policy.yaml` directly; policy changes do not require
signing the evidence again. Setup also copies it to `generated/policy.yaml` for
compatibility with earlier commands, but `validate.sh` reads the editable file.

The original two-image local fixture is still available for the full negative
test suite. These commands replace the prepared golden-image inputs with that
local fixture; run `setup-golden.sh` afterward to switch back:

```sh
./hack/evidence-poc/setup.sh
./hack/evidence-poc/check.sh
EC_USE_OPA=1 ./hack/evidence-poc/check.sh
```

The local fixture uses its own minimal generated policy and disposable build
key. `check.sh` selects that policy explicitly; to validate the local fixture
manually, use `./hack/evidence-poc/validate.sh --policy "$PWD/hack/evidence-poc/generated/policy.yaml"`.

The optional local registry listens on `127.0.0.1:55087`; its PID is in
`generated/registry.pid`. It is not used by the golden-image example.

All generated material, including keys, is ignored by Git:

| File in `generated/` | Meaning |
|---|---|
| `golden-image.txt`, `golden-image-manifest.json` | Resolved image reference and manifest list fetched from Quay |
| `collector.json` | Raw synthetic collector batch covering the index and both platform digests; not accepted as evidence |
| `golden-index-predicate.json`, `golden-manifest-*-predicate.json` | Per-target mock data extracted before signing |
| `golden-*-statement.json` | Readable decoded signed payloads; these bare statements are not accepted as evidence |
| `golden-*.sigstore.json` | Actual Cosign-produced Sigstore v0.3 DSSE bundles |
| `chi-attestations.json` | A JSON array containing all three bundles |
| `golden-build.pub`, `chi.pub` | Konflux verification key for OCI and the POC verification key for filesystem evidence |
| `snapshot.json`, `policy.yaml` | Snapshot and setup-time copy of the policy; edit `../policy.yaml` for the golden-image run |
| `report.json`, `policy-input.jsonl` | Latest validation report and per-image policy inputs |
| `check-*.json`, `check-*.log` | Expected failure reports/logs; admission errors happen before a report is created |

`setup-golden.sh` runs this real signing operation for each target:

```sh
cosign attest-blob --yes --tlog-upload=false --new-bundle-format \
  --key "$poc/chi.key" --type https://example.invalid/chi/v1 \
  --predicate "$poc/golden-index-predicate.json" \
  --hash '<scanned image sha256 hex from snapshot.json>' \
  --bundle "$poc/golden-index.sigstore.json" "$(cat "$poc/golden-image.txt")"
```

The hash binds the attestation to the image, not to the predicate file. Cosign
places the predicate and image digest into an in-toto Statement and signs its
original bytes inside DSSE. No signing occurs inside Conforma.

## POC interface and scope

* Repeatable `--evidence PATH` accepts a single Sigstore bundle or JSON array of
  bundles, up to 32 MiB per file. Raw predicates, unsigned statements, and bare
  DSSE envelopes are rejected.
* Repeatable `--evidence-key predicateURI=publicKeyFile` authorizes a key for that
  exact predicate **in filesystem sources**. Repeating a predicate permits
  rotation keys. Keys from other predicates are never pooled together.
* OCI evidence continues using the existing policy `publicKey`/identity and
  Sigstore settings. No CRD, policy configuration code, or `attestationTrust`
  field is changed. Predicate-specific OCI keys and keyless filesystem trust
  remain future work.
* Filesystem batches are verified once before workers start. `Collect(ctx,
  name.Digest)` performs immutable digest lookup and returns the existing
  `[]attestation.Attestation` type. Repository names and component labels do not
  establish cryptographic identity.
* Source failures are not hidden by successful evidence from another source.
  OCI collection in this mode verifies each supported candidate individually,
  handles legacy tags and bundles, and excludes image-signature predicates.
  Missing filesystem evidence reaches the demo's required-coverage policy.
* Filesystem mode rejects `--skip-att-sig-check`, bypasses VSA reuse, and rejects
  VSA generation/upload. Invocations without `--evidence` retain the existing
  OCI path. Both image validation entry points propagate `ValidationOptions`.
* This POC includes the CRITICAL advisory deadline rule. Collector integration,
  exceptions, scan-completeness/freshness checks, keyless filesystem workflow,
  evidence-aware VSA format, task integration, and policy API migration remain
  future work.

## Validation

Run the CHI rule tests (requires OPA):

```sh
opa test hack/evidence-poc/policy hack/evidence-poc/tests/chi_test.rego \
  hack/evidence-poc/chi-predicate.json -v
```

The 15 tests cover the sample's 30/90-day dates, expired and future CRITICAL
advisories, the deadline boundary, IMPORTANT exclusion, exact predicate
selection, stale `blocked` values, required coverage, invalid data, and effective
time. They also check the release-style result metadata. CLI verification
additionally uses actual Cosign-signed bundles.

```sh
CGO_ENABLED=0 go test -tags=unit,integration,generative ./internal/evidence ./internal/image \
  ./internal/evaluation_target/application_snapshot_image ./cmd/validate
```

The tests use real cryptographic signatures. The executable demo additionally
uses the installed Cosign binary and actual local OCI storage.

To verify that CLI-supplied evidence reaches the actual Rego evaluator, run:

```sh
./hack/evidence-poc/check-policy-input.sh
```

This regression check invokes the CLI with `--evidence` using both Conftest and
OPA. A dedicated probe policy reads each CHI record from `input.attestations`
and deliberately returns it in a policy violation. The script compares those
Rego results with the original signed statements and signatures, checks that
OCI SLSA provenance remains in the same array, and checks that the saved policy
input agrees with what Rego read. It requires all image targets to be observed
and both evaluators to agree. The expected probe violations are kept in
`generated/evidence-input-proof/`; the normal report is preserved.

Verified against the golden image's index, amd64, and arm64 targets. Results are
in `generated/evidence-input-proof/summary.json`. The check requires Python 3,
the prepared example, and its current `report.json` verification key.

| Requirement exercised | Evidence |
|---|---|
| OCI plus filesystem inputs, per-image pairing | Two-image demo with reversed batch; policy-input assertions |
| Multi-platform golden image | Each target receives its matching signed CHI record and reports the expired CRITICAL advisory. The combined release-policy findings are recorded above. |
| CLI evidence is added to `input.attestations` passed to Rego | `check-policy-input.sh`: actual Rego results match original signed statements/signatures for all three targets in both Conftest and OPA |
| Signature and predicate/key authorization | Unit mixed-key/rotation tests; wrong-key, tampered and unsigned CLI failures |
| Valid evidence cannot hide invalid evidence | Unit tests for mixed valid/invalid filesystem, legacy OCI, and bundle records |
| Absent evidence differs from a failed source | Empty-source unit tests; missing-alpha CLI failure while beta succeeds |
| CHI remains required if the new flag is omitted | CLI coverage failures for both images |
| Signed data still undergoes policy evaluation | Cosign-signed expired CVE rejected by Rego |
| Existing reports and evaluation paths work | SLSA build type retained; default and OPA demo runs; options propagation tests |
| New evidence cannot bypass verification/VSA restrictions | CLI guards and VSA-aware entry-point regression tests |

No PR, commit, or external registry publication is required to run the POC.
