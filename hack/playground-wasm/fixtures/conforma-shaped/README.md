# Conforma-Shaped Playground Fixture

This fixture is intentionally small, but it exercises policy patterns that are
closer to Conforma policy authoring than the first playground sample:

- Multiple Rego modules in one pasteable document.
- Helper packages imported through `data.lib.*`.
- Rule data supplied separately under `data`.
- Structured `deny` and `warn` results with `code`, `msg`, and `metadata`.

It is not a real release policy bundle and does not exercise
EnterpriseContractPolicy selection, rule include/exclude behavior, remote policy
fetching, OCI image metadata, Sigstore, Rekor, or Conforma CLI report shaping.

## Files

- `policy.rego` is the pasteable browser playground version. It uses `# file:`
  markers so the playground can split it into modules.
- `policy.yaml`, `cli-policy/`, and `cli-data/` are the equivalent local
  Conforma CLI fixture.
- `input-fail.yaml` should produce two violations and one warning.
- `input-pass.yaml` should pass with no violations or warnings.

## CLI Check

From the repository root:

```bash
GOCACHE=/private/tmp/ec-gocache-playground go run . validate input \
  hack/playground-wasm/fixtures/conforma-shaped/input-fail.yaml \
  --policy hack/playground-wasm/fixtures/conforma-shaped/policy.yaml \
  --output json \
  --strict=false
```

```bash
GOCACHE=/private/tmp/ec-gocache-playground go run . validate input \
  hack/playground-wasm/fixtures/conforma-shaped/input-pass.yaml \
  --policy hack/playground-wasm/fixtures/conforma-shaped/policy.yaml \
  --output json \
  --strict=false
```
