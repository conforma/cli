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
