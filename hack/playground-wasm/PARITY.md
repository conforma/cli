# Playground Parity Notes

The browser PoC currently proves that a Go/WASM evaluator can run OPA over
inline Rego modules, inline JSON/YAML input, and inline JSON/YAML data.

## Verified in This PoC

| Capability | Status | Evidence |
| --- | --- | --- |
| Go compiled to browser WASM | Works | `GOOS=js GOARCH=wasm go build ./hack/playground-wasm` |
| OPA evaluation in the browser | Works | `rego.New(...).Eval(ctx)` in `engine.go` |
| JSON/YAML input | Works | `parseDocument` tests |
| Multiple Rego modules | Works | `# file:` markers and fixture test |
| Helper module imports | Works | `import data.lib.pipeline` and `import data.lib.release` |
| Separate data document | Works | `data.yaml` loaded as OPA data |
| Structured deny/warn results | Works | fixture returns Conforma-like `code`, `msg`, and `metadata` objects |
| Same fixture through `ec validate input` | Works | local `policy.yaml` points at `cli-policy/` and `cli-data/` |

## CLI Comparison

The fixture has two equivalent forms:

- `policy.rego`, `input-*.yaml`, and `data.yaml` are the pasteable browser
  playground form.
- `policy.yaml`, `cli-policy/`, `cli-data/`, and the same `input-*.yaml`
  are the `ec validate input` form.

Run the real CLI path from the repository root:

```bash
GOCACHE=/private/tmp/ec-gocache-playground go run . validate input \
  hack/playground-wasm/fixtures/conforma-shaped/input-fail.yaml \
  --policy hack/playground-wasm/fixtures/conforma-shaped/policy.yaml \
  --output json \
  --strict=false
```

Observed result:

- `success: false`
- 2 violations:
  - `main.required_task_missing`
  - `main.signer_not_allowed`
- 1 warning:
  - `main.application_label_missing`

Run the passing input:

```bash
GOCACHE=/private/tmp/ec-gocache-playground go run . validate input \
  hack/playground-wasm/fixtures/conforma-shaped/input-pass.yaml \
  --policy hack/playground-wasm/fixtures/conforma-shaped/policy.yaml \
  --output json \
  --strict=false
```

Observed result:

- `success: true`
- 0 violations
- 0 warnings
- `success-count: 3`

This gives parity for the rule outcomes that users care about in this narrow
fixture: pass/fail, violation count, warning count, rule code, and message.
The browser output is still intentionally simpler than the CLI report envelope.

## Not Yet Full `ec validate input` Parity

| Conforma CLI behavior | Browser PoC status | Notes |
| --- | --- | --- |
| EnterpriseContractPolicy parsing | Partially exercised outside browser | The CLI fixture uses a local policy config; the browser still accepts pasted Rego/data directly. |
| Source resolution and downloading | Missing | No git, OCI, or remote bundle fetching in the browser path. |
| Include/exclude rule filtering | Missing | The playground queries package rules directly. |
| Conforma report shaping | Partial | Output is Conforma-like JSON, not the real CLI report type. |
| Policy metadata and docs links | Missing | OPA metadata comments are not inspected yet. |
| CLI custom built-ins | Unknown | Needs an inventory of Conforma-specific OPA built-ins used by real policies. |
| Sigstore/Rekor/OCI validation | Out of scope | Browser CORS and CLI dependency graph make this a backend or hybrid concern. |

## Suggested Next Experiment

Use the fixture in `fixtures/conforma-shaped/` as the baseline parity target.

1. Add include/exclude settings to the local `policy.yaml`.
2. Teach the browser evaluator either to apply equivalent filtering or to make
   clear that it does not.
3. Inventory Conforma-specific helper packages and OPA built-ins used by real
   policies.
4. Try one small real policy module from the release policy repo.

If exact parity is required, the recommendation should move toward a backend
or hybrid playground that calls the real `ec validate input` path. If the
playground is explicitly scoped to policy authoring, the browser-only evaluator
can stay useful as a fast syntax and logic loop.
