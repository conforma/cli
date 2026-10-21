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

## Not Yet Full `ec validate input` Parity

| Conforma CLI behavior | Browser PoC status | Notes |
| --- | --- | --- |
| EnterpriseContractPolicy parsing | Missing | The browser accepts pasted Rego/data directly instead of a policy config. |
| Source resolution and downloading | Missing | No git, OCI, or remote bundle fetching in the browser path. |
| Include/exclude rule filtering | Missing | The playground queries package rules directly. |
| Conforma report shaping | Partial | Output is Conforma-like JSON, not the real CLI report type. |
| Policy metadata and docs links | Missing | OPA metadata comments are not inspected yet. |
| CLI custom built-ins | Unknown | Needs an inventory of Conforma-specific OPA built-ins used by real policies. |
| Sigstore/Rekor/OCI validation | Out of scope | Browser CORS and CLI dependency graph make this a backend or hybrid concern. |

## Suggested Next Experiment

Use the fixture in `fixtures/conforma-shaped/` as the first parity target.

1. Keep the browser fixture passing.
2. Create an equivalent local policy config for `ec validate input`.
3. Run the same fail/pass input through the CLI.
4. Compare the rule result fields that matter for users: pass/fail, violation
   count, warning count, code, message, and metadata.

If exact parity is required, the recommendation should move toward a backend
or hybrid playground that calls the real `ec validate input` path. If the
playground is explicitly scoped to policy authoring, the browser-only evaluator
can stay useful as a fast syntax and logic loop.
