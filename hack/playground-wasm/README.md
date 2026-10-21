# Conforma Playground WASM PoC

This is a spike for EC-2222. It proves a narrow browser-local policy authoring
loop: inline Rego plus inline JSON/YAML input evaluated by OPA from Go compiled
to WebAssembly.

It intentionally does not run the full Conforma CLI command tree. The current
goal is to learn whether the browser can support the core `ec validate input`
authoring experience before pulling in image validation, OCI fetching, Sigstore,
Rekor, or remote policy source loading.

## Build and Run

From the repository root:

```bash
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" hack/playground-wasm/
GOOS=js GOARCH=wasm go build -o hack/playground-wasm/playground.wasm ./hack/playground-wasm
python3 -m http.server 8090 -d hack/playground-wasm
```

Then open:

```text
http://localhost:8090
```

`playground.wasm` and `wasm_exec.js` are generated local artifacts and are
ignored by Git.

## What It Supports

- A single pasted Rego module.
- Multiple pasted Rego modules separated by `# file: <name>.rego` markers.
- Pasted JSON or YAML input.
- Optional pasted JSON or YAML data available under `data`.
- `deny`, `violation`, and `warn` rules in the module package.
- A Conforma-like JSON result with `success`, `violations`, `warnings`, and
  parse/evaluation `errors`.

## What It Does Not Prove

- Full `ec validate input` parity.
- EnterpriseContractPolicy parsing.
- Include/exclude filtering.
- Remote policy fetching.
- OCI image, attestation, Rekor, or Sigstore flows.
- Website integration or production UX.

Those are follow-up decisions after the spike establishes whether a small
browser-local evaluator is practical.
