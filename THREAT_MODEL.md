# Threat Model: conforma/cli

## 1. System Context

The Conforma CLI (`ec`) is a Go binary that verifies software supply chain
artifacts. It validates container image signatures, verifies SLSA provenance
attestations, and evaluates OPA/Rego policies against those attestations to
determine whether artifacts meet compliance requirements.

The CLI operates in three modes:

- **CLI mode** (primary): one-shot evaluation invoked by CI pipelines and
  developers. The main commands are `ec validate image` (verifies container
  images against policy), `ec validate input` (verifies arbitrary JSON/YAML
  against policy), and `ec validate vsa` (validates Verification Summary
  Attestations). Additional subcommands: `ec validate policy` (validate policy
  bundles), `ec fetch`, `ec inspect`, `ec opa`, `ec sigstore`, `ec track`,
  `ec compare`.
- **Server mode**: a persistent HTTP server (`ec validate input --server`) that
  exposes a REST API for policy evaluation. Evaluators are initialized at
  startup with policy source configuration, but actual policy bundle downloads
  occur on first evaluation (cached via `sync.OnceValues`). The server accepts
  input documents over HTTP and returns evaluation results.
- **Acceptance test mode**: instrumented binary with test infrastructure
  (Cucumber/Gherkin via Godog, Testcontainers, WireMock).

### Where it runs

In the Konflux CI/CD platform, the CLI runs inside a Tekton task
(`verify-enterprise-contract`) at two gates:

1. **Integration testing** (post-build): validates a Snapshot against the
   EnterpriseContractPolicy (ECP) referenced by the user's
   IntegrationTestScenario.
2. **Release gating** (pre-release): validates a Snapshot against the ECP
   specified in the ReleasePlanAdmission (RPA) in the managed namespace.

The CLI is built with `CGO_ENABLED=0` for portability. It is distributed as an
OCI image (`quay.io/conforma/cli`, `registry.redhat.io/rhtas/ec-rhel9`) and as
a Tekton task bundle (`quay.io/conforma/tekton-task`).

### External dependencies

The CLI interacts with several external systems at runtime:

| System | Interaction |
|--------|-------------|
| OCI registries (Quay, registry.redhat.io) | Pull policy bundles, data sources, images, attestations, SBOMs |
| Sigstore (cosign, Rekor, Fulcio, TUF) | Verify image/attestation signatures, keyless verification, transparency log checks |
| Kubernetes API server | Resolve ECP custom resources, fetch public keys from Secrets |
| Git hosting (GitHub, GitLab) | Download policy configuration from git repos |
| OPA/Conftest engine (embedded) | Evaluate Rego policies against attestation data |

Key direct dependencies: `sigstore/cosign`, `sigstore/rekor`,
`sigstore/sigstore`, `open-policy-agent/opa`, `open-policy-agent/conftest`,
`google/go-containerregistry` (via `conforma/go-containerregistry` fork),
`in-toto/in-toto-golang`, `conforma/go-gather`, `conforma/crds`.

## 2. Assets

Assets are the things the system protects, produces, or depends on.

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| **Evaluation result** | The pass/fail verdict and detailed report. The primary output -- a false "pass" means a non-compliant artifact reaches production. | Critical |
| **Image/attestation signatures** | Cosign signatures and DSSE-wrapped attestations on container images. Prove provenance and integrity. | High |
| **Signing keys** | Public keys used to verify signatures (from ECP or K8s Secrets). Private keys used to sign VSAs. Compromise allows forged attestations or VSAs. | Critical |
| **Policy bundles** | OCI-bundled Rego rules downloaded at evaluation time. Substitution or tampering changes what is enforced. | High |
| **Policy data sources** | External data (trusted task lists, allowed registries, vulnerability thresholds) merged into the OPA data tree. Manipulation weakens policy rules. | High |
| **EnterpriseContractPolicy (ECP)** | Declarative policy configuration (sources, keys, identity, exclusions). Controls what is verified and how. | High |
| **SLSA provenance attestations** | In-toto attestation content consumed by Rego rules. Crafted content can evade rule logic. | High |
| **VSA (Verification Summary Attestation)** | Signed record that an image was validated. Forged or expired VSAs can skip re-validation. | High |
| **OCI registry credentials** | Implicit credentials used to pull images, policy bundles, and data sources. Leakage enables supply chain attacks. | High |
| **Temporary files** | Work directories (`ec-work-*`), server-mode input files, OPA bundle caches. May contain attestation data, policy content, or evaluation artifacts. | Medium |
| **Server-mode state** | Loaded evaluators, in-flight evaluation contexts, request/response data. | Medium |

## 3. Entry Points and Trust Boundaries

Each entry point is a place where data crosses a trust boundary into the CLI.
The trust level indicates who controls the data.

### 3.1 CLI arguments and flags

| Entry point | Trust level | Description |
|-------------|-------------|-------------|
| `--policy` / `-p` | Varies | ECP reference: K8s name, file path, git URL, or inline JSON. In integration tests, user-controlled. In release gate, SRE-controlled. |
| `--image` / `--images` | User-controlled | Image references or Snapshot spec. Determines what is validated. |
| `--public-key` / `-k` | Varies | Overrides the key from ECP. In Konflux, set by the Tekton task (from K8s Secret). |
| `--rekor-url` / `-r` | Varies | Rekor URL for transparency log checks. In Konflux, set by `collect-keyless-params`. |
| `--ignore-rekor` | Varies | Disables Rekor transparency log checks. Set to `true` in Konflux pipelines for traditional signing verification. Set to `false` for keyless verification by the `collect-keyless-params` pipeline task (not enforced at the CLI level). |
| `--skip-image-sig-check` | User-controlled (integration) | Skips image signature verification entirely. |
| `--skip-att-sig-check` | User-controlled (integration) | Skips attestation signature verification. Unverified attestation content flows to all policy rules. |
| `--effective-time` | Varies | Controls time-based rule evaluation. Can demote time-gated violations from failures to warnings. |
| `--allow-past-effective-time` | Varies | Defaults to `false`. When false, prevents past dates in `--effective-time`. CLI-level guard against effective-time manipulation. |
| `--extra-rule-data` | Varies | Merges additional key=value pairs into policy rule data. Pipeline parameter in Tekton task. |
| `--strict` / `-s` | Varies | When `false`, CLI returns exit code 0 regardless of violations. |
| `--vsa-signing-key` | Operator-controlled | Private key for signing VSAs. File path or K8s Secret reference. (`ec validate image` only) |
| `--vsa-upload` | Operator-controlled | Storage backends for VSA upload (Rekor, local filesystem). (`ec validate image` only) |
| `--filter-type` | User-controlled | Selects policy filtering mode. |
| `--workers` | User-controlled | Number of concurrent validation workers. |

### 3.2 OCI registry interactions

| Entry point | Trust level | Description |
|-------------|-------------|-------------|
| Policy bundle download | Depends on ECP config | Rego policies downloaded as OCI artifacts from `spec.sources[].policy` URLs. Content determines what rules are enforced. |
| Data source download | Depends on ECP config | Policy data downloaded from `spec.sources[].data` URLs. Merged into OPA data tree via deep merge. |
| Image manifest/config fetch | Untrusted (attacker-controlled image) | Image metadata pulled from registry. Parsed by go-containerregistry. |
| Attestation fetch | Untrusted (attacker-controlled image) | DSSE-wrapped attestations fetched alongside images. Parsed and signature-verified before policy evaluation. |
| SBOM fetch | Untrusted (attacker-controlled image) | Software Bill of Materials fetched via custom OPA builtins (`ec.oci.*`). Parsed by CycloneDX/SPDX libraries. |
| VSA fetch | Semi-trusted | VSAs retrieved from Rekor or local storage. Must be signature-verified and within expiration window. |

### 3.3 Sigstore infrastructure

| Entry point | Trust level | Description |
|-------------|-------------|-------------|
| Cosign verification | Trusted infrastructure | Signature verification via cosign libraries. Relies on correct key/certificate configuration. |
| Rekor transparency log | Trusted infrastructure | Transparency log queries/uploads. Subject to network availability and TLS. |
| Fulcio CA / TUF root | Trusted infrastructure | Certificate authority and trust root for keyless verification. |
| TUF mirror | Trusted infrastructure | Distributes root of trust metadata. URL from cluster ConfigMap. |

### 3.4 Kubernetes API

| Entry point | Trust level | Description |
|-------------|-------------|-------------|
| ECP custom resource | SRE-controlled (release) / User-controlled (integration) | Policy configuration fetched from K8s API. |
| Public key from Secret | Platform-controlled | Signing key read from `k8s://openshift-pipelines/public-key`. |
| Cluster ConfigMap | Platform-controlled | `cluster-config` in `konflux-info` namespace provides OIDC issuer, Rekor URL, TUF mirror. |

### 3.5 Server mode (HTTP)

| Entry point | Trust level | Description |
|-------------|-------------|-------------|
| `POST /v1/validate/input` | Network caller | Accepts JSON/YAML body (up to 80MB). Written to temp file, evaluated against pre-loaded policies. |
| `GET /live` | Network caller | Liveness probe. Always returns 200. |
| `GET /ready` | Network caller | Readiness probe. Returns 200 when evaluators are initialized (policy downloads may still be pending until first evaluation). |

Server mode has **no built-in authentication, authorization, or rate limiting**.
The server binds to `127.0.0.1` by default but can be configured to `0.0.0.0`.

### 3.6 Custom OPA builtins

The CLI registers custom OPA builtins that extend the Rego evaluation
environment:

| Builtin | Description | Trust boundary |
|---------|-------------|----------------|
| `ec.sigstore.verify_image` | Verifies image signatures from within Rego. Accepts sigstore opts from policy rule data. | Rego rules control parameters passed to signature verification. |
| `ec.sigstore.verify_attestation` | Verifies attestation signatures from within Rego. Same parameter trust issue. | Same as above. |
| `ec.oci.*` (`image_manifest`, `image_manifests`, `image_index`, `image_files`, `image_tag_refs`, `image_referrers`, `blob`, `blob_files`, `descriptor`, `parsed_blob`) | Fetch OCI manifests, blobs, indexes, and image metadata. Require registry network access. | All bypass OPA network sandbox (by design -- need registry access). |
| `ec.purl.*` | Package URL parsing/validation. | Input from attestation content (untrusted). |

### 3.7 Policy configuration and data merge

| Entry point | Trust level | Description |
|-------------|-------------|-------------|
| `spec.sources[].ruleData` | Depends on ECP ownership | Becomes `data.rule_data__configuration__` in OPA. Controls thresholds, allowed lists, trusted tasks. |
| `spec.sources[].config` | Depends on ECP ownership | Include/exclude rules, volatile exclusions with time bounds. |
| Data source deep merge | Depends on data source ownership | External data merged into OPA `data.*` namespace. `rule_data__configuration__` takes precedence over `rule_data`. New keys can be injected if absent from CLI config structs. |
| `--extra-rule-data` merge | Depends on pipeline parameter control | Merges key=value pairs into each source's ruleData. Values are resolved via `GetPolicyConfig` (can reference K8s, files, git, inline JSON). |

### 3.8 VSA validation (`ec validate vsa`)

| Entry point | Trust level | Description |
|-------------|-------------|-------------|
| `--vsa-public-key` | Operator-controlled | Public key used to verify VSA signatures. File path or K8s Secret reference. |
| `--fallback-public-key` | Operator-controlled | Public key used for fallback image validation when VSA validation fails. This is a different key from the VSA verification key, used for a fundamentally different validation mode (full image signature verification). |
| `--no-fallback` | Operator-controlled | Disables fallback to full image validation when VSA validation fails. When set, a VSA validation failure is final with no image validation retry. Fallback is enabled by default. |
| `--ignore-signature-verification` | Operator-controlled | Skips VSA signature verification entirely. Parallels `--skip-att-sig-check` for attestations. |
| `--vsa-retrieval` | Operator-controlled | Controls how VSAs are retrieved (e.g., from Rekor or local storage). |

The `--ignore-signature-verification` flag is a direct bypass mechanism for VSA
signature checking. When enabled, unverified VSAs are accepted, removing the
primary control against threats CA-6 (VSA-based validation skip) and CR-2 (VSA
signing key compromise). Deployments relying on VSA trust should restrict access
to this flag.

## 4. Threats

### 4.1 Supply Chain

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| SC-1 | **Compromised policy bundle**: attacker substitutes a malicious Rego policy bundle at the OCI registry, causing the CLI to enforce weakened rules. | Critical -- all validation is bypassed. | Low -- requires compromising the registry or OCI push credentials. | Policy bundles can be pinned by digest (`POLICY_BUNDLE_DIGEST` task param). TLS required for downloads (`isSecure` check). OCI registries require authentication for push. |
| SC-2 | **Compromised data source**: attacker modifies external data source content (e.g., trusted task list, allowed registry prefixes) to weaken policy enforcement. | High -- specific rules are weakened. | Medium -- data sources may be in repos with broader write access than the policy repo. | Data sources are fetched over TLS. Content is deep-merged into the OPA data tree: nested map keys are merged recursively, but non-map values at the same key path are overwritten by the later source. |
| SC-3 | **Dependency compromise**: a transitive dependency (cosign, OPA, go-containerregistry, etc.) is compromised, introducing vulnerabilities in signature verification or policy evaluation. | Critical -- undermines core verification logic. | Low -- major open-source projects with active security review. | Renovate for dependency updates. `go.sum` integrity verification. `CGO_ENABLED=0` reduces native dependency surface. |
| SC-4 | **Tekton task bundle substitution**: attacker replaces the EC Tekton task bundle with a modified version that changes CLI invocation flags. | Critical -- attacker controls all CLI parameters. | Low -- task bundles are digest-pinned and managed by platform team. Trusted Tasks policy validates task provenance. | Task bundle digest pinning. Trusted Tasks verification in policy rules. |
| SC-5 | **Git-based policy source tampering**: policy configuration fetched via git URL (`github.com/user/repo`) could be modified between fetches if not pinned to a specific ref/commit. | High -- policy config changes without detection. | Medium -- depends on whether git refs are pinned. | Git URLs support `?ref=` pinning. |

### 4.2 Input Validation

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| IV-1 | **Malformed OCI manifest/image**: crafted image metadata causes parsing errors in go-containerregistry that result in fail-open behavior. | High -- validation skipped for unparseable images. | Low -- go-containerregistry is mature and well-tested. | Errors during image processing propagate as failures, not silent passes. |
| IV-2 | **Crafted attestation content**: attacker controls build pipeline (PaC definitions in their repo) and produces attestation content that technically satisfies Rego rule predicates but doesn't represent real compliance. | High -- rules pass but compliance is illusory. | Medium -- attacker controls source repo and build pipeline definition. Tekton Chains independently generates attestations from pipeline results, but the user controls what results the pipeline produces. | Chains generates attestations independently of user code. SLSA provenance structure is defined by Chains, not the user. Policy rules validate specific attestation fields. |
| IV-3 | **Type confusion in Rego evaluation**: OPA's dynamic typing means attestation fields with unexpected types (string vs. array vs. object) could cause rules to silently fail to match. | Medium -- individual rules may not fire, but this doesn't bypass signature verification. | Medium -- depends on rule implementation robustness in the policy repo. | This is primarily a policy repo concern, but the CLI's data marshaling layer should preserve types faithfully. |
| IV-4 | **Snapshot manipulation**: the `--images` or `--snapshot` input determines which images are validated. If an attacker can influence the Snapshot content, they could omit non-compliant components. | High -- non-compliant images skip validation entirely. | Low in Konflux -- Snapshots are created by the Integration Service from the Global Candidate List, not by the user. | Snapshot creation is a platform function. The `SINGLE_COMPONENT` task param reduces scope but is set by the pipeline, not the user. |
| IV-5 | **Server-mode input parsing**: the HTTP evaluation endpoint accepts up to 80MB of JSON/YAML, written to a temp file. Malformed input could cause excessive resource consumption. | Medium -- denial of service on the server instance. | Medium -- server has body size limits but no rate limiting. | 80MB body limit. 90-second evaluation timeout. Read/write timeouts on the HTTP server. Recovery middleware catches panics. |

### 4.3 Configuration Abuse

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| CA-1 | **`--strict=false` bypass**: setting strict to false causes the CLI to return exit code 0 regardless of policy violations. | High -- validation failures are silently ignored. | Low at release gate -- this parameter is set by the Tekton task definition, which the user does not control in the managed namespace. High at integration gate -- user controls IntegrationTestScenario. | Two-gate architecture: even if integration tests are bypassed, the release gate re-validates with SRE-controlled parameters. |
| CA-2 | **`--effective-time` manipulation**: setting effective time to a past or future date can demote time-gated rule violations from failures to warnings, or activate/deactivate rules with `effective_on` dates. | High -- security rules with effective dates can be silently demoted. | Low at release gate -- parameter set by Tekton task. | In Konflux, defaults to `"now"`. The task definition controls this value for release pipelines. `--allow-past-effective-time` defaults to `false`, rejecting past dates at the CLI level as defense-in-depth. |
| CA-3 | **`--skip-image-sig-check` / `--skip-att-sig-check`**: skipping signature verification allows unverified content to flow through all policy rules. Critically, `--skip-att-sig-check` makes the skip invisible in the JSON report (no violation, no field indicating the skip). | Critical -- all attestation-based rules evaluate unverified content. | Low at release gate -- these are Tekton task parameters controlled by the platform. | Two-gate architecture. These flags are integration-test-only bypasses in default Konflux. |
| CA-4 | **`--extra-rule-data` injection**: this parameter merges key=value pairs into ruleData for every policy source. Values are resolved via `GetPolicyConfig`, which supports K8s, file, git, and inline JSON references. An attacker who controls this parameter could override thresholds or inject new data keys. | High -- weakens specific policy rules by changing their data inputs. | Low at release gate -- `EXTRA_RULE_DATA` is a pipeline parameter. Medium at integration gate -- user controls ITS params. | The merge operates on the top-level ruleData object. Existing keys in ruleData are overwritten (not deep-merged), which is both a risk and a constraint. |
| CA-5 | **Policy configuration from user-controlled source**: the `--policy` flag accepts K8s references, file paths, git URLs, and inline JSON. In integration testing, the user chooses the ECP, which means they can point to a permissive policy. | Critical -- user defines what is enforced. | Integration: certain (by design). Release: not applicable (RPA controls the ECP). | The two-gate architecture is the mitigation. Integration testing uses user-controlled ECP by design. The release gate uses SRE-controlled ECP. |
| CA-6 | **VSA-based validation skip**: if an attacker can forge or inject a valid-looking VSA, the CLI will skip re-validation for that image. | High -- policy enforcement bypassed for the lifetime of the VSA. | Low -- VSAs require DSSE signature verification. The signing key must match. Expiration limits the window. | DSSE signing is mandatory for VSAs. Configurable expiration (default 7 days, production typically 24h). |

### 4.4 Network

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| NW-1 | **MITM on registry traffic**: attacker intercepts OCI registry connections to serve modified policy bundles, data sources, or attestations. | Critical -- attacker controls verification inputs. | Low -- all OCI registry traffic uses TLS. | `isSecure()` rejects plaintext HTTP sources. TLS certificate validation via Go's standard library. |
| NW-2 | **Registry unavailability**: OCI registry or sigstore infrastructure is unavailable, preventing validation from completing. | Medium -- build/release pipeline stalls. | Medium -- depends on registry/service uptime. | Retry with exponential backoff (via `oras-go` retry transport). Timeout configuration. |
| NW-3 | **Unauthenticated network exposure in server mode**: if the server binds to `0.0.0.0`, the unauthenticated HTTP API is accessible from any network. An attacker on the same network could submit evaluation requests or probe policy configuration. | Medium -- unauthorized policy evaluation, potential information disclosure of policy configuration. | Low -- default binding is `127.0.0.1`. Documentation warns about production use without a reverse proxy. | Default localhost binding. Server documentation recommends reverse proxy or network policy for production. |
| NW-4 | **Custom OPA builtins bypass network sandbox**: the `ec.oci.*` builtins make HTTP requests to OCI registries, intentionally bypassing OPA's network restrictions (`AllowNet`). A policy rule could use these to exfiltrate data. | Low -- only affects what Rego rules can access, not the CLI's own verification logic. | Low -- standard policy rules are reviewed. Custom Rego requires explicit configuration. | By design: builtins need registry access. Standard OPA builtins (`http.send`, etc.) are sandboxed. |

### 4.5 Cryptographic

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| CR-1 | **Signing key compromise**: the cosign key pair used by Tekton Chains is compromised, allowing forged signatures on arbitrary attestations. | Critical -- all signature-based verification is meaningless. | Low -- keys are per-cluster, stored in platform-managed Secrets, and not accessible from tenant namespaces. | Per-cluster key pairs. Namespace isolation. Key rotation procedures. |
| CR-2 | **VSA signing key compromise**: the private key used to sign VSAs is compromised, allowing forged VSAs that skip validation. | High -- validation bypassed for forged VSAs until expiration. | Low -- key access restricted to the operator configuring VSA generation. | Key management is operator responsibility. VSA expiration limits blast radius. |
| CR-3 | **Weak or misconfigured keyless verification**: overly broad certificate identity regex or OIDC issuer patterns could accept signatures from unintended signers. | High -- signatures from unauthorized sources are accepted. | Low -- these parameters are typically set by the Tekton task from cluster configuration. | Certificate identity and OIDC issuer can be exact strings or regexps. Platform sets these from the cluster ConfigMap. |

### 4.6 Runtime / Server Mode

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| RT-1 | **Denial of service via large input**: server mode accepts up to 80MB request bodies. Concurrent large requests could exhaust memory or disk. | Medium -- server instance becomes unresponsive. | Medium -- no rate limiting or concurrent request limits. | 80MB body size limit. 90-second evaluation timeout. Temp files cleaned up after each request. |
| RT-2 | **Stale policies in server mode**: policies are loaded once at startup. Policy changes require a server restart. A long-running server may enforce outdated policies. | Medium -- new policy rules or data are not applied until restart. | Medium -- depends on operational procedures. | Documented behavior: "Restart the server to pick up policy changes." |
| RT-3 | **Temp file leakage**: server-mode input files and `ec-work-*` directories may contain sensitive data (attestation content, policy configuration). | Low -- temp files are cleaned up after each request/evaluation. | Low -- files are created with default permissions, removed on completion. Setting `EC_DEBUG` env var preserves work directories for inspection. | `defer os.Remove(tmpPath)` in handler. Config files written with 0444 (world-readable) permissions; see mitigation #10 for the recommendation to restrict to 0600. |
| RT-4 | **Panic recovery exposes internal state**: the recovery middleware catches panics and returns a generic error, but stack traces are logged. | Low -- stack traces go to server logs, not to the HTTP response. | Low -- panics are exceptional. | Recovery middleware returns generic "internal server error". Stack trace logged at error level (not returned to caller). |

## 5. Deprioritized Threats

| Threat | Rationale |
|--------|-----------|
| **Local privilege escalation** | The CLI runs as an unprivileged process in a Tekton task pod. It does not have elevated privileges, setuid bits, or capability requirements. Container isolation provides the boundary. |
| **Acceptance test mode exploitation** | Test mode is not deployed in production. The instrumented binary is used only in development/CI environments. Attack surface does not extend to production. |
| **OPA/Conftest engine vulnerabilities** | OPA is a mature, widely-deployed policy engine with active security review. Bugs are possible but are upstream concerns, not specific to the CLI's threat model. The CLI tracks upstream releases via Renovate. |
| **Operator misconfiguration** | Operators who misconfigure the ECP (wrong key, permissive exclusions, etc.) introduce risk, but this is an operational concern, not a software vulnerability. The CLI faithfully enforces whatever policy it is given. |
| **Physical access to build infrastructure** | Out of scope. Assumes standard datacenter/cloud physical security. |
| **Side-channel attacks on cryptographic operations** | The CLI uses Go's standard crypto libraries and cosign. Side-channel resistance is an upstream concern. The CLI does not implement custom cryptography. |
| **Concurrent evaluation race conditions** | The worker pool model uses channels for communication. Workers operate on independent components with component-scoped caches. No shared mutable state between workers. |

## 6. Open Questions

1. **Data source provenance**: policy bundles can be pinned by digest, but data
   sources (e.g., `oci::quay.io/conforma/policy-data:latest`) are typically
   fetched by tag. Should data source integrity be verified independently
   (e.g., signature on data bundles)?

2. **`--skip-*-sig-check` visibility**: when signature checks are skipped,
   this fact is not represented in the JSON output report. Should the report
   include a field indicating that signature verification was skipped, so
   downstream consumers (and release pipelines) can detect it?

3. **Server mode hardening**: the server has no authentication, authorization,
   or rate limiting. If server mode is intended for production use, what
   hardening is expected to be provided by the deployment environment vs.
   built into the CLI?

4. **VSA trust chain**: VSAs are signed with a key provided by the operator.
   How is trust in the VSA signing key established? Is there a chain of trust
   back to the platform's signing infrastructure?

5. **Custom OPA builtin parameter trust**: the `ec.sigstore.verify_image` and
   `ec.sigstore.verify_attestation` builtins accept sigstore configuration
   options from Rego rule data. The serialization path between CLI config
   structs and what builtins accept has known gaps (e.g., `rekor_public_key`
   parsed but not serialized). Are there other fields where this mismatch
   exists?

6. **`EXTRA_RULE_DATA` scope at release gate**: the Tekton task exposes
   `EXTRA_RULE_DATA` as a parameter with an empty default. In release
   pipelines, is this parameter ever populated? If so, who controls its value?

7. **Effective time in release pipelines**: the `EFFECTIVE_TIME` task
   parameter defaults to `"now"`. Can release pipeline configurations override
   this, and if so, through what mechanism?

8. **Data source deep merge completeness**: the OPA deep merge recursively
   merges nested maps but overwrites non-map values at the same key path. Is
   the set of config struct fields serialized by the CLI complete enough that
   no security-relevant fields can be overwritten or injected via deep merge?

## 7. Provenance

Initial draft produced on 2026-07-22 from the following sources:

- **Codebase inspection**: conforma/cli repository, including
  `cmd/validate/image.go`, `cmd/validate/input.go`, `internal/server/`,
  `internal/signature/`, `internal/downloader/`, `internal/rego/`,
  `internal/evaluator/`, `internal/policy/`, `internal/validate/vsa/`,
  `AGENTS.md`, `go.mod`.
- **Jira stories**: EC-2001 (ec-cli threat model scope and acceptance criteria),
  EC-2003 (ec-policies threat model, for cross-reference).
- **Red team investigation materials**: EC-1807 epic investigation
  instructions, which document the attacker profile, Konflux architecture,
  trust boundaries, and known findings from the EC-1840 red team assessment.
- **Architecture knowledge**: Konflux CI/CD platform architecture including
  the two-namespace security model, Tekton Chains attestation generation,
  Integration Service Snapshot creation, and Release Service gating.
- **Design documents**: `internal/evaluator/DESIGN.md` (rule filtering),
  `internal/validate/vsa/DESIGN.md` (VSA design rationale).

Validated on 2026-08-05 against conforma/cli at commit `a915bcfe`. File paths,
package names, entry points, OPA builtin registrations, server mode
configuration, and dependency references were cross-referenced with the actual
codebase.

This document follows the wg-agentic-sdlc 8-section threat model schema as
specified in EC-2001.

## 8. Recommended Mitigations

### High priority

1. **Report signature skip status**: add a field to the JSON output report
   indicating whether image signature and/or attestation signature verification
   was skipped. This makes the skip visible to downstream consumers, enabling
   detection and rejection of reports where verification was skipped. (Addresses
   CA-3, open question 2.)

2. **Data source integrity verification**: support digest-pinning or signature
   verification for data source OCI bundles, not just policy bundles. Data
   sources directly control what policy rules enforce (trusted tasks, allowed
   registries, thresholds). (Addresses SC-2, open question 1.)

3. **Audit serialization gaps in OPA builtins**: systematically compare the
   fields parsed by `parseCheckOpts` in the sigstore builtins against the
   fields serialized by `SigstoreOpts`. Any field that is parsed but not
   serialized represents an injection vector via data source deep merge.
   (Addresses open question 5.)

4. **Pin data sources by digest in release ECPs**: operational recommendation
   for Konflux release engineering. Data sources in release-gate ECPs should
   reference OCI bundles by digest, not by mutable tags like `:latest`.
   (Addresses SC-2.)

### Medium priority

5. **Server mode authentication**: if server mode is intended for production
   deployments beyond localhost, add support for authentication (e.g., mTLS,
   bearer token) or clearly document that a reverse proxy with authentication
   is required. (Addresses NW-3, RT-1, open question 3.)

6. **Rate limiting in server mode**: add configurable rate limiting and
   concurrent request limits to prevent resource exhaustion from large or
   frequent requests. (Addresses RT-1.)

7. **`EXTRA_RULE_DATA` auditing**: log or report what extra rule data was
   injected, so that release pipeline audits can detect unexpected data
   manipulation. (Addresses CA-4, open question 6.)

8. **Effective time constraints**: consider restricting `--effective-time` to
   values within a bounded window (e.g., +/- 24 hours from now) at the release
   gate, or logging when a non-`"now"` value is used. (Addresses CA-2.)

### Low priority

9. **Server mode policy reload**: add a mechanism to reload policies without
   restarting the server (e.g., SIGHUP handler, reload endpoint), so that
   long-running servers can pick up policy changes. (Addresses RT-2.)

10. **Temp file permissions**: ensure server-mode temp files are created with
    restrictive permissions (0600) rather than relying on umask. (Addresses
    RT-3.)

11. **Document custom builtin network access**: clearly document that
    `ec.oci.*` builtins bypass OPA's `AllowNet` restrictions by design, so
    that policy authors understand the security implications when writing
    custom rules. (Addresses NW-4.)
