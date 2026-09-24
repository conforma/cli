# Conforma CLI

Go CLI for verifying software supply chain artifacts — validates container image signatures,
provenance, and evaluates OPA/Rego policies. Built with `CGO_ENABLED=0`.

## Build & Test

```bash
make build                   # Build for current platform → dist/ec_<os>_<arch>
make test                    # Run unit + integration + generative tests
make lint                    # golangci-lint + addlicense + tekton-lint (0 warnings enforced)
make lint-fix                # Auto-fix lint issues
make ci                      # Full CI: test + lint-fix + acceptance
```

### Acceptance Tests

```bash
make acceptance              # Run all (Cucumber/Gherkin via Godog, 20m timeout)
make scenario_<name>         # Single scenario (replace spaces with underscores)
make feature_<name>          # All scenarios in a feature file
```

Flags: `-persist` keeps test env for debugging, `-restore` reruns against persisted env,
`-tags=@focus` runs tagged scenarios. Update snapshots: `UPDATE_SNAPS=true make acceptance`.

See `acceptance/README.md` for Testcontainers setup, WireMock stubbing, and snapshot testing details.

**macOS:** Acceptance tests require a Podman machine. Run `./hack/macos/setup-podman-machine.sh`
once for automated setup (creates machine with 4 CPUs, 8GB RAM, configures DNS and networks),
then `./hack/macos/run-acceptance-tests.sh` to run tests. See `hack/macos/README.md` for options
and `hack/macos/TROUBLESHOOTING.md` for detailed debugging.

### Test Tags

Tests use build tags with different timeouts:
- `unit` (10s), `integration` (15s), `generative` (30s), `acceptance` (20m)
- Run specific: `go test -tags=unit ./internal/evaluator -run TestName`

## Key Conventions

- **Multi-module project:** root, `acceptance/`, `tools/` each have their own go.mod.
  Run `go mod tidy` in the right module.
- **Debug mode:** `EC_DEBUG=1` preserves `ec-work-*` temp directories for inspection.
  The `--debug` flag only increases log verbosity.
- **Product name:** This project is "Conforma CLI" (binary name: `ec`). Use "Conforma CLI" in new
  user-facing strings, error messages, and documentation. Legacy identifiers required for
  compatibility (e.g., `quay.io/enterprise-contract/ec-cli`, Tekton parameter names) must be
  preserved as-is.

## Go file header convention

Go source files in this repository place the SPDX license header comment
before the `//go:build` tag. This is the established convention across
all Go files — do not flag build tag placement as a style violation.

## Security fix review expectations

Security bug fixes and vulnerability mitigations (PRs labeled `bug` +
`Possible security concern`, or referencing security-related Jira tickets
like EC-1842) should not be blocked on documentation updates.

Documentation gaps in files like `THREAT_MODEL.md`, `DESIGN.md`, and
user-facing docs should be flagged as informational comments (not
blocking change requests) when the PR's primary purpose is a security
fix. Authors are expected to create follow-up issues or PRs for
documentation updates after the security fix is merged.

## CGO and DNS Resolution

Binaries are built with `CGO_ENABLED=0` for portability. This uses Go's native DNS resolver,
which **cannot resolve second-level localhost domains** (e.g., `apiserver.localhost`).
Acceptance tests require `/etc/hosts` entries:

```
127.0.0.1 apiserver.localhost
127.0.0.1 rekor.localhost
```

## Benchmarks

Two benchmarks live under `benchmark/`:

- **simple/** — Single-component validation against the `@redhat` policy collection.
- **stress/** — Multi-component validation with configurable parallelism
  (`EC_STRESS_COMPONENTS`, `EC_STRESS_WORKERS`).

```bash
make benchmark              # Run simple benchmark
make benchmark_stress       # Run stress benchmark (via pattern rule)
make generate-baseline      # Run stress benchmark and write baseline.json
```

The stress benchmark has regression detection: `benchmark/stress/baseline.json` stores
reference metrics (peak RSS, ns/op) and `benchmark/stress/thresholds.json` defines
percentage thresholds. CI runs `benchmark/stress/compare.sh` to compare each run
against the baseline and fails the check on regression. Update the baseline with
`make generate-baseline` after intentional performance changes.

## Single-File Verification

```bash
golangci-lint run internal/evaluator/evaluator.go   # Lint a single file (fast)
gofmt -l internal/evaluator/evaluator.go            # Check formatting on a single file
```

## Design Documents

Read these before modifying the corresponding areas:

- [internal/evaluator/DESIGN.md](internal/evaluator/DESIGN.md) — rule filtering: why two resolvers, two-pass design, scoring precedence, adding filters
- [internal/validate/vsa/DESIGN.md](internal/validate/vsa/DESIGN.md) — VSA: storage backends, DSSE signing rationale, expiration model
- [acceptance/README.md](acceptance/README.md) — acceptance test framework, Testcontainers, WireMock, snapshot testing

## UBI Base Image Updates

The project pins the `ubi-minimal` base image digest in three Dockerfiles:

- `Dockerfile` (production)
- `Dockerfile.dist` (distribution)
- `acceptance/kubernetes/kind/acceptance.Dockerfile` (acceptance tests)

The script `hack/ubi-base-image-bump.sh` updates all three files to the same
digest and then invokes `hack/update-rpm-lock.sh` to regenerate `rpms.lock.yaml`.
Renovate raises the same bump automatically; the script exists for manual runs
between Renovate PRs. All three Dockerfiles must pin the same digest, and the
lockfile must be regenerated after any digest bump.

### RPM Lockfile Scope

`rpms.lock.yaml` is generated from `rpms.in.yaml`. It contains two kinds of
entries, and both are "tracked" for the purposes of this section:

1. The packages explicitly listed in `rpms.in.yaml` — currently
   `ca-certificates`, `jq`, and `gzip`.
2. Their resolved transitive dependencies pulled in by the resolver
   (for example `oniguruma`, which the lockfile carries as a dependency
   of `jq`). These are not named in `rpms.in.yaml` but appear in
   `rpms.lock.yaml` because the resolver had to pin them.

Together, "tracked packages" below means the union of (1) and (2): every RPM
that ends up in `rpms.lock.yaml`, whether requested directly or pulled in
transitively.

RPMs that ship inside the base image itself (for example `curl-minimal`,
`glib2`, `libcurl-minimal`, `libnghttp2`) are **not** tracked in the lockfile —
they are neither listed in `rpms.in.yaml` nor pulled in as a transitive
dependency of anything that is.

Consequence: when a UBI base image digest bump ships updates only to
base-image-bundled RPMs and no tracked package's available version changed
(neither an explicitly listed package nor any of its resolved transitive
dependencies), `hack/update-rpm-lock.sh` runs successfully but produces no
diff in `rpms.lock.yaml`. A commit that bumps the digest in the Dockerfiles
without touching `rpms.lock.yaml` is the expected outcome in that case, not
evidence that the lockfile was skipped.

### Review Guidance for UBI Bump PRs

On any PR that bumps the `ubi-minimal` digest:

- Do **not** flag "`rpms.lock.yaml` was not regenerated" as a finding solely
  because the lockfile is unchanged. Regeneration is a no-op when no tracked
  package's version changed, and that is the common case. Confirm the lockfile
  was regenerated only by asking the author (or checking CI logs) — the diff
  alone cannot prove it either way.
- If the concern is that a new base-image-bundled RPM should be tracked
  explicitly, that is a separate change to `rpms.in.yaml`, not a bug in the
  bump PR.

On `release-v*` branches, bump PRs may intentionally update only the production
Dockerfiles (`Dockerfile`, `Dockerfile.dist`) and skip the acceptance
Dockerfile, since acceptance test infrastructure is typically not backported.
The coordinated update set in `hack/ubi-base-image-bump.sh` applies to `main`;
a narrower scope on release branches is expected, not stale.

## Claude Code Skills

Skills live in `.claude/skills/<name>/SKILL.md`. They are **step-by-step executable workflows**
that Claude Code follows to complete a task — not reference documentation, how-to guides, or
API descriptions.

### Format

Every skill file has three parts:

**1. YAML frontmatter** with `name` (kebab-case, matches directory name) and `description`
(multi-line string listing trigger phrases so Claude Code knows when to invoke the skill):

```yaml
---
name: my-skill
description: >
  Short description. Use when users ask "trigger phrase 1", "trigger phrase 2",
  or need help with <topic>.
---
```

**2. Title and summary** — an `# H1` heading describing the skill's purpose, followed by a
one-line description of what the skill does:

````markdown
# Do the Thing

Determine what to do, execute it, and report results.
````

**3. Numbered step sections** — each `## Step N: Action` contains a brief explanation and,
typically, fenced code blocks (usually `bash`) with the concrete commands to run. The final step is always
`## Step N: Report [<topic>]`, describing what to summarize to the user:

````markdown
## Step 1: Do the first thing

Explanation of what this step accomplishes.

```bash
make build
```

## Step 2: Report results

Summarize:
- What happened
- Pass/fail status
- What needs attention
````

### Anti-patterns

- **How-to guides or reference docs:** Skills are not documentation — they are runbooks.
  "Here's how you could run tests" is wrong; "Run these tests and report the results" is right.
- **Missing trigger phrases:** Without them, Claude Code won't know when to invoke the skill.
- **Prose-only steps:** Action steps should generally include concrete commands, not just prose.
  Brief prose-only steps are acceptable when they establish context (e.g., classifying inputs).

See [.claude/skills/run-tests/SKILL.md](.claude/skills/run-tests/SKILL.md) as the canonical example.

## Troubleshooting

System-level issues that surface in acceptance tests:

| Problem | Fix |
|---------|-----|
| Go checksum mismatch | `go env -w GOPROXY='https://proxy.golang.org,direct'` |
| Podman container failures | Use user service: `systemctl enable --user --now podman.socket` |
| Too many containers (inotify) | `echo fs.inotify.max_user_watches=524288 \| sudo tee -a /etc/sysctl.conf` |
| Key limit errors | `echo kernel.keys.maxkeys=1000 \| sudo tee -a /etc/sysctl.conf` |

## Dependency Management

Go version updates are managed by both Renovate and Mintmaker (`red-hat-konflux[bot]`). The local `renovate.json` extends the org-level preset at `conforma/.github` with an additional `helpers:pinGitHubActionDigests` extension. The org-level config's dependency grouping strategy for Go has changed over time — config comments may reference a "go version" group that was never fully implemented. Do not propose changes to the Renovate or Mintmaker configuration for Go version management (e.g., adding package rules, re-enabling or disabling automated Go version bumps, or creating new dependency groups) without explicit maintainer approval.
