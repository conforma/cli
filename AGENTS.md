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

## Konflux/MintMaker Tekton task update reviews

Automated Konflux/MintMaker PRs update Tekton task bundle references in
`.tekton/` pipeline files. These updates fall into two categories with
different risk profiles:

**Digest-only bumps and patch version bumps** (e.g., updating the
`@sha256:...` digest or moving from `0.3.1` to `0.3.2`) are low-risk.
The task name and interface are unchanged, so cross-file analysis is
unnecessary — review the bundle reference change itself.

**Task name changes or task substitutions** (e.g., `clair-scan` →
`roxctl-scan`) are higher-risk. When a task name changes, grep the
codebase for references to the old task name. Key locations where task
names appear as string literals:

- **Go source** (`benchmark/`, `cmd/`, `pkg/`) — task-name filtering in
  SLSA provenance attestation processing, e.g.,
  `benchmark/offliner/scans.go` filters by task name to extract scan
  results. Stale references silently return empty results rather than
  errors.
- **Shell scripts** (`hack/`) — developer utilities like
  `hack/view-clair-reports.sh` use `jq` selects on task names.
- **Documentation and test fixtures** (`docs/`, `pkg/schema/examples/`)
  — example JSON and AsciiDoc references to task names.

When stale references are found, distinguish **production code paths**
(Go source in `benchmark/`, `cmd/`, `pkg/` — higher priority, should
block merge) from **developer utility scripts** in `hack/` (lower
priority, can be addressed in follow-up work).

## CGO and DNS Resolution

Binaries are built with `CGO_ENABLED=0` for portability. This uses Go's native DNS resolver,
which **cannot resolve second-level localhost domains** (e.g., `apiserver.localhost`).
Acceptance tests require `/etc/hosts` entries:

```
127.0.0.1 apiserver.localhost
127.0.0.1 rekor.localhost
```

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

## Troubleshooting

System-level issues that surface in acceptance tests:

| Problem | Fix |
|---------|-----|
| Go checksum mismatch | `go env -w GOPROXY='https://proxy.golang.org,direct'` |
| Podman container failures | Use user service: `systemctl enable --user --now podman.socket` |
| Too many containers (inotify) | `echo fs.inotify.max_user_watches=524288 \| sudo tee -a /etc/sysctl.conf` |
| Key limit errors | `echo kernel.keys.maxkeys=1000 \| sudo tee -a /etc/sysctl.conf` |
