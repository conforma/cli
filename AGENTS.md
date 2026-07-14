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

- **Product name:** This project is "Conforma CLI" (binary name: `ec`). Do not use the former
  name "ec-cli" in user-facing strings, error messages, or documentation, even if issue
  descriptions or existing comments reference the old name.
- **Multi-module project:** root, `acceptance/`, `tools/` each have their own go.mod.
  Run `go mod tidy` in the right module.
- **Debug mode:** `--debug` or `EC_DEBUG=1` preserves `ec-work-*` temp directories for inspection.
- Conventional commits with Jira key encouraged (e.g., `feat(EC-1234): description`).

## CGO and DNS Resolution

Binaries are built with `CGO_ENABLED=0` for portability. This uses Go's native DNS resolver,
which **cannot resolve second-level localhost domains** (e.g., `apiserver.localhost`).
Acceptance tests require `/etc/hosts` entries:

```
127.0.0.1 apiserver.localhost
127.0.0.1 rekor.localhost
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
