---
name: debug-failure
description: >
  Debug Conforma CLI test failures and runtime issues. Use when users ask "test
  failed", "debug failure", "why is this failing", "preserve temp dir", "podman
  error", "DNS resolution", "container failure", or need help troubleshooting.
---

# Debug a Failing Test or CLI Issue

## Step 1: Preserve Debug State

```bash
# CLI: preserve ec-work-* temp directories
ec validate image --debug ...
# or
EC_DEBUG=1 ec validate image ...

# Acceptance: keep containers running after failure (must use go test, not make)
cd acceptance && go test ./acceptance -args -persist

# Reattach to persisted containers later
cd acceptance && go test ./acceptance -args -restore
```

## Step 2: Read the Output

- **Unit/integration tests**: check the assertion message and stack trace
- **Acceptance tests**: check `features/__snapshots__/` for expected vs actual output. Snapshots are stored per feature file.
- **CLI runtime**: `ec-work-*` temp dirs (when `--debug` used) contain downloaded policies, OPA data, and evaluation artifacts

## Step 3: Common Failure Patterns

### DNS resolution failures
Binary is built with `CGO_ENABLED=0` (native Go DNS resolver). It cannot resolve second-level localhost domains.

**Fix:** Add to `/etc/hosts`:
```
127.0.0.1 apiserver.localhost
127.0.0.1 rekor.localhost
```

### Podman container failures
```bash
# Enable user podman socket
systemctl enable --user --now podman.socket

# macOS: setup podman machine
./hack/macos/setup-podman-machine.sh
```

### inotify / key limit errors
```bash
# Linux
sudo sysctl fs.inotify.max_user_watches=524288
sudo sysctl kernel.keys.maxkeys=1000
```

### Go checksum mismatch
```bash
go env -w GOPROXY='https://proxy.golang.org,direct'
```

### Snapshot mismatch in acceptance tests
```bash
UPDATE_SNAPS=true make acceptance
```

### `make generate` produces uncommitted changes
CI runs `make generate` then checks `git diff --exit-code`. If it fails, run `make generate` locally and commit the changes.

## Step 4: CI-Specific Issues

- Harden Runner is disabled for acceptance tests due to DNS resolution conflicts
- CI installs tkn and kubectl from pinned versions (not from Go tools)
- CI runs `hack/ubuntu-podman-update.sh` before acceptance tests
