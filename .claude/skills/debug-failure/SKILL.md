---
name: debug-failure
description: >
  Debug Conforma CLI test failures and runtime issues. Use when users ask "test
  failed", "debug failure", "why is this failing", "preserve temp dir", "podman
  error", "DNS resolution", "container failure", or need help troubleshooting.
---

# Debug a Failing Test or CLI Issue

Investigate the failure, preserve debug state, identify the root cause, and report findings.

## Step 1: Reproduce and preserve debug state

For CLI runtime issues, preserve temp directories:

```bash
EC_DEBUG=1 ec validate image ...
```

This keeps `ec-work-*` temp dirs for inspection. The `--debug` flag only increases log verbosity.

For acceptance test failures, keep containers running:

```bash
(cd acceptance && go test . -args -persist)
```

Reattach later with:

```bash
(cd acceptance && go test . -args -restore)
```

## Step 2: Read the failure output

- **Unit/integration tests**: check the assertion message and stack trace
- **Acceptance tests**: compare `features/__snapshots__/` for expected vs actual output
- **CLI runtime**: inspect `ec-work-*` temp dirs for downloaded policies, OPA data, and evaluation artifacts

```bash
ls -la /tmp/ec-work-*
```

## Step 3: Check common failure patterns

Run through each check and report which applies:

### DNS resolution failures

Binary is built with `CGO_ENABLED=0` (native Go DNS resolver). Check `/etc/hosts`:

```bash
grep -E 'apiserver\.localhost|rekor\.localhost' /etc/hosts
```

If missing, add:

```text
127.0.0.1 apiserver.localhost
127.0.0.1 rekor.localhost
```

### Podman issues

```bash
# Check podman socket (Linux)
systemctl --user status podman.socket

# macOS: verify podman machine
podman machine info
# If not configured:
./hack/macos/setup-podman-machine.sh
```

### inotify / key limit errors

```bash
cat /proc/sys/fs/inotify/max_user_watches
# If below 524288:
sudo sysctl fs.inotify.max_user_watches=524288

cat /proc/sys/kernel/keys/maxkeys
# If below 1000:
sudo sysctl kernel.keys.maxkeys=1000
```

### Go checksum mismatch

```bash
go env GOPROXY
# If not set correctly:
go env -w GOPROXY='https://proxy.golang.org,direct'
```

### Snapshot mismatch

```bash
UPDATE_SNAPS=true make acceptance
git diff features/__snapshots__/
```

Review the diff to confirm changes are expected.

### Generated code out of sync

```bash
make generate
git diff --exit-code
```

If CI fails with "File was modified in build", commit the generated changes.

## Step 4: Check CI-specific issues

If the failure is CI-only:

- Harden Runner is disabled for acceptance tests (DNS conflicts)
- CI installs tkn and kubectl from pinned versions, not Go tools
- CI runs `hack/ubuntu-podman-update.sh` before acceptance tests

## Step 5: Report findings

Summarize:
- Root cause identified or suspected
- Which check from Step 3 matched
- Fix applied or recommended
- Whether the fix needs to be committed
