# Podman Machine Setup Scripts

This directory contains automated scripts for setting up and running acceptance tests on macOS with Podman machine.

## Location
These scripts are located in `hack/podman-setup/` and should be run from the repository root.

## Scripts Overview

### 1. `setup-podman-machine.sh`
**Purpose**: Complete automated setup of Podman machine for acceptance tests

**What it does**:
- Checks prerequisites (podman, kind, kubectl)
- Cleans up existing podman machine
- Creates new podman machine with optimal settings (4 CPUs, 8GB RAM, 500GB disk)
- Fixes keyring quota issue (critical for avoiding "Disk quota exceeded" errors)
- Creates required networks (testcontainers)
- Configures DNS resolution (rekor.localhost, apiserver.localhost)
- Creates environment setup script
- Tests the setup

**Usage**:
```bash
# From repository root
./hack/podman-setup/setup-podman-machine.sh
```

### 2. `run-acceptance-tests.sh`
**Purpose**: Run acceptance tests with proper environment setup

**What it does**:
- Checks if setup was completed
- Loads environment variables
- Optionally cleans up test resources
- Runs tests with configurable parallelism and timeout
- Supports running specific test patterns

**Usage**:
```bash
# From repository root
# Run all tests
./hack/podman-setup/run-acceptance-tests.sh

# Run with custom settings
./hack/podman-setup/run-acceptance-tests.sh -p 2 -t 30m

# Run specific tests
./hack/podman-setup/run-acceptance-tests.sh "TestFeatures/conftest"

# Clean up and run
./hack/podman-setup/run-acceptance-tests.sh -c "TestFeatures/OPA"
```

## Quick Start

1. **Initial Setup** (run once):
   ```bash
   ./hack/podman-setup/setup-podman-machine.sh
   ```

2. **Run Tests**:
   ```bash
   ./hack/podman-setup/run-acceptance-tests.sh
   ```

## Environment Variables

The setup script creates `setup-test-env.sh` with these variables:
- `KIND_EXPERIMENTAL_PROVIDER=podman`
- `TESTCONTAINERS_RYUK_DISABLED=true`
- `TESTCONTAINERS_HOST_OVERRIDE=localhost`
- `DOCKER_HOST=unix:///var/run/docker.sock`

## Troubleshooting

### Common Issues

1. **"Disk quota exceeded" errors**:
   - The setup script automatically fixes this with `kernel.keys.maxkeys=20000`
   - If you still get errors, run: `podman machine ssh "sudo sysctl -w kernel.keys.maxkeys=20000"`

2. **"Network not found" errors**:
   - The setup script creates the required `testcontainers` network
   - If missing, run: `podman network create testcontainers`

3. **DNS resolution issues**:
   - The setup script adds required entries to `/etc/hosts`
   - If missing, add: `127.0.0.1 rekor.localhost` and `127.0.0.1 apiserver.localhost`

4. **TLS handshake timeouts**:
   - These are usually from stale Kubernetes connections
   - Clean up with: `kind delete cluster --all`

### Manual Cleanup

If you need to start over:
```bash
# Stop and remove podman machine
podman machine stop
podman machine rm podman-machine-default

# Clean up system
podman system prune -a -f

# Re-run setup
./hack/podman-setup/setup-podman-machine.sh
```

## Script Features

- **Colorized output** for easy reading
- **Error handling** with proper exit codes
- **Prerequisite checking** before setup
- **Automatic cleanup** of existing resources
- **Environment validation** after setup
- **Flexible test execution** with various options

## Dependencies

- `podman` (installed via Homebrew)
- `kind` (installed via Homebrew)
- `kubectl` (installed via Homebrew)
- `sudo` access (for /etc/hosts modification)

Install missing dependencies:
```bash
brew install podman kind kubectl
```
