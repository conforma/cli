# macOS Podman Machine Guide

This comprehensive guide covers setup, troubleshooting, performance optimization, and debugging for running acceptance tests on macOS with Podman machine.

> **Quick Start**: For automated setup, see [README.md](README.md) which provides automated scripts for setup and test execution.

## Prerequisites

Ensure you have the following tools installed:

```bash
# Check if required tools are installed
which kind kubectl podman
```

If any are missing, install them:

```bash
# Install kind
brew install kind

# Install kubectl
brew install kubectl

# Install podman
brew install podman
```

## Initial Setup

### 1. Start Podman Machine

```bash
# Check if podman machine is running
podman machine list

# If not running, start it
podman machine start
```

### 2. Set Environment Variables

```bash
# Set podman as the provider for kind
export KIND_EXPERIMENTAL_PROVIDER=podman

# Configure testcontainers for podman
export TESTCONTAINERS_RYUK_DISABLED=true
export TESTCONTAINERS_HOST_OVERRIDE=localhost
export DOCKER_HOST=unix:///var/run/docker.sock
```

### 3. Configure DNS Resolution

The tests require several localhost domains to resolve. Add them to your hosts file:

```bash
# Add required DNS entries
echo "127.0.0.1 rekor.localhost" | sudo tee -a /etc/hosts
echo "127.0.0.1 apiserver.localhost" | sudo tee -a /etc/hosts
echo "127.0.0.1 tuf.localhost" | sudo tee -a /etc/hosts
```

Verify DNS resolution works:

```bash
ping -c 1 rekor.localhost
ping -c 1 apiserver.localhost
ping -c 1 tuf.localhost
```

## Podman Machine Configuration

### Recommended Settings

For optimal performance with acceptance tests, configure your podman machine with sufficient resources:

```bash
# Stop existing machine
podman machine stop

# Remove existing machine (if needed)
podman machine rm podman-machine-default

# Create new machine with adequate resources
podman machine init --cpus 4 --memory 8192 --disk-size 500

# Start the machine
podman machine start
```

### Resource Requirements

- **CPU**: 4 cores minimum
- **Memory**: 8GB minimum
- **Disk**: 500GB recommended (tests use significant disk space)
- **Network**: Bridge network for testcontainers

## Running Tests

### Basic Test Execution

```bash
# Run all acceptance tests
E2E_INSTRUMENTATION=true make acceptance

# Or run tests directly
cd acceptance
go test -v ./...
```

### Optimized Test Execution

For better performance and resource management:

```bash
# Run with reduced concurrency to avoid resource exhaustion
go test -parallel 2 -timeout 30m ./...

# Run specific test scenarios
go test -v -run "TestFeatures/future_failure_is_a_deny_when_using_effective-date_flag" ./...
```

### Test Environment Variables

Set these environment variables before running tests:

```bash
export KIND_EXPERIMENTAL_PROVIDER=podman
export TESTCONTAINERS_RYUK_DISABLED=true
export TESTCONTAINERS_HOST_OVERRIDE=localhost
export DOCKER_HOST=unix:///var/run/docker.sock
```

## Performance Analysis

### ✅ **Individual Tests Run Fast:**
- **Simple tests**: ~9 seconds (no containers)
- **Container tests**: ~10 seconds (with registry + git containers)
- **No hanging processes** detected

### 🔍 **Container Test Breakdown:**
```
Container startup: ~4 seconds
├── Registry container: ~2 seconds
└── Git backend container: ~2 seconds

Test execution: ~5 seconds
└── Actual test logic

Total: ~10 seconds
```

### 🎯 **Potential Performance Issues:**

1. **Running All Tests Together**:
   - Creates many containers simultaneously
   - Can cause resource contention
   - **Solution**: Use `-parallel 1` and run tests in batches

2. **Kubernetes Tests**:
   - Create Kind clusters (slow)
   - May have cleanup issues
   - **Solution**: Run kubernetes tests separately

3. **Network Timeouts**:
   - Multiple tests hitting same endpoints
   - **Solution**: Add delays between tests

## Troubleshooting Common Issues

### 1. Disk Quota Exceeded

**Error**: `Disk quota exceeded: OCI runtime error`

**Solution**:
```bash
# Clean up existing containers
podman system prune -a -f

# Fix keyring quota issue
podman machine ssh
sudo sysctl -w kernel.keys.maxkeys=20000

# Recreate machine with more disk space
podman machine stop
podman machine rm podman-machine-default
podman machine init --cpus 4 --memory 8192 --disk-size 500
podman machine start
```

### 2. DNS Resolution Issues

**Error**: `dial tcp: lookup rekor.localhost: no such host`

**Solution**:
```bash
# Add all required localhost domains to hosts file
echo "127.0.0.1 rekor.localhost" | sudo tee -a /etc/hosts
echo "127.0.0.1 apiserver.localhost" | sudo tee -a /etc/hosts
echo "127.0.0.1 tuf.localhost" | sudo tee -a /etc/hosts

# Verify resolution
ping -c 1 rekor.localhost
ping -c 1 apiserver.localhost
ping -c 1 tuf.localhost
```

### 3. Network Connectivity Issues

**Error**: `no such host` or connection timeouts

**Solution**:
```bash
# Ensure environment variables are set
export KIND_EXPERIMENTAL_PROVIDER=podman
export TESTCONTAINERS_RYUK_DISABLED=true
export TESTCONTAINERS_HOST_OVERRIDE=localhost
export DOCKER_HOST=unix:///var/run/docker.sock

# Check podman machine status
podman machine list
```

### 4. Bridge Network Not Found

**Error**: `unable to find network with name or ID bridge: network not found`

**Solution**:
```bash
# Create the bridge network
podman network create bridge

# Or create a testcontainers network
podman network create testcontainers

# Verify networks exist
podman network ls
```

### 5. Test Timeout Issues

**Error**: Tests timing out after 5+ minutes

**Solution**:
```bash
# Run with reduced concurrency
go test -parallel 2 -timeout 30m ./...

# Or run individual tests
go test -v -run "TestName" ./...
```

## Debugging Commands

### Check Current Performance:
```bash
# Run single test with detailed logging
./hack/macos/run-acceptance-tests.sh "TestFeatures/a_warning_with_fail-on-warn"

# Run container test with logging
./hack/macos/run-acceptance-tests.sh "TestFeatures/track.*bundle" -t 5m
```

### Monitor Resource Usage:
```bash
# Check podman machine status
podman machine list

# Check running containers
podman ps

# Check system resources
podman system df
```

### Check for Hanging Processes:
```bash
# Look for hanging test processes
ps aux | grep -E "(go test|kind|podman)" | grep -v grep

# Check for hanging containers
podman ps -a
```

### Performance Optimization

#### Resource Management

```bash
# Monitor resource usage
podman system df
podman system events

# Clean up unused resources
podman system prune -a -f
```

#### Network Configuration

```bash
# Check network configuration
podman network ls
podman network inspect bridge

# Create testcontainers network if needed
podman network create testcontainers
```

## Test Results Interpretation

### Successful Test Run

```
=== RUN   TestFeatures
--- PASS: TestFeatures (2.73s)
    --- PASS: TestFeatures/future_failure_is_a_deny_when_using_effective-date_flag (2.70s)
PASS

Snapshot Summary
✓ 2 snapshots passed
```

### Common Test Failures

1. **Snapshot Mismatches**: Update snapshots with `UPDATE_SNAPS=clean go test ./...`
2. **Network Timeouts**: Check DNS resolution and environment variables
3. **Resource Exhaustion**: Increase podman machine resources
4. **Container Issues**: Clean up and recreate podman machine

## Recommendations

1. **For Development**: Run individual tests or small batches
2. **For CI**: Use `-parallel 1` to avoid resource contention
3. **For Kubernetes Tests**: Run separately with longer timeouts
4. **For Full Suite**: Consider running in stages

## Environment Persistence

To make the environment variables persistent across sessions, add them to your shell profile:

```bash
# Add to ~/.zshrc or ~/.bash_profile
echo 'export KIND_EXPERIMENTAL_PROVIDER=podman' >> ~/.zshrc
echo 'export TESTCONTAINERS_RYUK_DISABLED=true' >> ~/.zshrc
echo 'export TESTCONTAINERS_HOST_OVERRIDE=localhost' >> ~/.zshrc
echo 'export DOCKER_HOST=unix:///var/run/docker.sock' >> ~/.zshrc

# Reload shell configuration
source ~/.zshrc
```

## Cleanup

When done testing, you can clean up resources:

```bash
# Stop podman machine
podman machine stop

# Clean up containers and images
podman system prune -a -f

# Remove hosts file entry (optional)
sudo sed -i '' '/rekor.localhost/d' /etc/hosts
```

## Additional Notes

- Tests use testcontainers which require significant disk space
- Some tests may take several minutes to complete
- Network connectivity is crucial for tests involving external services
- Consider running tests in smaller batches for better resource management
- Monitor system resources during test execution

## Support

If you encounter issues not covered in this guide:

1. Check podman machine logs: `podman machine inspect`
2. Verify network connectivity: `ping rekor.localhost`
3. Check testcontainers configuration: `echo $TESTCONTAINERS_*`
4. Review test output for specific error messages
5. Consider increasing podman machine resources if tests are slow or failing