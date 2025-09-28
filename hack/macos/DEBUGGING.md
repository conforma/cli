# Debugging Test Performance

## Enhanced Logging Added

Both setup and run scripts now include comprehensive logging with timestamps to help debug performance issues.

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

## Debugging Commands

### Check Current Performance:
```bash
# Run single test with detailed logging
./hack/podman-setup/run-acceptance-tests.sh "TestFeatures/a_warning_with_fail-on-warn"

# Run container test with logging
./hack/podman-setup/run-acceptance-tests.sh "TestFeatures/track.*bundle" -t 5m
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

## Recommendations

1. **For Development**: Run individual tests or small batches
2. **For CI**: Use `-parallel 1` to avoid resource contention
3. **For Kubernetes Tests**: Run separately with longer timeouts
4. **For Full Suite**: Consider running in stages

## Logging Features

- **Timestamps**: All log messages include timestamps
- **Debug Info**: Environment variables, podman status, networks
- **Test Output**: Real-time test execution output
- **Process Monitoring**: Check for hanging processes
- **Performance Metrics**: Test execution duration tracking
