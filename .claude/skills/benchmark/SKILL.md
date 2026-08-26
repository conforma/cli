---
name: benchmark
description: >
  Run performance benchmarks for the Conforma CLI. Use when users ask "run benchmark",
  "performance test", "stress test", "how fast", "benchmark data", "make benchmark",
  or need help with performance measurement and profiling.
---

# Run Performance Benchmarks for the Conforma CLI

Prepare data, execute benchmarks, and report results.

## Step 1: Check prerequisites

Verify Docker or Podman is running (needed for testcontainers local registry):

```bash
podman info > /dev/null 2>&1 || docker info > /dev/null 2>&1
echo $?
```

If neither is available, start Podman or Docker before proceeding.

## Step 2: Prepare benchmark data

```bash
make benchmark_data
```

Or manually:

```bash
cd benchmark/simple
./prepare_data.sh
```

This pulls data from quay.io (~760MB). Only needed once.

## Step 3: Run the simple benchmark

Single-component validation against the `@redhat` policy collection:

```bash
make benchmark
```

Or with a specific iteration count:

```bash
cd benchmark/simple
go run . -benchnum 5
```

## Step 4: Run the stress benchmark (optional)

Multi-component snapshot with configurable parallelism:

```bash
cd benchmark/stress
./prepare_data.sh
go run .
```

Configure scale:

```bash
EC_STRESS_COMPONENTS=50 EC_STRESS_WORKERS=20 go run .
```

Defaults: 10 components, 35 workers.

## Step 5: Profile if needed

Use the CLI's built-in profiling:

```bash
ec validate image --trace=perf ...    # Go runtime trace
ec validate image --trace=cpu ...     # pprof CPU profile
ec validate image --trace=mem ...     # heap profile
```

## Step 6: Report results

Output is in standard Go benchmark format (ns/op, memory stats). Summarize:
- Benchmark type run (simple/stress)
- Iteration count
- Key metrics (ns/op, allocs/op, bytes/op)
- Comparison with previous results if available
