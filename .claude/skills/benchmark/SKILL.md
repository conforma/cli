---
name: benchmark
description: >
  Run performance benchmarks for the Conforma CLI. Use when users ask "run benchmark",
  "performance test", "stress test", "how fast", "benchmark data", "make benchmark",
  or need help with performance measurement and profiling.
---

# Run Performance Benchmarks

## Prerequisites

- Docker or Podman running (testcontainers for local OCI registry)
- Benchmark data prepared (see below)

## Two Benchmarks

### Simple (single-component)

Validates one golden-container image against the `@redhat` policy collection.

```bash
make benchmark_data    # prepare offline data (pulls from quay.io, ~760MB)
make benchmark         # run the simple benchmark
```

Or directly:
```bash
cd benchmark/simple
./prepare_data.sh      # one-time data prep
go run .               # run benchmark
go run . -benchnum 5   # run 5 iterations
```

### Stress (multi-component, parallel)

Validates a multi-component snapshot with configurable parallelism.

```bash
cd benchmark/stress
./prepare_data.sh
go run .
```

Configure via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `EC_STRESS_COMPONENTS` | 10 | Number of components in the snapshot |
| `EC_STRESS_WORKERS` | 35 | Number of parallel workers |

```bash
EC_STRESS_COMPONENTS=50 EC_STRESS_WORKERS=20 go run .
```

## Output Format

Both benchmarks use `golang.org/x/benchmarks/driver` and output in the standard Go benchmark format (ns/op, memory stats).

## Runtime Profiling

The CLI has built-in profiling via the `--trace` flag:

```bash
ec validate image --trace perf ...    # Go runtime trace file
ec validate image --trace cpu ...     # pprof CPU profile
ec validate image --trace mem ...     # heap profile
```
