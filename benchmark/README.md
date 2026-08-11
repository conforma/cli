# Benchmarks of ec CLI

Benchmarks within this directory use the [golang
benchmarking](golang.org/x/benchmarks/) package and output in the [standard
benchmark
format](https://go.googlesource.com/proposal/+/master/design/14313-benchmark-format.md).

Each benchmark is built as a standalone executable with no external dependency
other than any data that is contained within it. Benchmarks are run from within
the directory they're defined in, simply by running `go run .`, additional
arguments can be passed in, for example `-benchnum 10` to run the benchmark 10
times.

## Available benchmarks

- **simple/** — Single-component validation against the `@redhat` policy collection.
- **stress/** — Multi-component validation with configurable parallelism. Set
  `EC_STRESS_COMPONENTS` (default 10) and `EC_STRESS_WORKERS` (default 35) to
  control the workload.

## Baseline and regression detection

The stress benchmark stores a performance baseline in
`stress/baseline.json` (peak RSS and ns/op) along with configurable
regression thresholds in `stress/thresholds.json`. The CI workflow
compares each run against the baseline and fails the check when a metric
exceeds its threshold.

To regenerate the baseline after an intentional change:

```
make generate-baseline
```

This runs the stress benchmark locally, parses the results, and writes a
new `baseline.json` with the current commit SHA, date, Go version, and
worker/component counts.

Thresholds are expressed as percentages (e.g., 15 means a 15% increase
triggers a failure). Adjust them in `stress/thresholds.json` as
optimizations land.
