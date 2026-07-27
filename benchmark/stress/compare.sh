#!/bin/bash
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Compares current benchmark results against a stored baseline and exits
# non-zero if any metric regresses beyond the configured threshold.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE="${SCRIPT_DIR}/baseline.json"
THRESHOLDS="${SCRIPT_DIR}/thresholds.json"
BENCHMARK_OUTPUT="${1:-${SCRIPT_DIR}/benchmark-output.txt}"

if [[ ! -f "$BASELINE" ]]; then
    echo "No baseline found, skipping comparison."
    exit 0
fi

if [[ ! -f "$THRESHOLDS" ]]; then
    echo "No thresholds file found, skipping comparison."
    exit 0
fi

if [[ ! -f "$BENCHMARK_OUTPUT" ]]; then
    echo "No benchmark output found at ${BENCHMARK_OUTPUT}"
    exit 1
fi

line=$(grep '^BenchmarkStress' "$BENCHMARK_OUTPUT" || true)
if [[ -z "$line" ]]; then
    echo "No BenchmarkStress results found in output."
    exit 1
fi

current_ns=$(echo "$line" | grep -oP '[\d.]+ ns/op' | awk '{print $1}')
current_rss=$(echo "$line" | grep -oP '[\d.]+ peak-RSS-bytes' | awk '{print $1}')

baseline_ns=$(python3 -c "import json; print(json.load(open('${BASELINE}'))['execution_time_ns'])")
baseline_rss=$(python3 -c "import json; print(json.load(open('${BASELINE}'))['peak_rss_bytes'])")
threshold_rss=$(python3 -c "import json; print(json.load(open('${THRESHOLDS}'))['peak_rss_percent'])")
threshold_time=$(python3 -c "import json; print(json.load(open('${THRESHOLDS}'))['execution_time_percent'])")

rss_change=$(awk -v cur="$current_rss" -v base="$baseline_rss" 'BEGIN {printf "%.1f", ((cur - base) / base) * 100}')
time_change=$(awk -v cur="$current_ns" -v base="$baseline_ns" 'BEGIN {printf "%.1f", ((cur - base) / base) * 100}')

baseline_rss_mb=$(awk -v val="$baseline_rss" 'BEGIN {printf "%.0f", val / 1048576}')
current_rss_mb=$(awk -v val="$current_rss" 'BEGIN {printf "%.0f", val / 1048576}')
baseline_secs=$(awk -v val="$baseline_ns" 'BEGIN {printf "%.1f", val / 1000000000}')
current_secs=$(awk -v val="$current_ns" 'BEGIN {printf "%.1f", val / 1000000000}')

echo ""
echo "=== Benchmark Comparison ==="
echo ""
printf "%-20s %10s %10s %10s %10s\n" "Metric" "Baseline" "Current" "Change" "Threshold"
printf "%-20s %10s %10s %9s%% %9s%%\n" "Peak RSS" "${baseline_rss_mb} MB" "${current_rss_mb} MB" "$rss_change" "$threshold_rss"
printf "%-20s %10s %10s %9s%% %9s%%\n" "Execution time" "${baseline_secs}s" "${current_secs}s" "$time_change" "$threshold_time"
echo ""

failed=0

rss_exceeded=$(awk -v change="$rss_change" -v thresh="$threshold_rss" 'BEGIN {print (change > thresh) ? 1 : 0}')
time_exceeded=$(awk -v change="$time_change" -v thresh="$threshold_time" 'BEGIN {print (change > thresh) ? 1 : 0}')

if [[ "$rss_exceeded" == "1" ]]; then
    echo "FAIL: Peak RSS regressed by ${rss_change}% (threshold: ${threshold_rss}%)"
    failed=1
fi

if [[ "$time_exceeded" == "1" ]]; then
    echo "FAIL: Execution time regressed by ${time_change}% (threshold: ${threshold_time}%)"
    failed=1
fi

if [[ "$failed" == "0" ]]; then
    echo "PASS: No regressions detected."
fi

exit "$failed"
