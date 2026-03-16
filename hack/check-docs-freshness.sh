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

# Check for potentially stale documentation
# Run periodically or before releases

set -e

echo "=== Checking Documentation Freshness ==="
echo ""

# Check if design docs reference files that no longer exist
echo "## Checking for dead references in design docs..."
for doc in docs/design-docs/*.md; do
    # Look for references to internal/ files
    grep -oE 'internal/[a-zA-Z_/]+\.go' "$doc" 2>/dev/null | while read -r file; do
        if [[ ! -f "$file" ]]; then
            echo "WARNING: $doc references non-existent file: $file"
        fi
    done
done

# Check if key files were modified more recently than their docs
echo ""
echo "## Checking if code is newer than docs..."

check_freshness() {
    local code_file="$1"
    local doc_file="$2"

    if [[ -f "$code_file" && -f "$doc_file" ]]; then
        code_time=$(git log -1 --format="%ct" -- "$code_file" 2>/dev/null || echo "0")
        doc_time=$(git log -1 --format="%ct" -- "$doc_file" 2>/dev/null || echo "0")

        if [[ "$code_time" -gt "$doc_time" ]]; then
            code_date=$(git log -1 --format="%ci" -- "$code_file" 2>/dev/null | cut -d' ' -f1)
            doc_date=$(git log -1 --format="%ci" -- "$doc_file" 2>/dev/null | cut -d' ' -f1)
            echo "STALE: $doc_file (updated $doc_date) may be outdated"
            echo "       $code_file was modified $code_date"
        fi
    fi
}

# Key code-to-doc mappings
check_freshness "internal/evaluator/filters.go" "docs/design-docs/rule-filtering.md"
check_freshness "internal/evaluator/filters.go" "docs/design-docs/package-filtering.md"
check_freshness "internal/validate/vsa/vsa.go" "docs/design-docs/vsa-architecture.md"
check_freshness "cmd/validate/image.go" "docs/ARCHITECTURE.md"

echo ""
echo "## Summary"
echo "Run 'git log --oneline -5 -- docs/' to see recent doc changes"
echo "Run 'git log --oneline -5 -- internal/' to see recent code changes"
