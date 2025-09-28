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


# run-acceptance-tests.sh
# Script to run acceptance tests with proper environment setup
# 
# This script should be run from the repository root

set -e  # Exit on any error

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Change to repository root
cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO $(date '+%H:%M:%S')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS $(date '+%H:%M:%S')]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING $(date '+%H:%M:%S')]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR $(date '+%H:%M:%S')]${NC} $1"
}

print_debug() {
    echo -e "${CYAN}[DEBUG $(date '+%H:%M:%S')]${NC} $1"
}

print_test_info() {
    echo -e "${BLUE}[TEST $(date '+%H:%M:%S')]${NC} $1"
}

# Check if setup was completed
check_setup() {
    if [ ! -f "setup-test-env.sh" ]; then
        print_error "setup-test-env.sh not found. Please run setup-podman-machine.sh first."
        exit 1
    fi
    
    if ! podman machine list | grep -q "running"; then
        print_error "Podman machine is not running. Please run setup-podman-machine.sh first."
        exit 1
    fi
}

# Source environment variables
setup_environment() {
    print_status "Setting up environment variables..."
    source setup-test-env.sh
    print_success "Environment variables loaded"
}

# Clean up any existing test resources
cleanup_test_resources() {
    print_status "Cleaning up existing test resources..."
    
    # Clean up any existing Kind clusters
    kind delete cluster --all 2>/dev/null || true
    
    # Clean up any existing testcontainers
    podman system prune -f 2>/dev/null || true
    
    print_success "Test resources cleaned up"
}

# Run specific test or all tests
run_tests() {
    local test_pattern="${1:-}"
    local parallel="${2:-1}"
    local timeout="${3:-60m}"
    
    print_status "Running acceptance tests..."
    print_status "Test pattern: ${test_pattern:-'all tests'}"
    print_status "Parallelism: $parallel"
    print_status "Timeout: $timeout"
    
    # Check current directory and environment
    print_debug "Current directory: $(pwd)"
    print_debug "Environment variables:"
    print_debug "  KIND_EXPERIMENTAL_PROVIDER=$KIND_EXPERIMENTAL_PROVIDER"
    print_debug "  TESTCONTAINERS_RYUK_DISABLED=$TESTCONTAINERS_RYUK_DISABLED"
    print_debug "  TESTCONTAINERS_HOST_OVERRIDE=$TESTCONTAINERS_HOST_OVERRIDE"
    print_debug "  DOCKER_HOST=$DOCKER_HOST"
    
    # Check podman status
    print_debug "Podman machine status:"
    podman machine list
    print_debug "Podman system info:"
    podman system info | head -10
    
    # Check networks
    print_debug "Available networks:"
    podman network ls
    
    # Check if acceptance directory exists
    if [ ! -d "acceptance" ]; then
        print_error "acceptance directory not found in $(pwd)"
        exit 1
    fi
    
    cd acceptance
    print_debug "Changed to acceptance directory: $(pwd)"
    
    # Record start time
    local start_time=$(date +%s)
    print_test_info "Starting test execution at $(date)"
    
    if [ -n "$test_pattern" ]; then
        print_status "Running specific test: $test_pattern"
        print_debug "Command: go test -v -run \"$test_pattern\" -parallel $parallel -timeout $timeout ./..."
        
        # Run with timeout and capture output
        timeout 300 go test -v -run "$test_pattern" -parallel "$parallel" -timeout "$timeout" ./... 2>&1 | while IFS= read -r line; do
            print_test_info "$line"
        done
    else
        print_status "Running all tests"
        print_debug "Command: go test -v -parallel $parallel -timeout $timeout ./..."
        
        # Run with timeout and capture output
        timeout 300 go test -v -parallel "$parallel" -timeout "$timeout" ./... 2>&1 | while IFS= read -r line; do
            print_test_info "$line"
        done
    fi
    
    # Record end time and duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    print_test_info "Test execution completed in ${duration}s"
    
    # Check for any hanging processes
    print_debug "Checking for hanging processes..."
    ps aux | grep -E "(go test|kind|podman)" | grep -v grep || print_debug "No hanging processes found"
}

# Show usage information
show_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_PATTERN]"
    echo
    echo "OPTIONS:"
    echo "  -h, --help              Show this help message"
    echo "  -p, --parallel N        Set parallelism level (default: 1)"
    echo "  -t, --timeout DURATION  Set timeout (default: 60m)"
    echo "  -c, --cleanup           Clean up test resources before running"
    echo
    echo "TEST_PATTERN:"
    echo "  Optional pattern to run specific tests (e.g., 'TestFeatures/conftest')"
    echo
    echo "Examples:"
    echo "  $0                                    # Run all tests"
    echo "  $0 -p 2 -t 30m                      # Run with 2 parallel, 30min timeout"
    echo "  $0 'TestFeatures/conftest'           # Run only conftest tests"
    echo "  $0 -c 'TestFeatures/OPA'             # Clean up and run OPA tests"
}

# Parse command line arguments
parse_args() {
    local cleanup=false
    local parallel=1
    local timeout="60m"
    local test_pattern=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -p|--parallel)
                parallel="$2"
                shift 2
                ;;
            -t|--timeout)
                timeout="$2"
                shift 2
                ;;
            -c|--cleanup)
                cleanup=true
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                test_pattern="$1"
                shift
                ;;
        esac
    done
    
    # Run cleanup if requested
    if [ "$cleanup" = true ]; then
        cleanup_test_resources
    fi
    
    # Run tests
    run_tests "$test_pattern" "$parallel" "$timeout"
}

# Main execution
main() {
    echo "=========================================="
    echo "  Running Acceptance Tests"
    echo "=========================================="
    echo
    
    check_setup
    setup_environment
    
    # Parse arguments and run tests
    parse_args "$@"
    
    print_success "Test execution completed"
}

# Run main function with all arguments
main "$@"
