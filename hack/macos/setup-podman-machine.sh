#!/bin/bash

# setup-podman-machine.sh
# Automated setup script for running acceptance tests on macOS with Podman machine
# Based on README_MACOS.md
# 
# This script should be run from the repository root

set -e  # Exit on any error

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Change to repository root
cd "$REPO_ROOT"

echo "🚀 Setting up Podman machine for acceptance tests..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output with timestamps
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
    echo -e "${BLUE}[DEBUG $(date '+%H:%M:%S')]${NC} $1"
}

# Check if required tools are installed
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    local missing_tools=()
    
    if ! command -v podman &> /dev/null; then
        missing_tools+=("podman")
    fi
    
    if ! command -v kind &> /dev/null; then
        missing_tools+=("kind")
    fi
    
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        echo "Install them with:"
        echo "  brew install podman kind kubectl"
        exit 1
    fi
    
    print_success "All prerequisites are installed"
}

# Clean up existing podman machine
cleanup_existing_machine() {
    print_status "Cleaning up existing podman machine..."
    
    # Stop and remove existing machine if it exists
    if podman machine list | grep -q "podman-machine-default"; then
        print_status "Stopping existing podman machine..."
        podman machine stop podman-machine-default || true
        
        print_status "Removing existing podman machine..."
        podman machine rm podman-machine-default || true
    fi
    
    # Clean up system (only if podman is running)
    print_status "Cleaning up podman system..."
    if podman system info > /dev/null 2>&1; then
        podman system prune -a -f || true
    else
        print_status "Podman not running, skipping system cleanup"
    fi
    
    print_success "Cleanup completed"
}

# Create new podman machine with optimal settings
create_podman_machine() {
    print_status "Creating new podman machine with optimal settings..."
    
    # Create machine with sufficient resources
    podman machine init \
        --cpus 4 \
        --memory 8192 \
        --disk-size 500
    
    print_success "Podman machine created"
}

# Start podman machine
start_podman_machine() {
    print_status "Starting podman machine..."
    
    local start_time=$(date +%s)
    podman machine start
    
    # Wait for machine to be ready with progress updates
    print_status "Waiting for podman machine to be ready..."
    local wait_time=0
    local max_wait=60  # 60 seconds max wait
    
    while [ $wait_time -lt $max_wait ]; do
        if podman machine list | grep -q "running"; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_success "Podman machine is running (took ${duration}s)"
            return 0
        fi
        
        print_debug "Still waiting for podman machine... (${wait_time}s)"
        sleep 2
        wait_time=$((wait_time + 2))
    done
    
    print_error "Failed to start podman machine within ${max_wait}s"
    print_debug "Current machine status:"
    podman machine list
    exit 1
}

# Fix keyring quota issue
fix_keyring_quota() {
    print_status "Fixing keyring quota issue..."
    
    # This is the critical fix for "Disk quota exceeded" errors
    podman machine ssh "sudo sysctl -w kernel.keys.maxkeys=20000" || {
        print_warning "Could not set keyring quota. You may need to run this manually:"
        echo "  podman machine ssh"
        echo "  sudo sysctl -w kernel.keys.maxkeys=20000"
    }
    
    print_success "Keyring quota fixed"
}

# Create required networks
create_networks() {
    print_status "Creating required networks..."
    
    # Create testcontainers network
    podman network create testcontainers || {
        print_warning "testcontainers network already exists"
    }
    
    # Verify networks exist
    if ! podman network ls | grep -q "testcontainers"; then
        print_error "Failed to create testcontainers network"
        exit 1
    fi
    
    print_success "Networks created successfully"
}

# Configure DNS resolution
configure_dns() {
    print_status "Configuring DNS resolution..."
    
    # Add required localhost entries
    if ! grep -q "rekor.localhost" /etc/hosts; then
        echo "127.0.0.1 rekor.localhost" | sudo tee -a /etc/hosts
        print_success "Added rekor.localhost to /etc/hosts"
    else
        print_status "rekor.localhost already in /etc/hosts"
    fi
    
    if ! grep -q "apiserver.localhost" /etc/hosts; then
        echo "127.0.0.1 apiserver.localhost" | sudo tee -a /etc/hosts
        print_success "Added apiserver.localhost to /etc/hosts"
    else
        print_status "apiserver.localhost already in /etc/hosts"
    fi
    
    # Verify DNS resolution
    if ping -c 1 rekor.localhost > /dev/null 2>&1; then
        print_success "DNS resolution working for rekor.localhost"
    else
        print_warning "DNS resolution test failed for rekor.localhost"
    fi
}

# Set up environment variables
setup_environment() {
    print_status "Setting up environment variables..."
    
    # Create environment setup script
    cat > setup-test-env.sh << 'EOF'
#!/bin/bash
# Environment variables for running acceptance tests

export KIND_EXPERIMENTAL_PROVIDER=podman
export TESTCONTAINERS_RYUK_DISABLED=true
export TESTCONTAINERS_HOST_OVERRIDE=localhost
export DOCKER_HOST=unix:///var/run/docker.sock

echo "Environment variables set for acceptance tests"
echo "KIND_EXPERIMENTAL_PROVIDER=$KIND_EXPERIMENTAL_PROVIDER"
echo "TESTCONTAINERS_RYUK_DISABLED=$TESTCONTAINERS_RYUK_DISABLED"
echo "TESTCONTAINERS_HOST_OVERRIDE=$TESTCONTAINERS_HOST_OVERRIDE"
echo "DOCKER_HOST=$DOCKER_HOST"
EOF
    
    chmod +x setup-test-env.sh
    
    print_success "Environment setup script created: setup-test-env.sh"
}

# Test the setup
test_setup() {
    print_status "Testing the setup..."
    
    # Source the environment
    source setup-test-env.sh
    
    # Test podman connectivity
    if podman version > /dev/null 2>&1; then
        print_success "Podman is accessible"
    else
        print_error "Podman is not accessible"
        exit 1
    fi
    
    # Test network connectivity
    if podman network ls | grep -q "testcontainers"; then
        print_success "Testcontainers network is available"
    else
        print_error "Testcontainers network not found"
        exit 1
    fi
    
    print_success "Setup test completed successfully"
}

# Main execution
main() {
    echo "=========================================="
    echo "  Podman Machine Setup for Acceptance Tests"
    echo "=========================================="
    echo
    
    check_prerequisites
    cleanup_existing_machine
    create_podman_machine
    start_podman_machine
    fix_keyring_quota
    create_networks
    configure_dns
    setup_environment
    test_setup
    
    echo
    echo "=========================================="
    print_success "Setup completed successfully!"
    echo "=========================================="
    echo
    echo "To run acceptance tests:"
    echo "  1. Source the environment: source setup-test-env.sh"
    echo "  2. Run tests: make acceptance"
    echo "     or: cd acceptance && go test -v ./..."
    echo
    echo "Environment variables are saved in: setup-test-env.sh"
    echo "You can source this file before running tests."
    echo
}

# Run main function
main "$@"
