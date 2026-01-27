#!/bin/bash

# Docker Scout Installation Script
# Checks if Docker Scout is installed and installs it if not

set -e

echo "======================================"
echo "Docker Scout Installation Check"
echo "======================================"

check_docker_scout() {
    if docker scout version &>/dev/null; then
        echo "✓ Docker Scout is already installed"
        docker scout version
        return 0
    else
        return 1
    fi
}

install_docker_scout() {
    echo "Docker Scout is not installed. Installing..."
    
    # Install Docker Scout CLI plugin
    curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --
    
    # Verify installation
    if docker scout version &>/dev/null; then
        echo ""
        echo "✓ Docker Scout installed successfully"
        docker scout version
        return 0
    else
        echo "✗ Failed to install Docker Scout"
        return 1
    fi
}

main() {
    # Check if Docker is available
    if ! command -v docker &>/dev/null; then
        echo "✗ Error: Docker is not installed or not in PATH"
        exit 1
    fi
    
    echo "Checking for Docker Scout..."
    echo ""
    
    if ! check_docker_scout; then
        install_docker_scout
    fi
    
    echo ""
    echo "======================================"
    echo "Docker Scout is ready to use"
    echo "======================================"
}

main "$@"
