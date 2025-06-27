#!/bin/bash

# This script sets up Rust and its components for prebuilds.
# msrustup is not available for github actions, so we're using the public repository here.
# see https://eng.ms/docs/more/languages-at-microsoft/rust/articles/gettingstarted/install/installcicd

set -e

# Define default paths and Rust version
CARGO_HOME="${HOME}/.cargo"
RUST_VERSION="1.79"

echo "CARGO_HOME: $CARGO_HOME"

# Function to print status messages
function print_status() {
  echo -e "\033[1;93m[+] $1\033[0m"
}

# Check if Rust is already installed
if ! command -v rustup &> /dev/null; then
  print_status "Rust is not installed. Installing Rust and Rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
else
  print_status "Rust is already installed. Skipping installation."
fi

# Ensure the Cargo binary path is in the PATH
export PATH="${CARGO_HOME}/bin:$PATH"

# Set the required Rust version
print_status "Setting Rust version to ${RUST_VERSION}..."
rustup override set "${RUST_VERSION}"

# Install Clippy
print_status "Installing Clippy..."
rustup component add clippy
cargo clippy --version

# Install Rustfmt
print_status "Installing Rustfmt..."
rustup component add rustfmt
cargo fmt --version

print_status "Rust setup complete!"