#!/usr/bin/env bash
# Build standalone executable using PyApp
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
export PYAPP_PROJECT_NAME="stack-bootstrapper"
export PYAPP_PROJECT_VERSION="2.0.0"
export PYAPP_PROJECT_PATH="$PROJECT_ROOT"
export PYAPP_PYTHON_VERSION="3.11"
export PYAPP_EXEC_SCRIPT="stack_bootstrapper.py"
export PYAPP_DISTRIBUTION_EMBED="true"
export PYAPP_FULL_ISOLATION="true"

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo is required. Install from https://rustup.rs/"
    exit 1
fi

# Clone or update PyApp
PYAPP_DIR="$SCRIPT_DIR/.pyapp-src"
if [[ -d "$PYAPP_DIR" ]]; then
    echo "Updating PyApp source..."
    git -C "$PYAPP_DIR" pull --quiet
else
    echo "Cloning PyApp source..."
    git clone --depth 1 https://github.com/ofek/pyapp.git "$PYAPP_DIR"
fi

# Build
echo "Building standalone executable..."
cd "$PYAPP_DIR"
cargo build --release

# Copy output
mkdir -p "$SCRIPT_DIR/dist"
cp "$PYAPP_DIR/target/release/pyapp" "$SCRIPT_DIR/dist/stack-bootstrapper"
chmod +x "$SCRIPT_DIR/dist/stack-bootstrapper"

echo ""
echo "Build complete! Executable: $SCRIPT_DIR/dist/stack-bootstrapper"
echo ""
echo "Usage:"
echo "  ./dist/stack-bootstrapper --help"
echo "  ./dist/stack-bootstrapper --dry-run"
