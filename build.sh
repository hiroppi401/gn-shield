#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# GN-Shield: Local Build & Verification Script
# ==============================================================================

echo "==> [1/4] Checking code formatting (cargo fmt)..."
cargo fmt --all -- --check

echo "==> [2/4] Running linter (cargo clippy)..."
cargo clippy --workspace --all-targets -- -D warnings

echo "==> [3/4] Running test suite (cargo test)..."
cargo test --workspace

echo "==> [4/4] Building workspace binaries in debug mode..."
cargo build --workspace

echo ""
echo "✅ All build checks passed successfully!"
