#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# GN-Shield: Local Build & Verification Script
# ==============================================================================

echo "==> [1/6] Checking code formatting (cargo fmt)..."
cargo fmt --all -- --check

echo "==> [2/6] Running linter (cargo clippy)..."
cargo clippy --workspace --all-targets -- -D warnings

echo "==> [3/6] Running test suite (cargo test)..."
cargo test --workspace

echo "==> [4/6] Building workspace binaries in debug mode..."
cargo build --workspace

echo "==> [5/6] Checking dependency licenses & bans (cargo deny)..."
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
else
    echo "⚠️  cargo-deny not found in PATH. Install with: cargo install cargo-deny --locked"
fi

echo "==> [6/6] Checking security vulnerabilities (cargo audit)..."
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit
else
    echo "⚠️  cargo-audit not found in PATH. Install with: cargo install cargo-audit --locked"
fi

echo ""
echo "✅ All GN-Shield build, test, and security checks passed successfully!"
