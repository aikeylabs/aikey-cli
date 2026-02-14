#!/bin/bash

echo "=== AiKeyLabs AK Diagnostic Script ==="
echo ""

echo "1. Checking Rust installation..."
which rustc && rustc --version || echo "❌ rustc not found"
which cargo && cargo --version || echo "❌ cargo not found"
echo ""

echo "2. Checking current directory..."
pwd
echo ""

echo "3. Checking Cargo.toml..."
if [ -f "Cargo.toml" ]; then
    echo "✓ Cargo.toml exists"
else
    echo "❌ Cargo.toml not found"
fi
echo ""

echo "4. Attempting cargo check..."
cargo check 2>&1 | head -50
echo ""

echo "5. Checking for lock file..."
if [ -f "Cargo.lock" ]; then
    echo "✓ Cargo.lock exists"
else
    echo "⚠️  Cargo.lock not found"
fi
echo ""

echo "6. Listing source files..."
find src -name "*.rs" -type f 2>/dev/null || echo "❌ Cannot list source files"
echo ""

echo "=== End of Diagnostic ==="
