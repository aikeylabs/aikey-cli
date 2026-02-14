#!/bin/bash
# Test script to reproduce the fresh database initialization bug

set -e

echo "=== Testing Fresh Database Initialization ==="
echo ""

# Clean up any existing test database
rm -f ./test_fresh.db

# Set environment variables for testing (using AK_STORAGE_PATH as mentioned in the bug report)
export AK_STORAGE_PATH="./test_fresh.db"
export AK_TEST_PASSWORD="testpass123"
export AK_TEST_SECRET="my-secret-value"

echo "Step 1: Initialize vault with fresh database"
cargo run --quiet -- init

echo ""
echo "Step 2: Add first secret to empty vault"
cargo run --quiet -- add test-key

echo ""
echo "Step 3: List secrets"
cargo run --quiet -- list

echo ""
echo "Step 4: Get secret"
cargo run --quiet -- get test-key --print

echo ""
echo "✓ All tests passed!"

# Clean up
rm -f ./test_fresh.db
