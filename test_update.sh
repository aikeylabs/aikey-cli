#!/bin/bash
# Simple test script for the update command

set -e

echo "Building the project..."
cd /Users/lautom/aikeylabs-ak
cargo build --release

echo ""
echo "Running integration tests..."
cargo test test_09_update_secret -- --nocapture

echo ""
echo "✓ Update command tests passed!"
