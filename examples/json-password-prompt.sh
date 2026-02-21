#!/bin/bash
# Example: Using JSON mode with password prompts
# This demonstrates how the CLI prompts for passwords in JSON mode

set -e

# Create a temporary test vault
export AIKEY_VAULT_PATH="/tmp/test-json-vault-$$"
rm -rf "$AIKEY_VAULT_PATH"

echo "=== Initializing vault in JSON mode ==="
echo "mypassword123" | cargo run --bin ak -- init --json

echo ""
echo "=== Adding a secret in JSON mode ==="
echo "mypassword123" | cargo run --bin ak -- add test-secret "secret-value" --json

echo ""
echo "=== Changing password in JSON mode ==="
# The CLI will prompt for old and new passwords
# In JSON mode, it outputs a prompt object before reading input
printf "mypassword123\nnewpassword456\nnewpassword456\n" | cargo run --bin ak -- change-password --json

echo ""
echo "=== Verifying with new password ==="
echo "newpassword456" | cargo run --bin ak -- list --json

echo ""
echo "=== Cleanup ==="
rm -rf "$AIKEY_VAULT_PATH"
echo "Done!"
