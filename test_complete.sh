#!/bin/bash
set -e

echo "=== AK Complete Workflow Test ==="
echo

# Clean up any existing vault
rm -rf ~/.ak 2>/dev/null || true

# Test 1: Initialize vault
echo "Test 1: Initialize vault"
echo "test123" | cargo run -q -- --password-stdin init
echo "✓ Vault initialized"
echo

# Test 2: Add secrets
echo "Test 2: Add secrets"
AK_TEST_SECRET="github_token_value" bash -c 'echo "test123" | cargo run -q -- --password-stdin add github_token'
AK_TEST_SECRET="api_key_value" bash -c 'echo "test123" | cargo run -q -- --password-stdin add api_key'
AK_TEST_SECRET="db_password_value" bash -c 'echo "test123" | cargo run -q -- --password-stdin add db_password'
echo "✓ Added 3 secrets"
echo

# Test 3: List secrets
echo "Test 3: List secrets"
echo "test123" | cargo run -q -- --password-stdin list
echo

# Test 4: Get secret
echo "Test 4: Get secret"
SECRET=$(echo "test123" | cargo run -q -- --password-stdin get github_token 2>/dev/null | grep "Secret:" | cut -d' ' -f2)
if [ "$SECRET" = "github_token_value" ]; then
    echo "✓ Retrieved secret correctly: $SECRET"
else
    echo "✗ Failed to retrieve secret. Got: $SECRET"
    exit 1
fi
echo

# Test 5: Update secret
echo "Test 5: Update secret"
AK_TEST_SECRET="github_token_updated" bash -c 'echo "test123" | cargo run -q -- --password-stdin update github_token'
SECRET=$(echo "test123" | cargo run -q -- --password-stdin get github_token 2>/dev/null | grep "Secret:" | cut -d' ' -f2)
if [ "$SECRET" = "github_token_updated" ]; then
    echo "✓ Updated secret correctly: $SECRET"
else
    echo "✗ Failed to update secret. Got: $SECRET"
    exit 1
fi
echo

# Test 6: Execute command with secrets
echo "Test 6: Execute command with secrets"
RESULT=$(echo "test123" | cargo run -q -- --password-stdin exec -e GITHUB_TOKEN=github_token -e API_KEY=api_key -- printenv GITHUB_TOKEN 2>/dev/null)
if [ "$RESULT" = "github_token_updated" ]; then
    echo "✓ Exec injected secret correctly: $RESULT"
else
    echo "✗ Failed to inject secret. Got: $RESULT"
    exit 1
fi
echo

# Test 7: Export secrets
echo "Test 7: Export secrets"
echo "test123" | cargo run -q -- --password-stdin export "*" /tmp/test_export.akb
if [ -f /tmp/test_export.akb ]; then
    echo "✓ Exported secrets to /tmp/test_export.akb"
    ls -lh /tmp/test_export.akb
else
    echo "✗ Failed to export secrets"
    exit 1
fi
echo

# Test 8: Delete a secret
echo "Test 8: Delete secret"
echo "test123" | cargo run -q -- --password-stdin delete api_key
echo "✓ Deleted api_key"
echo

# Test 9: Import secrets
echo "Test 9: Import secrets"
echo "test123" | cargo run -q -- --password-stdin import /tmp/test_export.akb
SECRET=$(echo "test123" | cargo run -q -- --password-stdin get api_key 2>/dev/null | grep "Secret:" | cut -d' ' -f2)
if [ "$SECRET" = "api_key_value" ]; then
    echo "✓ Imported secret correctly: $SECRET"
else
    echo "✗ Failed to import secret. Got: $SECRET"
    exit 1
fi
echo

# Test 10: Wrong password
echo "Test 10: Wrong password (should fail)"
if echo "wrong_password" | cargo run -q -- --password-stdin get github_token 2>&1 | grep -q "Invalid master password"; then
    echo "✓ Correctly rejected wrong password"
else
    echo "✗ Should have rejected wrong password"
    exit 1
fi
echo

echo "=== All tests passed! ==="
