#!/usr/bin/env bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "AikeyLabs-AK Day 3 Audit Suite"
echo "=========================================="

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up temporary files..."
    rm -f audit.akb old.akb audit_test.db
}
trap cleanup EXIT

# Test counter
PASSED=0
FAILED=0

test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASSED++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAILED++))
}

echo "━━━━━━━━"
echo "TEST 1: Environment Check - Cargo Tests"
echo "━━━━━━━━"
if cargo test -- --nocapture 2>&1 | tee /tmp/cargo_test.log | grep -q "test result: ok"; then
    test_pass "All cargo tests passed"
else
    test_fail "Cargo tests failed or did not complete successfully"
fi

echo ""
echo "━━━━━━━━"
echo "TEST 2: Schema Audit - Database Structure"
echo "━━━━━━━━"
cargo build --release 2>&1 | grep -E "(Finished|Compiling)" || true
TEST_DB="audit_test.db"
export AK_VAULT_PATH="$TEST_DB"
echo "test_password" | ./target/release/ak init 2>/dev/null || true
echo -e "test_password\ntest_secret_value" | ./target/release/ak set audit_dummy 2>/dev/null || true
SCHEMA=$(sqlite3 "$TEST_DB" "PRAGMA table_info(secrets);" 2>/dev/null)

if echo "$SCHEMA" | grep -q "version_tag"; then
    test_pass "version_tag column exists"
else
    test_fail "version_tag column missing"
fi

if echo "$SCHEMA" | grep -q "updated_at"; then
    test_pass "updated_at column exists"
else
    test_fail "updated_at column missing"
fi

echo ""
echo "━━━━━━━━"
echo "TEST 3: Protocol Hex-Dump - Magic Bytes"
echo "━━━━━━━━"
echo "test_password" | ./target/release/ak export audit.akb 2>/dev/null || true
if [ -f "audit.akb" ]; then
    MAGIC_BYTES=$(xxd -p -l 4 audit.akb)
    echo "Magic bytes (hex): $MAGIC_BYTES"
    if [ "$MAGIC_BYTES" = "414b4201" ]; then
        test_pass "Magic bytes are correct: 41 4B 42 01 (AKB\x01)"
    else
        test_fail "Magic bytes incorrect"
    fi
else
    test_fail "Failed to create audit.akb"
fi

echo ""
echo "━━━━━━━━"
echo "TEST 4: Memory Logic - Zeroizing Deref"
echo "━━━━━━━━"
GET_OUTPUT=$(echo "test_password" | ./target/release/ak get audit_dummy 2>&1)
if [ $? -eq 0 ] && echo "$GET_OUTPUT" | grep -q "test_secret_value"; then
    test_pass "ak get executed and dereferenced correctly"
else
    test_fail "ak get failed or secret leaked/missing"
fi

echo ""
echo "━━━━━━━━"
echo "TEST 5: Conflict Resolution - Version Integrity"
echo "━━━━━━━━"
echo "test_password" | ./target/release/ak export old.akb 2>/dev/null || true
OLD_VERSION=$(sqlite3 "$TEST_DB" "SELECT version_tag FROM secrets WHERE alias='audit_dummy';")
echo -e "test_password\nnew_secret_value" | ./target/release/ak set audit_dummy 2>/dev/null || true
NEW_VERSION=$(sqlite3 "$TEST_DB" "SELECT version_tag FROM secrets WHERE alias='audit_dummy';")
echo "test_password" | ./target/release/ak import old.akb 2>/dev/null || true
FINAL_VERSION=$(sqlite3 "$TEST_DB" "SELECT version_tag FROM secrets WHERE alias='audit_dummy';")

if [ "$FINAL_VERSION" = "$NEW_VERSION" ] && [ "$NEW_VERSION" != "$OLD_VERSION" ]; then
    test_pass "Version integrity maintained (Newer version kept)"
else
    test_fail "Conflict resolution logic failed"
fi

echo ""
echo "=========================================="
echo "AUDIT SUMMARY"
echo "=========================================="
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED - Day 3 Complete!${NC}"
else
    echo -e "${RED}✗ SOME TESTS FAILED - Review required${NC}"
    exit 1
fi
