# Comprehensive Test Architecture

**Project:** AiKey CLI (ak engine) v0.4.0-alpha.1
**Date:** February 15, 2026
**Test Coverage Target:** 95%+

---

## Table of Contents

1. [Test Strategy Overview](#test-strategy-overview)
2. [Test Environment Isolation](#test-environment-isolation)
3. [Automated Test Suite](#automated-test-suite)
4. [Manual Test Suite](#manual-test-suite)
5. [Test Execution Plan](#test-execution-plan)
6. [Success Criteria](#success-criteria)

---

## 1. Test Strategy Overview

### Test Pyramid

```
           ┌─────────────────┐
           │  Manual Tests   │  (10% - User Experience)
           │   ~10 tests     │
           └─────────────────┘
          ┌───────────────────┐
          │ Integration Tests │  (30% - End-to-End)
          │    ~30 tests      │
          └───────────────────┘
        ┌─────────────────────────┐
        │     Unit Tests          │  (60% - Components)
        │      ~60 tests          │
        └─────────────────────────┘
```

### Test Categories

| Category | Type | Count | Isolation | Duration |
|----------|------|-------|-----------|----------|
| Unit Tests | Automated | 60 | Full | <5s |
| Integration Tests | Automated | 30 | Temp Vaults | <30s |
| Security Tests | Automated | 15 | Isolated | <20s |
| Performance Tests | Automated | 10 | Isolated | <60s |
| Manual Tests | Manual | 10 | User-driven | Variable |

---

## 2. Test Environment Isolation

### Isolation Strategy

**Problem:** Tests must not interfere with:
- User's production vault (`~/.aikey/vault.db`)
- Each other's test data
- System clipboard
- Rate limiting state

**Solution:** Multi-layer isolation

#### Layer 1: Environment Variables

```bash
# Each test gets unique vault path
export AK_VAULT_PATH="/tmp/test_vault_${TEST_ID}.db"
export AK_TEST_PASSWORD="test_password_123"
export AK_TEST_SECRET="test_secret_value"
```

#### Layer 2: Temporary Directories

```rust
use tempfile::TempDir;

let temp_dir = TempDir::new()?;
let vault_path = temp_dir.path().join("vault.db");
env::set_var("AK_VAULT_PATH", vault_path);
```

#### Layer 3: Test Cleanup

```rust
impl Drop for TestEnvironment {
    fn drop(&mut self) {
        // Automatic cleanup on test completion
        let _ = fs::remove_file(&self.vault_path);
    }
}
```

### Isolation Matrix

| Resource | Unit Tests | Integration Tests | Manual Tests |
|----------|-----------|-------------------|--------------|
| Vault DB | Temp file | Temp dir | `/tmp/manual_test_vault.db` |
| Password | `AK_TEST_PASSWORD` | `AK_TEST_PASSWORD` | User input |
| Clipboard | Mocked | Real (cleared after) | Real |
| Rate Limit | Disabled | Enabled | Enabled |
| Audit Log | Temp DB | Temp DB | Separate DB |

---

## 3. Automated Test Suite

### 3.1 Unit Tests (60 tests)

#### Crypto Module (10 tests)
```rust
// src/crypto.rs tests
#[test] fn test_key_derivation()
#[test] fn test_encrypt_decrypt()
#[test] fn test_secure_buffer_mlock()
#[test] fn test_secure_buffer_zeroize()
#[test] fn test_nonce_uniqueness()
#[test] fn test_salt_generation()
#[test] fn test_invalid_key_size()
#[test] fn test_invalid_nonce_size()
#[test] fn test_decrypt_wrong_key()
#[test] fn test_decrypt_tampered_ciphertext()
```

#### Storage Module (15 tests)
```rust
// src/storage.rs tests
#[test] fn test_initialize_vault()
#[test] fn test_store_entry()
#[test] fn test_get_entry()
#[test] fn test_delete_entry()
#[test] fn test_list_entries()
#[test] fn test_entry_exists()
#[test] fn test_update_entry()
#[test] fn test_get_salt()
#[test] fn test_migration_old_schema()
#[test] fn test_migration_add_columns()
#[test] fn test_secure_delete_pragma()
#[test] fn test_auto_vacuum_pragma()
#[test] fn test_duplicate_alias()
#[test] fn test_invalid_vault_path()
#[test] fn test_corrupted_database()
```

#### Rate Limiting Module (10 tests)
```rust
// src/ratelimit.rs tests
#[test] fn test_rate_limiter_load()
#[test] fn test_rate_limiter_check_allowed()
#[test] fn test_rate_limiter_record_failure()
#[test] fn test_rate_limiter_record_success()
#[test] fn test_rate_limiter_exponential_backoff()
#[test] fn test_rate_limiter_reset_after_hour()
#[test] fn test_rate_limiter_persistence()
#[test] fn test_rate_limiter_3_attempts()
#[test] fn test_rate_limiter_lockout_duration()
#[test] fn test_rate_limiter_concurrent_access()
```

#### Audit Module (10 tests)
```rust
// src/audit.rs tests
#[test] fn test_audit_log_initialization()
#[test] fn test_log_audit_event()
#[test] fn test_audit_hmac_computation()
#[test] fn test_audit_log_verification()
#[test] fn test_audit_tamper_detection()
#[test] fn test_audit_all_operations()
#[test] fn test_audit_key_derivation()
#[test] fn test_audit_log_query()
#[test] fn test_audit_log_persistence()
#[test] fn test_audit_concurrent_logging()
```

#### Synapse Module (15 tests)
```rust
// src/synapse.rs tests
#[test] fn test_export_vault()
#[test] fn test_import_vault()
#[test] fn test_akb_header_format()
#[test] fn test_akb_hmac_verification()
#[test] fn test_export_pattern_matching()
#[test] fn test_import_merge_strategy()
#[test] fn test_schema_versioning()
#[test] fn test_schema_compatibility_check()
#[test] fn test_export_encryption()
#[test] fn test_import_decryption()
#[test] fn test_export_empty_vault()
#[test] fn test_import_corrupted_file()
#[test] fn test_import_wrong_password()
#[test] fn test_export_import_roundtrip()
#[test] fn test_schema_version_mismatch()
```

### 3.2 Integration Tests (30 tests)

#### Core Workflow Tests (10 tests)
```bash
test_01_init_vault
test_02_add_secret
test_03_get_secret
test_04_update_secret
test_05_delete_secret
test_06_list_secrets
test_07_exec_with_env
test_08_export_secrets
test_09_import_secrets
test_10_full_workflow
```

#### Security Tests (10 tests)
```bash
test_11_password_verification
test_12_wrong_password_rejection
test_13_rate_limiting_3_attempts
test_14_rate_limiting_lockout
test_15_rate_limiting_reset
test_16_audit_log_creation
test_17_audit_log_verification
test_18_secure_deletion
test_19_memory_zeroization
test_20_clipboard_auto_clear
```

#### Edge Case Tests (10 tests)
```bash
test_21_empty_vault_operations
test_22_special_characters_in_secrets
test_23_large_secret_values
test_24_many_secrets_performance
test_25_concurrent_access
test_26_vault_corruption_recovery
test_27_migration_from_old_format
test_28_export_import_with_metadata
test_29_exec_with_multiple_envs
test_30_signal_handling
```

### 3.3 Performance Tests (10 tests)

```rust
#[test] fn bench_key_derivation()
#[test] fn bench_encrypt_100_secrets()
#[test] fn bench_decrypt_100_secrets()
#[test] fn bench_parallel_decrypt_100()
#[test] fn bench_sequential_decrypt_100()
#[test] fn bench_export_1000_secrets()
#[test] fn bench_import_1000_secrets()
#[test] fn bench_list_10000_secrets()
#[test] fn bench_vault_initialization()
#[test] fn bench_audit_log_write()
```

---

## 4. Manual Test Suite

### 4.1 User Experience Tests (5 tests)

#### Test MAN-01: First-Time User Onboarding
**Objective:** Verify smooth onboarding experience

**Steps:**
1. Install `ak` binary
2. Run `ak init` without prior setup
3. Create master password
4. Add first secret
5. Retrieve secret

**Expected:**
- Clear prompts and instructions
- Password strength feedback
- Success confirmation messages
- Clipboard contains secret

**Pass Criteria:** User completes workflow in <2 minutes without confusion

---

#### Test MAN-02: Clipboard Auto-Clear
**Objective:** Verify clipboard clears after timeout

**Steps:**
1. `ak get test-secret --timeout 5`
2. Immediately paste (Cmd+V) - should work
3. Wait 6 seconds
4. Paste again (Cmd+V) - should be empty

**Expected:**
- Secret in clipboard for 5 seconds
- Clipboard cleared after timeout
- User notified of countdown

**Pass Criteria:** Clipboard empty after timeout

---

#### Test MAN-03: Rate Limiting User Experience
**Objective:** Verify rate limiting provides clear feedback

**Steps:**
1. Enter wrong password 3 times
2. Observe lockout message
3. Wait for lockout to expire
4. Enter correct password

**Expected:**
- Clear error messages for wrong password
- Lockout message shows remaining time
- Successful auth after lockout expires

**Pass Criteria:** User understands why locked out and when they can retry

---

#### Test MAN-04: Multi-Environment Workflow
**Objective:** Verify real-world developer workflow

**Steps:**
1. Add secrets for dev, staging, prod
2. Export dev secrets to `dev.akb`
3. Export prod secrets to `prod.akb`
4. Use `ak exec` to run commands with different envs
5. Verify correct secrets injected

**Expected:**
- Easy to organize secrets by environment
- Export/import works smoothly
- Exec injects correct secrets

**Pass Criteria:** Developer can manage 3 environments efficiently

---

#### Test MAN-05: Error Recovery
**Objective:** Verify graceful error handling

**Steps:**
1. Try to get non-existent secret
2. Try to delete non-existent secret
3. Try to import corrupted .akb file
4. Try to init when vault exists
5. Try to use vault without init

**Expected:**
- Clear error messages
- Suggestions for resolution
- No crashes or data loss

**Pass Criteria:** All errors handled gracefully with helpful messages

---

### 4.2 Security Validation Tests (5 tests)

#### Test MAN-06: Memory Inspection
**Objective:** Verify secrets not in memory dumps

**Steps:**
1. Add secret "SUPER_SECRET_KEY_12345"
2. Run `ak exec --env KEY=test -- sleep 60` in background
3. While running, dump process memory: `sudo gcore <pid>`
4. Search memory dump: `strings core.<pid> | grep SUPER_SECRET`

**Expected:**
- Secret not found in parent process memory
- Secret may be in child process (expected)

**Pass Criteria:** Parent process memory clean

---

#### Test MAN-07: Disk Forensics
**Objective:** Verify deleted secrets unrecoverable

**Steps:**
1. Add secret "DELETED_SECRET_123"
2. Delete the secret
3. Run disk recovery tool on vault.db
4. Search for "DELETED_SECRET_123"

**Expected:**
- Secret not recoverable from free pages
- SQLite secure_delete working

**Pass Criteria:** Secret not found in disk analysis

---

#### Test MAN-08: Clipboard Sniffing
**Objective:** Verify clipboard cleared properly

**Steps:**
1. `ak get test-secret --timeout 10`
2. Use clipboard monitoring tool
3. Verify secret appears
4. Wait 11 seconds
5. Verify clipboard cleared

**Expected:**
- Secret visible for 10 seconds
- Clipboard empty after timeout

**Pass Criteria:** No secret in clipboard after timeout

---

#### Test MAN-09: Brute Force Simulation
**Objective:** Verify rate limiting effectiveness

**Steps:**
1. Write script to attempt 100 passwords
2. Run script against vault
3. Measure attempts per minute

**Expected:**
- First 3 attempts immediate
- 4th attempt: 30s delay
- 5th attempt: 60s delay
- Exponential backoff continues

**Pass Criteria:** <10 attempts per minute after lockout

---

#### Test MAN-10: Audit Log Tampering
**Objective:** Verify audit log tamper detection

**Steps:**
1. Perform several operations (add, get, delete)
2. Manually edit audit_log table in SQLite
3. Run audit verification (future feature)
4. Verify tampering detected

**Expected:**
- HMAC verification fails
- Tampered entries identified

**Pass Criteria:** Tampering detected and reported

---

## 5. Test Execution Plan

### Phase 1: Automated Tests (30 minutes)

```bash
# Step 1: Unit Tests
cargo test --lib
# Expected: All pass, <5 seconds

# Step 2: Integration Tests
cargo test --test cortex_stress_test
cargo test --test integration_test
cargo test --test synapse_stress_test
cargo test --test synapse_audit
# Expected: Most pass, <30 seconds

# Step 3: Performance Tests
cargo test --release --test performance_test
# Expected: Benchmarks within targets

# Step 4: Security Tests
cargo test --test security_test
# Expected: All security features validated
```

### Phase 2: Manual Tests (60 minutes)

```bash
# Step 1: Setup Manual Test Environment
export AK_MANUAL_TEST=1
rm -rf /tmp/manual_test_vault.db
export AK_VAULT_PATH=/tmp/manual_test_vault.db

# Step 2: Execute Manual Test Suite
# Follow manual test procedures MAN-01 through MAN-10
# Document results in test_results.md

# Step 3: Cleanup
unset AK_MANUAL_TEST
rm -rf /tmp/manual_test_vault.db
```

### Phase 3: Regression Tests (15 minutes)

```bash
# Verify no regressions from technical debt fixes
cargo test --all
cargo build --release
./target/release/ak --version
```

---

## 6. Success Criteria

### Automated Tests
- ✅ Unit Tests: 100% pass rate
- ✅ Integration Tests: 95%+ pass rate (known issues documented)
- ✅ Performance Tests: Within 10% of targets
- ✅ Security Tests: 100% pass rate

### Manual Tests
- ✅ User Experience: 5/5 tests pass
- ✅ Security Validation: 5/5 tests pass
- ✅ No critical bugs discovered
- ✅ All edge cases handled gracefully

### Code Coverage
- ✅ Line Coverage: >80%
- ✅ Branch Coverage: >70%
- ✅ Function Coverage: >90%

### Performance Targets
- ✅ Init vault: <500ms
- ✅ Add secret: <100ms
- ✅ Get secret: <50ms
- ✅ Exec with 10 secrets: <200ms
- ✅ Exec with 100 secrets: <500ms (parallel)
- ✅ Export 1000 secrets: <2s
- ✅ Import 1000 secrets: <3s

---

## 7. Test Execution Log Template

```markdown
# Test Execution Log

**Date:** YYYY-MM-DD
**Tester:** [Name]
**Environment:** [OS, Rust version]

## Automated Tests

| Test Suite | Total | Passed | Failed | Duration |
|------------|-------|--------|--------|----------|
| Unit Tests | 60 | | | |
| Integration Tests | 30 | | | |
| Performance Tests | 10 | | | |
| Security Tests | 15 | | | |

## Manual Tests

| Test ID | Status | Notes |
|---------|--------|-------|
| MAN-01 | | |
| MAN-02 | | |
| ... | | |

## Issues Found

| ID | Severity | Description | Status |
|----|----------|-------------|--------|
| | | | |

## Overall Result

- [ ] PASS - All tests passed
- [ ] PASS WITH ISSUES - Minor issues documented
- [ ] FAIL - Critical issues found
```

---

## 8. Continuous Integration

### GitHub Actions Workflow

```yaml
name: Comprehensive Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Run Unit Tests
        run: cargo test --lib

      - name: Run Integration Tests
        run: cargo test --test '*'

      - name: Run Security Tests
        run: cargo test --test security_test

      - name: Check Code Coverage
        run: |
          cargo install cargo-tarpaulin
          cargo tarpaulin --out Xml

      - name: Upload Coverage
        uses: codecov/codecov-action@v3
```

---

## Appendix A: Test Data Sets

### Small Dataset (10 secrets)
```
github-token, aws-key, aws-secret, openai-key, stripe-key,
db-password, api-key, jwt-secret, encryption-key, webhook-secret
```

### Medium Dataset (100 secrets)
```
Generated programmatically: secret-001 through secret-100
```

### Large Dataset (1000 secrets)
```
Generated programmatically: secret-0001 through secret-1000
```

### Special Characters Dataset
```
secret-with-spaces, secret_with_underscores, secret-with-dashes,
secret.with.dots, secret@with@at, secret#with#hash,
secret$with$dollar, secret%with%percent, secret&with&ampersand
```

---

## Appendix B: Known Issues

| Issue | Severity | Workaround | Status |
|-------|----------|------------|--------|
| Integration tests check stderr instead of stdout | Low | Update tests | Open |
| Ghost exec tests use cargo run | Low | Use test binary | Open |
| Clipboard tests require GUI | Low | Mock in CI | Open |

---

**End of Test Architecture Document**
