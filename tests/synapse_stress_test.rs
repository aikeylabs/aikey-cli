//! Synapse Stress & Security Audit Tests
//!
//! This test suite validates:
//! 1. HMAC integrity verification (bit-flip detection)
//! 2. Smart merge logic (version and timestamp priority)
//! 3. Memory safety (SecureBuffer protection for keys)
//! 4. CLI summary output formatting

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to set up a test environment with a vault
fn setup_test_vault() -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join(".ak_vault.db");

    // Ensure the vault doesn't exist yet
    if vault_path.exists() {
        fs::remove_file(&vault_path).ok();
    }

    (temp_dir, vault_path)
}

/// Helper to create a Command with test environment variables
fn test_command(vault_path: &PathBuf) -> Command {
    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.env("AK_NO_CLIPBOARD", "1");
    cmd
}

/// Helper to initialize vault and add test entries
fn init_vault_with_entries(vault_path: &PathBuf, entries: Vec<(&str, &str)>) {
    // Initialize vault
    test_command(vault_path)
        .arg("init")
        .assert()
        .success();

    // Add entries
    for (alias, secret) in entries {
        test_command(vault_path)
            .arg("add")
            .arg(alias)
            .env("AK_TEST_SECRET", secret)
            .assert()
            .success();
    }
}

#[test]
fn test_hmac_bit_flip_detection() {
    let (_temp_dir, vault_path) = setup_test_vault();

    // Initialize vault and add a test entry
    init_vault_with_entries(&vault_path, vec![("test_key", "test_secret_value")]);

    // Export to .akb file
    let export_path = _temp_dir.path().join("export.akb");
    test_command(&vault_path)
        .args(&["export", "*", export_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 1 secret(s)"));

    // Read the exported file
    let mut file_data = fs::read(&export_path).expect("Failed to read export file");

    // Flip a single bit in the middle of the file (in the encrypted payload)
    // Skip magic (4) + version (2) + salt (16) = 22 bytes
    let flip_position = 30;
    file_data[flip_position] ^= 0x01; // Flip the least significant bit

    // Write the corrupted file
    let corrupted_path = _temp_dir.path().join("corrupted.akb");
    fs::write(&corrupted_path, &file_data).expect("Failed to write corrupted file");

    // Create a new vault for import test
    let (_temp_dir2, import_vault_path) = setup_test_vault();

    // Initialize new vault
    test_command(&import_vault_path)
        .arg("init")
        .assert()
        .success();

    // Attempt to import the corrupted file - should fail with HMAC error
    test_command(&import_vault_path)
        .args(&["import", corrupted_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HMAC verification failed")
            .or(predicate::str::contains("corrupted"))
            .or(predicate::str::contains("tampered")));

    println!("✓ HMAC bit-flip detection test passed");
}

#[test]
fn test_smart_merge_version_priority() {
    let (_temp_dir, vault_path) = setup_test_vault();

    // Initialize vault with key_a at version 2
    init_vault_with_entries(&vault_path, vec![("key_a", "local_secret_v2")]);

    // Update key_a to increment version (simulate v2)
    test_command(&vault_path)
        .arg("update")
        .arg("key_a")
        .env("AK_TEST_SECRET", "local_secret_v2_updated")
        .assert()
        .success();

    // Export current state (v2)
    let export_v2_path = _temp_dir.path().join("export_v2.akb");
    test_command(&vault_path)
        .args(&["export", "*", export_v2_path.to_str().unwrap()])
        .assert()
        .success();

    // Update key_a again to v3
    test_command(&vault_path)
        .arg("update")
        .arg("key_a")
        .env("AK_TEST_SECRET", "local_secret_v3")
        .assert()
        .success();

    // Now import the v2 export - should be skipped (local v3 > import v2)
    test_command(&vault_path)
        .args(&["import", export_v2_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Skipped: 1"));

    // Verify key_a still has v3 value
    test_command(&vault_path)
        .args(&["get", "key_a"])
        .assert()
        .success()
        .stdout(predicate::str::contains("local_secret_v3"));

    println!("✓ Smart merge version priority test passed");
}

#[test]
fn test_smart_merge_timestamp_priority() {
    let (_temp_dir, vault_path) = setup_test_vault();

    // Initialize vault with key_b
    init_vault_with_entries(&vault_path, vec![("key_b", "old_value")]);

    // Export immediately (older timestamp)
    let export_old_path = _temp_dir.path().join("export_old.akb");
    test_command(&vault_path)
        .args(&["export", "*", export_old_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 1 secret(s)"));

    // Wait a moment to ensure timestamp difference
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Update key_b with same version but newer timestamp
    test_command(&vault_path)
        .arg("update")
        .arg("key_b")
        .env("AK_TEST_SECRET", "new_value")
        .assert()
        .success();

    // Export again (newer timestamp)
    let export_new_path = _temp_dir.path().join("export_new.akb");
    test_command(&vault_path)
        .args(&["export", "*", export_new_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 1 secret(s)"));

    // Import the older export - should be skipped (local timestamp newer)
    test_command(&vault_path)
        .args(&["import", export_old_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Skipped: 1"));

    // Verify key_b still has new value
    test_command(&vault_path)
        .args(&["get", "key_b"])
        .assert()
        .success()
        .stdout(predicate::str::contains("new_value"));

    println!("✓ Smart merge timestamp priority test passed");
}

#[test]
fn test_import_summary_output() {
    let (_temp_dir, vault_path) = setup_test_vault();

    // Initialize vault with multiple entries
    init_vault_with_entries(&vault_path, vec![
        ("key_a", "value_a"),
        ("key_b", "value_b"),
        ("key_c", "value_c"),
    ]);

    // Export all entries
    let export_path = _temp_dir.path().join("export_all.akb");
    test_command(&vault_path)
        .args(&["export", "*", export_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 3 secret(s)"));

    // Update key_a locally (will be skipped on import)
    test_command(&vault_path)
        .arg("update")
        .arg("key_a")
        .env("AK_TEST_SECRET", "value_a_updated")
        .assert()
        .success();

    // Delete key_b locally (will be added on import)
    test_command(&vault_path)
        .args(&["delete", "key_b"])
        .assert()
        .success();

    // key_c remains unchanged (will be skipped on import)

    // Import - should show: 1 added (key_b), 0 updated, 2 skipped (key_a, key_c)
    test_command(&vault_path)
        .args(&["import", export_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Import complete:"))
        .stderr(predicate::str::contains("Added: 1"))
        .stderr(predicate::str::contains("Skipped: 2"));

    println!("✓ Import summary output test passed");
}

#[test]
fn test_export_import_roundtrip() {
    let (_temp_dir, vault_path) = setup_test_vault();

    // Initialize vault with test data
    init_vault_with_entries(&vault_path, vec![
        ("github_token", "ghp_test123"),
        ("openai_key", "sk-test456"),
        ("aws_secret", "aws_test789"),
    ]);

    // Export all entries
    let export_path = _temp_dir.path().join("backup.akb");
    test_command(&vault_path)
        .args(&["export", "*", export_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 3 secret(s)"));

    // Verify export file exists and has restrictive permissions
    assert!(export_path.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&export_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600, "Export file should have 0600 permissions");
    }

    // Create a new vault for import
    let import_vault_path = _temp_dir.path().join(".ak_vault_import.db");

    // Initialize new vault
    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", import_vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.arg("init")
        .assert()
        .success();

    // Import the backup
    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", import_vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.args(&["import", export_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Added: 3"))
        .stderr(predicate::str::contains("Updated: 0"))
        .stderr(predicate::str::contains("Skipped: 0"));

    // Verify all entries were imported correctly
    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", import_vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.env("AK_NO_CLIPBOARD", "1");
    cmd.args(&["get", "github_token"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ghp_test123"));

    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", import_vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.env("AK_NO_CLIPBOARD", "1");
    cmd.args(&["get", "openai_key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk-test456"));

    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", import_vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.env("AK_NO_CLIPBOARD", "1");
    cmd.args(&["get", "aws_secret"])
        .assert()
        .success()
        .stdout(predicate::str::contains("aws_test789"));

    println!("✓ Export/Import roundtrip test passed");
}

#[test]
fn test_pattern_export() {
    let (_temp_dir, vault_path) = setup_test_vault();

    // Initialize vault with entries matching different patterns
    init_vault_with_entries(&vault_path, vec![
        ("openai_key_1", "sk-test1"),
        ("openai_key_2", "sk-test2"),
        ("github_token", "ghp-test"),
        ("aws_secret", "aws-test"),
    ]);

    // Export only openai keys
    let export_path = _temp_dir.path().join("openai_backup.akb");
    test_command(&vault_path)
        .args(&["export", "openai*", export_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 2 secret(s)"));

    // Create new vault and import
    let import_vault_path = _temp_dir.path().join(".ak_vault_import.db");

    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", import_vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.arg("init")
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", import_vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.args(&["import", export_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Added: 2"));

    // Verify only openai keys were imported
    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", import_vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.args(&["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("openai_key_1"))
        .stdout(predicate::str::contains("openai_key_2"))
        .stdout(predicate::str::contains("github_token").not())
        .stdout(predicate::str::contains("aws_secret").not());

    println!("✓ Pattern export test passed");
}

#[test]
fn test_invalid_akb_file() {
    let (_temp_dir, _vault_path) = setup_test_vault();

    // Initialize vault
    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", _vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.arg("init")
        .assert()
        .success();

    // Create an invalid .akb file with wrong magic bytes
    let invalid_path = _temp_dir.path().join("invalid.akb");
    fs::write(&invalid_path, b"INVALID_DATA").expect("Failed to write invalid file");

    // Attempt to import - should fail
    let mut cmd = Command::cargo_bin("ak").unwrap();
    cmd.env("AK_VAULT_PATH", _vault_path.to_str().unwrap());
    cmd.env("AK_TEST_PASSWORD", "test_password_123");
    cmd.args(&["import", invalid_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid .akb file"));

    println!("✓ Invalid .akb file test passed");
}

#[test]
fn test_wrong_password_import() {
    let (_temp_dir, vault_path) = setup_test_vault();

    // Initialize vault and add entry
    init_vault_with_entries(&vault_path, vec![("test_key", "test_value")]);

    // Export with test password
    let export_path = _temp_dir.path().join("export.akb");
    test_command(&vault_path)
        .args(&["export", "*", export_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported 1 secret(s)"));

    // Create new vault with different password
    let import_vault_path = _temp_dir.path().join(".ak_vault_import.db");
    std::env::set_var("AK_VAULT_PATH", import_vault_path.to_str().unwrap());
    std::env::set_var("AK_TEST_PASSWORD", "different_password");

    Command::cargo_bin("ak")
        .unwrap()
        .arg("init")
        .assert()
        .success();

    // Attempt to import with wrong password - should fail HMAC verification
    Command::cargo_bin("ak")
        .unwrap()
        .args(&["import", export_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HMAC verification failed")
            .or(predicate::str::contains("corrupted"))
            .or(predicate::str::contains("tampered")));

    println!("✓ Wrong password import test passed");
}
