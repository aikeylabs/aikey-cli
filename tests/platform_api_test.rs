/// Platform API v0.2 Integration Tests
/// Tests for the new secret set, profile current, and error code features

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

/// Helper to create a test vault
fn setup_test_vault(temp_dir: &TempDir) -> String {
    let vault_path = temp_dir.path().join(".aikey");

    // Create the vault directory with proper permissions
    fs::create_dir_all(&vault_path).unwrap();

    // Initialize vault with password via stdin
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    cmd.arg("init")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .write_stdin("test_password_123\n")
        .assert()
        .success();

    vault_path.to_string_lossy().to_string()
}

#[test]
fn test_secret_set_new_secret() {
    let temp_dir = TempDir::new().unwrap();
    setup_test_vault(&temp_dir);

    // Test: Set a new secret
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    let output = cmd
        .arg("secret")
        .arg("set")
        .arg("test_key")
        .arg("--from-stdin")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .write_stdin("test_password_123\ntest_secret_value\n")
        .output()
        .unwrap();

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: Value = serde_json::from_str(&stderr).unwrap();

    assert_eq!(json["ok"], true);
    assert_eq!(json["name"], "test_key");
}

#[test]
fn test_secret_set_duplicate_error() {
    let temp_dir = TempDir::new().unwrap();
    setup_test_vault(&temp_dir);

    // Add a secret first
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    cmd.arg("add")
        .arg("existing_key")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .env("AK_TEST_SECRET", "original_value")
        .write_stdin("test_password_123\n")
        .assert()
        .success();

    // Try to set the same secret again (should fail with ALIAS_EXISTS)
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    let output = cmd
        .arg("secret")
        .arg("set")
        .arg("existing_key")
        .arg("--from-stdin")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .write_stdin("test_password_123\nnew_value\n")
        .output()
        .unwrap();

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: Value = serde_json::from_str(&stderr).unwrap();

    assert_eq!(json["ok"], false);
    assert_eq!(json["code"], "ALIAS_EXISTS");
    assert!(json["message"].as_str().unwrap().contains("exists"));
}

#[test]
fn test_secret_set_requires_from_stdin() {
    let temp_dir = TempDir::new().unwrap();
    setup_test_vault(&temp_dir);

    // Try to set without --from-stdin flag (should fail)
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    let output = cmd
        .arg("secret")
        .arg("set")
        .arg("test_key")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .write_stdin("test_password_123\n")
        .output()
        .unwrap();

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: Value = serde_json::from_str(&stderr).unwrap();

    assert_eq!(json["ok"], false);
    assert_eq!(json["code"], "INVALID_INPUT");
    assert!(json["message"].as_str().unwrap().contains("--from-stdin"));
}

#[test]
fn test_secret_set_empty_value_error() {
    let temp_dir = TempDir::new().unwrap();

    // Don't call setup_test_vault to avoid setting AK_TEST_PASSWORD
    let vault_path = temp_dir.path().join(".aikey");
    fs::create_dir_all(&vault_path).unwrap();

    // Initialize vault manually without AK_TEST_PASSWORD
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    cmd.arg("init")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .env_remove("AK_TEST_PASSWORD")  // Ensure we don't use the test env var
        .write_stdin("test_password_123\n")
        .assert()
        .success();

    // Try to set an empty secret
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    let output = cmd
        .arg("secret")
        .arg("set")
        .arg("test_key")
        .arg("--from-stdin")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .env_remove("AK_TEST_PASSWORD")  // Ensure we don't use the test env var
        .write_stdin("test_password_123\n\n")  // password + empty secret value
        .output()
        .unwrap();

    eprintln!("Status: {:?}", output.status);
    eprintln!("Success: {}", output.status.success());
    eprintln!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
    eprintln!("Stderr: {}", String::from_utf8_lossy(&output.stderr));

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: Value = serde_json::from_str(&stderr).unwrap();

    assert_eq!(json["ok"], false);
    assert_eq!(json["code"], "INVALID_INPUT");
}

#[test]
fn test_profile_current_no_profile() {
    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("HOME", temp_dir.path());

    // Test: Get current profile when none is set
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    let output = cmd
        .arg("profile")
        .arg("current")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: Value = serde_json::from_str(&stderr).unwrap();

    assert_eq!(json["ok"], false);
    assert_eq!(json["code"], "NO_ACTIVE_PROFILE");
}

#[test]
fn test_profile_current_with_profile() {
    let temp_dir = TempDir::new().unwrap();
    setup_test_vault(&temp_dir);
    std::env::set_var("HOME", temp_dir.path());

    // Set a profile first
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    cmd.arg("profile")
        .arg("use")
        .arg("production")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .assert()
        .success();

    // Get current profile
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    let output = cmd
        .arg("profile")
        .arg("current")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: Value = serde_json::from_str(&stderr).unwrap();

    assert_eq!(json["ok"], true);
    assert_eq!(json["profile"], "production");
}

#[test]
fn test_profile_use_json_output() {
    let temp_dir = TempDir::new().unwrap();
    setup_test_vault(&temp_dir);
    std::env::set_var("HOME", temp_dir.path());

    // Set a profile
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    let output = cmd
        .arg("profile")
        .arg("use")
        .arg("development")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: Value = serde_json::from_str(&stderr).unwrap();

    assert_eq!(json["ok"], true);
    assert_eq!(json["profile"], "development");
}

#[test]
fn test_error_code_vault_locked() {
    let temp_dir = TempDir::new().unwrap();
    setup_test_vault(&temp_dir);

    // Try to set a secret with wrong password (should fail with authentication error)
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    let output = cmd
        .arg("secret")
        .arg("set")
        .arg("test_key")
        .arg("--from-stdin")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .env_remove("AK_TEST_PASSWORD")  // Remove to force stdin password reading
        .write_stdin("wrong_password\ntest_value\n")
        .output()
        .unwrap();

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: Value = serde_json::from_str(&stderr).unwrap();

    assert_eq!(json["ok"], false);
    // Check that we got an error message about authentication
    let message = json["message"].as_str().unwrap();
    assert!(message.contains("Invalid master password") || message.contains("authentication") || message.contains("corrupted vault"));
}

#[test]
fn test_secret_set_integration_with_get() {
    let temp_dir = TempDir::new().unwrap();
    setup_test_vault(&temp_dir);

    // Set a secret using the new API
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    cmd.arg("secret")
        .arg("set")
        .arg("integration_key")
        .arg("--from-stdin")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .env_remove("AK_TEST_PASSWORD")  // Remove to force stdin password reading
        .write_stdin("test_password_123\nintegration_value\n")
        .assert()
        .success();

    // Retrieve it using the existing get command
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    let output = cmd
        .arg("get")
        .arg("integration_key")
        .arg("--password-stdin")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .env("AK_NO_CLIPBOARD", "1")
        .env_remove("AK_TEST_PASSWORD")  // Remove to force stdin password reading
        .write_stdin("test_password_123\n")
        .output()
        .unwrap();

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json: Value = serde_json::from_str(&stderr).unwrap();

    assert_eq!(json["alias"], "integration_key");
    assert_eq!(json["value"], "integration_value");
}
