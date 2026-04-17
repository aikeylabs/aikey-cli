//! Tests for the `aikey project` subcommand: init + status.
//!
//! Renamed from `v03_integration_test.rs` on 2026-04-17. The file originally
//! held five additional `aikey env generate/inject` tests targeting the
//! v0.3 project-local `.env` workflow; those commands were removed in
//! Stage 2 and the tests were deleted alongside this rename. See the
//! 2026-04-17 ignored-test cleanup report for rationale.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_project_init_clean_directory() {
    let temp_dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("aikey").unwrap();

    cmd.current_dir(temp_dir.path())
        .arg("project")
        .arg("init")
        .write_stdin("test-project\nNode\n.env\nOPENAI_API_KEY,ANTHROPIC_API_KEY\n")
        .assert()
        .success();

    // Check that config file was created
    let config_path = temp_dir.path().join("aikey.config.json");
    assert!(config_path.exists());

    // Verify config content
    let config_content = fs::read_to_string(&config_path).unwrap();
    assert!(config_content.contains("test-project"));
    assert!(config_content.contains("OPENAI_API_KEY"));
    assert!(config_content.contains("ANTHROPIC_API_KEY"));
}

#[test]
fn test_project_init_existing_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("aikey.config.json");

    // Create an existing config
    let existing_config = r#"{
        "schemaVersion": "1",
        "project": {
            "name": "existing-project"
        }
    }"#;
    fs::write(&config_path, existing_config).unwrap();

    // When a config already exists the CLI prompts whether to overwrite.
    // The test declines (stdin ends with "no"). Current CLI exits non-zero
    // with "Cancelled" instead of silently succeeding — we assert that
    // behaviour so the user-visible "I didn't change anything" signal
    // (the exit code) is preserved across refactors.
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("project")
        .arg("init")
        .write_stdin("new-project\nNode\n.env\nKEY1\nno\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Cancelled"));

    // Config must be untouched.
    let config_content = fs::read_to_string(&config_path).unwrap();
    assert!(config_content.contains("existing-project"));
    assert!(!config_content.contains("new-project"));
}

#[test]
fn test_project_status_no_config() {
    let temp_dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("aikey").unwrap();

    cmd.current_dir(temp_dir.path())
        .arg("project")
        .arg("status")
        .assert()
        .failure()
        // Current wording (2026-04): "No aikey.config.json found in current
        // directory or parent directories". Match just the filename anchor so
        // minor phrasing revisions don't break the test.
        .stderr(predicate::str::contains("aikey.config.json"));
}

#[test]
fn test_project_status_with_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("aikey.config.json");

    let config = r#"{
        "schemaVersion": "1",
        "project": {
            "name": "test-project"
        },
        "env": {
            "target": ".env"
        },
        "requiredVars": ["KEY1", "KEY2"]
    }"#;
    fs::write(&config_path, config).unwrap();

    let mut cmd = Command::cargo_bin("aikey").unwrap();

    cmd.current_dir(temp_dir.path())
        .arg("project")
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("test-project"))
        .stdout(predicate::str::contains("KEY1"))
        .stdout(predicate::str::contains("KEY2"));
}
