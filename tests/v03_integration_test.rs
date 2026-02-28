use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to initialize vault and set a default profile for env commands
fn setup_vault_and_profile(temp_dir: &TempDir) {
    // Initialize vault
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    cmd.arg("init")
        .arg("--password-stdin")
        .env("HOME", temp_dir.path())
        .write_stdin("test_password_123\n")
        .assert()
        .success();

    // Set a default profile
    let mut cmd = Command::cargo_bin("aikey").unwrap();
    cmd.arg("profile")
        .arg("use")
        .arg("default")
        .arg("--json")
        .env("HOME", temp_dir.path())
        .assert()
        .success();
}

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

    // Create initial config
    let initial_config = r#"{
        "schemaVersion": "1",
        "project": {
            "name": "existing-project"
        },
        "env": {
            "target": ".env"
        },
        "requiredVars": ["KEY1"]
    }"#;
    fs::write(&config_path, initial_config).unwrap();

    let mut cmd = Command::cargo_bin("aikey").unwrap();

    // Test that it prompts for update confirmation
    // Input: y (update), existing-project (name), 1 (Node), .env (target), n (don't use suggested), KEY2 (custom vars)
    cmd.current_dir(temp_dir.path())
        .arg("project")
        .arg("init")
        .write_stdin("y\nexisting-project\n1\n.env\nn\nKEY2\n")
        .assert()
        .success();

    // Verify config was updated
    let config_content = fs::read_to_string(&config_path).unwrap();
    assert!(config_content.contains("existing-project"));
    // The new config should have KEY2 from the custom input
    assert!(config_content.contains("KEY2"));
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
        .stderr(predicate::str::contains("No aikey.config"));
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

#[test]
#[ignore = "Legacy profile-based feature - requires complex vault and profile setup"]
fn test_env_generate_no_existing_env() {
    let temp_dir = TempDir::new().unwrap();
    setup_vault_and_profile(&temp_dir);
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
        .env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .arg("env")
        .arg("generate")
        .assert()
        .success();

    // Check that .env file was created
    let env_path = temp_dir.path().join(".env");
    assert!(env_path.exists());

    // Verify .env content
    let env_content = fs::read_to_string(&env_path).unwrap();
    assert!(env_content.contains("KEY1="));
    assert!(env_content.contains("KEY2="));
}

#[test]
#[ignore = "Legacy profile-based feature - requires complex vault and profile setup"]
fn test_env_generate_with_existing_env() {
    let temp_dir = TempDir::new().unwrap();
    setup_vault_and_profile(&temp_dir);
    let config_path = temp_dir.path().join("aikey.config.json");
    let env_path = temp_dir.path().join(".env");

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

    // Create existing .env with comments and unknown keys
    let existing_env = "# This is a comment\nKEY1=old_value\nUNKNOWN_KEY=keep_this\n";
    fs::write(&env_path, existing_env).unwrap();

    let mut cmd = Command::cargo_bin("aikey").unwrap();

    cmd.current_dir(temp_dir.path())
        .env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .arg("env")
        .arg("generate")
        .assert()
        .success();

    // Verify .env content preserves comments and unknown keys
    let env_content = fs::read_to_string(&env_path).unwrap();
    assert!(env_content.contains("# This is a comment"));
    assert!(env_content.contains("UNKNOWN_KEY=keep_this"));
    assert!(env_content.contains("KEY1="));
    assert!(env_content.contains("KEY2="));
    assert!(!env_content.contains("old_value"));
}

#[test]
#[ignore = "Legacy profile-based feature - requires complex vault and profile setup"]
fn test_env_generate_dry_run() {
    let temp_dir = TempDir::new().unwrap();
    setup_vault_and_profile(&temp_dir);
    let config_path = temp_dir.path().join("aikey.config.json");
    let env_path = temp_dir.path().join(".env");

    let config = r#"{
        "schemaVersion": "1",
        "project": {
            "name": "test-project"
        },
        "env": {
            "target": ".env"
        },
        "requiredVars": ["KEY1"]
    }"#;
    fs::write(&config_path, config).unwrap();

    let mut cmd = Command::cargo_bin("aikey").unwrap();

    cmd.current_dir(temp_dir.path())
        .env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .arg("env")
        .arg("generate")
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("dry-run"));

    // Verify .env file was NOT created
    assert!(!env_path.exists());
}

#[test]
#[ignore = "Legacy profile-based feature - requires complex vault and profile setup"]
fn test_env_inject_basic() {
    let temp_dir = TempDir::new().unwrap();
    setup_vault_and_profile(&temp_dir);
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
        .env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .arg("env")
        .arg("inject")
        .assert()
        .success()
        .stdout(predicate::str::contains("KEY1"))
        .stdout(predicate::str::contains("KEY2"));

    // Verify no .env file was written
    let env_path = temp_dir.path().join(".env");
    assert!(!env_path.exists());
}

#[test]
#[ignore = "Legacy profile-based feature - requires complex vault and profile setup"]
fn test_env_inject_eval_mode() {
    let temp_dir = TempDir::new().unwrap();
    setup_vault_and_profile(&temp_dir);
    let config_path = temp_dir.path().join("aikey.config.json");

    let config = r#"{
        "schemaVersion": "1",
        "project": {
            "name": "test-project"
        },
        "env": {
            "target": ".env"
        },
        "requiredVars": ["KEY1"]
    }"#;
    fs::write(&config_path, config).unwrap();

    let mut cmd = Command::cargo_bin("aikey").unwrap();

    cmd.current_dir(temp_dir.path())
        .env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .env("AIKEY_INJECT_MODE", "eval")
        .arg("env")
        .arg("inject")
        .assert()
        .success()
        .stdout(predicate::str::contains("export KEY1="));
}
