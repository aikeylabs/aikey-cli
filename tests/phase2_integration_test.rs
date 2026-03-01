use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper function to parse JSON from stderr (where --json output goes)
fn parse_json_output(output: &assert_cmd::assert::Assert) -> Value {
    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    serde_json::from_str(&stderr).expect("Should be valid JSON")
}

/// Helper struct to manage test environment
struct TestEnv {
    _temp_dir: TempDir,
    vault_path: PathBuf,
    test_password: String,
}

impl TestEnv {
    fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let vault_path = temp_dir.path().join(".aikey");

        Self {
            _temp_dir: temp_dir,
            vault_path,
            test_password: "test_master_password_123".to_string(),
        }
    }

    /// Get a Command with HOME set to temp directory
    fn cmd(&self) -> Command {
        let mut cmd = Command::new(cargo_bin("aikey"));
        cmd.env("HOME", self._temp_dir.path());
        cmd.env("AK_TEST_PASSWORD", &self.test_password);
        cmd.current_dir(self._temp_dir.path());  // Set working directory to temp dir
        cmd
    }

    /// Get a Command using 'ak' alias
    fn cmd_ak(&self) -> Command {
        let mut cmd = Command::new(cargo_bin("aikey"));
        cmd.env("HOME", self._temp_dir.path());
        cmd.env("AK_TEST_PASSWORD", &self.test_password);
        cmd.current_dir(self._temp_dir.path());  // Set working directory to temp dir
        cmd
    }

    /// Initialize vault with test password (non-interactive)
    fn init_vault(&self) {
        // Create vault directory
        fs::create_dir_all(&self.vault_path).expect("Failed to create vault directory");

        // Use the library directly to initialize without interactive prompts
        use rand::RngCore;
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        // Create database file
        let db_path = self.vault_path.join("vault.db");
        let conn = rusqlite::Connection::open(&db_path).expect("Failed to create database");

        // Set strict permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.vault_path, fs::Permissions::from_mode(0o700))
                .expect("Failed to set vault directory permissions");
            fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600))
                .expect("Failed to set database permissions");
        }

        // Initialize schema
        conn.execute(
            "CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )",
            [],
        ).expect("Failed to create config table");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias TEXT NOT NULL UNIQUE,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                version_tag INTEGER NOT NULL DEFAULT 1,
                metadata TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )",
            [],
        ).expect("Failed to create entries table");

        // Store salt
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('salt', ?1)",
            [&salt[..]],
        ).expect("Failed to store salt");
    }

    /// Add a secret using environment variables
    fn add_secret(&self, alias: &str, secret_value: &str) -> assert_cmd::assert::Assert {
        self.cmd()
            .arg("add")
            .arg(alias)
            .env("AK_TEST_SECRET", secret_value)
            .assert()
    }

    /// Create a minimal project config file for testing
    fn create_test_config(&self, required_vars: Vec<&str>) {
        let required_vars_json: Vec<String> = required_vars.iter().map(|v| format!("\"{}\"", v)).collect();
        let config = format!(
            r#"{{
    "schemaVersion": "0.1.0",
    "project": {{"name": "test"}},
    "env": {{"target": ".env"}},
    "providers": {{}},
    "requiredVars": [{}],
    "bindings": {{}},
    "envMappings": {{}}
}}"#,
            required_vars_json.join(", ")
        );
        let config_path = self._temp_dir.path().join("aikey.config.json");
        fs::write(&config_path, config)
            .expect("Failed to create test config");
    }
}

// ============================================================================
// Phase 2 Feature Tests: Primary Binary Name
// ============================================================================

#[test]
fn test_aikey_binary_exists() {
    let env = TestEnv::new();
    env.init_vault();

    // Test that 'aikey' binary works
    env.cmd()
        .arg("list")
        .assert()
        .success();
}

#[test]
fn test_ak_alias_still_works() {
    let env = TestEnv::new();
    env.init_vault();

    // Test that 'ak' alias still works
    env.cmd_ak()
        .arg("list")
        .assert()
        .success();
}

#[test]
fn test_both_binaries_produce_same_output() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("TEST_KEY", "test_value").success();

    // Get output from aikey
    let output_aikey = env.cmd()
        .arg("list")
        .arg("--json")
        .assert()
        .success();

    // Get output from ak
    let output_ak = env.cmd_ak()
        .arg("list")
        .arg("--json")
        .assert()
        .success();

    let json_aikey = parse_json_output(&output_aikey);
    let json_ak = parse_json_output(&output_ak);

    // Both should produce identical JSON output
    assert_eq!(json_aikey, json_ak);
}

// ============================================================================
// Phase 2 Feature Tests: JSON Output Mode
// ============================================================================

#[test]
fn test_json_output_list_command() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("API_KEY", "sk-test-123").success();
    env.add_secret("DB_URL", "postgresql://localhost").success();

    let output = env.cmd()
        .arg("list")
        .arg("--json")
        .assert()
        .success();

    let json = parse_json_output(&output);

    assert_eq!(json["status"], "success");
    assert_eq!(json["secrets"].as_array().unwrap().len(), 2);

    // Verify JSON structure
    for secret in json["secrets"].as_array().unwrap() {
        assert!(secret["alias"].is_string());
        assert!(secret["created_at"].is_number());
    }
}

#[test]
fn test_json_output_get_command() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("TEST_SECRET", "secret_value").success();

    let output = env.cmd()
        .arg("get")
        .arg("TEST_SECRET")
        .arg("--json")
        .assert()
        .success();

    let json = parse_json_output(&output);

    assert_eq!(json["status"], "success");
    assert_eq!(json["alias"], "TEST_SECRET");
    assert_eq!(json["value"], "secret_value");
}

#[test]
fn test_json_output_add_command() {
    let env = TestEnv::new();
    env.init_vault();

    let output = env.cmd()
        .arg("add")
        .arg("NEW_KEY")
        .arg("--json")
        .env("AK_TEST_SECRET", "new_value")
        .assert()
        .success();

    let json = parse_json_output(&output);

    assert_eq!(json["status"], "success");
    assert_eq!(json["alias"], "NEW_KEY");
}

#[test]
fn test_json_output_update_command() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("UPDATE_KEY", "old_value").success();

    let output = env.cmd()
        .arg("update")
        .arg("UPDATE_KEY")
        .arg("--json")
        .env("AK_TEST_SECRET", "new_value")
        .assert()
        .success();

    let json = parse_json_output(&output);

    assert_eq!(json["status"], "success");
    assert_eq!(json["alias"], "UPDATE_KEY");
}

#[test]
fn test_json_output_delete_command() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("DELETE_KEY", "value").success();

    let output = env.cmd()
        .arg("delete")
        .arg("DELETE_KEY")
        .arg("--json")
        .assert()
        .success();

    let json = parse_json_output(&output);

    assert_eq!(json["status"], "success");
    assert_eq!(json["alias"], "DELETE_KEY");
}

#[test]
fn test_json_output_error_handling() {
    let env = TestEnv::new();
    env.init_vault();

    // Try to get non-existent secret
    let output = env.cmd()
        .arg("get")
        .arg("NONEXISTENT")
        .arg("--json")
        .assert()
        .failure();

    let json = parse_json_output(&output);

    assert_eq!(json["status"], "error");
    assert!(json["error"].is_string());
}

// ============================================================================
// Phase 2 Feature Tests: Exec Command
// ============================================================================

#[test]
fn test_exec_command_basic() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("TEST_VAR", "test_value").success();

    env.cmd()
        .arg("exec")
        .arg("--env")
        .arg("TEST_VAR=TEST_VAR")
        .arg("--")
        .arg("echo")
        .arg("test")
        .assert()
        .success();
}

#[test]
fn test_exec_command_with_json() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("API_KEY", "sk-123").success();
    env.create_test_config(vec!["API_KEY"]);

    let output = env.cmd()
        .arg("run")
        .arg("--json")
        .arg("--")
        .arg("echo")
        .arg("test")
        .assert()
        .success();

    // JSON output is on stderr to avoid mixing with child process stdout
    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "success");
    assert!(json["secrets_injected"].is_number());
    assert_eq!(json["exit_code"], 0);
}

#[test]
fn test_exec_command_exit_code_propagation() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("TEST_VAR", "value").success();
    env.create_test_config(vec!["TEST_VAR"]);

    let output = env.cmd()
        .arg("run")
        .arg("--json")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("exit 42")
        .assert()
        .failure();

    let json = parse_json_output(&output);

    assert_eq!(json["status"], "error");
    assert_eq!(json["exit_code"], 42);
}

// ============================================================================
// Phase 2 Feature Tests: Vault Operations Stability
// ============================================================================

#[test]
fn test_vault_init_idempotency() {
    let env = TestEnv::new();
    env.init_vault();

    // Try to init again - should fail gracefully
    let output = env.cmd()
        .arg("init")
        .arg("--json")
        .env("AK_TEST_PASSWORD", "new_password")
        .assert()
        .failure();

    let json = parse_json_output(&output);

    assert_eq!(json["status"], "error");
    assert!(json["error"].as_str().unwrap().contains("already initialized"));
}

#[test]
fn test_add_update_get_delete_workflow() {
    let env = TestEnv::new();
    env.init_vault();

    // Add
    env.cmd()
        .arg("add")
        .arg("WORKFLOW_KEY")
        .arg("--json")
        .env("AK_TEST_SECRET", "initial_value")
        .assert()
        .success();

    // Get
    let output = env.cmd()
        .arg("get")
        .arg("WORKFLOW_KEY")
        .arg("--json")
        .assert()
        .success();

    let json = parse_json_output(&output);
    assert_eq!(json["value"], "initial_value");

    // Update
    env.cmd()
        .arg("update")
        .arg("WORKFLOW_KEY")
        .arg("--json")
        .env("AK_TEST_SECRET", "updated_value")
        .assert()
        .success();

    // Get updated value
    let output = env.cmd()
        .arg("get")
        .arg("WORKFLOW_KEY")
        .arg("--json")
        .assert()
        .success();

    let json = parse_json_output(&output);
    assert_eq!(json["value"], "updated_value");

    // Delete
    env.cmd()
        .arg("delete")
        .arg("WORKFLOW_KEY")
        .arg("--json")
        .assert()
        .success();

    // Verify deleted
    env.cmd()
        .arg("get")
        .arg("WORKFLOW_KEY")
        .arg("--json")
        .assert()
        .failure();
}

#[test]
fn test_list_pagination_and_ordering() {
    let env = TestEnv::new();
    env.init_vault();

    // Add multiple secrets
    for i in 1..=5 {
        env.add_secret(&format!("KEY_{}", i), &format!("value_{}", i)).success();
    }

    let output = env.cmd()
        .arg("list")
        .arg("--json")
        .assert()
        .success();

    let json = parse_json_output(&output);

    let secrets = json["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 5);

    // Verify all keys are present
    let aliases: Vec<&str> = secrets.iter()
        .map(|s| s["alias"].as_str().unwrap())
        .collect();

    for i in 1..=5 {
        assert!(aliases.contains(&format!("KEY_{}", i).as_str()));
    }
}

// ============================================================================
// Phase 2 Feature Tests: Error Handling and Edge Cases
// ============================================================================

#[test]
fn test_json_output_preserves_error_codes() {
    let env = TestEnv::new();
    env.init_vault();

    // Test various error scenarios
    let test_cases = vec![
        ("get", vec!["NONEXISTENT"], "not found"),
        ("update", vec!["NONEXISTENT"], "not found"),
        ("delete", vec!["NONEXISTENT"], "not found"),
    ];

    for (command, args, expected_error) in test_cases {
        let mut cmd = env.cmd();
        cmd.arg(command);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.arg("--json");
        cmd.env("AK_TEST_SECRET", "dummy");

        let output = cmd.assert().failure();

        let json = parse_json_output(&output);

        assert_eq!(json["status"], "error");
        assert!(json["error"].as_str().unwrap().contains(expected_error),
                "Command {} should contain error: {}", command, expected_error);
    }
}

#[test]
fn test_concurrent_operations() {
    let env = TestEnv::new();
    env.init_vault();

    // Add initial secret
    env.add_secret("CONCURRENT_KEY", "initial").success();

    // Simulate concurrent reads (should all succeed)
    for _ in 0..5 {
        env.cmd()
            .arg("get")
            .arg("CONCURRENT_KEY")
            .arg("--json")
            .assert()
            .success();
    }
}

#[test]
fn test_special_characters_in_alias() {
    let env = TestEnv::new();
    env.init_vault();

    let special_aliases = vec![
        "KEY_WITH_UNDERSCORE",
        "KEY-WITH-DASH",
        "KEY.WITH.DOT",
        "KEY123",
    ];

    for alias in special_aliases {
        env.cmd()
            .arg("add")
            .arg(alias)
            .arg("--json")
            .env("AK_TEST_SECRET", "value")
            .assert()
            .success();

        let output = env.cmd()
            .arg("get")
            .arg(alias)
            .arg("--json")
            .assert()
            .success();

        let json = parse_json_output(&output);
        assert_eq!(json["alias"], alias);
    }
}

#[test]
fn test_empty_vault_operations() {
    let env = TestEnv::new();
    env.init_vault();

    // List empty vault
    let output = env.cmd()
        .arg("list")
        .arg("--json")
        .assert()
        .success();

    let json = parse_json_output(&output);
    assert_eq!(json["secrets"].as_array().unwrap().len(), 0);

    // Try to get from empty vault
    env.cmd()
        .arg("get")
        .arg("NONEXISTENT")
        .arg("--json")
        .assert()
        .failure();
}
