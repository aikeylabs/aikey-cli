use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

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

    /// Prepare the vault directory, then let the CLI lazy-init via a throwaway
    /// `add`. Hand-rolling the schema here used to work but the CLI's migrations
    /// have since added many columns/tables; delegating keeps this helper valid.
    fn init_vault(&self) {
        let data_dir = self.vault_path.join("data");
        fs::create_dir_all(&data_dir).expect("Failed to create vault data directory");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.vault_path, fs::Permissions::from_mode(0o700))
                .expect("Failed to set vault directory permissions");
        }

        self.cmd()
            .arg("add")
            .arg("__init_bootstrap__")
            .args(["--provider", "openai"])
            .env("AK_TEST_SECRET", "bootstrap")
            .assert()
            .success();
        self.cmd()
            .arg("delete")
            .arg("__init_bootstrap__")
            .assert()
            .success();
    }

    /// Add a secret using environment variables. `--provider` is required in
    /// non-interactive mode; default to openai since these tests don't exercise
    /// provider-specific behaviour.
    fn add_secret(&self, alias: &str, secret_value: &str) -> assert_cmd::assert::Assert {
        self.cmd()
            .arg("add")
            .arg(alias)
            .args(["--provider", "openai"])
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

#[test]
fn test_json_list_empty_vault() {
    let env = TestEnv::new();
    env.init_vault();

    let output = env.cmd()
        .arg("list")
        .arg("--json")
        .assert()
        .success();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "success");
    assert_eq!(json["secrets"].as_array().unwrap().len(), 0);
}

#[test]
fn test_json_list_with_secrets() {
    let env = TestEnv::new();
    env.init_vault();

    // Add test secrets
    env.add_secret("API_KEY", "sk-test-123").success();
    env.add_secret("DATABASE_URL", "postgresql://localhost/db").success();
    env.add_secret("SECRET_TOKEN", "token-xyz").success();

    let output = env.cmd()
        .arg("list")
        .arg("--json")
        .assert()
        .success();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    eprintln!("JSON output: {}", stderr);
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "success");

    let secrets = json["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 3);

    // Verify secret names are present
    let names: Vec<&str> = secrets.iter()
        .map(|s| s["alias"].as_str().unwrap())
        .collect();

    assert!(names.contains(&"API_KEY"));
    assert!(names.contains(&"DATABASE_URL"));
    assert!(names.contains(&"SECRET_TOKEN"));

    // Verify each secret has required fields
    for secret in secrets {
        assert!(secret["alias"].is_string());
        assert!(secret["created_at"].is_number());
    }
}

#[test]
fn test_json_add_success() {
    let env = TestEnv::new();
    env.init_vault();

    let output = env.cmd()
        .arg("add")
        .arg("TEST_KEY")
        .args(["--provider", "openai"])
        .arg("--json")
        .env("AK_TEST_SECRET", "test_value")
        .assert()
        .success();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "success");
    assert_eq!(json["alias"], "TEST_KEY");
    // 2026-04 wording: emphasizes the downstream effect (binding refresh), not
    // just the storage op. Match the current string rather than the old one.
    assert!(json["message"].as_str().unwrap().contains("Added key"));
}

#[test]
fn test_json_add_duplicate() {
    let env = TestEnv::new();
    env.init_vault();

    // Add first secret
    env.add_secret("DUPLICATE_KEY", "value1").success();

    // Try to add duplicate
    let output = env.cmd()
        .arg("add")
        .arg("DUPLICATE_KEY")
        .args(["--provider", "openai"])
        .arg("--json")
        .env("AK_TEST_SECRET", "value2")
        .assert()
        .failure();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "error");
    assert!(json["error"].as_str().unwrap().contains("already exists"));
}

#[test]
fn test_json_get_success() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("GET_TEST", "secret_value_123").success();

    let output = env.cmd()
        .arg("get")
        .arg("GET_TEST")
        .arg("--json")
        .assert()
        .success();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "success");
    assert_eq!(json["alias"], "GET_TEST");
    assert_eq!(json["value"], "secret_value_123");
}

#[test]
fn test_json_get_not_found() {
    let env = TestEnv::new();
    env.init_vault();

    let output = env.cmd()
        .arg("get")
        .arg("NONEXISTENT")
        .arg("--json")
        .assert()
        .failure();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "error");
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[test]
fn test_json_update_success() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("UPDATE_KEY", "initial_value").success();

    let output = env.cmd()
        .arg("update")
        .arg("UPDATE_KEY")
        .arg("--json")
        .env("AK_TEST_SECRET", "updated_value")
        .assert()
        .success();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "success");
    assert_eq!(json["alias"], "UPDATE_KEY");
    assert_eq!(json["message"], "API Key updated successfully");
}

#[test]
fn test_json_update_not_found() {
    let env = TestEnv::new();
    env.init_vault();

    let output = env.cmd()
        .arg("update")
        .arg("NONEXISTENT")
        .arg("--json")
        .env("AK_TEST_SECRET", "some_value")
        .assert()
        .failure();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "error");
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[test]
fn test_json_delete_success() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("DELETE_KEY", "value").success();

    let output = env.cmd()
        .arg("delete")
        .arg("DELETE_KEY")
        .arg("--json")
        .assert()
        .success();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "success");
    assert_eq!(json["alias"], "DELETE_KEY");
    assert_eq!(json["message"], "API Key deleted successfully");
}

#[test]
fn test_json_delete_not_found() {
    let env = TestEnv::new();
    env.init_vault();

    let output = env.cmd()
        .arg("delete")
        .arg("NONEXISTENT")
        .arg("--json")
        .assert()
        .failure();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "error");
    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[test]
fn test_json_change_password_success() {
    let env = TestEnv::new();
    env.init_vault();

    env.add_secret("TEST_SECRET", "value").success();

    let output = env.cmd()
        .arg("change-password")
        .arg("--json")
        .env("AK_TEST_NEW_PASSWORD", "new_password_456")
        .assert()
        .success();

    let stderr = String::from_utf8(output.get_output().stderr.clone()).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("Should be valid JSON");

    assert_eq!(json["status"], "success");
    assert_eq!(json["message"], "Master password changed successfully.");
}
