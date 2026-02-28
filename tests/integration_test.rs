use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use predicates::prelude::*;
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
        let mut cmd = Command::new(cargo_bin("ak"));
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

    /// Update a secret using environment variables
    fn update_secret(&self, alias: &str, secret_value: &str) -> assert_cmd::assert::Assert {
        self.cmd()
            .arg("update")
            .arg(alias)
            .env("AK_TEST_SECRET", secret_value)
            .assert()
    }

    /// Get vault database path
    fn db_path(&self) -> PathBuf {
        self.vault_path.join("vault.db")
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

        // Verify the file was created
        assert!(config_path.exists(), "Config file should exist at {:?}", config_path);
    }
}

#[test]
fn test_01_initialization() {
    let env = TestEnv::new();

    // Initialize vault programmatically
    env.init_vault();

    // Verify vault directory exists
    assert!(env.vault_path.exists(), "Vault directory should exist");
    assert!(env.db_path().exists(), "Database file should exist");

    // Verify permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let vault_perms = fs::metadata(&env.vault_path)
            .expect("Failed to get vault metadata")
            .permissions()
            .mode();
        assert_eq!(vault_perms & 0o777, 0o700, "Vault directory should have 0700 permissions");

        let db_perms = fs::metadata(&env.db_path())
            .expect("Failed to get database metadata")
            .permissions()
            .mode();
        assert_eq!(db_perms & 0o777, 0o600, "Database file should have 0600 permissions");
    }

    // Verify database schema
    let conn = rusqlite::Connection::open(env.db_path()).expect("Failed to open database");

    // Check config table exists
    let config_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='config'",
            [],
            |row| row.get(0),
        )
        .map(|count: i32| count > 0)
        .expect("Failed to check config table");
    assert!(config_exists, "Config table should exist");

    // Check entries table exists
    let entries_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='entries'",
            [],
            |row| row.get(0),
        )
        .map(|count: i32| count > 0)
        .expect("Failed to check entries table");
    assert!(entries_exists, "Entries table should exist");

    // Check salt exists
    let salt_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM config WHERE key='salt'",
            [],
            |row| row.get(0),
        )
        .map(|count: i32| count > 0)
        .expect("Failed to check salt");
    assert!(salt_exists, "Salt should be stored in config");
}

#[test]
fn test_02_crud_operations() {
    let env = TestEnv::new();
    env.init_vault();

    // Test: Add a secret
    env.add_secret("TEST_API_KEY", "sk-test-1234567890abcdef")
        .success()
        .stderr(predicate::str::contains("Secret 'TEST_API_KEY' added successfully"));

    // Test: List secrets
    env.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("TEST_API_KEY"));

    // Test: Add another secret
    env.add_secret("DATABASE_URL", "postgresql://user:pass@localhost/db")
        .success()
        .stderr(predicate::str::contains("Secret 'DATABASE_URL' added successfully"));

    // Test: List should show both secrets
    let list_output = env.cmd()
        .arg("list")
        .assert()
        .success();

    list_output
        .stdout(predicate::str::contains("TEST_API_KEY"))
        .stdout(predicate::str::contains("DATABASE_URL"));

    // Test: Delete a secret
    env.cmd()
        .arg("delete")
        .arg("TEST_API_KEY")
        .assert()
        .success()
        .stdout(predicate::str::contains("Secret deleted"));

    // Test: List should only show remaining secret
    env.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("DATABASE_URL"))
        .stdout(predicate::str::contains("TEST_API_KEY").not());

    // Test: Delete non-existent secret should fail
    env.cmd()
        .arg("delete")
        .arg("NONEXISTENT")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn test_03_injection_engine() {
    let env = TestEnv::new();
    env.init_vault();

    // Create config file with required vars
    env.create_test_config(vec!["TEST_VAR", "ANOTHER_VAR"]);

    // Add test secrets
    env.add_secret("TEST_VAR", "secret_value_123").success();
    env.add_secret("ANOTHER_VAR", "another_secret_456").success();

    // Test: Run command with environment variable injection
    // Use 'env' command to print environment variables
    let output = env.cmd()
        .arg("run")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo TEST_VAR=$TEST_VAR ANOTHER_VAR=$ANOTHER_VAR")
        .assert()
        .success();

    // Verify environment variables were injected
    output
        .stdout(predicate::str::contains("TEST_VAR=secret_value_123"))
        .stdout(predicate::str::contains("ANOTHER_VAR=another_secret_456"));

    // Test: Verify injection count message
    env.cmd()
        .arg("run")
        .arg("--")
        .arg("echo")
        .arg("test")
        .assert()
        .success()
        .stderr(predicate::str::contains("Injecting 2 secret(s)"));
}

#[test]
fn test_04_security_auth_failure() {
    let env = TestEnv::new();
    env.init_vault();

    // Add a secret with correct password
    env.add_secret("TEST_SECRET", "test_value").success();

    // Test: Try to add with wrong password (override the env var)
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", env._temp_dir.path())
        .env("AK_TEST_PASSWORD", "wrong_password")
        .env("AK_TEST_SECRET", "some_value")
        .arg("add")
        .arg("ANOTHER_SECRET")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Error"))
        .stderr(predicate::str::contains("Invalid master password").or(predicate::str::contains("corrupted vault")));

    // Wait for rate limit to reset (need to wait 30 seconds)
    std::thread::sleep(std::time::Duration::from_secs(31));

    // Test: Verify correct password still works after failed attempt
    env.add_secret("VALID_SECRET", "valid_value").success();
}

#[test]
fn test_05_persistence() {
    let env = TestEnv::new();
    env.init_vault();

    // Add secrets
    env.add_secret("PERSISTENT_KEY_1", "value_one").success();
    env.add_secret("PERSISTENT_KEY_2", "value_two").success();
    env.add_secret("PERSISTENT_KEY_3", "value_three").success();

    // Verify secrets are in database
    let conn = rusqlite::Connection::open(env.db_path()).expect("Failed to open database");
    let count: i32 = conn
        .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
        .expect("Failed to count secrets");
    assert_eq!(count, 3, "Should have 3 secrets in database");

    // Simulate process exit by dropping the command
    drop(env.cmd());

    // Create new command instance (simulates new process)
    let list_output = env.cmd()
        .arg("list")
        .assert()
        .success();

    // Verify all secrets still exist
    list_output
        .stdout(predicate::str::contains("PERSISTENT_KEY_1"))
        .stdout(predicate::str::contains("PERSISTENT_KEY_2"))
        .stdout(predicate::str::contains("PERSISTENT_KEY_3"));

    // Delete one secret
    env.cmd()
        .arg("delete")
        .arg("PERSISTENT_KEY_2")
        .assert()
        .success();

    // Verify deletion persisted
    let count_after: i32 = conn
        .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
        .expect("Failed to count secrets after deletion");
    assert_eq!(count_after, 2, "Should have 2 secrets after deletion");

    // Verify correct secrets remain
    env.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("PERSISTENT_KEY_1"))
        .stdout(predicate::str::contains("PERSISTENT_KEY_2").not())
        .stdout(predicate::str::contains("PERSISTENT_KEY_3"));
}

#[test]
fn test_06_empty_vault_operations() {
    let env = TestEnv::new();
    env.init_vault();

    // Test: List empty vault
    env.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets stored"));

    // Test: Run with empty vault and empty config (no required vars)
    env.create_test_config(vec![]);
    env.cmd()
        .arg("run")
        .arg("--")
        .arg("echo")
        .arg("test")
        .assert()
        .success()  // Should succeed with 0 injections
        .stderr(predicate::str::contains("Injecting 0 secret(s)"));

    // Test: Get non-existent secret
    env.cmd()
        .arg("get")
        .arg("NONEXISTENT")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn test_07_special_characters_in_secrets() {
    let env = TestEnv::new();
    env.init_vault();

    // Create config with SPECIAL_CHARS as required var
    env.create_test_config(vec!["SPECIAL_CHARS"]);

    // Test secrets with special characters
    let special_secret = "p@ssw0rd!#$%^&*(){}[]|\\:;\"'<>,.?/~`";
    env.add_secret("SPECIAL_CHARS", special_secret).success();

    // Verify it can be retrieved via run command
    let output = env.cmd()
        .arg("run")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("printf '%s' \"$SPECIAL_CHARS\"")
        .write_stdin(format!("{}\n", env.test_password))
        .assert()
        .success();

    output.stdout(predicate::str::contains(special_secret));
}

#[test]
fn test_08_run_command_exit_codes() {
    let env = TestEnv::new();
    env.init_vault();

    // Create config with TEST_VAR as required var
    env.create_test_config(vec!["TEST_VAR"]);

    env.add_secret("TEST_VAR", "test_value").success();

    // Test: Successful command should exit with 0
    env.cmd()
        .arg("run")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("exit 0")
        .assert()
        .success()
        .code(0);

    // Test: Failed command should preserve exit code
    env.cmd()
        .arg("run")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("exit 42")
        .assert()
        .failure()
        .code(42);
}

#[test]
fn test_09_update_secret() {
    let env = TestEnv::new();
    env.init_vault();

    // Create config with UPDATE_TEST as required var
    env.create_test_config(vec!["UPDATE_TEST"]);

    // Test: Add initial secret
    env.add_secret("UPDATE_TEST", "initial_value")
        .success()
        .stderr(predicate::str::contains("Secret 'UPDATE_TEST' added successfully"));

    // Test: Update the secret with new value
    env.update_secret("UPDATE_TEST", "updated_value")
        .success()
        .stderr(predicate::str::contains("Secret 'UPDATE_TEST' updated successfully"));

    // Test: Verify the updated value via run command
    let output = env.cmd()
        .arg("run")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo \"$UPDATE_TEST\"")
        .assert()
        .success();

    output.stdout(predicate::str::contains("updated_value"));

    // Test: Update non-existent secret should fail
    env.cmd()
        .arg("update")
        .arg("NONEXISTENT")
        .env("AK_TEST_SECRET", "some_value")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Secret 'NONEXISTENT' not found"));

    // Test: Update with wrong password should fail
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", env._temp_dir.path())
        .env("AK_TEST_PASSWORD", "wrong_password")
        .env("AK_TEST_SECRET", "new_value")
        .arg("update")
        .arg("UPDATE_TEST")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}
