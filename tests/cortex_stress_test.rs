//! Cortex (Day 2) Stress Test Suite
//!
//! This test suite verifies the complete implementation of the Cortex specification:
//! 1. Schema Integrity: Verify all required columns exist
//! 2. Migration Test: Simulate old database and verify automatic migration
//! 3. Versioning Logic: Verify version_tag increments correctly
//! 4. Metadata Parsing: Verify JSON metadata storage and retrieval

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use rusqlite::Connection;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to get test vault path
fn get_test_vault_path(temp_dir: &TempDir) -> PathBuf {
    temp_dir.path().join(".aikey").join("vault.db")
}

/// Helper to create a test vault directory
fn setup_test_vault(temp_dir: &TempDir) -> PathBuf {
    let vault_dir = temp_dir.path().join(".aikey");
    fs::create_dir_all(&vault_dir).expect("Failed to create vault directory");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&vault_dir).unwrap();
        let mut perms = metadata.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&vault_dir, perms).unwrap();
    }

    vault_dir.join("vault.db")
}

#[test]
fn test_01_schema_integrity() {
    println!("\n=== TEST 1: Schema Integrity ===");

    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = setup_test_vault(&temp_dir);

    // Initialize vault using the CLI
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .arg("init")
        .assert()
        .success();

    // Open database and verify schema
    let conn = Connection::open(&db_path).expect("Failed to open database");

    // Get all columns from entries table
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info('entries')")
        .expect("Failed to prepare query");

    let columns: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .expect("Failed to query columns")
        .collect::<Result<Vec<String>, _>>()
        .expect("Failed to collect columns");

    println!("Current schema columns: {:?}", columns);

    // Required columns according to Cortex spec
    let required_columns = vec![
        "id",
        "alias",
        "ciphertext",
        "nonce",
        "version_tag",
        "metadata",
        "created_at",
    ];

    let mut missing_columns = Vec::new();
    for col in &required_columns {
        if !columns.contains(&col.to_string()) {
            missing_columns.push(col);
        }
    }

    if !missing_columns.is_empty() {
        println!("❌ FAILED: Missing columns: {:?}", missing_columns);
        println!("Expected: {:?}", required_columns);
        println!("Found: {:?}", columns);
        panic!("Schema integrity check failed");
    }

    println!("✅ PASSED: All required columns present");
}

#[test]
fn test_02_migration_test() {
    println!("\n=== TEST 2: Migration Test ===");

    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = setup_test_vault(&temp_dir);

    // Create OLD schema (without version_tag, metadata, id)
    let conn = Connection::open(&db_path).expect("Failed to create database");

    conn.execute(
        "CREATE TABLE config (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )",
        [],
    )
    .expect("Failed to create config table");

    conn.execute(
        "CREATE TABLE entries (
            alias TEXT PRIMARY KEY,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        )",
        [],
    )
    .expect("Failed to create OLD entries table");

    // Store a salt
    let salt = vec![1u8; 16];
    conn.execute(
        "INSERT INTO config (key, value) VALUES ('salt', ?1)",
        [&salt],
    )
    .expect("Failed to store salt");

    // Insert a test entry with OLD schema
    conn.execute(
        "INSERT INTO entries (alias, nonce, ciphertext) VALUES ('old_secret', X'000102030405060708090a0b', X'aabbccdd')",
        [],
    )
    .expect("Failed to insert old entry");

    drop(conn);

    println!("✓ Created old database schema (missing version_tag, metadata, id)");

    // Now use the CLI to add a new secret (should trigger migration)
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .env("AK_TEST_SECRET", "new_value")
        .arg("add")
        .arg("new_secret")
        .assert()
        .success();

    println!("✓ Added new secret (migration should have occurred)");

    // Verify migration occurred
    let conn = Connection::open(&db_path).expect("Failed to open database");

    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info('entries')")
        .expect("Failed to prepare query");

    let columns: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .expect("Failed to query columns")
        .collect::<Result<Vec<String>, _>>()
        .expect("Failed to collect columns");

    println!("Columns after migration: {:?}", columns);

    // Check that old data still exists
    let old_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM entries WHERE alias = 'old_secret'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .expect("Failed to check old entry");

    if !old_exists {
        println!("❌ FAILED: Old secret data was lost during migration");
        panic!("Migration test failed: data loss");
    }

    println!("✓ Old secret data preserved");

    // Check that new columns were added
    if !columns.contains(&"version_tag".to_string()) {
        println!("❌ FAILED: version_tag column not added during migration");
        panic!("Migration test failed");
    }

    println!("✅ PASSED: Migration successful, data preserved");
}

#[test]
fn test_03_versioning_logic() {
    println!("\n=== TEST 3: Versioning Logic ===");

    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Initialize vault
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .arg("init")
        .assert()
        .success();

    // Add initial secret (version should be 1)
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .env("AK_TEST_SECRET", "value_v1")
        .arg("add")
        .arg("test_secret")
        .assert()
        .success();

    println!("✓ Added secret (version should be 1)");

    // Check version
    let db_path = get_test_vault_path(&temp_dir);
    let conn = Connection::open(&db_path).expect("Failed to open database");

    let version: i64 = conn
        .query_row(
            "SELECT version_tag FROM entries WHERE alias = 'test_secret'",
            [],
            |row| row.get(0),
        )
        .expect("Failed to get version");

    if version != 1 {
        println!("❌ FAILED: Initial version should be 1, got {}", version);
        panic!("Versioning test failed");
    }

    println!("✓ Initial version = 1");

    // Update secret (version should increment to 2)
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .env("AK_TEST_SECRET", "value_v2")
        .arg("add")
        .arg("test_secret")
        .assert()
        .success();

    let version: i64 = conn
        .query_row(
            "SELECT version_tag FROM entries WHERE alias = 'test_secret'",
            [],
            |row| row.get(0),
        )
        .expect("Failed to get version");

    if version != 2 {
        println!("❌ FAILED: Version after first update should be 2, got {}", version);
        panic!("Versioning test failed");
    }

    println!("✓ After first update: version = 2");

    // Update again (version should increment to 3)
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .env("AK_TEST_SECRET", "value_v3")
        .arg("add")
        .arg("test_secret")
        .assert()
        .success();

    let version: i64 = conn
        .query_row(
            "SELECT version_tag FROM entries WHERE alias = 'test_secret'",
            [],
            |row| row.get(0),
        )
        .expect("Failed to get version");

    if version != 3 {
        println!("❌ FAILED: Version after second update should be 3, got {}", version);
        panic!("Versioning test failed");
    }

    println!("✓ After second update: version = 3");
    println!("✅ PASSED: Version increments correctly (1 → 2 → 3)");
}

#[test]
fn test_04_metadata_parsing() {
    println!("\n=== TEST 4: Metadata Parsing ===");

    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Initialize vault
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .arg("init")
        .assert()
        .success();

    // For now, we'll manually insert metadata since CLI doesn't support it yet
    let db_path = get_test_vault_path(&temp_dir);
    let conn = Connection::open(&db_path).expect("Failed to open database");

    // Check if metadata column exists
    let has_metadata: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='metadata'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false);

    if !has_metadata {
        println!("❌ FAILED: metadata column does not exist");
        panic!("Metadata test failed: column missing");
    }

    println!("✓ metadata column exists");

    // Insert a secret with JSON metadata
    let json_metadata = r#"{"provider": "deepseek", "purpose": "prod"}"#;

    conn.execute(
        "INSERT INTO entries (alias, nonce, ciphertext, metadata) VALUES ('api_key', X'000102030405060708090a0b', X'aabbccdd', ?1)",
        [json_metadata],
    )
    .expect("Failed to insert entry with metadata");

    println!("✓ Inserted secret with JSON metadata");

    // Retrieve and verify metadata
    let retrieved_metadata: String = conn
        .query_row(
            "SELECT metadata FROM entries WHERE alias = 'api_key'",
            [],
            |row| row.get(0),
        )
        .expect("Failed to retrieve metadata");

    println!("✓ Retrieved metadata: {}", retrieved_metadata);

    // Parse JSON to verify it's valid
    let parsed: serde_json::Value = serde_json::from_str(&retrieved_metadata)
        .expect("Failed to parse metadata as JSON");

    if parsed["provider"] != "deepseek" || parsed["purpose"] != "prod" {
        println!("❌ FAILED: Metadata values don't match");
        panic!("Metadata test failed");
    }

    println!("✓ JSON metadata parsed successfully");
    println!("  - provider: {}", parsed["provider"]);
    println!("  - purpose: {}", parsed["purpose"]);

    // Test ak list command (should not crash with metadata present)
    let mut cmd = Command::new(cargo_bin("ak"));
    cmd.env("HOME", temp_dir.path())
        .env("AK_TEST_PASSWORD", "test_password_123")
        .arg("list")
        .assert()
        .success();

    println!("✓ ak list command works with metadata present");
    println!("✅ PASSED: Metadata storage and retrieval working");
}
