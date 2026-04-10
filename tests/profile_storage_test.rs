//! Tests for v1.0.2 multi-provider profile storage layer.
//!
//! Covers: `user_profiles`, `user_profile_provider_bindings`, migration from
//! legacy `active_key_config`, `resolve_supported_providers`, and the new
//! entries `supported_providers` column.

use aikeylabs_aikey_cli::storage;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use tempfile::TempDir;

/// Sets up an isolated vault DB via `AK_VAULT_PATH` and returns the temp dir
/// (must be kept alive for the duration of the test).
fn setup_vault() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("vault.db");
    std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap());

    // Trigger schema creation by initialising with a dummy password.
    use rand::RngCore;
    use secrecy::SecretString;
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let pw = SecretString::new("test_password_123".to_string());
    storage::initialize_vault(&salt, &pw).expect("init vault");

    (dir, db_path)
}

/// Open a raw connection for assertions / manual seeding.
fn raw_conn(db_path: &PathBuf) -> Connection {
    Connection::open(db_path).expect("open raw")
}

// ============================================================================
// user_profiles table
// ============================================================================

#[test]
fn default_profile_is_seeded_on_init() {
    let (_dir, db_path) = setup_vault();

    // Trigger open_connection() → apply_migrations() which seeds the profile.
    // list_provider_bindings opens a connection internally.
    let _ = storage::list_provider_bindings("default").unwrap();

    // Now verify via raw connection.
    let conn = raw_conn(&db_path);

    let (id, is_active): (String, i64) = conn
        .query_row(
            "SELECT id, is_active FROM user_profiles WHERE id = 'default'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("default profile should exist");

    assert_eq!(id, "default");
    assert_eq!(is_active, 1);
}

// ============================================================================
// user_profile_provider_bindings CRUD
// ============================================================================

#[test]
fn set_and_get_provider_binding() {
    let (_dir, _db_path) = setup_vault();

    // Set a binding
    storage::set_provider_binding("default", "anthropic", "personal", "my-claude")
        .expect("set binding");

    // Read it back
    let b = storage::get_provider_binding("default", "anthropic")
        .expect("get binding")
        .expect("should exist");

    assert_eq!(b.provider_code, "anthropic");
    assert_eq!(b.key_source_type, "personal");
    assert_eq!(b.key_source_ref, "my-claude");
}

#[test]
fn upsert_provider_binding_overwrites() {
    let (_dir, _db_path) = setup_vault();

    storage::set_provider_binding("default", "openai", "personal", "key-a").unwrap();
    storage::set_provider_binding("default", "openai", "team", "vk_123").unwrap();

    let b = storage::get_provider_binding("default", "openai")
        .unwrap()
        .unwrap();
    assert_eq!(b.key_source_type, "team");
    assert_eq!(b.key_source_ref, "vk_123");
}

#[test]
fn list_provider_bindings_returns_all() {
    let (_dir, _db_path) = setup_vault();

    storage::set_provider_binding("default", "anthropic", "personal", "a").unwrap();
    storage::set_provider_binding("default", "openai", "personal", "b").unwrap();
    storage::set_provider_binding("default", "google", "team", "c").unwrap();

    let list = storage::list_provider_bindings("default").unwrap();
    assert_eq!(list.len(), 3);

    // Ordered by provider_code
    assert_eq!(list[0].provider_code, "anthropic");
    assert_eq!(list[1].provider_code, "google");
    assert_eq!(list[2].provider_code, "openai");
}

#[test]
fn remove_provider_binding_works() {
    let (_dir, _db_path) = setup_vault();

    storage::set_provider_binding("default", "openai", "personal", "a").unwrap();
    assert!(storage::remove_provider_binding("default", "openai").unwrap());
    assert!(storage::get_provider_binding("default", "openai").unwrap().is_none());

    // Removing non-existent returns false
    assert!(!storage::remove_provider_binding("default", "openai").unwrap());
}

#[test]
fn remove_bindings_by_key_source_cleans_all_providers() {
    let (_dir, _db_path) = setup_vault();

    // gateway key bound to two providers
    storage::set_provider_binding("default", "openai", "personal", "gateway-a").unwrap();
    storage::set_provider_binding("default", "anthropic", "personal", "gateway-a").unwrap();
    // another key on google — should not be affected
    storage::set_provider_binding("default", "google", "team", "vk_g").unwrap();

    let affected =
        storage::remove_bindings_by_key_source("default", "personal", "gateway-a").unwrap();
    assert_eq!(affected.len(), 2);
    assert!(affected.contains(&"openai".to_string()));
    assert!(affected.contains(&"anthropic".to_string()));

    // google untouched
    assert!(storage::get_provider_binding("default", "google").unwrap().is_some());
    // openai + anthropic gone
    assert!(storage::get_provider_binding("default", "openai").unwrap().is_none());
    assert!(storage::get_provider_binding("default", "anthropic").unwrap().is_none());
}

// ============================================================================
// entries.supported_providers
// ============================================================================

#[test]
fn set_and_resolve_supported_providers() {
    let (_dir, _db_path) = setup_vault();

    // Store a dummy entry
    storage::store_entry("test-key", &[0u8; 12], &[1u8; 32]).unwrap();

    // Before setting, resolve should return empty (no provider_code either)
    let providers = storage::resolve_supported_providers("test-key").unwrap();
    assert!(providers.is_empty());

    // Set supported_providers
    storage::set_entry_supported_providers(
        "test-key",
        &["openai".to_string(), "anthropic".to_string()],
    )
    .unwrap();

    let providers = storage::resolve_supported_providers("test-key").unwrap();
    assert_eq!(providers, vec!["openai", "anthropic"]);
}

#[test]
fn resolve_falls_back_to_legacy_provider_code() {
    let (_dir, _db_path) = setup_vault();

    storage::store_entry("legacy-key", &[0u8; 12], &[1u8; 32]).unwrap();
    // Set only the legacy single-value column
    storage::set_entry_provider_code("legacy-key", Some("anthropic")).unwrap();

    let providers = storage::resolve_supported_providers("legacy-key").unwrap();
    assert_eq!(providers, vec!["anthropic"]);
}

#[test]
fn resolve_prefers_supported_providers_over_legacy() {
    let (_dir, _db_path) = setup_vault();

    storage::store_entry("both-key", &[0u8; 12], &[1u8; 32]).unwrap();
    storage::set_entry_provider_code("both-key", Some("anthropic")).unwrap();
    storage::set_entry_supported_providers(
        "both-key",
        &["openai".to_string(), "google".to_string()],
    )
    .unwrap();

    let providers = storage::resolve_supported_providers("both-key").unwrap();
    assert_eq!(providers, vec!["openai", "google"]);
}

// ============================================================================
// Migration: active_key_config -> default profile bindings
// ============================================================================

#[test]
fn migration_carries_over_legacy_active_key() {
    // We need to manually set up a legacy active key *before* the migration
    // runs.  Since `initialize_vault` triggers migrations, we'll create a
    // minimal DB, seed the legacy config, then open via the normal path.
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("vault.db");
    std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap());

    {
        // Create a minimal DB with only the config + entries tables
        // (simulates a pre-v1.0.2 vault).
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias TEXT NOT NULL UNIQUE,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                version_tag INTEGER NOT NULL DEFAULT 1,
                metadata TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );",
        )
        .unwrap();

        // Seed legacy active_key_config
        for (k, v) in &[
            ("active_key_type", "personal"),
            ("active_key_ref", "my-claude"),
            ("active_key_providers", r#"["anthropic","openai"]"#),
        ] {
            conn.execute(
                "INSERT INTO config (key, value) VALUES (?1, ?2)",
                params![k, v.as_bytes().to_vec()],
            )
            .unwrap();
        }

        // Seed master password config (required by open_connection pragmas)
        let mut salt = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('master_salt', ?1)",
            params![salt.to_vec()],
        )
        .unwrap();

        // Store a dummy Argon2id hash as password_hash
        let fake_hash = vec![0u8; 32];
        conn.execute(
            "INSERT INTO config (key, value) VALUES ('password_hash', ?1)",
            params![fake_hash],
        )
        .unwrap();
    }

    // Now trigger the migration by opening through the normal storage path.
    // open_connection -> apply_migrations -> migrate_active_key_config_to_default_profile
    let bindings = storage::list_provider_bindings("default").unwrap();

    assert_eq!(bindings.len(), 2);
    let anthropic = bindings.iter().find(|b| b.provider_code == "anthropic").unwrap();
    assert_eq!(anthropic.key_source_type, "personal");
    assert_eq!(anthropic.key_source_ref, "my-claude");

    let openai = bindings.iter().find(|b| b.provider_code == "openai").unwrap();
    assert_eq!(openai.key_source_type, "personal");
    assert_eq!(openai.key_source_ref, "my-claude");
}

#[test]
fn migration_is_idempotent() {
    let (_dir, _db_path) = setup_vault();

    // Set a binding manually
    storage::set_provider_binding("default", "anthropic", "personal", "key-a").unwrap();

    // Calling list again (which opens connection, re-runs migrations) should
    // not duplicate or overwrite anything.
    let bindings = storage::list_provider_bindings("default").unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].key_source_ref, "key-a");
}

#[test]
fn migration_skips_when_no_legacy_active_key() {
    let (_dir, _db_path) = setup_vault();

    // Fresh vault with no legacy active key → no bindings should be created
    let bindings = storage::list_provider_bindings("default").unwrap();
    assert!(bindings.is_empty());
}
