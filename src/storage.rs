//! Storage layer for AiKeyLabs vault
//!
//! Manages SQLite database operations for storing encrypted secrets
//! with proper file permissions and schema initialization.

use rusqlite::{params, Connection, Result as SqlResult};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::storage_acl;

/// Metadata for a secret entry (used for JSON output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    /// Provider code (e.g. "anthropic", "openai"); None for plain secrets.
    /// Legacy single-value field — prefer `supported_providers` for new code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_code: Option<String>,
    /// Custom upstream base URL set by the user; overrides the provider default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Provider codes this key supports (v1.0.2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_providers: Option<Vec<String>>,
    /// Route token (`aikey_personal_<64-hex>`) — stable public id for this entry.
    /// Added 2026-04-23 so the User Vault Web page can render a
    /// secondary id line under each alias without needing a second
    /// per-row query. Old callers ignore the new field via
    /// `skip_serializing_if` + `#[serde(default)]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_token: Option<String>,
    /// Unix seconds of the last recorded usage (bumped by
    /// `_internal vault-op record_usage`). Null until the key has been
    /// used. Added v1.0.6-alpha.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
    /// Monotonic counter of recorded usages. Defaults to 0; old vaults
    /// without the column report None (which the UI treats as 0).
    /// Added v1.0.6-alpha.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_count: Option<i64>,
}

/// Subdirectory under `~/.aikey/` that holds the vault data file.
/// Why split from the `.aikey` literal: the home + `.aikey` portion now
/// resolves through `commands_account::resolve_aikey_dir()` (windows-
/// compatibility.md §B1 single source of truth) so we only join the
/// trailing component here.
const VAULT_DATA_SUBDIR: &str = "data";

/// Database filename
const DB_NAME: &str = "vault.db";

/// Default binding domain
#[allow(dead_code)]
const DEFAULT_BINDING_DOMAIN: &str = "default";

/// Returns the full path to the vault database
pub fn get_vault_path() -> Result<PathBuf, String> {
    if let Ok(test_path) = std::env::var("AK_VAULT_PATH")
        .or_else(|_| std::env::var("AK_STORAGE_PATH")) {
        let path = PathBuf::from(test_path);
        if path.extension().and_then(|e| e.to_str()) == Some("db") {
            return Ok(path);
        } else {
            return Ok(path.join(DB_NAME));
        }
    }

    // Route through the single home-dir source of truth (windows-
    // compatibility.md §B1). HOME-priority preserved so sandbox tests that
    // override `HOME=<tmpdir>` keep working; USERPROFILE fallback covers
    // native Windows where HOME is unset (the breakage that motivated this
    // fix — `aikey proxy start` was failing with "Could not determine home
    // directory" on Windows).
    let vault_dir = crate::commands_account::resolve_aikey_dir().join(VAULT_DATA_SUBDIR);
    Ok(vault_dir.join(DB_NAME))
}

/// Opens a connection to the vault database with security pragmas + idempotent migrations.
/// Used by all write-path commands.
///
/// Routes through the unified migrations registry (D plan PR8): every
/// open auto-applies baseline + every subsequent version. main.rs /
/// executor.rs ALSO call upgrade_all() before dispatch — that's
/// belt-and-braces; the second call is a complete no-op due to
/// idempotency.
pub(crate) fn open_connection() -> Result<Connection, String> {
    let conn = open_connection_raw()?;
    crate::migrations::upgrade_all(&conn)?;
    Ok(conn)
}

/// Opens a read-only connection: security pragmas only, NO migrations.
/// Prefer `with_readonly()` for scoping an entire command as read-only.
pub(crate) fn open_connection_readonly() -> Result<Connection, String> {
    open_connection_raw()
}

/// Shared connection setup: open DB + security pragmas. No migrations.
fn open_connection_raw() -> Result<Connection, String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    // SECURITY: Enable secure delete on every connection
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(|e| format!("Failed to enable secure delete: {}", e))?;

    // WAL mode for better concurrency and crash safety
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| format!("Failed to enable WAL mode: {}", e))?;

    // Enforce foreign key constraints
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| format!("Failed to enable foreign keys: {}", e))?;

    Ok(conn)
}

// D plan PR8 cleanup: the previous apply_migrations / ensure_column /
// migrate_active_key_config_to_default_profile / mark_migration helpers
// were moved to migrations.rs::v1_0_1_baseline. open_connection() now
// routes through migrations::upgrade_all so the registry is the single
// source of truth for vault DDL.

/// Returns true if the given column exists on the given table. Used by a
/// few non-migration code paths below that need to gate behaviour on
/// schema state (e.g. recording route_token assignments on vaults that
/// may or may not have v1.0.4 columns yet during a transient pre-
/// migration window). The migration paths use their own private
/// has_column inside migrations.rs.
fn has_column(conn: &Connection, table: &str, column: &str) -> bool {
    conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name=?1",
            table
        ),
        [column],
        |row| row.get::<_, i64>(0),
    )
    .map(|c| c > 0)
    .unwrap_or(false)
}

/// Resolves effective supported providers for a personal key.
/// Priority: `supported_providers` JSON > single `provider_code` > empty.
pub fn resolve_supported_providers(alias: &str) -> Result<Vec<String>, String> {
    let conn = open_connection()?;
    let row: (Option<String>, Option<String>) = conn.query_row(
        "SELECT supported_providers, provider_code FROM entries WHERE alias = ?1", params![alias], |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => format!("Entry '{}' not found", alias),
        other => format!("query providers '{}': {}", alias, other),
    })?;
    if let Some(json) = row.0 {
        if let Ok(providers) = serde_json::from_str::<Vec<String>>(&json) {
            if !providers.is_empty() { return Ok(providers); }
        }
    }
    if let Some(code) = row.1 { if !code.is_empty() { return Ok(vec![code]); } }
    Ok(vec![])
}

/// Checks if the vault exists, returns an error if it doesn't
pub fn ensure_vault_exists() -> Result<(), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    Ok(())
}

/// Initializes the vault database with proper permissions
pub fn initialize_vault(salt: &[u8], password: &SecretString) -> Result<(), String> {
    let test_path_result = std::env::var("AK_VAULT_PATH")
        .or_else(|_| std::env::var("AK_STORAGE_PATH"));

    let (vault_dir, db_path) = if let Ok(test_path) = test_path_result {
        let path = PathBuf::from(test_path);
        if path.extension().and_then(|e| e.to_str()) == Some("db") {
            // Path is a direct database file path
            let parent = path.parent()
                .ok_or("Invalid database path: no parent directory")?
                .to_path_buf();
            (parent, path)
        } else {
            // Path is a directory
            (path.clone(), path.join(DB_NAME))
        }
    } else {
        // See get_vault_path() — same single-source home resolution.
        let vault_dir = crate::commands_account::resolve_aikey_dir().join(VAULT_DATA_SUBDIR);
        let db_path = vault_dir.join(DB_NAME);
        (vault_dir, db_path)
    };

    if !vault_dir.exists() {
        fs::create_dir_all(&vault_dir)
            .map_err(|e| format!("Failed to create vault directory: {}", e))?;

        // Stage 2.4 windows-compat: cross-platform owner-only ACL.
        // Unix → chmod 0o700 (unchanged); Windows → icacls strips the
        // inherited Authenticated Users grant so files created inside
        // (vault.db below) inherit owner-only.
        storage_acl::enforce_owner_only_dir(&vault_dir)
            .map_err(|e| format!("Failed to set directory permissions: {}", e))?;
    }

    // If the DB file exists, check whether it was fully initialized (has master_salt).
    // The file may exist without salt if session-backend selection created it first.
    if db_path.exists() {
        let probe = Connection::open(&db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        let has_salt: bool = probe
            .query_row(
                "SELECT COUNT(*) FROM config WHERE key = 'master_salt'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) > 0;
        if has_salt {
            return Err("Vault already initialized. If you need a fresh vault, delete the local vault file and run 'aikey init' again.".to_string());
        }
        // DB exists but no salt — fall through to complete initialization
    }

    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to create database: {}", e))?;

    // Stage 2.4 windows-compat: belt-and-suspenders — vault_dir's ACL
    // already inherits owner-only to vault.db on Windows, but we set it
    // explicitly here so even a vault.db that pre-existed (e.g. user
    // manually copied an old vault file in) gets re-hardened.
    storage_acl::enforce_owner_only_file(&db_path)
        .map_err(|e| format!("Failed to set database permissions: {}", e))?;

    // SECURITY: Enable secure delete to overwrite deleted data with zeros
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(|e| format!("Failed to enable secure delete: {}", e))?;

    // SECURITY: Enable auto-vacuum to reclaim space and prevent data remnants
    conn.pragma_update(None, "auto_vacuum", "FULL")
        .map_err(|e| format!("Failed to enable auto-vacuum: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to create config table: {}", e))?;

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
    )
    .map_err(|e| format!("Failed to create entries table: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            is_active INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to create profiles table: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS bindings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_name TEXT NOT NULL,
            domain TEXT NOT NULL DEFAULT 'default',
            alias TEXT NOT NULL,
            FOREIGN KEY (profile_name) REFERENCES profiles(name),
            UNIQUE(profile_name, alias)
        )",
        [],
    )
    .map_err(|e| format!("Failed to create bindings table: {}", e))?;

    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["master_salt", salt],
    )
    .map_err(|e| format!("Failed to store salt: {}", e))?;

    // Store KDF parameters for future use (e.g., password changes)
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["kdf_m_cost", &crate::crypto::ARGON2_M_COST.to_le_bytes()],
    )
    .map_err(|e| format!("Failed to store KDF m_cost: {}", e))?;

    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["kdf_t_cost", &crate::crypto::ARGON2_T_COST.to_le_bytes()],
    )
    .map_err(|e| format!("Failed to store KDF t_cost: {}", e))?;

    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["kdf_p_cost", &crate::crypto::ARGON2_P_COST.to_le_bytes()],
    )
    .map_err(|e| format!("Failed to store KDF p_cost: {}", e))?;

    // Derive key directly from password parameter instead of environment variable
    let key = crate::crypto::derive_key(password, salt)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    // Use &*key to dereference SecureBuffer and get &[u8; 32]
    let password_hash = &*key;

    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["password_hash", password_hash],
    )
    .map_err(|e| format!("Failed to store password hash: {}", e))?;

    Ok(())
}

/// Checks if the database needs migration
pub fn needs_migration() -> Result<bool, String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Ok(false);
    }

    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='entries'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false);

    if !table_exists {
        return Ok(false);
    }

    let has_id: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='id'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false);

    Ok(!has_id)
}

/// Migrates the database schema
fn migrate_database(conn: &Connection) -> Result<(), String> {
    let has_id: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='id'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false);

    if !has_id {
        conn.execute(
            "CREATE TABLE entries_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias TEXT NOT NULL UNIQUE,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                version_tag INTEGER NOT NULL DEFAULT 1,
                metadata TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )
        .map_err(|e| format!("Failed to create new entries table: {}", e))?;

        conn.execute(
            "INSERT INTO entries_new (alias, nonce, ciphertext, version_tag, created_at)
            SELECT alias, nonce, ciphertext, 1, strftime('%s', 'now')
            FROM entries",
            [],
        )
        .map_err(|e| format!("Failed to migrate data: {}", e))?;

        conn.execute("DROP TABLE entries", [])
            .map_err(|e| format!("Failed to drop old table: {}", e))?;

        conn.execute("ALTER TABLE entries_new RENAME TO entries", [])
            .map_err(|e| format!("Failed to rename table: {}", e))?;

        return Ok(());
    }

    let has_version_tag: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='version_tag'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false);

    if !has_version_tag {
        conn.execute(
            "ALTER TABLE entries ADD COLUMN version_tag INTEGER NOT NULL DEFAULT 1",
            [],
        )
        .map_err(|e| format!("Failed to add version_tag column: {}", e))?;
    }

    let has_metadata: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='metadata'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false);

    if !has_metadata {
        conn.execute(
            "ALTER TABLE entries ADD COLUMN metadata TEXT",
            [],
        )
        .map_err(|e| format!("Failed to add metadata column: {}", e))?;
    }

    let has_created_at: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='created_at'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false);

    if !has_created_at {
        conn.execute(
            "ALTER TABLE entries ADD COLUMN created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))",
            [],
        )
        .map_err(|e| format!("Failed to add created_at column: {}", e))?;
    }

    // Ensure audit_log table exists (for migration from pre-audit versions)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            operation TEXT NOT NULL,
            alias TEXT,
            success INTEGER NOT NULL,
            hmac TEXT NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to create audit_log table: {}", e))?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
        [],
    )
    .map_err(|e| format!("Failed to create audit index: {}", e))?;

    Ok(())
}

/// Retrieves the salt from the vault
pub fn get_salt() -> Result<Vec<u8>, String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    // Try new key name first, then fall back to old key name for migration
    let salt: Vec<u8> = conn
        .query_row(
            "SELECT value FROM config WHERE key = ?",
            params!["master_salt"],
            |row| row.get(0),
        )
        .or_else(|_| {
            // Fall back to old key name 'salt' for backward compatibility
            conn.query_row(
                "SELECT value FROM config WHERE key = ?",
                params!["salt"],
                |row| row.get(0),
            )
        })
        .map_err(|_| "Salt not found in vault. Vault may be corrupted.".to_string())?;

    Ok(salt)
}

/// Retrieves KDF parameters from the vault
pub fn get_kdf_params() -> Result<(u32, u32, u32), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    // Try to get stored KDF parameters, fall back to defaults if not found
    let m_cost: u32 = conn
        .query_row(
            "SELECT value FROM config WHERE key = ?",
            params!["kdf_m_cost"],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(0, "kdf_m_cost".to_string(), rusqlite::types::Type::Blob)
                })?))
            },
        )
        .unwrap_or(crate::crypto::ARGON2_M_COST);

    let t_cost: u32 = conn
        .query_row(
            "SELECT value FROM config WHERE key = ?",
            params!["kdf_t_cost"],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(0, "kdf_t_cost".to_string(), rusqlite::types::Type::Blob)
                })?))
            },
        )
        .unwrap_or(crate::crypto::ARGON2_T_COST);

    let p_cost: u32 = conn
        .query_row(
            "SELECT value FROM config WHERE key = ?",
            params!["kdf_p_cost"],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(0, "kdf_p_cost".to_string(), rusqlite::types::Type::Blob)
                })?))
            },
        )
        .unwrap_or(crate::crypto::ARGON2_P_COST);

    Ok((m_cost, t_cost, p_cost))
}

/// Verifies that a 32-byte derived `vault_key` matches the vault's stored
/// `password_hash` config row. Returns `Ok(())` on match, `Err` on mismatch
/// or on any vault state that cannot authoritatively confirm the key.
///
/// Why this exists: any code path that derives `vault_key` from a password
/// (or accepts one over a bridge) and then proceeds to `crypto::encrypt`
/// into a vault table MUST first call this. Without it, an unverified
/// `vault_key` silently encrypts ciphertext that no later reader can ever
/// decrypt — observed as the 2026-05-11 team-key registry-miss incident,
/// where `managed_virtual_keys_cache.provider_key_ciphertext` was written
/// with a key that did not match the current `password_hash`, and the
/// downstream proxy responded 401 "Route token not found in registry".
///
/// Strict-match semantics (no silent-accept fallback): this function
/// requires `password_hash` to exist and equal the supplied key. The
/// matching legacy "no hash + decrypt-an-entry-to-recover" fallback used
/// by `executor::verify_password_internal` is intentionally NOT replicated
/// here — write-path callers must fail loud on uncertainty, never silently
/// proceed to encrypt.
pub fn verify_vault_key(vault_key: &[u8]) -> Result<(), String> {
    if vault_key.len() != crate::crypto::KEY_SIZE {
        return Err(format!(
            "vault_key length mismatch (got {} bytes, expected {})",
            vault_key.len(),
            crate::crypto::KEY_SIZE
        ));
    }
    let conn = open_connection()?;
    let stored: Result<Vec<u8>, rusqlite::Error> = conn.query_row(
        "SELECT value FROM config WHERE key = ?1",
        params!["password_hash"],
        |row| row.get(0),
    );
    match stored {
        Ok(hash) => {
            if hash.as_slice() == vault_key {
                Ok(())
            } else {
                Err("vault_key does not match stored password_hash \
                     (write-path verify; refusing to encrypt with an unverified key)"
                    .to_string())
            }
        }
        Err(_) => Err(
            "vault password_hash missing — cannot verify write-path vault_key. \
             Run `aikey init` or restore the vault before any encrypt operation."
                .to_string(),
        ),
    }
}

/// Stores an encrypted entry in the vault
pub fn store_entry(alias: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<(), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    migrate_database(&conn)?;

    store_entry_on_conn(&conn, alias, nonce, ciphertext)
}

/// G-5 fix (2026-04-23): transactional variant of `store_entry`. Callers that
/// need to group multiple entry writes atomically (e.g. batch_import) open
/// their own `Connection` / `Transaction` and drive all writes through these
/// `*_on_conn` helpers so rollback can undo every side-effect on failure.
///
/// The plain `store_entry` wrapper above is kept for all single-write
/// callsites (which remain self-contained, one execute per command).
///
/// Migrations and vault-existence checks live with the wrapper; the inner
/// helper assumes the connection is already initialised (open_connection
/// applies migrations).
pub(crate) fn store_entry_on_conn(
    conn: &rusqlite::Connection,
    alias: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO entries (alias, nonce, ciphertext, version_tag) VALUES (?1, ?2, ?3, 1)
        ON CONFLICT(alias) DO UPDATE SET nonce = ?2, ciphertext = ?3, version_tag = version_tag + 1",
        params![alias, nonce, ciphertext],
    )
    .map_err(|e| format!("Failed to store entry: {}", e))?;
    Ok(())
}

/// Retrieves an encrypted entry from the vault
pub fn get_entry(alias: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    conn.query_row(
        "SELECT nonce, ciphertext FROM entries WHERE alias = ?1",
        [alias],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            format!("Entry '{}' not found", alias)
        }
        _ => format!("Failed to retrieve entry: {}", e),
    })
}

/// Lists all entry aliases in the vault
pub fn list_entries() -> Result<Vec<String>, String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    let mut stmt = conn
        .prepare("SELECT alias FROM entries ORDER BY alias")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let aliases = stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| format!("Failed to query entries: {}", e))?
        .collect::<SqlResult<Vec<String>>>()
        .map_err(|e| format!("Failed to collect results: {}", e))?;

    Ok(aliases)
}

/// List all entries with metadata (uses write connection with migrations).
pub fn list_entries_with_metadata() -> Result<Vec<SecretMetadata>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }
    query_entries_with_metadata(&open_connection()?)
}

/// List all entries with metadata (read-only, no migrations).
pub fn list_entries_with_metadata_readonly() -> Result<Vec<SecretMetadata>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(vec![]);
    }
    query_entries_with_metadata(&open_connection_readonly()?)
}

fn query_entries_with_metadata(conn: &Connection) -> Result<Vec<SecretMetadata>, String> {
    // provider_code, base_url, supported_providers may not exist on older vaults.
    // route_token (v1.0.4+) and last_used_at/use_count (v1.0.6+) are selected
    // in the preferred path; older DDL fallbacks project NULL / 0 so the
    // parse path stays uniform regardless of vault age.
    let mut stmt = conn
        .prepare("SELECT alias, created_at, provider_code, base_url, supported_providers, route_token, last_used_at, use_count FROM entries ORDER BY alias")
        .or_else(|_| conn.prepare("SELECT alias, created_at, provider_code, base_url, supported_providers, route_token, NULL, 0 FROM entries ORDER BY alias"))
        .or_else(|_| conn.prepare("SELECT alias, created_at, provider_code, base_url, supported_providers, NULL, NULL, 0 FROM entries ORDER BY alias"))
        .or_else(|_| conn.prepare("SELECT alias, created_at, provider_code, base_url, NULL, NULL, NULL, 0 FROM entries ORDER BY alias"))
        .or_else(|_| conn.prepare("SELECT alias, created_at, NULL, NULL, NULL, NULL, NULL, 0 FROM entries ORDER BY alias"))
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let metadata: Vec<SecretMetadata> = stmt
        .query_map([], |row| {
            let sp_json: Option<String> = row.get(4).ok().flatten();
            let supported_providers = sp_json
                .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok());
            Ok(SecretMetadata {
                alias:               row.get(0)?,
                created_at:          row.get(1).ok(),
                provider_code:       row.get(2).ok().flatten(),
                base_url:            row.get(3).ok().flatten(),
                supported_providers,
                route_token:         row.get(5).ok().flatten(),
                last_used_at:        row.get(6).ok().flatten(),
                use_count:           row.get(7).ok(),
            })
        })
        .map_err(|e| format!("Failed to query entries: {}", e))?
        .collect::<SqlResult<Vec<SecretMetadata>>>()
        .map_err(|e| format!("Failed to collect results: {}", e))?;

    Ok(metadata)
}

/// Atomically bump usage telemetry on a Personal entry: set `last_used_at`
/// to the caller-supplied unix seconds, increment `use_count`. Returns
/// the row-count affected — 0 if the alias doesn't exist (caller surfaces
/// I_CREDENTIAL_NOT_FOUND), 1 on success. Idempotent with respect to
/// repeated invocations (each call is a distinct recorded usage).
///
/// `last_used_at` is accepted as a parameter so the caller (CLI
/// `record_usage` action, which is in turn called from proxy) can pin
/// timestamps to the request time, not the db write time.
pub fn bump_entry_usage(alias: &str, ts: i64) -> Result<usize, String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE entries SET last_used_at = ?1, use_count = COALESCE(use_count, 0) + 1 WHERE alias = ?2",
        rusqlite::params![ts, alias],
    )
    .map_err(|e| format!("bump_entry_usage UPDATE: {}", e))
}

/// Deletes an entry from the vault
pub fn delete_entry(alias: &str) -> Result<(), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    let rows_affected = conn
        .execute("DELETE FROM entries WHERE alias = ?1", [alias])
        .map_err(|e| format!("Failed to delete entry: {}", e))?;

    if rows_affected == 0 {
        return Err(format!("Entry '{}' not found", alias));
    }

    Ok(())
}

/// Changes the master password by re-encrypting all entries
pub fn change_password(old_password: &SecretString, new_password: &SecretString) -> Result<(), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    // Why: short-circuit when new == old. Running the full flow would still
    // generate a new salt and re-encrypt every entry without changing what the
    // user remembers — pure I/O for no security benefit — and any bug in the
    // post-write verification path would brick the vault for no reason.
    if old_password.expose_secret() == new_password.expose_secret() {
        return Err("New password must differ from the current password.".to_string());
    }

    // Get salt and KDF parameters
    let salt = get_salt()?;
    let (m_cost, t_cost, p_cost) = get_kdf_params()?;

    // Derive old key to verify password
    let old_key = crate::crypto::derive_key_with_params(old_password, &salt, m_cost, t_cost, p_cost)
        .map_err(|e| format!("Failed to derive old key: {}", e))?;

    // Verify old password against the stored password_hash first (authoritative
    // source). Fall back to entry decryption for legacy vaults that predate
    // password_hash being written.
    let conn = open_connection()?;
    let stored_hash: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM config WHERE key = ?",
            params!["password_hash"],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok();

    match stored_hash {
        Some(hash) => {
            if old_key.as_slice() != hash.as_slice() {
                return Err("Incorrect password".to_string());
            }
        }
        None => {
            // Legacy vault: verify by decrypting the first entry (same fallback
            // as executor::verify_password_internal).
            let test_result: Result<(Vec<u8>, Vec<u8>), rusqlite::Error> = conn.query_row(
                "SELECT nonce, ciphertext FROM entries LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            );
            if let Ok((nonce, ciphertext)) = test_result {
                crate::crypto::decrypt(&old_key, &nonce, &ciphertext)
                    .map_err(|_| "Incorrect password".to_string())?;
            }
        }
    }

    // Generate new salt for new password
    let mut new_salt = [0u8; 16];
    crate::crypto::generate_salt(&mut new_salt)
        .map_err(|e| format!("Failed to generate salt: {}", e))?;

    // Derive new key with default parameters (which will be stored in DB)
    let new_key = crate::crypto::derive_key_with_params(
        new_password,
        &new_salt,
        crate::crypto::ARGON2_M_COST,
        crate::crypto::ARGON2_T_COST,
        crate::crypto::ARGON2_P_COST,
    )
    .map_err(|e| format!("Failed to derive new key: {}", e))?;

    // Why wrap everything below in a transaction: re-encrypting entries,
    // rotating the salt, and updating password_hash must be atomic. A crash
    // between steps previously bricked the vault (entries used new_key while
    // password_hash still matched the old key — no password could unlock it).
    let mut conn = conn;
    let tx = conn
        .transaction()
        .map_err(|e| format!("Failed to begin transaction: {}", e))?;

    // Get all entries
    let entries: Vec<(i64, String, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx
            .prepare("SELECT id, alias, nonce, ciphertext FROM entries")
            .map_err(|e| format!("Failed to prepare statement: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|e| format!("Failed to query entries: {}", e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to collect entries: {}", e))?;
        rows
    };

    // Re-encrypt all entries with new key
    for (id, alias, old_nonce, old_ciphertext) in entries {
        // Decrypt with old key
        let plaintext = crate::crypto::decrypt(&old_key, &old_nonce, &old_ciphertext)
            .map_err(|e| format!("Failed to decrypt entry '{}': {}", alias, e))?;

        // Encrypt with new key
        let (new_nonce, new_ciphertext) = crate::crypto::encrypt(&new_key, &plaintext)
            .map_err(|e| format!("Failed to encrypt entry '{}': {}", alias, e))?;

        // Update entry in database
        tx.execute(
            "UPDATE entries SET nonce = ?, ciphertext = ? WHERE id = ?",
            params![new_nonce, new_ciphertext, id],
        )
        .map_err(|e| format!("Failed to update entry '{}': {}", alias, e))?;
    }

    // ── Re-encrypt managed_virtual_keys_cache.provider_key_{nonce,ciphertext} ──
    //
    // Why this loop was added (2026-05-11 bugfix): the previous implementation
    // only re-encrypted the `entries` table. After change-password, team-key
    // ciphertext kept its old-key encryption while the rest of the vault
    // (salt, password_hash, entries) rotated — proxy then logged
    // "decrypt: invalid key or corrupted data" for every team key and dropped
    // it from the registry, surfacing as 401 "Route token not found in
    // registry" on the very next claude / codex / kimi launch.
    //
    // Refusal policy on row-level decrypt failure: per CLAUDE.md "失败要显眼，
    // 不要沉默" we abort the entire change-password (transaction rollback) and
    // hand the user the precise recovery path. The alternative — skipping the
    // bad row — would have us emit a new wrong-key ciphertext under the new
    // master and permanently lock that vk_id out, exactly the silent failure
    // we are trying to surface.
    let mvk_rows: Vec<(String, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx
            .prepare(
                "SELECT virtual_key_id, provider_key_nonce, provider_key_ciphertext
                 FROM managed_virtual_keys_cache
                 WHERE provider_key_nonce IS NOT NULL
                   AND provider_key_ciphertext IS NOT NULL",
            )
            .map_err(|e| format!("Failed to prepare managed_virtual_keys_cache select: {}", e))?;
        let mapped = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
            })
            .map_err(|e| format!("Failed to query managed_virtual_keys_cache: {}", e))?;
        let collected: Result<Vec<_>, _> = mapped.collect();
        collected.map_err(|e| format!("Failed to collect managed_virtual_keys_cache rows: {}", e))?
    };
    for (vk_id, old_nonce, old_ciphertext) in mvk_rows {
        let plaintext = crate::crypto::decrypt(&old_key, &old_nonce, &old_ciphertext)
            .map_err(|e| format!(
                "Failed to decrypt team key '{vk}' during password change: {err}. \
                 This row's ciphertext was written with a different vault_key than \
                 the current password_hash — change-password cannot rotate it. \
                 Recover by running `aikey key sync --force-reencrypt` first \
                 (clears stale ciphertext + re-downloads under the current key), \
                 then retry `aikey change-password`.",
                vk = vk_id, err = e))?;
        let (new_nonce, new_ciphertext) = crate::crypto::encrypt(&new_key, &plaintext)
            .map_err(|e| format!("Failed to re-encrypt team key '{}': {}", vk_id, e))?;
        tx.execute(
            "UPDATE managed_virtual_keys_cache
                SET provider_key_nonce = ?, provider_key_ciphertext = ?
              WHERE virtual_key_id = ?",
            params![new_nonce, new_ciphertext, vk_id],
        )
        .map_err(|e| format!("Failed to update team key '{}': {}", vk_id, e))?;
    }

    // ── Re-encrypt provider_account_tokens (OAuth access + refresh tokens) ──
    //
    // Same rationale as managed_virtual_keys_cache: if change-password didn't
    // rotate these, every OAuth account would silently lose access on the next
    // refresh-cycle and force the user through `aikey auth login` again. The
    // access_token/refresh_token pairs are independently nullable, so we
    // re-encrypt each non-null pair in place.
    let oauth_rows: Vec<(String, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> = {
        let mut stmt = tx
            .prepare(
                "SELECT provider_account_id,
                        access_token_nonce, access_token_ciphertext,
                        refresh_token_nonce, refresh_token_ciphertext
                 FROM provider_account_tokens",
            )
            .map_err(|e| format!("Failed to prepare provider_account_tokens select: {}", e))?;
        let mapped = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })
            .map_err(|e| format!("Failed to query provider_account_tokens: {}", e))?;
        let collected: Result<Vec<_>, _> = mapped.collect();
        collected.map_err(|e| format!("Failed to collect provider_account_tokens rows: {}", e))?
    };
    for (account_id, at_nonce, at_ct, rt_nonce, rt_ct) in oauth_rows {
        // Skip rows whose tokens are null on both sides — they hold metadata
        // only, no ciphertext to rotate. Matches the legacy schema where a
        // pending OAuth handshake row may exist before either token lands.
        let has_access = at_nonce.is_some() && at_ct.is_some();
        let has_refresh = rt_nonce.is_some() && rt_ct.is_some();
        if !has_access && !has_refresh {
            continue;
        }

        let (new_at_nonce, new_at_ct) = if has_access {
            let pt = crate::crypto::decrypt(&old_key, &at_nonce.unwrap(), &at_ct.unwrap())
                .map_err(|e| format!(
                    "Failed to decrypt OAuth access_token for account '{acc}': {err}. \
                     This token was encrypted with a vault_key that doesn't match \
                     the current password_hash. Run `aikey auth login <provider>` to \
                     re-issue, then retry change-password.",
                    acc = account_id, err = e))?;
            let (n, c) = crate::crypto::encrypt(&new_key, &pt)
                .map_err(|e| format!("Failed to re-encrypt OAuth access_token for '{}': {}", account_id, e))?;
            (Some(n), Some(c))
        } else {
            (None, None)
        };

        let (new_rt_nonce, new_rt_ct) = if has_refresh {
            let pt = crate::crypto::decrypt(&old_key, &rt_nonce.unwrap(), &rt_ct.unwrap())
                .map_err(|e| format!(
                    "Failed to decrypt OAuth refresh_token for account '{acc}': {err}. \
                     This token was encrypted with a vault_key that doesn't match \
                     the current password_hash. Run `aikey auth login <provider>` to \
                     re-issue, then retry change-password.",
                    acc = account_id, err = e))?;
            let (n, c) = crate::crypto::encrypt(&new_key, &pt)
                .map_err(|e| format!("Failed to re-encrypt OAuth refresh_token for '{}': {}", account_id, e))?;
            (Some(n), Some(c))
        } else {
            (None, None)
        };

        tx.execute(
            "UPDATE provider_account_tokens
                SET access_token_nonce = ?, access_token_ciphertext = ?,
                    refresh_token_nonce = ?, refresh_token_ciphertext = ?
              WHERE provider_account_id = ?",
            params![new_at_nonce, new_at_ct, new_rt_nonce, new_rt_ct, account_id],
        )
        .map_err(|e| format!("Failed to update OAuth tokens for '{}': {}", account_id, e))?;
    }

    // Update salt in config
    tx.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["master_salt", &new_salt[..]],
    )
    .map_err(|e| format!("Failed to update salt: {}", e))?;

    // Update KDF parameters to default values (stored as binary)
    tx.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["kdf_m_cost", &crate::crypto::ARGON2_M_COST.to_le_bytes()[..]],
    )
    .map_err(|e| format!("Failed to update m_cost: {}", e))?;

    tx.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["kdf_t_cost", &crate::crypto::ARGON2_T_COST.to_le_bytes()[..]],
    )
    .map_err(|e| format!("Failed to update t_cost: {}", e))?;

    tx.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["kdf_p_cost", &crate::crypto::ARGON2_P_COST.to_le_bytes()[..]],
    )
    .map_err(|e| format!("Failed to update p_cost: {}", e))?;

    // Why: password_hash is the authoritative check in executor::verify_password_internal
    // and in aikey-proxy's vault.go. Before this fix it was left at the old-key
    // value, so after a password change neither the new nor old password could
    // unlock the vault — a silent brick. Writing the new hash here closes that.
    tx.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params!["password_hash", &*new_key],
    )
    .map_err(|e| format!("Failed to update password_hash: {}", e))?;

    tx.commit()
        .map_err(|e| format!("Failed to commit password change: {}", e))?;

    Ok(())
}

/// Retrieves entries with full metadata matching a glob pattern
pub fn get_entries_with_metadata(
    pattern: &str,
) -> Result<Vec<(String, Vec<u8>, Vec<u8>, i64, i64, i64, Option<String>)>, String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    let sql_pattern = pattern.replace('*', "%").replace('?', "_");

    let mut stmt = conn
        .prepare(
            "SELECT alias, nonce, ciphertext, version_tag, created_at, created_at as updated_at, metadata
            FROM entries
            WHERE alias LIKE ?1
            ORDER BY alias",
        )
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let entries = stmt
        .query_map([&sql_pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })
        .map_err(|e| format!("Failed to query entries: {}", e))?
        .collect::<SqlResult<Vec<_>>>()
        .map_err(|e| format!("Failed to collect results: {}", e))?;

    Ok(entries)
}

/// Retrieves a single entry with full metadata
pub fn get_entry_with_metadata(
    alias: &str,
) -> Result<(Vec<u8>, Vec<u8>, i64, i64, i64, Option<String>), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    conn.query_row(
        "SELECT nonce, ciphertext, version_tag, created_at, created_at as updated_at, metadata
        FROM entries
        WHERE alias = ?1",
        [alias],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            format!("Entry '{}' not found", alias)
        }
        _ => format!("Failed to retrieve entry: {}", e),
    })
}

/// Updates an entry with full metadata (for import)
pub fn update_entry_full(
    alias: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    version_tag: i64,
    _updated_at: i64,
    created_at: i64,
    metadata: Option<&str>,
) -> Result<(), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    conn.execute(
        "UPDATE entries
        SET nonce = ?2, ciphertext = ?3, version_tag = ?4, created_at = ?5, metadata = ?6
        WHERE alias = ?1",
        params![alias, nonce, ciphertext, version_tag, created_at, metadata],
    )
    .map_err(|e| format!("Failed to update entry: {}", e))?;

    Ok(())
}

/// Inserts a new entry with full metadata (for import)
pub fn insert_entry_full(
    alias: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    version_tag: i64,
    _updated_at: i64,
    created_at: i64,
    metadata: Option<&str>,
) -> Result<(), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    migrate_database(&conn)?;

    conn.execute(
        "INSERT INTO entries (alias, nonce, ciphertext, version_tag, created_at, metadata)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![alias, nonce, ciphertext, version_tag, created_at, metadata],
    )
    .map_err(|e| format!("Failed to insert entry: {}", e))?;

    Ok(())
}

/// Checks if an entry exists in the vault
pub fn entry_exists(alias: &str) -> Result<bool, String> {
    let conn = open_connection()?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM entries WHERE alias = ?1",
            [alias],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(count > 0)
}

/// Retrieves all encrypted entries from the vault
pub fn get_all_entries() -> Result<Vec<(String, Vec<u8>, Vec<u8>)>, String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    let mut stmt = conn
        .prepare("SELECT alias, nonce, ciphertext FROM entries ORDER BY alias")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let entries = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|e| format!("Failed to query entries: {}", e))?
        .collect::<SqlResult<Vec<(String, Vec<u8>, Vec<u8>)>>>()
        .map_err(|e| format!("Failed to collect results: {}", e))?;

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Runtime vault/proxy change-sequence tracking
// ---------------------------------------------------------------------------
// These two keys in the config table allow the CLI to detect when a running
// proxy is serving requests with a stale vault snapshot:
//   runtime.vault.change_seq          — incremented on every vault write that
//                                       can affect proxy key resolution
//   runtime.proxy.loaded_vault_change_seq — written by the CLI after proxy
//                                       starts or completes a graceful reload

const VAULT_CHANGE_SEQ_KEY: &str = "runtime.vault.change_seq";
const PROXY_LOADED_SEQ_KEY: &str = "runtime.proxy.loaded_vault_change_seq";

/// Read a u64 stored as an 8-byte little-endian BLOB from the config table.
/// Returns 0 if the key does not exist or the vault has not been initialised.
fn read_u64_config(key: &str) -> Result<u64, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(0);
    }
    let conn = open_connection()?;
    let result: rusqlite::Result<Vec<u8>> = conn.query_row(
        "SELECT value FROM config WHERE key = ?",
        params![key],
        |row| row.get(0),
    );
    match result {
        Ok(bytes) => {
            let arr: [u8; 8] = bytes
                .try_into()
                .map_err(|_| format!("corrupt config value for '{}'", key))?;
            Ok(u64::from_le_bytes(arr))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(e) => Err(format!("failed to read '{}': {}", key, e)),
    }
}

/// Write a u64 as an 8-byte little-endian BLOB into the config table.
fn write_u64_config(key: &str, value: u64) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params![key, value.to_le_bytes().to_vec()],
    )
    .map_err(|e| format!("failed to write '{}': {}", key, e))?;
    Ok(())
}

/// Returns the current vault change sequence number (0 if vault not yet created).
pub fn get_vault_change_seq() -> Result<u64, String> {
    read_u64_config(VAULT_CHANGE_SEQ_KEY)
}

/// Increments `runtime.vault.change_seq` by 1.
/// Called after any vault write that can affect which keys the proxy resolves.
/// Failures are non-fatal — callers should use `let _ = ...`.
pub fn bump_vault_change_seq() -> Result<(), String> {
    let current = read_u64_config(VAULT_CHANGE_SEQ_KEY)?;
    write_u64_config(VAULT_CHANGE_SEQ_KEY, current.saturating_add(1))
}

/// Returns the vault change_seq that was snapshotted when the proxy last
/// started or completed a graceful reload (0 if never recorded).
pub fn get_proxy_loaded_seq() -> Result<u64, String> {
    read_u64_config(PROXY_LOADED_SEQ_KEY)
}

/// Persists the vault change_seq that the proxy has just loaded.
/// Called by the CLI immediately after confirming proxy start / graceful reload.
pub fn set_proxy_loaded_seq(seq: u64) -> Result<(), String> {
    write_u64_config(PROXY_LOADED_SEQ_KEY, seq)
}

// ---------------------------------------------------------------------------
// Route token generation and backfill
// ---------------------------------------------------------------------------

/// Generates a random route token: "aikey_personal_" + 64 lowercase hex chars
/// (256 bits). Used as the API_KEY identifier for static per-key proxy routing
/// (third-party clients via `aikey route`, current shell pin via `aikey activate`).
///
/// The output is always lowercase hex (Rust `hex::encode` default) — the proxy's
/// `isTier1Personal` form check rejects uppercase, so this is a hard contract.
///
/// Spec: roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §4
pub fn generate_route_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("aikey_personal_{}", hex::encode(bytes))
}

/// Sets the route_token for a personal key entry.
pub fn set_entry_route_token(alias: &str, token: &str) -> Result<(), String> {
    let conn = open_connection()?;
    let rows = conn
        .execute(
            "UPDATE entries SET route_token = ?1 WHERE alias = ?2",
            params![token, alias],
        )
        .map_err(|e| format!("Failed to set route_token for '{}': {}", alias, e))?;
    if rows == 0 {
        return Err(format!("Entry '{}' not found", alias));
    }
    Ok(())
}

/// Gets the route_token for a personal key entry (write connection with migrations).
pub fn get_entry_route_token(alias: &str) -> Result<Option<String>, String> {
    query_entry_route_token(&open_connection()?, alias)
}

/// Gets the route_token for a personal key entry (read-only, no migrations).
/// Returns Ok(None) if the column doesn't exist (old vault).
pub fn get_entry_route_token_readonly(alias: &str) -> Result<Option<String>, String> {
    query_entry_route_token(&open_connection_readonly()?, alias)
}

fn query_entry_route_token(conn: &Connection, alias: &str) -> Result<Option<String>, String> {
    if !has_column(conn, "entries", "route_token") {
        return Ok(None);
    }
    match conn.query_row(
        "SELECT route_token FROM entries WHERE alias = ?1",
        params![alias],
        |row| row.get::<_, Option<String>>(0),
    ) {
        Ok(token) => Ok(token),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get route_token for '{}': {}", alias, e)),
    }
}

/// Ensures a personal key entry has a route_token. Generates one if missing.
/// Returns the route_token (existing or newly generated).
pub fn ensure_entry_route_token(alias: &str) -> Result<String, String> {
    if let Some(token) = get_entry_route_token(alias)? {
        return Ok(token);
    }
    let token = generate_route_token();
    set_entry_route_token(alias, &token)?;
    Ok(token)
}

/// Sets the route_token for a provider (OAuth) account.
pub fn set_provider_account_route_token(account_id: &str, token: &str) -> Result<(), String> {
    let conn = open_connection()?;
    let rows = conn
        .execute(
            "UPDATE provider_accounts SET route_token = ?1 WHERE provider_account_id = ?2",
            params![token, account_id],
        )
        .map_err(|e| format!("Failed to set route_token for account '{}': {}", account_id, e))?;
    if rows == 0 {
        return Err(format!("Provider account '{}' not found", account_id));
    }
    Ok(())
}

/// Gets the route_token for a provider (OAuth) account (write connection with migrations).
pub fn get_provider_account_route_token(account_id: &str) -> Result<Option<String>, String> {
    query_provider_account_route_token(&open_connection()?, account_id)
}

/// Gets the route_token for a provider (OAuth) account (read-only, no migrations).
pub fn get_provider_account_route_token_readonly(account_id: &str) -> Result<Option<String>, String> {
    query_provider_account_route_token(&open_connection_readonly()?, account_id)
}

fn query_provider_account_route_token(conn: &Connection, account_id: &str) -> Result<Option<String>, String> {
    if !has_column(conn, "provider_accounts", "route_token") {
        return Ok(None);
    }
    match conn.query_row(
        "SELECT route_token FROM provider_accounts WHERE provider_account_id = ?1",
        params![account_id],
        |row| row.get::<_, Option<String>>(0),
    ) {
        Ok(token) => Ok(token),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get route_token for account '{}': {}", account_id, e)),
    }
}

/// Ensures a provider account has a route_token. Generates one if missing.
pub fn ensure_provider_account_route_token(account_id: &str) -> Result<String, String> {
    if let Some(token) = get_provider_account_route_token(account_id)? {
        return Ok(token);
    }
    let token = generate_route_token();
    set_provider_account_route_token(account_id, &token)?;
    Ok(token)
}

/// One-time backfill: generate route_tokens for all entries and provider_accounts
/// that are missing one. Called from ensure_schema() in write-path CLI commands.
/// Returns the number of tokens generated (0 if nothing to do).
///
/// Why transaction: many small UPDATEs wrapped in one transaction avoid per-statement
/// fsync overhead AND guarantee all-or-nothing semantics if the process is killed mid-loop.
pub fn backfill_route_tokens() -> Result<usize, String> {
    let mut conn = open_connection()?;
    let has_entries_col = has_column(&conn, "entries", "route_token");
    let has_accounts_col = has_column(&conn, "provider_accounts", "route_token");
    if !has_entries_col && !has_accounts_col {
        return Ok(0);
    }

    let tx = conn
        .transaction()
        .map_err(|e| format!("backfill begin transaction: {}", e))?;
    let mut count = 0;

    if has_entries_col {
        let aliases: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT alias FROM entries WHERE route_token IS NULL")
                .map_err(|e| format!("backfill query entries: {}", e))?;
            let rows: Vec<String> = stmt.query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| format!("backfill iter entries: {}", e))?
                .filter_map(|r| r.ok())
                .collect();
            rows
        };
        for alias in &aliases {
            let token = generate_route_token();
            tx.execute(
                "UPDATE entries SET route_token = ?1 WHERE alias = ?2 AND route_token IS NULL",
                params![token, alias],
            )
            .map_err(|e| format!("backfill set entries.route_token '{}': {}", alias, e))?;
            count += 1;
        }
    }

    if has_accounts_col {
        let ids: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT provider_account_id FROM provider_accounts WHERE route_token IS NULL")
                .map_err(|e| format!("backfill query provider_accounts: {}", e))?;
            let rows: Vec<String> = stmt.query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| format!("backfill iter provider_accounts: {}", e))?
                .filter_map(|r| r.ok())
                .collect();
            rows
        };
        for id in &ids {
            let token = generate_route_token();
            tx.execute(
                "UPDATE provider_accounts SET route_token = ?1 WHERE provider_account_id = ?2 AND route_token IS NULL",
                params![token, id],
            )
            .map_err(|e| format!("backfill set provider_accounts.route_token '{}': {}", id, e))?;
            count += 1;
        }
    }

    tx.commit()
        .map_err(|e| format!("backfill commit transaction: {}", e))?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Platform account, team key cache, provider bindings, and config helpers
// are in the storage_platform submodule. All items are re-exported here so
// existing callers (e.g. `storage::get_platform_account()`) keep working.
// ---------------------------------------------------------------------------
#[path = "storage_platform.rs"]
mod storage_platform;
pub use storage_platform::*;

/// Process-global lock that serializes every test touching `AK_VAULT_PATH`.
///
/// Tests across different modules must share the SAME mutex instance; if
/// each module defines its own, parallel `cargo test` threads stomp on each
/// other's env var while one is mid-initialization. Elevated from a
/// module-private static inside `mod tests` (2026-04-24) so `commands_account::
/// core_tests` and future cross-module vault tests can all `.lock()` the
/// same guard.
#[cfg(test)]
pub(crate) static TEST_VAULT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use tempfile::TempDir;

    /// Local alias to the crate-level TEST_VAULT_LOCK.
    static VAULT_LOCK: &std::sync::Mutex<()> = &super::TEST_VAULT_LOCK;

    /// Sets up an isolated vault DB via `AK_VAULT_PATH`.
    /// Returns the TempDir guard (must stay alive), the DB path, and the mutex guard.
    fn setup_vault() -> (TempDir, std::path::PathBuf, std::sync::MutexGuard<'static, ()>) {
        let guard = VAULT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("vault.db");
        unsafe { std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap()); }
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).expect("salt");
        let pw = SecretString::new("test_password".to_string());
        initialize_vault(&salt, &pw).expect("init vault");
        (dir, db_path, guard)
    }

    // ── Core vault CRUD ──────────────────────────────────────────────────

    #[test]
    fn test_store_and_get_entry() {
        let (_dir, _, _lock) = setup_vault();
        let nonce = vec![1u8; 12];
        let ciphertext = vec![2u8; 32];
        store_entry("test_key", &nonce, &ciphertext).expect("store");

        let (got_nonce, got_ct) = get_entry("test_key").expect("get");
        assert_eq!(got_nonce, nonce);
        assert_eq!(got_ct, ciphertext);
    }

    #[test]
    fn test_entry_exists() {
        let (_dir, _, _lock) = setup_vault();
        assert_eq!(entry_exists("missing").unwrap(), false);

        store_entry("exists_key", &[0u8; 12], &[0u8; 16]).expect("store");
        assert_eq!(entry_exists("exists_key").unwrap(), true);
    }

    #[test]
    fn test_list_entries() {
        let (_dir, _, _lock) = setup_vault();
        store_entry("alpha", &[0u8; 12], &[0u8; 16]).expect("store");
        store_entry("beta", &[0u8; 12], &[0u8; 16]).expect("store");

        let entries = list_entries().expect("list");
        assert!(entries.contains(&"alpha".to_string()));
        assert!(entries.contains(&"beta".to_string()));
    }

    #[test]
    fn test_delete_entry() {
        let (_dir, _, _lock) = setup_vault();
        store_entry("to_delete", &[0u8; 12], &[0u8; 16]).expect("store");
        assert!(entry_exists("to_delete").unwrap());

        delete_entry("to_delete").expect("delete");
        assert!(!entry_exists("to_delete").unwrap());
    }

    #[test]
    fn test_list_entries_with_metadata() {
        let (_dir, _, _lock) = setup_vault();
        store_entry("meta_key", &[0u8; 12], &[0u8; 16]).expect("store");

        let entries = list_entries_with_metadata().expect("list");
        assert!(entries.iter().any(|e| e.alias == "meta_key"));
        // created_at should be populated
        let entry = entries.iter().find(|e| e.alias == "meta_key").unwrap();
        assert!(entry.created_at.is_some());
    }

    // ── Provider metadata ────────────────────────────────────────────────

    #[test]
    fn test_provider_code_round_trip() {
        let (_dir, _, _lock) = setup_vault();
        store_entry("prov_key", &[0u8; 12], &[0u8; 16]).expect("store");

        set_entry_provider_code("prov_key", Some("openai")).expect("set");
        let code = get_entry_provider_code("prov_key").expect("get");
        assert_eq!(code, Some("openai".to_string()));
    }

    #[test]
    fn test_supported_providers_round_trip() {
        let (_dir, _, _lock) = setup_vault();
        store_entry("sp_key", &[0u8; 12], &[0u8; 16]).expect("store");

        let providers = vec!["openai".to_string(), "anthropic".to_string()];
        set_entry_supported_providers("sp_key", &providers).expect("set");

        let got = resolve_supported_providers("sp_key").expect("resolve");
        assert_eq!(got, providers);
    }

    #[test]
    fn test_base_url_round_trip() {
        let (_dir, _, _lock) = setup_vault();
        store_entry("url_key", &[0u8; 12], &[0u8; 16]).expect("store");

        set_entry_base_url("url_key", Some("https://custom.api.com")).expect("set");
        let url = get_entry_base_url("url_key").expect("get");
        assert_eq!(url, Some("https://custom.api.com".to_string()));
    }

    // ── Config table ─────────────────────────────────────────────────────

    #[test]
    fn test_text_config_round_trip() {
        let (_dir, _, _lock) = setup_vault();

        assert_eq!(get_text_config("test.key"), None);
        set_text_config("test.key", "test_value");
        assert_eq!(get_text_config("test.key"), Some("test_value".to_string()));
    }

    #[test]
    fn test_vault_change_seq() {
        let (_dir, _, _lock) = setup_vault();

        let seq1 = get_vault_change_seq().expect("get");
        bump_vault_change_seq().expect("bump");
        let seq2 = get_vault_change_seq().expect("get");
        assert!(seq2 > seq1, "change_seq should increase after bump");
    }

    // ── Active key config ────────────────────────────────────────────────

    #[test]
    fn test_active_key_config_round_trip() {
        let (_dir, _, _lock) = setup_vault();

        // Initially no active key
        assert!(get_active_key_config().unwrap().is_none());

        let cfg = ActiveKeyConfig {
            key_type: crate::credential_type::CredentialType::PersonalApiKey,
            key_ref: "my-key".to_string(),
            providers: vec!["openai".to_string()],
        };
        set_active_key_config(&cfg).expect("set");

        let got = get_active_key_config().unwrap().expect("should exist");
        assert_eq!(got.key_type, crate::credential_type::CredentialType::PersonalApiKey);
        assert_eq!(got.key_ref, "my-key");
        assert_eq!(got.providers, vec!["openai".to_string()]);

        // Clear
        clear_active_key_config().expect("clear");
        assert!(get_active_key_config().unwrap().is_none());
    }

    // ── Platform account ─────────────────────────────────────────────────

    #[test]
    fn test_platform_account_round_trip() {
        let (_dir, _, _lock) = setup_vault();

        assert!(get_platform_account().unwrap().is_none());

        save_platform_account("acc-1", "user@example.com", "jwt-token", "http://localhost:3000")
            .expect("save");

        let acc = get_platform_account().unwrap().expect("should exist");
        assert_eq!(acc.account_id, "acc-1");
        assert_eq!(acc.email, "user@example.com");
        assert_eq!(acc.control_url, "http://localhost:3000");

        // Update control URL
        update_platform_control_url("http://new-url:3000").expect("update");
        let acc = get_platform_account().unwrap().expect("should exist");
        assert_eq!(acc.control_url, "http://new-url:3000");

        // Clear
        clear_platform_account().expect("clear");
        assert!(get_platform_account().unwrap().is_none());
    }

    // ── Session backend preference ───────────────────────────────────────

    #[test]
    fn test_session_backend_pref() {
        let (_dir, _, _lock) = setup_vault();

        assert_eq!(get_session_backend_pref(), None);
        set_session_backend_pref("keychain");
        assert_eq!(get_session_backend_pref(), Some("keychain".to_string()));
    }

    // ── Sync version ─────────────────────────────────────────────────────

    #[test]
    fn test_sync_version_round_trip() {
        let (_dir, _, _lock) = setup_vault();

        assert_eq!(get_local_seen_sync_version(), 0);
        set_local_seen_sync_version(42);
        assert_eq!(get_local_seen_sync_version(), 42);
    }

    // ── change_password ──────────────────────────────────────────────────
    // Regression guards for the 2026-04-20 password-hash-not-updated bug.
    // Ref: workflow/CI/bugfix/2026-04-20-change-password-bricks-vault.md

    fn read_config_blob(conn: &Connection, key: &str) -> Option<Vec<u8>> {
        conn.query_row(
            "SELECT value FROM config WHERE key = ?",
            params![key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok()
    }

    #[test]
    fn change_password_updates_password_hash_and_salt() {
        let (_dir, db_path, _lock) = setup_vault();
        // Empty vault: the re-encrypt loop is a no-op, which is fine for this
        // test. A dedicated end-to-end test (tests/) covers the re-encrypt path
        // with real ciphertext produced via the CLI.
        let old = SecretString::new("test_password".to_string());
        let new = SecretString::new("new_password_xyz".to_string());

        let salt_before = read_config_blob(
            &rusqlite::Connection::open(&db_path).unwrap(),
            "master_salt",
        ).expect("salt present");
        let hash_before = read_config_blob(
            &rusqlite::Connection::open(&db_path).unwrap(),
            "password_hash",
        ).expect("hash present");

        change_password(&old, &new).expect("change_password ok");

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let salt_after = read_config_blob(&conn, "master_salt").expect("salt after");
        let hash_after = read_config_blob(&conn, "password_hash").expect("hash after");

        assert_ne!(salt_before, salt_after, "salt must rotate");
        assert_ne!(hash_before, hash_after,
            "password_hash MUST rotate — leaving it at the old value bricks the vault");

        // password_hash must equal derive(new_password, new_salt) with default params.
        let expected = crate::crypto::derive_key_with_params(
            &new,
            &salt_after,
            crate::crypto::ARGON2_M_COST,
            crate::crypto::ARGON2_T_COST,
            crate::crypto::ARGON2_P_COST,
        ).expect("derive new");
        assert_eq!(hash_after.as_slice(), expected.as_slice(),
            "password_hash must match derive(new_password, new_salt) so \
             executor::verify_password_internal / aikey-proxy vault.go can \
             open the vault with the new password");
    }

    #[test]
    fn change_password_rejects_same_password() {
        let (_dir, _, _lock) = setup_vault();
        let same = SecretString::new("test_password".to_string());

        let err = change_password(&same, &same)
            .expect_err("same-password change must be rejected");
        assert!(err.to_lowercase().contains("differ") || err.to_lowercase().contains("same"),
            "rejection message should explain why, got: {}", err);
    }

    #[test]
    fn change_password_rejects_wrong_old_password() {
        let (_dir, db_path, _lock) = setup_vault();

        let wrong = SecretString::new("not-the-real-password".to_string());
        let new = SecretString::new("new_password_xyz".to_string());

        let err = change_password(&wrong, &new)
            .expect_err("wrong old password must be rejected");
        assert!(err.to_lowercase().contains("incorrect") || err.to_lowercase().contains("invalid"),
            "rejection message should mention password validity, got: {}", err);

        // Hash must NOT have been touched by a failed attempt.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let hash_after = read_config_blob(&conn, "password_hash").expect("hash present");
        let correct = SecretString::new("test_password".to_string());
        let salt = read_config_blob(&conn, "master_salt").expect("salt present");
        let expected = crate::crypto::derive_key_with_params(
            &correct,
            &salt,
            crate::crypto::ARGON2_M_COST,
            crate::crypto::ARGON2_T_COST,
            crate::crypto::ARGON2_P_COST,
        ).expect("derive");
        assert_eq!(hash_after.as_slice(), expected.as_slice(),
            "failed change attempt must not mutate password_hash");
    }

    // ── change_password re-encrypts ALL ciphertext tables (2026-05-11 fix) ─

    /// Derives the current vault_key for a given password (using the live
    /// vault's salt + KDF params), used by the multi-table re-encrypt tests
    /// to verify that ciphertext can in fact be decrypted under the new
    /// password — the property that broke before the 2026-05-11 fix.
    fn derive_current(password: &str) -> [u8; 32] {
        let salt = get_salt().expect("salt");
        let (m, t, p) = get_kdf_params().expect("kdf");
        let key = crate::crypto::derive_key_with_params(
            &SecretString::new(password.to_string()),
            &salt,
            m,
            t,
            p,
        )
        .expect("derive");
        let mut out = [0u8; 32];
        out.copy_from_slice(key.as_slice());
        out
    }

    #[test]
    fn change_password_reencrypts_managed_virtual_keys_cache() {
        let (_dir, _db_path, _lock) = setup_vault();

        // Seed a team key row with provider_key ciphertext encrypted under
        // the *current* vault_key — the realistic state after `aikey key sync`.
        let conn = open_connection().expect("open");
        // managed_virtual_keys_cache schema is created by the platform
        // migrations; force them to run via storage_platform's first read.
        let _ = crate::storage::list_virtual_key_cache();

        let old_key = derive_current("test_password");
        let plaintext = b"sk-ant-fake-team-key-material";
        let (nonce, ct) = crate::crypto::encrypt(&old_key, plaintext).expect("encrypt");

        conn.execute(
            "INSERT INTO managed_virtual_keys_cache
                (virtual_key_id, org_id, seat_id, alias, provider_code, protocol_type,
                 base_url, credential_id, credential_revision, virtual_key_revision,
                 key_status, share_status, local_state,
                 provider_key_nonce, provider_key_ciphertext, synced_at)
             VALUES ('vk-test','org-1','seat-1','my-team-key','anthropic','anthropic',
                     'https://api.anthropic.com','cred-1','rev-1','vrev-1',
                     'active','claimed','synced_inactive', ?1, ?2, strftime('%s','now'))",
            params![nonce, ct],
        )
        .expect("insert managed key row");

        // Rotate the password — the new path must re-encrypt the team key row too.
        let old = SecretString::new("test_password".to_string());
        let new = SecretString::new("new_password_xyz".to_string());
        change_password(&old, &new).expect("change_password ok");

        // Read back: provider_key_ciphertext must decrypt under the NEW vault_key.
        let conn = open_connection().expect("reopen");
        let (new_nonce, new_ct): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT provider_key_nonce, provider_key_ciphertext
                 FROM managed_virtual_keys_cache WHERE virtual_key_id = ?1",
                params!["vk-test"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read row");

        let new_key = derive_current("new_password_xyz");
        let recovered = crate::crypto::decrypt(&new_key, &new_nonce, &new_ct)
            .expect("decrypt with new vault_key must succeed");
        assert_eq!(recovered.as_slice(), plaintext,
            "team key plaintext must round-trip across change_password");

        // The old vault_key must NOT decrypt anymore — proves a real rotate.
        assert!(
            crate::crypto::decrypt(&old_key, &new_nonce, &new_ct).is_err(),
            "old vault_key must no longer decrypt the rotated ciphertext"
        );
    }

    #[test]
    fn change_password_reencrypts_provider_account_tokens() {
        let (_dir, _db_path, _lock) = setup_vault();
        let _ = crate::storage::list_virtual_key_cache(); // run platform migrations

        let old_key = derive_current("test_password");
        let at_plain = b"oauth-access-token-xyz";
        let rt_plain = b"oauth-refresh-token-abc";
        let (at_n, at_c) = crate::crypto::encrypt(&old_key, at_plain).expect("encrypt access");
        let (rt_n, rt_c) = crate::crypto::encrypt(&old_key, rt_plain).expect("encrypt refresh");

        let conn = open_connection().expect("open");
        // provider_account_tokens has FK → provider_accounts; seed parent first.
        conn.execute(
            "INSERT INTO provider_accounts
                (provider_account_id, provider, auth_type, display_identity, created_at)
             VALUES ('acct-1','claude','oauth','user@example.com', strftime('%s','now'))",
            [],
        ).expect("insert provider_account");
        conn.execute(
            "INSERT INTO provider_account_tokens
                (provider_account_id,
                 access_token_nonce, access_token_ciphertext,
                 refresh_token_nonce, refresh_token_ciphertext,
                 token_expires_at, updated_at)
             VALUES ('acct-1', ?1, ?2, ?3, ?4, 9999999999, strftime('%s','now'))",
            params![at_n, at_c, rt_n, rt_c],
        ).expect("insert tokens");

        let old = SecretString::new("test_password".to_string());
        let new = SecretString::new("new_password_xyz".to_string());
        change_password(&old, &new).expect("change_password ok");

        let conn = open_connection().expect("reopen");
        let (atn, atc, rtn, rtc): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT access_token_nonce, access_token_ciphertext,
                        refresh_token_nonce, refresh_token_ciphertext
                 FROM provider_account_tokens WHERE provider_account_id = ?1",
                params!["acct-1"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read tokens");

        let new_key = derive_current("new_password_xyz");
        let at_back = crate::crypto::decrypt(&new_key, &atn, &atc)
            .expect("access decrypt with new vault_key");
        let rt_back = crate::crypto::decrypt(&new_key, &rtn, &rtc)
            .expect("refresh decrypt with new vault_key");
        assert_eq!(at_back.as_slice(), at_plain);
        assert_eq!(rt_back.as_slice(), rt_plain);
    }

    #[test]
    fn change_password_aborts_when_team_key_ciphertext_was_written_under_wrong_key() {
        let (_dir, _db_path, _lock) = setup_vault();
        let _ = crate::storage::list_virtual_key_cache(); // run platform migrations

        // Simulate the 2026-05-11 incident: insert team key ciphertext
        // encrypted under a vault_key that does NOT match password_hash.
        let bogus_key = [0u8; 32];
        let (nonce, ct) = crate::crypto::encrypt(&bogus_key, b"unknown-plaintext").expect("encrypt");
        let conn = open_connection().expect("open");
        conn.execute(
            "INSERT INTO managed_virtual_keys_cache
                (virtual_key_id, org_id, seat_id, alias, provider_code, protocol_type,
                 base_url, credential_id, credential_revision, virtual_key_revision,
                 key_status, share_status, local_state,
                 provider_key_nonce, provider_key_ciphertext, synced_at)
             VALUES ('vk-stale','org','seat','stale','anthropic','anthropic',
                     'https://api.anthropic.com','c','r','v',
                     'active','claimed','synced_inactive', ?1, ?2, strftime('%s','now'))",
            params![nonce, ct],
        ).expect("seed bad row");

        let old = SecretString::new("test_password".to_string());
        let new = SecretString::new("new_password_xyz".to_string());
        let err = change_password(&old, &new)
            .expect_err("change_password must abort when a team-key row can't be re-encrypted");
        assert!(
            err.contains("vk-stale") && err.contains("--force-reencrypt"),
            "error must name the affected vk_id and the recovery command, got: {}",
            err
        );

        // The password rotation must NOT have landed (transaction rollback).
        let conn = open_connection().expect("reopen");
        let hash_after: Vec<u8> = conn
            .query_row(
                "SELECT value FROM config WHERE key = 'password_hash'",
                [],
                |row| row.get(0),
            )
            .expect("hash present");
        let original = derive_current("test_password");
        assert_eq!(hash_after, original,
            "transaction must roll back: password_hash stays on the old key");
    }

    // ── force-reencrypt + verify_vault_key (2026-05-11 fix) ──

    #[test]
    fn clear_managed_key_ciphertexts_resets_only_active_rows() {
        let (_dir, _db_path, _lock) = setup_vault();
        let _ = crate::storage::list_virtual_key_cache();
        let conn = open_connection().expect("open");
        let key = derive_current("test_password");
        let (n, c) = crate::crypto::encrypt(&key, b"x").expect("encrypt");

        // Three rows: active+ct, disabled_by_account_scope+ct, active without ct.
        conn.execute(
            "INSERT INTO managed_virtual_keys_cache
                (virtual_key_id, org_id, seat_id, alias, provider_code, protocol_type,
                 base_url, credential_id, credential_revision, virtual_key_revision,
                 key_status, share_status, local_state,
                 provider_key_nonce, provider_key_ciphertext, synced_at)
             VALUES ('vk-A','o','s','A','anthropic','anthropic','u','c','r','v',
                     'active','claimed','synced_inactive', ?1, ?2, 0),
                    ('vk-B','o','s','B','anthropic','anthropic','u','c','r','v',
                     'active','claimed','disabled_by_account_scope', ?1, ?2, 0),
                    ('vk-C','o','s','C','anthropic','anthropic','u','c','r','v',
                     'active','pending_claim','synced_inactive', NULL, NULL, 0)",
            params![n, c],
        ).expect("seed");

        let cleared = crate::storage::clear_managed_key_ciphertexts().expect("clear");
        assert_eq!(cleared, 1, "only vk-A (active + non-disabled + has ct) is cleared");

        // vk-A: cleared
        let conn = open_connection().expect("reopen");
        let a_ct: Option<Vec<u8>> = conn.query_row(
            "SELECT provider_key_ciphertext FROM managed_virtual_keys_cache WHERE virtual_key_id='vk-A'",
            [], |row| row.get(0)).expect("vk-A");
        assert!(a_ct.is_none(), "vk-A ciphertext must be NULL after force-reencrypt");

        // vk-B: still has ct (disabled rows untouched — server-owned lifecycle)
        let b_ct: Option<Vec<u8>> = conn.query_row(
            "SELECT provider_key_ciphertext FROM managed_virtual_keys_cache WHERE virtual_key_id='vk-B'",
            [], |row| row.get(0)).expect("vk-B");
        assert!(b_ct.is_some(), "disabled rows must NOT be cleared");
    }

    #[test]
    fn verify_vault_key_strict_match_and_mismatch() {
        let (_dir, _db_path, _lock) = setup_vault();
        let good = derive_current("test_password");
        assert!(verify_vault_key(&good).is_ok(), "current key must verify");

        let wrong = [0u8; 32];
        let err = verify_vault_key(&wrong).expect_err("wrong key must reject");
        assert!(err.contains("password_hash"),
            "rejection message must reference password_hash, got: {}", err);

        // Length mismatch is a programmer error, not a credential error.
        assert!(verify_vault_key(&[0u8; 31]).is_err());
    }

    #[test]
    fn verify_vault_key_requires_password_hash_no_silent_accept() {
        let (_dir, db_path, _lock) = setup_vault();
        // Remove password_hash to simulate a broken vault state. With the old
        // fallback this would silently accept any key on an empty-entries
        // vault — the precise hole the 2026-05-11 fix closes.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("DELETE FROM config WHERE key='password_hash'", []).unwrap();

        let any_key = [0u8; 32];
        let err = verify_vault_key(&any_key)
            .expect_err("missing password_hash must REJECT (no silent accept)");
        assert!(err.contains("password_hash") && err.contains("init"),
            "rejection must explain missing hash + point at `aikey init`, got: {}", err);
    }
}

