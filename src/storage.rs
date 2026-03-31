//! Storage layer for AiKeyLabs vault
//!
//! Manages SQLite database operations for storing encrypted secrets
//! with proper file permissions and schema initialization.

use rusqlite::{params, Connection, Result as SqlResult};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Metadata for a secret entry (used for JSON output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    /// Provider code (e.g. "anthropic", "openai"); None for plain secrets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_code: Option<String>,
    /// Custom upstream base URL set by the user; overrides the provider default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
}

/// Default vault data directory path (~/.aikey/data/)
const VAULT_DIR: &str = ".aikey/data";

/// Database filename
const DB_NAME: &str = "vault.db";

/// Default binding domain
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

    let home = std::env::var("HOME")
        .map_err(|_| "Could not determine home directory".to_string())?;

    let vault_dir = PathBuf::from(home).join(VAULT_DIR);
    Ok(vault_dir.join(DB_NAME))
}

/// Opens a connection to the vault database with security pragmas enabled
pub(crate) fn open_connection() -> Result<Connection, String> {
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

    // Ensure required tables exist (idempotent migrations)
    apply_migrations(&conn)?;

    Ok(conn)
}

fn apply_migrations(conn: &Connection) -> Result<(), String> {
    // Core tables
    conn.execute(
        "CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to ensure config table: {}", e))?;

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
    .map_err(|e| format!("Failed to ensure entries table: {}", e))?;

    // Profiles and bindings
    conn.execute(
        "CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            is_active INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to ensure profiles table: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS bindings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_name TEXT NOT NULL,
            domain TEXT NOT NULL DEFAULT 'default',
            alias TEXT NOT NULL,
            FOREIGN KEY (profile_name) REFERENCES profiles(name),
            UNIQUE(profile_name, domain)
        )",
        [],
    )
    .map_err(|e| format!("Failed to ensure bindings table: {}", e))?;

    // Ensure domain column exists for older databases BEFORE creating index
    let has_domain: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('bindings') WHERE name='domain'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false);

    if !has_domain {
        conn.execute(
            "ALTER TABLE bindings ADD COLUMN domain TEXT NOT NULL DEFAULT 'default'",
            [],
        )
        .map_err(|e| format!("Failed to add domain column to bindings: {}", e))?;
    }

    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_profile_domain ON bindings(profile_name, domain)",
        [],
    )
    .map_err(|e| format!("Failed to ensure bindings index: {}", e))?;

    // Events table for usage tracking
    conn.execute(
        "CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            provider TEXT,
            alias TEXT,
            command TEXT,
            exit_code INTEGER,
            duration_ms INTEGER,
            secrets_count INTEGER,
            error TEXT,
            project TEXT,
            env TEXT,
            profile TEXT,
            ok INTEGER NOT NULL DEFAULT 0,
            error_type TEXT
        )",
        [],
    )
    .map_err(|e| format!("Failed to ensure events table: {}", e))?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
        [],
    )
    .map_err(|e| format!("Failed to ensure events index: {}", e))?;

    // ---- Platform account (global identity) ----
    // Stores the JWT and account metadata from aikey-control-service login.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS platform_account (
            id              INTEGER PRIMARY KEY CHECK (id = 1), -- singleton row
            account_id      TEXT NOT NULL,
            email           TEXT NOT NULL,
            jwt_token       TEXT NOT NULL,   -- Bearer token; refresh by re-login
            control_url     TEXT NOT NULL,   -- e.g. https://control.aikey.io
            logged_in_at    INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        )",
        [],
    )
    .map_err(|e| format!("Failed to ensure platform_account table: {}", e))?;

    // ---- Team-managed virtual key cache ----
    // Local mirror of managed_virtual_keys from the control service.
    // provider_key_nonce + provider_key_ciphertext hold the real provider key
    // re-encrypted with the local vault AES key (same scheme as entries table).
    //
    // local_state drives CLI/proxy behaviour; server share_status is authoritative
    // but may be slightly stale between syncs.
    //
    // cache_schema_version allows the proxy to reject incompatible cache rows
    // and prompt the user to re-sync.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS managed_virtual_keys_cache (
            virtual_key_id       TEXT PRIMARY KEY,
            org_id               TEXT NOT NULL,
            seat_id              TEXT NOT NULL,
            alias                TEXT NOT NULL,
            provider_code        TEXT NOT NULL,
            protocol_type        TEXT NOT NULL DEFAULT 'openai_compatible',
            base_url             TEXT NOT NULL,
            credential_id        TEXT NOT NULL,
            credential_revision  TEXT NOT NULL,
            virtual_key_revision TEXT NOT NULL,
            key_status           TEXT NOT NULL DEFAULT 'active',
            share_status         TEXT NOT NULL DEFAULT 'pending_claim',
            local_state          TEXT NOT NULL DEFAULT 'synced_inactive',
            expires_at           INTEGER,
            provider_key_nonce      BLOB,        -- NULL until delivered
            provider_key_ciphertext BLOB,        -- NULL until delivered
            cache_schema_version INTEGER NOT NULL DEFAULT 1,
            synced_at            INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        )",
        [],
    )
    .map_err(|e| format!("Failed to ensure managed_virtual_keys_cache table: {}", e))?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_mvkc_local_state ON managed_virtual_keys_cache(local_state)",
        [],
    )
    .map_err(|e| format!("Failed to ensure managed_virtual_keys_cache index: {}", e))?;

    // Migration guards for managed_virtual_keys_cache new columns.
    for (col, ddl) in &[
        (
            "local_alias",
            // v0.6: user-set local display name; does not affect server alias
            "ALTER TABLE managed_virtual_keys_cache ADD COLUMN local_alias TEXT",
        ),
        (
            "supported_providers",
            // v0.7: JSON array of provider codes this key supports (e.g. '["anthropic"]')
            // Populated from delivery payload slots at accept/sync time; used by `aikey use`
            // to know which env vars to write into ~/.aikey/active.env.
            "ALTER TABLE managed_virtual_keys_cache ADD COLUMN supported_providers TEXT",
        ),
        (
            "provider_base_urls",
            // v0.7: JSON object mapping provider_code → upstream base_url for each provider
            // slot (e.g. {"anthropic":"https://api.anthropic.com"}). Allows path-prefix proxy
            // routing to use the correct per-provider admin-configured upstream URL.
            "ALTER TABLE managed_virtual_keys_cache ADD COLUMN provider_base_urls TEXT",
        ),
    ] {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('managed_virtual_keys_cache') WHERE name=?1",
                [col],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !has_col {
            conn.execute(ddl, [])
                .map_err(|e| format!("Failed to add managed_virtual_keys_cache.{} column: {}", col, e))?;
        }
    }

    // Migration guards for entries routing columns (v0.7+).
    for (col, ddl, desc) in &[
        (
            "provider_code",
            "ALTER TABLE entries ADD COLUMN provider_code TEXT",
            // NULL = ordinary secret, not involved in provider routing.
            // Set via --provider flag or interactive prompt on `aikey add`.
            "entries.provider_code",
        ),
        (
            "base_url",
            "ALTER TABLE entries ADD COLUMN base_url TEXT",
            // User-supplied upstream base URL (e.g. a third-party proxy).
            // Overrides the provider's default when set.
            "entries.base_url",
        ),
    ] {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name=?1",
                [col],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !has_col {
            conn.execute(ddl, [])
                .map_err(|e| format!("Failed to add {} column: {}", desc, e))?;
        }
    }

    // Migration guards for platform_account OAuth columns (v0.5+).
    // jwt_token is repurposed as the OAuth access_token; refresh_token and
    // token_expires_at are new columns that allow silent token renewal.
    for (col, ddl) in &[
        ("refresh_token",    "ALTER TABLE platform_account ADD COLUMN refresh_token TEXT"),
        ("token_expires_at", "ALTER TABLE platform_account ADD COLUMN token_expires_at INTEGER"),
    ] {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('platform_account') WHERE name=?1",
                [col],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !has_col {
            conn.execute(ddl, [])
                .map_err(|e| format!("Failed to add platform_account.{} column: {}", col, e))?;
        }
    }

    // Migration guards for new event columns on existing databases
    for (col, ddl) in &[
        ("project",    "ALTER TABLE events ADD COLUMN project TEXT"),
        ("env",        "ALTER TABLE events ADD COLUMN env TEXT"),
        ("profile",    "ALTER TABLE events ADD COLUMN profile TEXT"),
        ("ok",         "ALTER TABLE events ADD COLUMN ok INTEGER NOT NULL DEFAULT 0"),
        ("error_type", "ALTER TABLE events ADD COLUMN error_type TEXT"),
    ] {
        let has_col: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name=?1",
                [col],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !has_col {
            conn.execute(ddl, [])
                .map_err(|e| format!("Failed to add events.{} column: {}", col, e))?;
        }
    }

    Ok(())
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
        let home = std::env::var("HOME")
            .map_err(|_| "Could not determine home directory".to_string())?;
        let vault_dir = PathBuf::from(home).join(VAULT_DIR);
        let db_path = vault_dir.join(DB_NAME);
        (vault_dir, db_path)
    };

    if !vault_dir.exists() {
        fs::create_dir_all(&vault_dir)
            .map_err(|e| format!("Failed to create vault directory: {}", e))?;

        #[cfg(unix)]
        {
            let metadata = fs::metadata(&vault_dir)
                .map_err(|e| format!("Failed to read directory metadata: {}", e))?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&vault_dir, perms)
                .map_err(|e| format!("Failed to set directory permissions: {}", e))?;
        }
    }

    if db_path.exists() {
        return Err("Vault already initialized. If you need a fresh vault, delete the local vault file and run 'aikey init' again.".to_string());
    }

    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to create database: {}", e))?;

    #[cfg(unix)]
    {
        let metadata = fs::metadata(&db_path)
            .map_err(|e| format!("Failed to read database metadata: {}", e))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&db_path, perms)
            .map_err(|e| format!("Failed to set database permissions: {}", e))?;
    }

    // SECURITY: Enable secure delete to overwrite deleted data with zeros
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(|e| format!("Failed to enable secure delete: {}", e))?;

    // SECURITY: Enable auto-vacuum to reclaim space and prevent data remnants
    conn.pragma_update(None, "auto_vacuum", "FULL")
        .map_err(|e| format!("Failed to enable auto-vacuum: {}", e))?;

    conn.execute(
        "CREATE TABLE config (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to create config table: {}", e))?;

    conn.execute(
        "CREATE TABLE entries (
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
        "CREATE TABLE profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            is_active INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )",
        [],
    )
    .map_err(|e| format!("Failed to create profiles table: {}", e))?;

    conn.execute(
        "CREATE TABLE bindings (
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

/// Stores an encrypted entry in the vault
pub fn store_entry(alias: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<(), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    migrate_database(&conn)?;

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

/// List all entries with metadata (for JSON output)
pub fn list_entries_with_metadata() -> Result<Vec<SecretMetadata>, String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run any aikey command to initialize it automatically.".to_string());
    }

    let conn = open_connection()?;

    // provider_code and base_url may not exist on older vaults — use ifnull to default to NULL.
    let mut stmt = conn
        .prepare("SELECT alias, created_at, provider_code, base_url FROM entries ORDER BY alias")
        .or_else(|_| conn.prepare("SELECT alias, created_at, NULL, NULL FROM entries ORDER BY alias"))
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let metadata: Vec<SecretMetadata> = stmt
        .query_map([], |row| {
            Ok(SecretMetadata {
                alias:         row.get(0)?,
                created_at:    row.get(1).ok(),
                provider_code: row.get(2).ok().flatten(),
                base_url:      row.get(3).ok().flatten(),
            })
        })
        .map_err(|e| format!("Failed to query entries: {}", e))?
        .collect::<SqlResult<Vec<SecretMetadata>>>()
        .map_err(|e| format!("Failed to collect results: {}", e))?;

    Ok(metadata)
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

    // Get salt and KDF parameters
    let salt = get_salt()?;
    let (m_cost, t_cost, p_cost) = get_kdf_params()?;

    // Derive old key to verify password
    let old_key = crate::crypto::derive_key_with_params(old_password, &salt, m_cost, t_cost, p_cost)
        .map_err(|e| format!("Failed to derive old key: {}", e))?;

    // Verify old password by attempting to decrypt an entry
    let conn = open_connection()?;

    // Get first entry to test decryption
    let test_result: Result<(Vec<u8>, Vec<u8>), rusqlite::Error> = conn.query_row(
        "SELECT nonce, ciphertext FROM entries LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    );

    if let Ok((nonce, ciphertext)) = test_result {
        // Try to decrypt with old key to verify password
        crate::crypto::decrypt(&old_key, &nonce, &ciphertext)
            .map_err(|_| "Incorrect password".to_string())?;
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

    // Get all entries
    let mut stmt = conn
        .prepare("SELECT id, alias, nonce, ciphertext FROM entries")
        .map_err(|e| format!("Failed to prepare statement: {}", e))?;

    let entries: Vec<(i64, String, Vec<u8>, Vec<u8>)> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
            ))
        })
        .map_err(|e| format!("Failed to query entries: {}", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to collect entries: {}", e))?;

    // Re-encrypt all entries with new key
    for (id, alias, old_nonce, old_ciphertext) in entries {
        // Decrypt with old key
        let plaintext = crate::crypto::decrypt(&old_key, &old_nonce, &old_ciphertext)
            .map_err(|e| format!("Failed to decrypt entry '{}': {}", alias, e))?;

        // Encrypt with new key
        let (new_nonce, new_ciphertext) = crate::crypto::encrypt(&new_key, &plaintext)
            .map_err(|e| format!("Failed to encrypt entry '{}': {}", alias, e))?;

        // Update entry in database
        conn.execute(
            "UPDATE entries SET nonce = ?, ciphertext = ? WHERE id = ?",
            params![new_nonce, new_ciphertext, id],
        )
        .map_err(|e| format!("Failed to update entry '{}': {}", alias, e))?;
    }

    // Update salt in config
    conn.execute(
        "UPDATE config SET value = ? WHERE key = ?",
        params![&new_salt[..], "master_salt"],
    )
    .map_err(|e| format!("Failed to update salt: {}", e))?;

    // Update KDF parameters to default values (stored as binary)
    conn.execute(
        "UPDATE config SET value = ? WHERE key = ?",
        params![&crate::crypto::ARGON2_M_COST.to_le_bytes()[..], "kdf_m_cost"],
    )
    .map_err(|e| format!("Failed to update m_cost: {}", e))?;

    conn.execute(
        "UPDATE config SET value = ? WHERE key = ?",
        params![&crate::crypto::ARGON2_T_COST.to_le_bytes()[..], "kdf_t_cost"],
    )
    .map_err(|e| format!("Failed to update t_cost: {}", e))?;

    conn.execute(
        "UPDATE config SET value = ? WHERE key = ?",
        params![&crate::crypto::ARGON2_P_COST.to_le_bytes()[..], "kdf_p_cost"],
    )
    .map_err(|e| format!("Failed to update p_cost: {}", e))?;

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

/// Get all profiles
pub fn get_all_profiles() -> Result<Vec<crate::profiles::Profile>, String> {
    let conn = open_connection()?;
    crate::profiles::list_profiles(&conn)
}

/// Get the active profile
pub fn get_active_profile() -> Result<Option<crate::profiles::Profile>, String> {
    let conn = open_connection()?;
    crate::profiles::get_active_profile(&conn)
}

/// Create a new profile
pub fn create_profile(name: &str) -> Result<crate::profiles::Profile, String> {
    let conn = open_connection()?;
    crate::profiles::create_profile(&conn, name)
}

/// Set a profile as active
pub fn set_active_profile(name: &str) -> Result<crate::profiles::Profile, String> {
    let conn = open_connection()?;
    crate::profiles::set_active_profile(&conn, name)
}

/// Delete a profile
pub fn delete_profile(name: &str) -> Result<(), String> {
    let conn = open_connection()?;
    crate::profiles::delete_profile(&conn, name)
}

/// Bind a secret to a profile for a given domain (env var)
pub fn bind_secret_to_profile(profile_name: &str, domain: &str, alias: &str) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "INSERT INTO bindings (profile_name, domain, alias) VALUES (?, ?, ?) ON CONFLICT(profile_name, domain) DO UPDATE SET alias=excluded.alias",
        params![profile_name, domain, alias],
    )
    .map_err(|e| format!("Failed to bind secret to profile: {}", e))?;
    Ok(())
}

/// Unbind a secret from a profile
pub fn unbind_secret_from_profile(profile_name: &str, domain: &str, alias: &str) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "DELETE FROM bindings WHERE profile_name = ? AND domain = ? AND alias = ?",
        params![profile_name, domain, alias],
    )
    .map_err(|e| format!("Failed to unbind secret from profile: {}", e))?;
    Ok(())
}

/// Get all secrets bound to a profile (default domain)
pub fn get_profile_secrets(profile_name: &str) -> Result<Vec<String>, String> {
    let conn = open_connection()?;
    let mut stmt = conn
        .prepare("SELECT alias FROM bindings WHERE profile_name = ? AND domain = ? ORDER BY alias")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let secrets = stmt
        .query_map(params![profile_name, DEFAULT_BINDING_DOMAIN], |row| row.get(0))
        .map_err(|e| format!("Failed to query bindings: {}", e))?
        .collect::<SqlResult<Vec<String>>>()
        .map_err(|e| format!("Failed to collect results: {}", e))?;

    Ok(secrets)
}

/// Get all bindings for a profile (domain -> alias)
pub fn get_profile_bindings(conn: &Connection, profile_name: &str) -> Result<Vec<(String, String)>, String> {
    let mut stmt = conn
        .prepare("SELECT domain, alias FROM bindings WHERE profile_name = ? ORDER BY domain")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let bindings = stmt
        .query_map(params![profile_name], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| format!("Failed to query bindings: {}", e))?
        .collect::<SqlResult<Vec<(String, String)>>>();

    bindings.map_err(|e| format!("Failed to collect results: {}", e))
}

/// Add a binding between a secret and a profile
pub fn add_profile_binding(conn: &Connection, profile_name: &str, domain: &str, alias: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO bindings (profile_name, domain, alias) VALUES (?, ?, ?) ON CONFLICT(profile_name, domain) DO UPDATE SET alias=excluded.alias",
        params![profile_name, domain, alias],
    )
    .map_err(|e| format!("Failed to add binding: {}", e))?;

    Ok(())
}

/// Remove a binding between a secret and a profile
pub fn remove_profile_binding(conn: &Connection, profile_name: &str, domain: &str, alias: &str) -> Result<(), String> {
    conn.execute(
        "DELETE FROM bindings WHERE profile_name = ? AND domain = ? AND alias = ?",
        params![profile_name, domain, alias],
    )
    .map_err(|e| format!("Failed to remove binding: {}", e))?;

    Ok(())
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
// Platform account (control-service login session)
// ---------------------------------------------------------------------------

/// Singleton row in the `platform_account` table.
///
/// `jwt_token` holds the current OAuth access_token (Bearer).
/// `refresh_token` is the long-lived opaque token for silent renewal.
/// `token_expires_at` is the Unix timestamp when the access_token expires.
/// When `token_expires_at` is `None` the row was created by an older CLI version
/// and the token may still be valid (legacy 24-hour window).
#[derive(Debug, Clone)]
pub struct PlatformAccount {
    pub account_id: String,
    pub email: String,
    pub jwt_token: String,         // current access_token (Bearer)
    pub control_url: String,
    pub logged_in_at: i64,
    pub refresh_token: Option<String>,    // OAuth refresh token; None on legacy rows
    pub token_expires_at: Option<i64>,    // Unix epoch when access_token expires
}

/// Upserts the singleton platform_account row (id = 1).
pub fn save_platform_account(
    account_id: &str,
    email: &str,
    jwt_token: &str,
    control_url: &str,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "INSERT OR REPLACE INTO platform_account
             (id, account_id, email, jwt_token, control_url, logged_in_at)
         VALUES (1, ?1, ?2, ?3, ?4, strftime('%s', 'now'))",
        params![account_id, email, jwt_token, control_url],
    )
    .map_err(|e| format!("Failed to save platform account: {}", e))?;
    Ok(())
}

/// Returns the stored platform account, or `None` if not logged in.
pub fn get_platform_account() -> Result<Option<PlatformAccount>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    let result = conn.query_row(
        "SELECT account_id, email, jwt_token, control_url, logged_in_at,
                refresh_token, token_expires_at
           FROM platform_account WHERE id = 1",
        [],
        |row| {
            Ok(PlatformAccount {
                account_id: row.get(0)?,
                email: row.get(1)?,
                jwt_token: row.get(2)?,
                control_url: row.get(3)?,
                logged_in_at: row.get(4)?,
                refresh_token: row.get(5)?,
                token_expires_at: row.get(6)?,
            })
        },
    );
    match result {
        Ok(acc) => Ok(Some(acc)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to read platform account: {}", e)),
    }
}

/// Upserts the singleton platform_account row with OAuth token data.
///
/// `access_token` is the short-lived Bearer JWT (1 h).
/// `refresh_token` is the long-lived opaque renewal token (30 d).
/// `token_expires_at` is the Unix timestamp when `access_token` expires.
pub fn save_oauth_session(
    account_id: &str,
    email: &str,
    access_token: &str,
    refresh_token: &str,
    token_expires_at: i64,
    control_url: &str,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "INSERT OR REPLACE INTO platform_account
             (id, account_id, email, jwt_token, control_url, logged_in_at,
              refresh_token, token_expires_at)
         VALUES (1, ?1, ?2, ?3, ?4, strftime('%s', 'now'), ?5, ?6)",
        params![account_id, email, access_token, control_url, refresh_token, token_expires_at],
    )
    .map_err(|e| format!("Failed to save OAuth session: {}", e))?;
    Ok(())
}

/// Updates only the access_token and its expiry after a silent refresh.
pub fn update_access_token(access_token: &str, token_expires_at: i64) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE platform_account SET jwt_token = ?1, token_expires_at = ?2 WHERE id = 1",
        params![access_token, token_expires_at],
    )
    .map_err(|e| format!("Failed to update access token: {}", e))?;
    Ok(())
}

/// Updates access_token, refresh_token, and expiry after a token refresh.
/// Call this whenever the server returns both tokens (e.g. POST /v1/auth/cli/token/refresh).
pub fn update_tokens(
    access_token: &str,
    refresh_token: &str,
    token_expires_at: i64,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE platform_account SET jwt_token = ?1, refresh_token = ?2, token_expires_at = ?3 WHERE id = 1",
        params![access_token, refresh_token, token_expires_at],
    )
    .map_err(|e| format!("Failed to update tokens: {}", e))?;
    Ok(())
}

/// Deletes the platform_account row (logout).
pub fn clear_platform_account() -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute("DELETE FROM platform_account WHERE id = 1", [])
        .map_err(|e| format!("Failed to clear platform account: {}", e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Active key configuration (global mutex for proxy routing)
// ---------------------------------------------------------------------------

/// Holds the currently-active key selection written by `aikey use`.
/// Stored as three TEXT entries in the `config` table.
///
/// `key_type` = "team" | "personal" | "" (empty = nothing active)
/// `key_ref`  = virtual_key_id (team) OR alias (personal)
/// `providers` = JSON array of provider codes the active key supports
#[derive(Debug, Clone)]
pub struct ActiveKeyConfig {
    pub key_type: String,
    pub key_ref: String,
    pub providers: Vec<String>,
}

const ACTIVE_KEY_TYPE_KEY: &str = "active_key_type";
const ACTIVE_KEY_REF_KEY: &str = "active_key_ref";
const ACTIVE_KEY_PROVIDERS_KEY: &str = "active_key_providers";

/// Returns the current active key config, or `None` if no key is active.
pub fn get_active_key_config() -> Result<Option<ActiveKeyConfig>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;

    let key_type: Option<String> = conn
        .query_row(
            "SELECT CAST(value AS TEXT) FROM config WHERE key = ?1",
            params![ACTIVE_KEY_TYPE_KEY],
            |row| row.get(0),
        )
        .ok();

    match key_type.as_deref() {
        None | Some("") => return Ok(None),
        _ => {}
    }

    let key_ref: String = conn
        .query_row(
            "SELECT CAST(value AS TEXT) FROM config WHERE key = ?1",
            params![ACTIVE_KEY_REF_KEY],
            |row| row.get(0),
        )
        .unwrap_or_default();

    let providers_json: String = conn
        .query_row(
            "SELECT CAST(value AS TEXT) FROM config WHERE key = ?1",
            params![ACTIVE_KEY_PROVIDERS_KEY],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "[]".to_string());

    let providers: Vec<String> = serde_json::from_str(&providers_json).unwrap_or_default();

    Ok(Some(ActiveKeyConfig {
        key_type: key_type.unwrap_or_default(),
        key_ref,
        providers,
    }))
}

/// Persists the active key configuration (upserts three config rows).
pub fn set_active_key_config(cfg: &ActiveKeyConfig) -> Result<(), String> {
    let conn = open_connection()?;
    let providers_json = serde_json::to_string(&cfg.providers)
        .map_err(|e| format!("Failed to serialize providers: {}", e))?;

    for (k, v) in &[
        (ACTIVE_KEY_TYPE_KEY, cfg.key_type.as_str()),
        (ACTIVE_KEY_REF_KEY, cfg.key_ref.as_str()),
    ] {
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![k, v.as_bytes().to_vec()],
        )
        .map_err(|e| format!("Failed to write active key config '{}': {}", k, e))?;
    }
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
        params![ACTIVE_KEY_PROVIDERS_KEY, providers_json.as_bytes().to_vec()],
    )
    .map_err(|e| format!("Failed to write active key config providers: {}", e))?;

    Ok(())
}

/// Clears all three active key config rows (no key active).
pub fn clear_active_key_config() -> Result<(), String> {
    let conn = open_connection()?;
    for k in &[ACTIVE_KEY_TYPE_KEY, ACTIVE_KEY_REF_KEY, ACTIVE_KEY_PROVIDERS_KEY] {
        conn.execute(
            "DELETE FROM config WHERE key = ?1",
            params![k],
        )
        .map_err(|e| format!("Failed to clear active key config '{}': {}", k, e))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generic text config helpers
// ---------------------------------------------------------------------------

const SESSION_BACKEND_KEY: &str = "session.backend";

/// Read a plain-text config value. Returns `None` if the key is absent or the
/// vault does not exist yet.
pub fn get_text_config(key: &str) -> Option<String> {
    let db_path = get_vault_path().ok()?;
    if !db_path.exists() {
        return None;
    }
    let conn = open_connection().ok()?;
    conn.query_row(
        "SELECT CAST(value AS TEXT) FROM config WHERE key = ?",
        params![key],
        |row| row.get::<_, String>(0),
    ).ok()
}

/// Write a plain-text config value. Silent on failure.
pub fn set_text_config(key: &str, value: &str) {
    if let Ok(conn) = open_connection() {
        let _ = conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![key, value],
        );
    }
}

/// Returns the user's preferred session backend: `"keychain"`, `"file"`, `"disabled"`,
/// or `None` if the user has not yet been asked.
pub fn get_session_backend_pref() -> Option<String> {
    get_text_config(SESSION_BACKEND_KEY)
}

/// Persist the session backend preference.
pub fn set_session_backend_pref(pref: &str) {
    set_text_config(SESSION_BACKEND_KEY, pref);
}

// ---------------------------------------------------------------------------
// Team-managed virtual key cache
// ---------------------------------------------------------------------------

/// Row from `managed_virtual_keys_cache`.
#[derive(Debug, Clone)]
pub struct VirtualKeyCacheEntry {
    pub virtual_key_id: String,
    pub org_id: String,
    pub seat_id: String,
    /// Server-assigned alias (authoritative, never modified locally).
    pub alias: String,
    pub provider_code: String,
    pub protocol_type: String,
    pub base_url: String,
    pub credential_id: String,
    pub credential_revision: String,
    pub virtual_key_revision: String,
    pub key_status: String,
    pub share_status: String,
    /// `synced_inactive` | `active` — controls proxy routing.
    pub local_state: String,
    pub expires_at: Option<i64>,
    pub provider_key_nonce: Option<Vec<u8>>,
    pub provider_key_ciphertext: Option<Vec<u8>>,
    pub synced_at: i64,
    /// User-set local display name (`aikey key alias`). `None` → use server alias.
    pub local_alias: Option<String>,
    /// Provider codes this key supports (e.g. `["anthropic"]`), parsed from JSON.
    /// Populated from delivery payload slots at accept/sync time.
    /// Used by `aikey use` to write the correct provider env vars.
    pub supported_providers: Vec<String>,
    /// Per-provider upstream base URLs (JSON object). Keys: provider code, Values: base URL.
    /// Populated from delivery payload slots; empty map until first key accept/sync.
    pub provider_base_urls: std::collections::HashMap<String, String>,
}

/// Inserts or replaces a cache entry.
/// `provider_key_nonce` / `provider_key_ciphertext` may be `None` until the key is accepted.
pub fn upsert_virtual_key_cache(entry: &VirtualKeyCacheEntry) -> Result<(), String> {
    let conn = open_connection()?;
    let supported_providers_json = serde_json::to_string(&entry.supported_providers)
        .unwrap_or_else(|_| "[]".to_string());
    let provider_base_urls_json = serde_json::to_string(&entry.provider_base_urls)
        .unwrap_or_else(|_| "{}".to_string());
    conn.execute(
        "INSERT OR REPLACE INTO managed_virtual_keys_cache (
             virtual_key_id, org_id, seat_id, alias,
             provider_code, protocol_type, base_url,
             credential_id, credential_revision, virtual_key_revision,
             key_status, share_status, local_state,
             expires_at,
             provider_key_nonce, provider_key_ciphertext,
             cache_schema_version, synced_at,
             local_alias, supported_providers,
             provider_base_urls
         ) VALUES (
             ?1,  ?2,  ?3,  ?4,
             ?5,  ?6,  ?7,
             ?8,  ?9,  ?10,
             ?11, ?12, ?13,
             ?14,
             ?15, ?16,
             1,   strftime('%s', 'now'),
             ?17, ?18,
             ?19
         )",
        params![
            entry.virtual_key_id,
            entry.org_id,
            entry.seat_id,
            entry.alias,
            entry.provider_code,
            entry.protocol_type,
            entry.base_url,
            entry.credential_id,
            entry.credential_revision,
            entry.virtual_key_revision,
            entry.key_status,
            entry.share_status,
            entry.local_state,
            entry.expires_at,
            entry.provider_key_nonce,
            entry.provider_key_ciphertext,
            entry.local_alias,
            supported_providers_json,
            provider_base_urls_json,
        ],
    )
    .map_err(|e| format!("Failed to upsert virtual key cache: {}", e))?;
    Ok(())
}

/// Parses a JSON array string into a `Vec<String>`, returning empty vec on failure.
fn parse_providers_json(json: Option<String>) -> Vec<String> {
    json.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Parses a JSON object string into a `HashMap<String, String>`, returning empty map on failure.
fn parse_base_urls_json(json: Option<String>) -> std::collections::HashMap<String, String> {
    json.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Returns all cached virtual key entries.
pub fn list_virtual_key_cache() -> Result<Vec<VirtualKeyCacheEntry>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(vec![]);
    }
    let conn = open_connection()?;
    let mut stmt = conn
        .prepare(
            "SELECT virtual_key_id, org_id, seat_id, alias,
                    provider_code, protocol_type, base_url,
                    credential_id, credential_revision, virtual_key_revision,
                    key_status, share_status, local_state,
                    expires_at,
                    provider_key_nonce, provider_key_ciphertext,
                    synced_at, local_alias, supported_providers,
                    provider_base_urls
               FROM managed_virtual_keys_cache
              ORDER BY COALESCE(local_alias, alias)",
        )
        .map_err(|e| format!("Failed to prepare list query: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(VirtualKeyCacheEntry {
                virtual_key_id: row.get(0)?,
                org_id: row.get(1)?,
                seat_id: row.get(2)?,
                alias: row.get(3)?,
                provider_code: row.get(4)?,
                protocol_type: row.get(5)?,
                base_url: row.get(6)?,
                credential_id: row.get(7)?,
                credential_revision: row.get(8)?,
                virtual_key_revision: row.get(9)?,
                key_status: row.get(10)?,
                share_status: row.get(11)?,
                local_state: row.get(12)?,
                expires_at: row.get(13)?,
                provider_key_nonce: row.get(14)?,
                provider_key_ciphertext: row.get(15)?,
                synced_at: row.get(16)?,
                local_alias: row.get(17)?,
                supported_providers: parse_providers_json(row.get(18)?),
                provider_base_urls: parse_base_urls_json(row.get(19)?),
            })
        })
        .map_err(|e| format!("Failed to query virtual key cache: {}", e))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to read virtual key cache rows: {}", e))
}

/// Returns a single cached entry by virtual_key_id, or `None`.
pub fn get_virtual_key_cache(virtual_key_id: &str) -> Result<Option<VirtualKeyCacheEntry>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    let result = conn.query_row(
        "SELECT virtual_key_id, org_id, seat_id, alias,
                provider_code, protocol_type, base_url,
                credential_id, credential_revision, virtual_key_revision,
                key_status, share_status, local_state,
                expires_at,
                provider_key_nonce, provider_key_ciphertext,
                synced_at, local_alias, supported_providers,
                provider_base_urls
           FROM managed_virtual_keys_cache
          WHERE virtual_key_id = ?1",
        params![virtual_key_id],
        |row| {
            Ok(VirtualKeyCacheEntry {
                virtual_key_id: row.get(0)?,
                org_id: row.get(1)?,
                seat_id: row.get(2)?,
                alias: row.get(3)?,
                provider_code: row.get(4)?,
                protocol_type: row.get(5)?,
                base_url: row.get(6)?,
                credential_id: row.get(7)?,
                credential_revision: row.get(8)?,
                virtual_key_revision: row.get(9)?,
                key_status: row.get(10)?,
                share_status: row.get(11)?,
                local_state: row.get(12)?,
                expires_at: row.get(13)?,
                provider_key_nonce: row.get(14)?,
                provider_key_ciphertext: row.get(15)?,
                synced_at: row.get(16)?,
                local_alias: row.get(17)?,
                supported_providers: parse_providers_json(row.get(18)?),
                provider_base_urls: parse_base_urls_json(row.get(19)?),
            })
        },
    );
    match result {
        Ok(entry) => Ok(Some(entry)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get virtual key cache entry: {}", e)),
    }
}

/// Looks up a cached entry by alias (tries `local_alias` first, then `alias`).
/// Returns `None` if no entry matches.
pub fn get_virtual_key_cache_by_alias(alias: &str) -> Result<Option<VirtualKeyCacheEntry>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    let result = conn.query_row(
        "SELECT virtual_key_id, org_id, seat_id, alias,
                provider_code, protocol_type, base_url,
                credential_id, credential_revision, virtual_key_revision,
                key_status, share_status, local_state,
                expires_at,
                provider_key_nonce, provider_key_ciphertext,
                synced_at, local_alias, supported_providers,
                provider_base_urls
           FROM managed_virtual_keys_cache
          WHERE local_alias = ?1 OR alias = ?1
          ORDER BY CASE WHEN local_alias = ?1 THEN 0 ELSE 1 END
          LIMIT 1",
        params![alias],
        |row| {
            Ok(VirtualKeyCacheEntry {
                virtual_key_id: row.get(0)?,
                org_id: row.get(1)?,
                seat_id: row.get(2)?,
                alias: row.get(3)?,
                provider_code: row.get(4)?,
                protocol_type: row.get(5)?,
                base_url: row.get(6)?,
                credential_id: row.get(7)?,
                credential_revision: row.get(8)?,
                virtual_key_revision: row.get(9)?,
                key_status: row.get(10)?,
                share_status: row.get(11)?,
                local_state: row.get(12)?,
                expires_at: row.get(13)?,
                provider_key_nonce: row.get(14)?,
                provider_key_ciphertext: row.get(15)?,
                synced_at: row.get(16)?,
                local_alias: row.get(17)?,
                supported_providers: parse_providers_json(row.get(18)?),
                provider_base_urls: parse_base_urls_json(row.get(19)?),
            })
        },
    );
    match result {
        Ok(entry) => Ok(Some(entry)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get virtual key cache entry by alias: {}", e)),
    }
}

/// Sets all team virtual key entries to `local_state = 'synced_inactive'`.
/// Called by `aikey use` before activating a new key (global mutex).
pub fn set_all_virtual_keys_inactive() -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache
            SET local_state = 'synced_inactive',
                synced_at   = strftime('%s', 'now')
          WHERE local_state = 'active'",
        [],
    )
    .map_err(|e| format!("Failed to deactivate all virtual keys: {}", e))?;
    Ok(())
}

/// Returns the `provider_code` stored for a personal key (entries table), or `None`.
/// Returns `None` if the entry does not exist or has no provider code.
pub fn get_entry_provider_code(alias: &str) -> Result<Option<String>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    let result: rusqlite::Result<Option<String>> = conn.query_row(
        "SELECT provider_code FROM entries WHERE alias = ?1",
        params![alias],
        |row| row.get(0),
    );
    match result {
        Ok(code) => Ok(code),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to get entry provider_code: {}", e)),
    }
}

/// Sets the `provider_code` for a personal key entry.
/// Pass `None` to clear the provider code.
pub fn set_entry_provider_code(alias: &str, provider_code: Option<&str>) -> Result<(), String> {
    let conn = open_connection()?;
    let rows = conn.execute(
        "UPDATE entries SET provider_code = ?1 WHERE alias = ?2",
        params![provider_code, alias],
    )
    .map_err(|e| format!("Failed to set entry provider_code: {}", e))?;
    if rows == 0 {
        return Err(format!("Entry '{}' not found", alias));
    }
    Ok(())
}

/// Returns the custom upstream `base_url` for a personal key entry.
/// Returns `None` if not set (proxy or SDK uses provider default).
pub fn get_entry_base_url(alias: &str) -> Result<Option<String>, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_connection()?;
    let result: rusqlite::Result<Option<String>> = conn.query_row(
        "SELECT base_url FROM entries WHERE alias = ?1",
        params![alias],
        |row| row.get(0),
    );
    match result {
        Ok(url) => Ok(url),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(_) => Ok(None), // column may not exist on older vaults
    }
}

/// Sets the custom upstream `base_url` for a personal key entry.
/// Pass `None` to clear (proxy will fall back to the provider default).
pub fn set_entry_base_url(alias: &str, base_url: Option<&str>) -> Result<(), String> {
    let conn = open_connection()?;
    let rows = conn.execute(
        "UPDATE entries SET base_url = ?1 WHERE alias = ?2",
        params![base_url, alias],
    )
    .map_err(|e| format!("Failed to set entry base_url: {}", e))?;
    if rows == 0 {
        return Err(format!("Entry '{}' not found", alias));
    }
    Ok(())
}

/// Sets a user-defined local alias for a cached key.
/// Pass `None` to clear the local alias and revert to the server alias.
pub fn set_virtual_key_local_alias(
    virtual_key_id: &str,
    local_alias: Option<&str>,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache
            SET local_alias = ?1, synced_at = strftime('%s', 'now')
          WHERE virtual_key_id = ?2",
        params![local_alias, virtual_key_id],
    )
    .map_err(|e| format!("Failed to update local_alias: {}", e))?;
    Ok(())
}

/// Sets `local_state` for a cached key (e.g., `"active"` or `"synced_inactive"`).
pub fn set_virtual_key_local_state(virtual_key_id: &str, local_state: &str) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache
            SET local_state = ?1, synced_at = strftime('%s', 'now')
          WHERE virtual_key_id = ?2",
        params![local_state, virtual_key_id],
    )
    .map_err(|e| format!("Failed to update local_state: {}", e))?;
    Ok(())
}

/// Updates `share_status` in the local cache (mirrors server state after claim).
pub fn set_virtual_key_share_status_local(
    virtual_key_id: &str,
    share_status: &str,
) -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute(
        "UPDATE managed_virtual_keys_cache
            SET share_status = ?1, synced_at = strftime('%s', 'now')
          WHERE virtual_key_id = ?2",
        params![share_status, virtual_key_id],
    )
    .map_err(|e| format!("Failed to update share_status: {}", e))?;
    Ok(())
}

/// Counts entries with `share_status = 'pending_claim'` that have NOT been
/// dismissed by the user (`local_state != 'prompt_dismissed'`).
/// Used for the non-intrusive startup hint (no vault auth required).
pub fn count_pending_virtual_keys() -> Result<usize, String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Ok(0);
    }
    let conn = open_connection()?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM managed_virtual_keys_cache
              WHERE share_status = 'pending_claim'
                AND key_status   = 'active'
                AND local_state  != 'prompt_dismissed'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("Failed to count pending keys: {}", e))?;
    Ok(count as usize)
}

/// Marks the given virtual key IDs as `local_state = 'prompt_dismissed'` so
/// the startup pending-key prompt never fires for them again.
/// Called when the user presses N at the accept prompt.
pub fn dismiss_pending_keys(virtual_key_ids: &[String]) -> Result<(), String> {
    if virtual_key_ids.is_empty() {
        return Ok(());
    }
    let conn = open_connection()?;
    for id in virtual_key_ids {
        conn.execute(
            "UPDATE managed_virtual_keys_cache
                SET local_state = 'prompt_dismissed',
                    synced_at   = strftime('%s', 'now')
              WHERE virtual_key_id = ?1
                AND share_status   = 'pending_claim'",
            params![id],
        )
        .map_err(|e| format!("Failed to dismiss key {}: {}", id, e))?;
    }
    Ok(())
}
