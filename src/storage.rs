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
}

/// Default vault directory path
const VAULT_DIR: &str = ".aikey";

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
    // PRAGMA commands don't return rows, so we use prepare and execute
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(|e| format!("Failed to enable secure delete: {}", e))?;

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

    Ok(())
}


/// Checks if the vault exists, returns an error if it doesn't
pub fn ensure_vault_exists() -> Result<(), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault already initialized. Use 'ak reset' to reinitialize.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
    }

    let conn = open_connection()?;

    let mut stmt = conn
        .prepare("SELECT alias, created_at FROM entries ORDER BY alias")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let entries = stmt
        .query_map([], |row| {
            let alias: String = row.get(0)?;
            let created_at: Option<i64> = row.get(1).ok();
            Ok((alias, created_at))
        })
        .map_err(|e| format!("Failed to query entries: {}", e))?
        .collect::<SqlResult<Vec<(String, Option<i64>)>>>()
        .map_err(|e| format!("Failed to collect results: {}", e))?;

    let metadata: Vec<SecretMetadata> = entries
        .into_iter()
        .map(|(alias, created_at)| {
            SecretMetadata {
                alias,
                created_at,
            }
        })
        .collect();

    Ok(metadata)
}

/// Deletes an entry from the vault
pub fn delete_entry(alias: &str) -> Result<(), String> {
    let db_path = get_vault_path()?;

    if !db_path.exists() {
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
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
