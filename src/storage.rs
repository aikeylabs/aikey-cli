//! Storage layer for AiKeyLabs vault
use rusqlite::{params, Connection, Result as SqlResult};
use secrecy::{SecretString, ExposeSecret};
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const VAULT_DIR: &str = ".aikey";
const DB_NAME: &str = "vault.db";

pub fn get_vault_path() -> Result<PathBuf, String> {
    if let Ok(test_path) = std::env::var("AK_VAULT_PATH").or_else(|_| std::env::var("AK_STORAGE_PATH")) {
        let path = PathBuf::from(test_path);
        if path.extension().and_then(|e| e.to_str()) == Some("db") {
            return Ok(path);
        } else {
            return Ok(path.join(DB_NAME));
        }
    }
    let home = std::env::var("HOME").map_err(|_| "Could not determine home directory".to_string())?;
    let vault_dir = PathBuf::from(home).join(VAULT_DIR);
    Ok(vault_dir.join(DB_NAME))
}

pub fn ensure_vault_exists() -> Result<(), String> {
    let db_path = get_vault_path()?;
    if !db_path.exists() {
        return Err("Vault not initialized. Run 'ak init' first.".to_string());
    }
    Ok(())
}

pub fn initialize_vault(salt: &[u8]) -> Result<(), String> {
    let vault_dir = if let Ok(test_path) = std::env::var("AK_VAULT_PATH").or_else(|_| std::env::var("AK_STORAGE_PATH")) {
        PathBuf::from(test_path)
    } else {
        let home = std::env::var("HOME").map_err(|_| "Could not determine home directory".to_string())?;
        PathBuf::from(home).join(VAULT_DIR)
    };

    if !vault_dir.exists() {
        fs::create_dir(&vault_dir).map_err(|e| format!("Failed to create vault directory: {}", e))?;
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&vault_dir).map_err(|e| format!("Failed to read directory metadata: {}", e))?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&vault_dir, perms).map_err(|e| format!("Failed to set directory permissions: {}", e))?;
        }
    }

    let db_path = vault_dir.join(DB_NAME);
    if db_path.exists() {
        return Err("Vault already initialized. Use 'ak reset' to reinitialize.".to_string());
    }

    let conn = Connection::open(&db_path).map_err(|e| format!("Failed to create database: {}", e))?;

    #[cfg(unix)]
    {
        let metadata = fs::metadata(&db_path).map_err(|e| format!("Failed to read database metadata: {}", e))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&db_path, perms).map_err(|e| format!("Failed to set database permissions: {}", e))?;
    }

    conn.execute("CREATE TABLE config (key TEXT PRIMARY KEY, value BLOB NOT NULL)", [])
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
    ).map_err(|e| format!("Failed to create entries table: {}", e))?;

    conn.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", params!["master_salt", salt])
        .map_err(|e| format!("Failed to store salt: {}", e))?;

    let password_raw = std::env::var("AK_MASTER_PASSWORD")
        .map_err(|_| "AK_MASTER_PASSWORD environment variable not set during init".to_string())?;

    let secret_password = SecretString::new(password_raw);
    let key = crate::crypto::derive_key(&secret_password, salt).map_err(|e| format!("Key derivation failed: {}", e))?;
    
    let password_hash = &*key;

    conn.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", params!["password_hash", password_hash])
        .map_err(|e| format!("Failed to store password hash: {}", e))?;

    Ok(())
}

pub fn get_salt() -> Result<Vec<u8>, String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;
    let salt: Vec<u8> = conn.query_row("SELECT value FROM config WHERE key = ?", params!["master_salt"], |row| row.get(0))
        .map_err(|_| "Salt not found in vault.".to_string())?;
    Ok(salt)
}

pub fn store_entry(alias: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<(), String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;
    conn.execute(
        "INSERT INTO entries (alias, nonce, ciphertext, version_tag) VALUES (?1, ?2, ?3, 1)
         ON CONFLICT(alias) DO UPDATE SET nonce = ?2, ciphertext = ?3, version_tag = version_tag + 1",
        params![alias, nonce, ciphertext],
    ).map_err(|e| format!("Failed to store entry: {}", e))?;
    Ok(())
}

pub fn get_entry(alias: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;
    conn.query_row("SELECT nonce, ciphertext FROM entries WHERE alias = ?1", [alias], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| format!("Failed to retrieve entry: {}", e))
}

pub fn get_entries_with_metadata(pattern: &str) -> Result<Vec<(String, Vec<u8>, Vec<u8>, i64, i64, i64, Option<String>)>, String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
    let sql_pattern = pattern.replace('*', "%").replace('?', "_");
    let mut stmt = conn.prepare("SELECT alias, nonce, ciphertext, version_tag, created_at, created_at, metadata FROM entries WHERE alias LIKE ?1").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([&sql_pattern], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))
    }).map_err(|e| e.to_string())?.collect::<SqlResult<Vec<_>>>().map_err(|e| e.to_string())?;
    Ok(rows)
}

pub fn get_entry_with_metadata(alias: &str) -> Result<(Vec<u8>, Vec<u8>, i64, i64, i64, Option<String>), String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
    conn.query_row("SELECT nonce, ciphertext, version_tag, created_at, created_at, metadata FROM entries WHERE alias = ?1", [alias], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
    }).map_err(|e| e.to_string())
}

pub fn update_entry_full(alias: &str, nonce: &[u8], ciphertext: &[u8], version: i64, _up: i64, created: i64, meta: Option<&str>) -> Result<(), String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
    conn.execute("UPDATE entries SET nonce=?2, ciphertext=?3, version_tag=?4, created_at=?5, metadata=?6 WHERE alias=?1", 
        params![alias, nonce, ciphertext, version, created, meta]).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn insert_entry_full(alias: &str, nonce: &[u8], ciphertext: &[u8], version: i64, _up: i64, created: i64, meta: Option<&str>) -> Result<(), String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
    conn.execute("INSERT INTO entries (alias, nonce, ciphertext, version_tag, created_at, metadata) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", 
        params![alias, nonce, ciphertext, version, created, meta]).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn list_entries() -> Result<Vec<String>, String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;
    let mut stmt = conn.prepare("SELECT alias FROM entries ORDER BY alias").map_err(|e| e.to_string())?;
    let aliases = stmt.query_map([], |row| row.get(0)).map_err(|e| e.to_string())?
        .collect::<SqlResult<Vec<String>>>().map_err(|e| e.to_string())?;
    Ok(aliases)
}

pub fn delete_entry(alias: &str) -> Result<(), String> {
    let db_path = get_vault_path()?;
    let conn = Connection::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;
    let rows = conn.execute("DELETE FROM entries WHERE alias = ?1", [alias]).map_err(|e| e.to_string())?;
    if rows == 0 { return Err(format!("Entry '{}' not found", alias)); }
    Ok(())
}
