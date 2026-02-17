//! Audit Logging Module
//!
//! Provides tamper-proof audit logging with HMAC verification.
//! All vault operations are logged with timestamps and HMAC signatures
//! to detect tampering and provide forensic capability.

use crate::crypto;
use crate::storage;
use hmac::{Hmac, Mac};
use rusqlite::params;
use secrecy::SecretString;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Audit log operation types
#[derive(Debug, Clone, Copy)]
pub enum AuditOperation {
    Init,
    Add,
    Get,
    Update,
    Delete,
    List,
    Export,
    Import,
    Exec,
}

impl AuditOperation {
    fn as_str(&self) -> &'static str {
        match self {
            AuditOperation::Init => "init",
            AuditOperation::Add => "add",
            AuditOperation::Get => "get",
            AuditOperation::Update => "update",
            AuditOperation::Delete => "delete",
            AuditOperation::List => "list",
            AuditOperation::Export => "export",
            AuditOperation::Import => "import",
            AuditOperation::Exec => "exec",
        }
    }
}

/// Initialize audit log table
pub fn initialize_audit_log() -> Result<(), String> {
    let conn = storage::open_connection()?;

    // Create audit_log table if it doesn't exist
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

    // Create index on timestamp for efficient queries
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
        [],
    )
    .map_err(|e| format!("Failed to create audit index: {}", e))?;

    Ok(())
}

/// Derives an audit key from the master password
///
/// Uses a different salt than the encryption key to ensure key separation.
/// The audit key is used to compute HMACs for tamper detection.
fn derive_audit_key(password: &SecretString) -> Result<crypto::SecureBuffer<[u8; 32]>, String> {
    // Use a fixed salt for audit key derivation (different from vault salt)
    // This ensures audit logs can be verified even if vault is re-initialized
    let audit_salt = b"AK_AUDIT_SALT_V1";
    crypto::derive_key(password, audit_salt)
}

/// Computes HMAC for an audit log entry
fn compute_audit_hmac(
    audit_key: &[u8; 32],
    timestamp: i64,
    operation: &str,
    alias: Option<&str>,
    success: bool,
) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(audit_key)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;

    // Include all fields in HMAC computation
    mac.update(timestamp.to_le_bytes().as_ref());
    mac.update(operation.as_bytes());
    if let Some(a) = alias {
        mac.update(a.as_bytes());
    }
    mac.update(&[if success { 1u8 } else { 0u8 }]);

    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Logs an audit event
///
/// # Arguments
/// * `password` - Master password (used to derive audit key)
/// * `operation` - Type of operation performed
/// * `alias` - Optional secret alias (if applicable)
/// * `success` - Whether the operation succeeded
pub fn log_audit_event(
    password: &SecretString,
    operation: AuditOperation,
    alias: Option<&str>,
    success: bool,
) -> Result<(), String> {
    // Derive audit key
    let audit_key = derive_audit_key(password)?;

    // Get current timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Failed to get timestamp: {}", e))?
        .as_secs() as i64;

    // Compute HMAC
    let hmac = compute_audit_hmac(&*audit_key, timestamp, operation.as_str(), alias, success)?;

    // Insert into audit log
    let conn = storage::open_connection()?;
    conn.execute(
        "INSERT INTO audit_log (timestamp, operation, alias, success, hmac) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![timestamp, operation.as_str(), alias, if success { 1 } else { 0 }, hmac],
    )
    .map_err(|e| format!("Failed to insert audit log: {}", e))?;

    Ok(())
}

/// Verifies the integrity of audit logs
///
/// Recomputes HMACs for all entries and checks for tampering.
/// Returns the number of entries verified and any tampered entries.
pub fn verify_audit_log(password: &SecretString) -> Result<(usize, Vec<i64>), String> {
    let audit_key = derive_audit_key(password)?;
    let conn = storage::open_connection()?;

    let mut stmt = conn
        .prepare("SELECT id, timestamp, operation, alias, success, hmac FROM audit_log ORDER BY id")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let mut rows = stmt
        .query([])
        .map_err(|e| format!("Failed to query audit log: {}", e))?;

    let mut verified_count = 0;
    let mut tampered_ids = Vec::new();

    while let Some(row) = rows.next().map_err(|e| format!("Failed to read row: {}", e))? {
        let id: i64 = row.get(0).map_err(|e| format!("Failed to get id: {}", e))?;
        let timestamp: i64 = row.get(1).map_err(|e| format!("Failed to get timestamp: {}", e))?;
        let operation: String = row.get(2).map_err(|e| format!("Failed to get operation: {}", e))?;
        let alias: Option<String> = row.get(3).map_err(|e| format!("Failed to get alias: {}", e))?;
        let success: i32 = row.get(4).map_err(|e| format!("Failed to get success: {}", e))?;
        let stored_hmac: String = row.get(5).map_err(|e| format!("Failed to get hmac: {}", e))?;

        // Recompute HMAC
        let computed_hmac = compute_audit_hmac(
            &*audit_key,
            timestamp,
            &operation,
            alias.as_deref(),
            success != 0,
        )?;

        if computed_hmac != stored_hmac {
            tampered_ids.push(id);
        }

        verified_count += 1;
    }

    Ok((verified_count, tampered_ids))
}

