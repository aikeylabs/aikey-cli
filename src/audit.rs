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
    /// A provider-binding write (Primary switch / auto-assign / reconcile
    /// replacement). Added 2026-07-06: the incident binding write had NO audit
    /// row, making "who bound this key" unanswerable — every write through
    /// `write_bindings_canonical` now signs one Bind row when the caller holds
    /// a `VerifiedVaultKey`. Pure enum addition — operation is a TEXT column,
    /// no migration; `verify_audit_log` recomputes HMAC over the raw string.
    Bind,
}

impl AuditOperation {
    pub fn as_str(&self) -> &'static str {
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
            AuditOperation::Bind => "bind",
        }
    }
}

/// A 32-byte vault key PROVEN to match this vault's stored password_hash.
///
/// Why a newtype (2026-07-06, B-2 protocol hardening): audit rows are
/// HMAC-signed with an audit_key derived from the vault key. A row signed with
/// a WRONG key doesn't fail at write time — it surfaces later as a bogus
/// "tampered" verdict from `verify_audit_log`, poisoning the whole chain's
/// trustworthiness. The ONLY constructor runs `storage::verify_vault_key`, so
/// the type system guarantees every signer input was checked against the vault
/// (one cheap SQLite read per command; same chokepoint contract as the
/// 2026-05-11 snapshot-sync strict-verify fix).
pub struct VerifiedVaultKey([u8; 32]);

impl VerifiedVaultKey {
    /// Verifies `key` against the vault's stored password_hash. Err when the
    /// key doesn't match (stale web session, wrong derivation) — callers must
    /// surface that, not sign with it.
    pub fn new(key: [u8; 32]) -> Result<Self, String> {
        storage::verify_vault_key(&key)?;
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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
/// 从已派生的 vault_key 通过 HKDF-lite 派生 audit_key（`_internal` IPC 路径专用）
///
/// # 决策说明（Stage 2 Phase F）
/// 现有 `derive_audit_key(password)` 要求明文密码，但 `_internal` IPC 只接收 vault_key_hex
/// （Argon2id 派生结果）。两条方案对比：
///
/// - **方案 1（选中）**：HMAC-SHA256(vault_key, "AK_AUDIT_V2") → audit_key
///   - 优点：协议零改动；性能成本 O(μs)；vault_key 本身已是 Argon2id 输出
///   - 代价：audit 链"绑定 vault_key"，而非"绑定 password" —— 但 change_password 后原有
///     audit 同样无法用新 audit_key 验证（现有 derive_audit_key 行为一致），语义等价
/// - **方案 2（未选）**：envelope 加 `audit_key_hex` 字段，Go local-server 在 unlock 时
///   双派生。代价：Argon2id 开销翻倍（unlock 慢 ~50ms），协议破坏性变更
///
/// Why HMAC 而非 HKDF：单次 32 字节输出 + 有 key material → HMAC-SHA256 与 HKDF-Expand
/// 在密码学上等价，但无需引入 `hkdf` crate 新依赖。
pub fn derive_audit_key_from_vault_key(vault_key: &[u8; 32]) -> Result<[u8; 32], String> {
    let mut mac = HmacSha256::new_from_slice(vault_key)
        .map_err(|e| format!("HMAC init for audit key: {}", e))?;
    mac.update(b"AK_AUDIT_V2:audit-v1");
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    Ok(key)
}

/// `_internal` IPC 路径的 audit 日志入口：用 vault_key 派生 audit_key，走同款 HMAC 签名
pub fn log_audit_event_from_vault_key(
    vault_key: &[u8; 32],
    operation: AuditOperation,
    alias: Option<&str>,
    success: bool,
) -> Result<(), String> {
    let audit_key = derive_audit_key_from_vault_key(vault_key)?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Failed to get timestamp: {}", e))?
        .as_secs() as i64;

    let hmac = compute_audit_hmac(&audit_key, timestamp, operation.as_str(), alias, success)?;

    let conn = storage::open_connection()?;
    conn.execute(
        "INSERT INTO audit_log (timestamp, operation, alias, success, hmac) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![timestamp, operation.as_str(), alias, if success { 1 } else { 0 }, hmac],
    )
    .map_err(|e| format!("Failed to insert audit log (from vault_key): {}", e))?;

    Ok(())
}

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
    // V2 acceptance (bugfix 2026-07-06, exposed by the B-2 bind-audit tests):
    // rows written through `log_audit_event_from_vault_key` (the `_internal`
    // web-bridge path since 2026-05, and B-2 bind rows) are signed with
    // HMAC(vault_key, "AK_AUDIT_V2") — a DIFFERENT key than V1's
    // Argon2(password, AK_AUDIT_SALT_V1). The verifier only ever tried V1, so
    // every V2-signed row read as "tampered" (false positive). A row now
    // verifies if EITHER derivation matches; both keys come from the same
    // password, so the tamper-evidence property is unchanged. Best-effort on
    // the V2 key: absent salt/kdf params (pre-vault state) just skips V2.
    let audit_key_v2: Option<[u8; 32]> = (|| {
        let salt = storage::get_salt().ok()?;
        let (m, t, p) = storage::get_kdf_params().ok()?;
        let vault_key = crypto::derive_key_with_params(password, &salt, m, t, p).ok()?;
        derive_audit_key_from_vault_key(&vault_key).ok()
    })();
    let conn = storage::open_connection()?;

    let mut stmt = conn
        .prepare("SELECT id, timestamp, operation, alias, success, hmac FROM audit_log ORDER BY id")
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let mut rows = stmt
        .query([])
        .map_err(|e| format!("Failed to query audit log: {}", e))?;

    let mut verified_count = 0;
    let mut tampered_ids = Vec::new();

    while let Some(row) = rows
        .next()
        .map_err(|e| format!("Failed to read row: {}", e))?
    {
        let id: i64 = row.get(0).map_err(|e| format!("Failed to get id: {}", e))?;
        let timestamp: i64 = row
            .get(1)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?;
        let operation: String = row
            .get(2)
            .map_err(|e| format!("Failed to get operation: {}", e))?;
        let alias: Option<String> = row
            .get(3)
            .map_err(|e| format!("Failed to get alias: {}", e))?;
        let success: i32 = row
            .get(4)
            .map_err(|e| format!("Failed to get success: {}", e))?;
        let stored_hmac: String = row
            .get(5)
            .map_err(|e| format!("Failed to get hmac: {}", e))?;

        // Recompute HMAC — V1 first (bulk of historic rows), then V2
        // (vault_key-signed rows from the web bridge / B-2 bind rows).
        let v1_hmac = compute_audit_hmac(
            &*audit_key,
            timestamp,
            &operation,
            alias.as_deref(),
            success != 0,
        )?;
        let mut matches = v1_hmac == stored_hmac;
        if !matches {
            if let Some(k2) = &audit_key_v2 {
                let v2_hmac =
                    compute_audit_hmac(k2, timestamp, &operation, alias.as_deref(), success != 0)?;
                matches = v2_hmac == stored_hmac;
            }
        }
        if !matches {
            tampered_ids.push(id);
        }

        verified_count += 1;
    }

    Ok((verified_count, tampered_ids))
}
