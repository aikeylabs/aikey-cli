//! `_internal update-alias`：编辑非敏感元数据（alias rename / provider / base_url / metadata）
//!
//! # Actions
//! - `rename_alias`：修改 alias（UNIQUE 约束；冲突时报 I_CREDENTIAL_CONFLICT）
//! - `set_provider`：修改 provider_code（None = 清空）
//! - `set_base_url`：修改 base_url（None = 清空）
//! - `set_supported_providers`：修改 supported_providers（JSON array）
//! - `set_metadata`：修改 metadata 通用 JSON blob（tag / note / enabled / 等由前端自定义）
//!
//! # 设计约束
//! - **所有操作仍需 vault_key 验证**：虽然字段非敏感，但写操作应由 unlock 把关（与 vault-op 对齐）
//! - **不碰 nonce / ciphertext / id**：update-alias 严格不改密文
//! - **rename_alias 的 UNIQUE 约束**：数据库层会报错，协议层翻译为 I_CREDENTIAL_CONFLICT

use serde::Deserialize;
use serde_json::json;

use crate::audit::{self, AuditOperation};
use crate::storage;
use super::protocol::{ResultEnvelope, StdinEnvelope};
use super::stdin_json::{decode_vault_key, emit, emit_error};

/// best-effort audit（同 vault_op 的 try_log_audit）
fn try_log_audit(key: &[u8; 32], op: AuditOperation, alias: Option<&str>, success: bool) -> bool {
    match audit::log_audit_event_from_vault_key(key, op, alias, success) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("[_internal update-alias audit WARN] {} {:?}: {}", op.as_str(), alias, e);
            false
        }
    }
}

// ========== payloads ==========

#[derive(Debug, Deserialize)]
struct RenamePayload {
    old_alias: String,
    new_alias: String,
}

#[derive(Debug, Deserialize)]
struct SetProviderPayload {
    alias: String,
    provider: Option<String>, // null 清空
}

#[derive(Debug, Deserialize)]
struct SetBaseUrlPayload {
    alias: String,
    base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SetSupportedProvidersPayload {
    alias: String,
    providers: Vec<String>, // [] 清空
}

#[derive(Debug, Deserialize)]
struct SetMetadataPayload {
    alias: String,
    /// 任意 JSON blob；null 清空；object 会序列化成字符串存到 entries.metadata 列
    metadata: serde_json::Value,
}

// ========== dispatch ==========

pub fn handle(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    match env.action.as_str() {
        "rename_alias" => handle_rename_alias(env),
        "set_provider" => handle_set_provider(env),
        "set_base_url" => handle_set_base_url(env),
        "set_supported_providers" => handle_set_supported_providers(env),
        "set_metadata" => handle_set_metadata(env),
        other => emit_error(
            req_id,
            "I_UNKNOWN_ACTION",
            format!("unknown update-alias action: '{}'", other),
        ),
    }
}

// ========== helpers ==========

fn prepare(env: &StdinEnvelope) -> Option<([u8; 32], rusqlite::Connection)> {
    let req_id = env.request_id.clone();

    // 只要 key 能匹配 password_hash 就放行
    let key = match decode_vault_key(&env.vault_key_hex) {
        Ok(k) => k,
        Err((c, m)) => { emit_error(req_id, c, m); return None; }
    };
    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id, "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return None;
    }
    let conn = match storage::open_connection() {
        Ok(c) => c,
        Err(e) => { emit_error(req_id, "I_VAULT_OPEN_FAILED", format!("{}", e)); return None; }
    };
    // key verify (password_hash 或空 vault 兜底)
    let stored: Result<Vec<u8>, rusqlite::Error> = conn.query_row(
        "SELECT value FROM config WHERE key = 'password_hash'",
        [],
        |r| r.get(0),
    );
    match stored {
        Ok(hash) if hash.as_slice() == key.as_slice() => Some((key, conn)),
        Ok(_) => {
            emit_error(
                req_id,
                "I_VAULT_KEY_INVALID",
                "vault_key does not match stored password_hash".to_string(),
            );
            None
        }
        Err(_) => {
            // 无 password_hash（兼容旧 vault）
            let entry: Result<(Vec<u8>, Vec<u8>), rusqlite::Error> = conn.query_row(
                "SELECT nonce, ciphertext FROM entries LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            );
            match entry {
                Ok((nonce, ciphertext)) => {
                    if crate::crypto::decrypt(&key, &nonce, &ciphertext).is_ok() {
                        Some((key, conn))
                    } else {
                        emit_error(req_id, "I_VAULT_KEY_INVALID",
                            "vault_key failed to decrypt any entry".to_string());
                        None
                    }
                }
                Err(_) => Some((key, conn)), // 空 vault 兜底
            }
        }
    }
}

fn alias_exists(conn: &rusqlite::Connection, alias: &str) -> Result<bool, (&'static str, String)> {
    conn.query_row(
        "SELECT COUNT(*) FROM entries WHERE alias = ?",
        [alias],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .map_err(|e| ("I_INTERNAL", format!("check alias failed: {}", e)))
}

// ========== rename_alias ==========

fn handle_rename_alias(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: RenamePayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => { emit_error(req_id, "I_STDIN_INVALID_JSON", format!("rename_alias payload: {}", e)); return; }
    };
    if payload.new_alias.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "new_alias must be non-empty");
        return;
    }
    if payload.old_alias == payload.new_alias {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "old_alias and new_alias are identical");
        return;
    }

    let (key, conn) = match prepare(&env) { Some(p) => p, None => return };

    match alias_exists(&conn, &payload.old_alias) {
        Ok(false) => {
            emit_error(req_id, "I_CREDENTIAL_NOT_FOUND",
                format!("alias '{}' not found", payload.old_alias));
            return;
        }
        Err((c, m)) => { emit_error(req_id, c, m); return; }
        Ok(true) => {}
    }
    // new_alias 不能已存在
    match alias_exists(&conn, &payload.new_alias) {
        Ok(true) => {
            emit_error(req_id, "I_CREDENTIAL_CONFLICT",
                format!("new_alias '{}' already exists", payload.new_alias));
            return;
        }
        Err((c, m)) => { emit_error(req_id, c, m); return; }
        Ok(false) => {}
    }

    match conn.execute(
        "UPDATE entries SET alias = ?1 WHERE alias = ?2",
        rusqlite::params![&payload.new_alias, &payload.old_alias],
    ) {
        Ok(n) if n == 1 => {
            let audit_logged = try_log_audit(&key, AuditOperation::Update, Some(&payload.new_alias), true);
            emit(&ResultEnvelope::ok(
                req_id,
                json!({
                    "old_alias": payload.old_alias,
                    "new_alias": payload.new_alias,
                    "action_taken": "renamed",
                    "audit_logged": audit_logged,
                }),
            ));
        }
        Ok(_) => emit_error(req_id, "I_INTERNAL", "UPDATE affected unexpected row count"),
        // UNIQUE 冲突兜底（理论上前面已检查过，但 race window 存在）
        Err(e) if format!("{}", e).contains("UNIQUE") => emit_error(
            req_id, "I_CREDENTIAL_CONFLICT",
            format!("UNIQUE constraint: {}", e)),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("rename_alias UPDATE: {}", e)),
    }
}

// ========== set_provider ==========

fn handle_set_provider(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: SetProviderPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => { emit_error(req_id, "I_STDIN_INVALID_JSON", format!("set_provider payload: {}", e)); return; }
    };

    let (key, conn) = match prepare(&env) { Some(p) => p, None => return };
    if !must_alias_exist(&conn, &req_id, &payload.alias) { return; }

    let affected = conn.execute(
        "UPDATE entries SET provider_code = ?1 WHERE alias = ?2",
        rusqlite::params![payload.provider, &payload.alias],
    );
    match affected {
        Ok(1) => {
            let audit_logged = try_log_audit(&key, AuditOperation::Update, Some(&payload.alias), true);
            emit(&ResultEnvelope::ok(
                req_id,
                json!({
                    "alias": payload.alias,
                    "provider_code": payload.provider,
                    "action_taken": "updated",
                    "audit_logged": audit_logged,
                }),
            ));
        }
        Ok(_) => emit_error(req_id, "I_INTERNAL", "UPDATE affected unexpected row count"),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("set_provider UPDATE: {}", e)),
    }
}

// ========== set_base_url ==========

fn handle_set_base_url(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: SetBaseUrlPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => { emit_error(req_id, "I_STDIN_INVALID_JSON", format!("set_base_url payload: {}", e)); return; }
    };

    let (key, conn) = match prepare(&env) { Some(p) => p, None => return };
    if !must_alias_exist(&conn, &req_id, &payload.alias) { return; }

    let affected = conn.execute(
        "UPDATE entries SET base_url = ?1 WHERE alias = ?2",
        rusqlite::params![payload.base_url, &payload.alias],
    );
    match affected {
        Ok(1) => {
            let audit_logged = try_log_audit(&key, AuditOperation::Update, Some(&payload.alias), true);
            emit(&ResultEnvelope::ok(
                req_id,
                json!({
                    "alias": payload.alias,
                    "base_url": payload.base_url,
                    "action_taken": "updated",
                    "audit_logged": audit_logged,
                }),
            ));
        }
        Ok(_) => emit_error(req_id, "I_INTERNAL", "UPDATE affected unexpected row count"),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("set_base_url UPDATE: {}", e)),
    }
}

// ========== set_supported_providers ==========

fn handle_set_supported_providers(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: SetSupportedProvidersPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => { emit_error(req_id, "I_STDIN_INVALID_JSON", format!("set_supported_providers payload: {}", e)); return; }
    };

    let (key, conn) = match prepare(&env) { Some(p) => p, None => return };
    if !must_alias_exist(&conn, &req_id, &payload.alias) { return; }

    // 存为 JSON 字符串（与现有 supported_providers 读取路径对齐，见 storage.rs line 472 / 498）
    let json_blob = match serde_json::to_string(&payload.providers) {
        Ok(s) => s,
        Err(e) => { emit_error(req_id, "I_INTERNAL", format!("serialize providers: {}", e)); return; }
    };

    let affected = conn.execute(
        "UPDATE entries SET supported_providers = ?1 WHERE alias = ?2",
        rusqlite::params![&json_blob, &payload.alias],
    );
    match affected {
        Ok(1) => {
            let audit_logged = try_log_audit(&key, AuditOperation::Update, Some(&payload.alias), true);
            emit(&ResultEnvelope::ok(
                req_id,
                json!({
                    "alias": payload.alias,
                    "supported_providers": payload.providers,
                    "action_taken": "updated",
                    "audit_logged": audit_logged,
                }),
            ));
        }
        Ok(_) => emit_error(req_id, "I_INTERNAL", "UPDATE affected unexpected row count"),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("set_supported_providers UPDATE: {}", e)),
    }
}

// ========== set_metadata ==========

fn handle_set_metadata(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: SetMetadataPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => { emit_error(req_id, "I_STDIN_INVALID_JSON", format!("set_metadata payload: {}", e)); return; }
    };

    let (key, conn) = match prepare(&env) { Some(p) => p, None => return };
    if !must_alias_exist(&conn, &req_id, &payload.alias) { return; }

    // metadata 列允许 NULL；payload.metadata==null → 清空
    let stored: Option<String> = if payload.metadata.is_null() {
        None
    } else {
        match serde_json::to_string(&payload.metadata) {
            Ok(s) => Some(s),
            Err(e) => { emit_error(req_id, "I_INTERNAL", format!("serialize metadata: {}", e)); return; }
        }
    };

    let affected = conn.execute(
        "UPDATE entries SET metadata = ?1 WHERE alias = ?2",
        rusqlite::params![stored, &payload.alias],
    );
    match affected {
        Ok(1) => {
            let audit_logged = try_log_audit(&key, AuditOperation::Update, Some(&payload.alias), true);
            emit(&ResultEnvelope::ok(
                req_id,
                json!({
                    "alias": payload.alias,
                    "metadata": payload.metadata,
                    "action_taken": "updated",
                    "audit_logged": audit_logged,
                }),
            ));
        }
        Ok(_) => emit_error(req_id, "I_INTERNAL", "UPDATE affected unexpected row count"),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("set_metadata UPDATE: {}", e)),
    }
}

// ========== 局部工具 ==========

fn must_alias_exist(conn: &rusqlite::Connection, req_id: &Option<String>, alias: &str) -> bool {
    match alias_exists(conn, alias) {
        Ok(true) => true,
        Ok(false) => {
            emit_error(
                req_id.clone(),
                "I_CREDENTIAL_NOT_FOUND",
                format!("alias '{}' not found", alias),
            );
            false
        }
        Err((c, m)) => { emit_error(req_id.clone(), c, m); false }
    }
}
