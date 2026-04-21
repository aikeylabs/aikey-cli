//! `_internal vault-op` 子命令：vault 加密/写操作入口
//!
//! # Phase 分工
//! - Phase A：`verify`
//! - Phase B（本次）：`add` / `batch_import` / `update_secret` / `delete`
//!
//! # Audit 接入（Phase F 完成）
//! 所有 mutating actions 在 vault 写成功后，调用
//! `audit::log_audit_event_from_vault_key(&key, operation, alias, success)` 写 audit_log。
//! 派生路径：HMAC-SHA256(vault_key, "AK_AUDIT_V2:audit-v1") → audit_key
//! 详见 `audit.rs::derive_audit_key_from_vault_key` 的决策注释。
//! 响应中 `audit_logged: true` 标志位给 Go 侧感知。
//! Audit 失败**不**回滚 vault 写（best-effort），但会降级到 `audit_logged: false` + warning。

use serde::Deserialize;
use serde_json::json;

use crate::audit::{self, AuditOperation};
use crate::crypto;
use crate::storage;
use super::protocol::{ResultEnvelope, StdinEnvelope};
use super::stdin_json::{decode_vault_key, emit, emit_error};

/// best-effort audit：失败不回滚 vault 写，只记 warning + 返回 false
fn try_log_audit(key: &[u8; 32], op: AuditOperation, alias: Option<&str>, success: bool) -> bool {
    match audit::log_audit_event_from_vault_key(key, op, alias, success) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("[_internal audit WARN] {} {:?}: {}", op.as_str(), alias, e);
            false
        }
    }
}

// ========== action-specific payload types ==========

#[derive(Debug, Deserialize)]
struct AddPayload {
    alias: String,
    secret_plaintext: String,
    #[serde(default)]
    provider: Option<String>,
    /// "error" (default) | "replace"
    #[serde(default = "default_on_conflict")]
    on_conflict: String,
}

#[derive(Debug, Deserialize)]
struct BatchImportPayload {
    items: Vec<BatchImportItem>,
    /// "error" (default) | "skip" | "replace"
    #[serde(default = "default_on_conflict")]
    on_conflict: String,
    /// 可选 job_id（UUID，Go local-server 生成）；提供则写入 import_jobs/import_items 审计表
    #[serde(default)]
    job_id: Option<String>,
    /// 可选 source_type（"paste"/"file"），仅用于 import_jobs.source_type 列
    #[serde(default)]
    source_type: Option<String>,
    /// 可选 source_hash（sha256:...），来自 parse 响应，Go 侧透传用于 dedup 检测
    #[serde(default)]
    source_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BatchImportItem {
    alias: String,
    secret_plaintext: String,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateSecretPayload {
    alias: String,
    new_secret_plaintext: String,
}

#[derive(Debug, Deserialize)]
struct DeletePayload {
    alias: String,
}

fn default_on_conflict() -> String { "error".to_string() }

// ========== dispatch ==========

pub fn handle(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    match env.action.as_str() {
        "verify" => handle_verify(env),
        "add" => handle_add(env),
        "batch_import" => handle_batch_import(env),
        "update_secret" => handle_update_secret(env),
        "delete" => handle_delete(env),
        other => {
            emit_error(
                req_id,
                "I_UNKNOWN_ACTION",
                format!("unknown vault-op action: '{}'", other),
            );
        }
    }
}

// ========== helpers ==========

/// 解码 vault_key_hex + 校验 vault 存在 + 打开连接。任何失败直接 emit error 并返回 None。
fn prepare_vault(env: &StdinEnvelope) -> Option<([u8; 32], rusqlite::Connection)> {
    let req_id = env.request_id.clone();

    let key = match decode_vault_key(&env.vault_key_hex) {
        Ok(k) => k,
        Err((code, msg)) => {
            emit_error(req_id, code, msg);
            return None;
        }
    };

    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id.clone(), "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return None;
    }

    let conn = match storage::open_connection() {
        Ok(c) => c,
        Err(e) => {
            emit_error(req_id, "I_VAULT_OPEN_FAILED", format!("{}", e));
            return None;
        }
    };

    // 在所有 mutating ops 之前校验 key（用 password_hash 或空 vault 兜底）
    if let Err((code, msg)) = verify_key_against_vault(&conn, &key) {
        emit_error(env.request_id.clone(), code, msg);
        return None;
    }

    Some((key, conn))
}

/// 校验 vault_key 与 config.password_hash 一致（或兼容旧 vault 无 password_hash 情况）
fn verify_key_against_vault(
    conn: &rusqlite::Connection,
    key: &[u8; 32],
) -> Result<(), (&'static str, String)> {
    let stored_hash: Result<Vec<u8>, rusqlite::Error> = conn.query_row(
        "SELECT value FROM config WHERE key = 'password_hash'",
        [],
        |r| r.get(0),
    );
    match stored_hash {
        Ok(hash) => {
            if hash.as_slice() == key.as_slice() {
                Ok(())
            } else {
                Err((
                    "I_VAULT_KEY_INVALID",
                    "vault_key does not match stored password_hash".to_string(),
                ))
            }
        }
        Err(_) => {
            // 无 password_hash：尝试解一条 entry 兜底
            let entry: Result<(Vec<u8>, Vec<u8>), rusqlite::Error> = conn.query_row(
                "SELECT nonce, ciphertext FROM entries LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            );
            match entry {
                Ok((nonce, ciphertext)) => crypto::decrypt(key, &nonce, &ciphertext)
                    .map(|_| ())
                    .map_err(|_| (
                        "I_VAULT_KEY_INVALID",
                        "vault_key failed to decrypt any entry".to_string(),
                    )),
                Err(_) => Ok(()), // 空 vault 兜底
            }
        }
    }
}

/// 把 plaintext 加密为 (nonce, ciphertext)
fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), (&'static str, String)> {
    crypto::encrypt(key, plaintext)
        .map_err(|e| ("I_INTERNAL", format!("encrypt failed: {}", e)))
}

/// 检查 alias 是否已存在
fn alias_exists(conn: &rusqlite::Connection, alias: &str) -> Result<bool, (&'static str, String)> {
    conn.query_row(
        "SELECT COUNT(*) FROM entries WHERE alias = ?",
        [alias],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .map_err(|e| ("I_INTERNAL", format!("check alias failed: {}", e)))
}

// ========== verify ==========

fn handle_verify(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let (_key, _conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return, // emit_error 已在 prepare_vault 内发出
    };
    emit(&ResultEnvelope::ok(
        req_id,
        json!({"verified": true, "method": "password_hash"}),
    ));
}

// ========== add ==========

fn handle_add(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: AddPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_STDIN_INVALID_JSON", format!("add payload invalid: {}", e));
            return;
        }
    };
    if payload.alias.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "alias must be non-empty");
        return;
    }

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // on_conflict 检查
    let exists = match alias_exists(&conn, &payload.alias) {
        Ok(b) => b,
        Err((c, m)) => { emit_error(req_id, c, m); return; }
    };
    if exists && payload.on_conflict == "error" {
        emit_error(
            req_id,
            "I_CREDENTIAL_CONFLICT",
            format!("alias '{}' already exists (use on_conflict=replace to overwrite)", payload.alias),
        );
        return;
    }

    // 加密
    let (nonce, ciphertext) = match encrypt_with_key(&key, payload.secret_plaintext.as_bytes()) {
        Ok(t) => t,
        Err((c, m)) => { emit_error(req_id, c, m); return; }
    };

    // 写 entries（UPSERT —— store_entry 原生行为）
    if let Err(e) = storage::store_entry(&payload.alias, &nonce, &ciphertext) {
        emit_error(req_id, "I_INTERNAL", format!("store_entry failed: {}", e));
        return;
    }

    // 写 provider_code（可选）
    if let Some(provider) = &payload.provider {
        if let Err(e) = conn.execute(
            "UPDATE entries SET provider_code = ?1 WHERE alias = ?2",
            rusqlite::params![provider, &payload.alias],
        ) {
            emit_error(
                req_id,
                "I_INTERNAL",
                format!("set provider_code failed: {}", e),
            );
            return;
        }
    }

    let audit_logged = try_log_audit(&key, AuditOperation::Add, Some(&payload.alias), true);

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "alias": payload.alias,
            "action_taken": if exists { "replaced" } else { "inserted" },
            "provider": payload.provider,
            "audit_logged": audit_logged,
        }),
    ));
}

// ========== batch_import ==========

fn handle_batch_import(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: BatchImportPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_STDIN_INVALID_JSON", format!("batch_import payload invalid: {}", e));
            return;
        }
    };
    if payload.items.is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "items must be non-empty");
        return;
    }

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // 预检：on_conflict=error 时，先扫一遍看有没有冲突
    if payload.on_conflict == "error" {
        for it in &payload.items {
            match alias_exists(&conn, &it.alias) {
                Ok(true) => {
                    emit_error(
                        req_id,
                        "I_CREDENTIAL_CONFLICT",
                        format!("alias '{}' already exists (set on_conflict=skip|replace)", it.alias),
                    );
                    return;
                }
                Ok(false) => {}
                Err((c, m)) => { emit_error(req_id, c, m); return; }
            }
        }
    }

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // 若提供 job_id，先写 import_jobs 开头行（status=in_progress）
    if let Some(jid) = &payload.job_id {
        if let Err(e) = conn.execute(
            "INSERT INTO import_jobs (job_id, source_type, source_hash, created_at, total_items, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'in_progress')",
            rusqlite::params![
                jid,
                payload.source_type,
                payload.source_hash,
                now_ts,
                payload.items.len() as i64,
            ],
        ) {
            // UNIQUE 冲突 → job_id 已被用（Go 侧生成重复），报错
            let msg = format!("{}", e);
            if msg.contains("UNIQUE") {
                emit_error(req_id, "I_CREDENTIAL_CONFLICT",
                    format!("job_id '{}' already exists", jid));
            } else {
                emit_error(req_id, "I_INTERNAL", format!("create import_jobs: {}", e));
            }
            return;
        }
    }

    // 逐条执行
    let mut inserted = 0usize;
    let mut replaced = 0usize;
    let mut skipped = 0usize;
    let mut item_reports = Vec::with_capacity(payload.items.len());
    let mut audit_failures = 0usize;

    for it in &payload.items {
        let exists = match alias_exists(&conn, &it.alias) {
            Ok(b) => b,
            Err((c, m)) => { emit_error(req_id, c, m); return; }
        };

        if exists && payload.on_conflict == "skip" {
            skipped += 1;
            item_reports.push(json!({"alias": it.alias, "action": "skipped"}));
            if let Some(jid) = &payload.job_id {
                let _ = conn.execute(
                    "INSERT INTO import_items (job_id, alias, action, provider_code, created_at) \
                     VALUES (?1, ?2, 'skipped', ?3, ?4)",
                    rusqlite::params![jid, &it.alias, it.provider, now_ts],
                );
            }
            continue;
        }

        let (nonce, ciphertext) = match encrypt_with_key(&key, it.secret_plaintext.as_bytes()) {
            Ok(t) => t,
            Err((c, m)) => { emit_error(req_id, c, m); return; }
        };
        if let Err(e) = storage::store_entry(&it.alias, &nonce, &ciphertext) {
            emit_error(req_id, "I_INTERNAL", format!("store_entry failed for '{}': {}", it.alias, e));
            return;
        }
        if let Some(p) = &it.provider {
            if let Err(e) = conn.execute(
                "UPDATE entries SET provider_code = ?1 WHERE alias = ?2",
                rusqlite::params![p, &it.alias],
            ) {
                emit_error(req_id, "I_INTERNAL", format!("set provider for '{}' failed: {}", it.alias, e));
                return;
            }
        }
        let action = if exists { "replaced" } else { "inserted" };
        if exists { replaced += 1 } else { inserted += 1 };
        item_reports.push(json!({"alias": it.alias, "action": action}));

        // 每条成功写都记 audit
        if !try_log_audit(&key, AuditOperation::Import, Some(&it.alias), true) {
            audit_failures += 1;
        }
        // 并写 import_items（若有 job_id）
        if let Some(jid) = &payload.job_id {
            let _ = conn.execute(
                "INSERT INTO import_items (job_id, alias, action, provider_code, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![jid, &it.alias, action, it.provider, now_ts],
            );
        }
    }

    // 完结 import_jobs
    if let Some(jid) = &payload.job_id {
        let _ = conn.execute(
            "UPDATE import_jobs SET completed_at = ?1, inserted_count = ?2, replaced_count = ?3, \
             skipped_count = ?4, status = 'completed' WHERE job_id = ?5",
            rusqlite::params![now_ts, inserted as i64, replaced as i64, skipped as i64, jid],
        );
    }

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "job_id": payload.job_id,
            "total": payload.items.len(),
            "inserted": inserted,
            "replaced": replaced,
            "skipped": skipped,
            "items": item_reports,
            "audit_logged": audit_failures == 0,
            "audit_failures": audit_failures,
        }),
    ));
}

// ========== update_secret ==========

fn handle_update_secret(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: UpdateSecretPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_STDIN_INVALID_JSON", format!("update_secret payload invalid: {}", e));
            return;
        }
    };

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // 必须已存在（区别于 add 的 UPSERT）
    match alias_exists(&conn, &payload.alias) {
        Ok(false) => {
            emit_error(
                req_id,
                "I_CREDENTIAL_NOT_FOUND",
                format!("alias '{}' does not exist (use add to create)", payload.alias),
            );
            return;
        }
        Err((c, m)) => { emit_error(req_id, c, m); return; }
        Ok(true) => {}
    }

    let (nonce, ciphertext) = match encrypt_with_key(&key, payload.new_secret_plaintext.as_bytes()) {
        Ok(t) => t,
        Err((c, m)) => { emit_error(req_id, c, m); return; }
    };
    if let Err(e) = storage::store_entry(&payload.alias, &nonce, &ciphertext) {
        emit_error(req_id, "I_INTERNAL", format!("store_entry failed: {}", e));
        return;
    }

    let audit_logged = try_log_audit(&key, AuditOperation::Update, Some(&payload.alias), true);

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "alias": payload.alias,
            "action_taken": "updated",
            "audit_logged": audit_logged,
        }),
    ));
}

// ========== delete ==========

fn handle_delete(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: DeletePayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_STDIN_INVALID_JSON", format!("delete payload invalid: {}", e));
            return;
        }
    };

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    match alias_exists(&conn, &payload.alias) {
        Ok(false) => {
            emit_error(
                req_id,
                "I_CREDENTIAL_NOT_FOUND",
                format!("alias '{}' does not exist", payload.alias),
            );
            return;
        }
        Err((c, m)) => { emit_error(req_id, c, m); return; }
        Ok(true) => {}
    }

    if let Err(e) = storage::delete_entry(&payload.alias) {
        emit_error(req_id, "I_INTERNAL", format!("delete_entry failed: {}", e));
        return;
    }

    let audit_logged = try_log_audit(&key, AuditOperation::Delete, Some(&payload.alias), true);

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "alias": payload.alias,
            "action_taken": "deleted",
            "audit_logged": audit_logged,
        }),
    ));
}
