//! `_internal update-alias`：metadata 编辑入口（alias rename + 通用 metadata blob）
//!
//! # Actions
//! - `rename_alias` - personal 重命名（alias 列；UNIQUE 约束）
//! - `rename_target` - 统一协议重命名：`{target, id, new_value}` 适配 personal / oauth / team
//! - `set_metadata` - 通用 JSON blob 写入（tag / note / enabled / 由前端自定义）
//!
//! # 架构契约（2026-04-24 `_internal 必须复用公开命令 core` 规则）
//! - **rename_* 全部走 `commands_account::apply_rename_core`** —— 与 CLI `aikey key alias` 共用同一条写路径，
//!   保证 personal/team/oauth 三种目标的校验、冲突检测、UPDATE 语义完全一致。
//! - **`set_provider` / `set_base_url` / `set_supported_providers` 已移除（2026-04-24）**：这三个 action 既
//!   无 Go HTTP 端点，也无前端 TS client / UI 调用，纯死代码；保留只会增加 audit 审计表面积。
//!   Provider / base_url / supported_providers 的**唯一**设定时机是在 `aikey add` / `_internal vault-op add`
//!   / `_internal vault-op batch_import` 三条 create 路径，全部走 `commands_account::apply_add_core_on_conn`。
//!   需要改现有 key 的 provider 配置，删掉重加（与命名约定的 "Web UI 不支持改 add-time 元数据" 一致）。
//! - **`set_metadata` 保留**：这个是前端用于写 tag / note 等自定义 blob 的通用接口，与 provider 配置正交。
//!
//! # 设计约束
//! - 所有写入仍需 vault_key 验证（password_hash 比对），与 vault-op 对齐
//! - rename 不动 nonce / ciphertext / id
//! - UNIQUE 冲突由 DB 层触发，协议层翻译为 `I_CREDENTIAL_CONFLICT`（match string 包含 "UNIQUE" / "already exists"）

use serde::Deserialize;
use serde_json::json;

use crate::audit::{self, AuditOperation};
use crate::commands_account::{apply_rename_core, RenameTarget};
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
struct SetMetadataPayload {
    alias: String,
    /// 任意 JSON blob；null 清空；object 会序列化成字符串存到 entries.metadata 列
    metadata: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RenameTargetPayload {
    target: String,
    id: String,
    new_value: String,
}

// ========== dispatch ==========

pub fn handle(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    match env.action.as_str() {
        "rename_alias" => handle_rename_alias(env),
        "rename_target" => handle_rename_target(env),
        "set_metadata" => handle_set_metadata(env),
        // `set_provider` / `set_base_url` / `set_supported_providers` were
        // removed 2026-04-24. They had no HTTP endpoint, no TS client, no UI;
        // pure dead code. Any caller still passing these actions gets a
        // clear "unknown action" error instead of a silent no-op.
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

/// Maps `apply_rename_core` error strings to stable `_internal` error_codes.
/// Kept in one place so both `rename_alias` and `rename_target` agree on
/// the mapping — same pattern as vault_op::handle_add's error-code switch.
fn rename_error_code(msg: &str) -> &'static str {
    if msg.contains("not found") {
        "I_CREDENTIAL_NOT_FOUND"
    } else if msg.contains("already exists") || msg.contains("UNIQUE") {
        "I_CREDENTIAL_CONFLICT"
    } else if msg.contains("empty")
        || msg.contains("identical")
        || msg.contains("exceeds")
        || msg.contains("control")
    {
        "I_STDIN_INVALID_JSON"
    } else {
        "I_INTERNAL"
    }
}

// ========== rename_alias ==========
//
// Legacy personal-only rename contract. Retained for callers still speaking
// the `{old_alias, new_alias}` payload shape; new callers should prefer
// `rename_target` with `target: "personal"`.

fn handle_rename_alias(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: RenamePayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => { emit_error(req_id, "I_STDIN_INVALID_JSON", format!("rename_alias payload: {}", e)); return; }
    };

    let (key, _conn) = match prepare(&env) { Some(p) => p, None => return };

    match apply_rename_core(RenameTarget::Personal, &payload.old_alias, &payload.new_alias) {
        Ok(outcome) => {
            let audit_logged = try_log_audit(&key, AuditOperation::Update, Some(&outcome.id), true);
            emit(&ResultEnvelope::ok(
                req_id,
                json!({
                    "old_alias": outcome.old_id,
                    "new_alias": outcome.new_value,
                    "action_taken": "renamed",
                    "audit_logged": audit_logged,
                }),
            ));
        }
        Err(msg) => emit_error(req_id, rename_error_code(&msg), msg),
    }
}

// ========== rename_target ==========
//
// Target-aware rename for the unified User Vault Web protocol (§2.0).
// Payload: `{ "target": "personal" | "oauth" | "team", "id": "...", "new_value": "..." }`

fn handle_rename_target(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    let payload: RenameTargetPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_STDIN_INVALID_JSON", format!("rename_target payload: {}", e));
            return;
        }
    };

    let target = match payload.target.as_str() {
        "personal" => RenameTarget::Personal,
        "oauth" => RenameTarget::Oauth,
        "team" => RenameTarget::Team,
        other => {
            emit_error(req_id, "I_UNKNOWN_TARGET",
                format!("unknown target '{}' (expected personal|oauth|team)", other));
            return;
        }
    };

    let (key, _conn) = match prepare(&env) { Some(p) => p, None => return };

    match apply_rename_core(target, &payload.id, &payload.new_value) {
        Ok(outcome) => {
            let audit_logged = try_log_audit(&key, AuditOperation::Update, Some(&outcome.id), true);
            let mut body = json!({
                "target": outcome.target,
                "id": outcome.id,
                "old_id": outcome.old_id,
                "action_taken": "renamed",
                "audit_logged": audit_logged,
            });
            // Emit target-specific display field for backward-compat with
            // existing Go/TS response shape expectations.
            match outcome.target {
                "oauth" => {
                    if let Some(o) = body.as_object_mut() {
                        o.insert("display_identity".into(), json!(outcome.new_value));
                    }
                }
                "team" => {
                    if let Some(o) = body.as_object_mut() {
                        o.insert("local_alias".into(), json!(outcome.new_value));
                    }
                }
                _ => {}
            }
            emit(&ResultEnvelope::ok(req_id, body));
        }
        Err(msg) => emit_error(req_id, rename_error_code(&msg), msg),
    }
}

// ========== set_metadata ==========
//
// Generic JSON blob writer for tag / note / enabled / etc. Unrelated to the
// provider/base_url/supported_providers trio that was removed 2026-04-24.

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
