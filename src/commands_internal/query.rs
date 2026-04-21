//! `_internal query`：vault 读操作入口（含解密）
//!
//! # Actions（Phase C）
//! - `list`：仅返回 alias 列表（无 metadata 无 secret，最轻量）
//! - `list_with_metadata`：返回每条 alias 的 provider_code / base_url / created_at / supported_providers（**不含 secret**）
//! - `get`：返回单个 alias 的 metadata + 可选 plaintext（`include_secret` 控制）
//! - `check_alias_exists`：仅存在性（不需要解密，不校验 vault_key）
//!
//! # 安全原则
//! - `get` 解密前必须校验 vault_key 匹配 `config.password_hash`（避免 key 错也能获取 metadata）
//! - `include_secret: false` 路径**不解密**，只返回 metadata
//! - 协议响应中的 `plaintext` 字段敏感，Go local-server 接收后必须**立即 zeroize**并仅传给前端做一次性展示/复制

use serde::Deserialize;
use serde_json::json;

use crate::crypto;
use crate::storage;
use super::protocol::{ResultEnvelope, StdinEnvelope};
use super::stdin_json::{decode_vault_key, emit, emit_error};

// ========== payload types ==========

#[derive(Debug, Deserialize, Default)]
struct GetPayload {
    alias: String,
    /// 默认 false：仅返回 metadata；true 时解密并返回 plaintext
    #[serde(default)]
    include_secret: bool,
}

#[derive(Debug, Deserialize, Default)]
struct CheckAliasExistsPayload {
    alias: String,
}

#[derive(Debug, Deserialize, Default)]
struct ListImportJobsPayload {
    /// 最多返回多少条；默认 20，最大 200
    #[serde(default)]
    limit: Option<usize>,
    /// 可选 status 过滤："completed" / "in_progress" / "aborted"
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct GetImportJobItemsPayload {
    job_id: String,
}

// ========== dispatch ==========

pub fn handle(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    match env.action.as_str() {
        "list" => handle_list(env),
        "list_with_metadata" => handle_list_with_metadata(env),
        "get" => handle_get(env),
        "check_alias_exists" => handle_check_alias_exists(env),
        "list_import_jobs" => handle_list_import_jobs(env),
        "get_import_job_items" => handle_get_import_job_items(env),
        other => emit_error(
            req_id,
            "I_UNKNOWN_ACTION",
            format!("unknown query action: '{}'", other),
        ),
    }
}

// ========== helpers ==========

/// 校验 vault_key（与 vault_op.rs 同款逻辑，但不依赖 prepare_vault 因为 query 有的 action 不需要 key）
fn verify_key(env: &StdinEnvelope) -> Result<[u8; 32], (&'static str, String)> {
    let key = decode_vault_key(&env.vault_key_hex)?;
    storage::ensure_vault_exists()
        .map_err(|e| ("I_VAULT_NOT_INITIALIZED", format!("{}", e)))?;
    let conn = storage::open_connection()
        .map_err(|e| ("I_VAULT_OPEN_FAILED", format!("{}", e)))?;

    let stored_hash: Result<Vec<u8>, rusqlite::Error> = conn.query_row(
        "SELECT value FROM config WHERE key = 'password_hash'",
        [],
        |r| r.get(0),
    );
    match stored_hash {
        Ok(hash) if hash.as_slice() == key.as_slice() => Ok(key),
        Ok(_) => Err((
            "I_VAULT_KEY_INVALID",
            "vault_key does not match stored password_hash".to_string(),
        )),
        Err(_) => {
            // 无 password_hash：尝试解一条 entry 兜底
            let entry: Result<(Vec<u8>, Vec<u8>), rusqlite::Error> = conn.query_row(
                "SELECT nonce, ciphertext FROM entries LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            );
            match entry {
                Ok((nonce, ciphertext)) => crypto::decrypt(&key, &nonce, &ciphertext)
                    .map(|_| key)
                    .map_err(|_| (
                        "I_VAULT_KEY_INVALID",
                        "vault_key failed to decrypt any entry".to_string(),
                    )),
                Err(_) => Ok(key), // 空 vault 兜底
            }
        }
    }
}

// ========== list ==========

fn handle_list(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    // list 也要验 key —— 防止"未解锁就能枚举 alias"（alias 本身有情报价值）
    if let Err((c, m)) = verify_key(&env) {
        emit_error(req_id, c, m);
        return;
    }

    match storage::list_entries() {
        Ok(aliases) => emit(&ResultEnvelope::ok(
            req_id,
            json!({"count": aliases.len(), "aliases": aliases}),
        )),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("list_entries failed: {}", e)),
    }
}

// ========== list_with_metadata ==========

fn handle_list_with_metadata(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    if let Err((c, m)) = verify_key(&env) {
        emit_error(req_id, c, m);
        return;
    }

    match storage::list_entries_with_metadata() {
        Ok(entries) => {
            let arr: Vec<_> = entries.iter().map(|m| json!({
                "alias": m.alias,
                "created_at": m.created_at,
                "provider_code": m.provider_code,
                "base_url": m.base_url,
                "supported_providers": m.supported_providers,
            })).collect();
            emit(&ResultEnvelope::ok(
                req_id,
                json!({"count": arr.len(), "entries": arr}),
            ));
        }
        Err(e) => emit_error(
            req_id,
            "I_INTERNAL",
            format!("list_entries_with_metadata failed: {}", e),
        ),
    }
}

// ========== get ==========

fn handle_get(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: GetPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_STDIN_INVALID_JSON", format!("get payload invalid: {}", e));
            return;
        }
    };
    if payload.alias.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "alias must be non-empty");
        return;
    }

    let key = match verify_key(&env) {
        Ok(k) => k,
        Err((c, m)) => { emit_error(req_id, c, m); return; }
    };

    // 先查 metadata（即使 include_secret=false 也返回）
    let all = match storage::list_entries_with_metadata() {
        Ok(v) => v,
        Err(e) => {
            emit_error(req_id, "I_INTERNAL", format!("list for get failed: {}", e));
            return;
        }
    };
    let meta = match all.into_iter().find(|m| m.alias == payload.alias) {
        Some(m) => m,
        None => {
            emit_error(
                req_id,
                "I_CREDENTIAL_NOT_FOUND",
                format!("alias '{}' not found", payload.alias),
            );
            return;
        }
    };

    let mut data = json!({
        "alias": meta.alias,
        "created_at": meta.created_at,
        "provider_code": meta.provider_code,
        "base_url": meta.base_url,
        "supported_providers": meta.supported_providers,
        "has_secret": true,
    });

    if payload.include_secret {
        let (nonce, ciphertext) = match storage::get_entry(&payload.alias) {
            Ok(t) => t,
            Err(e) => {
                emit_error(req_id, "I_INTERNAL", format!("get_entry failed: {}", e));
                return;
            }
        };
        let plaintext = match crypto::decrypt(&key, &nonce, &ciphertext) {
            Ok(p) => p,
            Err(e) => {
                emit_error(req_id, "I_INTERNAL", format!("decrypt failed: {}", e));
                return;
            }
        };
        let s = String::from_utf8_lossy(&plaintext).to_string();
        if let serde_json::Value::Object(ref mut m) = data {
            m.insert("secret_plaintext".to_string(), json!(s));
        }
    }

    emit(&ResultEnvelope::ok(req_id, data));
}

// ========== list_import_jobs ==========

fn handle_list_import_jobs(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: ListImportJobsPayload = serde_json::from_value(env.payload.clone()).unwrap_or_default();

    // 审计历史 = 敏感视图（显示用户过去导入了啥），需验 key
    if let Err((c, m)) = verify_key(&env) {
        emit_error(req_id, c, m);
        return;
    }

    let limit = payload.limit.unwrap_or(20).min(200);
    let conn = match storage::open_connection() {
        Ok(c) => c,
        Err(e) => { emit_error(req_id, "I_VAULT_OPEN_FAILED", format!("{}", e)); return; }
    };

    let sql = if payload.status.is_some() {
        "SELECT job_id, source_type, source_hash, created_at, completed_at, \
         total_items, inserted_count, replaced_count, skipped_count, status \
         FROM import_jobs WHERE status = ?1 ORDER BY created_at DESC LIMIT ?2"
    } else {
        "SELECT job_id, source_type, source_hash, created_at, completed_at, \
         total_items, inserted_count, replaced_count, skipped_count, status \
         FROM import_jobs ORDER BY created_at DESC LIMIT ?1"
    };

    let row_mapper = |r: &rusqlite::Row| -> rusqlite::Result<serde_json::Value> {
        Ok(json!({
            "job_id": r.get::<_, String>(0)?,
            "source_type": r.get::<_, Option<String>>(1)?,
            "source_hash": r.get::<_, Option<String>>(2)?,
            "created_at": r.get::<_, i64>(3)?,
            "completed_at": r.get::<_, Option<i64>>(4)?,
            "total_items": r.get::<_, i64>(5)?,
            "inserted_count": r.get::<_, i64>(6)?,
            "replaced_count": r.get::<_, i64>(7)?,
            "skipped_count": r.get::<_, i64>(8)?,
            "status": r.get::<_, String>(9)?,
        }))
    };

    let result: Result<Vec<serde_json::Value>, rusqlite::Error> = if let Some(status) = &payload.status {
        let mut stmt = match conn.prepare(sql) {
            Ok(s) => s,
            Err(e) => { emit_error(req_id, "I_INTERNAL", format!("prepare: {}", e)); return; }
        };
        stmt.query_map(rusqlite::params![status, limit as i64], row_mapper)
            .and_then(|rows| rows.collect())
    } else {
        let mut stmt = match conn.prepare(sql) {
            Ok(s) => s,
            Err(e) => { emit_error(req_id, "I_INTERNAL", format!("prepare: {}", e)); return; }
        };
        stmt.query_map(rusqlite::params![limit as i64], row_mapper)
            .and_then(|rows| rows.collect())
    };

    match result {
        Ok(jobs) => emit(&ResultEnvelope::ok(
            req_id,
            json!({"count": jobs.len(), "jobs": jobs}),
        )),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("list_import_jobs: {}", e)),
    }
}

// ========== get_import_job_items ==========

fn handle_get_import_job_items(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: GetImportJobItemsPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => { emit_error(req_id, "I_STDIN_INVALID_JSON",
            format!("get_import_job_items payload: {}", e)); return; }
    };
    if payload.job_id.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "job_id must be non-empty");
        return;
    }

    if let Err((c, m)) = verify_key(&env) {
        emit_error(req_id, c, m);
        return;
    }

    let conn = match storage::open_connection() {
        Ok(c) => c,
        Err(e) => { emit_error(req_id, "I_VAULT_OPEN_FAILED", format!("{}", e)); return; }
    };

    // 先验 job 存在
    let job_exists: Result<i64, rusqlite::Error> = conn.query_row(
        "SELECT COUNT(*) FROM import_jobs WHERE job_id = ?",
        [&payload.job_id],
        |r| r.get(0),
    );
    match job_exists {
        Ok(0) => {
            emit_error(req_id, "I_CREDENTIAL_NOT_FOUND",
                format!("import job '{}' not found", payload.job_id));
            return;
        }
        Err(e) => { emit_error(req_id, "I_INTERNAL", format!("check job: {}", e)); return; }
        Ok(_) => {}
    }

    let mut stmt = match conn.prepare(
        "SELECT alias, action, provider_code, created_at \
         FROM import_items WHERE job_id = ?1 ORDER BY id ASC"
    ) {
        Ok(s) => s,
        Err(e) => { emit_error(req_id, "I_INTERNAL", format!("prepare items: {}", e)); return; }
    };

    let items: Result<Vec<serde_json::Value>, rusqlite::Error> = stmt.query_map(
        [&payload.job_id],
        |r| Ok(json!({
            "alias": r.get::<_, String>(0)?,
            "action": r.get::<_, String>(1)?,
            "provider_code": r.get::<_, Option<String>>(2)?,
            "created_at": r.get::<_, i64>(3)?,
        })),
    ).and_then(|rows| rows.collect());

    match items {
        Ok(items) => emit(&ResultEnvelope::ok(
            req_id,
            json!({"job_id": payload.job_id, "count": items.len(), "items": items}),
        )),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("get items: {}", e)),
    }
}

// ========== check_alias_exists ==========

fn handle_check_alias_exists(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let payload: CheckAliasExistsPayload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_STDIN_INVALID_JSON",
                format!("check_alias_exists payload invalid: {}", e),
            );
            return;
        }
    };

    // check_alias_exists 不需要 key —— 用于 import 预检场景（Go local-server 批量导入前
    // 查哪些 alias 已存在）。只读 alias 本身（无 secret 内容），不涉及解密路径。
    // 仍需 vault 存在。
    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(
            req_id,
            "I_VAULT_NOT_INITIALIZED",
            format!("{}", e),
        );
        return;
    }

    let conn = match storage::open_connection() {
        Ok(c) => c,
        Err(e) => {
            emit_error(req_id, "I_VAULT_OPEN_FAILED", format!("{}", e));
            return;
        }
    };

    let exists: Result<i64, rusqlite::Error> = conn.query_row(
        "SELECT COUNT(*) FROM entries WHERE alias = ?",
        [&payload.alias],
        |r| r.get(0),
    );
    match exists {
        Ok(n) => emit(&ResultEnvelope::ok(
            req_id,
            json!({"alias": payload.alias, "exists": n > 0}),
        )),
        Err(e) => emit_error(
            req_id,
            "I_INTERNAL",
            format!("count alias failed: {}", e),
        ),
    }
}
