//! `_internal query`：vault 读操作入口（含解密）
//!
//! # Actions（Phase C）
//! - `list`：仅返回 alias 列表（无 metadata 无 secret，最轻量）
//! - `list_with_metadata`：返回每条 alias 的 provider_code / base_url / created_at / supported_providers（**不含 secret**）
//! - `get`：返回单个 alias 的 metadata + 可选 plaintext（`include_secret` 控制）
//! - `check_alias_exists`：仅存在性（不需要解密，不校验 vault_key）
//! - `list_personal_with_masked`：Personal entries 列表 + secret prefix/suffix4（用户 Vault Web 页面，解锁态）
//! - `list_oauth`：OAuth 账号列表（provider_accounts 表，**永不返 token 任何部分**）
//! - `list_metadata_locked`：无 vault_key 版本 —— 合并 Personal + OAuth 的明文 metadata，Personal secret 字段返 null（用户 Vault Web 页面，锁态）
//!
//! # 安全原则
//! - `get` 解密前必须校验 vault_key 匹配 `config.password_hash`（避免 key 错也能获取 metadata）
//! - `include_secret: false` 路径**不解密**，只返回 metadata
//! - 协议响应中的 `plaintext` 字段敏感，Go local-server 接收后必须**立即 zeroize**并仅传给前端做一次性展示/复制
//! - `list_oauth` 永远不含 access_token / refresh_token 任何字节（OAuth session token 永不暴露 — D3 决策）
//! - `list_metadata_locked` **有意**绕过反枚举防护（2026-04-23 用户决策 A）：用户希望锁态也看到 vault 结构，
//!   代价是能访问 local-server 端口的进程不需主密码就能枚举 alias。实际风险边界几乎不变 ——
//!   同机攻击者本就可直读 vault.db 明文列。生产版 Web 本身不挂 /user/vault，不影响。

use serde::Deserialize;
use serde_json::json;

use crate::crypto;
use crate::storage;
// storage_platform is a submodule re-exported via `pub use storage_platform::*`
// on storage. Call its functions through `storage::...` directly.
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

// ========== dispatch ==========

pub fn handle(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    match env.action.as_str() {
        "list" => handle_list(env),
        "list_with_metadata" => handle_list_with_metadata(env),
        "get" => handle_get(env),
        "check_alias_exists" => handle_check_alias_exists(env),
        // 2026-04-23: removed `list_import_jobs` / `get_import_job_items`
        // actions along with the `import_jobs` / `import_items` tables
        // (collapsed out of v1.0.4-alpha migration).
        "list_personal_with_masked" => handle_list_personal_with_masked(env),
        "list_oauth" => handle_list_oauth(env),
        "list_metadata_locked" => handle_list_metadata_locked(env),
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

// ========== list_personal_with_masked ==========
//
// Returns every Personal entry's prefix + last-4-char suffix + length of the
// decrypted secret, so the User Vault Web page can render a masked chip like
// `sk-ant-api03- ••••• afef3` without the browser ever seeing plaintext.
//
// Security shape:
//   - Requires a verified vault_key (anti-enumeration; same as `list_*` family).
//   - Decrypts every entry once to extract prefix/suffix; plaintext is zeroed
//     as soon as the slice goes out of scope. We never log it.
//   - The `secret_prefix` is only set when the secret starts with one of the
//     KNOWN_SECRET_PREFIXES (Anthropic / OpenAI / Groq / GitHub / AWS / ...).
//     For anything else we fall back to the first 4 chars — short enough to
//     not reveal the secret, long enough to help the user recognize it.
//   - Suffix is the last 4 chars. Secrets <= 8 chars return "****" for both
//     fields to avoid exposing more than half of a short token.
//   - `target` field is always "personal" per §2.0 unified-target rule.
fn handle_list_personal_with_masked(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    let key = match verify_key(&env) {
        Ok(k) => k,
        Err((c, m)) => { emit_error(req_id, c, m); return; }
    };

    let metas = match storage::list_entries_with_metadata() {
        Ok(v) => v,
        Err(e) => {
            emit_error(req_id, "I_INTERNAL", format!("list_entries_with_metadata failed: {}", e));
            return;
        }
    };

    let mut out = Vec::with_capacity(metas.len());
    for m in metas {
        let (nonce, ciphertext) = match storage::get_entry(&m.alias) {
            Ok(t) => t,
            Err(e) => {
                // Skip the entry instead of failing the whole list — a single
                // corrupted row shouldn't black-hole the Web page. Log via
                // stderr so operators can see it.
                eprintln!("[_internal query list_personal_with_masked WARN] get_entry '{}' failed: {}", m.alias, e);
                continue;
            }
        };
        let plaintext = match crypto::decrypt(&key, &nonce, &ciphertext) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[_internal query list_personal_with_masked WARN] decrypt '{}' failed: {}", m.alias, e);
                continue;
            }
        };
        let secret = String::from_utf8_lossy(&plaintext);
        let (prefix, suffix, len) = extract_prefix_suffix(&secret);
        out.push(json!({
            "target": "personal",
            "id": m.alias,
            "alias": m.alias,
            "provider_code": m.provider_code,
            "base_url": m.base_url,
            "supported_providers": m.supported_providers,
            "created_at": m.created_at,
            "status": "active",
            "route_token": m.route_token,
            "last_used_at": m.last_used_at,
            "use_count": m.use_count.unwrap_or(0),
            "secret_prefix": prefix,
            "secret_suffix": suffix,
            "secret_len": len,
        }));
    }

    emit(&ResultEnvelope::ok(
        req_id,
        json!({"count": out.len(), "entries": out}),
    ));
}

/// Known secret prefixes used to produce human-recognizable mask chips.
/// Order matters: longest-match-first (sk-ant-api03- must come before sk-ant-).
const KNOWN_SECRET_PREFIXES: &[&str] = &[
    "sk-ant-api03-", "sk-ant-sid01-", "sk-ant-oat01-", "sk-ant-",
    "sk-proj-", "sk-svcacct-", "sk-admin-",
    "AIzaSy", "AIza",
    "gsk_", "xai-",
    "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "sess_",
    "AKIA", "ASIA",
    "hf_", "glpat-", "ya29.",
    "SG.", "sg.",
    "sk-",
];

/// Extract a (prefix, suffix4, len) triple for masked UI display. Never
/// returns the middle of the secret. Short secrets (<= 8 chars) return
/// `"****"` for both prefix and suffix to avoid exposing >half the token.
fn extract_prefix_suffix(secret: &str) -> (String, String, usize) {
    let len = secret.chars().count();
    if len <= 8 {
        return ("****".to_string(), "****".to_string(), len);
    }
    let chars: Vec<char> = secret.chars().collect();
    let suffix: String = chars[len - 4..].iter().collect();

    for kp in KNOWN_SECRET_PREFIXES {
        if secret.starts_with(kp) {
            return ((*kp).to_string(), suffix, len);
        }
    }
    // Unknown shape: fall back to first 4 chars (safe — 4/len < 50% for len > 8).
    let prefix: String = chars[..4].iter().collect();
    (prefix, suffix, len)
}

// ========== list_oauth ==========
//
// Returns every OAuth provider account (`provider_accounts` table) with
// metadata + status + created_at + last_used_at. NEVER returns access_token
// or refresh_token bytes — the `provider_account_tokens` table is not even
// queried. This is a hard rule (D3 decision, 2026-04-23): OAuth session
// tokens are long-lived and leak impact is higher than Personal API keys,
// so the Web UI is permanently denied reveal access.
//
// The `target` field is always "oauth". `id` mirrors `provider_account_id`
// so the front end can use a single identifier column across targets.
fn handle_list_oauth(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    if let Err((c, m)) = verify_key(&env) {
        emit_error(req_id, c, m);
        return;
    }

    let accounts = match storage::list_provider_accounts() {
        Ok(v) => v,
        Err(e) => {
            emit_error(req_id, "I_INTERNAL", format!("list_provider_accounts failed: {}", e));
            return;
        }
    };

    // Look up `token_expires_at` in one shot. We don't touch ciphertext or
    // nonce columns — `provider_account_tokens` also holds access/refresh
    // blobs but we project only the expires_at timestamp, never the tokens
    // themselves (D3 rule: OAuth session tokens never leave cli → Go).
    let expires_map = load_oauth_expires_map().unwrap_or_default();

    let arr: Vec<_> = accounts.iter().map(|a| json!({
        "target": "oauth",
        "id": a.provider_account_id,
        "provider_account_id": a.provider_account_id,
        "provider": a.provider,
        "auth_type": a.auth_type,
        "credential_type": a.credential_type.as_str(),
        "display_identity": a.display_identity,
        "alias": a.display_identity,
        "external_id": a.external_id,
        "org_uuid": a.org_uuid,
        "account_tier": a.account_tier,
        "status": a.status,
        "created_at": a.created_at,
        "last_used_at": a.last_used_at,
        "use_count": a.use_count.unwrap_or(0),
        "token_expires_at": expires_map.get(&a.provider_account_id).copied().flatten(),
    })).collect();

    emit(&ResultEnvelope::ok(
        req_id,
        json!({"count": arr.len(), "accounts": arr}),
    ));
}

/// Bulk-loads `provider_account_id → token_expires_at` from the
/// `provider_account_tokens` table. Returns an empty map on any error
/// (old vault without the table, etc.) so callers degrade gracefully —
/// a missing expires timestamp renders as "—" in the UI, not an error.
/// Access/refresh token bytes are NEVER SELECTed here.
fn load_oauth_expires_map() -> Result<std::collections::HashMap<String, Option<i64>>, String> {
    let conn = storage::open_connection().map_err(|e| format!("open: {}", e))?;
    let mut stmt = conn
        .prepare("SELECT provider_account_id, token_expires_at FROM provider_account_tokens")
        .map_err(|e| format!("prepare: {}", e))?;
    let rows: Vec<(String, Option<i64>)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)))
        .map_err(|e| format!("query_map: {}", e))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| format!("collect: {}", e))?;
    Ok(rows.into_iter().collect())
}

// ========== list_metadata_locked ==========
//
// Locked-state list for the User Vault Web page. Returns the union of
// Personal entries + OAuth accounts but uses ONLY plaintext metadata
// columns from the vault.db — no AES-GCM decryption, no `verify_key`
// call. That means this action intentionally works without a vault_key,
// so the Web UI can render the list even when the user hasn't unlocked
// yet (2026-04-23 decision A).
//
// Security shape:
//   - The `vault_key_hex` envelope field is still required by protocol,
//     but we only do a format check on it (any valid 64-char hex passes,
//     including the all-zero placeholder). We do NOT compare against
//     `config.password_hash`.
//   - `entries.ciphertext` / `entries.nonce` are never read. The Personal
//     records therefore carry `secret_prefix / secret_suffix / secret_len
//     = null` — the caller (Go / Web) renders pure-asterisks for the
//     secret column when those are absent.
//   - `provider_account_tokens` table is never queried (same D3 rule as
//     `list_oauth`).
//   - All other columns are plaintext in the vault schema and are safe
//     to return without decryption.
//
// Why separate action instead of a flag on `list_personal_with_masked`:
// the behavior contract is materially different (no verify, no decrypt,
// merged response). A distinct action name makes the security intent
// auditable at call sites — grep for `list_metadata_locked` finds every
// place that bypasses the anti-enumeration guard.
fn handle_list_metadata_locked(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    // Format-validate only. Placeholder 64-char hex is fine; real hex
    // also fine. We do NOT compare to password_hash.
    if let Err((code, msg)) = decode_vault_key(&env.vault_key_hex) {
        emit_error(req_id, code, msg);
        return;
    }
    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id, "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return;
    }

    let mut out: Vec<serde_json::Value> = Vec::new();

    // Personal entries: plaintext metadata only. We go through the same
    // `list_entries_with_metadata` helper that the unlocked path uses —
    // it already returns only plaintext columns.
    match storage::list_entries_with_metadata() {
        Ok(metas) => {
            for m in metas {
                out.push(json!({
                    "target": "personal",
                    "id": m.alias,
                    "alias": m.alias,
                    "provider_code": m.provider_code,
                    "base_url": m.base_url,
                    "supported_providers": m.supported_providers,
                    "created_at": m.created_at,
                    "status": "active",
                    "route_token": m.route_token,
                    "last_used_at": m.last_used_at,
                    "use_count": m.use_count.unwrap_or(0),
                    // Null sentinel — front end uses this to render a
                    // fully-masked (no prefix, no suffix) secret pill.
                    "secret_prefix": serde_json::Value::Null,
                    "secret_suffix": serde_json::Value::Null,
                    "secret_len": serde_json::Value::Null,
                }));
            }
        }
        Err(e) => {
            emit_error(
                req_id,
                "I_INTERNAL",
                format!("list_entries_with_metadata failed: {}", e),
            );
            return;
        }
    }

    let personal_count = out.len();

    // OAuth accounts: identical shape to `handle_list_oauth`; no tokens.
    let expires_map = load_oauth_expires_map().unwrap_or_default();
    let oauth_count = match storage::list_provider_accounts() {
        Ok(accounts) => {
            for a in &accounts {
                out.push(json!({
                    "target": "oauth",
                    "id": a.provider_account_id,
                    "provider_account_id": a.provider_account_id,
                    "provider": a.provider,
                    "auth_type": a.auth_type,
                    "credential_type": a.credential_type.as_str(),
                    "display_identity": a.display_identity,
                    "alias": a.display_identity,
                    "external_id": a.external_id,
                    "org_uuid": a.org_uuid,
                    "account_tier": a.account_tier,
                    "status": a.status,
                    "created_at": a.created_at,
                    "last_used_at": a.last_used_at,
                    "use_count": a.use_count.unwrap_or(0),
                    "token_expires_at": expires_map.get(&a.provider_account_id).copied().flatten(),
                }));
            }
            accounts.len()
        }
        Err(e) => {
            emit_error(
                req_id,
                "I_INTERNAL",
                format!("list_provider_accounts failed: {}", e),
            );
            return;
        }
    };

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "records": out,
            "counts": {
                "personal": personal_count,
                "oauth":    oauth_count,
                "team":     0,
                "total":    personal_count + oauth_count,
            },
            "locked": true,
        }),
    ));
}

#[cfg(test)]
mod prefix_suffix_tests {
    use super::extract_prefix_suffix;

    #[test]
    fn anthropic_api_v3_prefix_recognized() {
        let s = "sk-ant-api03-XXXXXXXXXXXXafef3";
        let (p, sfx, len) = extract_prefix_suffix(s);
        assert_eq!(p, "sk-ant-api03-");
        assert_eq!(sfx, "fef3"); // last 4 chars
        assert_eq!(len, s.chars().count());
    }

    #[test]
    fn openai_project_prefix_recognized() {
        let (p, sfx, _) = extract_prefix_suffix("sk-proj-AAAAAAAAAAAAAAAAAAAAAAGHIJ");
        assert_eq!(p, "sk-proj-");
        assert_eq!(sfx, "GHIJ");
    }

    #[test]
    fn groq_prefix_recognized() {
        let (p, _, _) = extract_prefix_suffix("gsk_AAAAAAAAAAAAAAAAAAq2Nt");
        assert_eq!(p, "gsk_");
    }

    #[test]
    fn gemini_prefix_recognized() {
        let (p, _, _) = extract_prefix_suffix("AIzaSyAAAAAAAAAAAAAAAAAAAkzM1");
        // AIzaSy is longer and more specific than AIza — longest-match wins.
        assert_eq!(p, "AIzaSy");
    }

    #[test]
    fn oauth_session_prefix_recognized() {
        let (p, _, _) = extract_prefix_suffix("sess_AAAAAAAAAAAAAAAAAAAAAAb7f2");
        assert_eq!(p, "sess_");
    }

    #[test]
    fn unknown_shape_falls_back_to_first_4() {
        let (p, sfx, len) = extract_prefix_suffix("zzzz1234567890abcd");
        assert_eq!(p, "zzzz");
        assert_eq!(sfx, "abcd");
        assert_eq!(len, 18);
    }

    #[test]
    fn short_secret_is_fully_masked() {
        // Secrets <= 8 chars must not expose half the token — return **** both ends.
        let (p, sfx, len) = extract_prefix_suffix("short");
        assert_eq!(p, "****");
        assert_eq!(sfx, "****");
        assert_eq!(len, 5);

        let (p, sfx, len) = extract_prefix_suffix("12345678");
        assert_eq!(p, "****");
        assert_eq!(sfx, "****");
        assert_eq!(len, 8);
    }

    #[test]
    fn longest_match_wins_for_anthropic() {
        // sk-ant-api03- is longer than sk-ant- is longer than sk- — must pick the longest.
        let s = "sk-ant-api03-1234567890abcdef";
        let (p, _, _) = extract_prefix_suffix(s);
        assert_eq!(p, "sk-ant-api03-");
    }

    #[test]
    fn github_pat_prefix_recognized() {
        let (p, _, _) = extract_prefix_suffix("github_pat_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBB");
        assert_eq!(p, "github_pat_");
    }
}
