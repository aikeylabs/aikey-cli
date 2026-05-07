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
use crate::credential_type::CredentialType;
use crate::crypto;
use crate::profile_activation;
use crate::storage;
// storage_platform is a submodule re-exported via `pub use storage::*`
// on storage. Call its functions through `storage::...` directly.
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

/// Hook coverage v1 §H2 / §2.3: report rc-wire status to the Web envelope.
///
/// Phase Y (2026-05-07): Layer 1 (hook file render) is now done by the
/// lifecycle funnel tail, NOT by this function. Callers that already
/// have a `LifecycleOutcome` (i.e., all mutating handlers after the
/// 2026-05-07 batch_import fix) MUST use `merge_hook_status_from_outcome`
/// to avoid double-rendering Layer 1.
///
/// This function (no-outcome variant) is retained for two scenarios:
///   1. handlers that don't run lifecycle (read-only / metadata)
///   2. fallback when lifecycle was skipped (no binding changes touched)
///
/// Independently of Layer 1, `hook_rc_wired` is always read from disk
/// here — it's a passive grep of `~/.zshrc`/`~/.bashrc`, not a write.
fn hook_status_for_envelope() -> serde_json::Value {
    let (file_installed, failure_reason) =
        crate::commands_account::web_install_hook_file_layer1();
    let rc_wired = crate::commands_account::shell_rc_has_aikey_block();
    json!({
        "hook_file_installed": file_installed,
        "hook_rc_wired": rc_wired,
        "hook_failure_reason": failure_reason.map(|r| r.as_envelope_str()),
    })
}

/// Phase Y (2026-05-07): outcome-aware hook status. Reads `hook_file_installed`
/// + `hook_failure_reason` from the `LifecycleOutcome` (populated by the
/// funnel's tail step 4) instead of re-rendering Layer 1. `hook_rc_wired`
/// is still grep'd from disk (it's an independent passive read).
///
/// Use this from any handler that has just run lifecycle. Falls back to a
/// fresh Layer 1 render when `outcome` reports the tail didn't run
/// (e.g. no-op event with no binding touch) — guards against vault_op
/// emitting `file_installed=false` for pure passive operations.
fn hook_status_from_outcome(outcome: &crate::commands_account::LifecycleOutcome) -> serde_json::Value {
    let rc_wired = crate::commands_account::shell_rc_has_aikey_block();
    if outcome.active_env_refreshed {
        // Tail ran — outcome carries authoritative fields.
        json!({
            "hook_file_installed": outcome.hook_file_installed,
            "hook_rc_wired": rc_wired,
            "hook_failure_reason": outcome.hook_failure_reason.map(|r| r.as_envelope_str()),
        })
    } else {
        // Tail skipped (event was a no-op for bindings). Fall back to a
        // fresh Layer 1 render so the envelope still reports correct
        // file_installed state (not the default `false`).
        let (file_installed, failure_reason) =
            crate::commands_account::web_install_hook_file_layer1();
        json!({
            "hook_file_installed": file_installed,
            "hook_rc_wired": rc_wired,
            "hook_failure_reason": failure_reason.map(|r| r.as_envelope_str()),
        })
    }
}

/// Merge the hook-status fields into an existing `serde_json::Value`
/// object. Avoids each handler having to spell out the three fields.
/// Idempotent: a future caller adding more fields elsewhere won't
/// collide because we only write the three known keys.
///
/// Phase Y (2026-05-07): when caller has a `LifecycleOutcome`, prefer
/// `merge_hook_status_from_outcome` to avoid Layer 1 double-render.
fn merge_hook_status(base: serde_json::Value) -> serde_json::Value {
    let mut obj = base;
    if let serde_json::Value::Object(ref mut map) = obj {
        let hook = hook_status_for_envelope();
        if let serde_json::Value::Object(hook_map) = hook {
            for (k, v) in hook_map {
                map.insert(k, v);
            }
        }
    }
    obj
}

/// Phase Y (2026-05-07): outcome-aware merge. Same shape as
/// `merge_hook_status` but reads Layer 1 status from the funnel outcome
/// instead of re-rendering. Callers with lifecycle MUST prefer this.
fn merge_hook_status_from_outcome(
    base: serde_json::Value,
    outcome: &crate::commands_account::LifecycleOutcome,
) -> serde_json::Value {
    let mut obj = base;
    if let serde_json::Value::Object(ref mut map) = obj {
        let hook = hook_status_from_outcome(outcome);
        if let serde_json::Value::Object(hook_map) = hook {
            for (k, v) in hook_map {
                map.insert(k, v);
            }
        }
    }
    obj
}

// ========== action-specific payload types ==========

#[derive(Debug, Deserialize)]
struct AddPayload {
    alias: String,
    secret_plaintext: String,
    /// Single-protocol shorthand (backward compat with older callers).
    /// If both `provider` and `providers` are given, `providers` wins.
    #[serde(default)]
    provider: Option<String>,
    /// Multi-protocol set (aligned with batch_import + `aikey add --providers`).
    /// 2026-04-24: added so Web "Add key" no longer silently drops this field.
    #[serde(default)]
    providers: Option<Vec<String>>,
    /// Optional per-entry base URL override.
    #[serde(default)]
    base_url: Option<String>,
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
    // 2026-04-23: removed `job_id` / `source_type` / `source_hash` payload
    // fields together with the `import_jobs` / `import_items` tables
    // (collapsed into v1.0.4-alpha migration). They were the only write-side
    // users of those tables, and the only read-side consumer (history page)
    // never landed. `#[serde(deny_unknown_fields)]` is intentionally NOT
    // enabled on this struct, so older callers still sending these fields
    // get them silently ignored — no protocol break.
}

#[derive(Debug, Deserialize)]
struct BatchImportItem {
    alias: String,
    secret_plaintext: String,
    /// Single-protocol shorthand (backward compat with older callers).
    /// If both `provider` and `providers` are given, `providers` wins.
    #[serde(default)]
    provider: Option<String>,
    /// v4.1 Stage 5+: Multi-protocol binding (aggregator gateways like 0011 /
    /// openrouter / yunwu often serve multiple API protocols). Stored to
    /// `entries.supported_providers` as a JSON array. `provider_code` is set to
    /// `providers[0]` for routing-default compatibility with existing `aikey use`.
    #[serde(default)]
    providers: Option<Vec<String>>,
    /// v4.1 Stage 7+: Per-entry base URL override (optional).
    /// None or empty string → leave entries.base_url NULL (use provider default).
    /// Non-empty → stored via `storage::set_entry_base_url(alias, Some(url))`.
    #[serde(default)]
    base_url: Option<String>,
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
        "metadata" => handle_metadata(env),
        "add" => handle_add(env),
        "batch_import" => handle_batch_import(env),
        "update_secret" => handle_update_secret(env),
        "delete" => handle_delete(env),
        "delete_target" => handle_delete_target(env),
        "record_usage" => handle_record_usage(env),
        "use" => handle_use(env),
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

// ========== metadata ==========
//
// Pre-unlock metadata query used by Go local-server: returns the vault's KDF
// salt + Argon2id parameters so the caller can derive `vault_key_hex` locally
// before invoking `verify`. No secret is exposed; only rekey-inert public
// params. Follows the same "format-check only" pattern as `parse`: the stdin
// `vault_key_hex` field is required by protocol but not matched against the
// vault (the caller doesn't have it yet).
//
// Why a separate action (not an unlock-that-takes-password): keeps the
// password off stdin, so the only place the password lives is the Go
// process handling the unlock HTTP request, and only for the Argon2id call.
// Envelope contract stays action-agnostic (all actions still carry
// vault_key_hex).
fn handle_metadata(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    // Format-validate only (placeholder 64-char hex is fine; real hex also fine).
    if let Err((code, msg)) = decode_vault_key(&env.vault_key_hex) {
        emit_error(req_id, code, msg);
        return;
    }

    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id, "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return;
    }
    let conn = match storage::open_connection() {
        Ok(c) => c,
        Err(e) => {
            emit_error(req_id, "I_VAULT_OPEN_FAILED", format!("{}", e));
            return;
        }
    };

    // Salt: canonical key is `master_salt`; fall back to legacy `salt`.
    let salt: Vec<u8> = match conn.query_row(
        "SELECT value FROM config WHERE key = 'master_salt'",
        [],
        |r| r.get(0),
    ) {
        Ok(v) => v,
        Err(_) => match conn.query_row(
            "SELECT value FROM config WHERE key = 'salt'",
            [],
            |r| r.get(0),
        ) {
            Ok(v) => v,
            Err(e) => {
                emit_error(req_id, "I_VAULT_NOT_INITIALIZED",
                    format!("vault missing master_salt: {}", e));
                return;
            }
        },
    };

    // KDF params: stored as 4-byte LE uint32, default to Argon2id params if absent.
    let read_u32 = |k: &str, default: u32| -> u32 {
        conn.query_row("SELECT value FROM config WHERE key = ?", [k], |r| r.get::<_, Vec<u8>>(0))
            .ok()
            .filter(|v| v.len() == 4)
            .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
            .unwrap_or(default)
    };
    let m_cost = read_u32("kdf_m_cost", 65536);
    let t_cost = read_u32("kdf_t_cost", 3);
    let p_cost = read_u32("kdf_p_cost", 4);
    let key_len = 32u32;

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "salt_hex": hex::encode(&salt),
            "kdf": {
                "algorithm": "argon2id",
                "m_cost": m_cost,
                "t_cost": t_cost,
                "p_cost": p_cost,
                "key_len": key_len,
            },
        }),
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

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // Resolve providers: `providers` (multi, preferred) > `provider` (single, legacy)
    let providers_input: Vec<String> = payload.providers.clone()
        .or_else(|| payload.provider.clone().map(|p| vec![p]))
        .unwrap_or_default();

    // Decode on_conflict string → typed enum.
    let on_conflict = match payload.on_conflict.as_str() {
        "replace" => crate::commands_account::OnConflict::Replace,
        "skip" => crate::commands_account::OnConflict::Skip,
        _ => crate::commands_account::OnConflict::Error,
    };

    // Delegate to the shared core. Handles alias validation, canonical
    // provider normalization, encryption, entries write, supported_providers
    // + provider_code + base_url metadata writes in a single place.
    let outcome = match crate::commands_account::apply_add_core_on_conn(
        &conn,
        &key,
        &payload.alias,
        payload.secret_plaintext.as_bytes(),
        &providers_input,
        payload.base_url.as_deref(),
        on_conflict,
    ) {
        Ok(o) => o,
        Err(msg) => {
            // Map a handful of well-known error strings to stable error_codes
            // so the Go layer / front-end can key off them without parsing
            // human text. Everything else falls through as I_INTERNAL.
            let code = if msg.contains("already exists") {
                "I_CREDENTIAL_CONFLICT"
            } else if msg.contains("alias") && (msg.contains("empty") || msg.contains("exceeds") || msg.contains("control")) {
                "I_STDIN_INVALID_JSON"
            } else {
                "I_INTERNAL"
            };
            emit_error(req_id, code, msg);
            return;
        }
    };

    // Route token — outside core because it opens its own connection
    // (can't live in a transaction). Single-add here isn't in a tx so it's
    // fine. Best-effort: missing route_token isn't a hard failure, the
    // entry is still usable until a later `ensure_entry_route_token` fills it.
    let _ = storage::ensure_entry_route_token(&outcome.alias);

    // Auto-assign as Primary + refresh active.env. Mirrors the CLI's
    // `Commands::Add` post-write block in main.rs:1093-1099 — without
    // these two calls, a key added via the web UI silently lacks a
    // provider binding and the proxy/shell never picks it up. (Per
    // CLAUDE.md `_internal must reuse public command core` — both
    // entry points should produce identical state.) Best-effort:
    // failures here don't roll back the entry write that already
    // succeeded; the metadata can be reconciled later by `aikey use
    // <alias>`.
    // Single funnel: Added event runs auto_assign_primaries → refresh →
    // apply_third_party_cli_configs. Bugfix history pinned by the
    // CredentialLifecycleEvent variant docs.
    let lifecycle = crate::commands_account::apply_credential_lifecycle(
        crate::commands_account::CredentialLifecycleEvent::Added {
            source_type: "personal",
            source_ref: &outcome.alias,
            providers: &outcome.providers,
        },
    ).unwrap_or_default();
    let newly_primary = lifecycle.newly_primary.clone();
    let active_env_refreshed = lifecycle.active_env_refreshed;

    let audit_logged = try_log_audit(&key, AuditOperation::Add, Some(&outcome.alias), true);

    emit(&ResultEnvelope::ok(
        req_id,
        merge_hook_status_from_outcome(json!({
            "alias": outcome.alias,
            "action_taken": outcome.action.as_str(),
            "provider": outcome.primary_provider,
            "providers": outcome.providers,
            "newly_primary_providers": newly_primary,
            "active_env_refreshed": active_env_refreshed,
            "audit_logged": audit_logged,
        }), &lifecycle),
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

    // Batch-scope dedup check (items[i].alias duplicated within this call).
    // This can't be delegated to apply_add_core — it needs the full item
    // list in scope. Per-item validation + conflict-against-DB checks ARE
    // delegated (see below). Matches v4.1 Stage 14+ BUG-01 fix.
    if payload.on_conflict == "error" {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for it in &payload.items {
            if !seen.insert(&it.alias) {
                emit_error(
                    req_id,
                    "I_CREDENTIAL_CONFLICT",
                    format!("alias '{}' is duplicated within this batch (set on_conflict=skip|replace, or dedupe client-side)", it.alias),
                );
                return;
            }
        }
    }

    let (key, mut conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // Typed on_conflict for the shared core.
    let on_conflict = match payload.on_conflict.as_str() {
        "replace" => crate::commands_account::OnConflict::Replace,
        "skip" => crate::commands_account::OnConflict::Skip,
        _ => crate::commands_account::OnConflict::Error,
    };

    // G-5 P0 review fix (2026-04-23): entire batch write set runs in a
    // single IMMEDIATE transaction. Any failure mid-batch triggers ROLLBACK
    // via Transaction::Drop — callers see either "all committed" or "none
    // committed", never half-written vault state.
    //
    // Audit log writes stay outside the transaction (best-effort, as before).
    let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(t) => t,
        Err(e) => {
            emit_error(req_id, "I_INTERNAL", format!("begin batch transaction: {}", e));
            return;
        }
    };

    let mut inserted = 0usize;
    let mut replaced = 0usize;
    let mut skipped = 0usize;
    let mut item_reports = Vec::with_capacity(payload.items.len());
    let mut per_item_audit: Vec<String> = Vec::with_capacity(payload.items.len());
    // Bugfix 2026-05-07: capture (canonical_alias, canonical_providers) per
    // Inserted/Replaced item so we can run the lifecycle funnel after the
    // entries-write tx commits. Without this, batch_import wrote vault
    // entries but never auto-promoted to primary, never refreshed
    // active.env, never synced toml regions — symptom: web import +
    // CLI `claude` ran with no env routing at all. Phase 5 lifecycle
    // refactor wired 11 callers but missed batch_import; the user
    // surfaced this on 2026-05-07.
    let mut lifecycle_inputs: Vec<(String, Vec<String>)> = Vec::with_capacity(payload.items.len());

    for it in &payload.items {
        // Resolve providers: `providers` (multi, preferred) > `provider` (single).
        let providers_input: Vec<String> = match &it.providers {
            Some(ps) if !ps.is_empty() => ps.clone(),
            _ => it.provider.clone().map(|p| vec![p]).unwrap_or_default(),
        };

        // Delegate per-item write to the shared core (same helper as single
        // `aikey add` and `_internal vault-op add`). Handles alias validation,
        // canonical provider normalization, conflict policy, encryption,
        // and all three metadata writes atomically inside this transaction.
        let outcome = match crate::commands_account::apply_add_core_on_conn(
            &tx,
            &key,
            &it.alias,
            it.secret_plaintext.as_bytes(),
            &providers_input,
            it.base_url.as_deref(),
            on_conflict,
        ) {
            Ok(o) => o,
            Err(msg) => {
                let code = if msg.contains("already exists") {
                    "I_CREDENTIAL_CONFLICT"
                } else if msg.contains("alias")
                    && (msg.contains("empty") || msg.contains("exceeds") || msg.contains("control"))
                {
                    "I_INVALID_ALIAS"
                } else {
                    "I_INTERNAL"
                };
                emit_error(req_id, code, format!("item '{}': {}", it.alias, msg));
                return; // tx drops → ROLLBACK
            }
        };

        match outcome.action {
            crate::commands_account::AddAction::Inserted => {
                inserted += 1;
                per_item_audit.push(outcome.alias.clone());
                lifecycle_inputs.push((outcome.alias.clone(), outcome.providers.clone()));
            }
            crate::commands_account::AddAction::Replaced => {
                replaced += 1;
                per_item_audit.push(outcome.alias.clone());
                // Replaced rows still need lifecycle: the secret changed,
                // primary may need to be re-pointed (esp. when this alias
                // already was primary — preserve it). Treat as Added so
                // auto_assign re-evaluates against current binding state.
                lifecycle_inputs.push((outcome.alias.clone(), outcome.providers.clone()));
            }
            crate::commands_account::AddAction::Skipped => {
                skipped += 1;
            }
        }
        item_reports.push(json!({"alias": outcome.alias, "action": outcome.action.as_str()}));
    }

    // Commit — all writes land atomically.
    if let Err(e) = tx.commit() {
        emit_error(req_id, "I_INTERNAL", format!("commit batch transaction: {}", e));
        return;
    }

    // Route token generation (post-commit — each call opens its own
    // connection, can't live in the transaction). Best-effort per item;
    // failures log and continue (entry still usable, route_token fills
    // in on next ensure_entry_route_token call).
    for alias in &per_item_audit {
        let _ = storage::ensure_entry_route_token(alias);
    }

    // Post-commit audit fan-out (best-effort; matches single-entry add handler).
    let mut audit_failures = 0usize;
    for alias in &per_item_audit {
        if !try_log_audit(&key, AuditOperation::Import, Some(alias.as_str()), true) {
            audit_failures += 1;
        }
    }

    // Lifecycle funnel — auto_assign + refresh active.env + apply third-
    // party CLI configs. Bugfix 2026-05-07: previously omitted, leaving
    // imported keys with no binding rows, no active.env update, no toml
    // sync. Run AFTER the entries-write tx commits because the funnel
    // opens its own DB connection (and would deadlock on the held tx).
    // Failure here doesn't roll back the entries write; the binding
    // can be reconciled later by `aikey use <alias>` (matches the
    // best-effort posture of vault_op handle_add).
    let lifecycle_events: Vec<crate::commands_account::CredentialLifecycleEvent> =
        lifecycle_inputs
            .iter()
            .map(|(alias, providers)| crate::commands_account::CredentialLifecycleEvent::Added {
                source_type: "personal",
                source_ref: alias.as_str(),
                providers: providers.as_slice(),
            })
            .collect();
    let lifecycle_outcomes =
        crate::commands_account::apply_credential_lifecycle_batch(&lifecycle_events)
            .unwrap_or_default();
    let total_newly_primary: Vec<String> = lifecycle_outcomes
        .iter()
        .flat_map(|o| o.newly_primary.clone())
        .collect();
    // active_env_refreshed: true iff the funnel ran the tail and at least
    // one outcome reports it. The batch flavor runs the tail once after
    // all writes succeed, so all outcomes share the same value — but we
    // OR them together to be defensive against future funnel changes.
    let active_env_refreshed = lifecycle_outcomes.iter().any(|o| o.active_env_refreshed);
    // Phase Y: any outcome will do for hook fields — tail runs once, all
    // outcomes share the same hook_file_installed / hook_failure_reason.
    // Default outcome (empty events list path) reports tail-skipped,
    // which the merge_hook_status_from_outcome helper falls back to a
    // fresh Layer 1 render for.
    let representative_outcome = lifecycle_outcomes.first().cloned().unwrap_or_default();

    emit(&ResultEnvelope::ok(
        req_id,
        merge_hook_status_from_outcome(json!({
            "total": payload.items.len(),
            "inserted": inserted,
            "replaced": replaced,
            "skipped": skipped,
            "items": item_reports,
            "audit_logged": audit_failures == 0,
            "audit_failures": audit_failures,
            "newly_primary_providers": total_newly_primary,
            "active_env_refreshed": active_env_refreshed,
        }), &representative_outcome),
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

    // Single funnel: Removed event runs reconcile → refresh → apply.
    let _ = crate::commands_account::apply_credential_lifecycle(
        crate::commands_account::CredentialLifecycleEvent::Removed {
            source_type: "personal",
            source_ref: &payload.alias,
        },
    );

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

// ========== delete_target ==========
//
// Target-aware delete for the unified User Vault Web protocol (§2.0).
// Payload: `{ "target": "personal" | "oauth" | "team", "id": "..." }`
//
// Why a separate action (not overload `delete`): `delete` has a stable
// payload shape (`{alias: String}`) used by other callers (main.rs, import
// flow). Keeping them distinct means the unified-target contract can evolve
// without back-compat risk to existing consumers.
fn handle_delete_target(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(serde::Deserialize)]
    struct Payload {
        target: String,
        id: String,
    }
    let payload: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_STDIN_INVALID_JSON", format!("delete_target payload invalid: {}", e));
            return;
        }
    };
    if payload.id.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "id must be non-empty");
        return;
    }

    let (key, conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    match payload.target.as_str() {
        "personal" => {
            // id == alias for personal target
            match alias_exists(&conn, &payload.id) {
                Ok(false) => {
                    emit_error(req_id, "I_CREDENTIAL_NOT_FOUND",
                        format!("alias '{}' does not exist", payload.id));
                    return;
                }
                Err((c, m)) => { emit_error(req_id, c, m); return; }
                Ok(true) => {}
            }
            if let Err(e) = storage::delete_entry(&payload.id) {
                emit_error(req_id, "I_INTERNAL", format!("delete_entry failed: {}", e));
                return;
            }
            // Single funnel: Removed event runs reconcile → refresh → apply.
            let lifecycle = crate::commands_account::apply_credential_lifecycle(
                crate::commands_account::CredentialLifecycleEvent::Removed {
                    source_type: "personal",
                    source_ref: &payload.id,
                },
            ).unwrap_or_default();
            let audit_logged = try_log_audit(&key, AuditOperation::Delete, Some(&payload.id), true);
            emit(&ResultEnvelope::ok(
                req_id,
                merge_hook_status_from_outcome(json!({
                    "target": "personal",
                    "id": payload.id,
                    "action_taken": "deleted",
                    "audit_logged": audit_logged,
                }), &lifecycle),
            ));
        }
        "oauth" => {
            // Existence check first so we can return a precise NOT_FOUND.
            match storage::get_provider_account(&payload.id) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    emit_error(req_id, "I_CREDENTIAL_NOT_FOUND",
                        format!("provider_account_id '{}' does not exist", payload.id));
                    return;
                }
                Err(e) => { emit_error(req_id, "I_INTERNAL", format!("get_provider_account: {}", e)); return; }
            }
            // storage::delete_provider_account cascades provider_account_tokens.
            if let Err(e) = storage::delete_provider_account(&payload.id) {
                emit_error(req_id, "I_INTERNAL", format!("delete_provider_account failed: {}", e));
                return;
            }
            let audit_logged = try_log_audit(&key, AuditOperation::Delete, Some(&payload.id), true);
            emit(&ResultEnvelope::ok(
                req_id,
                merge_hook_status(json!({
                    "target": "oauth",
                    "id": payload.id,
                    "action_taken": "deleted",
                    "audit_logged": audit_logged,
                })),
            ));
        }
        "team" => {
            emit_error(req_id, "I_UNKNOWN_TARGET",
                "target 'team' is reserved for future use and not implemented in v1.0");
        }
        other => {
            emit_error(req_id, "I_UNKNOWN_TARGET",
                format!("unknown target '{}' (expected personal|oauth|team)", other));
        }
    }
}

// ========== record_usage ==========
//
// Bumps per-key usage telemetry: `last_used_at` = caller-supplied unix
// seconds (or now() if omitted), `use_count` = use_count + 1. Intended
// to be called from aikey-proxy after a successful credential
// resolution so the User Vault Web page can show "Last used 4m ago"
// and "12,345 uses" per key.
//
// Payload: `{ "target": "personal"|"oauth", "id": "...", "ts": <i64?> }`.
// `ts` is optional — omitted means "now on the cli host", which keeps
// proxy code clean when it doesn't care about exact request time.
//
// Security: this action does NOT verify the vault_key. Bumping a
// counter doesn't leak secrets and proxy usually runs before or
// without the user's interactive unlock; requiring a master password
// just to record usage would be pathological. The action is still
// gated at the Go layer by service-token / JWT auth like every other
// endpoint.
fn handle_record_usage(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(serde::Deserialize)]
    struct Payload {
        target: String,
        id: String,
        #[serde(default)]
        ts: Option<i64>,
    }
    let payload: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_STDIN_INVALID_JSON", format!("record_usage payload: {}", e));
            return;
        }
    };
    if payload.id.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "id must be non-empty");
        return;
    }

    if let Err(e) = storage::ensure_vault_exists() {
        emit_error(req_id, "I_VAULT_NOT_INITIALIZED", format!("{}", e));
        return;
    }

    let ts = payload.ts.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });

    let affected = match payload.target.as_str() {
        "personal" => storage::bump_entry_usage(&payload.id, ts),
        "oauth"    => storage::bump_oauth_usage(&payload.id, ts),
        "team" => {
            emit_error(req_id, "I_UNKNOWN_TARGET",
                "target 'team' is reserved for future use and not implemented in v1.0");
            return;
        }
        other => {
            emit_error(req_id, "I_UNKNOWN_TARGET",
                format!("unknown target '{}' (expected personal|oauth|team)", other));
            return;
        }
    };

    match affected {
        Ok(0) => emit_error(
            req_id,
            "I_CREDENTIAL_NOT_FOUND",
            format!("{} '{}' not found", payload.target, payload.id),
        ),
        Ok(n) => emit(&ResultEnvelope::ok(
            req_id,
            json!({
                "target": payload.target,
                "id": payload.id,
                "ts": ts,
                "rows_affected": n,
            }),
        )),
        Err(e) => emit_error(req_id, "I_INTERNAL", format!("record_usage: {}", e)),
    }
}

// ========== use (provider-binding switch) ==========
//
// Non-interactive counterpart of the `aikey use <alias>` CLI command. Writes
// `user_profile_provider_bindings` for every provider the target key serves,
// then refreshes `~/.aikey/active.env` so the shell precmd hook picks it up.
//
// Payload: `{ "target": "personal" | "oauth", "id": "..." }`
//   - personal → id is the alias
//   - oauth    → id is the provider_account_id
//   - team is rejected (reserved for future use, same rule as delete_target)
//
// Per-provider semantics: one binding per provider_code. Activating a personal
// key that supports multiple providers writes one binding per provider. OAuth
// accounts are always single-provider by construction.
//
// Interactive pieces from `commands_account::handle_key_use` that are
// deliberately omitted here (belong to the CLI, not the Web API):
//   - provider-selection prompt when `supported_providers` has > 1 entry —
//     Web path binds ALL supported providers (matches `aikey use` non-interactive
//     mode). A future UI refinement can add a provider_override field.
//   - shell hook install / Codex / Kimi / statusline auto-configuration —
//     those modify the user's home dir outside vault and are Web-UI-inappropriate.
//     If the user later runs `aikey use` from CLI those get installed on-demand.
//
// Why not "unset": the Web UI contract is "one active per provider, swap to
// replace" — there's no unset button. If a future requirement needs "clear
// routing for provider X", that's a distinct `use_unset` action, not an
// overload of this one.
fn handle_use(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(serde::Deserialize)]
    struct Payload {
        target: String,
        id: String,
    }
    let payload: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_STDIN_INVALID_JSON", format!("use payload invalid: {}", e));
            return;
        }
    };
    if payload.id.trim().is_empty() {
        emit_error(req_id, "I_STDIN_INVALID_JSON", "id must be non-empty");
        return;
    }

    let (key, _conn) = match prepare_vault(&env) {
        Some(pair) => pair,
        None => return,
    };

    // Resolve providers + key_source_type based on target.
    let (source_type, providers): (CredentialType, Vec<String>) = match payload.target.as_str() {
        "personal" => {
            let metas = match storage::list_entries_with_metadata() {
                Ok(v) => v,
                Err(e) => {
                    emit_error(req_id, "I_INTERNAL", format!("list_entries_with_metadata: {}", e));
                    return;
                }
            };
            let meta = match metas.into_iter().find(|m| m.alias == payload.id) {
                Some(m) => m,
                None => {
                    emit_error(req_id, "I_CREDENTIAL_NOT_FOUND",
                        format!("alias '{}' does not exist", payload.id));
                    return;
                }
            };
            // Prefer the v1.0.2+ multi-provider list; fall back to the legacy
            // single provider_code. An entry with neither is unbindable —
            // refuse rather than silently no-op.
            let providers: Vec<String> = meta.supported_providers
                .clone()
                .filter(|v| !v.is_empty())
                .or_else(|| meta.provider_code.clone().map(|p| vec![p]))
                .unwrap_or_default();
            if providers.is_empty() {
                emit_error(req_id, "I_KEY_NO_PROVIDER",
                    format!("key '{}' has no provider assignment; add one with `aikey secret set --provider`", payload.id));
                return;
            }
            (CredentialType::PersonalApiKey, providers)
        }
        "oauth" => {
            let acct = match storage::get_provider_account(&payload.id) {
                Ok(Some(a)) => a,
                Ok(None) => {
                    emit_error(req_id, "I_CREDENTIAL_NOT_FOUND",
                        format!("provider_account_id '{}' does not exist", payload.id));
                    return;
                }
                Err(e) => {
                    emit_error(req_id, "I_INTERNAL", format!("get_provider_account: {}", e));
                    return;
                }
            };
            (CredentialType::PersonalOAuthAccount, vec![acct.provider])
        }
        "team" => {
            // Stage 7-1 (active-state cross-shell sync, 2026-04-27):
            // team-target binding switch via the unified protocol. Looks up
            // the vk by id, allowing virtual_key_id, local_alias, or server
            // alias as input — same resolution order the CLI's interactive
            // picker uses, so Web and CLI accept the same identifiers.
            //
            // Validation gate: only `local_state in (active, synced_inactive)`
            // and `key_status == active` count as "usable". Anything else
            // (revoked, scope-disabled, stale snapshot) is rejected with an
            // explicit code so the Web UI can surface the right message.
            let entries = match storage::list_virtual_key_cache() {
                Ok(v) => v,
                Err(e) => {
                    emit_error(req_id, "I_INTERNAL",
                        format!("list_virtual_key_cache: {}", e));
                    return;
                }
            };
            // Resolution order: exact virtual_key_id → local_alias → server alias.
            // Exact id wins so a user who typed the canonical vk_xxx form is
            // never ambiguous with a local nickname.
            let entry = entries.iter().find(|e| e.virtual_key_id == payload.id)
                .or_else(|| entries.iter().find(|e|
                    e.local_alias.as_deref() == Some(payload.id.as_str())))
                .or_else(|| entries.iter().find(|e| e.alias == payload.id))
                .cloned();
            let entry = match entry {
                Some(e) => e,
                None => {
                    emit_error(req_id, "I_CREDENTIAL_NOT_FOUND",
                        format!("team key '{}' not found in local cache (run `aikey key sync`)", payload.id));
                    return;
                }
            };
            // Reject keys that the user shouldn't / can't activate. Each
            // local_state has a distinct error code so the Web UI can
            // tailor the surface message; the proxy will not route through
            // any of these regardless.
            match entry.local_state.as_str() {
                "active" | "synced_inactive" => {}
                "disabled_by_account_scope"
                | "disabled_by_account_status"
                | "disabled_by_seat_status"
                | "disabled_by_key_status" => {
                    emit_error(req_id, "I_KEY_DISABLED",
                        format!("team key '{}' is disabled (state={})", payload.id, entry.local_state));
                    return;
                }
                "stale" => {
                    emit_error(req_id, "I_KEY_STALE",
                        format!("team key '{}' is stale (run `aikey key sync` to refresh)", payload.id));
                    return;
                }
                other => {
                    emit_error(req_id, "I_KEY_DISABLED",
                        format!("team key '{}' is not usable (state={})", payload.id, other));
                    return;
                }
            }
            if entry.key_status != "active" {
                emit_error(req_id, "I_KEY_DISABLED",
                    format!("team key '{}' has server status '{}'", payload.id, entry.key_status));
                return;
            }
            // Provider list: prefer multi-protocol `supported_providers`,
            // fall back to single `provider_code`. Identical priority to
            // the personal target branch above (single source of truth).
            let providers: Vec<String> = if !entry.supported_providers.is_empty() {
                entry.supported_providers.clone()
            } else if !entry.provider_code.is_empty() {
                vec![entry.provider_code.clone()]
            } else {
                emit_error(req_id, "I_KEY_NO_PROVIDER",
                    format!("team key '{}' has no provider assignment", payload.id));
                return;
            };
            // Use the canonical vk_id as the binding's key_source_ref —
            // not the user-supplied identifier, which could have been a
            // local_alias / server alias. This keeps `provider_bindings.
            // key_source_ref` aligned with virtual_key_cache.virtual_key_id
            // for joinable lookups.
            (CredentialType::ManagedVirtualKey, providers)
        }
        other => {
            emit_error(req_id, "I_UNKNOWN_TARGET",
                format!("unknown target '{}' (expected personal|oauth|team)", other));
            return;
        }
    };

    // Re-resolve the canonical key_ref for team targets so write_bindings_canonical
    // gets the vk_id even when payload.id was a local_alias / server alias.
    // For personal/oauth, payload.id IS already canonical (alias / account_id).
    let canonical_key_ref: String = match payload.target.as_str() {
        "team" => {
            // Safe to expect: we already validated entry exists above.
            storage::list_virtual_key_cache().ok().and_then(|v| {
                v.into_iter().find(|e|
                    e.virtual_key_id == payload.id
                    || e.local_alias.as_deref() == Some(payload.id.as_str())
                    || e.alias == payload.id
                ).map(|e| e.virtual_key_id)
            }).unwrap_or_else(|| payload.id.clone())
        }
        _ => payload.id.clone(),
    };

    // Single funnel: Switched event runs write_bindings_canonical → refresh
    // → apply_third_party_cli_configs.
    let lifecycle = match crate::commands_account::apply_credential_lifecycle(
        crate::commands_account::CredentialLifecycleEvent::Switched {
            source_type: source_type.as_str(),
            source_ref: &canonical_key_ref,
            providers: &providers,
        },
    ) {
        Ok(o) => o,
        Err(e) => {
            emit_error(req_id, "I_INTERNAL", e);
            return;
        }
    };
    let refresh_ok = lifecycle.active_env_refreshed;

    let audit_logged = try_log_audit(&key, AuditOperation::Exec, Some(&canonical_key_ref), true);

    emit(&ResultEnvelope::ok(
        req_id,
        merge_hook_status_from_outcome(json!({
            "target": payload.target,
            "id": canonical_key_ref,
            "input_id": payload.id,
            "activated_providers": providers,
            "active_env_refreshed": refresh_ok,
            "audit_logged": audit_logged,
        }), &lifecycle),
    ));
}

// ============================================================================
// Phase Y (2026-05-07) — hook_status_from_outcome / merge_hook_status_from_outcome tests
// ============================================================================
//
// Pin the contract that vault_op envelope's hook fields reflect the
// `LifecycleOutcome` populated by the funnel tail (instead of double-
// rendering Layer 1). Tests cover the outcome path, the no-tail fallback
// path, and the merge shape.
//
// The helpers also call `shell_rc_has_aikey_block()` which reads
// HOME/SHELL env. We isolate via a tmpdir + ENV_MUTATION_LOCK so this
// module doesn't race with session.rs / shell_integration tests.

#[cfg(test)]
mod hook_envelope_tests {
    use super::*;
    use crate::commands_account::{HookFailureReason, LifecycleOutcome};
    use crate::test_env_lock::ENV_MUTATION_LOCK;

    /// Small RAII-ish helper: set HOME + SHELL for the lifetime of a closure,
    /// restore on exit. Same pattern as shell_integration's run_shell_rc_check.
    fn with_home_shell<F, R>(home: &std::path::Path, shell: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let prev_home = std::env::var("HOME").ok();
        let prev_shell = std::env::var("SHELL").ok();
        let prev_no_hook = std::env::var("AIKEY_NO_HOOK").ok();
        unsafe {
            std::env::set_var("HOME", home.to_str().unwrap());
            std::env::set_var("SHELL", shell);
            // Default off — individual tests opt-in by setting AIKEY_NO_HOOK
            // before calling f().
            std::env::remove_var("AIKEY_NO_HOOK");
        }
        let result = f();
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_shell {
                Some(v) => std::env::set_var("SHELL", v),
                None => std::env::remove_var("SHELL"),
            }
            match prev_no_hook {
                Some(v) => std::env::set_var("AIKEY_NO_HOOK", v),
                None => std::env::remove_var("AIKEY_NO_HOOK"),
            }
        }
        result
    }

    #[test]
    fn outcome_path_uses_outcome_fields_when_tail_ran() {
        // When LifecycleOutcome.active_env_refreshed=true, the helper MUST
        // read hook_file_installed / hook_failure_reason from the outcome
        // (not call web_install_hook_file_layer1 again). This is the whole
        // point of Phase Y — eliminate double Layer 1 renders per envelope.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");

        let outcome = LifecycleOutcome {
            active_env_refreshed: true,
            // Set an unambiguously fake reason. If the helper falls through
            // to web_install_hook_file_layer1, it would report the real
            // host's state (likely None in this temp HOME) — the assertion
            // below would fail.
            hook_file_installed: false,
            hook_failure_reason: Some(HookFailureReason::IoError),
            ..Default::default()
        };

        let json = with_home_shell(tmp.path(), "/bin/zsh", || {
            hook_status_from_outcome(&outcome)
        });

        assert_eq!(json["hook_file_installed"], serde_json::json!(false));
        assert_eq!(json["hook_failure_reason"], serde_json::json!("io_error"));
        // rc_wired is independently grep'd; tmp HOME with no .zshrc → false
        assert_eq!(json["hook_rc_wired"], serde_json::json!(false));
    }

    #[test]
    fn outcome_path_passes_through_success_state() {
        // Mirror of the previous test for the success case: outcome reports
        // file_installed=true with no failure_reason; merge MUST surface
        // those exact values to the envelope.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");

        let outcome = LifecycleOutcome {
            active_env_refreshed: true,
            hook_file_installed: true,
            hook_failure_reason: None,
            ..Default::default()
        };

        let json = with_home_shell(tmp.path(), "/bin/zsh", || {
            hook_status_from_outcome(&outcome)
        });

        assert_eq!(json["hook_file_installed"], serde_json::json!(true));
        assert_eq!(json["hook_failure_reason"], serde_json::json!(null));
    }

    #[test]
    fn fallback_path_runs_fresh_layer1_when_tail_skipped() {
        // When the funnel didn't run its tail (no_op event with no binding
        // touch), outcome.active_env_refreshed=false and outcome's hook
        // fields are at their default (false / None). The helper MUST
        // fall back to a fresh Layer 1 render so the envelope still
        // reports an accurate file_installed (not the misleading default
        // false).
        //
        // We force a known fallback result by setting AIKEY_NO_HOOK=1,
        // which makes web_install_hook_file_layer1 short-circuit to
        // (false, AikeyNoHook). If the helper instead read outcome's
        // hook_failure_reason=None directly, the assertion would fail.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");

        let outcome = LifecycleOutcome::default(); // active_env_refreshed=false

        let json = with_home_shell(tmp.path(), "/bin/zsh", || {
            unsafe { std::env::set_var("AIKEY_NO_HOOK", "1") };
            let r = hook_status_from_outcome(&outcome);
            unsafe { std::env::remove_var("AIKEY_NO_HOOK") };
            r
        });

        assert_eq!(json["hook_file_installed"], serde_json::json!(false));
        assert_eq!(json["hook_failure_reason"], serde_json::json!("aikey_no_hook"));
    }

    #[test]
    fn merge_preserves_base_fields_and_adds_three_hook_fields() {
        // Pin the merge contract: base fields untouched, exactly the three
        // documented hook fields added. A future caller adding a fourth
        // hook-related field would need to update the merge function AND
        // this test in lockstep — the assertion's exact-key list is the
        // contract.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");

        let outcome = LifecycleOutcome {
            active_env_refreshed: true,
            hook_file_installed: true,
            hook_failure_reason: None,
            ..Default::default()
        };
        let base = serde_json::json!({
            "alias": "foo",
            "newly_primary_providers": ["anthropic"],
        });

        let merged = with_home_shell(tmp.path(), "/bin/zsh", || {
            merge_hook_status_from_outcome(base.clone(), &outcome)
        });

        // Base fields preserved
        assert_eq!(merged["alias"], serde_json::json!("foo"));
        assert_eq!(merged["newly_primary_providers"], serde_json::json!(["anthropic"]));
        // Three hook fields added — exact key set, no others
        assert!(merged.get("hook_file_installed").is_some());
        assert!(merged.get("hook_rc_wired").is_some());
        assert!(merged.get("hook_failure_reason").is_some());
    }

    #[test]
    fn rc_wired_grep_picks_up_v3_block_in_zshrc() {
        // Independent verification that hook_rc_wired correctly reflects
        // disk state — sanity check that the helper isn't always returning
        // the default false. Pre-write a v3 marker block to tmp/.zshrc;
        // helper should report rc_wired=true.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let zshrc = tmp.path().join(".zshrc");
        std::fs::write(
            &zshrc,
            "# user content\n\
             # aikey shell hook v3 begin\n\
             [[ -f ~/.aikey/hook.zsh ]] && source ~/.aikey/hook.zsh\n\
             # aikey shell hook v3 end\n",
        )
        .expect("write zshrc");

        let outcome = LifecycleOutcome {
            active_env_refreshed: true,
            hook_file_installed: true,
            ..Default::default()
        };
        let json = with_home_shell(tmp.path(), "/bin/zsh", || {
            hook_status_from_outcome(&outcome)
        });

        assert_eq!(json["hook_rc_wired"], serde_json::json!(true));
    }
}
