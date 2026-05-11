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

use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::json;

use crate::commands_account::{oauth_provider_to_canonical, provider_info};
use crate::commands_proxy::proxy_port;
use crate::connectivity::default_base_url;
use crate::credential_type::CredentialType;
use crate::crypto;
use crate::storage;
// storage_platform is a submodule re-exported via `pub use storage_platform::*`
// on storage. Call its functions through `storage::...` directly.
use super::protocol::{ResultEnvelope, StdinEnvelope};
use super::stdin_json::{decode_vault_key, emit, emit_error};

/// Fully-qualified proxy URL clients should point their SDK at when using
/// this record (e.g. `http://127.0.0.1:27200/anthropic`). Built from the
/// running proxy port + the provider's proxy path (registered in
/// `provider_registry.yaml`). Returns None when the provider code is
/// unknown or has no proxy routing entry — callers should fall back to
/// the provider's own `base_url` / `official_base_url` in that case.
///
/// Factored out because three JSON-emitting handlers (`handle_get`,
/// `handle_list_personal_with_masked`, `handle_list_metadata_locked`)
/// all need the same computation and the result flows through to the
/// vault Web drawer as `route_url`.
fn route_url_for(provider_code: &str) -> Option<String> {
    let info = provider_info(provider_code)?;
    Some(format!("http://127.0.0.1:{}/{}", proxy_port(), info.proxy_path))
}

// ========== in-use detection ==========
//
// Loads the set of `key_source_ref` values that are currently bound in the
// default profile, partitioned by credential type so personal aliases and
// oauth `provider_account_id`s cannot collide. Used by the three vault list
// builders to emit `in_use: bool` per record (green-dot UI hint).
//
// Readonly connection: the list builders already either verified the vault
// key (unlocked path) or called `ensure_vault_exists()` (locked path); a
// second migration-bearing open would be redundant. If the readonly open
// or query fails (e.g. old vault without `user_profile_provider_bindings`),
// we degrade to empty sets — in_use comes back false everywhere, no error.
// Protocol-family classifier for UI grouping (V-layer transformer).
//
// Maps a record's M-layer provider_code (e.g. "kimi_code", "moonshot",
// "anthropic", or OAuth alias "claude") to its V-layer display family
// (e.g. "kimi", "anthropic"). Credentials that speak the same upstream API
// **and belong to the same family group in the UI** are placed together.
//
// 2026-05-08 显示层 family-grouping (详见 update/20260508-display-family-grouping.md):
// 之前实现误返回 canonical provider_code (e.g. "kimi_code" 自身),让 Web vault
// 列表把 Kimi family 三个 provider_code(kimi / kimi_code / moonshot)显示成
// 三个独立 group,违反"统一名词字典"原则。本函数是 V-layer transformer
// (DB query → HTTP response 中间),修正为真正返回 family。
//
// Pipeline:
//   ① OAuth alias canonicalization: "claude" → "anthropic"; "kimi" → "kimi_code"
//      (provider_registry.canonical 处理)
//   ② Family lookup: provider_registry.family_of("kimi_code") → "kimi"
//   ③ Unknown provider (custom user-entered, not in registry) → falls back to
//      its canonical code (= input lowercased),表现为独立 family group。
fn protocol_family_of(raw: Option<&str>) -> String {
    match raw {
        Some(s) if !s.is_empty() => {
            let canonical = oauth_provider_to_canonical(&s.to_lowercase());
            crate::provider_registry::family_of(canonical).to_string()
        }
        _ => "unknown".to_string(),
    }
}

/// Per-key-source map of providers that source is the active binding for.
///
/// Why a map (not a flat set; regression record 2026-04-30):
///   The previous flat `HashSet<key_ref>` returned by this function lost the
///   `provider_code` dimension of each binding row. Then `in_use: refs.
///   contains(&record.id)` evaluated `true` for ANY provider where the
///   record was active — but the Web UI groups records by their supported
///   providers, so a key bound only to `openai` (e.g. `zeroeleven_key_1`)
///   showed `in_use=true` under the `anthropic` group purely because its
///   alias appeared in the flat set. CLI's interactive picker didn't trip
///   this because it reads bindings per-provider directly. Web ended up
///   showing TWO active marks under `anthropic` (the OAuth account that's
///   actually anthropic-active + the openai-personal-key spuriously
///   marked in_use) — the user's "two inuse" report.
///
///   The fix is structural: keep the (key_ref → providers) mapping all the
///   way through to the JSON envelope. Emitters produce `in_use_for:
///   Vec<provider>` per record, and `in_use: bool` becomes derivative
///   (`!in_use_for.is_empty()`) for back-compat with older Web bundles.
///   New Web bundles render the badge ONLY when the current group's
///   provider is in `in_use_for`.
type ActiveBindingMap = HashMap<String, Vec<String>>;

/// Phase 3B revised (2026-05-11): emit team records inline with personal
/// + oauth in vault.list responses. Replaces the prior architecture where
/// team rows came from a separate cross-origin fetch to the team server
/// (see useTeamVaultStore). Now the CLI's `managed_virtual_keys_cache`
/// is the single source of truth for what team keys the user has
/// claimed locally — alias (local_alias preferred), route_url,
/// route_token, in_use_for state, and lifecycle metadata all flow
/// through one channel.
///
/// route_token derivation: team keys don't store a token in the cache
/// table — aikey-proxy expects `aikey_team_<virtual_key_id>` as the
/// bearer (see aikey-proxy/internal/proxy/dispatch.go line 84
/// "HasPrefix aikey_team_" path). We compute it here so the Web
/// drawer's "Route token" row mirrors the personal-key pattern.
///
/// route_url derivation: same `route_url_for(provider_code)` helper
/// personal/oauth use — the local aikey-proxy URL is per-provider, not
/// per-key.
///
/// effective_status: see `team_effective_status` helper below for the
/// full truth table. Short version: "usable right now" (decoupled from
/// "currently routed"), so claimed-but-not-routed keys correctly read
/// as active.

/// Format a Unix epoch (seconds, possibly negative) as an RFC3339 UTC
/// timestamp like "2027-05-10T08:34:20Z". Manual conversion to avoid
/// pulling in chrono just for this one call site. Algorithm: Gregorian
/// civil-from-days based on Howard Hinnant's date routines (public
/// domain, widely used). Negative timestamps are clamped — team key
/// expiry is always in the future on the wire, but defensive handling
/// keeps tests deterministic.
fn unix_to_rfc3339(secs: i64) -> String {
    let secs = secs.max(0);
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hh = (time_of_day / 3600) as u32;
    let mm = ((time_of_day / 60) % 60) as u32;
    let ss = (time_of_day % 60) as u32;

    // Civil-from-days: shift epoch to year -4800 so all dates fall in
    // the positive 400-year cycle. See Hinnant's "civil_from_days" paper.
    let z = days + 719_468; // days since 0000-03-01
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

/// Pure helper: derive `effective_status` ("active" | "inactive") for a
/// team key from the three CLI-local lifecycle fields.
///
/// "Usable" = the key can be selected via `aikey use` AND will route
/// through the proxy. Decoupled from "currently routed" (the latter
/// lives in `user_profile_provider_bindings` / `in_use_for`).
///
/// Truth table:
/// | key_status | share_status  | local_state            | result   |
/// |------------|---------------|------------------------|----------|
/// | active     | claimed       | active                 | active   |
/// | active     | claimed       | synced_inactive        | active   |
/// | active     | claimed       | prompt_dismissed       | active   |
/// | active     | claimed       | stale                  | inactive |
/// | active     | claimed       | disabled_by_*          | inactive |
/// | revoked    | *             | *                      | inactive |
/// | *          | pending_claim | *                      | inactive |
///
/// Regression: see bugfix
/// 20260511-team-vault-effective-status-mismaps-synced-inactive.md.
/// The prior naive `local_state == "active"` check conflated "usable"
/// with "currently routed", hiding the Use button on every
/// valid-but-not-routed team key.
pub(crate) fn team_effective_status(
    key_status: &str,
    share_status: &str,
    local_state: &str,
) -> &'static str {
    let is_usable = key_status == "active"
        && share_status == "claimed"
        && !local_state.starts_with("disabled_")
        && local_state != "stale";
    if is_usable { "active" } else { "inactive" }
}

fn team_records_for_emit(active_team: &ActiveBindingMap) -> Vec<serde_json::Value> {
    let entries = match storage::list_virtual_key_cache_readonly() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    entries
        .into_iter()
        .map(|t| {
            let effective_alias = t.local_alias.clone().unwrap_or_else(|| t.alias.clone());
            let route_token = format!("aikey_team_{}", t.virtual_key_id);
            let effective_status =
                team_effective_status(&t.key_status, &t.share_status, &t.local_state);
            // Wire-shape normalization for TeamVaultRecord:
            //   - share_status "pending_claim" → "pending" (UI union is
            //     'pending' | 'claimed' | 'revoked'). Pass through
            //     unrecognized values so debug/legacy values still surface
            //     in DOM rather than getting silently dropped.
            //   - expires_at i64 Unix seconds → RFC3339 string (UI type
            //     `expires_at?: string`). None → omit.
            let share_status_wire = match t.share_status.as_str() {
                "pending_claim" => "pending",
                other => other,
            };
            // expires_at: format as RFC3339 UTC string to match the
            // existing TeamVaultRecord.expires_at?: string contract that
            // the old teamVaultStore path emitted (via JSON serialization
            // of B's response). Manual conversion to avoid pulling chrono
            // in for one format call.
            let expires_at_iso = t.expires_at.map(unix_to_rfc3339);
            json!({
                "target": "team",
                "id": t.virtual_key_id,
                "virtual_key_id": t.virtual_key_id,
                "alias": effective_alias,
                "local_alias": t.local_alias,
                "protocol_family": protocol_family_of(Some(&t.provider_code)),
                "supported_providers": t.supported_providers,
                "share_status": share_status_wire,
                "effective_status": effective_status,
                "expires_at": expires_at_iso,
                "route_url": route_url_for(&t.provider_code),
                "route_token": route_token,
                // in_use_for: per-provider active binding membership. Same
                // semantics as personal — empty vec means "not bound
                // anywhere", non-empty means "active for those providers".
                "in_use_for": active_team.get(&t.virtual_key_id).cloned().unwrap_or_default(),
                "in_use": active_team.contains_key(&t.virtual_key_id),
                // status mirror for the existing TeamRowRecord chip
                // (UI reads either `effective_status` or `status` — both
                // are kept in lockstep for backward-compat with consumers
                // that branched before the field rename).
                "status": effective_status,
                // Shim fields: TeamRowRecord declares these as 0/null
                // placeholders since the team-store DTO didn't carry
                // them. Same defaults keep helpers/Row component happy.
                "created_at": 0,
                "last_used_at": serde_json::Value::Null,
                "use_count": 0,
            })
        })
        .collect()
}

fn load_active_binding_refs() -> (ActiveBindingMap, ActiveBindingMap, ActiveBindingMap) {
    let mut personal: ActiveBindingMap = HashMap::new();
    let mut oauth: ActiveBindingMap = HashMap::new();
    let mut team: ActiveBindingMap = HashMap::new();
    if let Ok(bindings) = storage::list_provider_bindings_readonly("default") {
        for b in bindings {
            match b.key_source_type {
                CredentialType::PersonalApiKey => {
                    personal.entry(b.key_source_ref).or_default().push(b.provider_code);
                }
                CredentialType::PersonalOAuthAccount => {
                    oauth.entry(b.key_source_ref).or_default().push(b.provider_code);
                }
                // Phase 3B (2026-05-11): team (ManagedVirtualKey) bindings
                // also captured. Map keyed by virtual_key_id so the Web
                // can populate per-team-row `in_use_for` after fetching the
                // team key list cross-origin from B. Previously this branch
                // was a no-op because team rows weren't rendered; clicking
                // `aikey use` on a team key wrote the binding correctly but
                // the Web showed no Active state, making it look like Use
                // had no effect.
                CredentialType::ManagedVirtualKey => {
                    team.entry(b.key_source_ref).or_default().push(b.provider_code);
                }
            }
        }
    }
    (personal, oauth, team)
}

// ========== payload types ==========

#[derive(Debug, Deserialize, Default)]
struct GetPayload {
    alias: String,
    // include_secret was removed 2026-04-24 (security review round 2): the
    // Go web server used this to power the /api/user/vault/reveal endpoint,
    // which has been removed entirely. Plaintext secrets no longer travel
    // CLI → Go → browser. Users who need the plaintext run `aikey get
    // <alias>` directly in a terminal (clipboard-only, auto-clears). Any
    // stdin-JSON payload that still carries `include_secret: true` is
    // silently ignored because the field is no longer deserialized.
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

    // Verify vault_key matches password_hash even though we no longer decrypt.
    // Why still verify: a locked / wrong-password caller must not receive
    // metadata either. The previous `include_secret: true` branch — which
    // powered the Go RevealHandler → browser pipeline — was removed on
    // 2026-04-24 so plaintext never leaves the terminal subprocess; users
    // run `aikey get <alias>` directly in a terminal for the actual plaintext.
    if let Err((c, m)) = verify_key(&env) {
        emit_error(req_id, c, m);
        return;
    }

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

    let official_base_url =
        meta.provider_code.as_deref().and_then(default_base_url);
    let data = json!({
        "alias": meta.alias,
        "created_at": meta.created_at,
        "provider_code": meta.provider_code,
        "base_url": meta.base_url,
        // Mirror of list_personal_with_masked — same rationale: let
        // callers know the real URL that gets used when base_url is
        // null, without having to embed PROVIDER_DEFAULTS client-side.
        "official_base_url": official_base_url,
        "route_url": meta.provider_code.as_deref().and_then(route_url_for),
        "supported_providers": meta.supported_providers,
        "has_secret": true,
    });

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

    let (active_personal, _active_oauth, active_team) = load_active_binding_refs();
    // Phase 3B revised (2026-05-11): team records inline with personal.
    // Web vault page now reads team rows from this list instead of
    // cross-fetching the team server via useTeamVaultStore.
    let team_records = team_records_for_emit(&active_team);

    let mut out = Vec::with_capacity(metas.len() + team_records.len());
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
        // `official_base_url`: the provider's recommended URL when the
        // user didn't set a custom `base_url` (stored value is NULL).
        // Resolved from the canonical PROVIDER_DEFAULTS table in
        // `connectivity::runtime`, which is the single source of truth
        // the rest of the CLI uses for connectivity probes. Exposing
        // it here lets the vault Web drawer show the real URL instead
        // of the opaque "provider default" placeholder + a one-click
        // copy button. Why surface it via the existing list response
        // rather than a new /v1/registry endpoint: "慎重新建 API" —
        // extending an existing payload is lower blast radius than
        // adding a new endpoint for a 6-row lookup table.
        let official_base_url =
            m.provider_code.as_deref().and_then(default_base_url);
        out.push(json!({
            "target": "personal",
            "id": m.alias,
            "alias": m.alias,
            "provider_code": m.provider_code,
            "protocol_family": protocol_family_of(m.provider_code.as_deref()),
            "base_url": m.base_url,
            "official_base_url": official_base_url,
        "route_url": m.provider_code.as_deref().and_then(route_url_for),
            "supported_providers": m.supported_providers,
            "created_at": m.created_at,
            "status": "active",
            "route_token": m.route_token,
            "last_used_at": m.last_used_at,
            "use_count": m.use_count.unwrap_or(0),
            // in_use_for: per-(record, provider) — empty list means not bound
            // anywhere; non-empty list = active for those specific providers.
            // in_use: bool kept for back-compat with older Web bundles, derived
            // as `!in_use_for.is_empty()`. New Web checks group.provider ∈
            // in_use_for. See load_active_binding_refs doc for the regression
            // record.
            "in_use_for": active_personal.get(&m.alias).cloned().unwrap_or_default(),
            "in_use": active_personal.contains_key(&m.alias),
            "secret_prefix": prefix,
            "secret_suffix": suffix,
            "secret_len": len,
        }));
    }

    // Phase 3B revised: append team records inline.
    let personal_count = out.len();
    out.extend(team_records.iter().cloned());

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "count": out.len(),
            "personal_count": personal_count,
            "team_count": team_records.len(),
            "entries": out,
            // Phase 3B (2026-05-11): team binding map keyed by virtual_key_id.
            // The local vault list returns Personal entries here, but the Web
            // also needs to know which team keys (fetched separately from B)
            // are the active binding for each provider — that information
            // lives in the same `user_profile_provider_bindings` table.
            // Surfacing it on the existing list response is the path of least
            // surprise (no new endpoint, no extra fetch hop).
            "team_active_bindings": active_team,
        }),
    ));
}

/// Extract a (prefix, suffix4, len) triple for masked UI display. Never
/// returns the middle of the secret.
///
/// 2026-05-09: prefix is always the first 12 chars. Previously we
/// matched a `KNOWN_SECRET_PREFIXES` allowlist (variable-width brand
/// markers like `sk-ant-api03-`) and fell back to first 4 chars
/// otherwise, which produced inconsistent column widths and hid
/// middle-of-prefix differentiators for unrecognized vendors. 12 chars
/// is enough to read brand markers (sk-ant-api03 = 12, sk-proj- = 8,
/// AIzaSy = 6, ya29. = 5, gsk_ = 4) AND give unrecognized providers
/// a reasonable identification window — without crossing the
/// "≥ half the secret" exposure line for any standard ≥ 32-char key.
///
/// Short-secret guard: secrets shorter than 24 chars return `"****"`
/// for both prefix and suffix. Rationale: with prefix=12 + suffix=4
/// we expose 16 chars; a mid-mask ≥ 8 chars means total ≥ 24.
/// Anything shorter than 24 chars is masked entirely. This is stricter
/// than the prior `len <= 8` guard but still covers the realistic
/// space (no major LLM provider issues keys < 32 chars).
fn extract_prefix_suffix(secret: &str) -> (String, String, usize) {
    const PREFIX_CHARS: usize = 12;
    const SUFFIX_CHARS: usize = 4;
    const MIN_LEN_FOR_REVEAL: usize = PREFIX_CHARS + SUFFIX_CHARS + 8; // 24

    let len = secret.chars().count();
    if len < MIN_LEN_FOR_REVEAL {
        return ("****".to_string(), "****".to_string(), len);
    }
    let chars: Vec<char> = secret.chars().collect();
    let prefix: String = chars[..PREFIX_CHARS].iter().collect();
    let suffix: String = chars[len - SUFFIX_CHARS..].iter().collect();
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
    let (_active_personal, active_oauth, active_team) = load_active_binding_refs();

    let arr: Vec<_> = accounts.iter().map(|a| {
        // route_url + route_token mirror the personal-key payload (2026-05-06).
        // Why: the user/vault drawer needs the same SDK-base-url + opaque token
        // pair for OAuth accounts that it already shows for personal keys, so
        // the values match `aikey route` exactly. Generation logic is identical
        // — `route_url_for` + `provider_proxy_path` already canonicalize aliases
        // (claude → anthropic, moonshot → moonshot/v1) the same way `aikey route`
        // does in handle_route. route_token is the server-issued opaque
        // identifier stored on the account; absent only on pre-route-token
        // vaults (returns null in that case, drawer hides the row).
        let route_token = storage::get_provider_account_route_token_readonly(&a.provider_account_id)
            .ok()
            .flatten();
        // Effective alias = local_alias if user has renamed, else
        // display_identity. v1.0.1-alpha.1 split the two so the
        // "alias differs from identity ⇒ render Identity row separately"
        // UI rule has a real signal — pre-split they were always equal.
        let effective_alias = a
            .local_alias
            .clone()
            .or_else(|| a.display_identity.clone());
        json!({
            "target": "oauth",
            "id": a.provider_account_id,
            "provider_account_id": a.provider_account_id,
            "provider": a.provider,
            "protocol_family": protocol_family_of(Some(&a.provider)),
            "auth_type": a.auth_type,
            "credential_type": a.credential_type.as_str(),
            "display_identity": a.display_identity,
            "alias": effective_alias,
            "local_alias": a.local_alias,
            "external_id": a.external_id,
            "org_uuid": a.org_uuid,
            "account_tier": a.account_tier,
            "status": a.status,
            "created_at": a.created_at,
            "last_used_at": a.last_used_at,
            "use_count": a.use_count.unwrap_or(0),
            // See list_personal handler for the in_use_for / in_use rationale.
            "in_use_for": active_oauth.get(&a.provider_account_id).cloned().unwrap_or_default(),
            "in_use": active_oauth.contains_key(&a.provider_account_id),
            "token_expires_at": expires_map.get(&a.provider_account_id).copied().flatten(),
            "route_url": route_url_for(&a.provider),
            "route_token": route_token,
        })
    }).collect();

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "count": arr.len(),
            "accounts": arr,
            // Phase 3B (2026-05-11): same payload contract as list_personal_with_masked.
            // See that handler for the team-binding rationale.
            // Phase 3B revised (2026-05-11): team records are emitted ONLY by
            // list_personal_with_masked (the records merge in Go's
            // collectRecords reads from there).
            "team_active_bindings": active_team,
        }),
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
    let (active_personal, active_oauth, active_team) = load_active_binding_refs();

    // Personal entries: plaintext metadata only. We go through the same
    // `list_entries_with_metadata` helper that the unlocked path uses —
    // it already returns only plaintext columns.
    match storage::list_entries_with_metadata() {
        Ok(metas) => {
            for m in metas {
                // Same rationale as list_personal_with_masked: surface
                // the resolved default URL so the Web drawer can show
                // the real provider endpoint in locked mode too (the
                // locked view is still the page users see before they
                // unlock, and copying the default URL is read-only).
                let official_base_url =
                    m.provider_code.as_deref().and_then(default_base_url);
                // route_token is blanked in the locked-state response. It is
                // a personal-bearer token accepted directly by aikey-proxy;
                // exposing the real value to anonymous local_bypass callers
                // (personal/trial editions) would let a malicious page issue
                // authenticated proxy calls without ever unlocking the vault.
                // The unlocked list (`list_personal_with_masked`) continues
                // to return the real token for in-UI copy flows. Emitting
                // null (rather than omitting the key) keeps the TS shape
                // contract `route_token: string | null` satisfied so the
                // drawer's `{personal.route_token && ...}` guard still works.
                // 2026-04-24 security review.
                out.push(json!({
                    "target": "personal",
                    "id": m.alias,
                    "alias": m.alias,
                    "provider_code": m.provider_code,
                    "protocol_family": protocol_family_of(m.provider_code.as_deref()),
                    "base_url": m.base_url,
                    "official_base_url": official_base_url,
                    "route_url": m.provider_code.as_deref().and_then(route_url_for),
                    "supported_providers": m.supported_providers,
                    "created_at": m.created_at,
                    "status": "active",
                    "route_token": serde_json::Value::Null,
                    "last_used_at": m.last_used_at,
                    "use_count": m.use_count.unwrap_or(0),
                    // See handle_list_personal_with_masked for the in_use_for
                    // / in_use rationale.
                    "in_use_for": active_personal.get(&m.alias).cloned().unwrap_or_default(),
                    "in_use": active_personal.contains_key(&m.alias),
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

    // OAuth accounts: same shape as `handle_list_oauth` plus the same
    // route_url-public + route_token-null security stance applied to personal
    // keys above (2026-04-24 security review). The drawer's
    // `{oauth.route_token && ...}` guard hides the row when null, so the
    // user sees the route URL but cannot copy a usable bearer until they
    // unlock the vault.
    let expires_map = load_oauth_expires_map().unwrap_or_default();
    let oauth_count = match storage::list_provider_accounts() {
        Ok(accounts) => {
            for a in &accounts {
                // Effective alias = local_alias if user has renamed, else
                // display_identity. Same rule as the unlocked-mode handler;
                // see comment in handle_list_oauth.
                let effective_alias = a
                    .local_alias
                    .clone()
                    .or_else(|| a.display_identity.clone());
                out.push(json!({
                    "target": "oauth",
                    "id": a.provider_account_id,
                    "provider_account_id": a.provider_account_id,
                    "provider": a.provider,
                    "protocol_family": protocol_family_of(Some(&a.provider)),
                    "auth_type": a.auth_type,
                    "credential_type": a.credential_type.as_str(),
                    "display_identity": a.display_identity,
                    "alias": effective_alias,
                    "local_alias": a.local_alias,
                    "external_id": a.external_id,
                    "org_uuid": a.org_uuid,
                    "account_tier": a.account_tier,
                    "status": a.status,
                    "created_at": a.created_at,
                    "last_used_at": a.last_used_at,
                    "use_count": a.use_count.unwrap_or(0),
                    // See handle_list_personal_with_masked for the in_use_for
                    // / in_use rationale.
                    "in_use_for": active_oauth.get(&a.provider_account_id).cloned().unwrap_or_default(),
                    "in_use": active_oauth.contains_key(&a.provider_account_id),
                    "token_expires_at": expires_map.get(&a.provider_account_id).copied().flatten(),
                    // Public — same SDK base URL the proxy serves; safe to expose
                    // in locked mode so users see the routing target before unlocking.
                    "route_url": route_url_for(&a.provider),
                    // Blanked in locked mode (same policy as personal route_token):
                    // an opaque bearer the proxy accepts; emitting null preserves
                    // the TS shape contract `route_token: string | null`.
                    "route_token": serde_json::Value::Null,
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

    // Phase 3B revised (2026-05-11): emit team records inline in the
    // locked path too. local_alias, share_status, expires_at, alias,
    // provider_code are all plaintext columns (not encrypted), so the
    // locked safety contract isn't broken. route_token IS sensitive
    // (a bearer the proxy accepts) — for team rows it's derived from
    // virtual_key_id without secrets, but exposing it would give an
    // unauthenticated reader a usable proxy bearer. Blank it to match
    // the personal/oauth locked-path policy (`null` so the TS
    // `{record.route_token && ...}` guards skip the row).
    let team_records: Vec<serde_json::Value> = team_records_for_emit(&active_team)
        .into_iter()
        .map(|mut v| {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("route_token".to_string(), serde_json::Value::Null);
            }
            v
        })
        .collect();
    let team_count = team_records.len();
    out.extend(team_records);

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "records": out,
            "counts": {
                "personal": personal_count,
                "oauth":    oauth_count,
                "team":     team_count,
                "total":    personal_count + oauth_count + team_count,
            },
            "locked": true,
            // Phase 3B (2026-05-11): team binding map. Surfaced even in the
            // locked list because the team-key list (B-side fetch) doesn't
            // require an unlocked vault either — keeping the Active state
            // consistent across lock/unlock prevents the team Active chip
            // from disappearing when the vault re-locks.
            "team_active_bindings": active_team,
        }),
    ));
}

#[cfg(test)]
mod active_binding_refs_tests {
    use super::*;
    use crate::storage;

    /// Regression pin (2026-04-30): user reported "two inuse under anthropic"
    /// after `aikey auth login claude` (writes anthropic-OAuth binding) +
    /// adding a personal key bound to openai (writes openai-personal binding).
    /// The bug was `load_active_binding_refs` returning a provider-agnostic
    /// `HashSet<key_ref>`, so when Web grouped records by provider and asked
    /// "is this record in_use", any record whose alias appeared in the
    /// global active set returned true — including the openai-personal key
    /// rendered under the anthropic group. Correct semantics: per-key-ref
    /// MAP of providers, so `in_use_for: ["openai"]` and the Web filters
    /// by group.provider before showing the badge.
    #[test]
    fn binding_refs_carry_per_provider_info_for_oauth_and_personal() {
        let guard = storage::TEST_VAULT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("vault.db");
        unsafe { std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap()); }
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).expect("salt");
        let pw = secrecy::SecretString::new("test_password".to_string());
        storage::initialize_vault(&salt, &pw).expect("init vault");

        // Reproduce user's flow:
        //   1. `aikey auth login claude` → binding(anthropic, oauth, acct-OAUTH)
        //   2. (key added via web) → no binding yet
        //   3. click `use` on openai-only personal key → binding(openai, personal, zeroeleven_key_1)
        storage::set_provider_binding("default", "anthropic", "personal_oauth_account", "acct-OAUTH").unwrap();
        storage::set_provider_binding("default", "openai", "personal", "zeroeleven_key_1").unwrap();

        let (personal, oauth, _team) = load_active_binding_refs();

        // OAuth account is bound for ANTHROPIC only — must not appear active
        // for any other provider.
        let anthropic_oauth_providers = oauth.get("acct-OAUTH").expect("OAuth ref present");
        assert_eq!(anthropic_oauth_providers, &vec!["anthropic".to_string()]);

        // Personal alias is bound for OPENAI only — must NOT show up in any
        // anthropic-grouped Web row's in_use computation. This is the
        // assertion that would have caught the user's bug.
        let openai_personal_providers = personal.get("zeroeleven_key_1").expect("personal ref present");
        assert_eq!(openai_personal_providers, &vec!["openai".to_string()]);

        // Cross-check: alias does NOT appear in oauth map (different
        // key_source_type partition) and account_id does not appear in
        // personal map. The flat `HashSet`-era code would have collapsed
        // both partitions so this check verifies the type discrimination.
        assert!(!oauth.contains_key("zeroeleven_key_1"));
        assert!(!personal.contains_key("acct-OAUTH"));

        drop(guard);
    }

    /// Multi-provider key (e.g. aggregator gateway): one alias bound for
    /// BOTH anthropic + openai. The map MUST list both providers under the
    /// same alias so the Web shows in_use under both groups (and ONLY
    /// those two — not under random unrelated groups like `kimi`).
    #[test]
    fn binding_refs_handle_multi_provider_alias() {
        let guard = storage::TEST_VAULT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("vault.db");
        unsafe { std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap()); }
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).expect("salt");
        let pw = secrecy::SecretString::new("test_password".to_string());
        storage::initialize_vault(&salt, &pw).expect("init vault");

        storage::set_provider_binding("default", "anthropic", "personal", "openrouter_key").unwrap();
        storage::set_provider_binding("default", "openai", "personal", "openrouter_key").unwrap();

        let (personal, _oauth, _team) = load_active_binding_refs();
        let providers = personal.get("openrouter_key").expect("alias present");
        let mut sorted = providers.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["anthropic".to_string(), "openai".to_string()]);

        drop(guard);
    }

    /// Phase 3B C (2026-05-11) — ghost binding cleanup pin:
    /// `aikey logout` must wipe all team-key rows from the bindings table,
    /// otherwise a subsequent login (even to a different account) would
    /// re-activate stale bindings pointing at vk_ids the new account
    /// doesn't own. Asserts:
    ///   - remove_bindings_by_key_source_type returns the affected rows
    ///     (provider_code, vk_id) pairs
    ///   - rows are actually deleted from the table
    ///   - other binding types (personal / oauth) are NOT touched
    #[test]
    fn remove_bindings_by_key_source_type_wipes_team_only() {
        let guard = storage::TEST_VAULT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("vault.db");
        unsafe { std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap()); }
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).expect("salt");
        let pw = secrecy::SecretString::new("test_password".to_string());
        storage::initialize_vault(&salt, &pw).expect("init vault");

        // Mix of three binding types, simulating a user who has personal +
        // OAuth + team bindings active simultaneously.
        storage::set_provider_binding("default", "anthropic", "managed_virtual_key", "vk_team_anthropic").unwrap();
        storage::set_provider_binding("default", "google", "managed_virtual_key", "vk_team_gemini").unwrap();
        storage::set_provider_binding("default", "openai", "personal", "personal_key").unwrap();
        storage::set_provider_binding("default", "kimi_code", "personal_oauth_account", "oauth_acct_id").unwrap();

        // Bulk-wipe team bindings.
        let cleared = storage::remove_bindings_by_key_source_type(
            "default",
            "managed_virtual_key",
        ).unwrap();

        // Both team rows surfaced.
        assert_eq!(cleared.len(), 2);
        let cleared_set: std::collections::HashSet<(String, String)> =
            cleared.into_iter().collect();
        assert!(cleared_set.contains(&("anthropic".to_string(), "vk_team_anthropic".to_string())));
        assert!(cleared_set.contains(&("google".to_string(), "vk_team_gemini".to_string())));

        // Personal + OAuth bindings preserved.
        let (personal, oauth, team) = load_active_binding_refs();
        assert!(personal.contains_key("personal_key"), "personal binding wiped accidentally");
        assert!(oauth.contains_key("oauth_acct_id"), "oauth binding wiped accidentally");
        assert!(team.is_empty(), "team bindings should be empty after bulk wipe");

        drop(guard);
    }

    /// Phase 3B regression pin (2026-05-11): user clicked Use on a team key
    /// from the Web vault page; the binding row was written correctly
    /// (`key_source_type='managed_virtual_key'`, `key_source_ref=<vk_id>`)
    /// but no Web row showed an Active state because `load_active_binding_refs`
    /// dropped the team branch on the floor (see git blame on the
    /// `_ => {}` arm pre-fix). Web sees `team_active_bindings: {}` and the
    /// in_use_for shim returns false → "Use button doesn't take effect"
    /// from the user's perspective.
    ///
    /// Asserts:
    ///   - team key bindings DO appear in the third map keyed by virtual_key_id
    ///   - the (vk_id → providers) shape matches the Personal/OAuth maps
    ///   - team and personal bindings under the same provider don't collide
    ///     (different partition by `key_source_type`)
    #[test]
    fn binding_refs_now_carry_team_bindings() {
        let guard = storage::TEST_VAULT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("vault.db");
        unsafe { std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap()); }
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).expect("salt");
        let pw = secrecy::SecretString::new("test_password".to_string());
        storage::initialize_vault(&salt, &pw).expect("init vault");

        // Mirror real-world flow: anthropic binding owned by a team VK,
        // openai binding owned by a personal alias. Both rows live in the
        // same `user_profile_provider_bindings` table — only key_source_type
        // distinguishes them. This is exactly the shape our team-merge UX hit.
        storage::set_provider_binding("default", "anthropic", "managed_virtual_key", "vk_team_anthropic_xxx").unwrap();
        storage::set_provider_binding("default", "openai", "personal", "personal_openai_alias").unwrap();

        let (personal, oauth, team) = load_active_binding_refs();

        // Team binding extracted into the third map.
        let team_providers = team.get("vk_team_anthropic_xxx").expect("team vk_id present");
        assert_eq!(team_providers, &vec!["anthropic".to_string()]);

        // Personal binding extracted into the personal map.
        let personal_providers = personal.get("personal_openai_alias").expect("personal alias present");
        assert_eq!(personal_providers, &vec!["openai".to_string()]);

        // Cross-partition guard: team vk_id MUST NOT appear in the personal
        // or oauth map (would re-trigger the original "two inuse" regression
        // class for personal/oauth Web rows).
        assert!(!personal.contains_key("vk_team_anthropic_xxx"));
        assert!(!oauth.contains_key("vk_team_anthropic_xxx"));

        drop(guard);
    }
}

#[cfg(test)]
mod prefix_suffix_tests {
    use super::extract_prefix_suffix;

    // 2026-05-09 contract: prefix is always the first 12 chars (no
    // brand-allowlist matching anymore); suffix is always the last 4
    // chars; secrets shorter than 24 chars return "****" / "****"
    // (full mask). The tests below pin both reveal-mode shape and the
    // short-secret guard.

    #[test]
    fn anthropic_api_v3_prefix_is_first_12() {
        // 30-char secret (≥ 24 → reveal). First 12 covers `sk-ant-api03`
        // (12 chars; the trailing `-` is char 13 and gets masked) so the
        // brand is still identifiable.
        let s = "sk-ant-api03-XXXXXXXXXXXXafef3";
        let (p, sfx, len) = extract_prefix_suffix(s);
        assert_eq!(p, "sk-ant-api03");
        assert_eq!(sfx, "fef3");
        assert_eq!(len, s.chars().count());
    }

    #[test]
    fn openai_project_prefix_is_first_12() {
        // sk-proj- = 8 chars; 12-char window grabs into the random body,
        // which is fine — the brand prefix is still visually present.
        let (p, sfx, _) = extract_prefix_suffix("sk-proj-AAAAAAAAAAAAAAAAAAAAAAGHIJ");
        assert_eq!(p, "sk-proj-AAAA");
        assert_eq!(sfx, "GHIJ");
    }

    #[test]
    fn gemini_prefix_is_first_12() {
        // AIzaSy = 6 chars; 12-char window includes 6 random chars after.
        let (p, _, _) = extract_prefix_suffix("AIzaSyAAAAAAAAAAAAAAAAAAAkzM1");
        assert_eq!(p, "AIzaSyAAAAAA");
    }

    #[test]
    fn unknown_shape_first_12_chars() {
        // Secret ≥ 24 chars, no recognized brand: still gets first 12.
        // "zzzz1234567890abcdefghijklmn" — first 12 = "zzzz12345678",
        // last 4 = "klmn".
        let (p, sfx, len) = extract_prefix_suffix("zzzz1234567890abcdefghijklmn");
        assert_eq!(p, "zzzz12345678");
        assert_eq!(sfx, "klmn");
        assert_eq!(len, 28);
    }

    #[test]
    fn boundary_24_chars_reveals() {
        // Exactly 24 chars: prefix=12, suffix=4, mid=8 hidden — minimum
        // length that still passes the short-secret guard.
        let (p, sfx, len) = extract_prefix_suffix("123456789012XXXXXXXXLAST");
        assert_eq!(p, "123456789012");
        assert_eq!(sfx, "LAST");
        assert_eq!(len, 24);
    }

    #[test]
    fn boundary_23_chars_is_fully_masked() {
        // One short of the 24-char threshold: full mask both ends.
        let (p, sfx, len) = extract_prefix_suffix("12345678901234567890123");
        assert_eq!(p, "****");
        assert_eq!(sfx, "****");
        assert_eq!(len, 23);
    }

    #[test]
    fn short_secret_is_fully_masked() {
        // Various short lengths under the 24-char threshold.
        for s in ["short", "12345678", "sk-ant-12345"] {
            let (p, sfx, _) = extract_prefix_suffix(s);
            assert_eq!(p, "****", "expected full mask for '{}'", s);
            assert_eq!(sfx, "****", "expected full mask for '{}'", s);
        }
    }

    #[test]
    fn long_real_world_anthropic_key() {
        // Realistic 108-char Anthropic key. First 12 includes the brand,
        // suffix shows last 4 — exactly the masking the Vault drawer expects.
        let s = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1234";
        let (p, sfx, len) = extract_prefix_suffix(s);
        assert_eq!(p, "sk-ant-api03");
        assert_eq!(sfx, "1234");
        assert_eq!(len, s.chars().count());
    }
}

#[cfg(test)]
mod protocol_family_of_tests {
    use super::protocol_family_of;

    // 2026-05-08 显示层 family-grouping (详见 update/20260508-display-family-grouping.md):
    // V-layer transformer 必须返回 display family,不是 canonical provider_code。
    // Web vault 列表用此字段做分组渲染,语义错误会导致 family 内多 provider_code 显示成多个独立 group。

    #[test]
    fn kimi_code_returns_kimi_family() {
        assert_eq!(protocol_family_of(Some("kimi_code")), "kimi");
    }

    #[test]
    fn moonshot_returns_kimi_family() {
        // 拆分前 'moonshot' 与 'kimi_code' 在不同 group,改后合并到 kimi family
        assert_eq!(protocol_family_of(Some("moonshot")), "kimi");
    }

    #[test]
    fn kimi_oauth_alias_returns_kimi_family() {
        // 'kimi' 是 kimi_code 的 OAuth alias → canonical "kimi_code" → family "kimi"
        assert_eq!(protocol_family_of(Some("kimi")), "kimi");
    }

    #[test]
    fn anthropic_returns_anthropic_family_unchanged() {
        // 单 platform family,family == code,与改前行为完全一致
        assert_eq!(protocol_family_of(Some("anthropic")), "anthropic");
    }

    #[test]
    fn claude_oauth_alias_returns_anthropic_family() {
        assert_eq!(protocol_family_of(Some("claude")), "anthropic");
    }

    #[test]
    fn unknown_custom_provider_falls_back_to_canonical() {
        // 用户自定义不在 registry 的 provider → 独立 family group (与改前一致)
        assert_eq!(protocol_family_of(Some("custom-vendor")), "custom-vendor");
    }

    #[test]
    fn empty_or_none_returns_unknown() {
        assert_eq!(protocol_family_of(None), "unknown");
        assert_eq!(protocol_family_of(Some("")), "unknown");
    }

    #[test]
    fn case_insensitive_input() {
        // 输入大小写无关
        assert_eq!(protocol_family_of(Some("KIMI_CODE")), "kimi");
        assert_eq!(protocol_family_of(Some("Moonshot")), "kimi");
    }
}
