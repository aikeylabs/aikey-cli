//! `aikey app *` subcommands — third-party Agent application management (Phase 4).
//!
//! These commands write the `app_records` + `app_keys` tables (schema added
//! by migrations.rs v1_0_0_baseline.upgrade() tail block, AKL-101) and the
//! `user_profile_provider_bindings` table with `profile_id = 'app:<slug>'`
//! scope. After every write, `storage::bump_vault_change_seq()` advances
//! the change-seq counter; aikey-proxy's `syncManagedKeys` loop (5s tick)
//! detects the bump and atomically rebuilds the registry — `aikey app
//! rotate / revoke / pause / resume / register / route` take effect
//! within 5s without `aikey proxy restart`. `maybe_warn_stale()` is left
//! as an informational helper (no auto-restart since 2026-05-22).
//! See memory: no-proxy-restart-for-vault-mutations.
//!
//! Scope (AKL-106 P0):
//!   - `register`   — UPSERT app_records (no token issued)
//!   - `authorize`  — INSERT app_keys (active) + optional initial binding,
//!                    prints env lines for the Agent
//!   - `list`       — SELECT app_records LEFT JOIN active app_keys
//!   - `route`      — UPSERT user_profile_provider_bindings (profile=app:<slug>)
//!   - `revoke`     — UPDATE app_keys SET status='revoked' for active row
//!
//! Out of scope (AKL-301 Sprint 3):
//!   - pause / resume / rotate / uninstall / doctor / usage
//!
//! Spec references:
//!   - 路线图 §3.2.2 (CLI app subcommands matrix)
//!   - 主方案 §11.A (writer pseudo-code) + §11.C (schema)
//!   - ER 图 §4.1-§4.6 (business flows)

use crate::credential_type::CredentialType;
use crate::storage;
use rusqlite::{params, Connection};

mod handlers;
mod install;
pub use handlers::{
    handle_list, handle_pause, handle_register, handle_resume, handle_revoke,
    handle_rotate, handle_route,
};
pub use install::handle_install;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// First-party whitelist (gates app_kind='first-party' + follow_user_active).
// ---------------------------------------------------------------------------

/// First-party app slugs allowed to register with `app_kind='first-party'`.
/// Only these slugs can set `follow_user_active=true` (which lets the app
/// share the user's `aikey use` selection rather than its own isolated
/// binding) — see 主方案 §3.3 for why this is a privileged mode.
///
/// Phase 4 launch list contains only `degrade-detector` (the official
/// degradation-probe plugin). Adding entries here is a deliberate trust
/// decision; do NOT widen the list without product sign-off.
pub const FIRST_PARTY_SLUGS: &[&str] = &["degrade-detector"];

pub fn is_first_party(slug: &str) -> bool {
    FIRST_PARTY_SLUGS.contains(&slug)
}

// ---------------------------------------------------------------------------
// Slug + protocol validation (writer-side guardrails matching main spec).
// ---------------------------------------------------------------------------

/// Allowed upstream-provider values for `app_records.upstreams`.
///
/// "Upstream" here = the LLM provider whose API + key the Agent will
/// ultimately consume. AiKey's URL is `/apps/<slug>/v1/...` (OpenAI-wire
/// at `/chat/completions`, Anthropic-wire at `/v1/messages`); routing
/// to the actual upstream is decided at request time by inferring from
/// body.model and looking up the binding.
///
/// This list must align with `aikey-proxy/internal/provider/model_router.go`'s
/// model-prefix → provider table + `IsOpenAIWireCompatible` catalog,
/// and the protocol-translator's per-edge support matrix in
/// `aikey-proxy/pkg/protocol-translator/pairs/*`.
///
/// 2026-05-21 (B addition): expanded from `[openai, anthropic]` to the
/// full OpenAI-wire-compatible family + Anthropic. New entries go through
/// the OpenAI-wire fast path (no translator pair needed); the per-provider
/// adapter handles BaseURL + auth header differences.
pub const ALLOWED_UPSTREAMS: &[&str] = &[
    // Anthropic — uses Anthropic native wire (translator engages when
    // inbound is OpenAI, passthrough when inbound is Anthropic).
    "anthropic",
    // OpenAI itself.
    "openai",
    // Tier-1 OpenAI-compatible direct providers.
    "kimi", "moonshot", "deepseek", "qwen",
    "groq", "together", "perplexity", "fireworks", "deepinfra",
    "siliconflow", "siliconflow-cn", "zhipu", "doubao", "01ai",
    // Aggregator gateways that forward OpenAI-wire to backends.
    "openrouter", "openrouter-ai", "litellm", "portkey",
];

/// `slug` form check: 3-64 chars, lowercase letters + digits + dash only,
/// must start with a letter, must not end with dash, no consecutive dashes.
/// Mirrors npm-package-name style conservatism so URLs and JSON keys
/// can't surprise the parser.
pub fn validate_slug(slug: &str) -> Result<(), String> {
    if slug.len() < 3 || slug.len() > 64 {
        return Err(format!(
            "app slug must be 3-64 chars, got {} ({})",
            slug.len(),
            slug
        ));
    }
    let bytes = slug.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return Err(format!("app slug must start with a lowercase letter: {}", slug));
    }
    if bytes[bytes.len() - 1] == b'-' {
        return Err(format!("app slug must not end with '-': {}", slug));
    }
    let mut prev_dash = false;
    for (i, c) in bytes.iter().enumerate() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-';
        if !ok {
            return Err(format!(
                "app slug char #{} is not [a-z0-9-]: {} (in {})",
                i,
                *c as char,
                slug
            ));
        }
        let is_dash = *c == b'-';
        if is_dash && prev_dash {
            return Err(format!("app slug has consecutive '-': {}", slug));
        }
        prev_dash = is_dash;
    }
    Ok(())
}

pub fn validate_upstreams(upstreams: &[String]) -> Result<(), String> {
    if upstreams.is_empty() {
        return Err("at least one --upstreams value is required (openai, anthropic)".to_string());
    }
    for u in upstreams {
        if !ALLOWED_UPSTREAMS.contains(&u.as_str()) {
            return Err(format!(
                "unsupported upstream {:?}; allowed: {}",
                u,
                ALLOWED_UPSTREAMS.join(", ")
            ));
        }
    }
    Ok(())
}

/// Validates the cross-field invariants from 主方案 §11.1:
///   1. `app_kind='first-party'` requires slug ∈ FIRST_PARTY_SLUGS.
///   2. `follow_user_active=true` requires `app_kind='first-party'`.
///
/// Returning Err here aborts the write before any vault row is touched.
pub fn validate_first_party_invariants(
    slug: &str,
    first_party: bool,
    follow_user_active: bool,
) -> Result<(), String> {
    if first_party && !is_first_party(slug) {
        return Err(format!(
            "slug '{}' is not in the first-party whitelist; only the following slugs may register with --first-party: [{}]",
            slug,
            FIRST_PARTY_SLUGS.join(", ")
        ));
    }
    if follow_user_active && !first_party {
        return Err(
            "--follow-user-active requires --first-party (only first-party apps may share the user's `aikey use` binding)"
                .to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Storage helpers — direct SQL on the vault SQLite. Mirror the patterns from
// storage_platform.rs (open_connection + rusqlite::params! + transaction
// for multi-table writes).
// ---------------------------------------------------------------------------

/// One row from `app_records` (read view used by `list` + `authorize`).
#[derive(Debug, Clone)]
pub struct AppRecord {
    pub slug: String,
    pub name: String,
    pub vendor: String,
    pub upstreams: Vec<String>,
    pub app_kind: String,
    pub follow_user_active: bool,
    pub requested_permissions: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Active-key summary joined per app for `list` output. None ⇒ app
/// registered but never authorized (no active key).
#[derive(Debug, Clone)]
pub struct ActiveAppKeyInfo {
    pub key_id: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// UPSERT `app_records`. Writer of `register`. Existing rows are updated in
/// place (name / vendor / protocols / app_kind / follow_user_active /
/// requested_permissions / updated_at) — slug is the primary key and stays
/// stable. Returns true if a new row was inserted, false if an existing one
/// was updated (purely informational for the caller's success message).
pub fn upsert_app_record(
    slug: &str,
    name: &str,
    vendor: &str,
    upstreams: &[String],
    app_kind: &str,
    follow_user_active: bool,
    requested_permissions: &[String],
) -> Result<bool, String> {
    let conn = storage::open_connection()?;
    let inserted = upsert_app_record_with_conn(
        &conn,
        slug,
        name,
        vendor,
        upstreams,
        app_kind,
        follow_user_active,
        requested_permissions,
    )?;
    let _ = storage::bump_vault_change_seq();
    Ok(inserted)
}

/// Test-friendly inner: same SQL as the public wrapper but takes the
/// Connection so the test suite can drive it against an in-memory vault
/// without touching the real ~/.aikey database. The public wrapper is
/// a 4-line shell; all behavior worth pinning lives here.
pub fn upsert_app_record_with_conn(
    conn: &Connection,
    slug: &str,
    name: &str,
    vendor: &str,
    upstreams: &[String],
    app_kind: &str,
    follow_user_active: bool,
    requested_permissions: &[String],
) -> Result<bool, String> {
    let upstreams_json = serde_json::to_string(upstreams)
        .map_err(|e| format!("encode upstreams JSON: {}", e))?;
    let permissions_json = serde_json::to_string(requested_permissions)
        .map_err(|e| format!("encode requested_permissions JSON: {}", e))?;

    let pre_existed: bool = conn
        .query_row(
            "SELECT 1 FROM app_records WHERE slug = ?1",
            params![slug],
            |_| Ok(()),
        )
        .is_ok();

    conn.execute(
        "INSERT INTO app_records (slug, name, vendor, upstreams, app_kind, follow_user_active, requested_permissions)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(slug) DO UPDATE SET
            name = excluded.name,
            vendor = excluded.vendor,
            upstreams = excluded.upstreams,
            app_kind = excluded.app_kind,
            follow_user_active = excluded.follow_user_active,
            requested_permissions = excluded.requested_permissions,
            updated_at = strftime('%s', 'now')",
        params![
            slug,
            name,
            vendor,
            upstreams_json,
            app_kind,
            follow_user_active as i64,
            permissions_json,
        ],
    )
    .map_err(|e| format!("UPSERT app_records: {}", e))?;
    Ok(!pre_existed)
}

/// SELECT a single `app_records` row by slug. Used by `authorize` to load
/// the metadata for the consent prompt and by `list`.
pub fn get_app_record(slug: &str) -> Result<Option<AppRecord>, String> {
    let conn = storage::open_connection()?;
    get_app_record_with_conn(&conn, slug)
}

/// Test-friendly inner. See `upsert_app_record_with_conn`.
pub fn get_app_record_with_conn(
    conn: &Connection,
    slug: &str,
) -> Result<Option<AppRecord>, String> {
    let row = conn
        .query_row(
            "SELECT slug, name, vendor, upstreams, app_kind, follow_user_active,
                    requested_permissions, created_at, updated_at
               FROM app_records WHERE slug = ?1",
            params![slug],
            |r| {
                let upstreams_json: String = r.get(3)?;
                let permissions_json: Option<String> = r.get(6)?;
                let follow: i64 = r.get(5)?;
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    upstreams_json,
                    r.get::<_, String>(4)?,
                    follow != 0,
                    permissions_json,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                ))
            },
        );
    let (slug, name, vendor, upstreams_json, app_kind, follow, perms_json, created_at, updated_at) =
        match row {
            Ok(t) => t,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => {
                // app_records may not exist on a vault that hasn't been opened by a
                // post-AKL-101 binary yet. Treat as "no row" rather than failing —
                // mirrors GetAppRecord's graceful-nil behavior on the Go side.
                if e.to_string().contains("no such table") {
                    return Ok(None);
                }
                return Err(format!("read app_records for slug={:?}: {}", slug, e));
            }
        };
    let upstreams: Vec<String> = serde_json::from_str(&upstreams_json)
        .map_err(|e| format!("decode upstreams JSON for slug={:?}: {}", slug, e))?;
    let requested_permissions: Vec<String> = match perms_json {
        Some(s) if !s.is_empty() => {
            serde_json::from_str(&s).map_err(|e| format!("decode permissions JSON: {}", e))?
        }
        _ => Vec::new(),
    };
    Ok(Some(AppRecord {
        slug,
        name,
        vendor,
        upstreams,
        app_kind,
        follow_user_active: follow,
        requested_permissions,
        created_at,
        updated_at,
    }))
}

/// List all app_records with the most recent active key (if any) joined in.
pub fn list_apps() -> Result<Vec<(AppRecord, Option<ActiveAppKeyInfo>)>, String> {
    let conn = storage::open_connection()?;
    let mut stmt = conn
        .prepare(
            "SELECT r.slug, r.name, r.vendor, r.upstreams, r.app_kind, r.follow_user_active,
                    r.requested_permissions, r.created_at, r.updated_at,
                    k.key_id, k.created_at, k.last_used_at
               FROM app_records r
          LEFT JOIN app_keys k
                 ON k.app_slug = r.slug AND k.status = 'active'
           ORDER BY r.created_at DESC",
        )
        .map_err(|e| {
            // Pre-AKL-101 vaults won't have app_records; treat as empty list.
            if e.to_string().contains("no such table") {
                "no such table".to_string()
            } else {
                format!("prepare list_apps: {}", e)
            }
        })?;

    if stmt.column_count() == 0 {
        return Ok(Vec::new());
    }

    let rows_iter = stmt
        .query_map([], |r| {
            let upstreams_json: String = r.get(3)?;
            let perms_json: Option<String> = r.get(6)?;
            let follow: i64 = r.get(5)?;
            let key_id: Option<String> = r.get(9)?;
            let key_created: Option<i64> = r.get(10)?;
            let key_last: Option<i64> = r.get(11)?;
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                upstreams_json,
                r.get::<_, String>(4)?,
                follow != 0,
                perms_json,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
                key_id,
                key_created,
                key_last,
            ))
        })
        .map_err(|e| format!("query list_apps: {}", e))?;

    let mut out = Vec::new();
    for row in rows_iter {
        let (slug, name, vendor, upstreams_json, app_kind, follow, perms_json, created_at,
             updated_at, key_id, key_created, key_last) =
            row.map_err(|e| format!("scan list_apps row: {}", e))?;
        let upstreams: Vec<String> =
            serde_json::from_str(&upstreams_json).unwrap_or_default();
        let requested_permissions: Vec<String> = match perms_json {
            Some(s) if !s.is_empty() => serde_json::from_str(&s).unwrap_or_default(),
            _ => Vec::new(),
        };
        let rec = AppRecord {
            slug,
            name,
            vendor,
            upstreams,
            app_kind,
            follow_user_active: follow,
            requested_permissions,
            created_at,
            updated_at,
        };
        let active = match (key_id, key_created) {
            (Some(id), Some(created)) => Some(ActiveAppKeyInfo {
                key_id: id,
                created_at: created,
                last_used_at: key_last,
            }),
            _ => None,
        };
        out.push((rec, active));
    }
    Ok(out)
}

/// Mints a new app key row + writes it active. Caller is responsible for any
/// pre-checks (slug exists, no existing active key). Returns the (key_id,
/// route_token) tuple — route_token is the plaintext bearer for the Agent.
///
/// WARNING: route_token is plaintext and MUST NOT be logged. Caller prints
/// it to stdout once for the user to copy, then drops the value.
pub fn insert_active_app_key(slug: &str) -> Result<(String, String), String> {
    let key_id = uuid_v4_simple();
    let route_token = storage::generate_app_route_token();
    let conn = storage::open_connection()?;
    conn.execute(
        "INSERT INTO app_keys (key_id, app_slug, route_token, status) VALUES (?1, ?2, ?3, 'active')",
        params![key_id, slug, route_token],
    )
    .map_err(|e| format!("INSERT app_keys for slug={:?}: {}", slug, e))?;
    let _ = storage::bump_vault_change_seq();
    Ok((key_id, route_token))
}

/// Authorize-time atomic write: insert active app_key AND optionally write
/// the initial provider bindings, all under one transaction so a partial
/// failure can't leave the user with "token exists but bindings missing"
/// (which would 409 every Agent request).
///
/// `initial_bindings` is the list of `(provider_code, key_source_type,
/// key_source_ref)` triples to UPSERT under `profile_id = "app:<slug>"`.
/// An empty slice ⇒ no binding writes (user can set via `aikey app route`
/// later).
pub fn authorize_atomic(
    slug: &str,
    initial_bindings: &[(String, CredentialType, String)],
) -> Result<(String, String), String> {
    let mut conn = storage::open_connection()?;
    let result = authorize_atomic_with_conn(&mut conn, slug, initial_bindings)?;
    let _ = storage::bump_vault_change_seq();
    Ok(result)
}

/// Test-friendly inner. The Connection is `&mut` because `transaction()`
/// borrows it mutably.
///
/// Profile-row seed (2026-05-20 fix): `user_profile_provider_bindings.profile_id`
/// has a FK → `user_profiles(id)`. The `default` profile is seeded at vault
/// init (migrations.rs), but app scopes are not. So before we write any
/// binding under `profile_id = "app:<slug>"` we must INSERT OR IGNORE a
/// matching row into `user_profiles`. This was missed in the 主方案 §11.C
/// "reuse existing binding table" wording and surfaced as a FK failure in
/// AKL-107 (see commands_app/tests.rs::authorize_atomic_inserts_key_and_bindings).
///
/// `is_active = 0` for the app profile — these are auxiliary scopes, not
/// the user's currently-active profile (which the UI profile switcher
/// tracks via `is_active = 1` rows).
pub fn authorize_atomic_with_conn(
    conn: &mut Connection,
    slug: &str,
    initial_bindings: &[(String, CredentialType, String)],
) -> Result<(String, String), String> {
    let key_id = uuid_v4_simple();
    let route_token = storage::generate_app_route_token();
    let tx = conn.transaction().map_err(|e| format!("begin authorize tx: {}", e))?;

    tx.execute(
        "INSERT INTO app_keys (key_id, app_slug, route_token, status) VALUES (?1, ?2, ?3, 'active')",
        params![key_id, slug, route_token],
    )
    .map_err(|e| format!("INSERT app_keys: {}", e))?;

    let profile_id = format!("app:{}", slug);

    if !initial_bindings.is_empty() {
        // FK-prerequisite: ensure the app profile row exists in user_profiles
        // before writing any binding under `app:<slug>` scope. Idempotent —
        // re-authorize after revoke is a no-op here.
        tx.execute(
            "INSERT OR IGNORE INTO user_profiles (id, is_active) VALUES (?1, 0)",
            params![profile_id],
        )
        .map_err(|e| format!("seed user_profiles row for {}: {}", profile_id, e))?;
    }

    for (provider_code, key_type, key_ref) in initial_bindings {
        tx.execute(
            "INSERT INTO user_profile_provider_bindings
                (profile_id, provider_code, key_source_type, key_source_ref, updated_at)
             VALUES (?1, ?2, ?3, ?4, strftime('%s', 'now'))
             ON CONFLICT (profile_id, provider_code) DO UPDATE SET
                key_source_type = excluded.key_source_type,
                key_source_ref  = excluded.key_source_ref,
                updated_at      = excluded.updated_at",
            params![profile_id, provider_code, key_type.as_str(), key_ref],
        )
        .map_err(|e| format!("UPSERT binding profile={} provider={}: {}", profile_id, provider_code, e))?;
    }

    tx.commit().map_err(|e| format!("commit authorize tx: {}", e))?;
    Ok((key_id, route_token))
}

/// UPSERT a single provider binding for the app's isolated scope
/// (`profile_id = "app:<slug>"`). Used by `aikey app route` after initial
/// authorize, or to change which credential the app resolves with.
///
/// Seeds the user_profiles row first (see authorize_atomic_with_conn docs
/// for why) so the binding write doesn't fail FK. Idempotent.
pub fn set_app_binding(
    slug: &str,
    provider_code: &str,
    key_source_type: &str,
    key_source_ref: &str,
) -> Result<(), String> {
    let profile_id = format!("app:{}", slug);
    // FK-prerequisite seed.
    let conn = storage::open_connection()?;
    conn.execute(
        "INSERT OR IGNORE INTO user_profiles (id, is_active) VALUES (?1, 0)",
        params![profile_id],
    )
    .map_err(|e| format!("seed user_profiles row for {}: {}", profile_id, e))?;
    drop(conn);

    storage::set_provider_binding(
        &profile_id,
        provider_code,
        key_source_type,
        key_source_ref,
    )?;
    let _ = storage::bump_vault_change_seq();
    Ok(())
}

/// UPDATE all currently-active app_keys for the slug → status='revoked'.
/// Returns the number of rows revoked (0 if no active key existed — that's
/// not an error, just a no-op for the caller's success message). app_records
/// row + key history are preserved per 主方案 §11 (revoke ≠ uninstall).
pub fn revoke_active_keys(slug: &str) -> Result<usize, String> {
    let conn = storage::open_connection()?;
    let rows = revoke_active_keys_with_conn(&conn, slug)?;
    if rows > 0 {
        let _ = storage::bump_vault_change_seq();
    }
    Ok(rows)
}

pub fn revoke_active_keys_with_conn(conn: &Connection, slug: &str) -> Result<usize, String> {
    conn.execute(
        "UPDATE app_keys SET status = 'revoked'
          WHERE app_slug = ?1 AND status = 'active'",
        params![slug],
    )
    .map_err(|e| format!("UPDATE app_keys revoke for slug={:?}: {}", slug, e))
}

/// UPDATE active app_keys for the slug → status='paused'. Returns rows affected.
/// Unlike revoke, paused is reversible via `resume_paused_keys`. Per 主方案 §11,
/// the bearer token's stored value is unchanged — same Agent config works after resume.
pub fn pause_active_keys(slug: &str) -> Result<usize, String> {
    let conn = storage::open_connection()?;
    let rows = pause_active_keys_with_conn(&conn, slug)?;
    if rows > 0 {
        let _ = storage::bump_vault_change_seq();
    }
    Ok(rows)
}

pub fn pause_active_keys_with_conn(conn: &Connection, slug: &str) -> Result<usize, String> {
    conn.execute(
        "UPDATE app_keys SET status = 'paused'
          WHERE app_slug = ?1 AND status = 'active'",
        params![slug],
    )
    .map_err(|e| format!("UPDATE app_keys pause for slug={:?}: {}", slug, e))
}

/// UPDATE paused app_keys for the slug → status='active'. Returns rows affected.
/// Symmetric to pause; same bearer plaintext continues to work — only the
/// Registry filter (`status='active'`) needs to re-include this row, which
/// happens on the next proxy reload triggered by `bump_vault_change_seq`.
pub fn resume_paused_keys(slug: &str) -> Result<usize, String> {
    let conn = storage::open_connection()?;
    let rows = resume_paused_keys_with_conn(&conn, slug)?;
    if rows > 0 {
        let _ = storage::bump_vault_change_seq();
    }
    Ok(rows)
}

pub fn resume_paused_keys_with_conn(conn: &Connection, slug: &str) -> Result<usize, String> {
    conn.execute(
        "UPDATE app_keys SET status = 'active'
          WHERE app_slug = ?1 AND status = 'paused'",
        params![slug],
    )
    .map_err(|e| format!("UPDATE app_keys resume for slug={:?}: {}", slug, e))
}

/// Atomic key rotation: in one transaction, mark the current active key as
/// revoked AND insert a new active key with a freshly-generated route_token.
/// Returns the new (key_id, route_token) tuple — caller prints the new
/// bearer for the user to paste into the Agent's env (the OLD bearer is
/// immediately rejected by proxy after vault_change_seq bumps).
///
/// Why atomic: if rotate were done as two separate operations (revoke old,
/// then insert new), a proxy restart racing the inserts could load an empty
/// Registry between the two writes — the Agent's old bearer rejected AND
/// no new bearer available → 401 storm. Single transaction prevents that.
pub fn rotate_app_key(slug: &str) -> Result<(String, String), String> {
    let mut conn = storage::open_connection()?;
    let result = rotate_app_key_with_conn(&mut conn, slug)?;
    let _ = storage::bump_vault_change_seq();
    Ok(result)
}

pub fn rotate_app_key_with_conn(conn: &mut Connection, slug: &str) -> Result<(String, String), String> {
    let new_key_id = uuid_v4_simple();
    let new_route_token = storage::generate_app_route_token();
    let tx = conn.transaction().map_err(|e| format!("begin rotate tx: {}", e))?;

    // Step 1: revoke existing active key (no-op if none — rotate on a
    // never-authorized app just becomes "first issuance").
    tx.execute(
        "UPDATE app_keys SET status = 'revoked'
          WHERE app_slug = ?1 AND status = 'active'",
        params![slug],
    )
    .map_err(|e| format!("UPDATE app_keys revoke (rotate step 1): {}", e))?;

    // Step 2: insert the new active key.
    tx.execute(
        "INSERT INTO app_keys (key_id, app_slug, route_token, status) VALUES (?1, ?2, ?3, 'active')",
        params![new_key_id, slug, new_route_token],
    )
    .map_err(|e| format!("INSERT app_keys (rotate step 2): {}", e))?;

    tx.commit().map_err(|e| format!("commit rotate tx: {}", e))?;
    Ok((new_key_id, new_route_token))
}

// ---------------------------------------------------------------------------
// Phase 2 Day 7 lookup helpers for the interactive `aikey app route` picker.
// Reads-only; do not mutate vault state.
// ---------------------------------------------------------------------------

/// SELECT the active app_keys rows for a slug. Returns metadata for each
/// (key_id, created_at, last_used_at). Used by handlers::handle_route to
/// decide whether the app has been "fully authorized once" (first-route
/// triggers bearer issuance with consent prompt; subsequent routes don't).
pub fn list_app_active_keys(slug: &str) -> Result<Vec<ActiveAppKeyInfo>, String> {
    let conn = storage::open_connection()?;
    let mut stmt = conn
        .prepare(
            "SELECT key_id, created_at, last_used_at
               FROM app_keys
              WHERE app_slug = ?1 AND status = 'active'
              ORDER BY created_at DESC",
        )
        .map_err(|e| {
            if e.to_string().contains("no such table") {
                "no such table".to_string()
            } else {
                format!("prepare list_app_active_keys: {}", e)
            }
        })?;
    if stmt.column_count() == 0 {
        return Ok(Vec::new());
    }
    let rows = stmt
        .query_map(params![slug], |r| {
            Ok(ActiveAppKeyInfo {
                key_id: r.get::<_, String>(0)?,
                created_at: r.get::<_, i64>(1)?,
                last_used_at: r.get::<_, Option<i64>>(2)?,
            })
        })
        .map_err(|e| format!("query list_app_active_keys: {}", e))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| format!("scan list_app_active_keys: {}", e))?);
    }
    Ok(out)
}

/// SELECT all current provider bindings for the app's profile_id
/// (`app:<slug>`). Returns (upstream_provider, key_type, key_ref) tuples
/// — matches the shape of authorize_atomic's initial_bindings parameter
/// so handlers can pass it directly into authorize_atomic at first-route
/// bearer issuance time.
pub fn get_active_bindings(
    slug: &str,
) -> Result<Vec<(String, CredentialType, String)>, String> {
    let profile_id = format!("app:{}", slug);
    let conn = storage::open_connection()?;
    let mut stmt = conn
        .prepare(
            "SELECT provider_code, key_source_type, key_source_ref
               FROM user_profile_provider_bindings
              WHERE profile_id = ?1
              ORDER BY provider_code",
        )
        .map_err(|e| {
            if e.to_string().contains("no such table") {
                "no such table".to_string()
            } else {
                format!("prepare get_active_bindings: {}", e)
            }
        })?;
    if stmt.column_count() == 0 {
        return Ok(Vec::new());
    }
    let rows = stmt
        .query_map(params![profile_id], |r| {
            let provider: String = r.get(0)?;
            let key_source_type: String = r.get(1)?;
            let key_source_ref: String = r.get(2)?;
            Ok((provider, key_source_type, key_source_ref))
        })
        .map_err(|e| format!("query get_active_bindings: {}", e))?;
    let mut out = Vec::new();
    for row in rows {
        let (p, kt, kr) = row.map_err(|e| format!("scan get_active_bindings: {}", e))?;
        let typed = match kt.as_str() {
            "personal" | "personal_api_key" => CredentialType::PersonalApiKey,
            "team" | "managed_virtual_key" => CredentialType::ManagedVirtualKey,
            "personal_oauth_account" => CredentialType::PersonalOAuthAccount,
            other => {
                // Schema-unknown values aren't actionable here; skip with a
                // log line on stderr per CLAUDE.md "失败要显眼" but don't
                // abort the picker (other rows may be fine).
                eprintln!(
                    "[aikey app] WARN: binding for profile={} provider={} has unknown \
                     key_source_type={:?}; skipping",
                    profile_id, p, other
                );
                continue;
            }
        };
        out.push((p, typed, kr));
    }
    Ok(out)
}

/// Return the bindings the runtime resolver will ACTUALLY use for `slug`,
/// not the snapshot stored in `app:<slug>` at register time.
///
/// Why this function exists separately from [`get_active_bindings`]:
///
///   - `get_active_bindings(slug)` ALWAYS queries `app:<slug>` profile.
///     That row is what `aikey app route` wrote (or was never written if
///     follow_user_active=true). It's the right answer when you want
///     "what the per-app binding row literally is" — e.g. for copying
///     into a bearer's `initial_bindings` at first authorize time, or
///     for the interactive picker showing what the user previously
///     chose.
///
///   - But the proxy's actual resolver branches on follow_user_active
///     (see 20260519-降智检测-follow-active-模式.md §how): when true,
///     it reads `profile_id='default'` — i.e. tracks the user's
///     current `aikey use` selection dynamically. For first-party apps
///     like degrade-detector this is the whole point of the mode.
///
///   - The display path (Web Apps page; `aikey app list` / `get`)
///     should reflect what the resolver will actually do — otherwise
///     the UI lies about which key the app is using. That's what this
///     function returns.
///
/// Internal state operations (snapshot copy, picker, bearer issuance)
/// keep calling [`get_active_bindings`]. Only DISPLAY paths switch to
/// this function.
pub fn get_effective_bindings(
    slug: &str,
) -> Result<Vec<(String, CredentialType, String)>, String> {
    let rec = get_app_record(slug)?
        .ok_or_else(|| format!("app '{}' not found", slug))?;

    let profile_id = if rec.follow_user_active {
        // First-party + follow-active: resolver reads default profile.
        // Show what's there so the UI matches runtime behavior.
        "default".to_string()
    } else {
        format!("app:{}", slug)
    };

    let conn = storage::open_connection()?;
    let mut stmt = conn
        .prepare(
            "SELECT provider_code, key_source_type, key_source_ref
               FROM user_profile_provider_bindings
              WHERE profile_id = ?1
              ORDER BY provider_code",
        )
        .map_err(|e| {
            if e.to_string().contains("no such table") {
                "no such table".to_string()
            } else {
                format!("prepare get_effective_bindings: {}", e)
            }
        })?;
    if stmt.column_count() == 0 {
        return Ok(Vec::new());
    }

    // For follow-active apps, filter the default profile down to the
    // upstreams the app actually declared at register time. Without
    // this, an app declaring only "anthropic" but with a default
    // profile that also covers "openai" / "kimi" would show three
    // rows — none of which are used by this app for non-anthropic
    // models. Filtering matches what the UI's per-upstream rendering
    // expects ("one row per declared upstream").
    let declared: std::collections::HashSet<&str> =
        rec.upstreams.iter().map(|s| s.as_str()).collect();

    let rows = stmt
        .query_map(params![profile_id], |r| {
            let provider: String = r.get(0)?;
            let key_source_type: String = r.get(1)?;
            let key_source_ref: String = r.get(2)?;
            Ok((provider, key_source_type, key_source_ref))
        })
        .map_err(|e| format!("query get_effective_bindings: {}", e))?;
    let mut out = Vec::new();
    for row in rows {
        let (p, kt, kr) = row.map_err(|e| format!("scan get_effective_bindings: {}", e))?;
        if rec.follow_user_active && !declared.contains(p.as_str()) {
            continue;
        }
        let typed = match kt.as_str() {
            "personal" | "personal_api_key" => CredentialType::PersonalApiKey,
            "team" | "managed_virtual_key" => CredentialType::ManagedVirtualKey,
            "personal_oauth_account" => CredentialType::PersonalOAuthAccount,
            other => {
                eprintln!(
                    "[aikey app] WARN: binding for profile={} provider={} has unknown \
                     key_source_type={:?}; skipping",
                    profile_id, p, other
                );
                continue;
            }
        };
        out.push((p, typed, kr));
    }
    Ok(out)
}

/// OAuth account candidate for the interactive picker. Minimal shape —
/// just enough to display + write a binding row.
#[derive(Debug, Clone)]
pub struct OAuthAccountCandidate {
    pub provider_account_id: String,
    pub display_label: String,
}

/// SELECT OAuth accounts logged in for a given provider. Returns empty
/// Vec when no `provider_accounts` table exists (older vaults) or no
/// matching account — never errors out (interactive picker treats as
/// "no candidates").
pub fn list_oauth_accounts_for_provider(
    provider: &str,
) -> Result<Vec<OAuthAccountCandidate>, String> {
    let conn = storage::open_connection()?;
    let mut stmt = match conn.prepare(
        "SELECT provider_account_id, COALESCE(display_label, provider_account_id)
           FROM provider_accounts
          WHERE provider = ?1
          ORDER BY provider_account_id",
    ) {
        Ok(s) => s,
        Err(e) => {
            if e.to_string().contains("no such table")
                || e.to_string().contains("no such column")
            {
                return Ok(Vec::new());
            }
            return Err(format!("prepare list_oauth_accounts: {}", e));
        }
    };
    let rows = stmt
        .query_map(params![provider], |r| {
            Ok(OAuthAccountCandidate {
                provider_account_id: r.get::<_, String>(0)?,
                display_label: r.get::<_, String>(1)?,
            })
        })
        .map_err(|e| format!("query list_oauth_accounts: {}", e))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| format!("scan list_oauth_accounts: {}", e))?);
    }
    Ok(out)
}

/// Team-managed virtual key candidate for the interactive picker.
#[derive(Debug, Clone)]
pub struct TeamKeyCandidate {
    pub virtual_key_id: String,
    pub alias: String,
}

/// SELECT managed virtual keys (team) for a given provider. Empty Vec
/// when the cache table isn't present or no matching row.
pub fn list_team_keys_for_provider(
    provider: &str,
) -> Result<Vec<TeamKeyCandidate>, String> {
    let conn = storage::open_connection()?;
    let mut stmt = match conn.prepare(
        "SELECT virtual_key_id, alias
           FROM managed_virtual_keys_cache
          WHERE provider_code = ?1
            AND COALESCE(deleted_at, 0) = 0
          ORDER BY alias",
    ) {
        Ok(s) => s,
        Err(e) => {
            if e.to_string().contains("no such table")
                || e.to_string().contains("no such column")
            {
                return Ok(Vec::new());
            }
            return Err(format!("prepare list_team_keys: {}", e));
        }
    };
    let rows = stmt
        .query_map(params![provider], |r| {
            Ok(TeamKeyCandidate {
                virtual_key_id: r.get::<_, String>(0)?,
                alias: r.get::<_, String>(1)?,
            })
        })
        .map_err(|e| format!("query list_team_keys: {}", e))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| format!("scan list_team_keys: {}", e))?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Small helper: UUID v4 string without pulling the `uuid` crate dep.
// 36-char canonical form, version=4 + variant=10. Random source: OsRng.
// ---------------------------------------------------------------------------

fn uuid_v4_simple() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // Set version (4) and variant (RFC 4122).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}
