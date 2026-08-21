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
use rusqlite::{params, Connection, OptionalExtension};

mod handlers;
mod install;
pub use handlers::{
    handle_list, handle_pause, handle_register, handle_resume, handle_reveal_token, handle_revoke,
    handle_rotate, handle_route, register_core, RegisterResult,
};
pub use install::{handle_install, handle_uninstall};

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
pub const FIRST_PARTY_SLUGS: &[&str] = &[
    "degrade-detector",
    "ai-compliance-detector",
    "ai-compliance-deep-scan",
];

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
    "kimi",
    "moonshot",
    "deepseek",
    "qwen",
    "groq",
    "together",
    "perplexity",
    "fireworks",
    "deepinfra",
    "siliconflow",
    "siliconflow-cn",
    "zhipu",
    "doubao",
    "01ai",
    // Aggregator gateways that forward OpenAI-wire to backends.
    "openrouter",
    "openrouter-ai",
    "litellm",
    "portkey",
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
        return Err(format!(
            "app slug must start with a lowercase letter: {}",
            slug
        ));
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
                i, *c as char, slug
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
    let upstreams_json =
        serde_json::to_string(upstreams).map_err(|e| format!("encode upstreams JSON: {}", e))?;
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

/// Marks an already-registered app as a proxy filter by writing its
/// filter_stages (+ priority + timeout policy) onto the existing app_records
/// row. The proxy supervisor discovers filter apps via
/// `SELECT DISTINCT slug FROM app_records WHERE filter_stages IS NOT NULL`
/// (aikey-proxy GetFilterAppSlugs) and spawns them on the data plane.
///
/// This is a separate UPDATE (not folded into upsert_app_record) on purpose:
/// upsert has 20+ existing call sites/tests and only filter apps need these
/// columns, so keeping it additive avoids a shotgun signature change.
pub fn set_app_filter_stages(
    slug: &str,
    filter_stages: &[String],
    filter_priority: Option<i64>,
    filter_timeout_policy: Option<&str>,
) -> Result<(), String> {
    let conn = storage::open_connection()?;
    set_app_filter_stages_with_conn(
        &conn,
        slug,
        filter_stages,
        filter_priority,
        filter_timeout_policy,
    )?;
    let _ = storage::bump_vault_change_seq();
    Ok(())
}

/// Test-friendly inner: see `set_app_filter_stages`. Defaults priority=100 and
/// policy=fail_open when omitted so the row is always well-formed for the proxy.
pub fn set_app_filter_stages_with_conn(
    conn: &Connection,
    slug: &str,
    filter_stages: &[String],
    filter_priority: Option<i64>,
    filter_timeout_policy: Option<&str>,
) -> Result<(), String> {
    let stages_json = serde_json::to_string(filter_stages)
        .map_err(|e| format!("encode filter_stages JSON: {}", e))?;
    let priority = filter_priority.unwrap_or(100);
    let policy = filter_timeout_policy.unwrap_or("fail_open");
    if policy != "fail_open" && policy != "fail_closed" {
        return Err(format!(
            "invalid --filter-timeout-policy {:?}; allowed: fail_open, fail_closed",
            policy
        ));
    }
    let affected = conn
        .execute(
            "UPDATE app_records
                SET filter_stages = ?2,
                    filter_priority = ?3,
                    filter_timeout_policy = ?4,
                    updated_at = strftime('%s', 'now')
              WHERE slug = ?1",
            params![slug, stages_json, priority, policy],
        )
        .map_err(|e| format!("UPDATE app_records filter_stages: {}", e))?;
    if affected == 0 {
        return Err(format!(
            "cannot set filter_stages: app '{}' is not registered",
            slug
        ));
    }
    // An explicit enable supersedes any earlier explicit disable — drop the
    // do-not-override marker so future default-activation migrations treat
    // this vault normally again (see clear_app_filter_stages_with_conn).
    conn.execute(
        "DELETE FROM config WHERE key = ?1",
        params![user_filter_disabled_marker(slug)],
    )
    .map_err(|e| format!("clear user filter-disabled marker: {}", e))?;
    Ok(())
}

/// Clears an app's filter columns (filter_stages = NULL) so the proxy stops
/// spawning it as a filter — the DISABLE half of the compliance on/off toggle.
/// NULL (not `[]`) is required: the proxy's GetFilterAppSlugs selects rows
/// WHERE filter_stages IS NOT NULL, and `[]` would still count as "declared".
/// Bumps change_seq so the proxy reload picks it up (same as the enable path).
pub fn clear_app_filter_stages(slug: &str) -> Result<(), String> {
    let conn = storage::open_connection()?;
    clear_app_filter_stages_with_conn(&conn, slug)?;
    let _ = storage::bump_vault_change_seq();
    Ok(())
}

/// Test-friendly inner: see `clear_app_filter_stages`.
pub fn clear_app_filter_stages_with_conn(conn: &Connection, slug: &str) -> Result<(), String> {
    let affected = conn
        .execute(
            "UPDATE app_records
                SET filter_stages = NULL,
                    filter_priority = NULL,
                    filter_timeout_policy = NULL,
                    updated_at = strftime('%s', 'now')
              WHERE slug = ?1",
            params![slug],
        )
        .map_err(|e| format!("UPDATE app_records clear filter_stages: {}", e))?;
    if affected == 0 {
        return Err(format!(
            "cannot clear filter_stages: app '{}' is not registered",
            slug
        ));
    }
    // Record the EXPLICIT user choice (bugfix 2026-08-19): default-activation
    // migrations (e.g. activate_compliance_wave2_once) must never force a
    // filter back on over a deliberate disable. The marker lives in config so
    // it survives baseline DDL replays and binary upgrades; any explicit
    // re-enable (set_app_filter_stages) removes it.
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?1, '1')",
        params![user_filter_disabled_marker(slug)],
    )
    .map_err(|e| format!("record user filter-disabled marker: {}", e))?;
    Ok(())
}

/// Whether the compliance detector binary is on this machine, at the SAME
/// canonical path the installer writes and the proxy resolves
/// (<home>/.aikey/apps/ai-compliance-detector/bin/ai-compliance-detector[.exe]).
/// Lives in the lib (not bin-only commands_compliance) so the console-toggle
/// internal handler can share the single truth (W2, bugfix 2026-08-19).
pub fn detector_installed() -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    let p = home.join(".aikey/apps/ai-compliance-detector/bin/ai-compliance-detector");
    if cfg!(windows) {
        p.with_extension("exe").exists()
    } else {
        p.exists()
    }
}

/// Config key marking "the user explicitly disabled this app's filter".
/// Consumed by default-activation migrations (migrations.rs) as a do-not-
/// override guard; written by the disable half of the toggle, cleared by the
/// enable half.
pub fn user_filter_disabled_marker(slug: &str) -> String {
    format!("user.filter_disabled.{}", slug)
}

/// Reads an app's filter state — the STATUS half of the compliance toggle.
/// Returns Ok(None) when the app isn't registered OR filter_stages IS NULL
/// (disabled); Ok(Some(stages)) when enabled. The proxy treats NULL as "off",
/// so None == disabled is the correct collapse for the web toggle.
pub fn get_app_filter_stages(slug: &str) -> Result<Option<Vec<String>>, String> {
    let conn = storage::open_connection()?;
    get_app_filter_stages_with_conn(&conn, slug)
}

/// Test-friendly inner: see `get_app_filter_stages`.
pub fn get_app_filter_stages_with_conn(
    conn: &Connection,
    slug: &str,
) -> Result<Option<Vec<String>>, String> {
    let stages_json: Option<String> = conn
        .query_row(
            "SELECT filter_stages FROM app_records WHERE slug = ?1",
            params![slug],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(|e| format!("read filter_stages: {}", e))?
        .flatten();
    match stages_json {
        None => Ok(None),
        Some(j) => {
            let stages: Vec<String> = serde_json::from_str(&j)
                .map_err(|e| format!("decode filter_stages JSON: {}", e))?;
            Ok(Some(stages))
        }
    }
}

/// Sets whether the local self-view records "allow" (clean-scan) events for a
/// filter app. Default is off (0) to save space. The proxy reads this column
/// and passes it to the detector child as env (AIKEY_COMPLIANCE_RECORD_ALLOW)
/// so the detector can skip emitting allow events at source. Bumps change_seq
/// so the proxy reload re-spawns the detector with the new env. Decoupled from
/// the compliance on/off toggle (filter_stages) — this is a sub-setting.
pub fn set_app_filter_record_allow(slug: &str, record_allow: bool) -> Result<(), String> {
    let conn = storage::open_connection()?;
    set_app_filter_record_allow_with_conn(&conn, slug, record_allow)?;
    let _ = storage::bump_vault_change_seq();
    Ok(())
}

/// Test-friendly inner: see `set_app_filter_record_allow`.
pub fn set_app_filter_record_allow_with_conn(
    conn: &Connection,
    slug: &str,
    record_allow: bool,
) -> Result<(), String> {
    let affected = conn
        .execute(
            "UPDATE app_records
                SET filter_record_allow = ?2,
                    updated_at = strftime('%s', 'now')
              WHERE slug = ?1",
            params![slug, if record_allow { 1 } else { 0 }],
        )
        .map_err(|e| format!("UPDATE app_records filter_record_allow: {}", e))?;
    if affected == 0 {
        return Err(format!(
            "cannot set filter_record_allow: app '{}' is not registered",
            slug
        ));
    }
    Ok(())
}

/// Reads whether the local self-view records "allow" events for an app.
/// Returns false (the default) when the app isn't registered OR the column is
/// 0/NULL. The proxy uses this to decide the detector's env.
pub fn get_app_filter_record_allow(slug: &str) -> Result<bool, String> {
    let conn = storage::open_connection()?;
    get_app_filter_record_allow_with_conn(&conn, slug)
}

/// Test-friendly inner: see `get_app_filter_record_allow`.
pub fn get_app_filter_record_allow_with_conn(
    conn: &Connection,
    slug: &str,
) -> Result<bool, String> {
    let v: Option<i64> = conn
        .query_row(
            "SELECT filter_record_allow FROM app_records WHERE slug = ?1",
            params![slug],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()
        .map_err(|e| format!("read filter_record_allow: {}", e))?
        .flatten();
    Ok(v.unwrap_or(0) != 0)
}

/// Sets the operational enforcement ceiling for a filter app. This changes no
/// detector policy or Finding; `warn` only caps mask/block for rapid rollback.
pub fn set_app_filter_max_action(slug: &str, max_action: &str) -> Result<(), String> {
    let conn = storage::open_connection()?;
    set_app_filter_max_action_with_conn(&conn, slug, max_action)?;
    let _ = storage::bump_vault_change_seq();
    Ok(())
}

pub fn set_app_filter_max_action_with_conn(
    conn: &Connection,
    slug: &str,
    max_action: &str,
) -> Result<(), String> {
    if max_action != "full" && max_action != "warn" {
        return Err(format!(
            "invalid filter max action {:?}; allowed: full, warn",
            max_action
        ));
    }
    let affected = conn
        .execute(
            "UPDATE app_records
                SET filter_max_action = ?2,
                    updated_at = strftime('%s', 'now')
              WHERE slug = ?1",
            params![slug, max_action],
        )
        .map_err(|e| format!("UPDATE app_records filter_max_action: {}", e))?;
    if affected == 0 {
        return Err(format!(
            "cannot set filter_max_action: app '{}' is not registered",
            slug
        ));
    }
    Ok(())
}

/// Reads the filter enforcement ceiling. Missing rows and pre-setting rows use
/// the production-compatible default `full`.
pub fn get_app_filter_max_action(slug: &str) -> Result<String, String> {
    let conn = storage::open_connection()?;
    get_app_filter_max_action_with_conn(&conn, slug)
}

pub fn get_app_filter_max_action_with_conn(
    conn: &Connection,
    slug: &str,
) -> Result<String, String> {
    let value: Option<String> = conn
        .query_row(
            "SELECT filter_max_action FROM app_records WHERE slug = ?1",
            params![slug],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(|e| format!("read filter_max_action: {}", e))?
        .flatten();
    let value = value.unwrap_or_else(|| "full".to_string());
    if value != "full" && value != "warn" {
        return Err(format!(
            "stored filter_max_action {:?} is invalid; allowed: full, warn",
            value
        ));
    }
    Ok(value)
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
    let row = conn.query_row(
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
        let (
            slug,
            name,
            vendor,
            upstreams_json,
            app_kind,
            follow,
            perms_json,
            created_at,
            updated_at,
            key_id,
            key_created,
            key_last,
        ) = row.map_err(|e| format!("scan list_apps row: {}", e))?;
        let upstreams: Vec<String> = serde_json::from_str(&upstreams_json).unwrap_or_default();
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
/// `initial_bindings` is the list of `(client_route, key_source_type,
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
    // Resolve every source to exact axes before opening the transaction. If
    // metadata is inconsistent, authorization fails without minting a bearer.
    let exact_bindings = initial_bindings
        .iter()
        .map(|(client_route, key_type, key_ref)| {
            let (provider, protocol) = crate::commands_account::binding_spec_for_client_route(
                client_route,
                key_type.as_str(),
                key_ref,
            )?;
            Ok((client_route, key_type, key_ref, provider, protocol))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let key_id = uuid_v4_simple();
    let route_token = storage::generate_app_route_token();
    let tx = conn
        .transaction()
        .map_err(|e| format!("begin authorize tx: {}", e))?;

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

    for (client_route, key_type, key_ref, provider_code, protocol_type) in exact_bindings {
        tx.execute(
            "INSERT INTO user_profile_provider_bindings
                (profile_id, provider_code, binding_provider_code, protocol_type,
                 key_source_type, key_source_ref, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%s', 'now'))
             ON CONFLICT (profile_id, provider_code) DO UPDATE SET
                binding_provider_code = excluded.binding_provider_code,
                protocol_type = excluded.protocol_type,
                key_source_type = excluded.key_source_type,
                key_source_ref  = excluded.key_source_ref,
                updated_at      = excluded.updated_at",
            params![
                profile_id,
                client_route,
                provider_code,
                protocol_type,
                key_type.as_str(),
                key_ref
            ],
        )
        .map_err(|e| {
            format!(
                "UPSERT binding profile={} route={} provider={}: {}",
                profile_id, client_route, provider_code, e
            )
        })?;
    }

    tx.commit()
        .map_err(|e| format!("commit authorize tx: {}", e))?;
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
    client_route: &str,
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

    let (provider_code, protocol_type) = crate::commands_account::binding_spec_for_client_route(
        client_route,
        key_source_type,
        key_source_ref,
    )?;
    storage::set_client_route_binding(
        &profile_id,
        client_route,
        &provider_code,
        &protocol_type,
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
/// DELETE every vault row tied to this slug: app_keys + app_records +
/// user_profile_provider_bindings whose profile_id == "app:<slug>".
/// Returns counts per table for caller-side audit (CLI prints them).
///
/// Used by `aikey app uninstall` (2026-05-23). Separate from revoke
/// because uninstall is the OPPOSITE of install — we want zero traces
/// left so a future `aikey app install <slug>` starts from a clean
/// state without "ghost" rows from a prior life. Audit trail lives in
/// usage events / events.db, not in the app management tables.
///
/// CRITICAL: this bypasses the `mutationLockedSlugs` revoke/rotate
/// guard on aikey-control. The lock exists to prevent the user from
/// half-breaking a running first-party app (revoke kills the bearer,
/// the agent crashes). Uninstall is whole-system: it stops the
/// service first (via install_service.sh --uninstall in the plugin's
/// own helper), then removes vault rows. No half-state.
pub fn delete_all_app_state(slug: &str) -> Result<UninstallCounts, String> {
    let mut conn = storage::open_connection()?;
    let counts = delete_all_app_state_with_conn(&mut conn, slug)?;
    let _ = storage::bump_vault_change_seq();
    Ok(counts)
}

#[derive(Debug, Default)]
pub struct UninstallCounts {
    pub app_keys_deleted: usize,
    pub app_keys_revoked: usize,
    pub app_records_deleted: usize,
    pub bindings_deleted: usize,
}

pub fn delete_all_app_state_with_conn(
    conn: &mut Connection,
    slug: &str,
) -> Result<UninstallCounts, String> {
    let tx = conn
        .transaction()
        .map_err(|e| format!("begin uninstall tx for slug={:?}: {}", slug, e))?;

    let app_keys_deleted = tx
        .execute("DELETE FROM app_keys WHERE app_slug = ?1", params![slug])
        .map_err(|e| format!("DELETE app_keys for slug={:?}: {}", slug, e))?;

    // FK on user_profile_provider_bindings.profile_id references
    // user_profiles.id; we use the synthetic profile id "app:<slug>"
    // for app-scoped bindings (set by authorize_atomic). Delete those
    // FIRST so app_records FK doesn't trip if we ever add such a
    // constraint later. The synthetic user_profiles row (is_active=0)
    // is left in place — other apps may reuse the profile slot, and
    // a stale "ghost" profile row with no bindings is harmless.
    let profile_id = format!("app:{}", slug);
    let bindings_deleted = tx
        .execute(
            "DELETE FROM user_profile_provider_bindings WHERE profile_id = ?1",
            params![profile_id],
        )
        .map_err(|e| format!("DELETE bindings for profile={:?}: {}", profile_id, e))?;

    let app_records_deleted = tx
        .execute("DELETE FROM app_records WHERE slug = ?1", params![slug])
        .map_err(|e| format!("DELETE app_records for slug={:?}: {}", slug, e))?;

    tx.commit()
        .map_err(|e| format!("commit uninstall tx for slug={:?}: {}", slug, e))?;

    Ok(UninstallCounts {
        app_keys_deleted,
        app_keys_revoked: 0,
        app_records_deleted,
        bindings_deleted,
    })
}

/// Third-party variant of uninstall: revoke active app_keys (keep history
/// rows) + delete bindings + delete app_records. Unlike `delete_all_app_state`
/// (used by first-party `aikey app uninstall`), this preserves
/// `app_keys` rows by flipping their status to 'revoked', so an audit
/// trail of "which tokens were ever issued for this slug" survives the
/// uninstall.
///
/// Why the asymmetry vs first-party (per 2026-05-25 user decision):
/// - first-party uninstall is whole-system removal (service binary +
///   vault). Audit lives in service logs + usage_event_ods.
/// - third-party uninstall is identity-only (the third-party agent's own
///   binary is not managed by AiKey). Retaining `app_keys` rows lets the
///   user later see "ah, I once had a token issued to slug=X" in vault
///   inspection tools.
///
/// Caveat for re-registration with same slug: with FK enforcement OFF
/// (current `PRAGMA foreign_keys = 0`), DELETE on app_records does NOT
/// cascade to app_keys. The revoked rows remain pointing at slug=X by
/// `app_slug` column. If the user later re-registers slug=X, the new
/// active `app_keys` row coexists with the old revoked ones — they share
/// the slug but were issued under separate "app instances". For audit
/// queries that need cross-reregistration provenance, prefer
/// `usage_event_ods.app_slug + virtual_key_hash` (which is per-request and
/// not affected by uninstall).
pub fn delete_third_party_app_identity(slug: &str) -> Result<UninstallCounts, String> {
    let mut conn = storage::open_connection()?;
    let counts = delete_third_party_app_identity_with_conn(&mut conn, slug)?;
    let _ = storage::bump_vault_change_seq();
    Ok(counts)
}

pub fn delete_third_party_app_identity_with_conn(
    conn: &mut Connection,
    slug: &str,
) -> Result<UninstallCounts, String> {
    // FK enforcement guard: the baseline schema declares
    //   app_keys.app_slug REFERENCES app_records(slug) ON DELETE CASCADE
    // which would erase the `app_keys` audit rows we want to preserve when
    // we DELETE the parent `app_records` row. Production currently runs
    // with `foreign_keys=OFF` (the cascade doesn't fire there), but tests
    // run with `foreign_keys=ON`, and prod could be flipped on for safety
    // in the future. To keep "preserve app_keys for audit" reliable
    // regardless of the runtime PRAGMA, we explicitly turn FK off for
    // the duration of this operation and restore the original setting
    // after. SQLite forbids PRAGMA foreign_keys inside a transaction, so
    // the save/set/restore happens outside the tx boundary.
    let prior_fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .map_err(|e| format!("read foreign_keys PRAGMA: {}", e))?;
    if prior_fk != 0 {
        conn.execute_batch("PRAGMA foreign_keys = OFF")
            .map_err(|e| format!("disable foreign_keys: {}", e))?;
    }

    let result = (|| -> Result<UninstallCounts, String> {
        let tx = conn
            .transaction()
            .map_err(|e| format!("begin third-party uninstall tx for slug={:?}: {}", slug, e))?;

        // Revoke (don't delete) all currently-non-revoked app_keys rows.
        // Audit trail: row count + revocation timestamp would be useful but
        // current app_keys schema has no `revoked_at` column — status flip
        // is sufficient since `created_at` is preserved + the implicit
        // ordering is by key_id (UUIDv4) which sorts roughly by time.
        let app_keys_revoked = tx
            .execute(
                "UPDATE app_keys SET status = 'revoked' \
                 WHERE app_slug = ?1 AND status != 'revoked'",
                params![slug],
            )
            .map_err(|e| format!("UPDATE app_keys for slug={:?}: {}", slug, e))?;

        let profile_id = format!("app:{}", slug);
        let bindings_deleted = tx
            .execute(
                "DELETE FROM user_profile_provider_bindings WHERE profile_id = ?1",
                params![profile_id],
            )
            .map_err(|e| format!("DELETE bindings for profile={:?}: {}", profile_id, e))?;

        let app_records_deleted = tx
            .execute("DELETE FROM app_records WHERE slug = ?1", params![slug])
            .map_err(|e| format!("DELETE app_records for slug={:?}: {}", slug, e))?;

        tx.commit()
            .map_err(|e| format!("commit third-party uninstall tx for slug={:?}: {}", slug, e))?;

        Ok(UninstallCounts {
            app_keys_deleted: 0,
            app_keys_revoked,
            app_records_deleted,
            bindings_deleted,
        })
    })();

    // Restore the PRAGMA regardless of result so we don't leak the
    // weakened FK state into subsequent operations on this connection.
    if prior_fk != 0 {
        if let Err(e) = conn.execute_batch("PRAGMA foreign_keys = ON") {
            // We only log because the primary operation succeeded; failing
            // to flip the PRAGMA back is a developer-environment issue
            // (e.g. weird platform behavior), not a vault data issue.
            eprintln!(
                "{} failed to restore foreign_keys=ON after uninstall: {}",
                crate::symbols::WARN.s(),
                e
            );
        }
    }

    result
}

pub fn rotate_app_key(slug: &str) -> Result<(String, String), String> {
    let mut conn = storage::open_connection()?;
    let result = rotate_app_key_with_conn(&mut conn, slug)?;
    let _ = storage::bump_vault_change_seq();
    Ok(result)
}

pub fn rotate_app_key_with_conn(
    conn: &mut Connection,
    slug: &str,
) -> Result<(String, String), String> {
    let new_key_id = uuid_v4_simple();
    let new_route_token = storage::generate_app_route_token();
    let tx = conn
        .transaction()
        .map_err(|e| format!("begin rotate tx: {}", e))?;

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

    tx.commit()
        .map_err(|e| format!("commit rotate tx: {}", e))?;
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

/// Active token info returned by `get_active_route_token`. Carries the
/// plaintext bearer + its key_id + the proxy base_url so callers can
/// surface a complete "what to put in the agent's env" picture without
/// a second round-trip. Plaintext value: the caller is responsible for
/// audit-log + display masking — this helper is the only legitimate
/// way to re-read an issued bearer after register/rotate time.
#[derive(Debug, Clone)]
pub struct ActiveAppToken {
    pub slug: String,
    pub key_id: String,
    pub route_token: String,
    pub base_url: String,
}

/// SELECT the most-recent active app_keys row for a slug and return its
/// plaintext route_token + key_id + the computed base_url.
///
/// Semantics: app_keys.status='active' is the gate (revoked/paused rows
/// are excluded). Schema allows N active rows during a rotation window;
/// we ORDER BY created_at DESC LIMIT 1 to consistently return THE freshly
/// issued one. This matches `read_active_route_token` (the older
/// private helper that callers like `issue_or_reuse_bearer` use) — kept
/// as a separate pub fn so the reveal-token feature (2026-05-25) has a
/// stable public API to wrap, without forcing the private helper to
/// grow a richer return type.
///
/// Errors:
///   - "no active token" — slug has no app_keys row with status='active'
///     (either never authorized, or all keys revoked). Caller maps to
///     I_NO_ACTIVE_TOKEN at the IPC envelope layer.
///
/// Why pub: consumed by `commands_internal::app::handle_reveal_token`
/// (Web UI bridge) and the new `aikey app reveal-token` public command,
/// per CLAUDE.md `_internal 隐藏命令必须复用公开命令逻辑` — one SQL,
/// two callers.
pub fn get_active_route_token(slug: &str) -> Result<ActiveAppToken, String> {
    let conn = storage::open_connection()?;
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT key_id, route_token FROM app_keys
              WHERE app_slug = ?1 AND status = 'active'
              ORDER BY created_at DESC
              LIMIT 1",
            params![slug],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok();
    let (key_id, route_token) = row.ok_or_else(|| {
        format!(
            "no active token for slug={:?} — register or rotate first",
            slug
        )
    })?;
    // Match the base_url format used by `handle_register` / `handle_rotate`
    // so all three commands emit the same shape and the Web UI doesn't
    // need to special-case the reveal payload.
    let base_url = format!("http://127.0.0.1:27200/apps/{}/v1", slug);
    Ok(ActiveAppToken {
        slug: slug.to_string(),
        key_id,
        route_token,
        base_url,
    })
}

/// SELECT all current provider bindings for the app's profile_id
/// (`app:<slug>`). Returns (upstream_provider, key_type, key_ref) tuples
/// — matches the shape of authorize_atomic's initial_bindings parameter
/// so handlers can pass it directly into authorize_atomic at first-route
/// bearer issuance time.
pub fn get_active_bindings(slug: &str) -> Result<Vec<(String, CredentialType, String)>, String> {
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
pub fn get_effective_bindings(slug: &str) -> Result<Vec<(String, CredentialType, String)>, String> {
    let rec = get_app_record(slug)?.ok_or_else(|| format!("app '{}' not found", slug))?;

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
    client_route: &str,
) -> Result<Vec<OAuthAccountCandidate>, String> {
    let mut out = storage::list_provider_accounts()?
        .into_iter()
        .filter(|account| {
            crate::provider_registry::client_route_for_binding(
                &account.provider,
                &account.protocol_type,
            )
            .eq_ignore_ascii_case(client_route)
        })
        .map(|account| {
            let display_label = account.effective_label().to_string();
            OAuthAccountCandidate {
                provider_account_id: account.provider_account_id,
                display_label,
            }
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| a.provider_account_id.cmp(&b.provider_account_id));
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
pub fn list_team_keys_for_provider(client_route: &str) -> Result<Vec<TeamKeyCandidate>, String> {
    let conn = storage::open_connection()?;
    let mut stmt = match conn.prepare(
        "SELECT virtual_key_id, alias, local_alias, provider_code, protocol_type
           FROM managed_virtual_keys_cache
          WHERE COALESCE(deleted_at, 0) = 0
          ORDER BY COALESCE(local_alias, alias)",
    ) {
        Ok(stmt) => stmt,
        Err(err)
            if err.to_string().contains("no such table")
                || err.to_string().contains("no such column") =>
        {
            return Ok(Vec::new());
        }
        Err(err) => return Err(format!("prepare list_team_keys: {}", err)),
    };
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|err| format!("query list_team_keys: {}", err))?;
    let mut out = Vec::new();
    for row in rows {
        let (virtual_key_id, alias, local_alias, provider_code, protocol_type) =
            row.map_err(|err| format!("scan list_team_keys: {}", err))?;
        if !crate::provider_registry::client_route_for_binding(&provider_code, &protocol_type)
            .eq_ignore_ascii_case(client_route)
        {
            continue;
        }
        if out
            .iter()
            .any(|candidate: &TeamKeyCandidate| candidate.virtual_key_id == virtual_key_id)
        {
            continue;
        }
        out.push(TeamKeyCandidate {
            virtual_key_id,
            alias: local_alias.unwrap_or(alias),
        });
    }
    out.sort_by(|a, b| a.alias.cmp(&b.alias));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Binding label resolution — single source of truth.
//
// Why this lives here:
//   `key_source_ref` is the storage-layer identifier (`alias`,
//   `virtual_key_id`, or `provider_account_id`). Only `personal` refs are
//   already user-facing; team and OAuth refs are opaque IDs (`vk_xxx`,
//   `session_<hex>`) that must be resolved against the local cache before
//   showing them to a user. Before this consolidation the resolver lived
//   in TWO places (main.rs `resolve_binding_display_name` and
//   commands_internal/app.rs `resolve_binding_label`) which had drifted —
//   the internal copy only handled OAuth and left team bindings showing
//   raw `vk_xxx` IDs in the Web UI's register modal / detail page. This
//   single function is the only resolver from here forward; every binding
//   row emitted to a user (CLI text, IPC JSON, register response) MUST
//   route through it.
//
// Falls back to `key_source_ref` for any storage error or missing row —
// surfacing the raw ID at least lets users copy it for forensics.
// ---------------------------------------------------------------------------

pub fn resolve_binding_label(key_source_type: &str, key_source_ref: &str) -> String {
    match key_source_type {
        "personal_oauth_account" => {
            match crate::storage::get_provider_account(key_source_ref) {
                Ok(Some(acct)) => {
                    // effective_label() already chains
                    // local_alias → display_identity → provider_account_id.
                    // If it returns the raw provider_account_id, both
                    // local_alias and display_identity were empty — try
                    // external_id as one more rung before giving up
                    // (some pre-v1.0.1 OAuth rows populate external_id
                    // but not display_identity).
                    let label = acct.effective_label();
                    if !label.is_empty() && label != acct.provider_account_id {
                        return label.to_string();
                    }
                    if let Some(id) = acct.external_id.as_deref().filter(|s: &&str| !s.is_empty()) {
                        return id.to_string();
                    }
                    key_source_ref.to_string()
                }
                _ => key_source_ref.to_string(),
            }
        }
        "team" => match crate::storage::get_virtual_key_cache(key_source_ref) {
            Ok(Some(entry)) => entry.local_alias.unwrap_or(entry.alias),
            _ => key_source_ref.to_string(),
        },
        // "personal" and any unknown type — ref is already the alias.
        _ => key_source_ref.to_string(),
    }
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
