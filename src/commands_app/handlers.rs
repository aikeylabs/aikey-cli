//! Handlers for `aikey app *` subcommands. Thin shells over the storage
//! helpers in `super::*` — keep them readable as "the user-facing flow"
//! while pure SQL lives next door.
//!
//! User-facing strings are English only (CLAUDE.md "代码与 UI 语言" 强制).
//! JSON output is gated by the global `--json` flag passed in by main.rs.
//!
//! 2026-05-21 Phase 2 Day 7 redesign:
//!   - `handle_authorize` removed — bearer issuance merged into the first
//!     full run of `handle_route` (with explicit `Issue bearer?` consent
//!     prompt to preserve the security-event semantics).
//!   - `handle_route` is now interactive by default, mirroring `aikey use`
//!     UX: shows one table row per declared upstream, lets the user pick
//!     a key (personal alias / OAuth account / team key). Non-interactive
//!     `--upstream / --key-type / --key-ref` triple is preserved for CI.
//!   - URLs printed everywhere use the new `/apps/<slug>/v1/` shape
//!     (no `<protocol>` URL segment). The routing now happens at request
//!     time via body.model → upstream inference (see Go-side
//!     internal/provider/model_router.go).

use std::io::{self, IsTerminal, Write};

use crate::commands_proxy;
use crate::credential_type::CredentialType;
use crate::json_output;
use crate::storage;

use super::{
    authorize_atomic, get_active_bindings, get_app_record, is_first_party, list_app_active_keys,
    list_apps, pause_active_keys, resume_paused_keys, revoke_active_keys, rotate_app_key,
    set_app_binding, set_app_filter_stages, upsert_app_record, validate_first_party_invariants,
    validate_slug, validate_upstreams, AppRecord,
};

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

/// Implements `aikey app register --slug X --name Y --vendor Z --upstreams A,B
/// [--first-party] [--follow-user-active] [--requested-permissions ...]
/// [--rotate-bearer]`.
///
/// 2026-05-21 UX redesign (Q1=A1 静态快照 / Q2=B2 success+warning /
/// Q3=follow_user_active 动态跟随 / Q4=C1 重用 bearer):
///
///   1. Validate flag combinations.
///   2. UPSERT app_records.
///   3. For follow_user_active=false (default): snapshot the user's
///      `aikey use` selections (default-profile bindings) for each
///      declared upstream into the app's profile (app:<slug>).
///      For follow_user_active=true: do NOT snapshot — the resolver
///      will fallback to default-profile at request time (dynamic).
///   4. Issue a bearer (or reuse existing active bearer when re-registering
///      the same slug; --rotate-bearer forces a new one).
///   5. Print env lines + binding summary + warnings for any declared
///      upstream that lacks an `aikey use` selection.
///
/// Validation runs BEFORE any vault write so a rejected register can't
/// leave a partial app_records row + change_seq bump that would trigger
/// a useless proxy restart.
#[allow(clippy::too_many_arguments)]
pub fn handle_register(
    slug: &str,
    name: &str,
    vendor: &str,
    upstreams: &[String],
    first_party: bool,
    follow_user_active: bool,
    requested_permissions: &[String],
    filter_stages: &[String],
    filter_priority: Option<i64>,
    filter_timeout_policy: Option<&str>,
    rotate_bearer: bool,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let r = register_core(
        slug,
        name,
        vendor,
        upstreams,
        first_party,
        follow_user_active,
        requested_permissions,
        filter_stages,
        filter_priority,
        filter_timeout_policy,
        rotate_bearer,
    )?;

    if json_mode {
        // json_output::success calls process::exit; nothing after this runs
        // in JSON mode. The IPC layer takes a different path entirely
        // (calls register_core directly + emits its own envelope), so
        // this exit is fine for the CLI public-facing path.
        json_output::success(serde_json::json!({
            "slug": r.slug,
            "name": r.name,
            "vendor": r.vendor,
            "upstreams": r.upstreams,
            "app_kind": r.app_kind,
            "follow_user_active": r.follow_user_active,
            "requested_permissions": r.requested_permissions,
            "action": if r.inserted { "inserted" } else { "updated" },
            "key_id": r.key_id,
            "api_key": r.route_token,
            "base_url": r.base_url,
            "bearer_was_new": r.bearer_was_new,
            "snapshotted_bindings": render_bindings_json(&r.snapshotted_bindings),
            "preserved_bindings": render_bindings_json(&r.preserved_bindings),
            "missing_upstreams_for_aikey_use": r.missing_upstreams,
            "base_url_protocol": r.base_url_protocol,
        }));
    }

    let action = if r.inserted { "Registered" } else { "Updated" };
    println!(
        "{} app '{}' ({}, upstreams={})",
        action,
        r.slug,
        r.app_kind,
        r.upstreams.join(",")
    );
    if r.bearer_was_new {
        println!("✓ Issued bearer for '{}':", r.name);
    } else {
        println!(
            "✓ Reusing existing bearer for '{}' (pass --rotate-bearer to rotate):",
            r.name
        );
    }
    println!();
    println!("    OPENAI_API_KEY={}", r.route_token);
    println!("    OPENAI_BASE_URL={}", r.base_url);
    println!();

    if r.follow_user_active {
        println!(
            "Mode: ⚠ follow-user-active (this app dynamically tracks your `aikey use` selection)."
        );
        println!("    Any change you make via `aikey use` will affect this app immediately.");
        if r.cleaned_stale_bindings > 0 {
            println!(
                "    Cleanup: removed {} stale app-specific binding(s) from a prior register.",
                r.cleaned_stale_bindings
            );
        }
        println!();
    } else {
        let nothing_to_say = r.snapshotted_bindings.is_empty()
            && r.preserved_bindings.is_empty()
            && r.missing_upstreams.is_empty();
        if nothing_to_say {
            println!("(no upstreams declared — pass --upstreams to register one)");
        } else {
            if !r.snapshotted_bindings.is_empty() {
                println!("Snapshotted from your `aikey use` selection (this register):");
                for (u, t, kr) in &r.snapshotted_bindings {
                    let label = super::resolve_binding_label(t.as_str(), kr);
                    println!("    {} → {}={}", u, t.as_str(), label);
                }
            }
            if !r.preserved_bindings.is_empty() {
                if !r.snapshotted_bindings.is_empty() {
                    println!();
                }
                println!("Preserved your previous per-app override (Bug 1 fix 2026-05-21):");
                for (u, t, kr) in &r.preserved_bindings {
                    let label = super::resolve_binding_label(t.as_str(), kr);
                    println!("    {} → {}={}  (kept — re-register did NOT touch your `aikey app route` choice)", u, t.as_str(), label);
                }
            }
            if !r.missing_upstreams.is_empty() {
                println!();
                println!("⚠️  No active key for these declared upstreams:");
                for u in &r.missing_upstreams {
                    println!("       - {}", u);
                }
                println!("    The app will fail at request time until you set bindings.");
                println!("    Option A (recommended): aikey use            # set globally, all apps inherit");
                println!(
                    "    Option B:               aikey app route {}    # set per-app override",
                    r.slug
                );
            } else if r.snapshotted_bindings.is_empty() && !r.preserved_bindings.is_empty() {
                // All bindings preserved, none new — nothing more to say.
            } else {
                println!();
                println!("To override per app: `aikey app route {}`", r.slug);
            }
        }
    }

    Ok(())
}

/// Output of `register_core`. Carries every piece of data needed by either
/// the CLI user-facing output or the `_internal app.register` IPC envelope.
/// Kept as plain data so callers can format it however they need without
/// re-doing SQL.
pub struct RegisterResult {
    pub slug: String,
    pub name: String,
    pub vendor: String,
    pub upstreams: Vec<String>,
    pub app_kind: String,
    pub follow_user_active: bool,
    pub requested_permissions: Vec<String>,
    pub inserted: bool,
    pub key_id: String,
    pub route_token: String,
    pub bearer_was_new: bool,
    pub snapshotted_bindings: Vec<(String, CredentialType, String)>,
    pub preserved_bindings: Vec<(String, CredentialType, String)>,
    pub missing_upstreams: Vec<String>,
    pub cleaned_stale_bindings: usize,
    pub base_url: String,
    pub base_url_protocol: String,
}

/// Pure (side-effecting on vault, but no stdout output) register logic.
/// All SQL writes + bearer issuance + binding snapshot/cleanup happen
/// here. Emits a single stderr line via `commands_proxy::maybe_warn_stale`
/// when the proxy needs to re-sync — that's the only printf.
///
/// Both the public CLI handler (`handle_register`) and the IPC dispatch
/// (`commands_internal::app::handle_register`) call this. Per CLAUDE.md
/// "_internal 隐藏命令必须复用公开命令逻辑" — single implementation,
/// two presentation shells.
#[allow(clippy::too_many_arguments)]
pub fn register_core(
    slug: &str,
    name: &str,
    vendor: &str,
    upstreams: &[String],
    first_party: bool,
    follow_user_active: bool,
    requested_permissions: &[String],
    filter_stages: &[String],
    filter_priority: Option<i64>,
    filter_timeout_policy: Option<&str>,
    rotate_bearer: bool,
) -> Result<RegisterResult, Box<dyn std::error::Error>> {
    validate_slug(slug).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    // A filter-only app (e.g. ai-compliance-detector) consumes no LLM upstream,
    // so empty --upstreams is allowed iff --filter-stages is set. Non-filter
    // apps still require at least one valid upstream.
    if upstreams.is_empty() {
        if filter_stages.is_empty() {
            return Err("at least one --upstreams value is required (e.g. anthropic), unless registering a filter-only app with --filter-stages".into());
        }
    } else {
        validate_upstreams(upstreams).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }
    validate_first_party_invariants(slug, first_party, follow_user_active)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let app_kind = if first_party {
        "first-party"
    } else {
        "third-party"
    };

    let inserted = upsert_app_record(
        slug,
        name,
        vendor,
        upstreams,
        app_kind,
        follow_user_active,
        requested_permissions,
    )?;

    // Filter registration is an additive UPDATE on the row just upserted, so
    // the existing upsert path (and its 20+ tests) stay untouched. Only runs
    // when this is a filter app; a plain re-register without --filter-stages
    // preserves any previously-set filter_stages.
    if !filter_stages.is_empty() {
        set_app_filter_stages(slug, filter_stages, filter_priority, filter_timeout_policy)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }

    // Resolve bindings for each declared upstream (Q1=A1 + Bug 1 修复).
    // For follow_user_active=true the snapshot is intentionally skipped —
    // resolver falls back to default profile dynamically. UX 2 cleanup:
    // ALSO drop any stale app-specific bindings written by a prior
    // register where follow_user_active was false, so `aikey app list`
    // doesn't display orphaned rows that the resolver no longer reads.
    let (outcome, cleaned_stale) = if follow_user_active {
        let cleaned = cleanup_stale_app_bindings(slug)?;
        (
            RegisterBindingOutcome {
                snapshotted: Vec::new(),
                preserved: Vec::new(),
                missing: Vec::new(),
            },
            cleaned,
        )
    } else {
        (resolve_register_bindings(slug, upstreams)?, 0usize)
    };

    // For bearer audit-trail purposes: snapshotted + preserved = "live"
    // bindings that the bearer will be associated with at issuance time.
    let mut live_bindings: Vec<(String, CredentialType, String)> = Vec::new();
    live_bindings.extend(outcome.snapshotted.iter().cloned());
    live_bindings.extend(outcome.preserved.iter().cloned());

    // Issue bearer. Q4=C1: reuse existing active bearer if any. Caller
    // can force rotation with --rotate-bearer.
    let (key_id, route_token, bearer_was_new) =
        issue_or_reuse_bearer(slug, rotate_bearer, &live_bindings)?;

    commands_proxy::maybe_warn_stale();

    let base_url_protocol = upstreams.first().map(String::as_str).unwrap_or("openai");
    let base_url = format!("http://127.0.0.1:27200/apps/{}/v1", slug);

    Ok(RegisterResult {
        slug: slug.to_string(),
        name: name.to_string(),
        vendor: vendor.to_string(),
        upstreams: upstreams.to_vec(),
        app_kind: app_kind.to_string(),
        follow_user_active,
        requested_permissions: requested_permissions.to_vec(),
        inserted,
        key_id,
        route_token,
        bearer_was_new,
        snapshotted_bindings: outcome.snapshotted,
        preserved_bindings: outcome.preserved,
        missing_upstreams: outcome.missing,
        cleaned_stale_bindings: cleaned_stale,
        base_url,
        base_url_protocol: base_url_protocol.to_string(),
    })
}

/// UX 2 cleanup (2026-05-21): when register's follow_user_active=true,
/// any pre-existing `profile=app:<slug>` binding rows become orphaned
/// (resolver ignores them in favor of `profile=default`). Delete them
/// so `aikey app list` doesn't display stale entries.
///
/// Returns the count of rows deleted (0 if no stale bindings existed).
fn cleanup_stale_app_bindings(slug: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let profile_id = format!("app:{}", slug);
    let existing = match storage::list_provider_bindings(&profile_id) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "[aikey app] WARN: failed to list app bindings to clean: {}",
                e
            );
            return Ok(0);
        }
    };
    let mut deleted = 0usize;
    for b in existing {
        match storage::remove_provider_binding(&profile_id, &b.provider_code) {
            Ok(true) => deleted += 1,
            Ok(false) => {}
            Err(e) => eprintln!(
                "[aikey app] WARN: failed to delete stale binding for {}: {}",
                b.provider_code, e
            ),
        }
    }
    Ok(deleted)
}

/// Outcome of resolving binding state for each declared upstream during
/// register. Three buckets, mutually exclusive per upstream:
///
///   - `snapshotted`: no app-specific binding existed; we wrote a fresh
///     snapshot from the user's `aikey use` default-profile binding
///   - `preserved`: app-specific binding ALREADY existed (likely from
///     a prior `aikey app route` user override); we DID NOT touch it,
///     preserving the user's intent
///   - `missing`: no app-specific binding, AND no default-profile
///     binding for this upstream — runtime will fail with BINDING_NOT_FOUND
///     until user fixes (warning printed)
pub struct RegisterBindingOutcome {
    pub snapshotted: Vec<(String, CredentialType, String)>,
    pub preserved: Vec<(String, CredentialType, String)>,
    pub missing: Vec<String>,
}

/// Pure decision logic for register-time binding classification.
/// Separated from `resolve_register_bindings` for unit-testability —
/// takes vec inputs, returns vec outputs, NO SQL.
///
/// Same 3-way semantics as `RegisterBindingOutcome` (snapshotted /
/// preserved / missing). `snapshotted` here is the list of bindings
/// that the caller MUST write to the app:<slug> profile after this
/// function returns. `preserved` is what already exists and must NOT
/// be touched. `missing` is the failure list.
pub fn classify_upstreams_for_register(
    upstreams: &[String],
    existing_app_bindings: &[storage::ProviderBinding],
    default_bindings: &[storage::ProviderBinding],
) -> RegisterBindingOutcome {
    let mut snapshotted: Vec<(String, CredentialType, String)> = Vec::new();
    let mut preserved: Vec<(String, CredentialType, String)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for upstream in upstreams {
        // 优先看 app-specific. 已存在则 preserve, 一行字节不动 (Bug 1 修复)。
        if let Some(b) = existing_app_bindings
            .iter()
            .find(|b| b.provider_code == *upstream)
        {
            preserved.push((
                upstream.clone(),
                b.key_source_type.clone(),
                b.key_source_ref.clone(),
            ));
            continue;
        }
        // 没 app-specific → 看默认能 snapshot 吗。
        match default_bindings
            .iter()
            .find(|b| b.provider_code == *upstream)
        {
            Some(b) => {
                snapshotted.push((
                    upstream.clone(),
                    b.key_source_type.clone(),
                    b.key_source_ref.clone(),
                ));
            }
            None => missing.push(upstream.clone()),
        }
    }

    RegisterBindingOutcome {
        snapshotted,
        preserved,
        missing,
    }
}

/// SQL wrapper around `classify_upstreams_for_register`. Reads both
/// binding sets from vault, computes outcome, writes snapshots to
/// app:<slug>.
///
/// Bug 1 修复 (2026-05-21): 已有 app-specific binding 的 upstream
/// **不动**, 保留用户之前用 `aikey app route` 设的 override。
pub fn resolve_register_bindings(
    slug: &str,
    upstreams: &[String],
) -> Result<RegisterBindingOutcome, Box<dyn std::error::Error>> {
    let existing_app_bindings = match storage::list_provider_bindings(&format!("app:{}", slug)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "[aikey app] WARN: failed to read app-specific bindings for slug={:?}: {}",
                slug, e
            );
            Vec::new()
        }
    };
    let default_bindings = match storage::list_provider_bindings("default") {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "[aikey app] WARN: failed to read default-profile bindings: {}",
                e
            );
            Vec::new()
        }
    };

    let outcome =
        classify_upstreams_for_register(upstreams, &existing_app_bindings, &default_bindings);

    // Persist the freshly-snapshotted rows.
    for (upstream, kt, kr) in &outcome.snapshotted {
        set_app_binding(slug, upstream, kt.as_str(), kr)?;
    }

    Ok(outcome)
}

/// Decide bearer issuance: reuse the existing active bearer for this slug
/// if any (Q4=C1), or issue a new one if no active bearer exists or the
/// caller passed --rotate-bearer.
///
/// Returns (key_id, route_token, was_newly_issued).
fn issue_or_reuse_bearer(
    slug: &str,
    rotate_bearer: bool,
    initial_bindings: &[(String, CredentialType, String)],
) -> Result<(String, String, bool), Box<dyn std::error::Error>> {
    // Check for existing active bearer.
    let existing_active = list_app_active_keys(slug)?;
    if !existing_active.is_empty() && !rotate_bearer {
        // Reuse. We need the route_token to print, but list_app_active_keys
        // only returns metadata (no route_token). Read it directly.
        let token = read_active_route_token(slug)?;
        let key_id = existing_active[0].key_id.clone();
        return Ok((key_id, token, false));
    }
    if !existing_active.is_empty() && rotate_bearer {
        // Forced rotation: revoke existing + issue new.
        let _ = revoke_active_keys(slug)?;
    }

    // No active bearer OR rotation requested — mint a new one with the
    // initial bindings as the audit trail.
    let (key_id, route_token) = authorize_atomic(slug, initial_bindings)?;
    Ok((key_id, route_token, true))
}

// ---------------------------------------------------------------------------
// reveal-token (2026-05-25) — re-read the active bearer plaintext
// ---------------------------------------------------------------------------

/// Implements `aikey app reveal-token <slug>` (CLI surface for the
/// 2026-05-25 token-reveal feature). Reads the most-recent active
/// `app_keys.route_token` plaintext + the matching key_id + computed
/// base_url.
///
/// Output shape:
///   - default (no `--json`): single line on stdout containing JUST the
///     plaintext token, no metadata, no trailing newline beyond what
///     println! adds. This is the form scripts use:
///       `OPENAI_API_KEY=$(aikey app reveal-token claude-mem)`
///   - `--json`: full envelope `{slug, key_id, route_token, base_url}`
///     matching what `aikey app rotate --json` emits, so existing
///     consumers can drop in either command.
///
/// Why no consent prompt: the value is already accessible via direct
/// `sqlite3 ~/.aikey/data/vault.db ...` query for anyone with shell
/// access (same user, same machine). Prompting would only block scripts
/// without adding security. The reveal is gated by vault-unlock
/// indirectly: `storage::open_connection` (under `get_active_route_token`)
/// requires an unlocked vault.
pub fn handle_reveal_token(slug: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    validate_slug(slug).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let info = super::get_active_route_token(slug)?;

    if json_mode {
        json_output::success(serde_json::json!({
            "slug": info.slug,
            "key_id": info.key_id,
            "route_token": info.route_token,
            "base_url": info.base_url,
        }));
    }

    println!("{}", info.route_token);
    Ok(())
}

/// Read the active route_token for the given slug (one expected, but
/// schema allows N — return the most recent created).
fn read_active_route_token(slug: &str) -> Result<String, String> {
    let conn = storage::open_connection()?;
    let token: Option<String> = conn
        .query_row(
            "SELECT route_token FROM app_keys
              WHERE app_slug = ?1 AND status = 'active'
              ORDER BY created_at DESC
              LIMIT 1",
            rusqlite::params![slug],
            |r| r.get(0),
        )
        .ok();
    token.ok_or_else(|| {
        format!(
            "expected an active route_token for slug={:?} but found none (vault corruption?)",
            slug
        )
    })
}

// ---------------------------------------------------------------------------
// route — OPTIONAL per-app binding override (2026-05-21 UX redesign)
//
// `aikey app route` is now OPTIONAL — `aikey app register` already issues
// the bearer + snapshots `aikey use` selections into app bindings. Use
// `aikey app route` only when you want to:
//   (a) override a specific app's binding to a non-default key
//   (b) add a binding for an upstream that wasn't in `aikey use` at
//       register time (or has been changed since)
//
// `aikey app route` does NOT issue bearer (that's register's job).
// `aikey app route` does NOT alter `app_records.follow_user_active` —
// if the app was registered with --follow-user-active, route is a no-op
// from the resolver's POV (resolver still goes to default profile).
// ---------------------------------------------------------------------------

/// `aikey app route <slug>` — interactive picker (default).
///
/// `aikey app route <slug> --upstream X --key-type Y --key-ref Z` —
/// non-interactive (CI / scripts).
pub fn handle_route(
    slug: &str,
    upstream: Option<&str>,
    key_type: Option<&str>,
    key_ref: Option<&str>,
    yes: bool,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_slug(slug).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // UX 3 (2026-05-21): `--yes` no longer has meaning here — it used
    // to skip the bearer-issuance prompt, which has moved to register.
    // Surface a deprecation warning so users / scripts know to remove it,
    // rather than silently ignoring.
    if yes {
        eprintln!(
            "[aikey app route] DEPRECATED: --yes is no longer needed (bearer issuance moved to `aikey app register`). Safe to remove from your script."
        );
    }

    let rec = get_app_record(slug)?.ok_or_else(|| -> Box<dyn std::error::Error> {
        format!(
            "app '{}' not found in vault; run `aikey app register --slug {} --upstreams ...` first",
            slug, slug
        )
        .into()
    })?;

    // Mode dispatch: explicit triple → non-interactive; partial flags → error;
    // none → interactive.
    let non_interactive = match (upstream, key_type, key_ref) {
        (Some(_), Some(_), Some(_)) => true,
        (None, None, None) => false,
        _ => {
            return Err(
                "non-interactive mode requires all three of --upstream, --key-type, --key-ref \
                 (or omit all three to run the interactive picker)"
                    .into(),
            );
        }
    };

    let updated_bindings: Vec<(String, CredentialType, String)> = if non_interactive {
        let u = upstream.unwrap();
        let kt = key_type.unwrap();
        let kr = key_ref.unwrap();
        if !rec.upstreams.iter().any(|x| x == u) {
            return Err(format!(
                "upstream '{}' not declared in app's manifest (declared: {}). \
                 Re-register with `aikey app register --slug {} --upstreams {}` \
                 to expand the upstream set (requires re-consent).",
                u,
                rec.upstreams.join(","),
                slug,
                u
            )
            .into());
        }
        let typed = parse_key_type(kt)?;
        set_app_binding(slug, u, kt, kr)?;
        vec![(u.to_string(), typed, kr.to_string())]
    } else {
        // Interactive flow.
        if !io::stdin().is_terminal() {
            return Err(
                "interactive mode requires a TTY; pass --upstream / --key-type / --key-ref \
                 (or pipe `yes` if you really mean it)"
                    .into(),
            );
        }
        interactive_pick_and_bind(&rec)?
    };

    commands_proxy::maybe_warn_stale();

    // Surface a friendly reminder if the app has follow_user_active=true —
    // any binding we write to app:<slug> profile will be IGNORED by the
    // resolver (which goes to default profile when follow_user_active=true).
    if rec.follow_user_active {
        println!();
        println!("⚠ Note: app '{}' is in follow-user-active mode.", slug);
        println!("    Bindings you set via `aikey app route` will be IGNORED at request time;");
        println!("    the resolver always uses your `aikey use` (default profile) selection.");
        println!("    Re-register without --follow-user-active to make per-app binding effective.");
        println!();
    }

    // No bearer issuance here (moved to handle_register). If the app
    // has no active bearer, tell the user to register first.
    let active_keys = list_app_active_keys(slug)?;
    let bearer_status = if active_keys.is_empty() {
        "missing (register first: `aikey app register --slug <slug> --upstreams ...`)"
    } else {
        "active"
    };

    if json_mode {
        json_output::success(serde_json::json!({
            "slug": slug,
            "bindings_updated": render_bindings_json(&updated_bindings),
            "follow_user_active": rec.follow_user_active,
            "bearer_status": bearer_status,
        }));
    }

    println!();
    for (u, t, r) in &updated_bindings {
        println!(
            "Set binding for app '{}' (profile=app:{}): {} → {}={}",
            slug,
            slug,
            u,
            t.as_str(),
            r
        );
    }
    if active_keys.is_empty() {
        println!();
        println!(
            "⚠ This app has no active bearer. Run `aikey app register --slug {} --upstreams ...`",
            slug
        );
        println!("    to issue one. (Route only updates bindings; register issues bearers.)");
    }
    Ok(())
}

/// Interactive picker: shows the upstream-binding table, prompts user to
/// pick a row to set, then prompts again to pick a key for that row.
/// Returns the (upstream, key_type, key_ref) tuples written this run
/// (may be empty if user picks "done").
fn interactive_pick_and_bind(
    rec: &AppRecord,
) -> Result<Vec<(String, CredentialType, String)>, Box<dyn std::error::Error>> {
    let mut updated: Vec<(String, CredentialType, String)> = Vec::new();

    loop {
        let current = get_active_bindings(&rec.slug)?;
        println!();
        println!("Bindings for app '{}' ({}):", rec.slug, rec.app_kind);
        for (idx, upstream) in rec.upstreams.iter().enumerate() {
            let label = current
                .iter()
                .find(|(p, _, _)| p == upstream)
                .map(|(_, t, r)| format!("{}={}", t.as_str(), r))
                .unwrap_or_else(|| "(unbound)".to_string());
            println!("  [{}] {:<12} → {}", idx + 1, upstream, label);
        }
        println!("  [q] done");
        print!("Pick row to set [1-{}/q]: ", rec.upstreams.len());
        io::stdout().flush()?;

        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim().to_lowercase();
        if trimmed == "q" || trimmed.is_empty() {
            break;
        }
        let idx: usize = match trimmed.parse::<usize>() {
            Ok(n) if n >= 1 && n <= rec.upstreams.len() => n - 1,
            _ => {
                println!("Invalid input; expected 1-{} or q.", rec.upstreams.len());
                continue;
            }
        };
        let upstream = &rec.upstreams[idx];
        let pick = prompt_key_for_upstream(upstream)?;
        if let Some((key_type, key_ref)) = pick {
            let key_type_str = key_type.as_str();
            set_app_binding(&rec.slug, upstream, key_type_str, &key_ref)?;
            updated.push((upstream.clone(), key_type, key_ref));
        }
    }

    Ok(updated)
}

/// Lists candidate keys for the given upstream and prompts user to pick.
/// Returns None if user cancels. Candidates aggregated from three sources:
///   - personal aliases (vault entries.provider_code = upstream)
///   - OAuth accounts logged in for this provider
///   - team-managed virtual keys for this provider
fn prompt_key_for_upstream(
    upstream: &str,
) -> Result<Option<(CredentialType, String)>, Box<dyn std::error::Error>> {
    let candidates = collect_key_candidates(upstream)?;
    if candidates.is_empty() {
        println!();
        println!("No keys found for upstream '{}'.", upstream);
        println!("Add one via:");
        println!("    aikey add my-{} --provider {}", upstream, upstream);
        println!(
            "    aikey auth login {}   # for OAuth-supported providers",
            upstream
        );
        return Ok(None);
    }

    println!();
    println!("Available keys for upstream '{}':", upstream);
    for (idx, c) in candidates.iter().enumerate() {
        println!(
            "  [{}] {:<24} {} ({})",
            idx + 1,
            c.label,
            c.kind_display,
            c.ref_display
        );
    }
    println!("  [s] skip this upstream");
    print!("Pick [1-{}/s]: ", candidates.len());
    io::stdout().flush()?;

    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim().to_lowercase();
    if trimmed == "s" || trimmed.is_empty() {
        return Ok(None);
    }
    let idx: usize = match trimmed.parse::<usize>() {
        Ok(n) if n >= 1 && n <= candidates.len() => n - 1,
        _ => {
            println!("Invalid input; skipping.");
            return Ok(None);
        }
    };
    let chosen = &candidates[idx];
    Ok(Some((chosen.key_type.clone(), chosen.key_ref.clone())))
}

/// One candidate key entry shown in the interactive picker.
struct KeyCandidate {
    /// Display label (alias name / OAuth identity / team key alias).
    label: String,
    /// Human-readable category ("personal" / "OAuth" / "team").
    kind_display: &'static str,
    /// Secondary display string (e.g., date added or upstream alias).
    ref_display: String,
    /// CredentialType for set_app_binding.
    key_type: CredentialType,
    /// key_source_ref string to write into binding row.
    key_ref: String,
}

/// Collect all key candidates for the given upstream from the three sources.
fn collect_key_candidates(upstream: &str) -> Result<Vec<KeyCandidate>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();

    // 1. Personal aliases (vault.entries with this provider_code).
    let conn = storage::open_connection()?;
    let mut stmt = conn.prepare(
        "SELECT alias FROM entries
          WHERE provider_code = ?1
             OR (supported_providers IS NOT NULL
                 AND supported_providers LIKE ?2)
          ORDER BY alias",
    )?;
    let like_pattern = format!("%\"{}\"%", upstream);
    let alias_rows = stmt
        .query_map(rusqlite::params![upstream, like_pattern], |r| {
            r.get::<_, String>(0)
        })?
        .filter_map(Result::ok);
    for alias in alias_rows {
        out.push(KeyCandidate {
            label: alias.clone(),
            kind_display: "personal",
            ref_display: "vault alias".to_string(),
            key_type: CredentialType::PersonalApiKey,
            key_ref: alias,
        });
    }

    // 2. OAuth accounts for this provider.
    if let Ok(accounts) = super::list_oauth_accounts_for_provider(upstream) {
        for acc in accounts {
            out.push(KeyCandidate {
                label: acc.display_label.clone(),
                kind_display: "OAuth",
                ref_display: acc.provider_account_id.clone(),
                key_type: CredentialType::PersonalOAuthAccount,
                key_ref: acc.provider_account_id,
            });
        }
    }

    // 3. Team-managed virtual keys for this provider.
    if let Ok(team_keys) = super::list_team_keys_for_provider(upstream) {
        for tk in team_keys {
            out.push(KeyCandidate {
                label: tk.alias.clone(),
                kind_display: "team",
                ref_display: tk.virtual_key_id.clone(),
                key_type: CredentialType::ManagedVirtualKey,
                key_ref: tk.virtual_key_id,
            });
        }
    }

    Ok(out)
}

/// Snapshot all bindings currently set for the app (across upstreams).
/// Used to populate the bearer's `initial_bindings` tuple atomically with
/// authorize_atomic at first-full-route time.
fn collect_all_app_bindings(
    slug: &str,
) -> Result<Vec<(String, CredentialType, String)>, Box<dyn std::error::Error>> {
    let active = get_active_bindings(slug)?;
    Ok(active)
}

fn parse_key_type(s: &str) -> Result<CredentialType, Box<dyn std::error::Error>> {
    Ok(match s {
        "personal" | "personal_api_key" => CredentialType::PersonalApiKey,
        "team" | "managed_virtual_key" => CredentialType::ManagedVirtualKey,
        "personal_oauth_account" => CredentialType::PersonalOAuthAccount,
        other => {
            return Err(format!(
                "--key-type must be 'personal', 'team', or 'personal_oauth_account', got {:?}",
                other
            )
            .into());
        }
    })
}

fn print_bearer_consent_prompt(rec: &AppRecord, bindings: &[(String, CredentialType, String)]) {
    println!();
    println!("─── About to issue bearer token for app ───");
    println!("  slug:      {}", rec.slug);
    println!("  name:      {}", rec.name);
    if !rec.vendor.is_empty() {
        println!("  vendor:    {}", rec.vendor);
    }
    println!("  kind:      {}", rec.app_kind);
    if rec.follow_user_active {
        println!("  mode:      ⚠ follow-active (shares your `aikey use` selection)");
    }
    println!("  upstreams: {}", rec.upstreams.join(", "));
    if !rec.requested_permissions.is_empty() {
        println!("  perms:     {}", rec.requested_permissions.join(", "));
    }
    println!("  bindings written this session:");
    for (p, t, r) in bindings {
        println!("             {} → {}={}", p, t.as_str(), r);
    }
    if is_first_party(&rec.slug) && rec.follow_user_active {
        println!();
        println!("⚠  first-party + follow-active: this app will see ANY future");
        println!("   `aikey use` change. Make sure you trust this app.");
    }
    println!();
}

fn confirm_yes_no(question: &str, default_yes: bool) -> Result<bool, io::Error> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{} {} ", question, hint);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim().to_lowercase();
    Ok(match trimmed.as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    })
}

fn render_bindings_json(bindings: &[(String, CredentialType, String)]) -> Vec<serde_json::Value> {
    bindings
        .iter()
        .map(|(p, t, r)| {
            let kt = t.as_str();
            serde_json::json!({
                "upstream": p,
                "key_source_type": kt,
                "key_source_ref": r,
                // Friendly display string the UI should render — see
                // commands_app::resolve_binding_label. Web UI prefers
                // this over key_source_ref so OAuth `session_<hex>` and
                // team `vk_<hex>` rows show a human-readable label.
                "key_source_label": super::resolve_binding_label(kt, r),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

pub fn handle_list(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let apps = list_apps()?;

    if json_mode {
        let json: Vec<serde_json::Value> = apps
            .iter()
            .map(|(rec, active)| {
                serde_json::json!({
                    "slug": rec.slug,
                    "name": rec.name,
                    "vendor": rec.vendor,
                    "upstreams": rec.upstreams,
                    "app_kind": rec.app_kind,
                    "follow_user_active": rec.follow_user_active,
                    "created_at": rec.created_at,
                    "updated_at": rec.updated_at,
                    "active_key": active.as_ref().map(|k| serde_json::json!({
                        "key_id": k.key_id,
                        "created_at": k.created_at,
                        "last_used_at": k.last_used_at,
                    })),
                })
            })
            .collect();
        json_output::success(serde_json::json!({ "apps": json }));
    }

    if apps.is_empty() {
        println!("(no apps registered — try `aikey app register --slug ... --name ... --upstreams openai`)");
        return Ok(());
    }
    println!(
        "{:<24} {:<12} {:<14} {:<18} {}",
        "SLUG", "KIND", "UPSTREAMS", "ACTIVE KEY", "LAST USED"
    );
    for (rec, active) in apps {
        let key_label = match &active {
            Some(k) => format!("{}…", &k.key_id[..k.key_id.len().min(8)]),
            None => "—".to_string(),
        };
        let last_used = match active.as_ref().and_then(|k| k.last_used_at) {
            Some(ts) => format_epoch_relative(ts),
            None => "—".to_string(),
        };
        println!(
            "{:<24} {:<12} {:<14} {:<18} {}",
            rec.slug,
            rec.app_kind,
            rec.upstreams.join(","),
            key_label,
            last_used
        );
    }
    Ok(())
}

fn format_epoch_relative(epoch_seconds: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(epoch_seconds);
    let delta = now - epoch_seconds;
    if delta < 60 {
        format!("{}s ago", delta.max(0))
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

pub fn handle_revoke(slug: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    validate_slug(slug).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let revoked = revoke_active_keys(slug)?;
    commands_proxy::maybe_warn_stale();

    if json_mode {
        json_output::success(serde_json::json!({
            "slug": slug,
            "revoked_count": revoked,
        }));
    }
    if revoked == 0 {
        println!(
            "No active key for app '{}' (already revoked or never authorized).",
            slug
        );
    } else {
        println!(
            "Revoked {} active key(s) for app '{}'. Re-issue with `aikey app route {}`.",
            revoked, slug, slug
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// pause / resume
// ---------------------------------------------------------------------------

pub fn handle_pause(slug: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    validate_slug(slug).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let paused = pause_active_keys(slug)?;
    commands_proxy::maybe_warn_stale();

    if json_mode {
        json_output::success(serde_json::json!({
            "slug": slug,
            "paused_count": paused,
        }));
    }
    if paused == 0 {
        println!("No active key to pause for app '{}'.", slug);
    } else {
        println!(
            "Paused active key for app '{}'. Run `aikey app resume {}` to re-enable — the Agent's OPENAI_API_KEY does NOT change.",
            slug, slug
        );
    }
    Ok(())
}

pub fn handle_resume(slug: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    validate_slug(slug).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let resumed = resume_paused_keys(slug)?;
    commands_proxy::maybe_warn_stale();

    if json_mode {
        json_output::success(serde_json::json!({
            "slug": slug,
            "resumed_count": resumed,
        }));
    }
    if resumed == 0 {
        println!(
            "No paused key for app '{}' (already active, never paused, or never authorized).",
            slug
        );
    } else {
        println!(
            "Resumed key for app '{}'. The Agent should work again with its existing OPENAI_API_KEY.",
            slug
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// rotate
// ---------------------------------------------------------------------------

pub fn handle_rotate(slug: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    validate_slug(slug).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    get_app_record(slug)?.ok_or_else(|| -> Box<dyn std::error::Error> {
        format!(
            "app '{}' not found; run `aikey app register --slug {}` first",
            slug, slug
        )
        .into()
    })?;

    let (key_id, route_token) = rotate_app_key(slug)?;
    commands_proxy::maybe_warn_stale();

    let base_url = format!("http://127.0.0.1:27200/apps/{}/v1", slug);

    if json_mode {
        json_output::success(serde_json::json!({
            "slug": slug,
            "key_id": key_id,
            "api_key": route_token,
            "base_url": base_url,
        }));
    }
    println!();
    println!(
        "Rotated key for app '{}'. The OLD bearer is immediately revoked — update the Agent's env:",
        slug
    );
    println!();
    println!("    OPENAI_API_KEY={}", route_token);
    println!("    OPENAI_BASE_URL={}", base_url);
    println!();
    println!("Note: the Agent must be restarted to pick up the new env. Any in-flight requests with the old bearer will 401.");
    Ok(())
}
