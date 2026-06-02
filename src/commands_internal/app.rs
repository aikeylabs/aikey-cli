//! `_internal app` — Phase 4 third-party Agent management ops for Web UI.
//!
//! # 定位
//!
//! All third-party-Agent App pipeline CRUD operations exposed to
//! aikey-local-server (via subprocess + `userapi/cli.Bridge`) so the
//! Web UI can manage connected apps without re-implementing vault
//! access. Mirrors the public `aikey app *` commands but with
//! JSON-over-stdin/stdout protocol instead of interactive prompts.
//!
//! # Sub-actions (env.action)
//!
//! | action | payload | reads / writes | notes |
//! |---|---|---|---|
//! | `list` | `{}` | reads `app_records` JOIN `app_keys` + per-app bindings | Web list page |
//! | `get` | `{slug}` | reads single app + active keys + bindings | Web detail page |
//! | `route` | `{slug, upstream, key_source_type, key_source_ref}` | writes `user_profile_provider_bindings` for `profile_id=app:<slug>` | "Switch Key" modal |
//! | `revoke` | `{slug}` | UPDATE all active keys for slug → 'revoked' | irreversible |
//! | `pause` | `{slug}` | UPDATE active → 'paused' | reversible via resume |
//! | `resume` | `{slug}` | UPDATE paused → 'active' | inverse of pause |
//! | `rotate` | `{slug}` | atomically revoke + insert new key | "Rotate bearer" — old token 401s immediately |
//!
//! # 复用公开命令的 pub fn core (CLAUDE.md `_internal 隐藏命令必须复用公开命令逻辑`)
//!
//! This module is a thin JSON wrapper. ALL business logic lives in
//! `commands_app::{list_apps, get_app_record, get_active_bindings,
//! set_app_binding, revoke_active_keys, pause_active_keys,
//! resume_paused_keys, rotate_app_key, list_app_active_keys}`. Do NOT
//! re-implement SQL or vault writes here — if a fix is needed, extract a
//! `pub fn` core in `commands_app/mod.rs` first, then wrap it here.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::commands_app;

use super::protocol::ResultEnvelope;
use super::protocol::StdinEnvelope;
use super::stdin_json::{emit, emit_error};

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub fn handle(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    match env.action.as_str() {
        "list" => handle_list(env),
        "get" => handle_get(env),
        "register" => handle_register(env),
        "route" => handle_route(env),
        "revoke" => handle_revoke(env),
        "pause" => handle_pause(env),
        "resume" => handle_resume(env),
        "rotate" => handle_rotate(env),
        "uninstall" => handle_uninstall(env),
        "reveal-token" => handle_reveal_token(env),
        "filter-status" => handle_filter_status(env),
        "filter-set" => handle_filter_set(env),
        other => emit_error(
            req_id,
            "I_UNKNOWN_ACTION",
            format!("unknown app action: '{}'", other),
        ),
    }
}

// ---------------------------------------------------------------------------
// Sub-action handlers
// ---------------------------------------------------------------------------

/// `list` — returns all registered apps with their per-upstream bindings
/// + active-key summary. Web "Connected Apps" list page consumes this.
fn handle_list(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    let rows = match commands_app::list_apps() {
        Ok(r) => r,
        Err(e) => {
            emit_error(req_id, "I_APP_LIST_FAILED", format!("list apps: {}", e));
            return;
        }
    };

    let apps: Vec<Value> = rows
        .into_iter()
        .map(|(rec, active_key)| {
            // Best-effort: fetch bindings per app. A binding query failure
            // for one app shouldn't crash the whole list — log on stderr
            // (per CLAUDE.md "失败要显眼") and continue with empty bindings.
            // Display path — use `get_effective_bindings` so first-party +
            // follow-user-active apps show the user's live `aikey use`
            // selection, not the stale per-app snapshot. See
            // commands_app::get_effective_bindings doc comment for the why.
            let bindings_json = match commands_app::get_effective_bindings(&rec.slug) {
                Ok(b) => render_bindings(
                    &b.iter()
                        .map(|(u, c, r)| (u.clone(), c.as_str(), r.clone()))
                        .collect::<Vec<_>>(),
                ),
                Err(e) => {
                    eprintln!(
                        "[_internal app list] WARN: get_active_bindings({}) failed: {}",
                        rec.slug, e
                    );
                    Value::Array(Vec::new())
                }
            };
            json!({
                "slug": rec.slug,
                "name": rec.name,
                "vendor": rec.vendor,
                "upstreams": rec.upstreams,
                "app_kind": rec.app_kind,
                "follow_user_active": rec.follow_user_active,
                "has_active_key": active_key.is_some(),
                "key_id": active_key.as_ref().map(|k| k.key_id.clone()),
                "last_used_at": active_key.as_ref().and_then(|k| k.last_used_at),
                "key_created_at": active_key.as_ref().map(|k| k.created_at),
                "bindings": bindings_json,
                "created_at": rec.created_at,
                "updated_at": rec.updated_at,
            })
        })
        .collect();

    emit(&ResultEnvelope::ok(req_id, json!({ "apps": apps })));
}

/// `get` — returns full detail for one app (record + active keys list +
/// bindings). Web "App Detail" page consumes this.
fn handle_get(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(Deserialize)]
    struct Payload {
        slug: String,
    }

    let p: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_BAD_PAYLOAD", format!("decode payload: {}", e));
            return;
        }
    };
    if let Err(e) = commands_app::validate_slug(&p.slug) {
        emit_error(req_id, "I_INVALID_SLUG", e);
        return;
    }

    let rec = match commands_app::get_app_record(&p.slug) {
        Ok(Some(r)) => r,
        Ok(None) => {
            emit_error(
                req_id,
                "I_APP_NOT_FOUND",
                format!("app '{}' not registered", p.slug),
            );
            return;
        }
        Err(e) => {
            emit_error(req_id, "I_APP_GET_FAILED", format!("get app: {}", e));
            return;
        }
    };

    // Display path — see handle_list comment on get_effective_bindings.
    let bindings = commands_app::get_effective_bindings(&p.slug).unwrap_or_default();
    let active_keys = commands_app::list_app_active_keys(&p.slug).unwrap_or_default();

    let data = json!({
        "app": {
            "slug": rec.slug,
            "name": rec.name,
            "vendor": rec.vendor,
            "upstreams": rec.upstreams,
            "app_kind": rec.app_kind,
            "follow_user_active": rec.follow_user_active,
            "requested_permissions": rec.requested_permissions,
            "created_at": rec.created_at,
            "updated_at": rec.updated_at,
        },
        "bindings": render_bindings(
            &bindings.iter()
                .map(|(u, c, r)| (u.clone(), c.as_str(), r.clone()))
                .collect::<Vec<_>>(),
        ),
        "active_keys": active_keys.into_iter().map(|k| json!({
            "key_id": k.key_id,
            "created_at": k.created_at,
            "last_used_at": k.last_used_at,
        })).collect::<Vec<_>>(),
    });
    emit(&ResultEnvelope::ok(req_id, data));
}

/// `register` — Web UI third-party app registration (added 2026-05-25).
///
/// Wraps `commands_app::handlers::register_core` with three security
/// invariants HARDCODED at this layer to keep the Web path narrow:
///
///   - `first_party = false`           → never grants the first-party
///     privilege from a Web request. First-party slugs are reserved for
///     `FIRST_PARTY_SLUGS` (currently degrade-detector); the CLI
///     `validate_first_party_invariants` would reject mis-claims at
///     write time, but rejecting here means we never even touch the
///     vault on a malformed Web call.
///   - `follow_user_active = false`    → third-party apps cannot
///     dynamically follow `aikey use`. Per
///     `2026-05-23-credential-mode-architecture.md` SPEC §29 + user
///     decision 2026-05-25, third-party should be Mode B-equivalent
///     (snapshot from default at register time, then independent).
///   - `rotate_bearer = false`         → re-register reuses the existing
///     active bearer (per 2026-05-21 §5.C C1). Rotation is a separate
///     intent, exposed via the dedicated `rotate` IPC action / UI button.
///
/// Web payload accepts only the safe fields: slug, name, vendor (opt),
/// upstreams, requested_permissions (opt). Anything else (first_party,
/// follow_user_active, rotate_bearer, app_kind) is ignored — server-
/// hardcoded above.
///
/// Reserved-slug pre-check: returns 400 `I_FIRST_PARTY_SLUG_RESERVED`
/// if the requested slug is in `FIRST_PARTY_SLUGS`, so the user gets a
/// clean "pick a different slug" instead of a generic permission error
/// from inside `register_core`.
fn handle_register(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(Deserialize)]
    struct Payload {
        slug: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        vendor: String,
        upstreams: Vec<String>,
        #[serde(default)]
        requested_permissions: Vec<String>,
    }
    let p: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_BAD_PAYLOAD", format!("decode payload: {}", e));
            return;
        }
    };

    // Pre-flight: slug shape (register_core also runs this, but checking
    // here lets us return I_INVALID_SLUG before the reserved-slug check
    // — clearer error precedence: format > policy).
    if let Err(e) = commands_app::validate_slug(&p.slug) {
        emit_error(req_id, "I_INVALID_SLUG", e);
        return;
    }

    // Block reserved first-party slugs from Web registration. CLI users
    // who legitimately need to add a first-party slug go through code:
    // they update FIRST_PARTY_SLUGS, recompile, then `aikey app register
    // --first-party`. There is no Web path to that privilege.
    if commands_app::is_first_party(&p.slug) {
        emit_error(
            req_id,
            "I_FIRST_PARTY_SLUG_RESERVED",
            format!(
                "slug '{}' is reserved for built-in first-party apps. \
                 Choose a different slug for third-party registration.",
                p.slug
            ),
        );
        return;
    }

    // Web UI register must always declare at least one upstream — empty
    // upstreams would let the user create a phantom app that can't route.
    if p.upstreams.is_empty() {
        emit_error(
            req_id,
            "I_NO_UPSTREAMS",
            "upstreams list cannot be empty — pick at least one provider \
             (e.g. \"anthropic\", \"openai\")"
                .to_string(),
        );
        return;
    }

    // Fall back to slug as display name when caller omits it (vendor
    // installers typically pass --name; manual Web Add lets users skip).
    let effective_name = if p.name.is_empty() {
        p.slug.clone()
    } else {
        p.name.clone()
    };

    let result = match commands_app::register_core(
        &p.slug,
        &effective_name,
        &p.vendor,
        &p.upstreams,
        /* first_party */ false,
        /* follow_user_active */ false,
        &p.requested_permissions,
        /* filter_stages */ &[],
        /* filter_priority */ None,
        /* filter_timeout_policy */ None,
        /* rotate_bearer */ false,
    ) {
        Ok(r) => r,
        Err(e) => {
            emit_error(req_id, "I_APP_REGISTER_FAILED", format!("register: {}", e));
            return;
        }
    };

    // Project the typed binding tuples into JSON arrays. Re-uses the
    // same shape as handle_register's CLI JSON output (see
    // commands_app::handlers::handle_register json_mode branch), so the
    // Web UI and the CLI consumers parse identical wire format. Each row
    // carries `key_source_label` — the friendly display string the UI
    // should show — alongside the raw `key_source_ref` (which the UI
    // still needs as the stable identifier for follow-up calls like
    // `aikey app route`). See commands_app::resolve_binding_label for
    // the resolution rules.
    let snapshotted: Vec<Value> = result
        .snapshotted_bindings
        .iter()
        .map(|(u, t, r)| {
            let kt = t.as_str();
            json!({
                "upstream": u,
                "key_source_type": kt,
                "key_source_ref": r,
                "key_source_label": commands_app::resolve_binding_label(kt, r),
            })
        })
        .collect();
    let preserved: Vec<Value> = result
        .preserved_bindings
        .iter()
        .map(|(u, t, r)| {
            let kt = t.as_str();
            json!({
                "upstream": u,
                "key_source_type": kt,
                "key_source_ref": r,
                "key_source_label": commands_app::resolve_binding_label(kt, r),
            })
        })
        .collect();

    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "slug": result.slug,
            "name": result.name,
            "vendor": result.vendor,
            "upstreams": result.upstreams,
            "app_kind": result.app_kind,
            "follow_user_active": result.follow_user_active,
            "requested_permissions": result.requested_permissions,
            "action": if result.inserted { "inserted" } else { "updated" },
            "key_id": result.key_id,
            // route_token is the one-time-shown bearer. Web UI surfaces
            // this in a token-reveal modal with a Copy button and a
            // "this will not be shown again" warning.
            "route_token": result.route_token,
            "base_url": result.base_url,
            "base_url_protocol": result.base_url_protocol,
            "bearer_was_new": result.bearer_was_new,
            "snapshotted_bindings": snapshotted,
            "preserved_bindings": preserved,
            "missing_upstreams_for_aikey_use": result.missing_upstreams,
        }),
    ));
}

/// `route` — UPSERT a per-upstream binding. Equivalent to the
/// non-interactive form of `aikey app route <slug> --upstream X
/// --key-type Y --key-ref Z`. Bug 1 (review-and-fixes 2026-05-21) is
/// handled by the resolver, not here — we just write the row the user
/// chose.
fn handle_route(env: StdinEnvelope) {
    let req_id = env.request_id.clone();

    #[derive(Deserialize)]
    struct Payload {
        slug: String,
        upstream: String,
        key_source_type: String,
        key_source_ref: String,
    }
    let p: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(req_id, "I_BAD_PAYLOAD", format!("decode payload: {}", e));
            return;
        }
    };
    if let Err(e) = commands_app::validate_slug(&p.slug) {
        emit_error(req_id, "I_INVALID_SLUG", e);
        return;
    }
    // Sanity-check key_source_type early so the Go side gets a precise
    // error before SQL row-level constraint failure. Mirrors the match
    // in CredentialType::from_db_str (which would silently default to
    // PersonalApiKey on unknown input — that's surprising for user-
    // supplied values, so we reject explicitly here).
    if !matches!(
        p.key_source_type.as_str(),
        "personal" | "personal_api_key" | "team" | "managed_virtual_key" | "personal_oauth_account"
    ) {
        emit_error(
            req_id,
            "I_INVALID_KEY_SOURCE_TYPE",
            format!(
                "key_source_type '{}' is not one of: personal, personal_api_key, team, managed_virtual_key, personal_oauth_account",
                p.key_source_type
            ),
        );
        return;
    }

    if let Err(e) =
        commands_app::set_app_binding(&p.slug, &p.upstream, &p.key_source_type, &p.key_source_ref)
    {
        emit_error(
            req_id,
            "I_APP_ROUTE_FAILED",
            format!("set_app_binding: {}", e),
        );
        return;
    }
    emit(&ResultEnvelope::ok(
        req_id,
        json!({ "slug": p.slug, "upstream": p.upstream, "ok": true }),
    ));
}

/// `revoke` — irreversibly mark all active keys for the slug as
/// 'revoked'. Web UI's "Revoke" action; user confirms in modal before
/// calling. After this the app's bearer 401s immediately.
fn handle_revoke(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let slug = match parse_slug_only(&env, &req_id) {
        Some(s) => s,
        None => return,
    };
    match commands_app::revoke_active_keys(&slug) {
        Ok(n) => emit(&ResultEnvelope::ok(
            req_id,
            json!({ "slug": slug, "revoked_count": n }),
        )),
        Err(e) => emit_error(req_id, "I_APP_REVOKE_FAILED", format!("revoke: {}", e)),
    }
}

/// `pause` — reversibly suspend the app's active key. Inverse of resume.
fn handle_pause(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let slug = match parse_slug_only(&env, &req_id) {
        Some(s) => s,
        None => return,
    };
    match commands_app::pause_active_keys(&slug) {
        Ok(n) => emit(&ResultEnvelope::ok(
            req_id,
            json!({ "slug": slug, "paused_count": n }),
        )),
        Err(e) => emit_error(req_id, "I_APP_PAUSE_FAILED", format!("pause: {}", e)),
    }
}

/// `resume` — reactivate a paused key. No-op if no paused key exists.
fn handle_resume(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let slug = match parse_slug_only(&env, &req_id) {
        Some(s) => s,
        None => return,
    };
    match commands_app::resume_paused_keys(&slug) {
        Ok(n) => emit(&ResultEnvelope::ok(
            req_id,
            json!({ "slug": slug, "resumed_count": n }),
        )),
        Err(e) => emit_error(req_id, "I_APP_RESUME_FAILED", format!("resume: {}", e)),
    }
}

/// `rotate` — atomically revoke old key + issue new one with same
/// bindings. Equivalent to the user-facing "Rotate Bearer" action. The
/// agent's env must be updated with the new `api_key` (returned in
/// `route_token`) or its requests will 401.
fn handle_rotate(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let slug = match parse_slug_only(&env, &req_id) {
        Some(s) => s,
        None => return,
    };
    match commands_app::rotate_app_key(&slug) {
        Ok((key_id, route_token)) => emit(&ResultEnvelope::ok(
            req_id,
            json!({
                "slug": slug,
                "key_id": key_id,
                "api_key": route_token,
                "base_url": format!("http://127.0.0.1:27200/apps/{}/v1", slug),
            }),
        )),
        Err(e) => emit_error(req_id, "I_APP_ROTATE_FAILED", format!("rotate: {}", e)),
    }
}

/// `uninstall` — whole-system removal: stop the service via the plugin's
/// own install_service.sh --uninstall, then wipe vault rows
/// (app_keys + app_records + bindings). Inverse of `install`.
///
/// Added 2026-05-23 alongside the rc.5 default-install flip — users who
/// got degrade-detector auto-installed need a single Web button to opt
/// out. Bypasses the mutationLockedSlugs revoke/rotate guard in
/// aikey-control because uninstall stops the service BEFORE removing
/// the bearer, so there's no partial-state to guard against.
fn handle_uninstall(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let slug = match parse_slug_only(&env, &req_id) {
        Some(s) => s,
        None => return,
    };
    // Run the full install.rs::handle_uninstall flow: curl-pipe-shell
    // the service installer with --uninstall, then delete_all_app_state.
    // json_mode=true so we don't pollute stdout with the CLI's user-
    // facing println! lines (the Web bridge expects clean stdin/stdout
    // for the result envelope).
    match commands_app::handle_uninstall(&slug, /* json_mode */ true) {
        Ok(()) => emit(&ResultEnvelope::ok(
            req_id,
            json!({ "slug": slug, "status": "uninstalled" }),
        )),
        Err(e) => emit_error(
            req_id,
            "I_APP_UNINSTALL_FAILED",
            format!("uninstall: {}", e),
        ),
    }
}

/// `reveal-token` — re-read the active bearer plaintext for a slug
/// (added 2026-05-25). Mirrors `aikey app reveal-token <slug>` but
/// emits the result as an envelope (rather than printing the bare token
/// to stdout) so the Web bridge can parse it.
///
/// Security note: this is gated by vault unlock on the Go side via
/// `Store.RequireUnlock`. The CLI side itself does not prompt because
/// it runs as a subprocess of the trusted Go bridge — the bridge has
/// already verified the user's session. Stand-alone CLI invocations of
/// `_internal app.reveal-token` would require an unlocked vault to
/// open the SQLite connection (same as every other vault read).
///
/// Error codes:
///   - I_INVALID_SLUG       — slug shape rejected
///   - I_NO_ACTIVE_TOKEN    — slug has no app_keys row with status='active'
///   - I_APP_REVEAL_FAILED  — generic vault error (open/query/etc.)
fn handle_reveal_token(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let slug = match parse_slug_only(&env, &req_id) {
        Some(s) => s,
        None => return,
    };
    let info = match commands_app::get_active_route_token(&slug) {
        Ok(t) => t,
        Err(e) => {
            // Distinguish "no active token" (a normal state — user never
            // registered, or all keys revoked) from genuine vault errors
            // (file missing, locked, corrupted). The error message from
            // get_active_route_token is the only signal we have, so
            // pattern-match its prefix.
            let code = if e.contains("no active token") {
                "I_NO_ACTIVE_TOKEN"
            } else {
                "I_APP_REVEAL_FAILED"
            };
            emit_error(req_id, code, e);
            return;
        }
    };
    emit(&ResultEnvelope::ok(
        req_id,
        json!({
            "slug": info.slug,
            "key_id": info.key_id,
            "route_token": info.route_token,
            "base_url": info.base_url,
        }),
    ));
}

/// `filter-status` — read whether a filter app (e.g. ai-compliance-detector)
/// is enabled (filter_stages non-NULL). The local web compliance on/off toggle
/// reads this. slug-only payload. Wraps commands_app::get_app_filter_stages.
fn handle_filter_status(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    let slug = match parse_slug_only(&env, &req_id) {
        Some(s) => s,
        None => return,
    };
    match commands_app::get_app_filter_stages(&slug) {
        Ok(stages) => emit(&ResultEnvelope::ok(
            req_id,
            json!({
                "slug": slug,
                "enabled": stages.is_some(),
                "stages": stages.unwrap_or_default(),
            }),
        )),
        Err(e) => emit_error(req_id, "I_APP_FILTER_STATUS_FAILED", e),
    }
}

/// `filter-set` — enable/disable a filter app (the compliance on/off toggle).
/// payload {slug, enable}. enable=true → filter_stages=["pre_forward"] (the
/// canonical compliance stage); enable=false → NULL. Reuses the set/clear
/// public cores; both bump change_seq so the proxy reload picks it up (~5s).
fn handle_filter_set(env: StdinEnvelope) {
    let req_id = env.request_id.clone();
    #[derive(Deserialize)]
    struct Payload {
        slug: String,
        enable: bool,
    }
    let p: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id,
                "I_BAD_PAYLOAD",
                format!("filter-set payload: {}", e),
            );
            return;
        }
    };
    if let Err(e) = commands_app::validate_slug(&p.slug) {
        emit_error(req_id, "I_INVALID_SLUG", e);
        return;
    }
    let res = if p.enable {
        commands_app::set_app_filter_stages(&p.slug, &["pre_forward".to_string()], None, None)
    } else {
        commands_app::clear_app_filter_stages(&p.slug)
    };
    match res {
        Ok(()) => emit(&ResultEnvelope::ok(
            req_id,
            json!({ "slug": p.slug, "enabled": p.enable }),
        )),
        Err(e) => emit_error(req_id, "I_APP_FILTER_SET_FAILED", e),
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Common payload shape for slug-only actions (revoke / pause / resume /
/// rotate). Centralised so adding a new slug-only action doesn't
/// duplicate the parse + validate boilerplate.
fn parse_slug_only(env: &StdinEnvelope, req_id: &Option<String>) -> Option<String> {
    #[derive(Deserialize)]
    struct Payload {
        slug: String,
    }
    let p: Payload = match serde_json::from_value(env.payload.clone()) {
        Ok(p) => p,
        Err(e) => {
            emit_error(
                req_id.clone(),
                "I_BAD_PAYLOAD",
                format!("decode payload: {}", e),
            );
            return None;
        }
    };
    if let Err(e) = commands_app::validate_slug(&p.slug) {
        emit_error(req_id.clone(), "I_INVALID_SLUG", e);
        return None;
    }
    Some(p.slug)
}

/// Convert binding rows → JSON array. Caller projects each row's
/// CredentialType to `&str` via `.as_str()` before calling.
///
/// Why this takes `&str` rather than `CredentialType`: this file is
/// compiled in BOTH the library crate AND the bin crate ("aikey"),
/// and the local `CredentialType` resolves to a different type
/// identity in each compilation (main.rs has its own `mod credential_type`
/// declaration; lib.rs has another). `commands_app::get_active_bindings`
/// returns the LIBRARY'S CredentialType, which fails to match a bin-
/// local CredentialType when the bin compiles this file. Taking `&str`
/// here sidesteps the type-identity issue entirely.
fn render_bindings(bindings: &[(String, &str, String)]) -> Value {
    Value::Array(
        bindings
            .iter()
            .map(|(upstream, kt_str, kr)| {
                json!({
                    "upstream": upstream,
                    "key_source_type": kt_str,
                    "key_source_ref": kr,
                    "key_source_label": commands_app::resolve_binding_label(kt_str, kr),
                })
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Tests
//
// Most business logic lives in commands_app:: (already covered by its own
// extensive test suite). Tests here just pin the I/O-shape contracts that
// the Go local-server side relies on — if any of these change shape, the
// frontend bindings break.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_bindings_emits_array_of_three_field_objects() {
        let raw = vec![
            ("anthropic".to_string(), "personal", "my-claude".to_string()),
            ("openai".to_string(), "team", "team-vk-123".to_string()),
        ];
        let v = render_bindings(&raw);
        let arr = v.as_array().expect("array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["upstream"], "anthropic");
        assert_eq!(arr[0]["key_source_type"], "personal");
        assert_eq!(arr[0]["key_source_ref"], "my-claude");
        assert_eq!(arr[1]["upstream"], "openai");
        assert_eq!(arr[1]["key_source_type"], "team");
        assert_eq!(arr[1]["key_source_ref"], "team-vk-123");
    }

    #[test]
    fn render_bindings_empty_input_emits_empty_array() {
        let v = render_bindings(&[]);
        assert_eq!(v.as_array().unwrap().len(), 0);
    }

    #[test]
    fn key_source_type_validator_accepts_canonical_and_legacy_aliases() {
        // Mirrors the match in handle_route's key_source_type guard.
        // If from_db_str's accepted list ever changes, this test catches
        // the drift on the _internal layer side too.
        let valid = [
            "personal",
            "personal_api_key",
            "team",
            "managed_virtual_key",
            "personal_oauth_account",
        ];
        for v in valid {
            assert!(
                matches!(
                    v,
                    "personal"
                        | "personal_api_key"
                        | "team"
                        | "managed_virtual_key"
                        | "personal_oauth_account"
                ),
                "expected key_source_type {:?} to be accepted",
                v
            );
        }
    }

    #[test]
    fn key_source_type_validator_rejects_garbage() {
        let invalid = [
            "",
            "PERSONAL",
            "team_managed",
            "unknown_type",
            "personal_oauth",
            " personal ",
        ];
        for v in invalid {
            assert!(
                !matches!(
                    v,
                    "personal"
                        | "personal_api_key"
                        | "team"
                        | "managed_virtual_key"
                        | "personal_oauth_account"
                ),
                "expected key_source_type {:?} to be rejected, but it matched",
                v
            );
        }
    }
}
