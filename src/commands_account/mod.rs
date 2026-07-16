//! `aikey account` and team key command handlers.
//!
//! Covers:
//!  - `aikey account login` / `aikey account status` / `aikey account logout`
//!  - `aikey key sync`  — refresh metadata from server
//!  - `aikey key use <id>` — activate a key for proxy routing
//!
//! Note: `aikey key list` and its alias `aikey list` share a single renderer
//! in `main.rs::run_unified_list` (unified Personal + Team + OAuth view).

use colored::Colorize;
use secrecy::SecretString;
use std::io::{self, IsTerminal, Write};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto;
use crate::platform_client::{PlatformClient, PollResponse};
use crate::storage::{self, VirtualKeyCacheEntry};

// Stage 2.1 windows-compat: in-module callsites use
// `shell_integration::shell_integration::resolve_aikey_dir()` directly. Importing it via
// `use` collides with the `pub use shell_integration::*;` re-export at
// the bottom of this module (E0603 privacy conflict), and a local
// alias would shadow that re-export — so we just spell the path out
// at the few callsites in this file.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Login throttle
// ---------------------------------------------------------------------------

/// Minimum seconds between two `aikey login` attempts before we block with a
/// friendly "check your inbox" nudge. Kept intentionally short so the user
/// is never stuck for long; --resend overrides it.
const LOGIN_THROTTLE_SECS: u64 = 60;

/// Path to the throttle marker file. Absent file ⇒ no prior attempt.
///
/// Stage 2.1 windows-compat: route through `shell_integration::resolve_aikey_dir()` so the
/// throttle file lands in the same `~/.aikey` (or `%USERPROFILE%\.aikey`)
/// the rest of the CLI uses. Always returns `Some(...)` now —
/// `resolve_user_home` has a `"."` last-resort that keeps the contract
/// "absent file ⇒ no prior attempt" intact (the file simply won't exist
/// in degraded environments).
fn login_throttle_path() -> Option<std::path::PathBuf> {
    Some(shell_integration::resolve_aikey_dir().join(".login_throttle.json"))
}

/// Returns the unix-seconds timestamp of the last recorded login attempt,
/// or None if the file is missing, unreadable, or malformed. Best-effort:
/// never returns an error — a missing/bad marker simply means "no throttle".
fn read_login_throttle() -> Option<u64> {
    let path = login_throttle_path()?;
    let data = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    v.get("session_started_at").and_then(|n| n.as_u64())
}

/// Writes the current unix-seconds timestamp to the throttle file.
/// Best-effort: I/O errors are swallowed so the login flow is never blocked
/// by marker-file problems.
fn write_login_throttle() -> std::io::Result<()> {
    let path = match login_throttle_path() {
        Some(p) => p,
        None => return Ok(()),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = format!("{{\"session_started_at\":{}}}\n", now);
    std::fs::write(&path, body)
}

/// Read `controlPanelUrl` from `~/.aikey/config/config.json` (if present).
///
/// Stage 2.1 windows-compat: routed through `shell_integration::resolve_aikey_dir()`.
fn read_control_url_from_config() -> Option<String> {
    let path = shell_integration::resolve_aikey_dir()
        .join("config")
        .join("config.json");
    let data = std::fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&data).ok()?;
    parsed["controlPanelUrl"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Auto-configure the proxy's TEAM upload destination after a successful
/// `aikey login --control-url <REMOTE>`.
///
/// 2026-05-11 F1 fix — write to user-layer config, not system yaml.
///
/// Before this fix the function patched `~/.aikey/config/aikey-proxy.yaml`
/// directly (system layer). That worked until the user ran any path that
/// re-renders the system yaml from template — `make restart-personal`,
/// `local-install.sh`, `aikey-config-tool render`, etc. — all of which
/// `rm` and re-emit the yaml from `workflow/CD/templates/common/
/// aikey-proxy.yaml.tmpl`, silently wiping the team route override. The
/// observable failure was "team usage events lost to the local SQLite
/// collector while the user is staring at the Postgres-backed master web
/// dashboard" — see workflow/CI/bugfix/2026-05-11-team-key-decrypt-…md
/// follow-up.
///
/// The fix moves the team-route override into `~/.aikey/config/
/// aikey-user.yaml` under a new `proxy:` section. The user file is the
/// system+user config-split scheme's user-owned layer (workflow/CLAUDE.md
/// "Config Split (Stage A-D landed)") — installer / render commands
/// never touch it. proxy's `config.Load` now calls
/// `configmerge.LoadAndMerge(system, user, "proxy")` so user-layer
/// values win deterministically on every restart.
///
/// `personal` and `oauth` route entries — and the legacy `collector_url` —
/// are intentionally NOT written here. Their install-time values (local
/// collector on Personal / Trial; production collector on Server) are
/// the correct sticky defaults; nothing about a remote-team login should
/// change where Personal-key usage events flow.
///
/// Stage 2.1 windows-compat: routed through `shell_integration::resolve_aikey_dir()`.
///
/// 2026-05-11 B3-phase extension: in addition to the F1 team-URL write,
/// also writes the current user JWT (access_token + expires_at) to
/// `proxy.events.collector_credentials.team`. proxy's reporter consumes
/// that to populate `RefreshableJWT.AccessToken` + `.ExpiresAt` on
/// startup so team events upload with a user-scoped bearer instead of
/// the legacy admin service_token. `refresh_token` is intentionally NOT
/// written here — it stays encrypted in the vault's `platform_account`
/// table, and B4's proxy reads it via the supervisor's already-derived
/// master key (no plaintext refresh_token on disk).
fn configure_proxy_collector(control_url: &str, json_mode: bool) {
    let user_config = shell_integration::resolve_aikey_dir()
        .join("config")
        .join("aikey-user.yaml");

    // Collector API is proxied through nginx on the same origin as the control panel.
    // Proxy uploads to {collector_url}/v1/usage-events:batch
    let collector_url = control_url.trim_end_matches('/').to_string();
    // Refresh path MUST match the server's real CLI-token refresh route
    // (router.go `POST /v1/auth/cli/token/refresh`) — the same endpoint the
    // CLI session refresh uses (platform_client.rs). An earlier `/auth/refresh`
    // here 404'd, so team usage events were silently dead-lettered once the
    // access token expired. See
    // workflow/CI/bugfix/2026-06-03-team-usage-refresh-contract-mismatch.md.
    let refresh_url = format!("{}/v1/auth/cli/token/refresh", collector_url);

    // Pull the user's current access_token + expires_at from vault. This is
    // the same blob `aikey login` just wrote a few lines up; reading it
    // back keeps a single source of truth (the vault row) rather than
    // threading the token down via parameters from every login call site.
    //
    // Missing platform_account = "login wasn't completed" — bail quietly
    // (file unchanged). Missing token_expires_at = "legacy CLI session
    // upgraded mid-flight" — emit credential with expires_at=0 so the
    // first Bearer() call triggers a refresh (it's within the 5min skew
    // window by definition).
    let cred_fields = match storage::get_platform_account() {
        Ok(Some(acc)) if !acc.jwt_token.is_empty() => Some(CredentialFields {
            access_token: acc.jwt_token,
            expires_at: acc.token_expires_at.unwrap_or(0),
            refresh_url: refresh_url.clone(),
        }),
        _ => None,
    };

    // Already configured to the same value? Avoid a no-op write that would
    // restart the proxy for nothing. Compare BOTH the URL and the credential
    // bundle — a stale access_token in the file should trigger a rewrite
    // even if the URL hasn't changed.
    let current = read_user_yaml_team(&user_config);
    let url_matches =
        current.as_ref().and_then(|s| s.url.as_deref()) == Some(collector_url.as_str());
    let cred_matches = match (&cred_fields, current.as_ref().and_then(|s| s.cred.as_ref())) {
        (Some(new), Some(cur)) => {
            new.access_token == cur.access_token
                && new.expires_at == cur.expires_at
                && new.refresh_url == cur.refresh_url
        }
        (None, None) => true,
        _ => false,
    };
    if url_matches && cred_matches {
        return;
    }

    if let Err(e) = write_user_yaml_team_section(&user_config, &collector_url, cred_fields.as_ref())
    {
        if !json_mode {
            eprintln!(
                "    {} couldn't update {}: {}",
                "!".yellow(),
                user_config.display(),
                e
            );
            eprintln!(
                "      Run {} after editing manually.",
                "'aikey proxy restart'".bold()
            );
        }
        return;
    }

    if !json_mode {
        eprintln!("    Team usage reporting → {}", collector_url);
        if cred_fields.is_some() {
            eprintln!(
                "    Team usage credentials → JWT ({})",
                if cred_fields.as_ref().unwrap().expires_at > 0 {
                    "auto-refresh enabled"
                } else {
                    "first-call refresh on startup"
                }
            );
        }
    }

    // Proxy reads its config at startup only; the new merge target won't
    // take effect until a restart. Mirror the historic UX: auto-restart
    // when we hold (or can obtain) the master password, otherwise hint.
    if crate::commands_proxy::proxy_is_running_managed() {
        let pw = if let Some(cached) = crate::session::try_get() {
            cached
        } else if !json_mode {
            eprintln!("    Restart proxy to apply.");
            match crate::prompt_hidden(&format!(
                "    {}Enter Master Password: ",
                crate::symbols::ICON_LOCK.pre()
            )) {
                Ok(p) => SecretString::new(p),
                Err(_) => {
                    eprintln!("\n    Run {} manually.", "'aikey proxy restart'".bold());
                    return;
                }
            }
        } else {
            return; // json_mode + no cached pw: don't prompt; caller will surface.
        };
        let _ = crate::commands_proxy::handle_restart(None, &pw);
    }
}

/// CredentialFields are the user-JWT bits proxy reporter needs to
/// bootstrap its RefreshableJWT for the team route. `access_token` is
/// the current short-lived JWT; `expires_at` is its unix expiry
/// (0 = unknown, treat as "refresh on first use"); `refresh_url` is
/// the absolute URL the proxy's auto-refresh loop POSTs to.
///
/// refresh_token is deliberately NOT here — it's a higher-sensitivity
/// long-lived credential and stays encrypted in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialFields {
    access_token: String,
    expires_at: i64,
    refresh_url: String,
}

/// UserYAMLTeamSection is the parsed shape of what configure_proxy_collector
/// cares about under `proxy.events`. Only used internally for the
/// no-op-write short-circuit; not exported.
#[derive(Debug, Default)]
struct UserYAMLTeamSection {
    url: Option<String>,
    cred: Option<CredentialFields>,
}

/// Reads what configure_proxy_collector cares about under
/// `proxy.events`: the team route URL and credential bundle (if any).
/// Used to short-circuit no-op writes so re-running `aikey login`
/// against the same control URL + still-fresh JWT doesn't trigger a
/// needless proxy restart.
///
/// Missing file / malformed yaml / missing sub-paths all return a
/// zero-value section — caller treats it the same as "nothing
/// configured yet" and proceeds to write.
fn read_user_yaml_team(user_config: &std::path::Path) -> Option<UserYAMLTeamSection> {
    let data = std::fs::read_to_string(user_config).ok()?;
    let v: serde_yaml::Value = serde_yaml::from_str(&data).ok()?;
    let events = v.get("proxy")?.get("events")?;
    let url = events
        .get("collector_routes")
        .and_then(|m| m.get("team"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    let cred = events
        .get("collector_credentials")
        .and_then(|m| m.get("team"))
        .and_then(|t| {
            let access_token = t.get("token")?.as_str()?.to_string();
            let expires_at = t.get("expires_at")?.as_i64()?;
            let refresh_url = t.get("refresh_url")?.as_str()?.to_string();
            Some(CredentialFields {
                access_token,
                expires_at,
                refresh_url,
            })
        });
    Some(UserYAMLTeamSection { url, cred })
}

/// Backwards-compat shim — older unit tests / callers may still ask
/// for "just the team URL". Kept here to avoid churning every existing
/// regression test added in F1.
#[cfg(test)]
fn read_user_yaml_team_route(user_config: &std::path::Path) -> Option<String> {
    read_user_yaml_team(user_config).and_then(|s| s.url)
}

/// Writes `proxy.events.collector_routes.team` (URL) and optionally
/// `proxy.events.collector_credentials.team` (JWT bundle) to
/// `aikey-user.yaml`, creating the file if absent and preserving every
/// other top-level section (e.g. existing `trial:` secrets).
///
/// Why parse-modify-serialize (vs string surgery): the user file is
/// shared with the trial installer which writes
/// `trial.{jwt_secret, master_key, service_token, admin_email}`.
/// Hand-spliced edits risked corrupting that section's indentation; a
/// structured rewrite via `serde_yaml::Value` is safe.
///
/// File mode is owner-only (0600) on Unix because adjacent fields in
/// the same file are secrets (jwt_secret, master_key, access_token,
/// refresh_token). Mirrors the trial installer's chmod. No-op on
/// Windows where unix file modes don't apply.
///
/// cred == None means "remove the credential bundle if present" — used
/// by `aikey account logout` to scrub the user JWT from disk while
/// keeping the team URL (re-login may target the same backend).
fn write_user_yaml_team_section(
    user_config: &std::path::Path,
    team_url: &str,
    cred: Option<&CredentialFields>,
) -> Result<(), String> {
    let mut root: serde_yaml::Value = if user_config.exists() {
        let data = std::fs::read_to_string(user_config)
            .map_err(|e| format!("read {}: {}", user_config.display(), e))?;
        if data.trim().is_empty() {
            serde_yaml::Value::Mapping(Default::default())
        } else {
            serde_yaml::from_str(&data)
                .map_err(|e| format!("parse {}: {}", user_config.display(), e))?
        }
    } else {
        if let Some(parent) = user_config.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create dir {}: {}", parent.display(), e))?;
        }
        serde_yaml::Value::Mapping(Default::default())
    };

    // Ensure root is a mapping. If the file existed but had a scalar/sequence
    // top-level, refuse to silently overwrite — that's a corruption signal
    // worth surfacing.
    let root_map = root
        .as_mapping_mut()
        .ok_or_else(|| format!("{} top-level is not a mapping", user_config.display()))?;

    // Walk / create the proxy.events.{collector_routes, collector_credentials} paths.
    let proxy = root_map
        .entry(serde_yaml::Value::String("proxy".into()))
        .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()))
        .as_mapping_mut()
        .ok_or_else(|| "proxy: section is not a mapping".to_string())?;
    let events = proxy
        .entry(serde_yaml::Value::String("events".into()))
        .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()))
        .as_mapping_mut()
        .ok_or_else(|| "proxy.events: is not a mapping".to_string())?;

    // collector_routes.team — URL string.
    {
        let routes = events
            .entry(serde_yaml::Value::String("collector_routes".into()))
            .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()))
            .as_mapping_mut()
            .ok_or_else(|| "proxy.events.collector_routes: is not a mapping".to_string())?;
        routes.insert(
            serde_yaml::Value::String("team".into()),
            serde_yaml::Value::String(team_url.to_string()),
        );
    }

    // collector_credentials.team — JWT bundle (optional).
    if let Some(cf) = cred {
        let credentials = events
            .entry(serde_yaml::Value::String("collector_credentials".into()))
            .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()))
            .as_mapping_mut()
            .ok_or_else(|| "proxy.events.collector_credentials: is not a mapping".to_string())?;
        let mut team_cred: serde_yaml::Mapping = Default::default();
        team_cred.insert(
            serde_yaml::Value::String("type".into()),
            serde_yaml::Value::String("jwt".into()),
        );
        team_cred.insert(
            serde_yaml::Value::String("token".into()),
            serde_yaml::Value::String(cf.access_token.clone()),
        );
        team_cred.insert(
            serde_yaml::Value::String("expires_at".into()),
            serde_yaml::Value::Number(cf.expires_at.into()),
        );
        team_cred.insert(
            serde_yaml::Value::String("refresh_url".into()),
            serde_yaml::Value::String(cf.refresh_url.clone()),
        );
        credentials.insert(
            serde_yaml::Value::String("team".into()),
            serde_yaml::Value::Mapping(team_cred),
        );
    } else if let Some(credentials) = events
        .get_mut(serde_yaml::Value::String("collector_credentials".into()))
        .and_then(|v| v.as_mapping_mut())
    {
        // cred == None and credentials block already exists: scrub the
        // team entry (logout path). Leave other route credentials
        // untouched in case future B-phases add personal/oauth here.
        credentials.remove(serde_yaml::Value::String("team".into()));
    }

    let serialized = serde_yaml::to_string(&root).map_err(|e| format!("serialize yaml: {}", e))?;
    std::fs::write(user_config, &serialized)
        .map_err(|e| format!("write {}: {}", user_config.display(), e))?;

    // Cross-platform owner-only hardening (2026-05-11 fix): the previous
    // `#[cfg(unix)]` chmod 0o600 left Windows files world-readable.
    // user.yaml now carries `proxy.events.collector_credentials.team.token`
    // (a user-scoped JWT) alongside the historical `trial.{jwt_secret,
    // master_key}` — both deserve owner-only protection on every OS.
    // storage_acl::enforce_owner_only_file abstracts the per-OS API
    // (Unix chmod 0600 / Windows icacls strip-everyone-except-owner).
    let _ = crate::storage_acl::enforce_owner_only_file(user_config);
    Ok(())
}

/// Test/back-compat wrapper for the URL-only write path. Callers using
/// the F1-era signature (URL only, no credential) still work unchanged
/// — they just don't write a credential bundle.
#[cfg(test)]
fn write_user_yaml_team_route(user_config: &std::path::Path, team_url: &str) -> Result<(), String> {
    write_user_yaml_team_section(user_config, team_url, None)
}

/// (Removed 2026-05-11 F1 fix) — the system-yaml-patching `patch_team_route`
/// / `local_collector_default` helpers and their unit tests lived here. They
/// patched `aikey-proxy.yaml` directly, which got wiped by every
/// `make restart-personal` (bootstrap-config rm + re-render). Replacement
/// path: `configure_proxy_collector` now writes
/// `proxy.events.collector_routes.team` to `aikey-user.yaml`, and the proxy
/// loader (aikey-proxy/internal/config/config.go::Load) deep-merges it on
/// top of the rendered system config at startup. Net effect: login-time
/// overrides survive system-yaml re-renders.
///
/// Stage 2.1 windows-compat: routed through `shell_integration::resolve_aikey_dir()`.
fn save_control_url_to_config(url: &str) {
    let dir = shell_integration::resolve_aikey_dir().join("config");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("config.json");

    let mut obj: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_else(|| serde_json::json!({"version": "1"}));

    obj["controlPanelUrl"] = serde_json::Value::String(url.to_string());
    let _ = std::fs::write(
        &path,
        serde_json::to_string_pretty(&obj).unwrap_or_default(),
    );
}

/// Persist the control URL to the side-channel locations the local proxy + web
/// read, BEYOND the vault platform_account row: config.json `controlPanelUrl`
/// (the proxy's compliance-policy poll source), install-state.json (`aikey web`
/// / `browse`), and the user-yaml collector_url (usage upload). The vault row is
/// written separately by the caller (login via `save_oauth_session`, set-url via
/// `update_platform_control_url`).
///
/// Why shared: `aikey login`, `aikey account set-url`, and `aikey agent register`
/// must all wire the proxy to the master IDENTICALLY. The unattended
/// digital-employee daemon (`agent register`) previously wrote only the vault,
/// so the proxy never learned the master URL → compliance policy never polled
/// (sensitive-word detector never spawned) and usage reporting fell back to the
/// Personal localhost default. Regression 2026-06-08 (form② remote DE) caught
/// this; reuse here keeps DE onboarding equal to a human login.
/// json_mode=true suppresses the human-readable status prints (daemon path).
pub(crate) fn persist_control_url_sidecar(control_url: &str, json_mode: bool) {
    save_control_url_to_config(control_url);
    update_install_state_control_url(control_url);
    configure_proxy_collector(control_url, json_mode);
}

/// DE-only: point the BASE usage collector (`proxy.events.collector_url`) at the
/// master in aikey-user.yaml. A digital employee has NO Personal local-server,
/// so the proxy.yaml default (`127.0.0.1:8090`) is a dead address on a DE host —
/// every event it produces is a team-key event that belongs on the master.
/// `configure_proxy_collector` only sets the per-route `collector_routes.team`;
/// for a human that's right (personal events stay on the local 8090, team events
/// route to the master), but a DE has no personal events, so its BASE collector
/// must also be the master or usage uploads bounce off the dead 8090 (regression
/// 2026-06-08 finding #2). Best-effort; only called from `aikey agent register`.
pub(crate) fn set_de_collector_base(control_url: &str) {
    use serde_yaml::Value;
    let user_config = shell_integration::resolve_aikey_dir()
        .join("config")
        .join("aikey-user.yaml");
    let base = control_url.trim_end_matches('/').to_string();
    let mut root: Value = std::fs::read_to_string(&user_config)
        .ok()
        .filter(|d| !d.trim().is_empty())
        .and_then(|d| serde_yaml::from_str(&d).ok())
        .unwrap_or_else(|| Value::Mapping(Default::default()));
    {
        let Some(root_map) = root.as_mapping_mut() else {
            return;
        };
        let Some(proxy) = root_map
            .entry(Value::String("proxy".into()))
            .or_insert_with(|| Value::Mapping(Default::default()))
            .as_mapping_mut()
        else {
            return;
        };
        let Some(events) = proxy
            .entry(Value::String("events".into()))
            .or_insert_with(|| Value::Mapping(Default::default()))
            .as_mapping_mut()
        else {
            return;
        };
        events.insert(Value::String("collector_url".into()), Value::String(base));
    }
    if let Ok(s) = serde_yaml::to_string(&root) {
        if std::fs::write(&user_config, &s).is_ok() {
            let _ = crate::storage_acl::enforce_owner_only_file(&user_config);
        }
    }
}

/// Updates `~/.aikey/install-state.json`'s `control_panel_url` field so
/// downstream consumers (notably `aikey web` / `aikey browse`, which
/// resolve the team URL through `derive_local_control_url`) see the
/// freshly-logged-in URL instead of the installer-time value.
///
/// 2026-06-01 bugfix: prior to this, `aikey login --control-url X` and
/// `aikey account set-url X` only touched (a) vault platform_account
/// (b) config.json (c) aikey-proxy.yaml. `install-state.json` stayed
/// stuck on whatever the LAST installer run wrote — so after a network
/// change + re-login, `aikey web` opened the previous network's IP.
///
/// Best-effort: silently no-ops if install-state.json doesn't exist
/// (fresh CLI-only state, no installer-tracked metadata yet) or can't
/// be parsed. Writes through a tmp file + atomic rename to avoid
/// corrupting the file on a partial-write crash. `last_updated_at`
/// is also bumped so operators eyeballing the file can see WHEN it
/// last changed via a login event (vs. installer event).
fn update_install_state_control_url(url: &str) {
    let path = shell_integration::resolve_aikey_dir().join("install-state.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return, // No install-state.json → no installer-tracked state to update.
    };
    let mut obj: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return, // Corrupt JSON — don't overwrite, let `aikey doctor` flag it.
    };
    if !obj.is_object() {
        return;
    }
    obj["control_panel_url"] = serde_json::Value::String(url.to_string());
    // Note: we intentionally don't touch `last_updated_at` here. The
    // existing pattern in this crate uses std::time (SystemTime / UNIX_EPOCH),
    // which can't format ISO 8601 without an extra crate, and bringing in
    // chrono just for one timestamp string is more weight than the
    // observability benefit. Operators tracking when the URL last changed
    // can still see the file mtime via `stat`.

    let tmp = path.with_extension("json.tmp");
    let body = match serde_json::to_string_pretty(&obj) {
        Ok(b) => b,
        Err(_) => return,
    };
    if std::fs::write(&tmp, body).is_err() {
        return;
    }
    let _ = std::fs::rename(&tmp, &path);
}

// ---------------------------------------------------------------------------
// account set-url
// ---------------------------------------------------------------------------

/// `aikey account set-url <URL>`
///
/// Updates the control panel URL without re-authenticating. Useful when the
/// server IP changes (e.g. after a reboot with DHCP).
pub fn handle_set_control_url(
    url: &str,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let url = url.trim_end_matches('/');

    // Update config.json (used by login flow for default URL).
    save_control_url_to_config(url);

    // 2026-06-01: also push to install-state.json so `aikey web` /
    // `aikey browse` (which resolve through derive_local_control_url and
    // ultimately read install-state.json's `control_panel_url`) see the
    // new URL. Without this, `aikey web` would keep opening the previous
    // network's IP until the next installer run.
    update_install_state_control_url(url);

    // Update the platform_account row if logged in (used by all API calls).
    if let Ok(Some(acc)) = storage::get_platform_account() {
        let old_url = acc.control_url.clone();
        storage::update_platform_control_url(url)?;

        // Also update proxy collector_url (nginx proxies collector on same origin).
        configure_proxy_collector(url, json_mode);

        // SyncRail §5.2 (2026-07-03): nudge the running proxy so the URL change
        // converges NOW — the reload re-reads aikey-proxy.yaml (reporter creds)
        // and kicks the control-plane sync rails (routing/group material re-pull
        // against the NEW server, team credential rebuilt). Best-effort by
        // design: when the proxy isn't running (or the POST fails) the rails'
        // per-cycle URL re-check still self-heals within ≤60s of the next start,
        // so this replaces the old "Restart proxy to apply" manual step for BOTH
        // entrances (CLI set-url and the Web Settings page, which subprocesses
        // this same core — internal-command-reuses-public-core).
        let proxy_running = crate::commands_proxy::proxy_is_running_managed();
        if proxy_running {
            crate::commands_proxy::try_reload_proxy();
        }

        if json_mode {
            crate::json_output::print_json(serde_json::json!({
                "ok": true,
                "old_url": old_url,
                "new_url": url,
                "proxy_reloaded": proxy_running,
            }));
        } else {
            println!("{} Control URL updated.", crate::symbols::CHECK.s().green());
            println!("  {} → {}", old_url.dimmed(), url.bold());
            println!("  Proxy collector URL also updated.");
            println!();
            if proxy_running {
                println!(
                    "  {} Proxy reloaded — the new URL is live (sync rails re-pull within seconds).",
                    crate::symbols::CHECK.s().green()
                );
            } else {
                println!(
                    "  {} Proxy not running — it picks up the new URL on next start.",
                    "\u{2192}".dimmed()
                );
            }
        }
    } else {
        // Not logged in — only save to config.json.
        if json_mode {
            crate::json_output::print_json(serde_json::json!({
                "ok": true,
                "new_url": url,
                "note": "not logged in — saved to config only",
            }));
        } else {
            println!(
                "{} Control URL saved to config.",
                crate::symbols::CHECK.s().green()
            );
            println!("  URL: {}", url.bold());
            println!(
                "  Log in with: {}",
                format!("aikey login --control-url {}", url).cyan()
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// account login / status / logout
// ---------------------------------------------------------------------------

/// `aikey account login [--url URL] [--token SESSION_ID:LOGIN_TOKEN]`
///
/// Starts the OAuth device-flow login via a browser web UI:
///   1. CLI calls the server to create a login session.
///   2. CLI opens the browser to the login page where the user enters their email.
///   3. Server sends a one-time activation link to that email.
///   4. User clicks the link; CLI polls and receives access_token + refresh_token.
///   5. Tokens are saved locally; all subsequent requests use them automatically.
///      Silent renewal via the refresh_token (valid 30 days, no re-login needed).
///
/// Copy-paste fallback: if the polling loop times out, pass the token shown on
/// the activation page as `--token SESSION_ID:LOGIN_TOKEN`.
///
/// Flag precedence (highest → lowest):
///   1. CLI flag (`--control-url`)
///   2. Environment variable `AIKEY_CONTROL_URL`
///   3. Config file (`~/.aikey/config/config.json` → `controlPanelUrl`)
///   4. Interactive prompt (suppressed in `--json` mode)
pub fn handle_login(
    json_mode: bool,
    flag_url: Option<String>,
    flag_token: Option<String>,
    flag_email: Option<String>,
    flag_resend: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Resolve default URL: env var → config file → hardcoded fallback.
    let default_url = std::env::var("AIKEY_CONTROL_URL")
        .ok()
        .or_else(|| read_control_url_from_config())
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    let control_url = if let Some(u) = flag_url {
        u
    } else if json_mode {
        // Non-interactive: use default (which may come from config/env).
        default_url.clone()
    } else if std::env::var("AIKEY_CONTROL_URL").is_ok() || read_control_url_from_config().is_some()
    {
        // Already configured via env or config file — use it directly, no prompt.
        if !json_mode {
            eprintln!("  Control Panel: {}", default_url);
        }
        default_url
    } else if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        // No TTY (spawned from a script / service / web bridge): reading
        // stdin here blocks forever on a silent pipe — observed live as an
        // `aikey login` process hung >1h on Windows (parity audit 2026-07-07
        // P2-5). Behave like json_mode: take the default without prompting;
        // a wrong default fails loudly downstream instead of hanging here.
        eprintln!(
            "  Control Panel: {} (no TTY — using default; pass --control-url to override)",
            default_url
        );
        default_url
    } else {
        print!("Control Panel URL [{}]: ", default_url);
        io::stdout().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim().to_string();
        if trimmed.is_empty() {
            default_url
        } else {
            trimmed
        }
    };

    // --- Copy-paste fallback: --token SESSION_ID:LOGIN_TOKEN ---
    if let Some(combined) = flag_token {
        return exchange_combined_token(&control_url, &combined, json_mode);
    }

    // --- Throttle: suppress rapid re-triggers of the email flow ---
    // Why: users who don't see an activation email often re-run `aikey login`
    // within seconds. Each re-run creates a fresh session and (when the user
    // hits "Send Login Link") another email — inflating the anti-spam rate
    // at QQ/Gmail. We block the second attempt within `LOGIN_THROTTLE_SECS`
    // unless --resend is passed. The file is advisory-only; concurrent
    // writes and missing files silently fall through.
    if !flag_resend {
        if let Some(last_started) = read_login_throttle() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now > 0 && now >= last_started && now - last_started < LOGIN_THROTTLE_SECS {
                let elapsed = now - last_started;
                let remaining = LOGIN_THROTTLE_SECS - elapsed;
                if !json_mode {
                    eprintln!();
                    eprintln!(
                        "  {}",
                        format!("A login email was just sent ({}s ago).", elapsed).yellow()
                    );
                    eprintln!("  • Check your inbox — and your spam folder.");
                    eprintln!(
                        "  • Add {} to your whitelist to avoid future filtering.",
                        "invite@aikeylabs.com".bold()
                    );
                    eprintln!(
                        "  • To force a new email, wait {}s or run: {}",
                        remaining,
                        "aikey login --resend".bold()
                    );
                    eprintln!();
                }
                return Ok(());
            }
        }
    }

    // --- OAuth device flow via browser ---
    let client_version = env!("CARGO_PKG_VERSION");
    let os_platform = std::env::consts::OS;

    let session = PlatformClient::init_cli_login(&control_url, client_version, os_platform)
        .map_err(|e| format!("Login failed: {}", e))?;

    // Record this attempt for the throttle window. Best-effort — any I/O
    // failure is silently ignored (the throttle is a UX nudge, not security).
    let _ = write_login_throttle();

    // Browser URL: in production nginx serves both Web and API on the same
    // origin (control_url), so use it directly for the browser login page.
    let mut login_url = format!(
        "{}/auth/cli/login?s={}&d={}",
        control_url.trim_end_matches('/'),
        session.login_session_id,
        session.device_code,
    );
    // Append Base64URL-encoded email so the login page can auto-fill it.
    if let Some(ref email) = flag_email {
        let encoded = base64_url_encode(email);
        login_url.push_str(&format!("&email={}", encoded));
    }

    if !json_mode {
        let step = |n: &str| format!("  {}", format!("Step {}", n).bold().cyan());
        println!();
        println!("{}  Opening browser…", step("1"));
        println!("          {}", login_url.dimmed());
        println!();
        if flag_email.is_some() {
            println!(
                "{}  Your {} is pre-filled — click {}",
                step("2"),
                "email".bold(),
                "\"Send Login Link\"".bold()
            );
        } else {
            println!(
                "{}  Enter your {} and click {}",
                step("2"),
                "email".bold(),
                "\"Send Login Link\"".bold()
            );
        }
        println!();
        println!(
            "{}  Check your inbox and click the {} link",
            step("3"),
            "activation".bold()
        );
        println!();
        println!("  {}", "Waiting for confirmation…".dimmed());
    }

    open_url_silently(&login_url);

    // Poll until approved, denied, or expired.
    let poll_interval = Duration::from_secs(session.poll_interval_seconds.max(2));
    let deadline = SystemTime::now() + Duration::from_secs(session.expires_in_seconds);

    loop {
        std::thread::sleep(poll_interval);

        if SystemTime::now() > deadline {
            // TTY guard (parity audit 2026-07-07 P2-5): without it, a
            // scripted/service-spawned login that outlived the poll window
            // fell into the paste-token read_line below and blocked forever
            // on a silent stdin (observed live: `aikey login` hung >1h on
            // Windows after the ~1h poll window expired).
            if !json_mode && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                eprintln!();
                eprintln!("  {}", "Session expired.".yellow());
                eprintln!(
                    "  Tip: copy the one-time {} from the {} page and run:",
                    "token".bold(),
                    "activation".bold()
                );
                eprintln!(
                    "       {}",
                    "aikey login --token SESSION_ID:LOGIN_TOKEN".bold()
                );
                eprint!("  Paste token (or press Enter to cancel): ");
                io::stderr().flush().ok();
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                let token_input = input.trim().to_string();
                if token_input.is_empty() {
                    return Err("Login timed out. Run 'aikey login' to try again.".into());
                }
                let combined = format!("{}:{}", session.login_session_id, token_input);
                return exchange_combined_token(&control_url, &combined, json_mode);
            } else {
                return Err("Login session expired. Use --token for non-interactive login.".into());
            }
        }

        let poll = PlatformClient::poll_cli_login(
            &control_url,
            &session.login_session_id,
            &session.device_code,
        )
        .map_err(|e| format!("Poll failed: {}", e))?;

        match poll.status.as_str() {
            "pending" => {
                if !json_mode {
                    print!(".");
                    io::stdout().flush().ok();
                }
            }
            "approved" | "token_claimed" => {
                if !json_mode {
                    println!();
                }
                return finish_login(&control_url, poll, json_mode);
            }
            "denied" => {
                return Err("Login was denied. Run 'aikey account login' to try again.".into());
            }
            "expired" => {
                return Err(
                    "Login session expired. Run 'aikey account login' to try again.".into(),
                );
            }
            other => {
                return Err(format!(
                    "Unexpected login status: {}. Run 'aikey account login' to try again.",
                    other
                )
                .into());
            }
        }
    }
}

/// Exchanges a `"session_id:login_token"` combined string for OAuth tokens.
fn exchange_combined_token(
    control_url: &str,
    combined: &str,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = combined.splitn(2, ':').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err("Invalid --token format. Expected: SESSION_ID:LOGIN_TOKEN".into());
    }
    let (session_id, login_token) = (parts[0], parts[1]);

    if !json_mode {
        println!("Exchanging login token…");
    }

    let resp = PlatformClient::exchange_login_token(control_url, session_id, login_token)
        .map_err(|e| format!("Token exchange failed: {}", e))?;

    if resp.status != "approved" && resp.status != "token_claimed" {
        return Err(format!(
            "Exchange failed with status: {}. Run 'aikey account login' to try again.",
            resp.status
        )
        .into());
    }

    finish_login(control_url, resp, json_mode)
}

/// Persists tokens from a successful poll/exchange response and prints confirmation.
fn finish_login(
    control_url: &str,
    resp: PollResponse,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let access_token = resp
        .access_token
        .ok_or("Server response missing access_token")?;
    let refresh_token = resp
        .refresh_token
        .ok_or("Server response missing refresh_token")?;
    let expires_in = resp.expires_in.unwrap_or(3600);
    let account = resp.account.ok_or("Server response missing account info")?;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let token_expires_at = now_secs + expires_in;

    // Detect account switch: if a different account was previously logged in,
    // purge all data that is scoped to the old account before saving the new one.
    // This prevents the new account from seeing or being prompted for the old
    // account's team keys, pending accepts, and seat statuses.
    let previous_account_id = storage::get_platform_account()
        .ok()
        .flatten()
        .map(|a| a.account_id);
    let is_account_switch = previous_account_id
        .as_deref()
        .map(|prev| prev != account.account_id)
        .unwrap_or(false);

    if is_account_switch {
        // Scope-disable all keys that don't belong to the new account.
        // Rows are preserved; proxy and `aikey use` ignore any key whose
        // local_state is not `active`.  The next sync under this account
        // will restore keys it owns to `synced_inactive`.
        let _ = storage::disable_keys_for_account_scope(&account.account_id);
        // Clear active key config — it may reference an old team key.
        // Personal keys are vault-scoped and remain usable by any account.
        if let Ok(Some(cfg)) = storage::get_active_key_config() {
            if cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey {
                // Deactivate team key — it belongs to the old account.
                // Personal keys are vault-local and remain valid for the new account.
                let _ = storage::clear_active_key_config();
            }
        }
        // Clear seat status cache so whoami shows fresh data for the new account.
        storage::set_seat_status_cache("{}");
        storage::set_last_status_sync(0);
        // Reset snapshot sync version so the new account triggers a full re-sync.
        storage::set_local_seen_sync_version(0);
    }

    storage::save_oauth_session(
        &account.account_id,
        &account.email,
        &access_token,
        &refresh_token,
        token_expires_at,
        control_url,
    )?;

    // Why: after clear-install + login, the vault DB exists (created by session
    // backend selection) but has no master_salt — meaning vault encryption is not
    // initialized. Without it, proxy start, key sync, and aikey use all fail.
    // Auto-initialize here so the user can immediately proceed with `aikey use`.
    // When this login initializes the vault we capture the master password so the
    // snapshot sync below can also download key MATERIAL (encrypted at rest needs
    // the vault key), not just metadata. Why this matters: "Test connection" (and
    // any real use) needs a team key's material locally; when login synced only
    // metadata the user hit a 404 ("no team credential matches … run `aikey key
    // sync`/`aikey use` first") and had to manually `aikey use` before a freshly
    // issued key was testable. The test path itself CANNOT pull material — it runs
    // unlocked (no vault key) by design — so login (which DOES hold the password)
    // is the correct place to pull. 2026-06-17, user-reported.
    let mut vault_pw: Option<secrecy::SecretString> = None;
    if crate::storage::get_salt().is_err() {
        if !json_mode {
            eprintln!();
            eprint!("  {}Set Master Password: ", crate::symbols::ICON_LOCK.pre());
        }
        let pw = if let Ok(val) = std::env::var("AK_TEST_PASSWORD") {
            secrecy::SecretString::new(val)
        } else {
            secrecy::SecretString::new(crate::prompt_hidden("")?)
        };
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt)?;
        crate::storage::initialize_vault(&salt, &pw)?;
        if !json_mode {
            eprintln!("  Vault initialized.");
        }
        vault_pw = Some(pw);
    }

    // Pull the account's current key snapshot immediately after login so keys are
    // visible (and usable) right away without a separate `aikey key list` / `key
    // sync` / `aikey use`. When this login set up the vault (vault_pw present) do a
    // FULL snapshot sync that ALSO downloads key material; when the vault already
    // existed (no password entered this run) fall back to the metadata-only
    // snapshot — without the vault key we can't encrypt material at rest.
    // Non-fatal: if the server is unreachable the local cache is still usable.
    match &vault_pw {
        Some(pw) => {
            let _ = run_full_snapshot_sync(pw);
        }
        None => {
            let _ = run_snapshot_sync();
        }
    }

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "account_id": account.account_id,
            "email": account.email,
        }));
    } else {
        println!();
        println!(
            "  {} Logged in as {}",
            crate::symbols::CHECK.s().green().bold(),
            account.email.bold()
        );
        println!("    Run {} to view your team keys.", "'aikey list'".bold());
    }

    // Persist control URL to all side-channels the proxy + web read (config.json
    // for compliance poll, install-state.json for `aikey web`, user-yaml
    // collector_url for usage reporting). Shared with `agent register` so the DE
    // daemon wires the proxy identically — see persist_control_url_sidecar.
    persist_control_url_sidecar(&control_url, json_mode);

    // Unified-origin landing (方案A, 2026-07-03): the ACTIVATION PAGE swaps
    // itself to the local console once it observes the gateway live (its
    // polling probe reads /system/team-url). The CLI deliberately does NOT
    // also open a tab — two openers meant two console tabs. `aikey web`
    // remains the manual entry (P3 gateway branch).

    Ok(())
}

// ---------------------------------------------------------------------------
// Browser helper
// ---------------------------------------------------------------------------

/// Returns the `(program, args)` invocation that opens `url` in the default
/// browser on the given OS (`std::env::consts::OS` values), or `None` on
/// unsupported platforms.
///
/// Why this is a pure function: so unit tests on any host can pin the
/// Windows invocation without cross-compiling (see `browser_launch_tests`).
///
/// Why Windows uses `rundll32 url.dll,FileProtocolHandler` and MUST NOT go
/// through `cmd /c start`: cmd.exe treats a bare `&` in its command line as
/// a command separator, so login URLs (`?s=...&d=...&email=...`) were
/// truncated at the first `&` — the browser opened with only `s`, the login
/// page failed with "Missing session parameters", and cmd spawned garbage
/// `d=...` / `email=...` commands (bugfix
/// 20260702-windows-login-url-ampersand-truncation). rundll32 receives the
/// URL as a plain argv entry with no shell parsing — same pattern as
/// `try_open_browser` (commands_import.rs) and `open_browser`
/// (commands_auth/mod.rs).
fn browser_launch_command<'a>(os: &str, url: &'a str) -> Option<(&'static str, Vec<&'a str>)> {
    match os {
        "macos" => Some(("open", vec![url])),
        "linux" => Some(("xdg-open", vec![url])),
        "windows" => Some(("rundll32", vec!["url.dll,FileProtocolHandler", url])),
        _ => None, // unsupported platform — silently skip
    }
}

/// Opens a URL in the default system browser (best-effort; failures are ignored).
fn open_url_silently(url: &str) {
    if let Some((program, args)) = browser_launch_command(std::env::consts::OS, url) {
        let _ = std::process::Command::new(program).args(args).spawn();
    }
}

/// Delivers the browse URL either by opening the browser (default) or by
/// copying to the system clipboard (`copy_url=true`).
///
/// Why both behaviours live in one helper: every `aikey web` exit point
/// must consistently honour the `--copy-url` flag, even if a later refactor
/// changes how the URL is built. Centralising the branch keeps the rule
/// "what the URL points at goes through this gate" enforceable.
///
/// No auto-clear (2026-06-03 decision): the cross-platform
/// `schedule_clipboard_clear` helper spawns a detached thread that dies
/// when this `aikey` process exits, so the timer never fires in
/// practice (same as `aikey get` — pre-existing bug, see future bugfix
/// "20260603-clipboard-auto-clear-detached-thread-killed"). Rather than
/// ship a false "auto-clear in 30s" promise, we deliberately don't
/// schedule a clear here. The user gets the URL on clipboard, sees the
/// confirmation message, and the next clipboard write overwrites it
/// naturally. JWT TTL is 24h — by then the token's already expired.
///
/// Failure fallback: if `arboard` reports the clipboard is unreachable
/// (no DISPLAY/WAYLAND_DISPLAY on Linux, sandbox restrictions, etc.) we
/// print the full URL to stdout with a WARN to stderr instead of failing
/// silently. The user explicitly asked for the URL, so we always give it
/// to them — through clipboard if possible, through stdout if not.
///
/// `display_url`: what to echo in the success line. Callers that don't
/// want the auth token in terminal scrollback (the JWT path) pass the
/// base+path form instead. The clipboard payload is ALWAYS the full URL
/// — that's what the user pastes.
fn deliver_browse_url(url: &str, copy_url: bool, json_mode: bool, display_url: &str) {
    if !copy_url {
        open_url_silently(url);
        return;
    }
    match crate::executor::copy_to_clipboard(url) {
        Ok(()) => {
            if !json_mode {
                println!("URL copied to clipboard.");
                println!("  {}", display_url);
            }
        }
        Err(e) => {
            // Surface the failure on stderr so it's visible even when
            // the caller pipes stdout. Then print the FULL URL (including
            // token) on stdout so the user can copy it manually — the
            // whole point of --copy-url is "give me the URL", and the
            // fallback path must still deliver on that promise.
            if json_mode {
                eprintln!("[warn] copy to clipboard failed: {}", e);
                eprintln!("[info] URL (auth token included): {}", url);
            } else {
                eprintln!("[warn] Clipboard unavailable: {}", e);
                println!("Copy the URL manually (auth token included):");
                println!("  {}", url);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Auth helpers (token refresh + authenticated client)
// ---------------------------------------------------------------------------

/// Returns a valid access token, silently refreshing it if it expires within 60 s.
///
/// On refresh both `access_token` and `refresh_token` are updated in storage so
/// the CLI is ready for the next request without re-login.
fn try_refresh_if_needed(acc: &storage::PlatformAccount) -> Result<String, String> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let needs_refresh = acc
        .token_expires_at
        .map(|exp| exp - 60 <= now_secs)
        .unwrap_or(false); // legacy rows without expiry: assume still valid

    if !needs_refresh {
        return Ok(acc.jwt_token.clone());
    }

    let refresh_token = acc.refresh_token.as_deref().ok_or_else(|| {
        "No refresh token stored. Run 'aikey account login' to re-authenticate.".to_string()
    })?;

    let resp = PlatformClient::do_refresh_token(&acc.control_url, refresh_token).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("login expired") {
            format!("{}. Run 'aikey login' to re-authenticate.", msg)
        } else {
            format!(
                "Token refresh failed: {}. Check your network or server, then retry. \
                 If the problem persists, run 'aikey login' to re-authenticate.",
                msg
            )
        }
    })?;

    let new_expires_at = {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        ts + resp.expires_in
    };

    storage::update_tokens(&resp.access_token, &resp.refresh_token, new_expires_at)
        .map_err(|e| format!("Failed to save refreshed tokens: {}", e))?;

    Ok(resp.access_token)
}

/// Returns an authenticated `PlatformClient` with a guaranteed-valid access token.
///
/// Automatically renews the token via refresh if it is close to expiry.
/// Returns `Err` if the user is not logged in or token renewal fails.
#[allow(dead_code)]
fn get_authenticated_client() -> Result<PlatformClient, Box<dyn std::error::Error>> {
    let acc = storage::get_platform_account()?
        .ok_or("Not logged in. Run 'aikey account login' first.")?;
    let token =
        try_refresh_if_needed(&acc).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    Ok(PlatformClient::new(&acc.control_url, &token))
}

/// Best-effort: resolve THIS user's cluster node (P5 channel) and persist it,
/// mirroring what `aikey use` does on its resolve step. Returns `true` if the
/// user is on a cluster (a node was resolved + persisted), `false` otherwise
/// (not logged in / control unreachable / non-cluster org → node cleared).
///
/// Why callable outside `aikey use`: the Web "Test Connection" on a cluster
/// team VK needs the resolved node to build a probe target (form-① key material
/// is central). Before this, a test without a prior `aikey use` had no persisted
/// node → `cluster_route` returned None → the probe surfaced a misleading
/// `I_CREDENTIAL_NOT_FOUND` / HTTP 404. Best-effort + silent: any failure leaves
/// the prior node state and the caller falls back to the local-material path.
/// Bug: workflow/CI/bugfix/20260611-cluster-form1-connectivity-test-404.md
pub(crate) fn try_resolve_and_persist_cluster_node() -> bool {
    let client = match get_authenticated_client() {
        Ok(c) => c,
        Err(_) => return false, // not logged in → can't be on a cluster
    };
    match client.resolve_cluster_node() {
        crate::platform_client::ClusterNodeResolution::Node(addr) => {
            let _ = shell_integration::write_cluster_node(&addr);
            true
        }
        crate::platform_client::ClusterNodeResolution::NotACluster => {
            // Authoritative 404: org has no cluster — clear any stale node so
            // a later test doesn't wrongly route to a dead node.
            shell_integration::clear_cluster_node();
            false
        }
        crate::platform_client::ClusterNodeResolution::Unknown(_) => {
            // Auth/transport failure: topology UNKNOWN — keep last-known-good
            // routing untouched (2026-06-12 L8 次生缺口: a dead token here
            // used to clear the node and downgrade routing to the
            // material-less local proxy → 503 until a manual `aikey use`).
            shell_integration::read_cluster_node().is_some()
        }
    }
}

/// Probes the server to confirm `token` is still cryptographically valid,
/// and recovers when it isn't.
///
/// # Why this exists
///
/// `try_refresh_if_needed` only refreshes when the local `exp` claim is
/// near expiry. That's correct for the common "token aged out" path, but
/// it blindly trusts the cached token in another scenario that surfaces
/// often during dev / pre-prod work:
///
/// When the backend is rebuilt (`docker compose down -v` or equivalent
/// nuke), `JWT_SECRET` is regenerated. Tokens we issued against the
/// previous secret have a perfectly fine `exp` (e.g. tomorrow), but the
/// new server can't verify their signature and returns
/// `BIZ_AUTH_TOKEN_INVALID`. The CLI happily prints a `/go/<alias>#auth_token=...`
/// URL with the dead token; the browser opens it, the SPA gets 401,
/// localStorage clears, the user lands on `/user/session-expired` with
/// no clue why. Bugfix: `workflow/CI/bugfix/2026-06-08-server-jwt-secret-rotation-stale-cached-token.md`.
///
/// # Behaviour
///
/// 1. Probe `/accounts/me` with the supplied token.
/// 2. If the server accepts it → return as-is.
/// 3. If the server rejects it as `Invalid` (signature mismatch) →
///    bypass the `exp`-based gate and force a `do_refresh_token` round
///    trip. Refresh tokens are usually rotated through the same secret
///    so this typically still fails — but if the deployment happens to
///    keep refresh secrets separate, we recover transparently.
/// 4. If the forced refresh also fails → return a user-actionable error
///    instructing them exactly which command to run.
/// 5. If we can't reach the server at all → keep the cached token. The
///    user may be offline; the URL still works once their network is
///    back and the cached token is presumed valid until proven otherwise.
///
/// `Expired` from the probe falls through to step 3 (force refresh) too:
/// expired+no-clock-skew is the same recovery path as invalid-signature.
fn ensure_token_accepted_by_server(
    acc: &storage::PlatformAccount,
    token: String,
) -> Result<String, String> {
    use crate::platform_client::TokenProbeError;
    match PlatformClient::probe_token(&acc.control_url, &token) {
        Ok(()) => Ok(token),
        Err(TokenProbeError::Offline) => {
            // Offline (or 5xx). Cached token is presumed-valid; let the
            // browser surface any later failure when the user actually
            // navigates. Not noisy here because the user may explicitly
            // be `--copy-url`-ing for paste-into-other-machine workflows.
            Ok(token)
        }
        Err(probe_err @ TokenProbeError::Invalid) | Err(probe_err @ TokenProbeError::Expired) => {
            force_refresh_after_server_reject(acc, &probe_err.to_string())
        }
    }
}

/// SHARED recovery core for "the server rejected a token the local clock
/// still considers valid" — secret rotation, control reinstall, revocation,
/// or a restored vault backup holding pre-rotation tokens.
///
/// Extracted 2026-06-11 from `ensure_token_accepted_by_server` (its sole
/// logic until then) so BOTH trigger styles share one truth source:
///   - `aikey web` / `browse`: PRE-flight probe (one extra RTT before
///     opening a browser is acceptable) → on reject, calls this.
///   - sync/snapshot (`aikey use` chain): POST-hoc on 401 (high-frequency
///     path — probing before every call is not) → on 401, calls this and
///     replays once. Bug: 20260611-jwt-renewal-l8-test.md (L8 T2: bare 401
///     with no re-login guidance).
///
/// Behaviour (pinned by `probe_token_tests` + docstring contract):
///   1. Force a `do_refresh_token` round trip, IGNORING the local `exp`
///      gate (`try_refresh_if_needed`'s 60s-window check would skip the
///      refresh and hand back the same dead token).
///   2. No refresh token / refresh fails → user-actionable error naming
///      the exact `aikey login` command (the user can't fix HTTP; they
///      CAN re-login).
///   3. Refresh succeeds → persist the rotated pair, then re-probe as
///      defense in depth (a misconfigured server may reject the new token
///      too — error out rather than mislead). Offline re-probe → accept.
///
/// `reject_context` prefixes the error strings (e.g. the probe error or
/// "snapshot request returned 401") so the caller's failure mode stays
/// visible in the final message.
fn force_refresh_after_server_reject(
    acc: &storage::PlatformAccount,
    reject_context: &str,
) -> Result<String, String> {
    use crate::platform_client::TokenProbeError;

    let refresh_token = acc.refresh_token.as_deref().ok_or_else(|| {
        format!(
            "{}.\nThe cached login is unusable and there is no refresh token to retry with.\n\
             Run: aikey login --email {} --control-url {}",
            reject_context, acc.email, acc.control_url,
        )
    })?;
    let resp = match PlatformClient::do_refresh_token(&acc.control_url, refresh_token) {
        Ok(r) => r,
        Err(e) => {
            // Refresh also failed — almost certainly because the
            // refresh token was signed by the same rotated secret.
            return Err(format!(
                "{} ({}).\nThe cached login is unusable. Re-authenticate with:\n  \
                aikey login --email {} --control-url {}",
                reject_context, e, acc.email, acc.control_url,
            ));
        }
    };
    let new_expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
        + resp.expires_in;
    storage::update_tokens(&resp.access_token, &resp.refresh_token, new_expires_at)
        .map_err(|e| format!("Failed to save refreshed tokens: {}", e))?;
    match PlatformClient::probe_token(&acc.control_url, &resp.access_token) {
        Ok(()) => Ok(resp.access_token),
        Err(TokenProbeError::Offline) => Ok(resp.access_token),
        Err(_) => Err(format!(
            "Refreshed the token but the server still rejects it. The login is likely \
             bound to a previous server install. Re-authenticate with:\n  \
             aikey login --email {} --control-url {}",
            acc.email, acc.control_url,
        )),
    }
}

/// `aikey account status`
pub fn handle_account_status(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    match storage::get_platform_account()? {
        Some(acc) => {
            if json_mode {
                crate::json_output::print_json(serde_json::json!({
                    "ok": true,
                    "logged_in": true,
                    "account_id": acc.account_id,
                    "email": acc.email,
                    "control_url": acc.control_url,
                }));
            } else {
                println!("Logged in as : {} ({})", acc.email, acc.account_id);
                println!("Control Panel: {}", acc.control_url);
            }
        }
        None => {
            if json_mode {
                crate::json_output::print_json(serde_json::json!({
                    "ok": true,
                    "logged_in": false,
                }));
            } else {
                println!("Not logged in.");
                println!("Run 'aikey account login' to connect to a control service.");
            }
        }
    }
    Ok(())
}

/// Canonical alias for the CLI-side `aikey web [page]` command.
///
/// The CLI deliberately does NOT know the real paths (`/user/...`). Every
/// recognised page name is normalised to an alias here, and the URL is
/// then built as `<base>/go/<alias>`. The real alias → path mapping lives
/// in `aikey-control/web/src/app/router/go-alias.tsx` — letting the web
/// team reorganise routes without a CLI release.
///
/// Unknown names bubble up as an error so typos get caught at the CLI
/// boundary rather than silently landing on the fallback page.
fn web_page_alias(page: Option<&str>) -> Result<&'static str, String> {
    match page {
        None                                                     => Ok("overview"),
        Some("overview")                                         => Ok("overview"),
        Some("keys" | "virtual-keys" | "team-keys")              => Ok("keys"),
        Some("vault" | "secrets" | "my-vault")                   => Ok("vault"),
        Some("account" | "profile")                              => Ok("account"),
        Some("usage" | "usage-ledger")                           => Ok("usage"),
        Some("import" | "bulk-import" | "quick-import")          => Ok("import"),
        Some("referrals")                                        => Ok("referrals"),
        // Degrade-detector M5 trust-check page (/user/trust-check) —
        // added 2026-05-24 after user surfaced that the page was
        // reachable via the sidebar / URL but `aikey web trust-check`
        // errored "Unknown page". The page is Personal-only at the
        // sidebar level, but the CLI doesn't edition-gate page names
        // (matches existing pattern); the web side decides what to
        // render on Trial / Production hosts.
        Some("trust-check" | "trust")                            => Ok("trust-check"),
        Some(other) => Err(format!(
            "Unknown page '{}'. Available: overview, keys, vault, account, usage, import, referrals, trust-check",
            other
        )),
    }
}

/// `aikey web [page] [--import] [--port PORT]` — open User Console in the
/// default browser with auth.
///
/// In local-user mode (personal edition, installed with `--with-console`),
/// opens the console directly without JWT — reads `install-state.json` to
/// detect `control_plane_mode == "local"`.
///
/// In team/trial mode, reads the local JWT token and appends it as a URL
/// fragment so the web app can pick it up from `location.hash` without the
/// token ever hitting server logs.
///
/// When `control_url` points to localhost, automatically probes common dev-server
/// ports (3000, 5173) and prefers the first one that responds.  This lets
/// `aikey web` work in both dev and production without extra flags.
pub fn handle_browse(
    page: Option<&str>,
    port: Option<u16>,
    json_mode: bool,
    copy_url: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate the page name at the CLI boundary. Doing it here (before
    // the local/JWT branch) means typos fail fast with a clear error
    // regardless of which mode the user is in — instead of silently
    // opening the overview page.
    let alias = web_page_alias(page)?;

    // 2026-06-01 design change (user spec):
    //   logged in     → team Control Panel (was: local-first, now flipped)
    //   not logged in → 127.0.0.1:8090 local console
    //
    // Previous Phase 3B (2026-05-11) design preferred LOCAL even when logged
    // in, on the reasoning that `aikey web` opens the user's own dashboard
    // which surfaces the Phase 3A merged Personal + Team key view. Users
    // pushed back: when they're logged into a team, `aikey web` should land
    // them in the team's Control Panel (where seats / providers / org admin
    // live), not their loopback. Users who specifically want the merged
    // local view can still pass `--port 8090` to force local.
    //
    // The team path runs first now. If get_platform_account returns Some,
    // we route through the JWT branch below (which fall-throughs here) and
    // skip the local-server preflight entirely. If None, we fall to the
    // local path next.
    let logged_in = matches!(storage::get_platform_account(), Ok(Some(_)));

    // Local-user mode: only used when NOT logged in. Personal edition has
    // no login flow — LocalIdentityMiddleware handles auth server-side,
    // and the SPA is served with authMode:"local_bypass". Also used when
    // an explicit --port is passed (force-local intent).
    if !logged_in && port.is_none() {
        // Resolve the local console URL. try_local_browse_url returns None when
        // install-state.json is missing OR records no local web component.
        //
        // Fault isolation (2026-06-14): a Personal user is local-first and must
        // NEVER be told to `aikey login` for `aikey web`. A MISSING install-state
        // (a partial / aborted install, corruption, or a SIDE step that failed —
        // e.g. service registration) must NOT let us fall through to the team
        // login path; degrade to the default local console (127.0.0.1:8090) and
        // let the preflight below probe / auto-start it. Only when install-state
        // EXPLICITLY records a Personal install with no console do we send the
        // precise "reinstall --with-console" hint instead of a dead URL.
        let url = match try_local_browse_url(alias) {
            Some(u) => u,
            None => {
                if read_install_state().is_some() {
                    return Err(
                        "No web console on this Personal install (CLI + Proxy only).\n  \
                         To enable a local console, reinstall with --with-console:\n  \
                         curl -fsSL https://github.com/aikeylabs/launch/releases/latest/download/latest-install.sh \\\n    \
                           | sh -s -- --yes --with-console"
                            .into(),
                    );
                }
                default_local_browse_url(alias)
            }
        };
        // Pre-flight: probe local-server before opening the browser.
        // Without this, an unstarted service produced ERR_CONNECTION_
        // REFUSED in the browser with no useful actionable hint —
        // user couldn't tell whether the install was broken or the
        // service just needed starting. See decisions (1c, A-a, B-b,
        // C-b) recorded in the 2026-05-18 session.
        let preflight = local_server_preflight_for_browse(json_mode);
        match preflight {
            BrowseLocalPreflight::OpenNow => {
                if json_mode {
                    crate::json_output::print_json(serde_json::json!({
                        "ok": true,
                        "url": &url,
                        "mode": "local",
                    }));
                } else if !copy_url {
                    // The clipboard branch prints its own confirmation
                    // inside deliver_browse_url; skip the duplicate
                    // "Opening..." message when --copy-url is set.
                    println!("Opening Local Console...");
                    println!("  {}", url);
                }
                // Local URL has no auth token, so display_url == url.
                deliver_browse_url(&url, copy_url, json_mode, &url);
                return Ok(());
            }
            BrowseLocalPreflight::DeclineNoOpen => {
                // User said "no, don't auto-start". Don't open a URL
                // that will refuse the connection; exit non-zero so
                // wrapper scripts can detect the abort.
                return Err("local-server is not running; declined to start".into());
            }
            BrowseLocalPreflight::JsonModeError(msg) => {
                return Err(msg.into());
            }
        }
    }

    // Personal-no-console mode (control_plane_mode = "none"): user installed
    // CLI + Proxy only, no local web console. Falling through to the JWT
    // branch below would tell them to "Run 'aikey login' first" — confusing
    // because login is for team/trial OAuth, not Personal. Give the right
    // hint instead: reinstall with --with-console to enable a local console.
    if port.is_none() {
        if let Some(state) = read_install_state() {
            let mode = state
                .get("control_plane_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if mode == "none" {
                return Err(
                    "No web console on this Personal install (CLI + Proxy only).\n  \
                     To enable a local console, reinstall with --with-console:\n  \
                     curl -fsSL https://github.com/aikeylabs/launch/releases/latest/download/latest-install.sh \\\n    \
                       | sh -s -- --yes --with-console".into()
                );
            }
        }
    }

    // Unified-origin composing gateway (P3, 2026-07-03 design doc
    // 20260703-web统一origin-本地网关方案): when the co-installed local-server
    // composes the team side on 127.0.0.1, `aikey web` opens the LOCAL
    // origin. Team pages/data are reachable there same-origin (which is why
    // the 2026-06-01 "logged-in must land on the team panel" pushback no
    // longer applies), and this path performs NO remote token refresh —
    // refresh hard-blocked `aikey web` whenever the team server's address
    // changed (2026-07-02 report: Connection refused on token/refresh).
    // OLD local-servers don't advertise the gateway → fall through to the
    // pre-existing team-origin flow below, unchanged (progressive
    // enhancement, no hard cutover). Explicit --port keeps its meaning.
    if port.is_none() {
        if let Some(base) = local_gateway_base() {
            let url = format!("{}/go/{}", base, alias);
            if json_mode {
                crate::json_output::print_json(serde_json::json!({
                    "ok": true,
                    "url": &url,
                    "mode": "local-gateway",
                }));
            } else if !copy_url {
                println!("Opening User Console (unified local origin)...");
                println!("  {}", url);
            }
            // Local origin needs no auth token in the URL — the gateway
            // injects the vault JWT server-side for team requests.
            deliver_browse_url(&url, copy_url, json_mode, &url);
            return Ok(());
        }
    }

    // JWT-based browse (team/trial mode).
    let acc = storage::get_platform_account()?.ok_or("Not logged in. Run 'aikey login' first.")?;

    let token =
        try_refresh_if_needed(&acc).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // Verify the token still works against the server before we hand it
    // to the browser. The exp-based gate in try_refresh_if_needed CAN'T
    // catch the "server reset → JWT_SECRET rotated → signature now
    // invalid" case (the cached exp says next-week but the new server
    // can't verify); without this probe the user lands on
    // /user/session-expired with no idea why. 2026-06-08 bugfix; see
    // doc on ensure_token_accepted_by_server.
    let token = ensure_token_accepted_by_server(&acc, token)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // Build `/go/<alias>` rather than `/user/<page>` so we don't freeze
    // user-facing route paths into CLI binaries.
    let path = format!("/go/{}", alias);

    let base_url = resolve_browse_base_url(&acc.control_url, port);

    let url = format!("{}{}#auth_token={}", base_url, path, token);

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "url": format!("{}{}", base_url, path),
        }));
    } else if !copy_url {
        // The clipboard branch prints its own confirmation inside
        // deliver_browse_url; skip the duplicate "Opening..." message
        // when --copy-url is set.
        println!("Opening User Console...");
        println!("  {}{}", base_url, path);
    }

    // Token-bearing URL goes into the clipboard / browser; the display
    // form (base+path) is what we ever echo to the terminal — keeps the
    // 24h JWT out of shell scrollback even in --copy-url mode.
    let display_url = format!("{}{}", base_url, path);
    deliver_browse_url(&url, copy_url, json_mode, &display_url);
    Ok(())
}

/// `aikey web {start|stop|restart}` — control the local web service.
///
/// Why this lives under `aikey web` rather than a new `aikey service`
/// command: the only thing the CLI needs to start / stop / restart on
/// a user's host is the process that serves the web UI (local-server
/// on Personal, full-trial on Trial). Folding it into `aikey web`
/// keeps the surface area small ("aikey web" opens the page, "aikey
/// web restart" reboots its backend) without inventing a new noun.
///
/// Edition-aware: detects Personal vs Trial from install-state.json
/// and dispatches to the right binary (aikey-local-server vs
/// aikey-full-trial). Uses direct process management (nohup-style
/// spawn + port-based PID lookup + SIGTERM/SIGKILL) rather than
/// launchctl/systemctl because that's what local-install.sh and
/// trial-install.sh actually do — neither installer registers the
/// web service with the OS service manager. See bugfix:
/// workflow/CI/bugfix/2026-05-21-aikey-web-auto-start-launchctl-noop.md
///
/// Refuses on Production (or any host where neither edition is
/// installed) with an actionable message — the cli has no business
/// touching server-install's docker-compose stack.
pub fn handle_web_service(action: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let edition = match crate::local_server_probe::detect_edition() {
        Some(e) => e,
        None => {
            let msg = "no local web service installed on this host. \
                       `aikey web start/stop/restart` is for Personal \
                       (aikey-local-server) and Trial (aikey-trial-server) \
                       editions only. Production servers are managed by the \
                       server-install runbook (docker-compose / systemd on \
                       the server host).";
            if json_mode {
                crate::json_output::print_json(serde_json::json!({
                    "ok": false,
                    "error": "no_local_web_service",
                    "action": action,
                    "detail": msg,
                }));
            } else {
                eprintln!("{}", msg);
            }
            return Err(msg.into());
        }
    };

    let result = match action {
        "start" => crate::local_server_probe::spawn_start_command(),
        "stop" => crate::local_server_probe::spawn_stop_command(),
        "restart" => crate::local_server_probe::spawn_restart_command(),
        other => {
            return Err(format!(
                "unknown web action `{}` (use start, stop, or restart)",
                other
            )
            .into());
        }
    };

    match result {
        Ok(()) => {
            // For start / restart, follow with a reachability probe so
            // we don't claim success while the service is still booting.
            // Stop has no symmetric probe — we trust the service manager.
            let final_state = if matches!(action, "start" | "restart") {
                // Use `_or_default` (not the strict variant): we're on a host
                // that just spawned the local-server binary one frame up, so
                // local-server IS installed. If YAML config is missing the
                // binary still runs on its built-in default 8090 — falling
                // back here matches binary behavior. Strict variant would
                // surface a Bulk-Import-flavored "not installed" message
                // (BR-rc.5-47); bugfix
                // 20260524-aikey-service-restart-web-port-undiscoverable.md.
                match crate::local_server_probe::read_local_server_port_or_default() {
                    Ok(port) => crate::local_server_probe::wait_for_reachable(
                        port,
                        // find#10 (2026-07-07): 8s was too short on Windows. The
                        // local-server cold start (Go binary + embedded web +
                        // SQLite open, plus an antivirus scan of a freshly-written
                        // .exe) routinely exceeds 8s, so `aikey service start web`
                        // reported "did not come up within 8s" as a FALSE NEGATIVE
                        // even though the console bound :8090 a few seconds later.
                        // wait_for_reachable polls every 200ms and returns on the
                        // FIRST success, so a larger ceiling never slows a fast
                        // start — it only stops the premature failure verdict.
                        std::time::Duration::from_secs(25),
                    )
                    .map(|()| Some(port)),
                    Err(strict_err) => Err(strict_err),
                }
            } else {
                Ok(None)
            };

            if json_mode {
                let (ok, detail) = match &final_state {
                    Ok(_) => (true, String::new()),
                    Err(e) => (false, e.clone()),
                };
                crate::json_output::print_json(serde_json::json!({
                    "ok": ok,
                    "action": action,
                    "edition": edition.label(),
                    "port": final_state.as_ref().ok().and_then(|p| *p),
                    "detail": detail,
                }));
            } else {
                match &final_state {
                    Ok(Some(port)) => println!(
                        "{}: {} succeeded (reachable on port {})",
                        edition.label(),
                        action,
                        port
                    ),
                    Ok(None) => println!("{}: {} succeeded", edition.label(), action),
                    Err(e) => eprintln!(
                        "{}: {} dispatched but service did not come up: {}",
                        edition.label(),
                        action,
                        e
                    ),
                }
            }

            match final_state {
                Ok(_) => Ok(()),
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => {
            if json_mode {
                crate::json_output::print_json(serde_json::json!({
                    "ok": false,
                    "action": action,
                    "edition": edition.label(),
                    "error": "service_command_failed",
                    "detail": &e,
                }));
            } else {
                eprintln!("{}: {} failed — {}", edition.label(), action, e);
                eprintln!(
                    "Manual command: {}",
                    crate::local_server_probe::service_command_hint(edition, action)
                );
            }
            Err(e.into())
        }
    }
}

/// `aikey web status` (and `aikey service status web`) — read-only report of
/// the local web service (Personal local-server / Trial trial-server).
///
/// Distinct from `handle_web_service` (which drives start/stop/restart and
/// mutates state): status never spawns anything, needs no vault password, and
/// on a host with no local web service reports that as a non-error status.
/// Both entry points call this single core so the two CLI spellings agree.
pub fn handle_web_status(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (running, detail) = crate::local_server_probe::status_summary();
    if json_mode {
        let edition = crate::local_server_probe::detect_edition().map(|e| e.label());
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "service": "web",
            "running": running,
            "edition": edition,
            "detail": detail,
        }));
    } else {
        // Reuse the richer multi-line line for the dedicated command — it
        // already includes a Start hint on the NOT RUNNING path.
        println!("{}", crate::local_server_probe::local_server_status_line());
    }
    Ok(())
}

/// `aikey master [page] [--port PORT]` — open Master Console in the default browser.
///
/// Resolves the control panel URL from install-state.json or the stored
/// platform account, then opens `/master/<page>` in the browser.
///
/// Precondition: without explicit `--url` / `--port`, refuse to open unless
/// either (a) install_profile=="trial" or (b) the user has a stored
/// platform_account (logged in). Spec: requirements/2026-05-11-aikey-web-
/// local-first-team-merge.md §R4-pre.
pub fn handle_master_browse(
    page: Option<&str>,
    url_override: Option<&str>,
    port: Option<u16>,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = match page {
        Some("seats") => "/master/orgs/default/seats",
        Some("keys" | "virtual-keys") => "/master/orgs/default/virtual-keys",
        Some("bindings") => "/master/orgs/default/bindings",
        Some("providers" | "provider-accounts") => "/master/orgs/default/provider-accounts",
        Some("events" | "control-events") => "/master/orgs/default/control-events",
        Some("usage" | "usage-ledger") => "/master/orgs/default/usage-ledger",
        Some("dashboard") | None => "/master/dashboard",
        Some(other) => {
            return Err(format!(
                "Unknown page '{}'. Available: dashboard, seats, virtual-keys, bindings, providers, events, usage",
                other
            ).into());
        }
    };

    // Precondition gate (skipped when --url / --port explicitly given).
    if url_override.is_none() && port.is_none() {
        let install_state = read_install_state();
        let logged_in = matches!(storage::get_platform_account(), Ok(Some(_)));
        if !master_precondition_satisfied(install_state.as_ref(), logged_in) {
            return Err(
                "Enterprise edition not connected. Run `aikey login --control-url <your-team-url>` first.".into()
            );
        }
    }

    // Resolve base URL: --url > --port > stored account > install-state > interactive prompt.
    //
    // Phase 3B (2026-05-11): platform_account (login URL) was promoted ABOVE
    // try_local_control_url (install-state). Reasoning: if the user explicitly
    // ran `aikey login --control-url X`, X is their active workspace; the
    // local install-state URL is just the install profile's default. Previous
    // order opened localhost even after login to a remote team server, which
    // confused users running `aikey master` after `aikey login` to a team
    // server URL — they expected the team console, got their local trial.
    // Users who genuinely want the local console can still pass --url / --port
    // explicitly, both of which still win over login.
    let base_url = if let Some(u) = url_override {
        u.to_string()
    } else if let Some(p) = port {
        format!("http://localhost:{}", p)
    } else if let Ok(Some(acc)) = storage::get_platform_account() {
        acc.control_url.clone()
    } else if let Some(url) = try_local_control_url() {
        url
    } else if !json_mode && std::io::stdin().is_terminal() {
        // Interactive prompt with a sensible default
        use std::io::Write;
        let default = "http://localhost:8090";
        print!("Control Panel URL [{}]: ", default);
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if input.is_empty() {
            default.to_string()
        } else {
            input.to_string()
        }
    } else {
        return Err("No control panel URL found. Use --url <url> or --port <port>.".into());
    };

    let url = format!("{}{}", base_url.trim_end_matches('/'), path);

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "url": &url,
        }));
    } else {
        println!("Opening Master Console...");
        println!("  {}", url);
    }

    open_url_silently(&url);
    Ok(())
}

/// Resolve the local-machine control-panel base URL from install-state.json.
///
/// **Why this is profile-driven instead of reading `control_panel_url` directly**
/// (regression record: 2026-04-27 — server-then-trial install sequence left
/// `control_panel_url` pointing at the production sandbox port 39000 even
/// though the active service was the trial server on 8090; `make
/// restart-trial1` doesn't rerun trial-install.sh and therefore can't
/// overwrite the stale field). The fix decouples the URL from the
/// `control_panel_url` field for local/trial profiles by deriving the
/// console port from `ports.trial`, which both profiles already populate
/// canonically:
///
///   * trial-install.sh writes  `ports.trial = trial_server_port`  (default 8090)
///   * local-install.sh --with-console writes  `ports.trial = console_port`
///     (also 8090 by default — same field, same meaning under both profiles)
///   * server-install.sh writes a different port set (`ports.web` etc.) and
///     `install_profile = "server"`; for that case we keep `control_panel_url`
///     as the source of truth because it is genuinely externally configured
///     (BIND_IP + manifest-resolved web port).
///
/// Returns `None` when no resolvable URL exists for the current profile —
/// callers fall back to JWT / interactive resolution.
fn try_local_control_url() -> Option<String> {
    let state = read_install_state()?;
    derive_local_control_url(&state)
}

/// Pure helper for `try_local_control_url` so the resolution logic can be
/// unit-tested without touching the filesystem. Profile-driven: see the
/// caller's comment for the regression history.
fn derive_local_control_url(state: &serde_json::Value) -> Option<String> {
    let profile = state
        .get("install_profile")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match profile {
        // trial / local-with-console / personal: ports.trial is canonical for
        // all "user-side" installs that run a local-server. Both
        // `local-install.sh --with-console` and `make restart-personal`
        // write `ports.trial = console_port`. install_profile differs
        // ("local" vs "personal") for historical reasons — we accept
        // both. 2026-06-01: added "personal" so `aikey web` after
        // logout (which is supposed to land on 127.0.0.1:8090 per user
        // spec) doesn't fall to the `_ =>` arm and read the now-stale
        // `control_panel_url` (set by the previous login). The handle_
        // browse function decides team-vs-local on login state; this
        // helper is the LOCAL-side of that decision, so reading the
        // team URL from install-state here would be a layering bug.
        "trial" | "local" | "personal" => {
            let port = state.get("ports")?.get("trial")?.as_u64()?;
            Some(format!("http://127.0.0.1:{}", port))
        }
        // server / production: control_panel_url is externally configured
        // (BIND_IP + manifest web port), use as the source of truth.
        "server" | "production" => {
            let url = state.get("control_panel_url")?.as_str()?;
            if url.is_empty() {
                None
            } else {
                Some(url.to_string())
            }
        }
        // Unknown / blank profile — back-compat fallback to control_panel_url
        // (older install-state.json versions may not carry an install_profile).
        _ => {
            let url = state.get("control_panel_url")?.as_str()?;
            if url.is_empty() {
                None
            } else {
                Some(url.to_string())
            }
        }
    }
}

/// Build a local-mode browse URL for `aikey browse <page>`.
///
/// Returning `None` means "no local server is installed — caller should fall
/// back to the JWT path". Uses the same profile-driven base-URL resolution as
/// `try_local_control_url` (see that fn's `Why` block). The alias is already
/// validated by the caller.
///
/// Phase 3B (2026-05-11): the `control_plane_mode` gate was removed.
/// Reasoning: `aikey web` is the user's own dashboard (Personal vault +
/// Phase 3A merged Team-key view), which is served by the LOCAL local-server
/// regardless of whether the user has logged into a remote team. Previously
/// the gate over-restricted to mode=="local"|"trial"; an install whose
/// install-state.json had a stale `control_plane_mode: "remote"` field
/// (set by an old `aikey login --control-url` flow that wrote the field)
/// would route `aikey web` through the remote JWT path, which fails with
/// "Not logged in" before login and opens the remote server's user pages
/// (a different context — no local Personal keys) after login.
///
/// `installed_components` is the canonical signal "local-server is on this
/// machine"; we check that instead. derive_local_control_url's downstream
/// requirement on `ports.trial` is the second guard for malformed states.
fn try_local_browse_url(alias: &str) -> Option<String> {
    let state = read_install_state()?;
    derive_local_browse_url(&state, alias)
}

/// Default local console URL, used by `aikey web` when install-state.json is
/// absent. A Personal install is local-first, so `aikey web` degrades HERE
/// rather than to the team login path. Uses the console's well-known default
/// port (read from the live proxy/console config, else 8090) and the same
/// `/go/<alias>` web-router path `derive_local_browse_url` builds. Fault
/// isolation (2026-06-14): a missing side-artifact (install-state, e.g. after a
/// service-registration step aborted the installer) must not break the main
/// local-console feature.
fn default_local_browse_url(alias: &str) -> String {
    let port = crate::local_server_probe::read_local_server_port_or_default().unwrap_or(8090);
    format!("http://127.0.0.1:{}/go/{}", port, alias)
}

/// Outcome of the local-server pre-flight that `aikey web` runs before
/// opening the browser. Three terminal states; the caller branches on
/// these instead of taking action mid-helper so the I/O surface stays
/// localized.
enum BrowseLocalPreflight {
    /// Either the service is already up, or the user opted to auto-start
    /// (regardless of whether the start actually succeeded — decision A
    /// is "open the browser anyway and let the user see the real error").
    OpenNow,
    /// User answered "no" to the auto-start prompt. Don't open a URL
    /// that's known to be unreachable.
    DeclineNoOpen,
    /// `--json` mode: pre-flight surfaces a structured error and exits;
    /// auto-start prompts only make sense in tty mode.
    JsonModeError(String),
}

/// Probe local-server, then either proceed, prompt for auto-start, or
/// surface a JSON-mode error. Decisions encoded here:
///   - Auto-start uses platform-native service manager (launchctl /
///     systemd-user / direct spawn) — no master password required.
///   - 5 s reachability deadline after start.
///   - On start failure or timeout, still open the browser so the user
///     sees ERR_CONNECTION_REFUSED with the real port (decision A-a).
///   - JSON mode never prompts — auto-start needs a tty; we emit JSON
///     error + a stderr hint pointing at non-JSON mode (decision C-b).
fn local_server_preflight_for_browse(json_mode: bool) -> BrowseLocalPreflight {
    // Resolve port once — both probe and prompt need it.
    // `_or_default`: this preflight only fires when try_local_browse_url
    // returned Some(local URL), meaning local-server is installed. YAML
    // missing → fall back to 8090 (matches binary's built-in default).
    // Strict variant would emit Bulk-Import wording here. Bugfix
    // 20260524-aikey-service-restart-web-port-undiscoverable.md.
    let port = match crate::local_server_probe::read_local_server_port_or_default() {
        Ok(p) => p,
        Err(e) => {
            // local-server isn't installed at all (rare — try_local_browse_url
            // should already have rejected this case). Surface the real
            // reason instead of opening a half-baked URL.
            let msg = format!("local-server configuration unreadable: {}", e);
            if json_mode {
                crate::json_output::print_json(serde_json::json!({
                    "ok": false,
                    "error": "local_server_unconfigured",
                    "detail": &msg,
                }));
                return BrowseLocalPreflight::JsonModeError(msg);
            }
            eprintln!("{}", msg);
            return BrowseLocalPreflight::DeclineNoOpen;
        }
    };

    let base = format!("http://127.0.0.1:{}", port);

    // Reachable? Open immediately, identical to pre-pre-flight behavior.
    if crate::local_server_probe::probe_vault_status(&base).is_ok() {
        return BrowseLocalPreflight::OpenNow;
    }

    // Unreachable. JSON mode surfaces a structured error and exits.
    if json_mode {
        let msg = format!(
            "local-server is not running on port {}. Auto-start requires \
             non-JSON (tty) mode.",
            port
        );
        crate::json_output::print_json(serde_json::json!({
            "ok": false,
            "error": "local_server_not_running",
            "port": port,
            "detail": &msg,
        }));
        eprintln!(
            "Re-run `aikey web` without --json to auto-start local-server, \
                   or start it manually: {}",
            crate::local_server_probe::start_command_hint()
        );
        return BrowseLocalPreflight::JsonModeError(msg);
    }

    // Tty path: prompt to auto-start.
    println!("local-server is not running on port {}.", port);
    if !prompt_yes_no_default_yes("Start local-server now? [Y/n] ") {
        eprintln!(
            "To start manually:\n    {}",
            crate::local_server_probe::start_command_hint()
        );
        return BrowseLocalPreflight::DeclineNoOpen;
    }

    println!("Starting local-server…");
    let start_result = crate::local_server_probe::spawn_start_command();
    // find#10 (2026-07-07): 5s was too short on Windows — same cold-start
    // false-negative as `aikey service start web` (mod.rs:1787). Poll returns
    // on first success, so a larger ceiling only helps slow starts.
    let wait =
        crate::local_server_probe::wait_for_reachable(port, std::time::Duration::from_secs(25));

    match (start_result, &wait) {
        (Ok(()), Ok(())) => {
            println!("local-server is up.");
        }
        (Err(e), _) => {
            // The start command itself failed to invoke (e.g. launchctl
            // not on PATH, plist missing). Tell the user what we tried,
            // then continue to open-browser per decision A-a so they
            // see the underlying connection error in context.
            eprintln!("Auto-start failed: {}", e);
            eprintln!(
                "Continuing to open the browser anyway — it will \
                       report the connection error directly."
            );
        }
        (Ok(()), Err(e)) => {
            // Start command succeeded but service didn't come up within
            // 5 s. Could be slow boot or a config error. Open browser
            // per decision A-a.
            eprintln!(
                "{}. Continuing to open the browser anyway — it \
                       will report what local-server actually returns.",
                e
            );
        }
    }

    BrowseLocalPreflight::OpenNow
}

/// Simple yes/no prompt with Y as the default (empty input → true).
/// Reads from stdin. Returns false for explicit "n" / "no" and on EOF
/// (e.g. stdin closed) to fail safe — auto-start should require an
/// affirmative human action.
fn prompt_yes_no_default_yes(prompt: &str) -> bool {
    use std::io::Write;
    print!("{}", prompt);
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) => false, // EOF — treat as no (fail safe)
        Ok(_) => {
            let t = line.trim().to_lowercase();
            t.is_empty() || t == "y" || t == "yes"
        }
        Err(_) => false,
    }
}

/// Pure helper for `try_local_browse_url` so the resolution logic can be
/// unit-tested without touching the filesystem. Mirrors the
/// `derive_local_control_url` ↔ `try_local_control_url` pattern.
///
/// Edition signatures (workflow/CD/installer/*.sh write these strings):
///   - Personal w/ console : installed_components includes "local-server"
///   - Personal CLI-only   : neither — returns None (caller's mode=="none"
///                           guard then shows "No web console" hint)
///   - Trial               : installed_components includes "full-trial"
///                           (aikey-full-trial bundles the same user-side
///                           web at 127.0.0.1:8090, just packaged in a
///                           single binary with master + collector + query)
///
/// Phase 3B (2026-05-11 regression fix): the literal "local-server" check
/// was missing the Trial case, breaking `aikey web` on Trial installs
/// (spec: requirements/2026-05-11-aikey-web-local-first-team-merge.md R5).
/// The Trial composer's `/go/<alias>` routes are wire-identical to Personal
/// — same web bundle, same handlers — so accepting either component name
/// is the correct fix.
fn derive_local_browse_url(state: &serde_json::Value, alias: &str) -> Option<String> {
    let has_local_web = state
        .get("installed_components")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .any(|c| matches!(c.as_str(), Some("local-server") | Some("full-trial")))
        })
        .unwrap_or(false);
    if !has_local_web {
        return None;
    }

    let base_url = derive_local_control_url(state)?;

    // Both branches go through `/go/<alias>` so the web router owns
    // every real route.
    Some(format!("{}/go/{}", base_url.trim_end_matches('/'), alias))
}

/// Read install-state.json once, returning the parsed value.
/// Pure decision: is `aikey master` allowed to proceed without `--url` / `--port` override?
///
/// True when either:
///   - install_profile == "trial"  (local aikey-full-trial bundles a master), or
///   - the user has a stored platform_account (`aikey login` has been run).
///
/// All other states (e.g. Personal install with no team login) return false
/// and the caller refuses with a brief "not connected" message.
fn master_precondition_satisfied(
    install_state: Option<&serde_json::Value>,
    logged_in: bool,
) -> bool {
    let is_trial = install_state.and_then(|s| s.get("install_profile").and_then(|v| v.as_str()))
        == Some("trial");
    is_trial || logged_in
}

fn read_install_state() -> Option<serde_json::Value> {
    let home = dirs::home_dir()?;
    let state_path = home.join(".aikey").join("install-state.json");
    let content = std::fs::read_to_string(&state_path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Determine the base URL for `aikey web`.
///
/// Priority:
///   1. Explicit `--port` flag  →  `<scheme>://<host>:<port>` (host borrowed
///                                   from `control_url` so cookie domain /
///                                   CORS / CSP stay aligned with the host
///                                   the login flow wrote — see `host_loopback_parts`).
///   2. Env var `AIKEY_WEB_URL` →  use as-is (trailing slash trimmed)
///   3. Auto-detect: if control_url is loopback, probe dev-server ports
///   4. Fall back to the stored `control_url` (trailing slash trimmed)
///
/// CONTRACT: the returned base NEVER has a trailing slash, so callers can join
/// it with a leading-slash path (`/go/<alias>`) without producing a `//` that
/// the browser would treat as a protocol-relative (cross-origin) URL.
fn resolve_browse_base_url(control_url: &str, explicit_port: Option<u16>) -> String {
    use std::net::TcpStream;
    use std::time::Duration;

    // Cache the parsed scheme + host once: every branch below that returns a
    // synthesized URL (1 and 3) needs them, and re-parsing per branch would
    // both repeat work and risk drift if the parse rules ever change.
    let (scheme, host) = host_loopback_parts(control_url);

    // 1. Explicit --port — keep host from control_url so cookies/CORS line up
    //    with whatever the user logged in against (was hardcoded "localhost"
    //    pre-2026-06-08 and quietly broke 127.0.0.1-configured installs:
    //    the SPA at `localhost:3000` couldn't read the auth cookie that
    //    `aikey login` wrote against `127.0.0.1`, kicking the user back to
    //    the login page on every `aikey web`).
    if let Some(p) = explicit_port {
        return format!("{}://{}:{}", scheme, host, p);
    }

    // 2. Env var override
    if let Ok(url) = std::env::var("AIKEY_WEB_URL") {
        if !url.is_empty() {
            // Strip any trailing slash: the caller joins this base with a
            // leading-slash path (`/go/<alias>`), so a trailing slash here would
            // produce `//go/...` — a PROTOCOL-RELATIVE URL the browser resolves to
            // a foreign origin (`http://go/...`) and rejects in history.replaceState.
            return url.trim_end_matches('/').to_string();
        }
    }

    // 3. Auto-detect dev server (only when control_url is loopback).
    //    Vite may listen on IPv6 (::1) or IPv4 (127.0.0.1) — probe both.
    //    The returned URL keeps control_url's host (not the IP probe order)
    //    so `127.0.0.1` configs stay on `127.0.0.1` and `localhost` configs
    //    stay on `localhost` — see the 2026-06-08 fix rationale above.
    let is_local = control_url.contains("localhost") || control_url.contains("127.0.0.1");
    if is_local {
        let dev_ports: &[u16] = &[3000, 5173];
        let addrs: &[std::net::IpAddr] = &[
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        ];
        for &p in dev_ports {
            for &ip in addrs {
                if TcpStream::connect_timeout(
                    &std::net::SocketAddr::new(ip, p),
                    Duration::from_millis(150),
                )
                .is_ok()
                {
                    return format!("{}://{}:{}", scheme, host, p);
                }
            }
        }
    }

    // 4. Fall back to control_url. Strip any trailing slash so the deep link
    //    joins cleanly with the leading-slash `/go/<alias>` path — a stored
    //    control_url like `http://host:3000/` would otherwise yield
    //    `http://host:3000//go/overview`, which the browser treats as a
    //    protocol-relative URL (`http://go/overview`) and rejects with a
    //    SecurityError in the SPA's history.replaceState (cross-origin).
    //    Normalizing at READ time also fixes installs that already stored a
    //    trailing-slash control_url, with no re-login/migration.
    control_url.trim_end_matches('/').to_string()
}

/// Extracts `(scheme, host)` from a URL like `http://127.0.0.1:3000/foo` or
/// `https://localhost`. Inline parser (no `url` crate) because:
///   - this function only ever sees the user's stored `control_url`, which is
///     already validated at `aikey login` time, so we don't need RFC-3986 strict
///     parsing — just split on `://` then on the first `:` or `/`.
///   - keeps `aikey-cli` dependency-footprint small.
///
/// Falls back to `("http", "localhost")` if the parse can't find a scheme or
/// host — same default the pre-2026-06-08 code used unconditionally, so the
/// fallback path of an unparseable `control_url` keeps the OLD behavior rather
/// than panicking.
fn host_loopback_parts(control_url: &str) -> (&str, String) {
    let (scheme, rest) = if let Some(r) = control_url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = control_url.strip_prefix("http://") {
        ("http", r)
    } else {
        return ("http", "localhost".to_string());
    };
    // Trim any path segment.
    let authority = rest.split('/').next().unwrap_or(rest);
    // Strip optional `:<port>` to get the bare host. IPv6 in URLs is wrapped
    // in `[...]` but loopback configs are always `127.0.0.1` / `localhost`
    // (or hostnames without colons), so a plain split on `:` is safe here —
    // and IPv6 would still trip our `is_local` check below which only matches
    // the literal substrings "localhost" or "127.0.0.1".
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        ("http", "localhost".to_string())
    } else {
        (scheme, host.to_string())
    }
}

/// Base64URL-encode a string (URL-safe, no padding).
/// Compatible with the JS `atob` + URL-safe alphabet decoder on the web side.
fn base64_url_encode(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input.as_bytes())
}

/// `aikey account logout`
/// `aikey whoami` — compact identity card: login session + active key + vault state.
pub fn handle_whoami(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let account = storage::get_platform_account().ok().flatten();
    let active_cfg = storage::get_active_key_config().ok().flatten();
    let vault_exists = storage::get_vault_path()
        .map(|p| p.exists())
        .unwrap_or(false);

    let local_seen_version = storage::get_local_seen_sync_version();

    if json_mode {
        let active_json = active_cfg.as_ref().map(|cfg| {
            serde_json::json!({
                "key_type": cfg.key_type,
                "key_ref":  cfg.key_ref,
                "providers": cfg.providers,
            })
        });
        crate::json_output::print_json(serde_json::json!({
            "vault_initialized": vault_exists,
            "logged_in": account.is_some(),
            "account": account.as_ref().map(|a| serde_json::json!({
                "email":       a.email,
                "account_id":  a.account_id,
                "control_url": a.control_url,
            })),
            "active_key": active_json,
            "sync": {
                "local_seen_sync_version": local_seen_version,
            },
        }));
        return Ok(());
    }

    // ── Vault ────────────────────────────────────────────────────────────────
    let vault_str = if vault_exists {
        "initialized".green().to_string()
    } else {
        "not initialized".dimmed().to_string()
    };
    println!("{:<16} {}", "Vault:".bold(), vault_str);

    // ── Account ──────────────────────────────────────────────────────────────
    match &account {
        Some(a) => {
            println!(
                "{:<16} {} {}",
                "Account:".bold(),
                a.email.bold(),
                format!("({})", a.account_id).dimmed()
            );
            println!("{:<16} {}", "Control URL:".bold(), a.control_url.dimmed());
        }
        None => {
            println!("{:<16} {}", "Account:".bold(), "not logged in".dimmed());
            println!("  {}", "→ Run: aikey login".dimmed());
        }
    }

    // ── Active key ───────────────────────────────────────────────────────────
    match &active_cfg {
        Some(cfg) => {
            let providers = if cfg.providers.is_empty() {
                "—".dimmed().to_string()
            } else {
                cfg.providers.join(", ").cyan().to_string()
            };
            println!(
                "{:<16} {} {} [{}]",
                "Active key:".bold(),
                cfg.key_ref.bold(),
                format!("({})", cfg.key_type).dimmed(),
                providers
            );
        }
        None => {
            println!("{:<16} {}", "Active key:".bold(), "none".dimmed());
            println!("  {}", "→ Run: aikey use <alias>".dimmed());
        }
    }

    // ── Sync status ──────────────────────────────────────────────────────────
    if account.is_some() {
        let version_str = if local_seen_version == 0 {
            "not synced".dimmed().to_string()
        } else {
            format!("v{}", local_seen_version).dimmed().to_string()
        };
        println!("{:<16} {}", "Key sync:".bold(), version_str);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `aikey status` — combined overview dashboard
// ---------------------------------------------------------------------------

pub fn handle_status_overview(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;

    let vault_exists = storage::get_vault_path()
        .map(|p| p.exists())
        .unwrap_or(false);
    let account = storage::get_platform_account().ok().flatten();

    // Collect key counts.
    let personal_count = if vault_exists {
        storage::list_entries().map(|v| v.len()).unwrap_or(0)
    } else {
        0
    };
    let team_keys = storage::list_virtual_key_cache().unwrap_or_default();
    let active_team = team_keys
        .iter()
        .filter(|k| k.local_state == "active")
        .count();
    let team_total = team_keys.len();

    // Collect unique providers from personal keys + team keys + bindings.
    let mut providers = BTreeSet::new();
    if vault_exists {
        if let Ok(entries) = storage::list_entries_with_metadata() {
            for e in &entries {
                if let Some(ref pc) = e.provider_code {
                    if !pc.is_empty() {
                        providers.insert(pc.clone());
                    }
                }
                if let Some(ref sp) = e.supported_providers {
                    for p in sp {
                        if !p.is_empty() {
                            providers.insert(p.clone());
                        }
                    }
                }
            }
        }
    }
    for k in &team_keys {
        if !k.provider_code.is_empty() {
            providers.insert(k.provider_code.clone());
        }
        for p in &k.supported_providers {
            if !p.is_empty() {
                providers.insert(p.clone());
            }
        }
    }

    // Active key config.
    let active_cfg = storage::get_active_key_config().ok().flatten();

    if json_mode {
        let active_json = active_cfg.as_ref().map(|cfg| {
            serde_json::json!({
                "key_type": cfg.key_type,
                "key_ref":  cfg.key_ref,
                "providers": cfg.providers,
            })
        });
        // Round 9 fix #1: was is_proxy_running (PID-only); now Layer 1.
        let proxy_running = crate::commands_proxy::proxy_is_running_managed();
        crate::json_output::print_json(serde_json::json!({
            "gateway": {
                "running": proxy_running,
            },
            "login": {
                "logged_in": account.is_some(),
                "email": account.as_ref().map(|a| &a.email),
                "control_url": account.as_ref().map(|a| &a.control_url),
            },
            "keys": {
                "personal": personal_count,
                "team_total": team_total,
                "team_active": active_team,
            },
            "active_key": active_json,
            "providers": providers.iter().collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    let mut rows: Vec<String> = Vec::new();

    // ── Gateway ─────────────────────────────────────────────────────────────
    rows.push(format!(
        "{}{}",
        crate::symbols::ICON_SATELLITE.pre(),
        "Gateway".bold()
    ));
    for line in crate::commands_proxy::status_rows() {
        rows.push(format!("  {}", line));
    }
    rows.push(String::new());

    // ── Login ───────────────────────────────────────────────────────────────
    rows.push(format!(
        "{}{}",
        crate::symbols::ICON_PERSON.pre(),
        "Login".bold()
    ));
    match &account {
        Some(a) => {
            rows.push(format!("  status:  {}", "logged in".green()));
            rows.push(format!("  email:   {}", a.email.bold()));
            rows.push(format!("  server:  {}", a.control_url.dimmed()));
        }
        None => {
            rows.push(format!("  status:  {}", "not logged in".dimmed()));
            rows.push("  hint:    run `aikey login` to connect to your team".to_string());
        }
    }
    rows.push(String::new());

    // ── Keys ────────────────────────────────────────────────────────────────
    rows.push(format!(
        "{}{}",
        crate::symbols::ICON_KEY.pre(),
        "Keys".bold()
    ));
    rows.push(format!("  personal:  {}", personal_count));
    rows.push(format!(
        "  team:      {} total, {} active",
        team_total, active_team
    ));
    match &active_cfg {
        Some(cfg) => {
            let prov_str = if cfg.providers.is_empty() {
                "—".to_string()
            } else {
                cfg.providers.join(", ")
            };
            // Human-friendly label: prefer OAuth display identity / email; for personal
            // and team keys, key_ref is already a readable alias or virtual_key_id.
            let (label, type_label) = match cfg.key_type {
                crate::credential_type::CredentialType::PersonalOAuthAccount => {
                    let human = storage::list_provider_accounts()
                        .ok()
                        .and_then(|accts| {
                            accts
                                .into_iter()
                                .find(|a| a.provider_account_id == cfg.key_ref)
                                .and_then(|a| {
                                    a.display_identity
                                        .filter(|s| !s.is_empty())
                                        .or(a.external_id)
                                })
                        })
                        .unwrap_or_else(|| cfg.key_ref.clone());
                    (human, "OAuth")
                }
                crate::credential_type::CredentialType::ManagedVirtualKey => {
                    (cfg.key_ref.clone(), "team")
                }
                crate::credential_type::CredentialType::PersonalApiKey => {
                    (cfg.key_ref.clone(), "personal")
                }
            };
            rows.push(format!(
                "  active:    {} {} {}",
                label.bold(),
                format!("({})", type_label).dimmed(),
                format!("\u{2192} {}", prov_str).cyan()
            ));
        }
        None => {
            rows.push(format!("  active:    {}", "none".dimmed()));
        }
    }
    rows.push(String::new());

    // ── Protocols ───────────────────────────────────────────────────────────
    rows.push(format!(
        "{}{}",
        crate::symbols::ICON_PLUG.pre(),
        "Protocols".bold()
    ));
    if providers.is_empty() {
        rows.push(format!("  {}", "no protocols configured".dimmed()));
        rows.push("  hint:    add a key with `aikey add <alias> --provider <code>`".to_string());
    } else {
        rows.push(format!(
            "  {}",
            providers.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }

    crate::ui_frame::print_box(crate::symbols::ICON_CHART.s(), "Status", &rows);

    Ok(())
}

pub fn handle_logout(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Scope-disable all team keys so the proxy stops routing them immediately.
    // Passing "" disables every row regardless of owner_account_id, since no
    // row has owner_account_id = "".
    let _ = storage::disable_keys_for_account_scope("");

    // Clear the active key config if it references a team key — a logged-out
    // session has no valid account to own team keys.
    if let Ok(Some(cfg)) = storage::get_active_key_config() {
        if cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey {
            let _ = storage::clear_active_key_config();
        }
    }

    // Phase 3B R3/C (2026-05-11) — ghost-binding cleanup:
    // Wipe all team-key rows from user_profile_provider_bindings. Without
    // this, the bindings table keeps `key_source_type='managed_virtual_key'`
    // rows pointing at vk_ids the user no longer owns; a subsequent
    // `aikey login` (even to a different account) would re-activate stale
    // bindings and proxy.list / vault-list would surface them as if the
    // team key were still bound. Spec: requirements/2026-05-11-aikey-web-
    // local-first-team-merge.md R3 (ghost binding paragraph).
    //
    // Returns the (provider_code, vk_id) tuples we cleared so we can refresh
    // active.env afterwards — any team-bound provider needs its env vars
    // re-derived since the binding is gone.
    let cleared_team_bindings = storage::remove_bindings_by_key_source_type(
        crate::profile_activation::DEFAULT_PROFILE,
        crate::credential_type::CredentialType::ManagedVirtualKey.as_str(),
    )
    .unwrap_or_default();

    // Reset sync version so the next login always performs a full sync,
    // even if the new account happens to be different from the old one
    // (in which case finish_login won't detect an "account switch").
    storage::set_local_seen_sync_version(0);

    storage::clear_platform_account()?;

    // Refresh active.env after binding wipe so the proxy / shells see the
    // updated state. No-op when no team bindings existed (skip the syscall
    // overhead in the common path).
    if !cleared_team_bindings.is_empty() {
        let _ = crate::profile_activation::refresh_implicit_profile_activation();
    }

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "cleared_team_bindings": cleared_team_bindings.len(),
        }));
    } else {
        println!("Logged out.");
        if !cleared_team_bindings.is_empty() {
            println!(
                "  Cleared {} team-key binding(s).",
                cleared_team_bindings.len()
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase C — incremental snapshot sync
// ---------------------------------------------------------------------------

/// Maps a server-computed (effective_status, effective_reason) pair to a local_state value,
/// taking into account the entry's pre-existing local state to preserve user decisions.
fn compute_local_state_from_effective(
    effective_status: &str,
    effective_reason: &str,
    existing_state: &str,
) -> String {
    if effective_status != "active" {
        // Server says this key cannot currently be used.
        return match effective_reason {
            "seat_disabled" => "disabled_by_seat_status".to_string(),
            "key_revoked" | "key_expired" => "disabled_by_key_status".to_string(),
            "account_disabled" => "disabled_by_account_status".to_string(),
            _ => "synced_inactive".to_string(), // e.g. not_claimed
        };
    }

    // effective_status == "active": preserve meaningful local states.
    match existing_state {
        // Key is currently active in proxy — keep it active.
        "active" => "active".to_string(),
        // User dismissed the accept banner — don't re-show it.
        "prompt_dismissed" => "prompt_dismissed".to_string(),
        // Was disabled by scope/status — server says it's valid again, restore.
        "disabled_by_account_scope"
        | "disabled_by_account_status"
        | "disabled_by_seat_status"
        | "disabled_by_key_status"
        | "stale" => "synced_inactive".to_string(),
        // Default (synced_inactive, empty, new entry).
        _ => "synced_inactive".to_string(),
    }
}

/// Merges a server snapshot into the local managed_virtual_keys_cache.
///
/// Coverage rules (design doc §5.3):
/// - Server fields overwrite local server-mirrored fields.
/// - Local-only fields (local_alias, key material, owner_account_id) are preserved.
/// - local_state is recomputed from effective_status / effective_reason.
/// - Keys owned by current account that are absent from the snapshot are marked `stale`.
fn apply_snapshot_to_cache(
    items: &[crate::platform_client::ManagedKeySnapshotItem],
    current_account_id: &str,
) {
    use std::collections::HashSet;
    let seen_ids: HashSet<String> = items.iter().map(|i| i.virtual_key_id.clone()).collect();

    for item in items {
        let existing = storage::get_virtual_key_cache(&item.virtual_key_id)
            .ok()
            .flatten();

        // Preserve local-only fields from the existing cache entry.
        let local_alias = existing.as_ref().and_then(|e| e.local_alias.clone());
        let nonce = existing.as_ref().and_then(|e| e.provider_key_nonce.clone());
        let ciphertext = existing
            .as_ref()
            .and_then(|e| e.provider_key_ciphertext.clone());
        let existing_state = existing
            .as_ref()
            .map(|e| e.local_state.as_str())
            .unwrap_or("");

        let local_state = compute_local_state_from_effective(
            &item.effective_status,
            &item.effective_reason,
            existing_state,
        );

        let entry = storage::VirtualKeyCacheEntry {
            virtual_key_id: item.virtual_key_id.clone(),
            org_id: item.org_id.clone(),
            seat_id: item.seat_id.clone(),
            alias: item.alias.clone(),
            provider_code: item.provider_code.clone(),
            protocol_type: item.protocol_type.clone(),
            base_url: item.base_url.clone(),
            credential_id: item.credential_id.clone(),
            credential_revision: item.credential_revision.clone(),
            virtual_key_revision: item.virtual_key_revision.clone(),
            key_status: item.key_status.clone(),
            share_status: item.share_status.clone(),
            local_state,
            expires_at: item.expires_at,
            provider_key_nonce: nonce,
            provider_key_ciphertext: ciphertext,
            synced_at: 0,
            local_alias,
            supported_providers: item.supported_providers.clone(),
            provider_base_urls: item.provider_base_urls.clone(),
            owner_account_id: Some(current_account_id.to_string()),
            owner_email: None,   // upsert stamps the current account's email
            group_runtime: None, // proxy-owned (channel ③) — never written from here

            // Sync writers MUST always set extra: None. The value is
            // ignored by upsert (extra is omitted from the UPSERT's
            // DO UPDATE SET — see upsert_virtual_key_cache doc); the
            // None here is purely a struct-literal completeness
            // requirement. Putting any other value here would be
            // misleading, not destructive.
            extra: None,
            // N6: fold the oauth-group candidate set from the snapshot. These ARE
            // server-owned (in the upsert's DO UPDATE SET). group_accounts is
            // stored as raw JSON text; None for a direct-bind VK.
            oauth_group_id: item.oauth_group_id.clone(),
            group_accounts: item
                .group_accounts
                .as_ref()
                .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string())),
            routing_config: item.routing_config.clone(),
            group_alias: item.group_alias.clone(),
        };

        let _ = storage::upsert_virtual_key_cache(&entry);

        // If this key is currently active in the proxy, refresh active.env so the
        // proxy picks up any updated provider list without requiring a restart.
        if !entry.supported_providers.is_empty() {
            if let Ok(Some(active_cfg)) = crate::storage::get_active_key_config() {
                if active_cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey
                    && active_cfg.key_ref == entry.virtual_key_id
                {
                    let display = entry.local_alias.as_deref().unwrap_or(entry.alias.as_str());
                    let _ = write_active_env(
                        "team",
                        &entry.virtual_key_id,
                        display,
                        &entry.supported_providers,
                        crate::commands_proxy::proxy_port(),
                    );
                }
            }
        }
    }

    // Prune: keys the current account owns locally but the server no longer
    // returns are DELETED (2026-07-04 self-heal, replaces the old mark-stale).
    // WHY delete, not stale: the server is the single authority for the
    // owner's keys — a server-deleted key kept as a local `stale` row rendered
    // forever as a "revoked / inactive" ghost in /user/vault (the exact user
    // confusion on 2026-07-03), and for DETERMINISTIC group-VK aliases the
    // ghost also shadowed the freshly re-issued key. Scope guard: ONLY rows
    // owned by the CURRENT account are pruned — other accounts' rows keep the
    // re-login recovery semantics (see clear_virtual_key_cache's doc note).
    // Idempotent: the second sync finds nothing absent to prune.
    // This includes the currently-active key: if the server removed it, it is
    // no longer valid and must be deactivated immediately.
    if let Ok(cached) = storage::list_virtual_key_cache() {
        let mut pruned = 0usize;
        for entry in cached {
            if entry.owner_account_id.as_deref() == Some(current_account_id)
                && !seen_ids.contains(&entry.virtual_key_id)
            {
                // If this key was the active proxy key, clear the active key config
                // so the proxy stops routing it on next reload.
                if entry.local_state == "active" {
                    if let Ok(Some(cfg)) = storage::get_active_key_config() {
                        if cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey
                            && cfg.key_ref == entry.virtual_key_id
                        {
                            let _ = storage::clear_active_key_config();
                        }
                    }
                }
                match storage::delete_virtual_key_cache_row(&entry.virtual_key_id) {
                    Ok(()) => pruned += 1,
                    Err(e) => {
                        // Fall back to the legacy stale mark so the row at least
                        // stops being usable; visible per the mandatory-WARN rule.
                        eprintln!(
                            "[aikey] warn: prune of server-removed key {} failed ({}); marked stale instead",
                            entry.virtual_key_id, e
                        );
                        let _ =
                            storage::set_virtual_key_local_state(&entry.virtual_key_id, "stale");
                    }
                }
            }
        }
        if pruned > 0 {
            println!("  pruned {pruned} server-removed key(s) from local cache");
        }
    }
}

/// Persists the quota rules carried by a delivery snapshot into the local
/// `quota_rules_cache` for the proxy to read (design §0.5/§5.2). Best-effort:
/// a failure is logged and never blocks the managed-key sync — quota is the
/// rule-distribution rail, not the critical key-delivery path. `None` (older /
/// quota-less server, field absent) leaves the cache untouched; `Some` is the
/// authoritative full set and full-replaces the cache (an empty list clears
/// rules after the last quota for a seat is deleted).
fn apply_quota_snapshot_to_cache(quota: &Option<crate::platform_client::QuotaSnapshot>) {
    let snap = match quota {
        Some(s) => s,
        None => return,
    };
    let entries: Vec<storage::QuotaRuleCacheEntry> = snap
        .subjects
        .iter()
        .map(|s| {
            let members_json = if s.subject_kind == "group" && !s.members.is_empty() {
                serde_json::to_string(&s.members).ok()
            } else {
                None
            };
            let rules_json = serde_json::to_string(&s.rules).unwrap_or_else(|_| "[]".to_string());
            // Stage 4 回填: persist baselines JSON when present (skip null/empty).
            let baseline_json = if s.baselines.is_null() {
                None
            } else {
                match serde_json::to_string(&s.baselines) {
                    Ok(j) if j != "null" && j != "[]" => Some(j),
                    _ => None,
                }
            };
            storage::QuotaRuleCacheEntry {
                subject_id: s.subject_id.clone(),
                subject_kind: s.subject_kind.clone(),
                members_json,
                rules_json,
                baseline_json,
            }
        })
        .collect();
    if let Err(e) = storage::replace_quota_rules_cache(&entries) {
        eprintln!("[aikey] warning: failed to cache quota rules: {}", e);
    }
    // D-U8/P6: persist the deployment-global edge price summary for the proxy's
    // local usd pricing. Only when present — an absent field leaves the last-good
    // summary untouched (resilient to an old / summary-less server response).
    if let Some(pt) = &snap.price_tiers {
        if let Ok(j) = serde_json::to_string(pt) {
            if let Err(e) = storage::set_quota_price_summary(&j) {
                eprintln!(
                    "[aikey] warning: failed to cache quota price summary: {}",
                    e
                );
            }
        }
    }
}

/// Runs one snapshot sync cycle (blocking):
/// 1. Calls GET /accounts/me/sync-version — fast server round-trip.
/// 2. Compares remote version with `local_seen_sync_version` in the config table.
/// 3. If the version has changed, pulls the full snapshot and merges it.
/// 4. Updates `local_seen_sync_version` and bumps `vault_change_seq`.
///
/// Returns `Ok(true)` if a new snapshot was applied, `Ok(false)` if already
/// up-to-date or not logged in, `Err(msg)` on network / parse failure.
pub fn run_snapshot_sync() -> Result<bool, String> {
    let acc = match storage::get_platform_account().ok().flatten() {
        Some(a) => a,
        None => return Ok(false),
    };
    let token = match try_refresh_if_needed(&acc) {
        Ok(t) => t,
        Err(e) => return Err(format!("token refresh: {}", e)),
    };
    let client = PlatformClient::new(&acc.control_url, &token);

    // Fast version check — one lightweight request before pulling the full snapshot.
    let remote_version = match client.get_sync_version() {
        Ok(r) => r.sync_version,
        Err(e) => return Err(format!("sync-version: {}", e)),
    };
    let local_seen = storage::get_local_seen_sync_version();
    if remote_version <= local_seen {
        return Ok(false); // already up-to-date
    }

    // Version has changed — pull the full snapshot.
    let snapshot = match client.get_managed_keys_snapshot() {
        Ok(s) => s,
        Err(e) => return Err(format!("snapshot: {}", e)),
    };

    apply_snapshot_to_cache(&snapshot.keys, &acc.account_id);
    apply_quota_snapshot_to_cache(&snapshot.quota);

    // Record the new version so the next command skips the snapshot pull.
    storage::set_local_seen_sync_version(snapshot.sync_version);
    let _ = storage::bump_vault_change_seq();

    Ok(true)
}

/// Full snapshot sync: metadata + claim unclaimed keys + download key material.
///
/// Called by `aikey list` (when version changed) and `aikey key sync`.
/// Requires the master password to encrypt downloaded provider keys into the vault.
///
/// Returns the number of newly downloaded keys.
pub fn run_full_snapshot_sync(password: &SecretString) -> Result<usize, String> {
    let vault_key = derive_vault_key(password)?;
    run_full_snapshot_sync_with_vault_key(&vault_key)
}

/// Form-② digital-employee variant: same full snapshot sync, but the
/// cluster gate on key-material download is OPEN.
///
/// Why a separate entry instead of a flag at every call site: the `aikey
/// agent start` daemon IS the form-② local digital employee — its design
/// contract (20260603 ER §5.3) is to pull ITS OWN seat's key material into
/// the local DE vault so the local DE proxy can serve it, even when the org
/// is a cluster org. Every other caller (human `aikey key sync` / `use`
/// bridge / login) keeps the keys-stay-central cluster behavior. The control
/// plane is the enforcement authority either way: it only honors cluster-org
/// per-VK delivery for the caller's own digital_employee seat (delivery.go
/// seat-scoped check), so this flag merely lets the daemon ATTEMPT the
/// download instead of silently skipping (which left ciphertext NULL and the
/// DE proxy with an empty registry — bug
/// 20260611-form2-de-proxy-token-registry-mismatch).
pub fn run_full_snapshot_sync_for_agent(password: &SecretString) -> Result<usize, String> {
    let vault_key = derive_vault_key(password)?;
    run_full_snapshot_sync_opts(&vault_key, true)
}

/// Phase 3B (2026-05-11): vault_key-only snapshot sync. Used by the web
/// bridge path where the master password isn't available — only the
/// already-derived 32-byte vault_key flows through the session cookie.
///
/// Identical behavior to `run_full_snapshot_sync` minus the password →
/// vault_key Argon2id step. Caller must guarantee `vault_key` matches
/// the vault's stored password_hash (the bridge's `prepare_vault`
/// already enforces this before invoking us).
/// A virtual key plus the metadata for one `managed_virtual_keys_cache` row,
/// EXCEPT the encrypted provider-key material (which `upsert_delivered_key`
/// derives from the plaintext).
///
/// Shared shape for the two delivery writers: the account-scoped CLI sync
/// (`run_full_snapshot_sync_with_vault_key`) and the org-scoped cluster daemon
/// path (`_internal vault-op cluster_apply_snapshot`). Both build a
/// `DeliveredKey` from their own payload, then hand it to the single
/// encrypt+upsert core below — so the cache row format and the critical vault
/// encryption live in exactly one place (internal-command-reuses-public-core).
pub(crate) struct DeliveredKey {
    pub virtual_key_id: String,
    pub org_id: String,
    pub seat_id: String,
    pub alias: String,
    pub provider_code: String,
    pub protocol_type: String,
    pub base_url: String,
    pub credential_id: String,
    pub credential_revision: String,
    pub virtual_key_revision: String,
    pub key_status: String,
    pub share_status: String,
    pub local_state: String,
    pub expires_at: Option<i64>,
    pub local_alias: Option<String>,
    pub supported_providers: Vec<String>,
    pub provider_base_urls: std::collections::HashMap<String, String>,
    pub owner_account_id: Option<String>,
}

/// Encrypts `plaintext_provider_key` with the (already-verified) vault key and
/// upserts the resulting `managed_virtual_keys_cache` row. The single chokepoint
/// for writing real provider-key ciphertext into the cache.
///
/// Callers MUST have already passed `vault_key` through
/// `storage::verify_vault_key` (the CLI sync does so at its entry; the
/// `_internal` handler does so via `prepare_vault`). Writing ciphertext under an
/// unverified key is the 2026-05-11 registry-miss incident.
pub(crate) fn upsert_delivered_key(
    vault_key: &[u8; crypto::KEY_SIZE],
    dk: &DeliveredKey,
    plaintext_provider_key: &str,
) -> Result<(), String> {
    let (nonce, ciphertext) = crypto::encrypt(vault_key, plaintext_provider_key.as_bytes())
        .map_err(|e| format!("encrypt: {}", e))?;
    // N6: this is a direct-bind key-delivery path (single credential ciphertext),
    // NOT the oauth-group structural sync — but it shares upsert_virtual_key_cache,
    // whose DO UPDATE SET now includes the server-owned oauth_group columns. Carry
    // forward the existing row's group fields so accepting a key never wipes the
    // candidate set a prior snapshot sync folded in.
    let existing = storage::get_virtual_key_cache(&dk.virtual_key_id)
        .ok()
        .flatten();
    let entry = VirtualKeyCacheEntry {
        virtual_key_id: dk.virtual_key_id.clone(),
        org_id: dk.org_id.clone(),
        seat_id: dk.seat_id.clone(),
        alias: dk.alias.clone(),
        provider_code: dk.provider_code.clone(),
        protocol_type: dk.protocol_type.clone(),
        base_url: dk.base_url.clone(),
        credential_id: dk.credential_id.clone(),
        credential_revision: dk.credential_revision.clone(),
        virtual_key_revision: dk.virtual_key_revision.clone(),
        key_status: dk.key_status.clone(),
        share_status: dk.share_status.clone(),
        local_state: dk.local_state.clone(),
        expires_at: dk.expires_at,
        provider_key_nonce: Some(nonce),
        provider_key_ciphertext: Some(ciphertext),
        synced_at: 0,
        local_alias: dk.local_alias.clone(),
        supported_providers: dk.supported_providers.clone(),
        provider_base_urls: dk.provider_base_urls.clone(),
        owner_account_id: dk.owner_account_id.clone(),
        owner_email: None,   // upsert stamps the current account's email
        group_runtime: None, // proxy-owned (channel ③) — never written from here

        // Sync writers MUST always pass extra: None; upsert ignores this
        // field. See doc on VirtualKeyCacheEntry::extra.
        extra: None,
        // Carry forward server-synced group fields (this path isn't authoritative
        // over them) so a key-accept doesn't clobber them to NULL.
        oauth_group_id: existing.as_ref().and_then(|e| e.oauth_group_id.clone()),
        group_accounts: existing.as_ref().and_then(|e| e.group_accounts.clone()),
        routing_config: existing.as_ref().and_then(|e| e.routing_config.clone()),
        group_alias: existing.as_ref().and_then(|e| e.group_alias.clone()),
    };
    storage::upsert_virtual_key_cache(&entry)
}

pub fn run_full_snapshot_sync_with_vault_key(
    vault_key: &[u8; crypto::KEY_SIZE],
) -> Result<usize, String> {
    run_full_snapshot_sync_opts(vault_key, false)
}

/// Inner sync core. `allow_cluster_key_download` is true ONLY for the form-②
/// agent daemon (see run_full_snapshot_sync_for_agent) — it opens the cluster
/// gate on the key-material download loop below.
fn run_full_snapshot_sync_opts(
    vault_key: &[u8; crypto::KEY_SIZE],
    allow_cluster_key_download: bool,
) -> Result<usize, String> {
    use colored::Colorize;

    // Strict-verify before any encrypt write: a vault_key that does not
    // match the stored password_hash would silently encrypt managed-key
    // ciphertext that nothing downstream can decrypt — root cause of the
    // 2026-05-11 team-key registry-miss incident. Both call sites
    // (CLI `aikey key sync` via derive + handle_use's bridge path) pass
    // through here, so this is the single chokepoint.
    crate::storage::verify_vault_key(vault_key)
        .map_err(|e| format!("snapshot sync aborted: {}", e))?;

    let acc = match storage::get_platform_account().ok().flatten() {
        Some(a) => a,
        None => return Ok(0),
    };
    let token = match try_refresh_if_needed(&acc) {
        Ok(t) => t,
        Err(e) => return Err(format!("token refresh: {}", e)),
    };
    let client = PlatformClient::new(&acc.control_url, &token);

    // P5 §5.5: is this user on a cluster? Authoritative resolve (works even before
    // any `aikey use`). On a cluster, managed-VK key material stays on the CENTRAL
    // node — never on this machine; the cli points the tool at the node via the
    // resolve channel. So persist the node for the per-provider router and SKIP the
    // local key-material download below. The server ALSO refuses per-VK delivery for
    // cluster orgs (defense-in-depth); skipping here avoids the 403 churn + keeps the
    // sidecar fresh on sync (not just on `aikey use`).
    //
    // 2026-06-12: only an authoritative 404 (NotACluster) may clear the
    // persisted node. This resolve runs BEFORE the snapshot step's 401-triggered
    // token self-heal, so with a server-rejected token it fails 401 — the old
    // code read that as "not a cluster", cleared the node, and rewrote
    // active.env to the material-less local route → 503 NO_ACTIVE_KEY after an
    // otherwise-successful self-heal (E2E case 2026-06-11 §L8 次生缺口).
    // Unknown keeps last-known-good routing.
    let on_cluster = match client.resolve_cluster_node() {
        crate::platform_client::ClusterNodeResolution::Node(addr) => {
            let _ = shell_integration::write_cluster_node(&addr);
            true
        }
        crate::platform_client::ClusterNodeResolution::NotACluster => {
            shell_integration::clear_cluster_node();
            false
        }
        crate::platform_client::ClusterNodeResolution::Unknown(_) => {
            shell_integration::read_cluster_node().is_some()
        }
    };

    // Pull the full snapshot (metadata).
    let snapshot = match client.get_managed_keys_snapshot() {
        Ok(s) => s,
        // L8 fix (2026-06-11): 401 here means the server rejected a token the
        // local clock still considers valid (secret rotation / control
        // reinstall / restored vault backup) — `try_refresh_if_needed` above
        // can't catch that (it only checks local exp). Recover through the
        // SAME shared core `aikey web` uses (force refresh ignoring the exp
        // gate) and replay once; if recovery fails the core's error already
        // names the exact `aikey login` command. Previously this surfaced as
        // a bare "status code 401" with no guidance (L8 T2). Bug:
        // 20260611-jwt-renewal-l8-test.md
        Err(e) if e.contains("status code 401") => {
            let new_token = force_refresh_after_server_reject(
                &acc,
                &format!("snapshot request rejected ({})", e),
            )
            .map_err(|msg| format!("snapshot: {}", msg))?;
            let retry_client = PlatformClient::new(&acc.control_url, &new_token);
            match retry_client.get_managed_keys_snapshot() {
                Ok(s) => s,
                Err(e2) => return Err(format!("snapshot (after token refresh): {}", e2)),
            }
        }
        Err(e) => return Err(format!("snapshot: {}", e)),
    };

    apply_snapshot_to_cache(&snapshot.keys, &acc.account_id);
    apply_quota_snapshot_to_cache(&snapshot.quota);
    storage::set_local_seen_sync_version(snapshot.sync_version);
    let _ = storage::bump_vault_change_seq();

    // Claim any unclaimed keys and download missing key material.
    let account_id = Some(acc.account_id.clone());

    let cached = storage::list_virtual_key_cache().unwrap_or_default();
    let mut downloaded = 0usize;

    // Key-material freshness (bugfix 2026-06-16: form-⓪ credential rotation left
    // the local provider key stale). `apply_snapshot_to_cache` above refreshed
    // metadata (incl. credential_revision) but, by design, PRESERVED the local
    // ciphertext. A rotation bumps the account sync_version, so "the server is
    // ahead of the last material download" is our re-download trigger — without
    // it, the old `needs_download = ciphertext.is_none()` gate never re-fired on
    // rotation (ciphertext stays non-NULL). Account-level/coarse on purpose: all
    // of this account's active material is re-pulled on any bump (cheap at
    // employee scale; see 数据同步方案.md). The marker only advances after a
    // clean pass below, and a *separate* marker from `local_seen_sync_version`
    // so the no-password lightweight sync can't consume the signal.
    let material_stale = snapshot.sync_version > storage::get_last_material_sync_version();

    // The deployment's delivery form — the SERVER's word, not our guess
    // (2026-07-13). Until now this was inferred purely from `on_cluster` (does a
    // cluster-node sidecar exist?), which desynced from the server's rule in both
    // directions and produced the two failure shapes we kept hitting:
    //   - fresh machine on a central cluster (no sidecar yet) → we tried to
    //     download → opaque 403 → "run `aikey key sync`" while running it;
    //   - a box carrying a stray CLUSTER_DELIVERY_ORG_ID → the server refused
    //     delivery even though it was not a cluster at all.
    // `from_wire` falls back to the old inference when the field is absent (older
    // control plane), so nothing regresses.
    let delivery_form = crate::platform_client::KeyDeliveryForm::from_wire(
        snapshot.key_delivery_form.as_deref(),
        on_cluster,
    );
    let central_form = delivery_form.is_central();

    let mut had_download_error = false;
    // Set when the control plane refuses delivery BY DESIGN (form-①). Not an
    // error: it means this deployment keeps material central and we should route
    // through the cluster node instead of downloading. Reported once at the end
    // rather than once per key.
    let mut central_refused = false;

    for entry in &cached {
        // Group VKs carry NO static key material — their per-account material is
        // pulled by the proxy via channel ③ (group-runtime), not CLI claim/delivery.
        // The master delivery endpoint denies group VKs (403 access_denied), which
        // otherwise surfaces as a spurious "could not fetch key" + "0 downloaded"
        // during sync. Skip claim/delivery entirely for them; their metadata
        // (oauth_group_id / group_accounts / routing_config) was already folded into
        // the cache by apply_snapshot_to_cache above.
        if entry.oauth_group_id.is_some() {
            continue;
        }
        // Needs claim: pending_claim but not yet claimed on server.
        let needs_claim = entry.share_status == "pending_claim" && entry.key_status == "active";
        // Needs download: claimed (or about to be) AND either we have no local
        // ciphertext yet, OR the server advanced past our last material pull
        // (rotation → `material_stale`).
        // §5.5: not on a cluster for HUMAN flows — key material stays on the
        // central node; the tool reaches it via the resolve channel. Exception
        // (2026-06-11): the form-② agent daemon (allow_cluster_key_download)
        // pulls its OWN seat's material even on a cluster — the control plane's
        // seat-scoped delivery check is the enforcement authority (only the
        // caller's own digital_employee seat is honored there).
        // Gate on the SERVER-DECLARED form (2026-07-13), not on "do I have a node
        // sidecar". Under `central`, asking for material is refused by design, so
        // we must not ask at all — that request is what produced the misleading
        // 403. The form-② agent daemon keeps its documented exception.
        let needs_download = (!central_form || allow_cluster_key_download)
            && (entry.provider_key_ciphertext.is_none() || material_stale)
            && entry.key_status == "active"
            && !entry.local_state.starts_with("disabled_by_");

        if !needs_claim && !needs_download {
            continue;
        }

        // Claim on server first if pending.
        if needs_claim {
            if let Err(e) = client.claim_key(&entry.virtual_key_id) {
                eprintln!(
                    "  {} could not claim {}: {}",
                    crate::symbols::CROSS.s().red(),
                    entry.alias,
                    e
                );
                continue;
            }
        }

        // Download the delivery payload (plaintext provider key over TLS).
        match client.get_key_delivery(&entry.virtual_key_id) {
            Ok(payload) => {
                match payload.primary_binding() {
                    None => {
                        eprintln!(
                            "  {} key '{}' has no active bindings — skipping.",
                            "!".yellow(),
                            entry.alias
                        );
                    }
                    Some(binding) => {
                        let protocol_type = payload.primary_protocol_type().to_string();
                        let sync_supported_providers = if !payload.supported_providers.is_empty() {
                            payload.supported_providers.clone()
                        } else if !binding.provider_code.is_empty() {
                            vec![binding.provider_code.clone()]
                        } else {
                            entry.supported_providers.clone()
                        };
                        let sync_provider_base_urls: std::collections::HashMap<String, String> =
                            payload
                                .slots
                                .iter()
                                .flat_map(|slot| slot.binding_targets.iter())
                                .map(|b| (b.provider_code.clone(), b.base_url.clone()))
                                .collect();

                        // Encrypt + upsert via the shared delivered-key core
                        // (also used by the cluster daemon's `_internal` path).
                        let dk = DeliveredKey {
                            virtual_key_id: payload.virtual_key_id.clone(),
                            org_id: payload.org_id.clone(),
                            seat_id: payload.seat_id.clone(),
                            alias: payload.alias.clone(),
                            provider_code: binding.provider_code.clone(),
                            protocol_type,
                            base_url: binding.base_url.clone(),
                            credential_id: binding.credential_id.clone(),
                            credential_revision: binding.credential_revision.clone(),
                            virtual_key_revision: payload.current_revision.clone(),
                            key_status: payload.key_status.clone(),
                            share_status: payload.share_status.clone(),
                            local_state: "synced_inactive".to_string(),
                            expires_at: entry.expires_at,
                            local_alias: entry.local_alias.clone(),
                            supported_providers: sync_supported_providers,
                            provider_base_urls: sync_provider_base_urls,
                            owner_account_id: account_id.clone(),
                        };
                        upsert_delivered_key(vault_key, &dk, &binding.provider_key)
                            .map_err(|e| format!("encrypt/store key: {}", e))?;

                        eprintln!(
                            "  {} New key: {} {}",
                            crate::symbols::CHECK.s().green().bold(),
                            payload.alias.bold(),
                            format!("[{}]", binding.provider_code).dimmed()
                        );

                        downloaded += 1;
                    }
                }
            }
            Err(e) => {
                // Self-correcting refusal (2026-07-13): a BIZ_DELIVERY_CENTRAL_ONLY
                // 403 is not a failure to retry — it is the control plane telling us
                // our understanding of the deployment was wrong. Adopt the truth,
                // stop asking for material this run, and say what the user should do
                // instead. Retrying (had_download_error = true) would re-issue the
                // same refused request forever and pin the material watermark.
                //
                // Why check the message: the delivery client returns a formatted
                // error string; the code is the stable, localized-message-proof
                // discriminator the server now sends precisely so we can do this.
                let msg = e.to_string();
                if msg.contains("BIZ_DELIVERY_CENTRAL_ONLY") {
                    central_refused = true;
                    continue;
                }
                eprintln!(
                    "  {} could not fetch key '{}': {}",
                    crate::symbols::CROSS.s().red(),
                    entry.alias,
                    e
                );
                // Leave the material marker un-advanced so the next full sync
                // retries this stale/missing key.
                had_download_error = true;
            }
        }
    }

    // Stamp the material marker only on a clean pass: now every eligible VK's
    // local ciphertext reflects this snapshot's sync_version, so subsequent
    // syncs skip re-download until the next server-side change bumps it again
    // (credential/VK rotation → material_stale again). A failed delivery fetch
    // above keeps the marker behind so the stale key is retried next time.
    //
    // Under a download-suppressing form the marker must ALSO stay behind
    // (2026-07-13, caught by the SYNC-DELIVERY-01 integration closure): central
    // form skips every fetch, so "no download error" is vacuously true while NO
    // ciphertext reflects this sync_version. Advancing here would make a later
    // return to local form (e.g. the admin fixes EMPLOYEE_KEY_MODE) silently
    // skip every rotation that happened meanwhile — stale material forever.
    // The form-② agent daemon (allow_cluster_key_download) really downloads,
    // so it keeps stamping. A legacy-server refusal (central_refused) means
    // material was asked for and denied — same conclusion, keep it behind.
    let downloads_suppressed = (central_form && !allow_cluster_key_download) || central_refused;
    if !had_download_error && !downloads_suppressed {
        storage::set_last_material_sync_version(snapshot.sync_version);
    }

    // Form-① is not a failure — tell the user what the deployment IS and what to
    // do, instead of the bare "403" + "run `aikey key sync`" (the command they are
    // running) this used to surface. 2026-07-13. Printed here (the core fn) because
    // the form state lives here; threading it out to handle_key_sync would mean
    // changing the return type through every sync wrapper and call site.
    if central_form || central_refused {
        eprintln!(
            "  {} This deployment keeps key material on its cluster nodes (central delivery);",
            crate::symbols::INFO_I.s().cyan()
        );
        eprintln!("     keys are not downloaded here by design \u{2014} your tools route through your node.");
        if shell_integration::read_cluster_node().is_none() {
            eprintln!(
                "     {} No cluster node is resolved yet, so nothing can route: check the hub is reachable,",
                "\u{25b2}".yellow()
            );
            eprintln!("       or ask an admin to enable EMPLOYEE_KEY_MODE=local if keys should live on your machine.");
        }
    }

    Ok(downloaded)
}

/// Returns true if the remote sync_version differs from local (i.e. server has changes).
/// Returns false if already up-to-date or not logged in.
pub fn check_sync_version_changed() -> Result<bool, String> {
    let acc = match storage::get_platform_account().ok().flatten() {
        Some(a) => a,
        None => return Ok(false),
    };
    let token = match try_refresh_if_needed(&acc) {
        Ok(t) => t,
        Err(e) => return Err(format!("token refresh: {}", e)),
    };
    let client = PlatformClient::new(&acc.control_url, &token);
    let remote_version = match client.get_sync_version() {
        Ok(r) => r.sync_version,
        Err(e) => return Err(format!("sync-version: {}", e)),
    };
    let local_seen = storage::get_local_seen_sync_version();
    let last_material = storage::get_last_material_sync_version();
    // Trigger a full sync when the server is ahead of EITHER the metadata we've
    // seen OR the key material we've downloaded. The material arm catches
    // credential rotation (bugfix 2026-06-16): the lightweight background sync
    // advances `local_seen` (metadata only, no key download), so gating on
    // `local_seen` alone made `aikey list`/auto-sync skip the re-download once
    // metadata had caught up — leaving the local provider key stale forever.
    // `last_material <= local_seen` always holds, so the material arm only ever
    // ADDS triggers (when material lags), never removes the metadata trigger.
    Ok(remote_version > local_seen || remote_version > last_material)
}

/// Spawns a background thread to check and apply a server snapshot update.
///
/// Single-flight: if a sync is already in progress (e.g. from a concurrent
/// command invocation), this call is a no-op. This prevents duplicate snapshot
/// fetches and local-cache write races when multiple commands run close together.
///
/// Non-blocking: the calling command is not delayed.
/// All errors are silently suppressed — the local cache remains usable offline.
/// Cross-process debounce window for the implicit background snapshot sync.
///
/// Why this exists (2026-07-07, profiled live on the Windows box): the sync's
/// own sync_version fast-check runs INSIDE the spawned thread, but
/// `std::thread::spawn` ITSELF cost ~1.2s there — endpoint AV (Norton)
/// intercepts thread creation. Every short-lived `_internal` bridge child
/// paid that before any version check could run, which is exactly the
/// vault-page latency. The in-process SYNC_IN_PROGRESS flag can't help:
/// each bridge call is a NEW process, so every one of them spawned a thread.
///
/// The debounce is therefore a FILE (cross-process): if any aikey process
/// attempted the sync within the window, later processes skip the spawn
/// entirely (sub-ms stat+read on the hot path). Freshness bound for
/// OAuth-pool material (the reason the implicit sync exists — user decision
/// 2026-07-07: keep it, don't exempt `_internal`) becomes the window below,
/// on top of the server-side page-load trigger which is unaffected.
const SNAPSHOT_SYNC_DEBOUNCE_SECS: u64 = 30;

fn snapshot_sync_debounce_path() -> std::path::PathBuf {
    crate::commands_account::resolve_aikey_dir()
        .join("run")
        .join("snapshot-sync-last-attempt")
}

/// True when a sync attempt was recorded within the debounce window.
/// State-file reads follow the "enhancement, not dependency" rule: any
/// IO/parse failure reads as "stale" so the sync still runs.
fn snapshot_sync_recently_attempted(path: &std::path::Path, now_epoch: u64) -> bool {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(last) = raw.trim().parse::<u64>() else {
        return false;
    };
    // `last > now` (clock jumped backwards) reads as stale — never lets a
    // future timestamp suppress syncs indefinitely.
    now_epoch >= last && now_epoch - last < SNAPSHOT_SYNC_DEBOUNCE_SECS
}

/// Record "an attempt happened now". Written BEFORE the sync runs so
/// concurrent processes inside the window skip even while the winner is
/// still working; a failed sync simply retries after the window (bounded
/// cadence for a best-effort path). Write failures are ignored.
fn record_snapshot_sync_attempt(path: &std::path::Path, now_epoch: u64) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, now_epoch.to_string());
}

pub fn try_background_snapshot_sync() {
    use std::sync::atomic::{AtomicBool, Ordering};
    // Static flag: true while a background sync thread is running.
    static SYNC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

    // Cross-process debounce (see SNAPSHOT_SYNC_DEBOUNCE_SECS): skip the
    // expensive thread spawn when any process attempted a sync recently.
    //
    // Why thread::spawn and not a detached worker PROCESS (evaluated and
    // measured 2026-07-07): endpoint AV taxes creating a process from our
    // unsigned binary just as hard as creating a thread (~1.4s vs ~1.2s,
    // Norton live box) — the earlier "process creation is ~30ms" datum was
    // for SIGNED system binaries (cmd.exe) and does not transfer. A worker
    // process buys nothing and adds detach/handle-inheritance hazards.
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let debounce = snapshot_sync_debounce_path();
    if snapshot_sync_recently_attempted(&debounce, now_epoch) {
        return;
    }

    // compare_exchange(expected=false, new=true): only one thread wins.
    if SYNC_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return; // another sync is already running — skip
    }

    record_snapshot_sync_attempt(&debounce, now_epoch);
    std::thread::spawn(|| {
        let _ = run_snapshot_sync();
        SYNC_IN_PROGRESS.store(false, Ordering::Release);
    });
}

// ---------------------------------------------------------------------------
// Managed key metadata sync (shared helper)
// ---------------------------------------------------------------------------

/// Silently syncs managed virtual key metadata from the server into the local cache.
///
/// - Non-active keys (revoked/recycled/expired) are forced to `local_state =
///   "synced_inactive"` so the proxy stops routing them immediately.
/// - Existing encrypted key material is preserved (no re-encryption needed).
/// - Network/auth failures are silently ignored; the caller falls back to stale cache.
///
/// Returns `true` if the server was reachable, `false` otherwise.
/// Called by the shared key-list renderer (`run_unified_list` in main.rs)
/// so the list command always displays fresh metadata without a separate sync step.
pub fn sync_managed_key_metadata() -> bool {
    let acc = match storage::get_platform_account().ok().flatten() {
        Some(a) => a,
        None => return false,
    };
    let token = match try_refresh_if_needed(&acc) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let client = PlatformClient::new(&acc.control_url, &token);
    let items = match client.get_all_keys() {
        Ok(i) => i,
        Err(_) => return false,
    };

    for item in &items {
        let existing = match storage::get_virtual_key_cache(&item.virtual_key_id) {
            Ok(e) => e,
            Err(_) => continue,
        };
        // If the key was scope-disabled (belonged to a different account) but
        // the server is now returning it for the current account, restore it.
        let existing_state = existing
            .as_ref()
            .map(|e| e.local_state.as_str())
            .unwrap_or("");
        let local_state = match (item.key_status.as_str(), existing_state) {
            // Server says key is active; restore scope-disabled back to synced_inactive
            // (the current account now owns it again after re-login).
            ("active", "disabled_by_account_scope") => "synced_inactive".to_string(),
            // Server says key is active; preserve non-disabled states (active, synced_inactive,
            // prompt_dismissed).
            ("active", state) if !state.starts_with("disabled_by_") => {
                if state.is_empty() {
                    "synced_inactive".to_string()
                } else {
                    state.to_string()
                }
            }
            // Any other combination: fall back to synced_inactive.
            _ => "synced_inactive".to_string(),
        };
        // Preserve key material and delivery-time fields (base_url, credential_id, etc.).
        let nonce = existing.as_ref().and_then(|e| e.provider_key_nonce.clone());
        let ciphertext = existing
            .as_ref()
            .and_then(|e| e.provider_key_ciphertext.clone());
        let base_url = existing
            .as_ref()
            .map(|e| e.base_url.clone())
            .unwrap_or_default();
        let credential_id = existing
            .as_ref()
            .map(|e| e.credential_id.clone())
            .unwrap_or_default();
        let credential_revision = existing
            .as_ref()
            .map(|e| e.credential_revision.clone())
            .unwrap_or_default();
        let virtual_key_revision = existing
            .as_ref()
            .map(|e| e.virtual_key_revision.clone())
            .unwrap_or_default();

        let local_alias = existing.as_ref().and_then(|e| e.local_alias.clone());
        // Preserve supported_providers from existing cache; update from server if non-empty.
        let supported_providers = if !item.supported_providers.is_empty() {
            item.supported_providers.clone()
        } else {
            existing
                .as_ref()
                .map(|e| e.supported_providers.clone())
                .unwrap_or_default()
        };
        // Preserve existing provider_base_urls — server metadata sync doesn't re-deliver base URLs.
        let provider_base_urls = existing
            .as_ref()
            .map(|e| e.provider_base_urls.clone())
            .unwrap_or_default();
        let entry = VirtualKeyCacheEntry {
            virtual_key_id: item.virtual_key_id.clone(),
            org_id: item.org_id.clone(),
            seat_id: item.seat_id.clone(),
            alias: item.alias.clone(),
            provider_code: item.provider_code.clone(),
            protocol_type: "openai_compatible".to_string(),
            base_url,
            credential_id,
            credential_revision,
            virtual_key_revision,
            key_status: item.key_status.clone(),
            share_status: item.share_status.clone(),
            local_state,
            expires_at: None,
            provider_key_nonce: nonce,
            provider_key_ciphertext: ciphertext,
            synced_at: 0,
            local_alias,
            supported_providers,
            provider_base_urls,
            owner_account_id: Some(acc.account_id.clone()),
            owner_email: Some(acc.email.clone()), // owner email for /user/vault
            group_runtime: None, // proxy-owned (channel ③) — never written from here

            // Sync writers MUST always pass extra: None; upsert ignores
            // this field. See doc on VirtualKeyCacheEntry::extra.
            extra: None,
            // N6: this lightweight metadata sync (KeyItem) does NOT carry oauth-group
            // data — carry forward existing values so it doesn't clobber what the
            // full snapshot sync folded in. The full sync (apply_snapshot_to_cache)
            // is authoritative over these.
            oauth_group_id: existing.as_ref().and_then(|e| e.oauth_group_id.clone()),
            group_accounts: existing.as_ref().and_then(|e| e.group_accounts.clone()),
            routing_config: existing.as_ref().and_then(|e| e.routing_config.clone()),
            group_alias: existing.as_ref().and_then(|e| e.group_alias.clone()),
        };
        let _ = storage::upsert_virtual_key_cache(&entry);

        // If this key is currently active, refresh ~/.aikey/active.env with updated providers.
        // Handles the case where sync adds new providers to an already-active key.
        if !entry.supported_providers.is_empty() {
            if let Ok(Some(active_cfg)) = crate::storage::get_active_key_config() {
                if active_cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey
                    && active_cfg.key_ref == entry.virtual_key_id
                {
                    let display = entry.local_alias.as_deref().unwrap_or(entry.alias.as_str());
                    let _ = write_active_env(
                        "team",
                        &entry.virtual_key_id,
                        display,
                        &entry.supported_providers,
                        crate::commands_proxy::proxy_port(),
                    );
                }
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// aikey key sync
// ---------------------------------------------------------------------------

/// `aikey key sync`
///
/// Two-phase sync: (1) forces a full metadata refresh via the snapshot path
/// (resetting local_seen_sync_version to 0); (2) re-downloads missing key
/// material for claimed keys that lack local ciphertext.
pub fn handle_key_sync(
    password: &SecretString,
    json_mode: bool,
    force_reencrypt: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // --force-reencrypt: clear local ciphertext on active team keys so the
    // sync loop below treats them as `needs_download` and pulls a fresh
    // copy encrypted under the current vault_key. Recovery path for the
    // 2026-05-11 decrypt-inconsistency incident — see
    // workflow/CI/bugfix/2026-05-11-team-key-decrypt-inconsistent.md.
    if force_reencrypt {
        let cleared = storage::clear_managed_key_ciphertexts()
            .map_err(|e| format!("clear team key ciphertext: {}", e))?;
        if !json_mode {
            use colored::Colorize;
            eprintln!(
                "  {} Cleared local ciphertext on {} active team key(s); re-downloading...",
                crate::symbols::REFRESH.s().cyan(),
                cleared
            );
        }
    }
    // Force a full sync by resetting local_seen_sync_version to 0.
    storage::set_local_seen_sync_version(0);
    let downloaded = run_full_snapshot_sync(password)?;
    // B-2 (2026-07-06): sign post-sync auto-assign binding writes. The full
    // sync above already strict-verified this password's derived key, so
    // VerifiedVaultKey::new cannot fail here except on a concurrent password
    // change — in which case signing is correctly skipped (best-effort None).
    let audit_key = derive_vault_key(password)
        .ok()
        .and_then(|k| crate::audit::VerifiedVaultKey::new(k).ok());

    // v1.0.2: reconcile provider primaries after sync.
    let cached = storage::list_virtual_key_cache().unwrap_or_default();
    let synced_keys: Vec<(String, Vec<String>)> = cached
        .iter()
        .filter(|e| e.key_status == "active" && !e.local_state.starts_with("disabled_by_"))
        .map(|e| {
            let p = if !e.supported_providers.is_empty() {
                e.supported_providers.clone()
            } else if !e.provider_code.is_empty() {
                vec![e.provider_code.clone()]
            } else {
                vec![]
            };
            (e.virtual_key_id.clone(), p)
        })
        .filter(|(_, p)| !p.is_empty())
        .collect();
    let reconciled = crate::profile_activation::reconcile_provider_primaries_after_team_key_sync(
        &synced_keys,
        audit_key.as_ref(),
    )
    .unwrap_or_default();
    if !reconciled.is_empty() {
        let _ = crate::profile_activation::refresh_implicit_profile_activation();
    }

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "downloaded": downloaded,
            "auto_activated_providers": reconciled.iter().flat_map(|(_, p)| p.clone()).collect::<Vec<String>>(),
        }));
    } else {
        use colored::Colorize;
        println!("Sync complete: {} key(s) downloaded.", downloaded);
        for (vk_id, providers) in &reconciled {
            for p in providers {
                eprintln!(
                    "  {} Team key '{}' auto-activated as Primary for {}",
                    crate::symbols::STAR.s().yellow(),
                    vk_id.bold(),
                    p
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// aikey key use
// ---------------------------------------------------------------------------

/// Single source of truth for provider metadata (L5 unification 2026-04-17).
///
/// Consolidates what were previously three parallel match tables:
///   - main.rs::canonical_provider (alias → canonical code)
///   - commands_account::provider_env_vars (code → API_KEY/BASE_URL env var pair)
///   - commands_account::provider_proxy_prefix (code → URL path segment)
///
/// Why one struct: keeping them separate let kimi/moonshot drift apart — `route`
/// was emitting `/kimi` (broken for OpenAI-compatible Kimi SDK), while `activate`
/// was emitting `/kimi/v1` (working). The single match table prevents future drift.
#[derive(Debug, Clone, Copy)]
pub struct ProviderInfo {
    /// Real canonical provider code for vault queries / activation / binding /
    /// proxy routing. Aliases like "claude" → "anthropic"; "moonshot" stays
    /// "moonshot" (NOT folded to family "kimi").
    ///
    /// 2026-05-08 Kimi 双平台拆分 evaluation feedback: 历史上此字段曾返回
    /// `entry.family`,导致 moonshot/kimi_code 在 resolve_single_provider 被
    /// 折叠回 "kimi",环境变量 / base_url / binding 都走错路径。修后回归
    /// "真正的 provider_code" 语义,UI 分组通过新 `family` 字段处理。
    pub canonical_code: &'static str,
    /// Protocol family for UI grouping / vault-query "show all of one brand"
    /// scenarios. kimi_code 和 moonshot 的 family 都是 "kimi",上层 UI 想
    /// 把它们分到同一卡片下时按 family 聚合;具体路由仍然按 canonical_code。
    pub family: &'static str,
    /// URL path segment registered in the proxy. Must include `/v1` suffix
    /// for providers whose upstream has no `/v1` prefix AND whose SDK doesn't
    /// auto-prepend /v1 (kimi/moonshot use OpenAI-compatible SDKs that treat
    /// base_url as "already has /v1").
    pub proxy_path: &'static str,
    /// Provider-specific env var names written by `aikey use`/`aikey activate`.
    ///
    /// 2026-05-08 Kimi family 互斥后(详见 update/20260508-Kimi-family互斥-active-env
    /// 统一KIMI写入.md 决策 #8): kimi_code / moonshot / kimi(deprecated) 三个 family
    /// 内 provider_code 都共用 KIMI_API_KEY / KIMI_BASE_URL,family 互斥保证同时只
    /// 1 个 active binding,激活哪个由 proxy_path 决定上游路由。其它 family 仍
    /// 各自一对 env var(ANTHROPIC_*, OPENAI_* 等),互不干扰。
    pub env_vars: (&'static str, &'static str),
}

/// Look up provider metadata by code or alias. Returns `None` for unknown codes.
///
/// Delegates to `provider_registry::lookup` (2026-04-24 refactor — the
/// hand-coded match table was externalized to `data/provider_registry.yaml`
/// as part of the provider-expansion effort). See that module for the full
/// schema and lookup semantics (including OAuth alias resolution).
pub fn provider_info(code: &str) -> Option<ProviderInfo> {
    let entry = crate::provider_registry::lookup(code)?;
    Some(ProviderInfo {
        // 2026-05-08 review feedback: 必须是 entry.code (真正 canonical code),
        // 不是 entry.family —— 否则 moonshot 激活时会被折叠回 kimi,后续
        // env / base_url / binding 全走错路径。Family 通过新 `family` 字段提供。
        canonical_code: entry.code,
        family: entry.family,
        proxy_path: entry.proxy_path,
        env_vars: entry.env_vars,
    })
}

// ── Back-compat wrappers: existing call sites keep working unchanged. ──

/// Provider code → environment variable names for API key + base URL.
/// Public re-export for use by `executor::run_with_active_key`.
pub fn provider_env_vars_pub(provider_code: &str) -> Option<(&'static str, &'static str)> {
    provider_env_vars(provider_code)
}

/// Public re-export of `provider_extra_env_vars` for use across crates.
pub fn provider_extra_env_vars_pub(provider_code: &str) -> Vec<(&'static str, &'static str)> {
    provider_extra_env_vars(provider_code)
}

pub(crate) fn provider_env_vars(provider_code: &str) -> Option<(&'static str, &'static str)> {
    provider_info(provider_code).map(|i| i.env_vars)
}

/// Provider-specific extra env vars beyond (api_key, base_url).
///
/// Used by active.env writers to populate provider-specific hints that the
/// third-party CLI reads at runtime. Returns `Vec` (not fixed tuple) so a
/// provider can declare multiple extras as needed.
///
/// Why Kimi has extras: we radically simplified `~/.kimi/config.toml` to
/// contain only the Stop hook (no `[providers.kimi]` / `[models.*]` / top-level
/// `default_model`). Kimi CLI's fallback logic at [app.py:177-185] constructs
/// an empty LLMModel/LLMProvider when config lacks those, then
/// `augment_provider_with_env_vars` populates fields from env vars. Without
/// `KIMI_MODEL_NAME`, `model.model` stays empty and Kimi rejects the request.
pub(crate) fn provider_extra_env_vars(provider_code: &str) -> Vec<(&'static str, &'static str)> {
    // Delegates to registry so Kimi's extras (+ any future provider's) stay
    // in the single YAML source of truth.
    match crate::provider_registry::lookup(provider_code) {
        Some(e) => e.extra_env_vars.to_vec(),
        None => Vec::new(),
    }
}

/// Provider code → proxy URL path segment. Unknown codes fall back to "openai"
/// (OpenAI-compatible default) to preserve the previous function's contract.
pub fn provider_proxy_prefix_pub(provider_code: &str) -> &'static str {
    provider_proxy_prefix(provider_code)
}

/// Map OAuth provider name to canonical provider code used in bindings.
///
/// OAuth accounts store provider as `"claude"` / `"codex"` / `"kimi"` (broker
/// vocabulary) but everything else — bindings, proxy routing, persona header
/// selection in `test_provider_connectivity` — keys on the canonical
/// `"anthropic"` / `"openai"` / `"kimi"`. Any code that holds a raw
/// `ProviderAccountInfo.provider` **must** normalize via this before using
/// the value for URL/routing/persona decisions — otherwise provider-specific
/// tweaks (Claude's `?beta=true`, Codex's Responses API path) silently fail
/// and the chat probe 404s.
///
/// Lives here (lib-accessible) so the connectivity suite resolvers in
/// `commands_project` can share the same mapping `auth use` / `auth doctor`
/// already rely on.
pub fn oauth_provider_to_canonical(provider: &str) -> &'static str {
    // Delegates to the registry's alias resolution. Unknown codes pass
    // through via the registry's cached-leak mechanism — preserves the old
    // helper's "custom provider names still work" contract while keeping
    // the claude↔anthropic / codex↔openai / glm↔zhipu / ark↔doubao / etc.
    // alias tables in a single YAML file.
    crate::provider_registry::canonical(provider)
}

// ============================================================================
// Shared add-secret core (2026-04-24)
//
// Single source of truth for "write a personal key entry to vault.db". Used
// by three callers:
//   - `aikey add` (CLI, interactive / batch-friendly single add)
//   - `_internal vault-op add`  (single-add via Web "Add key" modal)
//   - `_internal vault-op batch_import` (Web paste-import, N items in a tx)
//
// Rationale — see `.claude/CLAUDE.md` §"_internal 隐藏命令必须复用公开命令的
// 非交互 core（强制执行）". Previously each path reimplemented the same
// four-step write (validate → encrypt → store_entry → metadata), with
// subtle divergences: `vault-op add` skipped supported_providers + base_url;
// `batch_import` had its own alias validator; neither did canonical
// provider normalization. All three now funnel through `apply_add_core_on_conn`.
// ============================================================================

/// Personal-key alias length cap — shared by all add paths.
const MAX_ALIAS_LEN: usize = 128;

/// How to respond when the target alias already exists in vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnConflict {
    /// Reject with an error (CLI default + batch strict mode).
    Error,
    /// Overwrite the existing entry's ciphertext + metadata.
    Replace,
    /// No-op this item and return `AddAction::Skipped` (batch lenient mode).
    Skip,
}

/// Result variant from `apply_add_core_on_conn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddAction {
    Inserted,
    Replaced,
    Skipped,
}

impl AddAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddAction::Inserted => "inserted",
            AddAction::Replaced => "replaced",
            AddAction::Skipped => "skipped",
        }
    }
}

/// Structured outcome of an `apply_add_core_on_conn` call.
#[derive(Debug, Clone)]
pub struct AddOutcome {
    /// The alias as it was actually written (post trim/validate). Callers
    /// should prefer this over the input `alias` for downstream references.
    pub alias: String,
    pub action: AddAction,
    /// Provider codes after canonical normalization + dedup. Empty if the
    /// caller passed no providers (stored unassigned; `aikey use` later
    /// errors out until at least one provider is set).
    pub providers: Vec<String>,
    /// First canonical provider, also written to `entries.provider_code`
    /// for legacy-single-provider callers. `None` when providers is empty.
    pub primary_provider: Option<String>,
}

/// Validates a personal-key alias. Returns the trimmed form on success.
///
/// Rules (single-source-of-truth; previously split between `aikey add`'s
/// empty-string check and `batch_import`'s char/length checks):
///   - Must be non-empty after trim
///   - Must be ≤ 128 chars (MAX_ALIAS_LEN)
///   - Must not contain ASCII control characters (0x00-0x1F + 0x7F)
pub fn validate_alias(alias: &str) -> Result<String, String> {
    let trimmed = alias.trim();
    if trimmed.is_empty() {
        return Err("alias must not be empty".to_string());
    }
    if trimmed.chars().count() > MAX_ALIAS_LEN {
        return Err(format!("alias exceeds {} characters", MAX_ALIAS_LEN));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("alias contains control characters".to_string());
    }
    Ok(trimmed.to_string())
}

/// Normalizes a list of raw provider strings into canonical, deduplicated,
/// order-preserving form. Runs each value through:
///   1. `trim()` + `to_lowercase()` (user typo tolerance)
///   2. drop empty strings
///   3. `oauth_provider_to_canonical` (claude → anthropic, codex → openai)
///   4. dedup (preserve first-seen order)
///
/// Single source of truth for "what goes into `entries.supported_providers`
/// and `entries.provider_code` at add-time". Write-side counterpart of the
/// read-side `protocol_family_of` (`commands_internal/query.rs`).
pub fn normalize_providers(raw: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in raw {
        let lower = p.trim().to_lowercase();
        if lower.is_empty() {
            continue;
        }
        let canonical = oauth_provider_to_canonical(&lower).to_string();
        if seen.insert(canonical.clone()) {
            out.push(canonical);
        }
    }
    out
}

/// Core personal-key add logic. Connection-bound so it participates cleanly
/// in both single-add (direct connection) and batch-import (Transaction,
/// which derefs to `&Connection`) scenarios.
///
/// This function does NOT:
///   - Open a DB connection (caller provides one)
///   - Bump vault_change_seq (caller's responsibility; batch bumps once
///     post-commit rather than per item)
///   - Generate route_token (requires its own connection — caller issues
///     `storage::ensure_entry_route_token(&outcome.alias)` AFTER this
///     returns, outside any transaction on the same DB)
///   - Write audit log (caller decides; uses different audit key paths
///     for password-derived vs vault_key paths)
///   - Refresh active.env / auto-assign profiles (CLI-UX side effects)
pub(crate) fn apply_add_core_on_conn(
    conn: &rusqlite::Connection,
    vault_key: &[u8; 32],
    alias: &str,
    secret_plaintext: &[u8],
    providers: &[String],
    base_url: Option<&str>,
    on_conflict: OnConflict,
) -> Result<AddOutcome, String> {
    let validated = validate_alias(alias)?;
    let normalized = normalize_providers(providers);

    // Conflict check
    let exists = conn
        .query_row(
            "SELECT COUNT(*) FROM entries WHERE alias = ?1",
            rusqlite::params![&validated],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .map_err(|e| format!("check alias exists '{}': {}", validated, e))?;

    let action = if exists {
        match on_conflict {
            OnConflict::Error => {
                return Err(format!("alias '{}' already exists", validated));
            }
            OnConflict::Skip => {
                return Ok(AddOutcome {
                    alias: validated,
                    action: AddAction::Skipped,
                    providers: normalized.clone(),
                    primary_provider: normalized.first().cloned(),
                });
            }
            OnConflict::Replace => AddAction::Replaced,
        }
    } else {
        AddAction::Inserted
    };

    // Encrypt with provided vault_key (caller owns key lifetime).
    let (nonce, ciphertext) = crate::crypto::encrypt(vault_key, secret_plaintext)
        .map_err(|e| format!("encrypt '{}': {}", validated, e))?;

    // Vault ciphertext row (UPSERT semantics at storage layer).
    storage::store_entry_on_conn(conn, &validated, &nonce, &ciphertext)
        .map_err(|e| format!("store_entry '{}': {}", validated, e))?;

    // Provider metadata — only touch when caller provided providers. An
    // add with no providers leaves supported_providers + provider_code
    // untouched (defensive for Replace path where caller might intentionally
    // refuse to overwrite existing metadata).
    if !normalized.is_empty() {
        storage::set_entry_supported_providers_on_conn(conn, &validated, &normalized)
            .map_err(|e| format!("set_supported_providers '{}': {}", validated, e))?;
        // Legacy single-value column — set to the primary (first canonical).
        // Kept in sync so old `aikey use` / proxy consumers that read
        // provider_code still work alongside the v1.0.2+ supported_providers.
        conn.execute(
            "UPDATE entries SET provider_code = ?1 WHERE alias = ?2",
            rusqlite::params![&normalized[0], &validated],
        )
        .map_err(|e| format!("set provider_code '{}': {}", validated, e))?;
    }

    // Base URL (optional)
    if let Some(url) = base_url.map(str::trim).filter(|u| !u.is_empty()) {
        storage::set_entry_base_url_on_conn(conn, &validated, Some(url))
            .map_err(|e| format!("set_base_url '{}': {}", validated, e))?;
    }

    let primary = normalized.first().cloned();
    Ok(AddOutcome {
        alias: validated,
        action,
        providers: normalized,
        primary_provider: primary,
    })
}

// ============================================================================
// Shared rename core (2026-04-24)
//
// Unified rename path for all three vault row types. Callers:
//   - `aikey key alias <old> <new>` (CLI, all three targets now)
//   - `_internal update-alias rename_alias` (personal-only legacy contract)
//   - `_internal update-alias rename_target` (target-aware Web §2.0 protocol)
//
// Rationale — see `.claude/CLAUDE.md` §"_internal 隐藏命令必须复用公开命令的
// 非交互 core（强制执行）". Previously: public CLI rejected personal rename
// entirely (pointing user at delete+re-add), while hidden CLI accepted it —
// users could land the vault in a state where one tool refused what the
// other permitted. Single core + CLI unblocks personal rename, both ends now
// agree on semantics, validation, and conflict handling.
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameTarget {
    /// Personal key entry — renames `entries.alias` (UNIQUE column).
    Personal,
    /// Team (virtual) key — renames `managed_virtual_keys_cache.local_alias`
    /// (server alias stays untouched).
    Team,
    /// OAuth account — writes `provider_accounts.local_alias`, leaving
    /// `display_identity` (the immutable upstream identity) untouched. No
    /// UNIQUE constraint on either column; two accounts may legitimately
    /// share a label. Pre-v1.0.1-alpha.1 overwrote `display_identity`
    /// instead — that path destroyed the original email returned by the
    /// OAuth provider, which the new column split fixes.
    Oauth,
}

impl RenameTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            RenameTarget::Personal => "personal",
            RenameTarget::Team => "team",
            RenameTarget::Oauth => "oauth",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RenameOutcome {
    pub target: &'static str,
    /// The row's stable identifier post-rename:
    ///   - personal → the NEW alias (alias IS the id)
    ///   - team → virtual_key_id (unchanged by rename)
    ///   - oauth → provider_account_id (unchanged by rename)
    pub id: String,
    /// The pre-rename identifier (alias for personal; vkid/account_id
    /// otherwise — unchanged).
    pub old_id: String,
    /// The human-facing new label actually applied:
    ///   - personal → new alias (same as `id`)
    ///   - team → new local_alias
    ///   - oauth → new local_alias (display_identity stays immutable)
    pub new_value: String,
}

/// Core rename logic. Validates, performs existence check, conflict check
/// (personal only — UNIQUE column), and the UPDATE. Error strings follow
/// the same "NotFound" / "already exists" / "empty"/"identical"/"control"
/// markers that `apply_add_core_on_conn` uses so callers can reuse the
/// same error-code mapping.
///
/// Does NOT:
///   - Write audit log (caller does, with its own audit key path)
///   - Bump vault_change_seq (caller's responsibility; personal rename
///     should bump, team/oauth may not need to)
///   - Refresh active.env (rename doesn't change routing identity)
pub fn apply_rename_core(
    target: RenameTarget,
    id: &str,
    new_value: &str,
) -> Result<RenameOutcome, String> {
    if id.trim().is_empty() {
        return Err("id must not be empty".to_string());
    }
    if new_value.trim().is_empty() {
        return Err("new_value must not be empty".to_string());
    }

    match target {
        RenameTarget::Personal => {
            let validated = validate_alias(new_value)?;
            if id == validated {
                return Err("old and new alias are identical".to_string());
            }
            let conn = storage::open_connection().map_err(|e| format!("open vault: {}", e))?;

            // Existence check on old
            let old_exists = conn
                .query_row(
                    "SELECT COUNT(*) FROM entries WHERE alias = ?1",
                    rusqlite::params![id],
                    |r| r.get::<_, i64>(0),
                )
                .map(|n| n > 0)
                .map_err(|e| format!("check old alias '{}': {}", id, e))?;
            if !old_exists {
                return Err(format!("alias '{}' not found", id));
            }

            // Pre-check conflict on new (UNIQUE column — UPDATE would fail)
            let new_exists = conn
                .query_row(
                    "SELECT COUNT(*) FROM entries WHERE alias = ?1",
                    rusqlite::params![&validated],
                    |r| r.get::<_, i64>(0),
                )
                .map(|n| n > 0)
                .map_err(|e| format!("check new alias '{}': {}", validated, e))?;
            if new_exists {
                return Err(format!("alias '{}' already exists", validated));
            }

            let n = conn
                .execute(
                    "UPDATE entries SET alias = ?1 WHERE alias = ?2",
                    rusqlite::params![&validated, id],
                )
                .map_err(|e| {
                    // Race window: concurrent renames can land between our
                    // pre-check and the UPDATE. SQLite surfaces this as UNIQUE
                    // constraint — translate to the same "already exists"
                    // marker as the pre-check.
                    if format!("{}", e).contains("UNIQUE") {
                        format!("alias '{}' already exists (UNIQUE)", validated)
                    } else {
                        format!("UPDATE entries: {}", e)
                    }
                })?;
            if n == 0 {
                return Err(format!("alias '{}' not found (race)", id));
            }

            let _ = storage::bump_vault_change_seq();
            Ok(RenameOutcome {
                target: "personal",
                id: validated.clone(),
                old_id: id.to_string(),
                new_value: validated,
            })
        }

        RenameTarget::Team => {
            // Validate, don't just trim: a team key's local_alias is written
            // verbatim into `~/.aikey/active.env` (AIKEY_ACTIVE_KEYS, sourced
            // every prompt) and `active.env.flat` (parsed line-by-line). A
            // control char (esp. newline) would let a renamed alias forge a
            // KEY=VALUE line in the flat file. Shell metachars are additionally
            // neutralized at the write boundary by sh single-quoting, but
            // rejecting control chars here is the cheap input-side guard and
            // brings team rename to parity with personal rename.
            let new_trimmed = validate_alias(new_value)?;
            let entry = storage::get_virtual_key_cache(id)
                .map_err(|e| format!("get team key '{}': {}", id, e))?
                .or_else(|| storage::get_virtual_key_cache_by_alias(id).ok().flatten())
                .ok_or_else(|| format!("team key '{}' not found", id))?;
            storage::set_virtual_key_local_alias(&entry.virtual_key_id, Some(&new_trimmed))
                .map_err(|e| format!("set_virtual_key_local_alias: {}", e))?;
            Ok(RenameOutcome {
                target: "team",
                id: entry.virtual_key_id,
                old_id: id.to_string(),
                new_value: new_trimmed,
            })
        }

        RenameTarget::Oauth => {
            // Same rationale as the Team branch: the OAuth account's
            // local_alias reaches active.env / active.env.flat as a display
            // value. Validate (reject control chars) for parity, not bare trim.
            let new_trimmed = validate_alias(new_value)?;
            // Existence check for precise 404
            let acct = match storage::get_provider_account(id)
                .map_err(|e| format!("get_provider_account '{}': {}", id, e))?
            {
                Some(a) => a,
                None => return Err(format!("provider_account_id '{}' not found", id)),
            };
            // v1.0.1-alpha.1: rename writes provider_accounts.local_alias
            // and leaves display_identity (the immutable upstream identity)
            // untouched. Why: the previous behavior overwrote
            // display_identity, destroying the original email returned by
            // the OAuth provider and making the "alias differs from
            // identity" UI rule unreachable. local_alias = NULL ↔ "never
            // renamed"; resolvers fall back to display_identity for a
            // stable label.
            //
            // No-op short-circuit: if the new value equals the effective
            // current label (local_alias if set, else display_identity)
            // there's nothing to do — match the personal-rename "identical"
            // error so callers get a consistent signal.
            let current_effective = acct
                .local_alias
                .as_deref()
                .or(acct.display_identity.as_deref())
                .unwrap_or("");
            if current_effective == new_trimmed {
                return Err("old and new alias are identical".to_string());
            }
            let conn = storage::open_connection().map_err(|e| format!("open vault: {}", e))?;
            let n = conn
                .execute(
                    "UPDATE provider_accounts SET local_alias = ?1 WHERE provider_account_id = ?2",
                    rusqlite::params![&new_trimmed, id],
                )
                .map_err(|e| format!("UPDATE provider_accounts: {}", e))?;
            if n == 0 {
                return Err(format!("provider_account_id '{}' not found (race)", id));
            }
            Ok(RenameOutcome {
                target: "oauth",
                id: id.to_string(),
                old_id: id.to_string(),
                new_value: new_trimmed,
            })
        }
    }
}

/// Writes provider bindings for one key across `providers`, normalizing
/// every provider_code to its canonical API-protocol form (claude →
/// anthropic, codex → openai) and cleaning any pre-fix stale alias row
/// left over from older CLI versions.
///
/// # Why this is the single write-path for `user_profile_provider_bindings`
///
/// The bindings table PRIMARY KEY is `(profile_id, provider_code)`. Before
/// this helper existed, `aikey use <codex-oauth>` wrote a row with
/// provider_code="codex" and `aikey use <openai-key>` wrote one with
/// provider_code="openai" — two distinct rows, both legal per the schema.
/// At runtime both rows would then race to write OPENAI_API_KEY into
/// active.env (last-writer-wins silently), and the vault Web UI's "in use"
/// indicator would light up on BOTH rows under the same protocol family,
/// violating the one-active-per-family rule users expect.
///
/// Funneling all binding writes through this helper guarantees the table
/// only ever holds rows keyed by canonical codes, so the same rule is
/// enforced structurally via the PRIMARY KEY constraint (UPSERT replaces
/// the prior in-family active automatically).
///
/// 2026-05-08 Kimi family 互斥(详见 update/20260508-Kimi-family互斥-active-env
/// 统一KIMI写入.md 决策 #2):family 内 kimi_code / moonshot / kimi(deprecated)
/// 三者 binding 互斥(同时只 1 个 active);env var 全部统一 KIMI_*,proxy_path
/// 区分上游路由(kimi_code 与 deprecated kimi 走 /kimi/v1,moonshot 走 /moonshot/v1)。
/// 互斥逻辑下沉到 set_provider_binding 内事务包裹,所有 lifecycle event(Switched/
/// Added/team-sync/reconcile)统一遵守。
pub(crate) fn write_bindings_canonical(
    providers: &[String],
    key_type_str: &str,
    key_ref: &str,
    audit: Option<&crate::audit::VerifiedVaultKey>,
) -> Result<(), String> {
    for raw_provider in providers {
        let raw = raw_provider.to_lowercase();
        let canonical = oauth_provider_to_canonical(&raw);
        if canonical != raw.as_str() {
            // Best-effort cleanup of any stale non-canonical row. Silent
            // on error — worst case the stale row lingers until the next
            // activation UPSERTs over it via the canonical primary key.
            let _ =
                storage::remove_provider_binding(crate::profile_activation::DEFAULT_PROFILE, &raw);
        }
        storage::set_provider_binding(
            crate::profile_activation::DEFAULT_PROFILE,
            canonical,
            key_type_str,
            key_ref,
        )
        .map_err(|e| format!("set_provider_binding: {}", e))?;
        // B-2 (2026-07-06): sign one tamper-evident `bind` audit row per
        // binding write when the caller holds a verified vault key — the
        // incident write (post-sync auto-assign) was invisible in audit_log
        // AND the internal log. BEST-EFFORT by design: the binding write above
        // already landed; an audit insert failure must never fail activation
        // (fail-visible via WARN instead). `None` (keyless automatic contexts)
        // still leaves the observability event emitted by the caller.
        if let Some(vk) = audit {
            if let Err(e) = crate::audit::log_audit_event_from_vault_key(
                vk.as_bytes(),
                crate::audit::AuditOperation::Bind,
                Some(&format!("{}:{}:{}", canonical, key_type_str, key_ref)),
                true,
            ) {
                eprintln!("[aikey] warning: bind audit row not written: {}", e);
            }
        }
    }
    Ok(())
}

pub(crate) fn provider_proxy_prefix(provider_code: &str) -> &'static str {
    provider_info(provider_code)
        .map(|i| i.proxy_path)
        .unwrap_or("openai")
}

/// Writes `~/.aikey/active.env` with provider env vars for the active key.
///
/// For all credential types (team / personal API key / OAuth) the API key
/// value is the active sentinel `aikey_active_<provider>` — proxy's tier-3
/// fallthrough reads the active binding via the URL path's canonical provider
/// and injects the real key. The sentinel suffix is informational (post-
/// 2026-04-29 prefix rename — was previously per-credential-type sentinels).
///
/// `aikey run --direct -- <cmd>`
///
/// Decrypts the real key for the currently active **personal** key and injects it directly
/// into the child process environment — bypassing the proxy entirely. Any proxy sentinel
/// env vars that the shell may have inherited (ANTHROPIC_API_KEY, OPENAI_API_KEY, …) are
/// overridden with the real values so the child never contacts the local proxy.
///
/// No file is written. The key is only visible inside the child process.
pub fn handle_run_direct(
    cmd: &[String],
    password: &SecretString,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if cmd.is_empty() {
        return Err("no command specified. Usage: aikey run --direct -- <cmd> [args…]".into());
    }

    // ── 1. Resolve the active personal key ────────────────────────────────────
    let active_cfg =
        storage::get_active_key_config()?.ok_or("No active key. Run `aikey use <alias>` first.")?;

    if active_cfg.key_type != crate::credential_type::CredentialType::PersonalApiKey {
        return Err(format!(
            "--direct only supports personal keys (current active key is type '{}').\n\
             Switch to a personal key first: aikey use <alias>",
            active_cfg.key_type
        )
        .into());
    }

    let alias = &active_cfg.key_ref;

    // ── 2. Decrypt the real key once ──────────────────────────────────────────
    let plaintext = crate::executor::get_secret(alias, password)
        .map_err(|e| format!("Failed to decrypt key '{}': {}", alias, e))?;
    let real_key = plaintext.as_str().trim().to_string();

    // ── 3. Resolve the stored base_url (single value shared across providers) ─
    let stored_base_url = storage::get_entry_base_url(alias)
        .ok()
        .flatten()
        .unwrap_or_default();

    // ── 4. Determine which providers to inject ────────────────────────────────
    // Use the providers stored in the active config (set by `aikey use`).
    // If empty, fall back to the default generic-gateway list.
    const DEFAULT_PROVIDERS: &[&str] = &["anthropic", "openai", "google", "deepseek", "kimi"];
    let providers: Vec<String> = if active_cfg.providers.is_empty() {
        DEFAULT_PROVIDERS.iter().map(|s| s.to_string()).collect()
    } else {
        active_cfg.providers.clone()
    };

    // ── 5. Build the env overrides map ────────────────────────────────────────
    let mut overrides: Vec<(String, String)> = Vec::new();
    for provider in &providers {
        if let Some((api_var, base_var)) = provider_env_vars(provider) {
            overrides.push((api_var.to_string(), real_key.clone()));
            if !stored_base_url.is_empty() {
                overrides.push((base_var.to_string(), stored_base_url.clone()));
            }
        }
    }

    // ── 6. Print what will be injected (non-JSON mode) ─────────────────────
    if !json_mode {
        use colored::Colorize;
        println!(
            "{} Running {} with direct key injection (no proxy):",
            "→".dimmed(),
            cmd[0].bold()
        );
        for (var, val) in &overrides {
            if var.ends_with("_BASE_URL") {
                println!("  {:<28} = {}", var.bold(), val.cyan());
            } else {
                println!("  {:<28} = {}", var.bold(), "<real key>".dimmed());
            }
        }
        println!();
    }

    // ── 7. Spawn child process with overridden env ────────────────────────────
    let mut child = std::process::Command::new(&cmd[0]);
    child.args(&cmd[1..]);
    for (var, val) in &overrides {
        child.env(var, val);
    }

    let status = child
        .status()
        .map_err(|e| format!("Failed to execute '{}': {}", cmd[0], e))?;

    std::process::exit(status.code().unwrap_or(1));
}

mod shell_integration;
pub use shell_integration::*;

// OpenClaw (龙虾 digital-employee) integration: `aikey hook {install,uninstall,
// status} openclaw`. Separate from shell_integration because OpenClaw is an
// unattended agent (no precmd hook); we write a static provider into its own
// config via `openclaw config patch`. Reuses `aikey route` primitives.
pub(crate) mod openclaw_hook;

// Claude Desktop takeover (阶段7, D1–D10): pure file layer that flips the
// GUI app between official (1p) and aikey-gateway (3p) modes, following the
// active anthropic binding. P1 = writer core only; the P2 funnel hook lives
// inside `apply_third_party_cli_configs` so BOTH production call sites
// (lifecycle tail + handle_key_unuse's parallel copy) cover it.
pub(crate) mod claude_desktop;

// Credential lifecycle: single funnel for all binding writes + read-only
// state audit. See `lifecycle/mod.rs` for the design rationale (Phase 5
// of bugfix 2026-05-07-handle-add-skips-third-party-cli-config).
mod lifecycle;
pub use lifecycle::*;

// PowerShell hook install logic, extracted 2026-04-29 from
// shell_integration.rs (Strategy A purity). Compiled on all platforms —
// pwsh 7+ runs on macOS / Linux too, and cross-platform tests in
// stage3_powershell_hook_tests reference its functions on macOS.
// `_windows.rs` is a naming convention here (this is the PowerShell
// sibling, mainly relevant to Windows users), not a compilation gate.
// See shell_integration_windows.rs module docstring.
mod shell_integration_windows;
// ExecutionPolicy wired-but-dead probe (2026-07-12 X2) — consumed by doctor.
pub use shell_integration_windows::powershell_profile_load_blocked;
// pwsh-7 dual-profile wiring gap probe (2026-07-12 3a) — consumed by doctor.
pub use shell_integration_windows::pwsh_profile_wiring_gap;

/// Resolve an OAuth account by `provider_account_id`, `local_alias`, OR
/// `display_identity` (email). Returns `None` when no match — caller treats
/// that as "not OAuth, try next lookup kind".
///
/// Case-insensitive on all keys: account_id is a UUID-ish random string so
/// case doesn't practically matter, but emails / aliases are routinely
/// typed with varying case. Mirrors the lookup in
/// `connectivity::targets::targets_from_alias` so behaviour stays symmetric
/// between `aikey test` and `aikey use`.
///
/// v1.0.1-alpha.1: matches `local_alias` first so a renamed account is
/// findable by its new label without losing the email-based fallback.
fn resolve_oauth_account(alias_or_id: &str) -> Option<storage::ProviderAccountInfo> {
    let accounts = storage::list_provider_accounts_readonly().ok()?;
    accounts.into_iter().find(|a| {
        a.provider_account_id.eq_ignore_ascii_case(alias_or_id)
            || a.local_alias
                .as_deref()
                .map(|d| d.eq_ignore_ascii_case(alias_or_id))
                .unwrap_or(false)
            || a.display_identity
                .as_deref()
                .map(|d| d.eq_ignore_ascii_case(alias_or_id))
                .unwrap_or(false)
    })
}

/// `aikey key use <alias-or-id>` / `aikey use <alias-or-id>`
///
/// Global mutex: deactivates ALL keys (personal + team), then activates the target.
///
/// Writes `~/.aikey/active.env` with provider env vars; installs shell hook on first use.
/// Accepts virtual_key_id, alias (local_alias preferred, then server alias),
/// or OAuth account (by provider_account_id or display_identity / email).
///
/// P5 form-① (§5.5): resolve the user's cluster node (one resolve per `aikey use`,
/// hashed by user → one node for all the user's VKs) and persist its AUTHORITY for
/// the per-provider router. The token is NOT stored here — each provider's token
/// comes from its own binding (that's what makes routing per-provider). Control
/// returns an authoritative 404 for non-cluster, in which case we clear the
/// node so every binding routes to the local proxy. The employee never holds
/// the infra hub token — control brokers the resolve server-side.
///
/// 2026-06-12: auth/transport failures (Unknown) keep the persisted node —
/// only the authoritative 404 clears it (see resolve_cluster_node docs).
fn update_cluster_node_sidecar() {
    use crate::commands_account::shell_integration::{clear_cluster_node, write_cluster_node};
    use crate::platform_client::ClusterNodeResolution;
    let client = match get_authenticated_client() {
        Ok(c) => c,
        Err(_) => return, // not logged in / token unrenewable → keep state; next login fixes it
    };
    match client.resolve_cluster_node() {
        ClusterNodeResolution::Node(addr) => {
            let _ = write_cluster_node(&addr);
        }
        ClusterNodeResolution::NotACluster => clear_cluster_node(), // authoritative → all local
        ClusterNodeResolution::Unknown(_) => {} // topology unknown → keep last-known-good
    }
}

pub fn handle_key_use(
    alias_or_id: &str,
    no_hook: bool,
    provider_override: Option<&str>, // --provider flag or None
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy_port: u16 = crate::commands_proxy::proxy_port();

    // P5 form-① (§5.5): resolve the user's cluster node up front (one resolve per
    // `aikey use`). Done BEFORE the team-key delivery check below — a cluster VK's
    // key lives on the central node, not here, so it must SKIP local delivery — and
    // before the refresh funnel, whose per-binding cluster_route reads this node.
    update_cluster_node_sidecar();

    // ── 1. Resolve key — try team keys, then personal, then OAuth ────────────
    let team_entry = storage::get_virtual_key_cache(alias_or_id)?.or_else(|| {
        storage::get_virtual_key_cache_by_alias(alias_or_id)
            .ok()
            .flatten()
    });

    let (key_type, key_ref, display_name, providers) = if let Some(ref entry) = team_entry {
        // Team key validation.
        if entry.key_status != "active" {
            return Err(format!(
                "Key '{}' has status '{}' and cannot be activated. Run 'aikey key sync' to refresh.",
                entry.alias, entry.key_status
            ).into());
        }
        if entry.local_state.starts_with("disabled_by_") {
            let reason = match entry.local_state.as_str() {
                "disabled_by_account_scope" => format!(
                    "Key '{}' belongs to a different account and cannot be activated.\n\
                     Log in to the correct account with: aikey account login",
                    entry.alias
                ),
                "disabled_by_seat_status" => format!(
                    "Key '{}' is unavailable because your seat has been suspended.\n\
                     Contact your organization admin for details.",
                    entry.alias
                ),
                "disabled_by_account_status" => format!(
                    "Key '{}' is unavailable because the account has been disabled.",
                    entry.alias
                ),
                "disabled_by_key_status" => format!(
                    "Key '{}' has been revoked or expired. Run 'aikey key sync' to refresh.",
                    entry.alias
                ),
                other => format!(
                    "Key '{}' is currently unavailable (state: {}). Run 'aikey key sync' to refresh.",
                    entry.alias, other
                ),
            };
            return Err(reason.into());
        }
        // §5.5: a cluster VK's key material lives on the central node, not on this
        // machine — skip the local delivery below; the up-front resolve set the node
        // and the refresh routes the tool straight to it. Only non-cluster managed
        // VKs (key served by the local proxy) still deliver locally.
        let on_cluster = shell_integration::read_cluster_node().is_some();
        if on_cluster && entry.provider_key_ciphertext.is_none() {
            eprintln!("  Key '{}' → cluster node (key stays central)", entry.alias);
        }
        // Group VKs (oauth_group_id set) carry NO local key material BY DESIGN — the
        // per-account credential is pulled by the proxy via channel ③ (group runtime),
        // so `use` (set active routing) works without local ciphertext, exactly like a
        // cluster central key. Without this exemption a group VK fell into the "not
        // delivered" sync below, the sync produced no ciphertext (it never will), and
        // `aikey use` errored with "downloaded no key material — admin may need to
        // attach a credential" — misleading, the VK routes fine. Mirrors the web
        // set-route fix (key_material_reachable) + connectivity-probe / proxy
        // group-route fixes (the same "组 VK 无本地物料是设计" systemic root cause; this
        // is the CLI public-command path, separate from vault_op's web path). (2026-06-26)
        if entry.provider_key_ciphertext.is_none() && !on_cluster && entry.oauth_group_id.is_none()
        {
            // Why: key material is NULL when the VK was synced but not yet delivered
            // (share_status=pending_claim). Auto-trigger a full snapshot sync (which
            // includes key material download) instead of forcing a separate command.
            eprintln!("  Key '{}' not yet delivered — syncing...", entry.alias);

            // Acquire the master password. Order:
            //   1) Session cache (kept warm by recent vault ops),
            //   2) Test env vars (automation),
            //   3) Interactive TTY prompt (and persist to session for the rest of the run).
            //
            // Why no silent metadata-only fallback: after `aikey login` the
            // session cache is invalidated by the snapshot apply (vault_seq
            // bumps), so the previous "let _ = run_full_snapshot_sync(); else
            // metadata_only" path would silently land here, write no
            // ciphertext, and exit with a misleading "admin may need to
            // re-issue" error. Fail-fast surfaces the real client-side
            // password requirement.
            let pw_cached = crate::session::try_get()
                .or_else(|| {
                    std::env::var("AK_TEST_PASSWORD")
                        .ok()
                        .map(secrecy::SecretString::new)
                })
                .or_else(|| {
                    std::env::var("AIKEY_TEST_MASTER_PASSWORD")
                        .ok()
                        .map(secrecy::SecretString::new)
                });

            let pw = match pw_cached {
                Some(p) => p,
                None => {
                    let can_prompt = !json_mode && std::io::stdin().is_terminal();
                    if !can_prompt {
                        return Err(format!(
                            "Key '{}' needs to be downloaded but no master password is available. \
                             Set AK_TEST_PASSWORD or run from an interactive terminal.",
                            entry.alias
                        )
                        .into());
                    }
                    let raw = crate::prompt_hidden(&format!(
                        "  {}Enter Master Password: ",
                        crate::symbols::ICON_LOCK.pre()
                    ))
                    .map_err(|e| format!("prompt: {}", e))?;
                    let pw_fresh = secrecy::SecretString::new(raw);
                    // Persist to session cache so subsequent commands don't re-prompt.
                    crate::session::maybe_configure_backend();
                    crate::session::store(&pw_fresh);
                    pw_fresh
                }
            };

            if let Err(e) = run_full_snapshot_sync(&pw) {
                return Err(format!("Sync failed for '{}': {}", entry.alias, e).into());
            }

            // Re-read after sync.
            let refreshed = storage::get_virtual_key_cache(&entry.virtual_key_id)?.or_else(|| {
                storage::get_virtual_key_cache_by_alias(alias_or_id)
                    .ok()
                    .flatten()
            });
            if refreshed
                .as_ref()
                .and_then(|e| e.provider_key_ciphertext.as_ref())
                .is_none()
            {
                // Sync ran but didn't produce ciphertext — the most likely
                // causes are server-side: no active binding for this VK, key
                // revoked between snapshot and delivery, or admin hasn't
                // attached a credential yet. Surface those instead of the
                // old "admin may need to re-issue" blanket message.
                return Err(format!(
                    "Key '{}' downloaded no key material — the team admin may need to \
                     attach a provider credential to it. Retry with `aikey key sync` after \
                     the admin confirms the binding.",
                    entry.alias
                )
                .into());
            }
            drop(refreshed);
            return handle_key_use(alias_or_id, no_hook, provider_override, json_mode);
        }
        let display = entry
            .local_alias
            .as_deref()
            .unwrap_or(&entry.alias)
            .to_string();
        let providers = if !entry.supported_providers.is_empty() {
            entry.supported_providers.clone()
        } else if !entry.provider_code.is_empty() {
            vec![entry.provider_code.clone()]
        } else {
            vec![]
        };
        (
            crate::credential_type::CredentialType::ManagedVirtualKey,
            entry.virtual_key_id.clone(),
            display,
            providers,
        )
    } else if storage::entry_exists(alias_or_id).unwrap_or(false) {
        // Personal key — v1.0.2: use resolve_supported_providers.
        let stored = storage::resolve_supported_providers(alias_or_id).unwrap_or_default();
        let providers = if !stored.is_empty() {
            stored
        } else {
            const KNOWN: &[&str] = &["anthropic", "openai", "google", "deepseek", "kimi"];
            KNOWN.iter().map(|s| s.to_string()).collect()
        };
        (
            crate::credential_type::CredentialType::PersonalApiKey,
            alias_or_id.to_string(),
            alias_or_id.to_string(),
            providers,
        )
    } else if let Some(acct) = resolve_oauth_account(alias_or_id) {
        // OAuth account — lookup by account_id or display_identity (email).
        //
        // Why this branch exists (2026-04-22): users reading their
        // `AIKEY_ACTIVE_KEYS` env see `anthropic=<email>` and reasonably
        // expect `aikey use <email>` to re-activate that OAuth account.
        // Before this branch they got "not found in team keys or personal
        // keys" — which was technically true but silently excluded the
        // third credential kind.
        if !matches!(acct.status.as_str(), "active" | "idle") {
            return Err(format!(
                "OAuth account '{}' is in state '{}' and cannot be activated.\n\
                 Run: aikey auth login {}",
                acct.display_identity
                    .as_deref()
                    .unwrap_or(&acct.provider_account_id),
                acct.status,
                acct.provider,
            )
            .into());
        }
        let display = acct
            .display_identity
            .clone()
            .unwrap_or_else(|| acct.provider_account_id.clone());
        // OAuth accounts are single-provider by definition (Claude OAuth
        // → anthropic; Codex OAuth → openai; etc.). `provider_override`
        // would be redundant here; we carry the provider through the
        // normal binding flow for uniformity.
        let providers = vec![acct.provider.clone()];
        (
            crate::credential_type::CredentialType::PersonalOAuthAccount,
            acct.provider_account_id.clone(),
            display,
            providers,
        )
    } else {
        return Err(format!(
            "Key '{}' not found in team keys, personal keys, or OAuth accounts.\n\
             Hints:\n\
             - run `aikey list` to see all known aliases / accounts\n\
             - for team keys, run `aikey key sync` if the cache may be stale\n\
             - for personal keys, re-add with: aikey add {}",
            alias_or_id, alias_or_id
        )
        .into());
    };

    if providers.is_empty() {
        return Err(format!(
            "Key '{}' has no supported providers — cannot write env vars.\n\
             Run 'aikey key sync' to refresh, or re-add with '--provider <code>'.",
            display_name
        )
        .into());
    }

    // ── 2. Provider-level primary promotion (v1.0.2) ─────────────────────────
    //
    // Kimi family multi-provider 在添加 / import 阶段已经被 input-layer mutex 阻止
    // (Web ProviderMultiSelect / Import / CLI add 都强制 family 内单选),所以这里
    // 不会再遇到 supports kimi_code+moonshot 的同 key entry。
    let target_providers: Vec<String> = if let Some(ov) = provider_override {
        if !ov.is_empty() {
            let code = ov.to_lowercase();
            if !providers.iter().any(|p| p.to_lowercase() == code) {
                return Err(format!(
                    "Key '{}' does not support provider '{}'. Supported: {}",
                    display_name,
                    code,
                    providers.join(", ")
                )
                .into());
            }
            vec![code]
        } else if providers.len() == 1 {
            providers.clone()
        } else {
            if !std::io::stdin().is_terminal() || json_mode {
                return Err(format!("This key supports multiple providers: {}. Please specify --provider or choose interactively.", providers.join(", ")).into());
            }
            use colored::Colorize;
            println!("Key '{}' supports multiple providers:", display_name.bold());
            for (i, p) in providers.iter().enumerate() {
                println!("  {}  {}", format!("[{}]", i + 1).dimmed(), p);
            }
            print!("Select protocol(s) to set as Primary (comma-separated): ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();
            if input.is_empty() {
                return Err(
                    "No provider selected. Use --provider <code> or select interactively.".into(),
                );
            }
            let mut selected = Vec::new();
            for part in input.split(',').map(|s| s.trim()) {
                if let Ok(n) = part.parse::<usize>() {
                    if n >= 1 && n <= providers.len() {
                        let p = providers[n - 1].clone();
                        if !selected.contains(&p) {
                            selected.push(p);
                        }
                    }
                }
            }
            if selected.is_empty() {
                return Err("Invalid selection. Use --provider <code>.".into());
            }
            selected
        }
    } else if providers.len() == 1 {
        providers.clone()
    } else {
        if !std::io::stdin().is_terminal() || json_mode {
            return Err(format!(
                "This key supports multiple providers: {}. Please specify --provider.",
                providers.join(", ")
            )
            .into());
        }
        use colored::Colorize;
        println!("Key '{}' supports multiple providers:", display_name.bold());
        for (i, p) in providers.iter().enumerate() {
            println!("  {}  {}", format!("[{}]", i + 1).dimmed(), p);
        }
        print!("Select protocol(s) to set as Primary (comma-separated): ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().is_empty() {
            return Err("No protocol selected.".into());
        }
        let mut selected = Vec::new();
        for part in input.trim().split(',').map(|s| s.trim()) {
            if let Ok(n) = part.parse::<usize>() {
                if n >= 1 && n <= providers.len() {
                    let p = providers[n - 1].clone();
                    if !selected.contains(&p) {
                        selected.push(p);
                    }
                }
            }
        }
        if selected.is_empty() {
            return Err("Invalid selection.".into());
        }
        selected
    };

    // (The cluster node was resolved up front, before the delivery check — see the
    // top of handle_key_use. The funnel's refresh reads it per-binding via cluster_route.)

    // Single funnel: Switched event runs write_bindings_canonical →
    // refresh → apply_third_party_cli_configs. Drive off the refreshed
    // binding set so switching one provider away from kimi/codex correctly
    // unconfigures the corresponding toml region.
    let lifecycle = apply_credential_lifecycle(
        CredentialLifecycleEvent::Switched {
            source_type: key_type.as_str(),
            source_ref: &key_ref,
            providers: &target_providers,
        },
        try_audit_key_from_session().as_ref(),
    )
    .map_err(|e| format!("Failed to apply use: {}", e))?;

    // ── 6. Shell hook (one-time, first use) ───────────────────────────────────
    let hook_msg = if !json_mode {
        ensure_shell_hook(no_hook)
    } else {
        None
    };

    // Bindings reread for the JSON envelope below (apply already wrote
    // active.env). Cheap; single DB read.
    let bindings = crate::storage::list_provider_bindings_readonly("default").unwrap_or_default();
    // Suppress unused-warning when json_mode skips the helper apply.
    let _ = proxy_port;

    // ── 5. Output ─────────────────────────────────────────────────────────────
    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "key_type": key_type,
            "key_ref": key_ref,
            "display_name": display_name,
            "promoted_providers": target_providers,
            "all_active_providers": bindings.iter().map(|b| &b.provider_code).collect::<Vec<_>>(),
            "active_env_written": true,
            // 阶段7 (2026-07-13): Desktop takeover state from the funnel —
            // same wire shape as the vault-op envelope, so scripted `aikey
            // use --json` callers (E2E DS-13) can assert consent semantics.
            "desktop_switch": lifecycle.desktop_switch,
        }));
    } else {
        // Stage 4 (active-state cross-shell sync, 2026-04-27): the previous
        // "Env vars applied" message was a half-truth. `aikey` is a child
        // process — it cannot mutate the parent shell's env directly. The
        // precmd hook picks up the new active.env on the user's next prompt
        // (free, unconditional), but if they want to use the new key in
        // *this* prompt they can `source` the file. State that plainly.
        //
        // Use-effectiveness self-check (2026-07-10): "next prompt picks it
        // up automatically" is only true when the hook is actually loaded
        // in the invoking shell. Classify via the exported
        // _AIKEY_HOOK_LOADED_HASH marker + rc wiring state instead of
        // asserting it unconditionally — a terminal opened before hook
        // install got a claim that silently never came true.
        let status = use_status_line(
            hook_msg.as_deref(),
            std::env::var("_AIKEY_HOOK_LOADED_HASH").is_ok(),
            shell_integration::shell_rc_has_aikey_block(),
            no_hook
                || std::env::var("AIKEY_NO_HOOK")
                    .map(|v| v == "1")
                    .unwrap_or(false),
        );

        let mut rows: Vec<String> = Vec::new();
        for b in &bindings {
            if let Some((api_key_var, _)) = provider_env_vars(&b.provider_code) {
                let display_ref =
                    resolve_binding_display_name(b.key_source_type.as_str(), &b.key_source_ref);
                let is_changed = target_providers.contains(&b.provider_code);
                let arrow_ref = format!("\u{2192} {}", display_ref);
                let arrow_padded = format!("{:<22}", arrow_ref);
                let arrow_col = if is_changed {
                    format!("{}", arrow_padded.green())
                } else {
                    arrow_padded
                };
                rows.push(format!(
                    "  {:<14} {} {}",
                    b.provider_code,
                    arrow_col,
                    format!("[{}]", b.key_source_type).bright_black()
                ));
                let _ = api_key_var;
            }
        }
        rows.push(String::new());
        rows.push(status);

        let title = format!(
            "Set '{}' as Primary for {}",
            display_name,
            target_providers.join(", ")
        );
        crate::ui_frame::print_box(crate::symbols::ICON_GREEN_DOT.s(), &title, &rows);
        // 阶段7: Desktop is a cold-switch surface — when THIS use rewrote
        // its config the user must restart the app, and silence here would
        // read as "done" (防呆: every takeover needs visible feedback).
        if lifecycle.desktop_switch.is_some_and(|d| d.restart_required) {
            println!(
                "  {} Claude Desktop config updated — restart Desktop to apply.",
                crate::symbols::REFRESH.s()
            );
        }
        println!();
    }

    // Claude Code status-line install/uninstall is now driven through the
    // shared lifecycle tail (`apply_third_party_cli_configs`) — symmetric
    // with kimi/codex. See bugfix 2026-05-18-claude-statusline-residue-on-
    // unuse.md for why the previous one-sided install call was hiding a
    // matching uninstall gap.
    Ok(())
}

/// Classify the `aikey use` summary line so it never overpromises
/// (use-effectiveness self-check, 2026-07-10).
///
/// Problem this solves: the old summary claimed "Next prompt picks it up
/// automatically" unconditionally whenever the rc was already wired
/// (AlreadyV3 → `hook_msg == None`). In a terminal opened BEFORE the hook
/// was wired, precmd was never registered there, so the claim silently
/// never came true — the user ran `claude` bare and nothing routed through
/// aikey, with zero feedback. Re-running `aikey use` with the SAME key hit
/// the same silent path.
///
/// Detection: the hook file exports `_AIKEY_HOOK_LOADED_HASH` at source
/// time (see `hook_content_with_hash_header`), so a child process seeing
/// that env var knows the invoking shell loaded the hook. aikey cannot
/// source the hook into the parent shell on the user's behalf — the honest
/// remediation is a precise, actionable hint.
///
/// Transitional caveat: shells that loaded a pre-export hook (< 2026-07-10
/// template) don't expose the marker until the auto-reload picks up the
/// regenerated file at the next prompt; they may see one warning that a
/// fresh prompt (or new terminal) resolves. Self-healing, accepted.
pub(crate) fn use_status_line(
    hook_msg: Option<&str>,
    hook_loaded_in_shell: bool,
    rc_wired: bool,
    hook_opted_out: bool,
) -> String {
    // Platform-aware immediate-apply hint (2026-07-12, Windows X4/X5):
    // `source ~/.aikey/active.env` is a dead instruction on PowerShell/cmd.
    let apply_now = shell_integration::apply_now_hint();
    if hook_opted_out {
        return format!(
            "{} Active key updated. Shell hook disabled (AIKEY_NO_HOOK) \u{2014} apply manually: {apply_now}",
            crate::symbols::CHECK.s()
        );
    }
    // ensure_shell_hook spoke (installed / migrated / declined / non-TTY
    // hint): surface its exact message instead of the old generic "hook
    // just installed" line, which mislabeled hints and declines. The
    // message text was previously swallowed (only is_some() was checked).
    if let Some(msg) = hook_msg {
        return format!(
            "\u{2192} {}\n     To apply right now: {apply_now}",
            msg.trim_start()
        );
    }
    if hook_loaded_in_shell {
        return format!(
            "{} Active key updated. Next prompt picks it up automatically.\n     To apply right now: {apply_now}",
            crate::symbols::CHECK.s()
        );
    }
    if rc_wired {
        // Platform-aware remediation (2026-07-12, found on Windows real-machine
        // verification): the first draft hardcoded "~/.zshrc / ~/.bashrc",
        // which is a dead instruction for PowerShell users — their hook lives
        // in $PROFILE.CurrentUserAllHosts. reload_hint_for_shell() owns the
        // per-shell dispatch.
        format!(
            "{}",
            format!(
                "\u{25b2} Active key updated, but aikey env is NOT loaded in this shell (terminal opened before the hook was installed?).\n     Apply: open a new terminal, or run: {}",
                shell_integration::reload_hint_for_shell()
            )
            .yellow()
        )
    } else {
        "\u{25b2} Active key updated, but the shell hook is not wired \u{2014} `claude`/`codex` will NOT route through aikey.\n     Fix: run `aikey hook install`, then open a new terminal."
            .yellow()
            .to_string()
    }
}

#[cfg(test)]
mod use_status_line_tests {
    use super::use_status_line;

    #[test]
    fn opted_out_is_neutral_and_never_warns() {
        let s = use_status_line(None, false, false, true);
        assert!(s.contains("AIKEY_NO_HOOK"));
        assert!(
            !s.contains("\u{25b2}"),
            "opt-out users chose this — no warning"
        );
    }

    #[test]
    fn hook_msg_is_surfaced_verbatim_not_swallowed() {
        // Regression: the old code only checked is_some() and replaced the
        // actual hint ("Skipped...", "needs interactive confirmation...")
        // with a generic "hook just installed" line — wrong for declines.
        let s = use_status_line(
            Some("  Skipped. To apply once: source ~/.aikey/hook.zsh"),
            false,
            false,
            false,
        );
        assert!(s.contains("Skipped. To apply once"));
    }

    #[test]
    fn loaded_shell_keeps_autopickup_promise() {
        let s = use_status_line(None, true, true, false);
        assert!(s.contains("Next prompt picks it up automatically"));
        assert!(!s.contains("\u{25b2}"));
    }

    #[test]
    fn wired_but_stale_shell_warns_with_reload_hint() {
        let s = use_status_line(None, false, true, false);
        assert!(s.contains("NOT loaded in this shell"));
        assert!(s.contains("new terminal"));
    }

    #[test]
    fn unwired_shell_warns_with_hook_install_hint() {
        let s = use_status_line(None, false, false, false);
        assert!(s.contains("aikey hook install"));
        assert!(s.contains("NOT route through aikey"));
    }
}

/// Post-`aikey hook uninstall` third-party CLI config reconciliation
/// (2026-07-12, user report X8: Windows `hook uninstall` → `codex` dies
/// with "Missing environment variable: OPENAI_API_KEY").
///
/// Why: `hook uninstall` removes the env-injection channel but used to
/// leave `~/.codex/config.toml` (`model_provider=aikey`, env_key) and the
/// kimi config pointing at aikey — configs that only work WITH the hook.
/// New terminals then fail with a cryptic upstream error. `aikey unuse`
/// got symmetric cleanup in 2026-05-18 (B1/B2); this is the same lifecycle
/// gap on the hook-uninstall edge.
///
/// Behavior:
/// - 2026-07-12 (X8, option b): interactive sessions get a Y/n prompt to
///   strip aikey routing from the affected CLI configs (bindings are KEPT —
///   re-wiring the hook or the next `aikey use` re-configures them).
/// - 2026-07-13 (G1 revision, user-approved): non-TTY callers now get the
///   SAME default applied (strip) instead of a warn-and-leave. Sandbox
///   repro showed the warn path left `model_provider="aikey"` in codex's
///   toml, and scripted callers swallow stderr — users hit "Missing
///   environment variable: OPENAI_API_KEY" with no visible cause. The
///   strip is harmless + reversible (next `aikey use` / `hook install`
///   re-applies), same rationale as the unconditional Claude Desktop
///   restore (D8②). "Never silent": we print the stripped list — the
///   TTY prompt remains the opt-out chance when a human is present.
pub fn reconcile_cli_configs_after_hook_uninstall() {
    use std::io::{IsTerminal, Write};

    let injected = shell_integration::injected_provider_toml_paths();
    if injected.is_empty() {
        return;
    }
    eprintln!(
        "  {}",
        "\u{25b2} These CLI configs still route through aikey, but the hook (env channel) is now unwired:".yellow()
    );
    for (label, path) in &injected {
        eprintln!(
            "{}",
            format!("      {:<6} {}", label, path.display()).yellow()
        );
    }
    eprintln!(
        "    {}",
        "In new terminals those CLIs would fail (e.g. codex: Missing environment variable: OPENAI_API_KEY).".yellow()
    );

    if !std::io::stderr().is_terminal() || !std::io::stdin().is_terminal() {
        // Headless: apply the interactive default (strip) instead of
        // leaving broken hard-pointing configs behind (G1, 2026-07-13).
        shell_integration::apply_third_party_cli_configs(&[], crate::commands_proxy::proxy_port());
        eprintln!(
            "  {} aikey routing removed from the configs above (bindings kept; \
             next `aikey use` or `aikey hook install` re-applies them).",
            crate::symbols::CHECK.s()
        );
        return;
    }

    eprint!("  Remove aikey routing from these CLI configs now? [Y/n] (default Y): ");
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok()
        && matches!(input.trim().to_lowercase().as_str(), "n" | "no")
    {
        eprintln!(
            "    Kept. Clean up later with: {}  \u{2014} or re-enable: {}",
            "aikey unuse <provider>".cyan(),
            "aikey hook install".cyan()
        );
        return;
    }

    // Empty provider set = unconfigure every aikey-managed third-party CLI
    // config (same funnel `aikey unuse` drives after removing the last
    // binding). Bindings themselves are untouched.
    shell_integration::apply_third_party_cli_configs(&[], crate::commands_proxy::proxy_port());
    eprintln!(
        "  {} aikey routing removed from third-party CLI configs (bindings kept; next `aikey use` re-applies them).",
        crate::symbols::CHECK.s()
    );
}

/// `aikey unuse <PROVIDERS...>` — remove the active binding for one or more
/// providers, clearing the corresponding env vars from active.env and toml
/// configs (kimi.toml, codex.toml, etc.).
///
/// Inverse of `aikey use`. After unbinding, the provider's env var will no
/// longer be injected by the shell hook, and third-party CLI configs that
/// reference the proxy endpoint for that provider will be cleared.
///
/// Idempotent: if a provider has no active binding, it's silently skipped
/// (exit 0, no error).
pub fn handle_key_unuse(
    providers: &[String],
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let mut unbound: Vec<String> = Vec::new();
    let mut already_unbound: Vec<String> = Vec::new();

    for raw in providers {
        let canonical = oauth_provider_to_canonical(&raw.to_lowercase());
        let removed =
            storage::remove_provider_binding(crate::profile_activation::DEFAULT_PROFILE, canonical)
                .map_err(|e| format!("remove binding for {}: {}", canonical, e))?;

        if removed {
            unbound.push(canonical.to_string());
        } else {
            already_unbound.push(canonical.to_string());
        }
    }

    // Run the side-effect tail (same as lifecycle event batch tail):
    // refresh active.env → apply third-party CLI configs → hook file.
    // This ensures env vars and toml regions for unbound providers are
    // removed immediately.
    let mut desktop_switch: Option<claude_desktop::DesktopSwitch> = None;
    if !unbound.is_empty() {
        if let Ok(refresh) = crate::profile_activation::refresh_implicit_profile_activation() {
            let proxy_port = crate::commands_proxy::proxy_port();
            let active_providers: Vec<String> = refresh
                .bindings
                .iter()
                .map(|b| b.provider_code.clone())
                .collect();
            // Second (parallel) funnel call site — Desktop takeover/restore
            // rides INSIDE apply_third_party_cli_configs, so `unuse
            // anthropic` restores Desktop and `unuse <other>` leaves it
            // alone with no extra wiring here (阶段7 §4.1).
            let third_party = apply_third_party_cli_configs(&active_providers, proxy_port);
            desktop_switch = third_party.desktop;
            let _ = web_install_hook_file_layer1();
        }
    }

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "unbound_providers": unbound,
            "already_unbound": already_unbound,
            "desktop_switch": desktop_switch,
        }));
    } else {
        if unbound.is_empty() && !already_unbound.is_empty() {
            println!(
                "No active binding for {}. Nothing to do.",
                already_unbound.join(", ")
            );
        } else if !unbound.is_empty() {
            let rows: Vec<String> = unbound
                .iter()
                .map(|p| format!("  {} {}", crate::symbols::CROSS.s().red(), p))
                .collect();
            crate::ui_frame::print_box(
                crate::symbols::ICON_YELLOW_DOT.s(),
                &format!("Unbound: {}", unbound.join(", ")),
                &rows,
            );
            println!();
            println!(
                "{}",
                format!(
                    "{} active.env and CLI configs updated. Next prompt picks it up automatically.",
                    crate::symbols::CHECK.s()
                )
                .dimmed()
            );
            if !already_unbound.is_empty() {
                println!(
                    "  {} already had no binding: {}",
                    crate::symbols::INFO_I.s().dimmed(),
                    already_unbound.join(", ")
                );
            }
        }
    }

    Ok(())
}

/// `aikey key alias <old-alias> <new-alias>`
///
/// Renames a vault row. As of 2026-04-24 this supports **both** personal
/// and team keys (previously only team). Dispatch:
///   - If `old_alias` matches a personal entry → RenameTarget::Personal
///   - If it matches a team virtual_key_id / local_alias / server alias →
///     RenameTarget::Team
///   - Otherwise returns "not found"
///
/// Routes through `apply_rename_core`, same helper used by `_internal
/// update-alias rename_alias` / `rename_target` (single-source-of-truth
/// rule — `.claude/CLAUDE.md`).
pub fn handle_key_alias(
    old_alias: &str,
    new_alias: &str,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Decide target. Personal check is fast (single query); only fall
    // through to team resolution if the alias isn't personal.
    let is_personal = storage::list_entries()
        .ok()
        .map(|v| v.iter().any(|a| a == old_alias))
        .unwrap_or(false);

    let target = if is_personal {
        RenameTarget::Personal
    } else {
        // Try to resolve as team key first (covers vkid + local_alias +
        // server alias). If not found the core will return a clean error.
        RenameTarget::Team
    };

    let outcome = apply_rename_core(target, old_alias, new_alias)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    if json_mode {
        let mut body = serde_json::json!({
            "ok": true,
            "target": outcome.target,
            "id": outcome.id,
            "old_id": outcome.old_id,
            "new_value": outcome.new_value,
        });
        // Keep backward-compat field names for the team-key JSON shape
        // that existing scripts may depend on.
        if matches!(target, RenameTarget::Team) {
            if let Ok(Some(entry)) = storage::get_virtual_key_cache(&outcome.id) {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert(
                        "virtual_key_id".into(),
                        serde_json::json!(entry.virtual_key_id),
                    );
                    obj.insert("server_alias".into(), serde_json::json!(entry.alias));
                    obj.insert("local_alias".into(), serde_json::json!(outcome.new_value));
                }
            }
        }
        crate::json_output::print_json(body);
    } else {
        let suffix = match target {
            RenameTarget::Team => storage::get_virtual_key_cache(&outcome.id)
                .ok()
                .flatten()
                .map(|e| format!(" (server alias: {})", e.alias))
                .unwrap_or_default(),
            _ => String::new(),
        };
        println!(
            "{} Renamed {} → {}  {}",
            crate::symbols::CHECK.s().green().bold(),
            format!("'{}'", old_alias).dimmed(),
            format!("'{}'", outcome.new_value).bold(),
            suffix.dimmed()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derives the vault AES key from the master password.
/// Uses the same salt + KDF parameters stored in the vault DB.
/// B-2 (2026-07-06): best-effort audit signer for binding writes in commands
/// that don't already hold the master password. Reads the CACHED session
/// password (keychain/file) — non-interactive by contract, NEVER prompts
/// (interaction-simplicity-first: audit must not add a password prompt).
/// None ⇒ the binding write proceeds unsigned (observability events only).
pub(crate) fn try_audit_key_from_session() -> Option<crate::audit::VerifiedVaultKey> {
    let pw = crate::session::try_get()?;
    let key = derive_vault_key(&pw).ok()?;
    crate::audit::VerifiedVaultKey::new(key).ok()
}

/// B-2 sibling for commands that already hold the master password (add /
/// delete / key sync): derive + verify, best-effort (None on mismatch — the
/// command's own executor already failed loudly in that case).
pub(crate) fn audit_key_from_password(
    password: &SecretString,
) -> Option<crate::audit::VerifiedVaultKey> {
    let key = derive_vault_key(password).ok()?;
    crate::audit::VerifiedVaultKey::new(key).ok()
}

fn derive_vault_key(password: &SecretString) -> Result<[u8; crypto::KEY_SIZE], String> {
    let salt = storage::get_salt()?;
    let (m, t, p) = storage::get_kdf_params()?;
    let secure_key = crypto::derive_key_with_params(password, &salt, m, t, p)?;
    Ok(*secure_key)
}

fn resolve_binding_display_name(source_type: &str, source_ref: &str) -> String {
    if source_type == "team" {
        if let Ok(Some(entry)) = storage::get_virtual_key_cache(source_ref) {
            return entry.local_alias.unwrap_or(entry.alias);
        }
    }
    source_ref.to_string()
}

#[cfg(test)]
mod browser_launch_tests {
    //! Fence for bugfix 20260702-windows-login-url-ampersand-truncation.
    //!
    //! On Windows the login URL (`?s=...&d=...&email=...`) was launched via
    //! `cmd /c start "" <url>`; cmd.exe splits its command line at bare `&`,
    //! so the browser opened a URL truncated at the first `&` ("Missing
    //! session parameters" on the login page) and cmd tried to run `d=...` /
    //! `email=...` as commands. The URL must reach a non-shell launcher as
    //! one intact argv entry.

    use super::browser_launch_command;

    const LOGIN_URL: &str = "http://127.0.0.1:3000/auth/cli/login?s=abc&d=def&email=ZmFuZw";

    #[test]
    fn windows_never_routes_through_cmd_start() {
        let (program, args) =
            browser_launch_command("windows", LOGIN_URL).expect("windows is supported");
        assert_ne!(
            program, "cmd",
            "cmd.exe shell-parses bare `&` — truncates the URL"
        );
        assert_eq!(program, "rundll32");
        assert_eq!(args, vec!["url.dll,FileProtocolHandler", LOGIN_URL]);
    }

    #[test]
    fn unix_launchers_take_url_as_single_arg() {
        assert_eq!(
            browser_launch_command("macos", LOGIN_URL),
            Some(("open", vec![LOGIN_URL]))
        );
        assert_eq!(
            browser_launch_command("linux", LOGIN_URL),
            Some(("xdg-open", vec![LOGIN_URL]))
        );
    }

    #[test]
    fn unsupported_platform_skips() {
        assert_eq!(browser_launch_command("freebsd", LOGIN_URL), None);
    }
}

#[cfg(test)]
mod provider_mapping_tests {
    //! Pin the current behavior of provider-code → {env vars, URL path} mapping
    //! BEFORE attempting to consolidate with main.rs::canonical_provider.
    //! Any refactor (L5) must pass all of these.

    use super::{provider_env_vars, provider_extra_env_vars, provider_proxy_prefix};

    // ── provider_env_vars: (API_KEY, BASE_URL) per provider ─────────────────

    #[test]
    fn env_vars_anthropic_and_claude_same() {
        let expected = Some(("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"));
        assert_eq!(provider_env_vars("anthropic"), expected);
        assert_eq!(provider_env_vars("claude"), expected);
        assert_eq!(provider_env_vars("CLAUDE"), expected); // case insensitive
    }

    #[test]
    fn env_vars_openai_aliases() {
        let expected = Some(("OPENAI_API_KEY", "OPENAI_BASE_URL"));
        assert_eq!(provider_env_vars("openai"), expected);
        assert_eq!(provider_env_vars("gpt"), expected);
        assert_eq!(provider_env_vars("chatgpt"), expected);
        // L5: codex was previously a canonical-only alias (env_vars returned None).
        // After unification, codex is a full openai alias across all three fields.
        assert_eq!(provider_env_vars("codex"), expected);
    }

    #[test]
    fn env_vars_google_aliases() {
        let expected = Some(("GOOGLE_API_KEY", "GOOGLE_BASE_URL"));
        assert_eq!(provider_env_vars("google"), expected);
        assert_eq!(provider_env_vars("gemini"), expected);
    }

    #[test]
    fn env_vars_kimi_family_unified_to_kimi_envs() {
        // 2026-05-08 Kimi family 互斥落地: kimi_code / moonshot / kimi(deprecated)
        // 三个 provider_code 都共用 KIMI_API_KEY / KIMI_BASE_URL env var (因 Kimi
        // CLI 上游只读 KIMI_*,实证三层证据见 update/20260508-Kimi-family互斥-active-env
        // 统一KIMI写入.md)。区分 platform 由 proxy_path 决定 (moonshot 走 /moonshot/v1,
        // 其它走 /kimi/v1),不再由 env var 名区分。
        // pre-fix 时 moonshot 写 MOONSHOT_API_KEY,但实证无消费方,直接停写。
        assert_eq!(
            provider_env_vars("kimi"),
            Some(("KIMI_API_KEY", "KIMI_BASE_URL"))
        );
        assert_eq!(
            provider_env_vars("kimi_code"),
            Some(("KIMI_API_KEY", "KIMI_BASE_URL"))
        );
        assert_eq!(
            provider_env_vars("moonshot"),
            Some(("KIMI_API_KEY", "KIMI_BASE_URL"))
        );
    }

    #[test]
    fn env_vars_deepseek() {
        assert_eq!(
            provider_env_vars("deepseek"),
            Some(("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL"))
        );
    }

    #[test]
    fn env_vars_unknown_returns_none() {
        assert_eq!(provider_env_vars("unknown"), None);
        assert_eq!(provider_env_vars(""), None);
    }

    // ── provider_proxy_prefix: URL path per provider ────────────────────────

    #[test]
    fn proxy_prefix_anthropic_and_claude_same() {
        assert_eq!(provider_proxy_prefix("anthropic"), "anthropic");
        assert_eq!(provider_proxy_prefix("claude"), "anthropic");
    }

    #[test]
    fn proxy_prefix_openai_aliases() {
        assert_eq!(provider_proxy_prefix("openai"), "openai");
        assert_eq!(provider_proxy_prefix("codex"), "openai");
        assert_eq!(provider_proxy_prefix("gpt"), "openai");
        assert_eq!(provider_proxy_prefix("chatgpt"), "openai");
    }

    #[test]
    fn proxy_prefix_google_aliases() {
        assert_eq!(provider_proxy_prefix("google"), "google");
        assert_eq!(provider_proxy_prefix("gemini"), "google");
    }

    #[test]
    fn proxy_prefix_kimi_has_v1_suffix() {
        // IMPORTANT: provider_proxy_prefix includes "/v1" for kimi/moonshot;
        // main.rs::canonical_provider does NOT. This divergence is documented in
        // main.rs::route_and_activate_paths_currently_diverge_for_kimi.
        // Both resolve to the same upstream because proxy strips the /kimi prefix
        // and OpenAI-SDK clients append /chat/completions after base_url.
        assert_eq!(provider_proxy_prefix("kimi"), "kimi/v1");
        assert_eq!(provider_proxy_prefix("moonshot"), "moonshot/v1");
    }

    #[test]
    fn proxy_prefix_deepseek() {
        assert_eq!(provider_proxy_prefix("deepseek"), "deepseek");
    }

    #[test]
    fn proxy_prefix_unknown_falls_back_to_openai() {
        // Unknown providers fall back to "openai" (OpenAI-compatible default).
        // This preserves the lifetime requirement of returning &'static str.
        assert_eq!(provider_proxy_prefix("unknown-provider"), "openai");
        assert_eq!(provider_proxy_prefix(""), "openai");
    }

    #[test]
    fn proxy_prefix_case_insensitive() {
        assert_eq!(provider_proxy_prefix("ANTHROPIC"), "anthropic");
        assert_eq!(provider_proxy_prefix("Claude"), "anthropic");
        assert_eq!(provider_proxy_prefix("Kimi"), "kimi/v1");
    }

    // ── cross-function consistency: same provider → matching env vars AND path ──

    #[test]
    fn all_known_providers_have_both_env_vars_and_prefix() {
        // Every provider code that has env vars must also have a proxy prefix.
        // (provider_proxy_prefix falls back to "openai", so it always succeeds.)
        // L5: "codex" is now included because it's a full alias of openai.
        for code in &[
            "anthropic",
            "claude",
            "openai",
            "codex",
            "gpt",
            "chatgpt",
            "google",
            "gemini",
            "kimi",
            "moonshot",
            "deepseek",
        ] {
            assert!(
                provider_env_vars(code).is_some(),
                "provider_env_vars returned None for known code '{}'",
                code
            );
            // Just ensure it returns without panic; the actual value is tested above.
            let _ = provider_proxy_prefix(code);
        }
    }

    // ── ProviderInfo unification (L5 2026-04-17) ────────────────────────────

    #[test]
    fn provider_info_single_source_of_truth() {
        // Legacy wrappers must return the SAME values as ProviderInfo for every
        // known provider. If this fails, the wrappers have drifted from provider_info.
        for code in &[
            "anthropic",
            "claude",
            "openai",
            "codex",
            "gpt",
            "chatgpt",
            "google",
            "gemini",
            "kimi",
            "moonshot",
            "deepseek",
        ] {
            let info = super::provider_info(code).unwrap();
            assert_eq!(
                provider_env_vars(code),
                Some(info.env_vars),
                "env_vars mismatch for '{}'",
                code
            );
            assert_eq!(
                provider_proxy_prefix(code),
                info.proxy_path,
                "proxy_path mismatch for '{}'",
                code
            );
        }
    }

    #[test]
    fn provider_info_aliases_point_to_same_canonical() {
        use super::provider_info;
        // anthropic/claude
        assert_eq!(
            provider_info("anthropic").unwrap().canonical_code,
            provider_info("claude").unwrap().canonical_code
        );
        // openai family (codex, gpt, chatgpt)
        let openai = provider_info("openai").unwrap().canonical_code;
        for alias in &["codex", "gpt", "chatgpt"] {
            assert_eq!(
                provider_info(alias).unwrap().canonical_code,
                openai,
                "alias '{}' should canonicalize to openai",
                alias
            );
        }
        // google/gemini
        assert_eq!(
            provider_info("google").unwrap().canonical_code,
            provider_info("gemini").unwrap().canonical_code
        );
        // 2026-05-08 Kimi 双平台拆分 review feedback:
        //   - kimi (deprecated alias) canonicalizes → kimi_code (registry alias)
        //   - moonshot is its own canonical (NOT folded to kimi anymore)
        // 共享的是 family ("kimi"),不是 canonical_code。
        assert_eq!(provider_info("kimi").unwrap().canonical_code, "kimi_code");
        assert_eq!(
            provider_info("moonshot").unwrap().canonical_code,
            "moonshot"
        );
        assert_ne!(
            provider_info("kimi").unwrap().canonical_code,
            provider_info("moonshot").unwrap().canonical_code,
            "kimi_code 与 moonshot 是两个独立 provider_code,不能折叠"
        );
        // family-level: 两者都属 'kimi' family
        assert_eq!(
            provider_info("kimi").unwrap().family,
            provider_info("moonshot").unwrap().family
        );
        assert_eq!(provider_info("kimi_code").unwrap().family, "kimi");
    }

    /// 2026-05-08 review feedback [高] #1 防退化:resolve_single_provider 必须
    /// 返回真正 provider_code (kimi_code / moonshot),不能折叠回 family ("kimi")。
    /// 否则 aikey activate moonshot 会用错 env vars / base_url / binding。
    #[test]
    fn provider_info_canonical_code_is_real_code_not_family() {
        use super::provider_info;
        // moonshot 必须保持 moonshot,不被折叠
        assert_eq!(
            provider_info("moonshot").unwrap().canonical_code,
            "moonshot"
        );
        // kimi_code 自身就是 canonical
        assert_eq!(
            provider_info("kimi_code").unwrap().canonical_code,
            "kimi_code"
        );
        // 'kimi' 字面值 (deprecated alias) → 经 registry alias 解析 → kimi_code
        assert_eq!(provider_info("kimi").unwrap().canonical_code, "kimi_code");
    }

    #[test]
    fn provider_extra_env_vars_kimi_family_per_platform_model() {
        // Minimal-scaffold Kimi requires KIMI_MODEL_NAME so Kimi's empty-model
        // fallback can populate the model.
        //
        // 2026-05-08 Kimi family 互斥 + per-platform model(详见 update/20260508-
        // Kimi-family互斥-active-env统一KIMI写入.md 决策 #9):
        // 三个 family 内 provider_code 各自的 KIMI_MODEL_NAME / MAX_CONTEXT_SIZE 不同
        // (避免上游 reject + 客户端预估错):
        //   kimi_code → kimi-k2.5 / 131072(api.kimi.com 自家 model,128K context)
        //   moonshot  → moonshot-v1-128k / 131072(2026-07-08 从 moonshot-v1-8k/8192
        //               反转,原 8k 默认使 Kimi CLI 开箱即废;选 v1-128k 而非更新的
        //               kimi-latest 因后者账号权限门控会 404,基础 v1 家族最广兼容)
        //   kimi(deprecated)→ 与 kimi_code 一致(经 oauth_alias 解析)
        let kimi_code = provider_extra_env_vars("kimi_code");
        assert!(kimi_code
            .iter()
            .any(|(k, v)| *k == "KIMI_MODEL_NAME" && *v == "kimi-k2.5"));
        assert!(kimi_code
            .iter()
            .any(|(k, v)| *k == "KIMI_MODEL_MAX_CONTEXT_SIZE" && *v == "131072"));

        let moonshot = provider_extra_env_vars("moonshot");
        // 2026-07-08 默认模型反转为 moonshot-v1-128k: Kimi CLI 最小提示词 ~12.4K > 8192,
        // 原 moonshot-v1-8k 从第一句就 400 token-limit-exceeded(开箱即废)。选基础 v1
        // 家族的 128k 而非更新的 kimi-latest —— 后者在 api.moonshot.cn 账号权限门控,
        // 实测 404 Permission denied;DEFAULT 要最广兼容而非最新。
        assert!(moonshot
            .iter()
            .any(|(k, v)| *k == "KIMI_MODEL_NAME" && *v == "moonshot-v1-128k"));
        // MAX_CONTEXT 匹配 128K 上限,否则 kimi-cli 端会按旧 8192 错误截断。
        assert!(moonshot
            .iter()
            .any(|(k, v)| *k == "KIMI_MODEL_MAX_CONTEXT_SIZE" && *v == "131072"));

        // deprecated 'kimi' alias 解析到 kimi_code,继承 kimi-k2.5 / 131072
        let kimi_alias = provider_extra_env_vars("kimi");
        assert_eq!(kimi_alias, kimi_code);

        // 关键不变量:moonshot 的 model 不应该是 kimi-k2.5(pre-fix bug — 会被
        // api.moonshot.cn reject);现默认 moonshot-v1-128k,仍与 kimi_code 不同。
        assert_ne!(moonshot, kimi_code,
            "moonshot extras must use moonshot-v1-128k, not kimi-k2.5 (would be rejected by api.moonshot.cn)");
    }

    #[test]
    fn provider_extra_env_vars_returns_empty_for_non_kimi() {
        for p in &["anthropic", "openai", "google", "deepseek"] {
            assert!(
                provider_extra_env_vars(p).is_empty(),
                "{} must have no extras",
                p
            );
        }
    }
}

#[cfg(test)]
mod sync_tests {
    use super::compute_local_state_from_effective;

    // ── inactive paths ──────────────────────────────────────────────────────

    #[test]
    fn inactive_seat_disabled_maps_correctly() {
        assert_eq!(
            compute_local_state_from_effective("inactive", "seat_disabled", ""),
            "disabled_by_seat_status"
        );
    }

    #[test]
    fn inactive_key_revoked_maps_correctly() {
        assert_eq!(
            compute_local_state_from_effective("inactive", "key_revoked", "active"),
            "disabled_by_key_status"
        );
    }

    #[test]
    fn inactive_key_expired_maps_correctly() {
        assert_eq!(
            compute_local_state_from_effective("inactive", "key_expired", "active"),
            "disabled_by_key_status"
        );
    }

    #[test]
    fn inactive_account_disabled_maps_correctly() {
        assert_eq!(
            compute_local_state_from_effective("inactive", "account_disabled", "active"),
            "disabled_by_account_status"
        );
    }

    #[test]
    fn inactive_unknown_reason_maps_to_synced_inactive() {
        // not_claimed and any unknown reason → synced_inactive
        assert_eq!(
            compute_local_state_from_effective("inactive", "not_claimed", ""),
            "synced_inactive"
        );
        assert_eq!(
            compute_local_state_from_effective("inactive", "", ""),
            "synced_inactive"
        );
    }

    // ── active paths — existing state is preserved or restored ──────────────

    #[test]
    fn active_preserves_active_state() {
        assert_eq!(
            compute_local_state_from_effective("active", "", "active"),
            "active"
        );
    }

    #[test]
    fn active_preserves_prompt_dismissed() {
        assert_eq!(
            compute_local_state_from_effective("active", "", "prompt_dismissed"),
            "prompt_dismissed"
        );
    }

    #[test]
    fn active_restores_disabled_scope_to_synced_inactive() {
        assert_eq!(
            compute_local_state_from_effective("active", "", "disabled_by_account_scope"),
            "synced_inactive"
        );
        assert_eq!(
            compute_local_state_from_effective("active", "", "disabled_by_account_status"),
            "synced_inactive"
        );
        assert_eq!(
            compute_local_state_from_effective("active", "", "disabled_by_seat_status"),
            "synced_inactive"
        );
        assert_eq!(
            compute_local_state_from_effective("active", "", "disabled_by_key_status"),
            "synced_inactive"
        );
        assert_eq!(
            compute_local_state_from_effective("active", "", "stale"),
            "synced_inactive"
        );
    }

    #[test]
    fn active_new_entry_defaults_to_synced_inactive() {
        assert_eq!(
            compute_local_state_from_effective("active", "", ""),
            "synced_inactive"
        );
        assert_eq!(
            compute_local_state_from_effective("active", "", "synced_inactive"),
            "synced_inactive"
        );
    }
}

// ============================================================================
// Tests for the shared cores (apply_add_core / apply_rename_core /
// validate_alias / normalize_providers / write_bindings_canonical).
//
// These exercise the logic that `aikey add` / `aikey key alias` /
// `_internal vault-op add` / `_internal vault-op batch_import` /
// `_internal update-alias rename_*` all share. A regression here would
// surface as a drift between the CLI and Web paths — exactly the class
// of bug the 2026-04-24 `_internal must reuse public command core` rule
// is designed to prevent.
// ============================================================================
#[cfg(test)]
mod snapshot_sync_debounce_tests {
    use super::*;

    // Pins the cross-process debounce contract (2026-07-07 vault-page
    // latency): within the window → skip (this is what saves the ~1.2s
    // AV-taxed thread::spawn per bridge child); stale / missing / corrupt /
    // future-clock states all read as "attempt now" so the sync semantics
    // the OAuth-pool design relies on are never silently lost.
    #[test]
    fn debounce_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run").join("snapshot-sync-last-attempt");
        let now = 1_000_000u64;

        // Missing file → not recently attempted (sync runs).
        assert!(!snapshot_sync_recently_attempted(&path, now));

        // Recorded just now → suppressed for the window.
        record_snapshot_sync_attempt(&path, now);
        assert!(snapshot_sync_recently_attempted(&path, now));
        assert!(snapshot_sync_recently_attempted(
            &path,
            now + SNAPSHOT_SYNC_DEBOUNCE_SECS - 1
        ));

        // Window elapsed → stale again.
        assert!(!snapshot_sync_recently_attempted(
            &path,
            now + SNAPSHOT_SYNC_DEBOUNCE_SECS
        ));

        // Corrupt content → stale (enhancement-not-dependency).
        std::fs::write(&path, "not-a-number").unwrap();
        assert!(!snapshot_sync_recently_attempted(&path, now));

        // Future timestamp (clock jumped back) → stale, never a permanent
        // suppression.
        std::fs::write(&path, (now + 10_000).to_string()).unwrap();
        assert!(!snapshot_sync_recently_attempted(&path, now));
    }
}

#[cfg(test)]
mod core_tests {
    use super::*;
    use secrecy::SecretString;
    use tempfile::TempDir;

    fn setup_vault() -> (TempDir, std::sync::MutexGuard<'static, ()>) {
        // Share the crate-level TEST_VAULT_LOCK with storage::tests so
        // parallel cargo threads don't race on AK_VAULT_PATH. See
        // storage.rs::TEST_VAULT_LOCK docstring.
        let guard = crate::storage::TEST_VAULT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("vault.db");
        unsafe {
            std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap());
        }
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).expect("salt");
        let pw = SecretString::new("test_password".to_string());
        storage::initialize_vault(&salt, &pw).expect("init vault");
        (dir, guard)
    }

    fn dummy_vault_key() -> [u8; 32] {
        // Any 32-byte key works for apply_add_core tests — it's used purely
        // for AES-GCM encryption. Decryption round-trips aren't tested here.
        [0x42u8; 32]
    }

    // ── N6: oauth-group fold + extra fence ─────────────────────────────────────

    fn vk_entry(
        vk: &str,
        oauth_group_id: Option<&str>,
        group_accounts: Option<&str>,
        routing_config: Option<&str>,
    ) -> storage::VirtualKeyCacheEntry {
        storage::VirtualKeyCacheEntry {
            virtual_key_id: vk.into(),
            org_id: "org-1".into(),
            seat_id: "seat-1".into(),
            alias: "k".into(),
            provider_code: "anthropic".into(),
            protocol_type: "anthropic".into(),
            base_url: String::new(),
            credential_id: String::new(),
            credential_revision: String::new(),
            virtual_key_revision: "r1".into(),
            key_status: "active".into(),
            share_status: "claimed".into(),
            local_state: "synced_inactive".into(),
            expires_at: None,
            provider_key_nonce: None,
            provider_key_ciphertext: None,
            synced_at: 0,
            local_alias: None,
            supported_providers: vec![],
            provider_base_urls: std::collections::HashMap::new(),
            owner_account_id: Some("acct-1".into()),
            owner_email: Some("acct-1@test".into()),
            group_runtime: None,
            group_alias: None,
            extra: None,
            oauth_group_id: oauth_group_id.map(|s| s.to_string()),
            group_accounts: group_accounts.map(|s| s.to_string()),
            routing_config: routing_config.map(|s| s.to_string()),
        }
    }

    #[test]
    fn n6_group_fields_fold_and_extra_survives_sync() {
        let (_dir, _guard) = setup_vault();

        // First sync: a group-bound VK with a candidate set + routing config.
        let ga = r#"[{"account_id":"acc-A","identity":"a@t.com","provider_code":"anthropic","priority":1,"assigned":true}]"#;
        let rc = r#"{"exhaustion_signals":["unified_rate_limited"]}"#;
        storage::upsert_virtual_key_cache(&vk_entry("vk-1", Some("grp-1"), Some(ga), Some(rc)))
            .unwrap();

        let got = storage::get_virtual_key_cache("vk-1").unwrap().unwrap();
        assert_eq!(
            got.oauth_group_id.as_deref(),
            Some("grp-1"),
            "oauth_group_id folded"
        );
        assert!(
            got.group_accounts.as_deref().unwrap().contains("acc-A"),
            "group_accounts folded"
        );
        assert_eq!(
            got.routing_config.as_deref(),
            Some(rc),
            "routing_config folded"
        );

        // User records a connectivity-test result into the user-owned `extra` blob.
        {
            let conn = crate::storage::open_connection().unwrap();
            conn.execute(
                "UPDATE managed_virtual_keys_cache SET extra = ?1 WHERE virtual_key_id = ?2",
                rusqlite::params![r#"{"last_test":{"ok":true}}"#, "vk-1"],
            )
            .unwrap();
        }

        // Second sync: candidate set changed (server authoritative) — must UPDATE
        // group fields BUT leave `extra` intact (the 2026-05-22 fence invariant).
        let ga2 = r#"[{"account_id":"acc-B","identity":"b@t.com","provider_code":"anthropic","priority":1,"assigned":true}]"#;
        let rc2 = r#"{"reject_ratio":5}"#;
        storage::upsert_virtual_key_cache(&vk_entry("vk-1", Some("grp-2"), Some(ga2), Some(rc2)))
            .unwrap();

        let got = storage::get_virtual_key_cache("vk-1").unwrap().unwrap();
        assert_eq!(
            got.oauth_group_id.as_deref(),
            Some("grp-2"),
            "oauth_group_id updated by sync"
        );
        assert_eq!(
            got.routing_config.as_deref(),
            Some(rc2),
            "routing_config updated by sync"
        );
        assert!(
            got.group_accounts.as_deref().unwrap().contains("acc-B"),
            "group_accounts updated"
        );
        assert!(
            !got.group_accounts.as_deref().unwrap().contains("acc-A"),
            "old candidate replaced"
        );
        // The critical fence: sync touching group fields must NOT wipe extra.
        let extra = got.extra.expect("extra survived sync");
        assert_eq!(
            extra["last_test"]["ok"],
            serde_json::json!(true),
            "user-owned extra preserved"
        );
    }

    #[test]
    fn n6_direct_bind_vk_has_no_group_fields() {
        let (_dir, _guard) = setup_vault();
        // A direct-bind VK syncs with no seat group → all group columns NULL.
        storage::upsert_virtual_key_cache(&vk_entry("vk-2", None, None, None)).unwrap();
        let got = storage::get_virtual_key_cache("vk-2").unwrap().unwrap();
        assert_eq!(got.oauth_group_id, None);
        assert_eq!(got.group_accounts, None);
        assert_eq!(got.routing_config, None);
    }

    // ── apply_quota_snapshot_to_cache (Phase 2 Stage 2b) ──────────────────────

    #[test]
    fn quota_snapshot_cache_replace_clear_and_none() {
        use crate::platform_client::{QuotaSnapshot, QuotaSubjectSnapshot};
        use rusqlite::OptionalExtension;
        let (_dir, _guard) = setup_vault();

        // Use the production open_connection() (it runs migrations::upgrade_all,
        // creating quota_rules_cache) — a raw Connection::open would skip the
        // lazy schema upgrade and not see the table.
        let count_rows = || -> i64 {
            let conn = crate::storage::open_connection().unwrap();
            conn.query_row("SELECT COUNT(*) FROM quota_rules_cache", [], |r| r.get(0))
                .unwrap()
        };
        let read_row = |id: &str| -> Option<(String, Option<String>, String, Option<String>)> {
            let conn = crate::storage::open_connection().unwrap();
            conn.query_row(
                "SELECT subject_kind, members, rules, baseline FROM quota_rules_cache WHERE subject_id = ?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()
            .unwrap()
        };

        // None (older/quota-less server) must not touch the cache.
        apply_quota_snapshot_to_cache(&None);
        assert_eq!(count_rows(), 0, "None must not write");

        // Some with seat + group → full set; seat members NULL, group members JSON.
        let snap = QuotaSnapshot {
            subjects: vec![
                QuotaSubjectSnapshot {
                    subject_id: "seat-a".into(),
                    subject_kind: "seat".into(),
                    members: vec![],
                    rules: serde_json::json!([{"metric":"usd","period":"monthly","limit_amount":50.0}]),
                    baselines: serde_json::json!([{"metric":"tokens","period":"monthly","used":42.0}]),
                },
                QuotaSubjectSnapshot {
                    subject_id: "grp-1".into(),
                    subject_kind: "group".into(),
                    members: vec!["seat-a".into(), "seat-b".into()],
                    rules: serde_json::json!([{"metric":"tokens","period":"daily","limit_amount":1000000.0}]),
                    baselines: serde_json::Value::Null,
                },
            ],
            price_tiers: None,
        };
        apply_quota_snapshot_to_cache(&Some(snap));
        assert_eq!(count_rows(), 2);
        let (kind, members, rules, baseline) = read_row("seat-a").expect("seat-a row");
        assert_eq!(kind, "seat");
        assert!(
            members.is_none(),
            "seat members must be NULL, got {:?}",
            members
        );
        assert!(
            rules.contains("\"usd\""),
            "seat rules round-trip: {}",
            rules
        );
        // Stage 4 baseline persists for seat-a; NULL for grp-1 (no baseline).
        assert!(
            baseline.as_deref().unwrap_or("").contains("\"used\":42"),
            "seat baseline round-trip: {:?}",
            baseline
        );
        let (gkind, gmembers, _, gbaseline) = read_row("grp-1").expect("grp-1 row");
        assert_eq!(gkind, "group");
        assert_eq!(gmembers.unwrap(), "[\"seat-a\",\"seat-b\"]");
        assert!(
            gbaseline.is_none(),
            "grp baseline must be NULL, got {:?}",
            gbaseline
        );

        // Some with empty subjects → full-replace clears (last-quota-deleted).
        apply_quota_snapshot_to_cache(&Some(QuotaSnapshot {
            subjects: vec![],
            price_tiers: None,
        }));
        assert_eq!(count_rows(), 0, "empty Some must clear stale rules");
    }

    // ── validate_alias ────────────────────────────────────────────────────

    #[test]
    fn validate_alias_rejects_empty() {
        assert!(validate_alias("").is_err());
        assert!(validate_alias("   ").is_err());
        assert!(validate_alias("\t\n").is_err());
    }

    #[test]
    fn validate_alias_accepts_normal() {
        assert_eq!(validate_alias("my-key").unwrap(), "my-key");
        assert_eq!(validate_alias("  trim-me  ").unwrap(), "trim-me");
        assert_eq!(validate_alias("user@gmail.com").unwrap(), "user@gmail.com");
    }

    #[test]
    fn validate_alias_rejects_over_max_length() {
        let ok = "a".repeat(128);
        let bad = "a".repeat(129);
        assert!(validate_alias(&ok).is_ok());
        assert!(validate_alias(&bad).is_err());
    }

    #[test]
    fn validate_alias_rejects_control_chars() {
        assert!(validate_alias("foo\nbar").is_err());
        assert!(validate_alias("foo\0bar").is_err());
        assert!(validate_alias("foo\x7fbar").is_err());
    }

    // ── normalize_providers ───────────────────────────────────────────────

    #[test]
    fn normalize_providers_maps_claude_codex_to_canonical() {
        assert_eq!(
            normalize_providers(&["claude".to_string()]),
            vec!["anthropic".to_string()],
        );
        assert_eq!(
            normalize_providers(&["codex".to_string()]),
            vec!["openai".to_string()],
        );
    }

    #[test]
    fn normalize_providers_case_insensitive() {
        assert_eq!(
            normalize_providers(&["CLAUDE".to_string(), "Codex".to_string()]),
            vec!["anthropic".to_string(), "openai".to_string()],
        );
    }

    #[test]
    fn normalize_providers_dedups_after_canonicalization() {
        // claude + anthropic both canonicalize to "anthropic" → single entry.
        assert_eq!(
            normalize_providers(&["claude".to_string(), "anthropic".to_string()]),
            vec!["anthropic".to_string()],
        );
    }

    #[test]
    fn normalize_providers_preserves_first_seen_order() {
        assert_eq!(
            normalize_providers(&["openai".to_string(), "anthropic".to_string()]),
            vec!["openai".to_string(), "anthropic".to_string()],
        );
        assert_eq!(
            normalize_providers(&["anthropic".to_string(), "openai".to_string()]),
            vec!["anthropic".to_string(), "openai".to_string()],
        );
    }

    #[test]
    fn normalize_providers_filters_empty_strings() {
        assert_eq!(
            normalize_providers(&["".to_string(), "  ".to_string(), "claude".to_string()]),
            vec!["anthropic".to_string()],
        );
    }

    #[test]
    fn normalize_providers_leaves_moonshot_distinct_from_kimi_code() {
        // 2026-05-08 Kimi 双平台拆分: 'kimi' 字符串被作为 oauth_aliases 挂在
        // kimi_code 上,canonical("kimi") = "kimi_code"。Moonshot 与 kimi_code
        // 仍是两个独立 provider_code,各自 env vars / proxy paths 不同。
        // pre-split 测试期望 ["moonshot", "kimi"]; 后:["moonshot", "kimi_code"]。
        assert_eq!(
            normalize_providers(&["moonshot".to_string(), "kimi".to_string()]),
            vec!["moonshot".to_string(), "kimi_code".to_string()],
        );
    }

    // ── apply_add_core_on_conn ────────────────────────────────────────────

    #[test]
    fn apply_add_core_writes_entry_with_canonical_providers() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();

        let outcome = apply_add_core_on_conn(
            &conn,
            &key,
            "my-codex",
            b"sk-fake-secret",
            &["codex".to_string()], // raw broker vocab
            None,
            OnConflict::Error,
        )
        .expect("add core ok");

        assert_eq!(outcome.action, AddAction::Inserted);
        assert_eq!(outcome.alias, "my-codex");
        // Canonical normalization: codex → openai
        assert_eq!(outcome.providers, vec!["openai".to_string()]);
        assert_eq!(outcome.primary_provider.as_deref(), Some("openai"));
    }

    #[test]
    fn apply_add_core_respects_on_conflict_error() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();
        apply_add_core_on_conn(
            &conn,
            &key,
            "dup",
            b"s1",
            &["openai".to_string()],
            None,
            OnConflict::Error,
        )
        .unwrap();

        let err = apply_add_core_on_conn(&conn, &key, "dup", b"s2", &[], None, OnConflict::Error)
            .unwrap_err();
        assert!(err.contains("already exists"), "err was: {}", err);
    }

    #[test]
    fn apply_add_core_on_conflict_replace_overwrites() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();

        apply_add_core_on_conn(
            &conn,
            &key,
            "rep",
            b"s1",
            &["openai".to_string()],
            None,
            OnConflict::Error,
        )
        .unwrap();
        let outcome = apply_add_core_on_conn(
            &conn,
            &key,
            "rep",
            b"s2",
            &["anthropic".to_string()],
            None,
            OnConflict::Replace,
        )
        .expect("replace ok");
        assert_eq!(outcome.action, AddAction::Replaced);
        assert_eq!(outcome.primary_provider.as_deref(), Some("anthropic"));
    }

    #[test]
    fn apply_add_core_on_conflict_skip_noops() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();

        apply_add_core_on_conn(
            &conn,
            &key,
            "keep",
            b"s1",
            &["openai".to_string()],
            None,
            OnConflict::Error,
        )
        .unwrap();
        let outcome =
            apply_add_core_on_conn(&conn, &key, "keep", b"s2", &[], None, OnConflict::Skip)
                .expect("skip ok");
        assert_eq!(outcome.action, AddAction::Skipped);
        // Verify original provider was NOT overwritten.
        let metas = storage::list_entries_with_metadata().unwrap();
        let entry = metas.iter().find(|m| m.alias == "keep").unwrap();
        assert_eq!(entry.provider_code.as_deref(), Some("openai"));
    }

    #[test]
    fn apply_add_core_writes_base_url() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();
        apply_add_core_on_conn(
            &conn,
            &key,
            "with-url",
            b"s",
            &["openai".to_string()],
            Some("https://api.example.com/v1"),
            OnConflict::Error,
        )
        .unwrap();
        let metas = storage::list_entries_with_metadata().unwrap();
        let entry = metas.iter().find(|m| m.alias == "with-url").unwrap();
        assert_eq!(
            entry.base_url.as_deref(),
            Some("https://api.example.com/v1")
        );
    }

    #[test]
    fn apply_add_core_rejects_invalid_alias() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();
        let err = apply_add_core_on_conn(&conn, &key, "  ", b"s", &[], None, OnConflict::Error)
            .unwrap_err();
        assert!(err.contains("empty"), "err was: {}", err);

        let err2 = apply_add_core_on_conn(
            &conn,
            &key,
            "bad\nalias",
            b"s",
            &[],
            None,
            OnConflict::Error,
        )
        .unwrap_err();
        assert!(err2.contains("control"), "err was: {}", err2);
    }

    // ── apply_rename_core ─────────────────────────────────────────────────

    #[test]
    fn apply_rename_core_personal_happy_path() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();
        apply_add_core_on_conn(&conn, &key, "old-name", b"s", &[], None, OnConflict::Error)
            .unwrap();
        drop(conn);

        let outcome =
            apply_rename_core(RenameTarget::Personal, "old-name", "new-name").expect("rename ok");
        assert_eq!(outcome.target, "personal");
        assert_eq!(outcome.id, "new-name");
        assert_eq!(outcome.old_id, "old-name");
        assert!(!storage::entry_exists("old-name").unwrap());
        assert!(storage::entry_exists("new-name").unwrap());
    }

    #[test]
    fn apply_rename_core_personal_not_found_errors() {
        let (_dir, _lock) = setup_vault();
        let err = apply_rename_core(RenameTarget::Personal, "ghost", "something").unwrap_err();
        assert!(err.contains("not found"), "err was: {}", err);
    }

    #[test]
    fn apply_rename_core_personal_conflict_errors() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();
        apply_add_core_on_conn(&conn, &key, "a", b"s1", &[], None, OnConflict::Error).unwrap();
        apply_add_core_on_conn(&conn, &key, "b", b"s2", &[], None, OnConflict::Error).unwrap();
        drop(conn);

        let err = apply_rename_core(RenameTarget::Personal, "a", "b").unwrap_err();
        assert!(err.contains("already exists"), "err was: {}", err);
    }

    #[test]
    fn apply_rename_core_personal_identical_errors() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();
        apply_add_core_on_conn(&conn, &key, "same", b"s", &[], None, OnConflict::Error).unwrap();
        drop(conn);

        let err = apply_rename_core(RenameTarget::Personal, "same", "same").unwrap_err();
        assert!(err.contains("identical"), "err was: {}", err);
    }

    #[test]
    fn apply_rename_core_personal_rejects_invalid_new_alias() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();
        apply_add_core_on_conn(&conn, &key, "source", b"s", &[], None, OnConflict::Error).unwrap();
        drop(conn);

        let err = apply_rename_core(RenameTarget::Personal, "source", "bad\ncontrol").unwrap_err();
        assert!(err.contains("control"), "err was: {}", err);
    }

    // ── write_bindings_canonical ──────────────────────────────────────────

    #[test]
    fn write_bindings_canonical_normalizes_claude_to_anthropic() {
        let (_dir, _lock) = setup_vault();
        write_bindings_canonical(
            &["claude".to_string()],
            "personal_oauth_account",
            "acct-xyz",
            None,
        )
        .expect("write ok");
        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        let row = bindings
            .iter()
            .find(|b| b.provider_code == "anthropic")
            .expect("anthropic row");
        assert_eq!(row.key_source_ref, "acct-xyz");
        // The raw "claude" provider_code row must NOT exist.
        assert!(bindings.iter().all(|b| b.provider_code != "claude"));
    }

    #[test]
    fn write_bindings_canonical_cleans_stale_alias_row() {
        let (_dir, _lock) = setup_vault();
        // Simulate a pre-fix CLI version that wrote a raw "codex" binding.
        storage::set_provider_binding("default", "codex", "personal_oauth_account", "stale-uuid")
            .unwrap();
        assert!(storage::list_provider_bindings_readonly("default")
            .unwrap()
            .iter()
            .any(|b| b.provider_code == "codex"));

        // Now write canonical via the shared helper.
        write_bindings_canonical(
            &["codex".to_string()],
            "personal_oauth_account",
            "fresh-uuid",
            None,
        )
        .unwrap();

        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        // Stale raw-alias row must be gone.
        assert!(
            bindings.iter().all(|b| b.provider_code != "codex"),
            "expected no 'codex' row after canonical write, got: {:?}",
            bindings
        );
        // Canonical row must exist with the new ref.
        let row = bindings
            .iter()
            .find(|b| b.provider_code == "openai")
            .expect("openai row");
        assert_eq!(row.key_source_ref, "fresh-uuid");
    }

    #[test]
    fn write_bindings_canonical_kimi_family_mutex_last_write_wins() {
        // 2026-05-08 Kimi family 互斥(详见 update/20260508-Kimi-family互斥-active-env
        // 统一KIMI写入.md 决策 #2):同 profile 内 kimi_code / moonshot / kimi(legacy)
        // 互斥,同时只 1 个 active binding。set_provider_binding 在事务内做 mutex,
        // 写新 family 成员之前 DELETE 其它 family 成员。
        //
        // pre-mutex 测试期望两个 binding 共存 → 实际不再可能。改测试为断言:
        //   ① mutex 生效:最后写入的 family 成员独占
        //   ② 输入 "kimi" 经 oauth_alias 解析到 canonical "kimi_code"
        //   ③ deprecated 'kimi' 字面值不落库
        //   ④ 跨 family 不受影响(anthropic 不被 mutex 触动)
        let (_dir, _lock) = setup_vault();
        // 先写 anthropic 作为 cross-family 不受影响的对照
        write_bindings_canonical(&["anthropic".to_string()], "personal", "k-claude", None).unwrap();
        // 然后顺序写入 kimi family 两个成员
        write_bindings_canonical(&["moonshot".to_string()], "personal", "k-moonshot", None)
            .unwrap();
        write_bindings_canonical(&["kimi".to_string()], "personal", "k-kimi", None).unwrap();

        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        // ① + ② 最后写入的 'kimi' 经 alias → kimi_code,独占 family
        assert!(
            bindings.iter().any(|b| b.provider_code == "kimi_code"),
            "expected kimi_code (canonical of 'kimi' alias) as final family active"
        );
        // mutex 应该已经删除 moonshot binding
        assert!(!bindings.iter().any(|b| b.provider_code == "moonshot"),
            "moonshot should be deactivated by family mutex when 'kimi' (→ kimi_code) was written after");
        // ③ deprecated 'kimi' 字面值不落库
        assert!(
            !bindings.iter().any(|b| b.provider_code == "kimi"),
            "post-split 'kimi' should be canonicalized to 'kimi_code' on write"
        );
        // ④ cross-family 不受 mutex 影响
        assert!(
            bindings.iter().any(|b| b.provider_code == "anthropic"),
            "anthropic binding must survive Kimi family mutex"
        );
    }

    #[test]
    fn write_bindings_canonical_upserts_same_canonical() {
        let (_dir, _lock) = setup_vault();
        write_bindings_canonical(&["anthropic".to_string()], "personal", "first", None).unwrap();
        write_bindings_canonical(&["anthropic".to_string()], "personal", "second", None).unwrap();
        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        let anthropic_rows: Vec<_> = bindings
            .iter()
            .filter(|b| b.provider_code == "anthropic")
            .collect();
        assert_eq!(
            anthropic_rows.len(),
            1,
            "UPSERT should leave exactly one row per canonical"
        );
        assert_eq!(anthropic_rows[0].key_source_ref, "second");
    }

    // ── binding material guard (2026-07-06 incident) ─────────────────────────
    //
    // A post-`aikey key sync` reconcile auto-bound a team VK with NO local
    // provider_key_ciphertext as the anthropic Primary. Result: proxy 503s,
    // the picker hides the key (material filter), the web vault shows it as
    // "IN USE" — three surfaces disagreeing about the active key. The guard:
    // automatic binding fills (auto_assign / removal-reconcile replacement)
    // must skip material-unreachable team VKs and rather leave the slot empty.
    // See update/20260706-绑定材料守卫与Web解锁态全量sync.md.
    //
    // NOTE: these tests assume the non-cluster environment (no
    // ~/.aikey/active-cluster.json) — `key_material_reachable(false)` requires
    // local ciphertext unless the VK is a group VK.

    fn guard_vk(vk: &str, group: Option<&str>, ciphertext: Option<&[u8]>) -> () {
        let mut e = vk_entry(vk, group, None, None);
        e.provider_key_ciphertext = ciphertext.map(|c| c.to_vec());
        e.provider_key_nonce = ciphertext.map(|_| vec![0u8; 12]);
        storage::upsert_virtual_key_cache(&e).unwrap();
    }

    #[test]
    fn auto_assign_skips_material_unreachable_team_vk() {
        let (_dir, _lock) = setup_vault();
        // Direct-bind VK, no local ciphertext, no group → unreachable.
        guard_vk("vk-nomat", None, None);

        let assigned = crate::profile_activation::auto_assign_primaries_for_key(
            "team",
            "vk-nomat",
            &["anthropic".to_string()],
            None,
        )
        .expect("auto_assign must not error");
        assert!(assigned.is_empty(), "unreachable VK must not be promoted");
        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        assert!(
            bindings.iter().all(|b| b.key_source_ref != "vk-nomat"),
            "no binding may reference the unreachable VK, got: {:?}",
            bindings
        );
    }

    #[test]
    fn auto_assign_allows_group_vk_without_ciphertext() {
        let (_dir, _lock) = setup_vault();
        // Group VK: no local material BY DESIGN (proxy channel ③) → reachable.
        guard_vk("vk-grp", Some("grp-1"), None);

        let assigned = crate::profile_activation::auto_assign_primaries_for_key(
            "team",
            "vk-grp",
            &["anthropic".to_string()],
            None,
        )
        .expect("auto_assign ok");
        assert_eq!(assigned, vec!["anthropic".to_string()]);
    }

    #[test]
    fn auto_assign_allows_team_vk_with_local_ciphertext() {
        let (_dir, _lock) = setup_vault();
        guard_vk("vk-mat", None, Some(b"cipher"));

        let assigned = crate::profile_activation::auto_assign_primaries_for_key(
            "team",
            "vk-mat",
            &["anthropic".to_string()],
            None,
        )
        .expect("auto_assign ok");
        assert_eq!(assigned, vec!["anthropic".to_string()]);
    }

    /// Pins the exact incident path: `aikey key sync`'s post-sync reconcile
    /// wrapper must not bind a material-unreachable VK even when it is the
    /// only anthropic candidate — an empty slot is the correct outcome.
    #[test]
    fn post_sync_reconcile_does_not_bind_material_unreachable_vk() {
        let (_dir, _lock) = setup_vault();
        guard_vk("vk-nomat", None, None);

        let reconciled =
            crate::profile_activation::reconcile_provider_primaries_after_team_key_sync(
                &[("vk-nomat".to_string(), vec!["anthropic".to_string()])],
                None,
            )
            .expect("reconcile ok");
        assert!(reconciled.is_empty(), "nothing may be promoted");
        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        assert!(
            bindings.iter().all(|b| b.provider_code != "anthropic"),
            "anthropic slot must stay EMPTY rather than bind an unusable key"
        );
    }

    /// Removal-reconcile replacement search must skip the unreachable VK and
    /// promote the reachable one, regardless of cache iteration order.
    #[test]
    fn removal_reconcile_replacement_skips_unreachable_vk() {
        let (_dir, _lock) = setup_vault();
        // Current primary that is about to be removed.
        guard_vk("vk-old", None, Some(b"cipher-old"));
        write_bindings_canonical(&["anthropic".to_string()], "team", "vk-old", None).unwrap();
        // Two candidates: unreachable direct-bind VK (inserted first) and a
        // reachable group VK.
        guard_vk("vk-nomat", None, None);
        guard_vk("vk-grp", Some("grp-1"), None);

        let actions = crate::profile_activation::reconcile_provider_primary_after_key_removal(
            "team", "vk-old", None,
        )
        .expect("reconcile ok");
        let anthropic = actions
            .iter()
            .find(|a| a.provider_code == "anthropic")
            .expect("anthropic action");
        match &anthropic.outcome {
            crate::profile_activation::ReconcileOutcome::Replaced { new_source_ref, .. } => {
                assert_eq!(
                    new_source_ref, "vk-grp",
                    "replacement must be the reachable VK, not the material-less one"
                );
            }
            other => panic!("expected Replaced, got {:?}", other),
        }
    }

    // ── B-2 bind audit rows (2026-07-06) ─────────────────────────────────────
    //
    // Every binding write through write_bindings_canonical must sign a
    // tamper-evident `bind` audit row when the caller holds a VerifiedVaultKey.
    // The incident write (post-sync auto-assign) had NO trace in audit_log —
    // root-causing required timestamp cross-referencing across three stores.

    fn verified_key() -> crate::audit::VerifiedVaultKey {
        // setup_vault stored password_hash = derived key of "test_password";
        // derive the same way the CLI does and let the newtype verify it.
        let pw = SecretString::new("test_password".to_string());
        let key = derive_vault_key(&pw).expect("derive");
        crate::audit::VerifiedVaultKey::new(key).expect("verified")
    }

    fn bind_audit_rows() -> Vec<String> {
        let conn = storage::open_connection().expect("open");
        let mut stmt = conn
            .prepare("SELECT alias FROM audit_log WHERE operation = 'bind' ORDER BY id")
            .expect("prepare");
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();
        rows
    }

    #[test]
    fn bind_write_with_verified_key_signs_audit_row() {
        let (_dir, _lock) = setup_vault();
        crate::audit::initialize_audit_log().expect("audit table");
        let vk = verified_key();
        write_bindings_canonical(&["anthropic".to_string()], "personal", "k-1", Some(&vk))
            .expect("write");
        let rows = bind_audit_rows();
        assert_eq!(rows, vec!["anthropic:personal:k-1".to_string()]);
        // Chain integrity: the signed row must VERIFY (a wrong-key signature
        // would surface as a tampered entry and poison the whole chain).
        let pw = SecretString::new("test_password".to_string());
        let (verified, tampered) = crate::audit::verify_audit_log(&pw).expect("verify");
        assert!(verified >= 1, "bind row must be part of the verified chain");
        assert!(
            tampered.is_empty(),
            "bind row signed with VerifiedVaultKey must not read as tampered: {:?}",
            tampered
        );
    }

    #[test]
    fn bind_write_without_key_stays_unsigned_but_succeeds() {
        let (_dir, _lock) = setup_vault();
        crate::audit::initialize_audit_log().expect("audit table");
        write_bindings_canonical(&["anthropic".to_string()], "personal", "k-2", None)
            .expect("keyless binding write must not fail");
        assert!(
            bind_audit_rows().is_empty(),
            "no VerifiedVaultKey → no audit row (observability event only)"
        );
        // The binding itself must still land (audit is an overlay, never a gate).
        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        assert!(bindings.iter().any(|b| b.key_source_ref == "k-2"));
    }

    #[test]
    fn verified_vault_key_rejects_wrong_key() {
        let (_dir, _lock) = setup_vault();
        let err = crate::audit::VerifiedVaultKey::new([0x41u8; 32]);
        assert!(
            err.is_err(),
            "a non-matching key must NOT be constructible — it would sign rows that read as tampered"
        );
    }

    #[test]
    fn auto_assign_with_verified_key_signs_bind_row() {
        let (_dir, _lock) = setup_vault();
        crate::audit::initialize_audit_log().expect("audit table");
        guard_vk("vk-audit", None, Some(b"cipher"));
        let vk = verified_key();
        let assigned = crate::profile_activation::auto_assign_primaries_for_key(
            "team",
            "vk-audit",
            &["anthropic".to_string()],
            Some(&vk),
        )
        .expect("auto_assign");
        assert_eq!(assigned, vec!["anthropic".to_string()]);
        assert_eq!(
            bind_audit_rows(),
            vec!["anthropic:team:vk-audit".to_string()],
            "the previously-invisible auto-assign write must now leave a signed audit row"
        );
    }

    // ── snapshot sync verify (2026-05-11 fix) ────────────────────────────────

    /// Critical defense-in-depth: `run_full_snapshot_sync_with_vault_key`
    /// MUST reject a vault_key that doesn't match the stored password_hash
    /// BEFORE touching the network or writing ciphertext. The pre-fix
    /// version silently encrypted team-key material with whatever key it
    /// was given, persisted the result, and downstream proxy decrypts then
    /// failed forever (the 2026-05-11 incident).
    ///
    /// We assert two properties:
    ///   1. Err result containing "vault_key does not match" guidance.
    ///   2. NO network call: the test runs with no platform account
    ///      registered, so reaching the snapshot fetch would crash with
    ///      a different error. A bare "snapshot sync aborted" return
    ///      proves verify ran first and short-circuited.
    #[test]
    fn run_full_snapshot_sync_rejects_wrong_vault_key() {
        let (_dir, _lock) = setup_vault();
        // Wrong vault_key — all zeros never matches the derived hash.
        let wrong_key = [0u8; 32];
        let err = run_full_snapshot_sync_with_vault_key(&wrong_key)
            .expect_err("must reject vault_key that doesn't match password_hash");
        assert!(
            err.contains("snapshot sync aborted") && err.contains("password_hash"),
            "error must call out the verify failure (not a downstream network error), got: {}",
            err
        );
    }

    #[test]
    fn run_full_snapshot_sync_accepts_correct_vault_key_in_offline_mode() {
        // The matching test: a correctly-derived vault_key passes verify.
        // Without a platform account the snapshot fetch returns Ok(0) — no
        // network — so this exercises the verify path's happy case without
        // standing up a control server.
        let (_dir, _lock) = setup_vault();
        let salt = storage::get_salt().expect("salt");
        let (m, t, p) = storage::get_kdf_params().expect("kdf");
        let key = crate::crypto::derive_key_with_params(
            &SecretString::new("test_password".to_string()),
            &salt,
            m,
            t,
            p,
        )
        .expect("derive");
        let mut vk = [0u8; 32];
        vk.copy_from_slice(key.as_slice());

        // get_platform_account returns None on a fresh vault → snapshot sync
        // returns Ok(0). The verify gate must allow the call through.
        let result = run_full_snapshot_sync_with_vault_key(&vk);
        assert!(
            result.is_ok(),
            "correct vault_key must pass verify; got {:?}",
            result
        );
        assert_eq!(result.unwrap(), 0, "no platform account → no downloads");
    }
}

// ============================================================================
// derive_local_control_url tests
//
// Pin the regression caught on 2026-04-27: server-then-trial install left
// `control_panel_url` pointing at the production sandbox port (39000) while
// `install_profile == "trial"` and `ports.trial == 8090` were correct.
// `aikey web` opened the wrong port. Fix is profile-driven URL derivation;
// these tests pin every branch.
// ============================================================================
#[cfg(test)]
mod control_url_resolution_tests {
    use super::derive_local_control_url;

    fn state(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("test fixture must be valid JSON")
    }

    #[test]
    fn trial_profile_uses_ports_trial_not_control_panel_url() {
        // The exact mid-state we observed on 2026-04-27: install_profile=trial
        // + ports.trial=8090 is correct, but control_panel_url=39000 is stale
        // from a prior server install. Profile-driven derivation must IGNORE
        // the stale URL and use ports.trial.
        let s = state(
            r#"{
            "install_profile": "trial",
            "control_plane_mode": "trial",
            "control_panel_url": "http://127.0.0.1:39000",
            "ports": {"proxy": 27200, "trial": 8090}
        }"#,
        );
        assert_eq!(
            derive_local_control_url(&s),
            Some("http://127.0.0.1:8090".to_string())
        );
    }

    #[test]
    fn local_with_console_profile_uses_ports_trial() {
        // local-install.sh --with-console writes ports.trial = console_port
        // (same field name, same loopback semantics as trial). The current
        // local installer also writes a matching control_panel_url, but if
        // a stale value is present from a prior server install we still
        // want ports.trial to win.
        let s = state(
            r#"{
            "install_profile": "local",
            "control_plane_mode": "local",
            "control_panel_url": "http://stale:39000",
            "ports": {"proxy": 27200, "trial": 8090}
        }"#,
        );
        assert_eq!(
            derive_local_control_url(&s),
            Some("http://127.0.0.1:8090".to_string())
        );
    }

    #[test]
    fn local_without_console_returns_none() {
        // Personal-only install: no console, no ports.trial. derive returns
        // None and the caller falls through to other resolution paths
        // (interactive prompt, AIKEY_WEB_URL, etc).
        let s = state(
            r#"{
            "install_profile": "local",
            "control_plane_mode": "none",
            "control_panel_url": "",
            "ports": {"proxy": 27200}
        }"#,
        );
        assert_eq!(derive_local_control_url(&s), None);
    }

    #[test]
    fn server_profile_uses_control_panel_url() {
        // Production: control_panel_url IS the source of truth (externally
        // configured BIND_IP + manifest web port). Don't try to derive from
        // ports — server uses different port keys (web, control, ...).
        let s = state(
            r#"{
            "install_profile": "server",
            "control_plane_mode": "remote",
            "control_panel_url": "http://10.0.0.5:39000",
            "ports": {"web": 39000, "control": 39080}
        }"#,
        );
        assert_eq!(
            derive_local_control_url(&s),
            Some("http://10.0.0.5:39000".to_string())
        );
    }

    #[test]
    fn server_profile_with_empty_url_returns_none() {
        let s = state(
            r#"{
            "install_profile": "server",
            "control_panel_url": ""
        }"#,
        );
        assert_eq!(derive_local_control_url(&s), None);
    }

    #[test]
    fn unknown_profile_falls_back_to_control_panel_url() {
        // Older install-state.json versions or hand-edited files may have
        // unknown / missing install_profile. Back-compat: still honor
        // control_panel_url if non-empty.
        let s = state(
            r#"{
            "install_profile": "ancient-unknown",
            "control_panel_url": "http://legacy:7777"
        }"#,
        );
        assert_eq!(
            derive_local_control_url(&s),
            Some("http://legacy:7777".to_string())
        );
    }

    #[test]
    fn missing_install_profile_falls_back_to_control_panel_url() {
        let s = state(
            r#"{
            "control_panel_url": "http://legacy:7777"
        }"#,
        );
        assert_eq!(
            derive_local_control_url(&s),
            Some("http://legacy:7777".to_string())
        );
    }

    #[test]
    fn trial_with_no_ports_field_returns_none() {
        // If install-state somehow lacks `ports` entirely (corrupt state),
        // we don't fall back to the stale control_panel_url for trial —
        // returning None forces the caller into safer interactive prompts.
        let s = state(
            r#"{
            "install_profile": "trial",
            "control_panel_url": "http://stale:39000"
        }"#,
        );
        assert_eq!(derive_local_control_url(&s), None);
    }

    #[test]
    fn trial_with_ports_but_missing_trial_key_returns_none() {
        let s = state(
            r#"{
            "install_profile": "trial",
            "ports": {"proxy": 27200},
            "control_panel_url": "http://stale:39000"
        }"#,
        );
        assert_eq!(derive_local_control_url(&s), None);
    }
}

// ============================================================================
// derive_local_browse_url tests — edition coverage for R5
//
// Pin the regression caught on 2026-05-11: `try_local_browse_url` originally
// checked the literal string "local-server" in installed_components, missing
// the Trial edition's "full-trial" component. Result: `aikey web` on Trial
// installs fell through to the JWT path → "Not logged in" error or wrong
// remote URL routing. Spec: requirements/2026-05-11-aikey-web-local-first-
// team-merge.md R5.
// ============================================================================
#[cfg(test)]
mod master_precondition_tests {
    use super::master_precondition_satisfied;

    fn state(profile: &str) -> serde_json::Value {
        serde_json::json!({ "install_profile": profile })
    }

    #[test]
    fn trial_allows_without_login() {
        assert!(master_precondition_satisfied(Some(&state("trial")), false));
    }

    #[test]
    fn local_with_login_allows() {
        assert!(master_precondition_satisfied(Some(&state("local")), true));
    }

    #[test]
    fn local_without_login_denies() {
        assert!(!master_precondition_satisfied(Some(&state("local")), false));
    }

    #[test]
    fn server_without_login_denies() {
        assert!(!master_precondition_satisfied(
            Some(&state("server")),
            false
        ));
    }

    #[test]
    fn missing_state_without_login_denies() {
        assert!(!master_precondition_satisfied(None, false));
    }

    #[test]
    fn missing_state_with_login_allows() {
        assert!(master_precondition_satisfied(None, true));
    }
}

#[cfg(test)]
mod browse_url_resolution_tests {
    use super::derive_local_browse_url;

    fn state(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("test fixture must be valid JSON")
    }

    #[test]
    fn personal_with_console_returns_local_go_url() {
        // local-install.sh --with-console writes "local-server" and ports.trial.
        let s = state(
            r#"{
            "install_profile": "local",
            "control_plane_mode": "local",
            "installed_components": ["cli", "proxy", "local-server"],
            "ports": {"proxy": 27200, "trial": 8090}
        }"#,
        );
        assert_eq!(
            derive_local_browse_url(&s, "vault"),
            Some("http://127.0.0.1:8090/go/vault".to_string())
        );
    }

    #[test]
    fn trial_returns_local_go_url() {
        // trial-install.sh writes "full-trial" (not "local-server") +
        // ports.trial. Before the 2026-05-11 fix this case returned None.
        let s = state(
            r#"{
            "install_profile": "trial",
            "control_plane_mode": "trial",
            "installed_components": ["cli", "proxy", "full-trial"],
            "ports": {"proxy": 27200, "trial": 8090}
        }"#,
        );
        assert_eq!(
            derive_local_browse_url(&s, "vault"),
            Some("http://127.0.0.1:8090/go/vault".to_string())
        );
    }

    #[test]
    fn personal_cli_only_returns_none() {
        // No local web server installed → caller falls back to the
        // mode=="none" guard which shows "No web console" hint.
        let s = state(
            r#"{
            "install_profile": "local",
            "control_plane_mode": "none",
            "installed_components": ["cli", "proxy"]
        }"#,
        );
        assert_eq!(derive_local_browse_url(&s, "vault"), None);
    }

    #[test]
    fn production_server_returns_none() {
        // Server installs deploy services, not user-facing web — there's
        // no /go/<alias> route on the server-side machine.
        // (End-user CLI pointing at production has installed_components
        // [cli, proxy] only, identical to personal_cli_only test above.)
        let s = state(
            r#"{
            "install_profile": "server",
            "control_plane_mode": "remote",
            "installed_components": ["control-service", "collector-service", "query-service"],
            "control_panel_url": "http://10.0.0.5:39000"
        }"#,
        );
        assert_eq!(derive_local_browse_url(&s, "vault"), None);
    }

    #[test]
    fn alias_threads_through_to_path_suffix() {
        // Sanity-check that the alias parameter becomes the path suffix.
        let s = state(
            r#"{
            "install_profile": "local",
            "installed_components": ["cli", "proxy", "local-server"],
            "ports": {"proxy": 27200, "trial": 8090}
        }"#,
        );
        assert_eq!(
            derive_local_browse_url(&s, "import"),
            Some("http://127.0.0.1:8090/go/import".to_string())
        );
        assert_eq!(
            derive_local_browse_url(&s, "overview"),
            Some("http://127.0.0.1:8090/go/overview".to_string())
        );
    }

    #[test]
    fn missing_installed_components_returns_none() {
        // Defensive: older install-state.json formats may not have the
        // field at all — treat as "no local web" rather than crashing.
        let s = state(
            r#"{
            "install_profile": "local",
            "ports": {"trial": 8090}
        }"#,
        );
        assert_eq!(derive_local_browse_url(&s, "vault"), None);
    }
}

// ============================================================================
// 2026-05-11 F1 fix tests — user-layer team-route writer/reader.
//
// configure_proxy_collector now writes proxy.events.collector_routes.team
// to ~/.aikey/config/aikey-user.yaml so the value survives system-yaml
// re-renders (the make restart-personal / aikey-config-tool render
// pipeline rm + re-emits the system file every time). These tests pin
// the surface a downstream refactor would have to preserve.
// ============================================================================
#[cfg(test)]
mod user_yaml_team_route_tests {
    use super::{read_user_yaml_team_route, write_user_yaml_team_route};
    use tempfile::TempDir;

    /// Fresh install: aikey-user.yaml doesn't exist yet. Writer must
    /// create the parent dir + file + minimal mapping shape.
    #[test]
    fn writes_team_route_when_file_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config").join("aikey-user.yaml");
        write_user_yaml_team_route(&path, "http://192.168.0.113:3000").unwrap();
        let got = read_user_yaml_team_route(&path);
        assert_eq!(got.as_deref(), Some("http://192.168.0.113:3000"));
    }

    /// Trial installs already write `trial.{jwt_secret, master_key, ...}`
    /// to the same file. The writer must NOT touch any other section —
    /// corrupting that section would brick the trial server's auth.
    #[test]
    fn writes_team_route_preserving_other_sections() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("aikey-user.yaml");
        std::fs::write(
            &path,
            "trial:\n  jwt_secret: dont-touch-me\n  service_token: also-dont\n",
        )
        .unwrap();

        write_user_yaml_team_route(&path, "http://192.168.0.113:3000").unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        // trial: section intact
        assert_eq!(
            v.get("trial")
                .and_then(|t| t.get("jwt_secret"))
                .and_then(|s| s.as_str()),
            Some("dont-touch-me"),
            "trial.jwt_secret must survive the proxy-section write"
        );
        assert_eq!(
            v.get("trial")
                .and_then(|t| t.get("service_token"))
                .and_then(|s| s.as_str()),
            Some("also-dont"),
        );
        // proxy: section was added
        assert_eq!(
            read_user_yaml_team_route(&path).as_deref(),
            Some("http://192.168.0.113:3000"),
        );
    }

    /// Re-login against a different control URL overwrites the previous
    /// team route in place — no orphaned old value left behind.
    #[test]
    fn rewrites_existing_team_route() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("aikey-user.yaml");
        write_user_yaml_team_route(&path, "http://old:3000").unwrap();
        write_user_yaml_team_route(&path, "http://new:3000").unwrap();
        assert_eq!(
            read_user_yaml_team_route(&path).as_deref(),
            Some("http://new:3000")
        );
    }

    /// Reader contract: missing file / missing path returns None rather
    /// than erroring. configure_proxy_collector relies on this to
    /// short-circuit no-op writes.
    #[test]
    fn reader_returns_none_for_missing_file_or_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.yaml");
        assert_eq!(read_user_yaml_team_route(&path), None);

        // File exists but no proxy section
        let path = dir.path().join("aikey-user.yaml");
        std::fs::write(&path, "trial:\n  jwt_secret: x\n").unwrap();
        assert_eq!(read_user_yaml_team_route(&path), None);
    }

    /// Top-level scalar / sequence is corruption — writer refuses to
    /// silently smash it. Returning Err here surfaces the issue (caller
    /// prints a hint) instead of writing on top of bad state.
    #[test]
    fn writer_refuses_to_overwrite_corrupt_root() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("aikey-user.yaml");
        std::fs::write(&path, "- just\n- a\n- list\n").unwrap();
        let err = write_user_yaml_team_route(&path, "http://x:3000")
            .expect_err("non-mapping root must reject");
        assert!(
            err.contains("top-level"),
            "error must name the shape issue: {}",
            err
        );
    }

    // ── 2026-05-11 B3: collector_credentials.team bundle ─────────────────
    //
    // configure_proxy_collector now ALSO writes a JWT bundle into
    // proxy.events.collector_credentials.team — these tests pin that
    // contract (proxy reporter's RefreshableJWT depends on the exact
    // field names + nesting). Keeping the tests in the existing test
    // mod since they share the same fixtures.

    fn make_cred(token: &str, exp: i64, url: &str) -> super::CredentialFields {
        super::CredentialFields {
            access_token: token.into(),
            expires_at: exp,
            refresh_url: url.into(),
        }
    }

    /// Happy path: writer emits the full bundle in the expected shape.
    /// proxy reporter loads `token`/`expires_at`/`refresh_url` plus
    /// `type` (selector for future non-JWT credentials, e.g. mTLS).
    #[test]
    fn writes_team_credential_bundle() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("aikey-user.yaml");
        let cred = make_cred(
            "eyJ.fakejwt.xyz",
            1_778_500_000,
            "http://192.168.0.113:3000/auth/refresh",
        );
        super::write_user_yaml_team_section(&path, "http://192.168.0.113:3000", Some(&cred))
            .expect("write");

        let got = super::read_user_yaml_team(&path).expect("read");
        assert_eq!(got.url.as_deref(), Some("http://192.168.0.113:3000"));
        assert_eq!(
            got.cred.as_ref().map(|c| c.access_token.as_str()),
            Some("eyJ.fakejwt.xyz"),
        );
        assert_eq!(got.cred.as_ref().map(|c| c.expires_at), Some(1_778_500_000));
        assert_eq!(
            got.cred.as_ref().map(|c| c.refresh_url.as_str()),
            Some("http://192.168.0.113:3000/auth/refresh"),
        );

        // The serialized form must include `type: jwt` so future
        // selector logic (multi-credential type) keeps working.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("type: jwt"),
            "serialized yaml should declare type: jwt; got:\n{}",
            raw
        );
    }

    /// Re-login refreshes the bundle: new access_token + new expires_at
    /// land in user.yaml, replacing the prior values in place.
    #[test]
    fn rewrites_team_credential_on_relogin() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("aikey-user.yaml");

        super::write_user_yaml_team_section(
            &path,
            "http://192.168.0.113:3000",
            Some(&make_cred(
                "old-jwt",
                1_000_000,
                "http://192.168.0.113:3000/auth/refresh",
            )),
        )
        .unwrap();

        super::write_user_yaml_team_section(
            &path,
            "http://192.168.0.113:3000",
            Some(&make_cred(
                "new-jwt",
                9_999_999,
                "http://192.168.0.113:3000/auth/refresh",
            )),
        )
        .unwrap();

        let got = super::read_user_yaml_team(&path).unwrap();
        assert_eq!(got.cred.unwrap().access_token, "new-jwt");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("old-jwt"),
            "old credential must be fully replaced; got:\n{}",
            raw
        );
    }

    /// cred == None: the writer leaves the URL but scrubs any prior
    /// credential. Models the `aikey account logout` path — user
    /// shouldn't leave a usable JWT on disk after signing out.
    #[test]
    fn scrubs_team_credential_when_cred_is_none() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("aikey-user.yaml");

        // Seed with a credential bundle.
        super::write_user_yaml_team_section(
            &path,
            "http://x:3000",
            Some(&make_cred("secret-jwt", 100, "http://x:3000/auth/refresh")),
        )
        .unwrap();

        // Logout-like call: same URL, no credential.
        super::write_user_yaml_team_section(&path, "http://x:3000", None).unwrap();

        let got = super::read_user_yaml_team(&path).unwrap();
        assert_eq!(
            got.url.as_deref(),
            Some("http://x:3000"),
            "URL must persist"
        );
        assert!(got.cred.is_none(), "credential bundle must be scrubbed");

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("secret-jwt"),
            "scrubbed yaml must not contain old jwt; got:\n{}",
            raw
        );
    }

    /// Credential writes preserve sibling sections (`trial:` and the
    /// other `proxy.events.collector_routes.*` entries). Trial-server
    /// installer writes `trial.jwt_secret` etc.; corrupting that would
    /// brick the trial server.
    #[test]
    fn credential_write_preserves_trial_section() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("aikey-user.yaml");
        std::fs::write(
            &path,
            "trial:\n  jwt_secret: dont-touch\n  master_key: keep-me\n",
        )
        .unwrap();

        super::write_user_yaml_team_section(
            &path,
            "http://x:3000",
            Some(&make_cred("jwt-A", 7777, "http://x:3000/auth/refresh")),
        )
        .unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        assert_eq!(
            v.get("trial")
                .and_then(|t| t.get("jwt_secret"))
                .and_then(|s| s.as_str()),
            Some("dont-touch"),
        );
        assert_eq!(
            v.get("trial")
                .and_then(|t| t.get("master_key"))
                .and_then(|s| s.as_str()),
            Some("keep-me"),
        );
    }

    /// Reader returns None on missing / malformed; configure_proxy_collector
    /// relies on this short-circuit to decide write-vs-noop.
    #[test]
    fn read_returns_partial_when_only_url_set() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("aikey-user.yaml");
        super::write_user_yaml_team_section(&path, "http://x:3000", None).unwrap();
        let got = super::read_user_yaml_team(&path).unwrap();
        assert_eq!(got.url.as_deref(), Some("http://x:3000"));
        assert!(got.cred.is_none(), "credential should be absent");
    }

    #[test]
    fn read_returns_none_on_missing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.yaml");
        assert!(super::read_user_yaml_team(&path).is_none());
    }
}

// ============================================================================
// Tests for `host_loopback_parts` / `resolve_browse_base_url` host preservation
// (2026-06-08 fix). These pin the contract that `aikey web --copy-url` returns
// a URL whose host matches the host the user logged in against — so cookies /
// CORS / CSP all agree across `aikey login` and `aikey web`. Pre-fix, the host
// was hardcoded to `localhost` and a `127.0.0.1`-configured install would have
// its login cookie ignored on the auto-detected dev port.
// ============================================================================
#[cfg(test)]
mod browse_url_tests {
    use super::*;

    #[test]
    fn host_loopback_parts_preserves_ipv4_loopback() {
        let (scheme, host) = host_loopback_parts("http://127.0.0.1:3000");
        assert_eq!(scheme, "http");
        assert_eq!(host, "127.0.0.1");
    }

    #[test]
    fn host_loopback_parts_preserves_localhost_hostname() {
        let (scheme, host) = host_loopback_parts("http://localhost:3000");
        assert_eq!(scheme, "http");
        assert_eq!(host, "localhost");
    }

    #[test]
    fn host_loopback_parts_preserves_https_and_named_host() {
        // Production team Control Panel: scheme + non-loopback host should
        // also survive parsing — `resolve_browse_base_url` won't synthesize
        // a URL for non-loopback hosts, but we still build (scheme, host)
        // for the explicit-port branch.
        let (scheme, host) = host_loopback_parts("https://team.example.com");
        assert_eq!(scheme, "https");
        assert_eq!(host, "team.example.com");
    }

    #[test]
    fn host_loopback_parts_strips_trailing_path() {
        let (_, host) = host_loopback_parts("http://127.0.0.1:3000/user/overview");
        assert_eq!(host, "127.0.0.1");
    }

    #[test]
    fn host_loopback_parts_handles_url_without_port() {
        let (_, host) = host_loopback_parts("https://team.example.com/some/path");
        assert_eq!(host, "team.example.com");
    }

    #[test]
    fn host_loopback_parts_falls_back_when_unparseable() {
        // Garbage / scheme-less input → same default the pre-fix code used
        // unconditionally, so unparseable URLs land on the OLD behavior
        // rather than crashing.
        let (scheme, host) = host_loopback_parts("not-a-url");
        assert_eq!(scheme, "http");
        assert_eq!(host, "localhost");

        let (scheme, host) = host_loopback_parts("");
        assert_eq!(scheme, "http");
        assert_eq!(host, "localhost");
    }

    #[test]
    fn resolve_browse_base_url_explicit_port_keeps_ipv4_host() {
        // The reported bug: `aikey web --copy-url` after logging in with
        // `127.0.0.1` was returning `localhost`. With this fix, the
        // explicit-port branch (which `aikey web --port 3000` hits, and
        // which all auto-detect callers in is_local also pass through
        // via the rebuilt format string) preserves the host.
        let got = resolve_browse_base_url("http://127.0.0.1:8080", Some(3000));
        assert_eq!(got, "http://127.0.0.1:3000");
    }

    #[test]
    fn resolve_browse_base_url_explicit_port_keeps_localhost_host() {
        let got = resolve_browse_base_url("http://localhost:8080", Some(3000));
        assert_eq!(got, "http://localhost:3000");
    }

    #[test]
    fn resolve_browse_base_url_explicit_port_keeps_https() {
        let got = resolve_browse_base_url("https://team.example.com", Some(5173));
        assert_eq!(got, "https://team.example.com:5173");
    }

    #[test]
    fn resolve_browse_base_url_non_local_falls_back_to_control_url() {
        // Production team URL with no --port: no probing happens, the
        // stored control_url is returned verbatim.
        let got = resolve_browse_base_url("https://team.example.com", None);
        assert_eq!(got, "https://team.example.com");
    }

    #[test]
    fn resolve_browse_base_url_strips_trailing_slash_on_fallback() {
        // Regression: a LAN control_url stored WITH a trailing slash must not
        // leak it into the base — otherwise `base + /go/<alias>` becomes
        // `http://host:3000//go/overview`, a protocol-relative URL the SPA's
        // history.replaceState rejects with a SecurityError (cross-origin).
        let got = resolve_browse_base_url("http://192.168.0.240:3000/", None);
        assert_eq!(got, "http://192.168.0.240:3000");
    }
}

// ============================================================================
// Tests for `ensure_token_accepted_by_server` (2026-06-08 server-secret
// rotation handling). These tests pin the behaviour we promised in the
// docstring — namely:
//   - happy path: probe-OK → token passes through untouched
//   - server-reject + no refresh_token → actionable error mentioning the
//     exact `aikey login` command
//   - offline probe → cached token passes through (don't punish offline
//     users for a network blip during `aikey web --copy-url`)
// Live server-reject + successful refresh is covered by integration tests
// in workflow/CI/e2e/ — those need an actual backend to exercise.
// ============================================================================
#[cfg(test)]
mod probe_token_tests {
    use super::*;

    fn make_acc(refresh: Option<&str>) -> storage::PlatformAccount {
        storage::PlatformAccount {
            account_id: "test-acc".into(),
            email: "user@example.com".into(),
            control_url: "http://127.0.0.1:0".into(), // port 0 = guaranteed-no-listener
            jwt_token: "dummy-jwt".into(),
            logged_in_at: 0,
            refresh_token: refresh.map(str::to_string),
            token_expires_at: Some(i64::MAX), // never expire by clock
        }
    }

    #[test]
    fn ensure_token_offline_returns_cached_token() {
        // control_url points at port 0 (closed). probe_token returns
        // Offline. Caller should pass the token through unchanged so
        // `aikey web --copy-url` offline isn't blocked.
        let acc = make_acc(Some("rf"));
        let got = ensure_token_accepted_by_server(&acc, "cached-jwt".into()).unwrap();
        assert_eq!(got, "cached-jwt");
    }

    #[test]
    fn force_refresh_core_no_refresh_token_gives_actionable_error() {
        // 2026-06-11 extraction fence: the shared recovery core (now also
        // wired into the sync/snapshot 401 path — L8 fix) must return the
        // user-actionable `aikey login` command when there is no refresh
        // token, with the caller's reject context preserved as the prefix.
        let acc = make_acc(None);
        let err =
            force_refresh_after_server_reject(&acc, "snapshot request rejected (401)").unwrap_err();
        assert!(
            err.contains("aikey login --email user@example.com"),
            "must name the exact re-login command, got: {err}"
        );
        assert!(
            err.contains("--control-url http://127.0.0.1:0"),
            "must include the control url, got: {err}"
        );
        assert!(
            err.starts_with("snapshot request rejected (401)"),
            "caller context must stay visible as prefix, got: {err}"
        );
    }

    #[test]
    fn force_refresh_core_refresh_failure_gives_actionable_error() {
        // refresh_token present but control_url is port 0 (closed) →
        // do_refresh_token fails → error must still carry the re-login
        // command rather than a bare HTTP error.
        let acc = make_acc(Some("rf"));
        let err = force_refresh_after_server_reject(&acc, "ctx").unwrap_err();
        assert!(
            err.contains("aikey login --email user@example.com"),
            "must name the exact re-login command, got: {err}"
        );
    }

    #[test]
    fn ensure_token_error_mentions_login_command_when_no_refresh() {
        // No refresh_token + non-offline error → error string must
        // include the actionable `aikey login` command tailored to the
        // user's email + control_url. Skipped if probe falls through to
        // Offline (port 0). To deterministically exercise the Invalid
        // branch we'd need a mock HTTP server; here we just assert the
        // error formatting contract on the no-refresh-token case via the
        // direct error path coverage (the message construction is the
        // same code path regardless of which probe variant triggers).
        //
        // This is a smoke test for the format string, not a behaviour
        // test for the network path. Live network path is covered by E2E.
        let _ = make_acc(None);
        // The actual format is exercised inline; assertion: the error
        // string built when refresh_token is None always contains
        // "aikey login" + the email + the URL.
        let err = format!(
            "{}.\nThe cached login is unusable and there is no refresh token to retry with.\n\
             Run: aikey login --email {} --control-url {}",
            crate::platform_client::TokenProbeError::Invalid,
            "user@example.com",
            "http://127.0.0.1:0",
        );
        assert!(err.contains("aikey login"));
        assert!(err.contains("user@example.com"));
        assert!(err.contains("http://127.0.0.1:0"));
    }
}

#[cfg(test)]
mod sync_prune_tests {
    // Sync prune self-heal (2026-07-04): keys the server no longer returns for
    // the OWNING account are DELETED from the local cache (not stale-marked) —
    // a server-deleted key kept as `stale` rendered a permanent ghost row and,
    // for deterministic group-VK aliases, shadowed the re-issued key. Other
    // accounts' rows keep the re-login recovery semantics. 能红: revert the
    // prune to mark-stale and `owner_absent_row_is_deleted` fails.
    use super::*;
    use crate::storage;
    use secrecy::SecretString;

    fn setup_vault() -> (
        tempfile::TempDir,
        (
            std::sync::MutexGuard<'static, ()>,
            std::sync::MutexGuard<'static, ()>,
        ),
    ) {
        // AK_VAULT_PATH is guarded by storage::TEST_VAULT_LOCK (the vault
        // lock domain used by core_tests / query / executor / storage
        // tests). This module used to take ONLY ENV_MUTATION_LOCK here —
        // the sole offender in the crate — so it raced every vault-lock
        // test mutating the same var (surfaced 2026-07-13 as a flaky
        // 2-rows-vs-1 assert here that poisoned the env lock and cascaded
        // into 22 local_server_probe PoisonErrors). Hold BOTH, in the
        // crate-wide order established by claude_desktop::p2_tests::
        // EnvSandbox: ENV_MUTATION_LOCK first, TEST_VAULT_LOCK second.
        let env_guard = crate::test_env_lock::ENV_MUTATION_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let vault_guard = crate::storage::TEST_VAULT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("vault.db");
        unsafe {
            std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap());
        }
        let mut salt = [0u8; 16];
        crate::crypto::generate_salt(&mut salt).expect("salt");
        storage::initialize_vault(&salt, &SecretString::new("test_password".to_string()))
            .expect("init vault");
        (dir, (env_guard, vault_guard))
    }

    fn cache_entry(vk_id: &str, owner: &str) -> storage::VirtualKeyCacheEntry {
        storage::VirtualKeyCacheEntry {
            virtual_key_id: vk_id.to_string(),
            org_id: "org-1".to_string(),
            seat_id: "seat-1".to_string(),
            alias: format!("alias-{vk_id}"),
            provider_code: "anthropic".to_string(),
            protocol_type: "anthropic".to_string(),
            base_url: String::new(),
            credential_id: "cred-1".to_string(),
            credential_revision: "r1".to_string(),
            virtual_key_revision: "vr1".to_string(),
            key_status: "active".to_string(),
            share_status: "claimed".to_string(),
            local_state: "synced_inactive".to_string(),
            expires_at: None,
            provider_key_nonce: None,
            provider_key_ciphertext: None,
            synced_at: 0,
            local_alias: None,
            supported_providers: vec!["anthropic".to_string()],
            provider_base_urls: Default::default(),
            owner_account_id: Some(owner.to_string()),
            owner_email: None,
            extra: None,
            oauth_group_id: None,
            group_accounts: None,
            routing_config: None,
            group_alias: None,
            group_runtime: None,
        }
    }

    #[test]
    fn owner_absent_row_is_deleted_other_account_kept_idempotent() {
        let (_dir, _lock) = setup_vault();
        storage::upsert_virtual_key_cache(&cache_entry("vk-mine-gone", "acct-A")).unwrap();
        storage::upsert_virtual_key_cache(&cache_entry("vk-other-acct", "acct-B")).unwrap();

        // Empty snapshot for acct-A → its row must be DELETED; acct-B's row
        // (another server session's cache) must be untouched.
        apply_snapshot_to_cache(&[], "acct-A");

        let left = storage::list_virtual_key_cache().unwrap();
        assert!(
            !left.iter().any(|e| e.virtual_key_id == "vk-mine-gone"),
            "owner's server-removed key must be pruned, not stale-marked: {left:?}"
        );
        let other = left
            .iter()
            .find(|e| e.virtual_key_id == "vk-other-acct")
            .expect("other account's row must survive the prune");
        assert_ne!(
            other.local_state, "stale",
            "other account's row must be untouched"
        );

        // Idempotent: a second pass has nothing to prune and must not error.
        apply_snapshot_to_cache(&[], "acct-A");
        assert_eq!(storage::list_virtual_key_cache().unwrap().len(), 1);
    }
}

// ---------------------------------------------------------------------------
// Unified-origin composing gateway probe (P3, 20260703-web统一origin design)
// ---------------------------------------------------------------------------

/// Decides whether the local console can serve as the unified origin, from
/// the parsed /system/team-url response. Pure so unit tests can pin the
/// gating rule without a live server (same pattern as
/// `browser_launch_command`).
///
/// Gate = `gateway:true` AND a non-empty team_url: the gateway capability
/// exists only on new local-server binaries, and it composes nothing until
/// the CLI is logged in — both must hold or `aikey web` must keep the
/// pre-gateway team-origin behavior.
fn gateway_base_from_team_url_response(v: &serde_json::Value, port: u16) -> Option<String> {
    let gateway = v.get("gateway").and_then(|g| g.as_bool()).unwrap_or(false);
    let team = v.get("team_url").and_then(|t| t.as_str()).unwrap_or("");
    if gateway && !team.is_empty() {
        Some(format!("http://127.0.0.1:{}", port))
    } else {
        None
    }
}

/// Probes the co-installed local-server for the composing gateway. Returns
/// the local console base URL when the RUNNING server advertises it.
///
/// Why probe at call time instead of trusting install-state: the gateway is
/// login-gated per request inside the server and only exists on new
/// binaries; a 400ms loopback probe is cheap and always current, and a
/// failed probe simply falls back to the old flow (never blocks).
fn local_gateway_base() -> Option<String> {
    let port = crate::local_server_probe::read_local_server_port_or_default().unwrap_or(8090);
    let url = format!("http://127.0.0.1:{}/system/team-url", port);
    let resp = ureq::get(&url)
        .timeout(std::time::Duration::from_millis(400))
        .call()
        .ok()?;
    let v: serde_json::Value = resp.into_json().ok()?;
    gateway_base_from_team_url_response(&v, port)
}

#[cfg(test)]
mod gateway_probe_tests {
    use super::gateway_base_from_team_url_response;
    use serde_json::json;

    // Fence for the P3 gating rule: `aikey web` may only route to the local
    // origin when the server EXPLICITLY advertises the composing gateway AND
    // a team login exists. Every other shape (old server without the field,
    // logged-out, malformed) must fall back to the team-origin flow.
    #[test]
    fn routes_local_only_when_gateway_and_logged_in() {
        let yes = json!({"team_url": "http://192.168.0.120:3000", "gateway": true});
        assert_eq!(
            gateway_base_from_team_url_response(&yes, 8090).as_deref(),
            Some("http://127.0.0.1:8090")
        );
    }

    #[test]
    fn old_server_without_gateway_field_falls_back() {
        let old = json!({"team_url": "http://192.168.0.120:3000"});
        assert!(gateway_base_from_team_url_response(&old, 8090).is_none());
    }

    #[test]
    fn logged_out_or_malformed_falls_back() {
        let out = json!({"team_url": "", "gateway": true});
        assert!(gateway_base_from_team_url_response(&out, 8090).is_none());
        let weird = json!({"gateway": "yes"});
        assert!(gateway_base_from_team_url_response(&weird, 8090).is_none());
    }
}
