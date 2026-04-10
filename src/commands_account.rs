//! `aikey account` and team key command handlers.
//!
//! Covers:
//!  - `aikey account login` / `aikey account status` / `aikey account logout`
//!  - `aikey key list`  — show cached + server keys
//!  - `aikey key sync`  — refresh metadata from server
//!  - `aikey key use <id>` — activate a key for proxy routing

use colored::Colorize;
use secrecy::SecretString;
use std::io::{self, IsTerminal, Write};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto;
use crate::platform_client::{PlatformClient, PollResponse};
use crate::storage::{self, VirtualKeyCacheEntry};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read `controlPanelUrl` from `~/.aikey/config/config.json` (if present).
fn read_control_url_from_config() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::PathBuf::from(home).join(".aikey/config/config.json");
    let data = std::fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&data).ok()?;
    parsed["controlPanelUrl"].as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Auto-configure proxy `collector_url` in `~/.aikey/config/aikey-proxy.yaml`.
/// Uses the same control_url (nginx proxies collector API on the same port).
fn configure_proxy_collector(control_url: &str, json_mode: bool) {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let proxy_config = std::path::PathBuf::from(&home).join(".aikey/config/aikey-proxy.yaml");
    if !proxy_config.exists() {
        return; // No proxy config yet — skip silently.
    }

    // Collector API is proxied through nginx on the same origin as the control panel.
    // Proxy uploads to {collector_url}/v1/usage-events:batch
    let collector_url = control_url.trim_end_matches('/').to_string();

    let content = match std::fs::read_to_string(&proxy_config) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Check if collector_url is already set to the correct value.
    if content.contains(&format!("collector_url: \"{}\"", collector_url)) {
        return; // Already configured correctly.
    }

    // Update or insert collector_url.
    let updated = if content.contains("collector_url:") {
        // Replace existing line.
        let mut result = String::new();
        for line in content.lines() {
            if line.trim_start().starts_with("collector_url:") {
                let indent = &line[..line.len() - line.trim_start().len()];
                result.push_str(&format!("{}collector_url: \"{}\"", indent, collector_url));
            } else {
                result.push_str(line);
            }
            result.push('\n');
        }
        result
    } else if content.contains("flush_interval:") {
        // Append after flush_interval.
        let mut result = String::new();
        for line in content.lines() {
            result.push_str(line);
            result.push('\n');
            if line.trim_start().starts_with("flush_interval:") {
                result.push_str(&format!("  collector_url: \"{}\"\n", collector_url));
            }
        }
        result
    } else {
        return; // Can't find a safe place to insert.
    };

    if std::fs::write(&proxy_config, &updated).is_ok() && !json_mode {
        eprintln!("    Usage reporting → {}", collector_url);
        // Proxy reads YAML at startup only; reload won't pick up config changes.
        // Auto-restart proxy so the new collector_url takes effect immediately.
        if crate::commands_proxy::is_proxy_running() {
            let pw = if let Some(cached) = crate::session::try_get() {
                cached
            } else {
                // No cached password — prompt inline.
                eprintln!("    Restart proxy to apply.");
                eprint!("    \u{1F512} Enter Master Password: ");
                let _ = io::Write::flush(&mut io::stderr());
                match rpassword::read_password() {
                    Ok(p) => SecretString::new(p),
                    Err(_) => {
                        eprintln!("\n    Run {} manually.", "'aikey proxy restart'".bold());
                        return;
                    }
                }
            };
            let _ = crate::commands_proxy::handle_restart(None, &pw);
        }
    }
}

/// Persist `controlPanelUrl` in `~/.aikey/config/config.json`.
fn save_control_url_to_config(url: &str) {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let dir = std::path::PathBuf::from(&home).join(".aikey/config");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("config.json");

    let mut obj: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_else(|| serde_json::json!({"version": "1"}));

    obj["controlPanelUrl"] = serde_json::Value::String(url.to_string());
    let _ = std::fs::write(&path, serde_json::to_string_pretty(&obj).unwrap_or_default());
}

// ---------------------------------------------------------------------------
// account set-url
// ---------------------------------------------------------------------------

/// `aikey account set-url <URL>`
///
/// Updates the control panel URL without re-authenticating. Useful when the
/// server IP changes (e.g. after a reboot with DHCP).
pub fn handle_set_control_url(url: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let url = url.trim_end_matches('/');

    // Update config.json (used by login flow for default URL).
    save_control_url_to_config(url);

    // Update the platform_account row if logged in (used by all API calls).
    if let Ok(Some(acc)) = storage::get_platform_account() {
        let old_url = acc.control_url.clone();
        storage::update_platform_control_url(url)?;

        // Also update proxy collector_url (nginx proxies collector on same origin).
        configure_proxy_collector(url, json_mode);

        if json_mode {
            crate::json_output::print_json(serde_json::json!({
                "ok": true,
                "old_url": old_url,
                "new_url": url,
            }));
        } else {
            println!("{} Control URL updated.", "\u{2713}".green());
            println!("  {} → {}", old_url.dimmed(), url.bold());
            println!("  Proxy collector URL also updated.");
            println!();
            println!("  {} Restart proxy to apply: {}", "\u{2192}".dimmed(), "aikey proxy restart".bold());
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
            println!("{} Control URL saved to config.", "\u{2713}".green());
            println!("  URL: {}", url.bold());
            println!("  Log in with: {}", format!("aikey login --control-url {}", url).cyan());
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
    } else if std::env::var("AIKEY_CONTROL_URL").is_ok() || read_control_url_from_config().is_some() {
        // Already configured via env or config file — use it directly, no prompt.
        if !json_mode {
            eprintln!("  Control Panel: {}", default_url);
        }
        default_url
    } else {
        print!("Control Panel URL [{}]: ", default_url);
        io::stdout().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim().to_string();
        if trimmed.is_empty() { default_url } else { trimmed }
    };

    // --- Copy-paste fallback: --token SESSION_ID:LOGIN_TOKEN ---
    if let Some(combined) = flag_token {
        return exchange_combined_token(&control_url, &combined, json_mode);
    }

    // --- OAuth device flow via browser ---
    let client_version = env!("CARGO_PKG_VERSION");
    let os_platform = std::env::consts::OS;

    let session = PlatformClient::init_cli_login(
        &control_url,
        client_version,
        os_platform,
    )
    .map_err(|e| format!("Login failed: {}", e))?;

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
            println!("{}  Your {} is pre-filled — click {}", step("2"), "email".bold(), "\"Send Login Link\"".bold());
        } else {
            println!("{}  Enter your {} and click {}", step("2"), "email".bold(), "\"Send Login Link\"".bold());
        }
        println!();
        println!("{}  Check your inbox and click the {} link", step("3"), "activation".bold());
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
            if !json_mode {
                eprintln!();
                eprintln!("  {}", "Session expired.".yellow());
                eprintln!("  Tip: copy the one-time {} from the {} page and run:", "token".bold(), "activation".bold());
                eprintln!("       {}", "aikey login --token SESSION_ID:LOGIN_TOKEN".bold());
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
        return Err(
            "Invalid --token format. Expected: SESSION_ID:LOGIN_TOKEN".into(),
        );
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
            if cfg.key_type == "team" {
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
    if crate::storage::get_salt().is_err() {
        if !json_mode {
            eprintln!();
            eprint!("  \u{1F512} Set Master Password: ");
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
    }

    // Pull the account's current key snapshot immediately after login.
    // This ensures keys are visible right after `aikey login` without needing
    // a separate `aikey key list` or `aikey key sync` call.
    // Non-fatal: if the server is unreachable the local cache is still usable.
    let _ = run_snapshot_sync();

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "account_id": account.account_id,
            "email": account.email,
        }));
    } else {
        println!();
        println!("  {} Logged in as {}", "✓".green().bold(), account.email.bold());
        println!("    Run {} to view your team keys.", "'aikey key list'".bold());
    }

    // Persist control URL to config.json so future logins skip the prompt.
    save_control_url_to_config(&control_url);

    // Auto-configure proxy collector_url so usage reporting works out of the box.
    // Collector runs on the same host as the control panel, fixed port 27300.
    configure_proxy_collector(&control_url, json_mode);

    Ok(())
}


// ---------------------------------------------------------------------------
// Browser helper
// ---------------------------------------------------------------------------

/// Opens a URL in the default system browser (best-effort; failures are ignored).
fn open_url_silently(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let _ = url; // unsupported platform — silently skip
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
        format!(
            "Token refresh failed: {}. Run 'aikey account login' to re-authenticate.",
            e
        )
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
fn get_authenticated_client() -> Result<PlatformClient, Box<dyn std::error::Error>> {
    let acc = storage::get_platform_account()?
        .ok_or("Not logged in. Run 'aikey account login' first.")?;
    let token = try_refresh_if_needed(&acc).map_err(|e| -> Box<dyn std::error::Error> {
        e.into()
    })?;
    Ok(PlatformClient::new(&acc.control_url, &token))
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

/// `aikey browse [page] [--port PORT]` — open User Console in the default browser with auth.
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
/// `aikey browse` work in both dev and production without extra flags.
pub fn handle_browse(page: Option<&str>, port: Option<u16>, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Local-user mode: open console directly without JWT.
    // Why: personal edition has no login flow — LocalIdentityMiddleware handles
    // auth server-side, and the SPA is served with authMode:"local_bypass".
    if port.is_none() {
        if let Some(url) = try_local_browse_url(page) {
            if json_mode {
                crate::json_output::print_json(serde_json::json!({
                    "ok": true,
                    "url": &url,
                    "mode": "local",
                }));
            } else {
                println!("Opening Local Console...");
                println!("  {}", url);
            }
            open_url_silently(&url);
            return Ok(());
        }
    }

    // JWT-based browse (team/trial mode).
    let acc = storage::get_platform_account()?
        .ok_or("Not logged in. Run 'aikey login' first.")?;

    let token = try_refresh_if_needed(&acc).map_err(|e| -> Box<dyn std::error::Error> {
        e.into()
    })?;

    let path = match page {
        Some("keys" | "virtual-keys") => "/user/virtual-keys",
        Some("account")               => "/user/account",
        Some("usage" | "usage-ledger") => "/user/usage-ledger",
        Some("overview") | None        => "/user/overview",
        Some(other) => {
            return Err(format!(
                "Unknown page '{}'. Available: overview, keys, account, usage",
                other
            ).into());
        }
    };

    let base_url = resolve_browse_base_url(&acc.control_url, port);

    let url = format!("{}{}#auth_token={}", base_url, path, token);

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "url": format!("{}{}", base_url, path),
        }));
    } else {
        println!("Opening User Console...");
        println!("  {}{}", base_url, path);
    }

    open_url_silently(&url);
    Ok(())
}

/// Try to resolve a local-user browse URL from install-state.json.
///
/// Returns `Some(full_url)` if `control_plane_mode == "local"` and
/// `control_panel_url` is set; `None` otherwise (falls through to JWT flow).
fn try_local_browse_url(page: Option<&str>) -> Option<String> {
    let home = dirs::home_dir()?;
    let state_path = home.join(".aikey").join("install-state.json");
    let content = std::fs::read_to_string(&state_path).ok()?;
    let state: serde_json::Value = serde_json::from_str(&content).ok()?;

    let mode = state.get("control_plane_mode")?.as_str()?;
    if mode != "local" {
        return None;
    }

    let base_url = state.get("control_panel_url")?.as_str()?;
    if base_url.is_empty() {
        return None;
    }

    let path = match page {
        Some("keys" | "virtual-keys") => "/user/virtual-keys",
        Some("account")               => "/user/account",
        Some("usage" | "usage-ledger") => "/user/usage-ledger",
        Some("overview") | None        => "/user/overview",
        _                              => "/user/overview",
    };

    Some(format!("{}{}", base_url.trim_end_matches('/'), path))
}

/// Determine the base URL for `aikey browse`.
///
/// Priority:
///   1. Explicit `--port` flag  →  `http://localhost:<port>`
///   2. Env var `AIKEY_WEB_URL` →  use as-is
///   3. Auto-detect: if control_url is localhost, probe dev-server ports
///   4. Fall back to the stored `control_url`
fn resolve_browse_base_url(control_url: &str, explicit_port: Option<u16>) -> String {
    use std::net::TcpStream;
    use std::time::Duration;

    // 1. Explicit --port
    if let Some(p) = explicit_port {
        return format!("http://localhost:{}", p);
    }

    // 2. Env var override
    if let Ok(url) = std::env::var("AIKEY_WEB_URL") {
        if !url.is_empty() {
            return url;
        }
    }

    // 3. Auto-detect dev server (only when control_url is localhost).
    //    Vite may listen on IPv6 (::1) or IPv4 (127.0.0.1) — probe both.
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
                ).is_ok() {
                    return format!("http://localhost:{}", p);
                }
            }
        }
    }

    // 4. Fall back to control_url
    control_url.to_string()
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
    let vault_exists = storage::get_vault_path().map(|p| p.exists()).unwrap_or(false);

    let local_seen_version = storage::get_local_seen_sync_version();

    if json_mode {
        let active_json = active_cfg.as_ref().map(|cfg| serde_json::json!({
            "key_type": cfg.key_type,
            "key_ref":  cfg.key_ref,
            "providers": cfg.providers,
        }));
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
            println!("{:<16} {} {}", "Account:".bold(),
                a.email.bold(),
                format!("({})", a.account_id).dimmed());
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
            println!("{:<16} {} {} [{}]",
                "Active key:".bold(),
                cfg.key_ref.bold(),
                format!("({})", cfg.key_type).dimmed(),
                providers);
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

pub fn handle_logout(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Scope-disable all team keys so the proxy stops routing them immediately.
    // Passing "" disables every row regardless of owner_account_id, since no
    // row has owner_account_id = "".
    let _ = storage::disable_keys_for_account_scope("");

    // Clear the active key config if it references a team key — a logged-out
    // session has no valid account to own team keys.
    if let Ok(Some(cfg)) = storage::get_active_key_config() {
        if cfg.key_type == "team" {
            let _ = storage::clear_active_key_config();
        }
    }

    // Reset sync version so the next login always performs a full sync,
    // even if the new account happens to be different from the old one
    // (in which case finish_login won't detect an "account switch").
    storage::set_local_seen_sync_version(0);

    storage::clear_platform_account()?;
    if json_mode {
        crate::json_output::print_json(serde_json::json!({ "ok": true }));
    } else {
        println!("Logged out.");
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
            "seat_disabled"                   => "disabled_by_seat_status".to_string(),
            "key_revoked" | "key_expired"     => "disabled_by_key_status".to_string(),
            "account_disabled"                => "disabled_by_account_status".to_string(),
            _                                 => "synced_inactive".to_string(), // e.g. not_claimed
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
        let local_alias  = existing.as_ref().and_then(|e| e.local_alias.clone());
        let nonce        = existing.as_ref().and_then(|e| e.provider_key_nonce.clone());
        let ciphertext   = existing.as_ref().and_then(|e| e.provider_key_ciphertext.clone());
        let existing_state = existing.as_ref().map(|e| e.local_state.as_str()).unwrap_or("");

        let local_state = compute_local_state_from_effective(
            &item.effective_status,
            &item.effective_reason,
            existing_state,
        );

        let entry = storage::VirtualKeyCacheEntry {
            virtual_key_id:       item.virtual_key_id.clone(),
            org_id:               item.org_id.clone(),
            seat_id:              item.seat_id.clone(),
            alias:                item.alias.clone(),
            provider_code:        item.provider_code.clone(),
            protocol_type:        item.protocol_type.clone(),
            base_url:             item.base_url.clone(),
            credential_id:        item.credential_id.clone(),
            credential_revision:  item.credential_revision.clone(),
            virtual_key_revision: item.virtual_key_revision.clone(),
            key_status:           item.key_status.clone(),
            share_status:         item.share_status.clone(),
            local_state,
            expires_at:           item.expires_at,
            provider_key_nonce:   nonce,
            provider_key_ciphertext: ciphertext,
            synced_at:            0,
            local_alias,
            supported_providers:  item.supported_providers.clone(),
            provider_base_urls:   item.provider_base_urls.clone(),
            owner_account_id:     Some(current_account_id.to_string()),
        };

        let _ = storage::upsert_virtual_key_cache(&entry);

        // If this key is currently active in the proxy, refresh active.env so the
        // proxy picks up any updated provider list without requiring a restart.
        if !entry.supported_providers.is_empty() {
            if let Ok(Some(active_cfg)) = crate::storage::get_active_key_config() {
                if active_cfg.key_type == "team" && active_cfg.key_ref == entry.virtual_key_id {
                    let display = entry.local_alias.as_deref().unwrap_or(entry.alias.as_str());
                    let _ = write_active_env(
                        "team", &entry.virtual_key_id, display,
                        &entry.supported_providers, crate::commands_proxy::proxy_port(),
                    );
                }
            }
        }
    }

    // Mark stale: keys the current account owns locally but the server no longer returns.
    // This includes the currently-active key: if the server has removed it from the
    // snapshot, it is no longer valid and must be deactivated immediately.
    if let Ok(cached) = storage::list_virtual_key_cache() {
        for entry in cached {
            if entry.owner_account_id.as_deref() == Some(current_account_id)
                && !seen_ids.contains(&entry.virtual_key_id)
                && entry.local_state != "stale"
            {
                let _ = storage::set_virtual_key_local_state(&entry.virtual_key_id, "stale");
                // If this key was the active proxy key, clear the active key config
                // so the proxy stops routing it on next reload.
                if entry.local_state == "active" {
                    if let Ok(Some(cfg)) = storage::get_active_key_config() {
                        if cfg.key_type == "team" && cfg.key_ref == entry.virtual_key_id {
                            let _ = storage::clear_active_key_config();
                        }
                    }
                }
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
    use colored::Colorize;

    let acc = match storage::get_platform_account().ok().flatten() {
        Some(a) => a,
        None => return Ok(0),
    };
    let token = match try_refresh_if_needed(&acc) {
        Ok(t) => t,
        Err(e) => return Err(format!("token refresh: {}", e)),
    };
    let client = PlatformClient::new(&acc.control_url, &token);

    // Pull the full snapshot (metadata).
    let snapshot = match client.get_managed_keys_snapshot() {
        Ok(s) => s,
        Err(e) => return Err(format!("snapshot: {}", e)),
    };

    apply_snapshot_to_cache(&snapshot.keys, &acc.account_id);
    storage::set_local_seen_sync_version(snapshot.sync_version);
    let _ = storage::bump_vault_change_seq();

    // Claim any unclaimed keys and download missing key material.
    let vault_key = derive_vault_key(password)?;
    let account_id = Some(acc.account_id.clone());

    let cached = storage::list_virtual_key_cache().unwrap_or_default();
    let mut downloaded = 0usize;

    for entry in &cached {
        // Needs claim: pending_claim but not yet claimed on server.
        let needs_claim = entry.share_status == "pending_claim"
            && entry.key_status == "active";
        // Needs download: claimed (or about to be) but missing local ciphertext.
        let needs_download = entry.provider_key_ciphertext.is_none()
            && entry.key_status == "active"
            && !entry.local_state.starts_with("disabled_by_");

        if !needs_claim && !needs_download {
            continue;
        }

        // Claim on server first if pending.
        if needs_claim {
            if let Err(e) = client.claim_key(&entry.virtual_key_id) {
                eprintln!("  {} could not claim {}: {}",
                    "✗".red(), entry.alias, e);
                continue;
            }
        }

        // Download the delivery payload (plaintext provider key over TLS).
        match client.get_key_delivery(&entry.virtual_key_id) {
            Ok(payload) => {
                match payload.primary_binding() {
                    None => {
                        eprintln!("  {} key '{}' has no active bindings — skipping.",
                            "!".yellow(), entry.alias);
                    }
                    Some(binding) => {
                        let protocol_type = payload.primary_protocol_type().to_string();
                        let (nonce, ciphertext) =
                            crypto::encrypt(&vault_key, binding.provider_key.as_bytes())
                                .map_err(|e| format!("encrypt: {}", e))?;

                        let sync_supported_providers = if !payload.supported_providers.is_empty() {
                            payload.supported_providers.clone()
                        } else if !binding.provider_code.is_empty() {
                            vec![binding.provider_code.clone()]
                        } else {
                            entry.supported_providers.clone()
                        };
                        let sync_provider_base_urls: std::collections::HashMap<String, String> =
                            payload.slots
                                .iter()
                                .flat_map(|slot| slot.binding_targets.iter())
                                .map(|b| (b.provider_code.clone(), b.base_url.clone()))
                                .collect();

                        let updated = VirtualKeyCacheEntry {
                            virtual_key_id:       payload.virtual_key_id.clone(),
                            org_id:               payload.org_id.clone(),
                            seat_id:              payload.seat_id.clone(),
                            alias:                payload.alias.clone(),
                            provider_code:        binding.provider_code.clone(),
                            protocol_type,
                            base_url:             binding.base_url.clone(),
                            credential_id:        binding.credential_id.clone(),
                            credential_revision:  binding.credential_revision.clone(),
                            virtual_key_revision: payload.current_revision.clone(),
                            key_status:           payload.key_status.clone(),
                            share_status:         payload.share_status.clone(),
                            local_state:          "synced_inactive".to_string(),
                            expires_at:           entry.expires_at,
                            provider_key_nonce:   Some(nonce),
                            provider_key_ciphertext: Some(ciphertext),
                            synced_at:            0,
                            local_alias:          entry.local_alias.clone(),
                            supported_providers:  sync_supported_providers,
                            provider_base_urls:   sync_provider_base_urls,
                            owner_account_id:     account_id.clone(),
                        };
                        let _ = storage::upsert_virtual_key_cache(&updated);

                        eprintln!("  {} New key: {} {}",
                            "✓".green().bold(),
                            payload.alias.bold(),
                            format!("[{}]", binding.provider_code).dimmed());

                        downloaded += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("  {} could not fetch key '{}': {}",
                    "✗".red(), entry.alias, e);
            }
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
    Ok(remote_version > local_seen)
}

/// Spawns a background thread to check and apply a server snapshot update.
///
/// Single-flight: if a sync is already in progress (e.g. from a concurrent
/// command invocation), this call is a no-op. This prevents duplicate snapshot
/// fetches and local-cache write races when multiple commands run close together.
///
/// Non-blocking: the calling command is not delayed.
/// All errors are silently suppressed — the local cache remains usable offline.
pub fn try_background_snapshot_sync() {
    use std::sync::atomic::{AtomicBool, Ordering};
    // Static flag: true while a background sync thread is running.
    static SYNC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

    // compare_exchange(expected=false, new=true): only one thread wins.
    if SYNC_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return; // another sync is already running — skip
    }

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
/// Called by both `handle_key_list` (aikey key list) and the `aikey list` command
/// so both always display fresh metadata without a separate sync step.
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
        let existing_state = existing.as_ref().map(|e| e.local_state.as_str()).unwrap_or("");
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
        let ciphertext = existing.as_ref().and_then(|e| e.provider_key_ciphertext.clone());
        let base_url = existing.as_ref().map(|e| e.base_url.clone()).unwrap_or_default();
        let credential_id = existing.as_ref().map(|e| e.credential_id.clone()).unwrap_or_default();
        let credential_revision = existing.as_ref().map(|e| e.credential_revision.clone()).unwrap_or_default();
        let virtual_key_revision = existing.as_ref().map(|e| e.virtual_key_revision.clone()).unwrap_or_default();

        let local_alias = existing.as_ref().and_then(|e| e.local_alias.clone());
        // Preserve supported_providers from existing cache; update from server if non-empty.
        let supported_providers = if !item.supported_providers.is_empty() {
            item.supported_providers.clone()
        } else {
            existing.as_ref().map(|e| e.supported_providers.clone()).unwrap_or_default()
        };
        // Preserve existing provider_base_urls — server metadata sync doesn't re-deliver base URLs.
        let provider_base_urls = existing.as_ref()
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
        };
        let _ = storage::upsert_virtual_key_cache(&entry);

        // If this key is currently active, refresh ~/.aikey/active.env with updated providers.
        // Handles the case where sync adds new providers to an already-active key.
        if !entry.supported_providers.is_empty() {
            if let Ok(Some(active_cfg)) = crate::storage::get_active_key_config() {
                if active_cfg.key_type == "team" && active_cfg.key_ref == entry.virtual_key_id {
                    let display = entry.local_alias.as_deref().unwrap_or(entry.alias.as_str());
                    let _ = write_active_env("team", &entry.virtual_key_id, display, &entry.supported_providers, crate::commands_proxy::proxy_port());
                }
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// aikey key list
// ---------------------------------------------------------------------------

/// `aikey key list`
///
/// Fetches all team keys from the control service (if logged in) and merges
/// with local cache, then displays a table.  No master password required —
/// key material stays encrypted; only metadata is shown.
pub fn handle_key_list(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let logged_in = storage::get_platform_account()?.is_some();

    // Sync key state from server using the snapshot path; warn on failure only in
    // interactive mode.  run_snapshot_sync() is a no-op when the server version
    // matches local_seen, so it's fast after the background sync has already run.
    let server_ok = run_snapshot_sync().is_ok();
    if !server_ok && !json_mode && logged_in {
        eprintln!("Warning: could not reach control service. Showing local cache.");
    }

    let maybe_client: Option<()> = if logged_in { Some(()) } else { None };

    // Read (now-refreshed) local cache.
    // Only surface active keys — revoked / recycled / expired keys are hidden
    // from all list output so users are not misled about usable keys.
    let cached: Vec<_> = storage::list_virtual_key_cache()?
        .into_iter()
        .filter(|e| e.key_status == "active")
        .collect();

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "keys": cached.iter().map(|e| serde_json::json!({
                "virtual_key_id": e.virtual_key_id,
                "alias": e.alias,
                "local_alias": e.local_alias,
                "provider_code": e.provider_code,
                "key_status": e.key_status,
                "share_status": e.share_status,
                "local_state": e.local_state,
                "has_key": e.provider_key_ciphertext.is_some(),
            })).collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    if cached.is_empty() {
        if maybe_client.is_none() {
            println!("Not logged in. Run 'aikey account login' to connect.");
        } else if server_ok {
            println!("No team keys assigned yet.");
        } else {
            println!("No keys in local cache.");
        }
        return Ok(());
    }

    // Table header.
    println!("{:<36}  {:<20}  {:<12}  {:<10}  {:<14}  {}",
        "ID", "ALIAS", "PROVIDER", "STATUS", "SHARE", "LOCAL");
    println!("{}", "─".repeat(110));

    for e in &cached {
        let has_key = if e.provider_key_ciphertext.is_some() { "✓" } else { "" };
        let share = match e.share_status.as_str() {
            "pending_claim" => "pending  ←",
            other => other,
        };
        println!("{:<36}  {:<20}  {:<12}  {:<10}  {:<14}  {:<14}  {}",
            &e.virtual_key_id,
            truncate(&e.alias, 20),
            &e.provider_code,
            &e.key_status,
            share,
            &e.local_state,
            has_key,
        );
    }

    let pending_count = cached.iter().filter(|e|
        e.provider_key_ciphertext.is_none() && e.key_status == "active"
        && !e.local_state.starts_with("disabled_by_")
    ).count();
    if pending_count > 0 {
        println!();
        println!("  {} key(s) not yet synced. Run 'aikey key sync' to download.", pending_count);
    }

    Ok(())
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
) -> Result<(), Box<dyn std::error::Error>> {
    // Force a full sync by resetting local_seen_sync_version to 0.
    storage::set_local_seen_sync_version(0);
    let downloaded = run_full_snapshot_sync(password)?;

    // v1.0.2: reconcile provider primaries after sync.
    let cached = storage::list_virtual_key_cache().unwrap_or_default();
    let synced_keys: Vec<(String, Vec<String>)> = cached.iter()
        .filter(|e| e.key_status == "active" && !e.local_state.starts_with("disabled_by_"))
        .map(|e| {
            let p = if !e.supported_providers.is_empty() { e.supported_providers.clone() }
                    else if !e.provider_code.is_empty() { vec![e.provider_code.clone()] }
                    else { vec![] };
            (e.virtual_key_id.clone(), p)
        }).filter(|(_, p)| !p.is_empty()).collect();
    let reconciled = crate::profile_activation::reconcile_provider_primaries_after_team_key_sync(&synced_keys).unwrap_or_default();
    if !reconciled.is_empty() { let _ = crate::profile_activation::refresh_implicit_profile_activation(); }

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
                eprintln!("  {} Team key '{}' auto-activated as Primary for {}", "\u{2B50}".yellow(), vk_id.bold(), p);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// aikey key use
// ---------------------------------------------------------------------------

/// Provider code → environment variable names for API key + base URL.
///
/// Accepts both canonical codes ("anthropic") and common brand-name aliases
/// ("claude", "claude-3", etc.) that servers may use.
/// Public re-export of `provider_env_vars` for use by `executor::run_with_active_key`.
pub fn provider_env_vars_pub(provider_code: &str) -> Option<(&'static str, &'static str)> {
    provider_env_vars(provider_code)
}

fn provider_env_vars(provider_code: &str) -> Option<(&'static str, &'static str)> {
    match provider_code.to_lowercase().as_str() {
        "anthropic" | "claude" => Some(("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL")),
        "openai" | "gpt" | "chatgpt" => Some(("OPENAI_API_KEY", "OPENAI_BASE_URL")),
        "google" | "gemini"   => Some(("GOOGLE_API_KEY", "GOOGLE_BASE_URL")),
        "kimi"                => Some(("KIMI_API_KEY", "KIMI_BASE_URL")),
        "deepseek"            => Some(("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL")),
        "moonshot"            => Some(("MOONSHOT_API_KEY", "MOONSHOT_BASE_URL")),
        _                     => None,
    }
}

/// Returns the canonical proxy path prefix for a provider code.
///
/// The proxy's path-prefix router only recognises the canonical names
/// (e.g. `/anthropic/v1/...`), so env vars written by `write_active_env`
/// must use these — even when the server sends a brand alias like "Claude".
/// Public re-export of `provider_proxy_prefix` for use by `executor::run_with_active_key`.
pub fn provider_proxy_prefix_pub(provider_code: &str) -> &'static str {
    provider_proxy_prefix(provider_code)
}

fn provider_proxy_prefix(provider_code: &str) -> &'static str {
    match provider_code.to_lowercase().as_str() {
        "anthropic" | "claude" => "anthropic",
        "openai" | "gpt" | "chatgpt" => "openai",
        "google" | "gemini"   => "google",
        "kimi"                => "kimi/v1",
        "deepseek"            => "deepseek",
        "moonshot"            => "moonshot/v1",
        other => {
            // Unknown provider: pass through as-is (proxy may still handle it
            // if a matching path prefix is registered in the future).
            // SAFETY: returning 'static requires leaking; use Box::leak once.
            // For now fall back to "openai" (OpenAI-compatible default).
            let _ = other;
            "openai"
        }
    }
}

/// Writes `~/.aikey/active.env` with provider env vars for the active key.
///
/// For team keys the API key value is the virtual key ID (`aikey_vk_xxx`) — proxy
/// reads the active config and injects the real key.  For personal keys the value
/// is a sentinel `aikey_personal_<alias>` that the proxy resolves via `GetSecret`.
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
    let active_cfg = storage::get_active_key_config()?
        .ok_or("No active key. Run `aikey use <alias>` first.")?;

    if active_cfg.key_type != "personal" {
        return Err(format!(
            "--direct only supports personal keys (current active key is type '{}').\n\
             Switch to a personal key first: aikey use <alias>",
            active_cfg.key_type
        ).into());
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
        println!("{} Running {} with direct key injection (no proxy):",
            "→".dimmed(), cmd[0].bold());
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

    let status = child.status()
        .map_err(|e| format!("Failed to execute '{}': {}", cmd[0], e))?;

    std::process::exit(status.code().unwrap_or(1));
}

/// Auto-configure `~/.kimi/config.toml` so Kimi CLI works through the proxy.
///
/// Kimi CLI requires a static config with `[providers.kimi]` and `[models.*]`
/// (env vars alone are not enough — it won't select a model without config).
/// This function ensures the provider block points to the aikey proxy and the
/// api_key matches the current token. Model entries are added idempotently.
fn configure_kimi_cli(token_value: &str, proxy_port: u16) {
    use colored::Colorize;
    use std::io::{IsTerminal, Write};

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".kimi");
    let config_path = config_dir.join("config.toml");

    let base_url = format!("http://127.0.0.1:{}/kimi/v1", proxy_port);

    // Read existing config or start with defaults.
    let mut content = std::fs::read_to_string(&config_path).unwrap_or_default();

    let marker = "# managed by aikey";

    // Already configured — silent update (no prompt needed for subsequent switches).
    if content.contains(marker) {
        let mut updated = String::new();
        let mut in_kimi_provider = false;
        for line in content.lines() {
            if line.starts_with("[providers.kimi]") {
                in_kimi_provider = true;
                updated.push_str(line);
            } else if line.starts_with('[') {
                in_kimi_provider = false;
                updated.push_str(line);
            } else if in_kimi_provider && line.starts_with("api_key = ") {
                updated.push_str(&format!("api_key = \"{}\"", token_value));
            } else if in_kimi_provider && line.starts_with("base_url = ") {
                updated.push_str(&format!("base_url = \"{}\"", base_url));
            } else if line.starts_with("default_model = ") {
                // Why: TOML section keys cannot contain dots, so "kimi-k2.5" becomes
                // key "kimi-k2-5". Kimi CLI validates default_model against key names.
                let fixed = line
                    .replace("\"kimi-k2.5\"", "\"kimi-k2-5\"")
                    .replace("\"moonshot-v1.128k\"", "\"moonshot-v1-128k\"");
                updated.push_str(&fixed);
            } else {
                updated.push_str(line);
            }
            updated.push('\n');
        }
        let _ = std::fs::write(&config_path, updated);
        return;
    }

    // First time — prompt user before modifying their config.
    if io::stderr().is_terminal() {
        let mut rows: Vec<String> = vec![
            format!("File:    {}", "~/.kimi/config.toml"),
            format!("Add:     provider  base_url={}", base_url),
            format!("         models: kimi-k2.5, moonshot-v1-128k"),
        ];
        if !content.is_empty() {
            rows.push(format!("Backup:  {}", "~/.kimi/config.aikey_backup.toml"));
        }
        crate::ui_frame::eprint_box("\u{2753}", "Configure Kimi CLI", &rows);
        eprint!("  Proceed? [Y/n]: ");
        io::stderr().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            if input.trim().to_lowercase() == "n" {
                eprintln!("  {}", "Skipped. Run 'aikey use kimi' again to retry.".dimmed());
                return;
            }
        }
    }

    // Backup original config before first modification.
    let backup_path = config_dir.join("config.aikey_backup.toml");
    if !content.is_empty() && !backup_path.exists() {
        let _ = std::fs::copy(&config_path, &backup_path);
    }

    let _ = std::fs::create_dir_all(&config_dir);

    // If default_model is empty, set it.
    if content.contains("default_model = \"\"") {
        content = content.replace("default_model = \"\"", "default_model = \"kimi-k2-5\"");
    }

    let kimi_provider = format!(
        "[providers.kimi]  {}\ntype = \"kimi\"\nbase_url = \"{}\"\napi_key = \"{}\"",
        marker, base_url, token_value
    );
    let kimi_models = concat!(
        "[models.kimi-k2-5]\nprovider = \"kimi\"\nmodel = \"kimi-k2.5\"\nmax_context_size = 131072\n\n",
        "[models.moonshot-v1-128k]\nprovider = \"kimi\"\nmodel = \"moonshot-v1-128k\"\nmax_context_size = 131072",
    );

    if content.contains("[providers]") && !content.contains("[providers.") {
        content = content.replace("[providers]", &kimi_provider);
    } else if !content.contains("[providers.kimi]") {
        content.push_str(&format!("\n{}\n", kimi_provider));
    }

    if content.contains("[models]") && !content.contains("[models.") {
        content = content.replace("[models]", kimi_models);
    } else if !content.contains("[models.kimi") {
        content.push_str(&format!("\n{}\n", kimi_models));
    }

    match std::fs::write(&config_path, &content) {
        Ok(_) => {
            eprintln!("  {} Kimi CLI auto-configured: {}",
                "✓".green().bold(),
                config_path.display().to_string().dimmed());
        }
        Err(e) => {
            eprintln!("  {} Could not configure Kimi CLI: {}",
                "!".yellow(), e);
        }
    }
}

/// Restore `~/.kimi/config.toml` from the backup created by `configure_kimi_cli`.
///
/// Called when `aikey use` switches to a key that does not include kimi.
/// If a backup exists (`config.aikey_backup.toml`), it is moved back to `config.toml`.
/// If no backup exists but the config contains our marker, it is left as-is
/// (the user may have modified it after we configured it).
fn unconfigure_kimi_cli() {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let config_dir = std::path::PathBuf::from(&home).join(".kimi");
    let config_path = config_dir.join("config.toml");
    let backup_path = config_dir.join("config.aikey_backup.toml");

    if backup_path.exists() {
        // Restore the original config from backup.
        let _ = std::fs::rename(&backup_path, &config_path);
    } else if config_path.exists() {
        // No backup but config exists — check if it's ours.
        let content = std::fs::read_to_string(&config_path).unwrap_or_default();
        if content.contains("# managed by aikey") {
            // We created this file from scratch (there was no original).
            // Remove it so Kimi CLI returns to its default behavior.
            let _ = std::fs::remove_file(&config_path);
        }
    }
}

fn write_active_env(
    key_type: &str,
    key_ref: &str,    // virtual_key_id (team) or alias (personal)
    display_name: &str,
    providers: &[String],
    proxy_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let aikey_dir = std::path::PathBuf::from(&home).join(".aikey");
    std::fs::create_dir_all(&aikey_dir)?;
    let env_path = aikey_dir.join("active.env");

    let mut lines = vec![
        format!("# aikey active key — auto-generated by 'aikey use', do not edit manually"),
        format!("export AIKEY_ACTIVE_KEY=\"{}\"", display_name),
    ];

    for provider in providers {
        if let Some((api_key_var, base_url_var)) = provider_env_vars(provider) {
            let token_value = if key_type == "team" {
                format!("aikey_vk_{}", key_ref)
            } else {
                format!("aikey_personal_{}", key_ref)
            };
            let base_url = format!("http://127.0.0.1:{}/{}", proxy_port, provider_proxy_prefix(provider));
            lines.push(format!("export {}=\"{}\"", api_key_var, token_value));
            lines.push(format!("export {}=\"{}\"", base_url_var, base_url));
        }
    }

    // Ensure localhost proxy traffic bypasses user's HTTP proxy.
    // Appends to existing no_proxy via shell expansion — does not clobber.
    if !providers.is_empty() {
        lines.push(format!("export no_proxy=\"127.0.0.1,localhost,${{no_proxy:-}}\""));
        lines.push(format!("export NO_PROXY=\"127.0.0.1,localhost,${{NO_PROXY:-}}\""));
    }

    std::fs::write(&env_path, lines.join("\n") + "\n")?;
    Ok(())
}

/// Installs the shell precmd hook into ~/.zshrc or ~/.bashrc on first `aikey use`.
/// Returns the hook lines written, or `None` if no hook is needed / supported.
///
/// Skipped with `--no-hook` flag or when `AIKEY_NO_HOOK=1` is set.
pub fn ensure_shell_hook(no_hook: bool) -> Option<String> {
    if no_hook || std::env::var("AIKEY_NO_HOOK").map(|v| v == "1").unwrap_or(false) {
        return None;
    }

    let home = std::env::var("HOME").ok()?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    let is_zsh = shell.contains("zsh");
    let is_bash = shell.contains("bash");

    if !is_zsh && !is_bash {
        // Unknown shell — print manual instruction.
        return Some(format!(
            "  Add to your shell config: source ~/.aikey/active.env"
        ));
    }

    // Determine the rc file to check/write.
    let rc_candidates: Vec<String> = if is_zsh {
        vec![format!("{}/.zshrc", home)]
    } else {
        vec![
            format!("{}/.bashrc", home),
            format!("{}/.bash_profile", home),
        ]
    };

    // Check if hook is already installed in any candidate.
    let hook_marker = "# aikey shell hook";
    for rc in &rc_candidates {
        if let Ok(contents) = std::fs::read_to_string(rc) {
            if contents.contains(hook_marker) {
                return None; // already installed
            }
        }
    }

    // Write to the first candidate that exists or the first one if none exist.
    let rc_file = rc_candidates
        .iter()
        .find(|rc| std::path::Path::new(rc).exists())
        .or_else(|| rc_candidates.first())
        .cloned()?;

    let hook_block = if is_zsh {
        format!(
            "\n{}\n_aikey_precmd() {{ [[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env; }}\nprecmd_functions+=(_aikey_precmd)\n",
            hook_marker
        )
    } else {
        format!(
            "\n{}\nPROMPT_COMMAND='[[ -f ~/.aikey/active.env ]] && source ~/.aikey/active.env'\n",
            hook_marker
        )
    };

    // Prompt the user before writing.
    use std::io::{IsTerminal, Write};
    if io::stderr().is_terminal() {
        let shell_name = if is_zsh { "zsh" } else { "bash" };
        let hook_desc = if is_zsh { "precmd hook" } else { "PROMPT_COMMAND" };
        let rows = vec![
            format!("Shell:  {}", shell_name),
            format!("File:   {}", rc_file),
            format!("Add:    {} \u{2192} source ~/.aikey/active.env", hook_desc),
        ];
        crate::ui_frame::eprint_box("\u{2753}", "Install Shell Hook", &rows);
        eprint!("  Proceed? [Y/n]: ");
        io::stderr().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            match input.trim().to_lowercase().as_str() {
                "n" | "no" => {
                    return Some(format!("  Run: source ~/.aikey/active.env  (to apply once)"));
                }
                _ => {}
            }
        }
    }

    match std::fs::OpenOptions::new().append(true).open(&rc_file) {
        Ok(mut f) => {
            use std::io::Write as _;
            let _ = f.write_all(hook_block.as_bytes());
            Some(format!("  Shell hook installed in {}", rc_file))
        }
        Err(_) => Some(format!("  Could not write to {}. Run: source ~/.aikey/active.env", rc_file)),
    }
}

/// `aikey key use <alias-or-id>` / `aikey use <alias-or-id>`
///
/// Global mutex: deactivates ALL keys (personal + team), then activates the target.
/// Writes `~/.aikey/active.env` with provider env vars; installs shell hook on first use.
/// Accepts either virtual_key_id (exact) or alias (local_alias preferred, then server alias).
pub fn handle_key_use(
    alias_or_id: &str,
    no_hook: bool,
    provider_override: Option<&str>, // --provider flag or None
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy_port: u16 = crate::commands_proxy::proxy_port();

    // ── 1. Resolve key — try team keys first, then personal ──────────────────
    let team_entry = storage::get_virtual_key_cache(alias_or_id)?
        .or_else(|| storage::get_virtual_key_cache_by_alias(alias_or_id).ok().flatten());

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
        if entry.provider_key_ciphertext.is_none() {
            // Why: key material is NULL when the VK was synced but not yet delivered
            // (share_status=pending_claim). Auto-trigger a full snapshot sync (which
            // includes key material download) instead of forcing a separate command.
            eprintln!("  Key '{}' not yet delivered — syncing...", entry.alias);
            // Full sync needs the vault master password to decrypt/re-encrypt key material.
            // Try session cache first, then env var (for automation/testing).
            let pw = crate::session::try_get()
                .or_else(|| std::env::var("AK_TEST_PASSWORD").ok().map(secrecy::SecretString::new))
                .or_else(|| std::env::var("AIKEY_TEST_MASTER_PASSWORD").ok().map(secrecy::SecretString::new));
            if let Some(ref password) = pw {
                let _ = run_full_snapshot_sync(password);
            } else {
                // Cannot get password — fallback to metadata-only sync.
                sync_managed_key_metadata();
            }
            // Re-read the entry after sync.
            let refreshed = storage::get_virtual_key_cache(&entry.virtual_key_id)?
                .or_else(|| storage::get_virtual_key_cache_by_alias(alias_or_id).ok().flatten());
            if refreshed.as_ref().and_then(|e| e.provider_key_ciphertext.as_ref()).is_none() {
                return Err(format!(
                    "Key '{}' could not be delivered. The admin may need to re-issue the key, \
                     or try again with: aikey key sync",
                    entry.alias
                ).into());
            }
            // Re-call with the refreshed state.
            drop(refreshed);
            return handle_key_use(alias_or_id, no_hook, provider_override, json_mode);
        }
        let display = entry.local_alias.as_deref().unwrap_or(&entry.alias).to_string();
        let providers = if !entry.supported_providers.is_empty() {
            entry.supported_providers.clone()
        } else if !entry.provider_code.is_empty() {
            vec![entry.provider_code.clone()]
        } else {
            vec![]
        };
        ("team", entry.virtual_key_id.clone(), display, providers)
    } else {
        // Personal key — v1.0.2: use resolve_supported_providers.
        let exists = storage::entry_exists(alias_or_id).unwrap_or(false);
        if !exists {
            return Err(format!(
                "Key '{}' not found in team keys or personal keys.\n\
                 If this is a personal key, re-add it with: aikey add {}",
                alias_or_id, alias_or_id
            ).into());
        }
        let stored = storage::resolve_supported_providers(alias_or_id).unwrap_or_default();
        let providers = if !stored.is_empty() { stored } else {
            const KNOWN: &[&str] = &["anthropic", "openai", "google", "deepseek", "kimi"];
            KNOWN.iter().map(|s| s.to_string()).collect()
        };
        ("personal", alias_or_id.to_string(), alias_or_id.to_string(), providers)
    };

    if providers.is_empty() {
        return Err(format!(
            "Key '{}' has no supported providers — cannot write env vars.\n\
             Run 'aikey key sync' to refresh, or re-add with '--provider <code>'.",
            display_name
        ).into());
    }

    // ── 2. Provider-level primary promotion (v1.0.2) ─────────────────────────
    let target_providers: Vec<String> = if let Some(ov) = provider_override {
        if !ov.is_empty() {
            let code = ov.to_lowercase();
            if !providers.iter().any(|p| p.to_lowercase() == code) {
                return Err(format!("Key '{}' does not support provider '{}'. Supported: {}", display_name, code, providers.join(", ")).into());
            }
            vec![code]
        } else if providers.len() == 1 { providers.clone() }
        else {
            if !std::io::stdin().is_terminal() || json_mode {
                return Err(format!("This key supports multiple providers: {}. Please specify --provider or choose interactively.", providers.join(", ")).into());
            }
            use colored::Colorize;
            println!("Key '{}' supports multiple providers:", display_name.bold());
            for (i, p) in providers.iter().enumerate() { println!("  {}  {}", format!("[{}]", i + 1).dimmed(), p); }
            print!("Select provider(s) to set as Primary (comma-separated): ");
            io::stdout().flush()?;
            let mut input = String::new(); io::stdin().read_line(&mut input)?;
            let input = input.trim();
            if input.is_empty() { return Err("No provider selected. Use --provider <code> or select interactively.".into()); }
            let mut selected = Vec::new();
            for part in input.split(',').map(|s| s.trim()) {
                if let Ok(n) = part.parse::<usize>() {
                    if n >= 1 && n <= providers.len() { let p = providers[n-1].clone(); if !selected.contains(&p) { selected.push(p); } }
                }
            }
            if selected.is_empty() { return Err("Invalid selection. Use --provider <code>.".into()); }
            selected
        }
    } else if providers.len() == 1 { providers.clone() }
    else {
        if !std::io::stdin().is_terminal() || json_mode {
            return Err(format!("This key supports multiple providers: {}. Please specify --provider.", providers.join(", ")).into());
        }
        use colored::Colorize;
        println!("Key '{}' supports multiple providers:", display_name.bold());
        for (i, p) in providers.iter().enumerate() { println!("  {}  {}", format!("[{}]", i + 1).dimmed(), p); }
        print!("Select provider(s) to set as Primary (comma-separated): ");
        io::stdout().flush()?;
        let mut input = String::new(); io::stdin().read_line(&mut input)?;
        if input.trim().is_empty() { return Err("No provider selected.".into()); }
        let mut selected = Vec::new();
        for part in input.trim().split(',').map(|s| s.trim()) {
            if let Ok(n) = part.parse::<usize>() {
                if n >= 1 && n <= providers.len() { let p = providers[n-1].clone(); if !selected.contains(&p) { selected.push(p); } }
            }
        }
        if selected.is_empty() { return Err("Invalid selection.".into()); }
        selected
    };

    // Write provider bindings.
    for provider in &target_providers {
        storage::set_provider_binding(crate::profile_activation::DEFAULT_PROFILE, provider, key_type, &key_ref)?;
    }

    // ── 3. Refresh active.env from ALL provider bindings ─────────────────────
    let refresh = crate::profile_activation::refresh_implicit_profile_activation()
        .map_err(|e| format!("Failed to refresh activation: {}", e))?;

    // ── 6. Shell hook (one-time, first use) ───────────────────────────────────
    let hook_msg = if !json_mode { ensure_shell_hook(no_hook) } else { None };

    // ── 6b. Auto-configure / unconfigure third-party CLI tools ─────────────
    if !json_mode {
        let has_kimi = providers.iter().any(|p| {
            let c = p.to_lowercase();
            c == "kimi" || c == "moonshot"
        });
        if has_kimi {
            let token_value = if key_type == "team" {
                format!("aikey_vk_{}", key_ref)
            } else {
                format!("aikey_personal_{}", key_ref)
            };
            configure_kimi_cli(&token_value, proxy_port);
        } else {
            // Switching away from kimi — restore Kimi CLI to standalone mode.
            unconfigure_kimi_cli();
        }
    }

    // ── 7. Output ─────────────────────────────────────────────────────────────
    let primary_provider = providers.first().map(String::as_str).unwrap_or("unknown");
    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "key_type": key_type,
            "key_ref": key_ref,
            "display_name": display_name,
            "providers": providers,
            "active_env_written": true,
        }));
    } else {
        use colored::Colorize;

        // Collect env var lines.
        let mut env_lines: Vec<String> = Vec::new();
        for provider in &providers {
            if let Some((api_key_var, base_url_var)) = provider_env_vars(provider) {
                let token_value = if key_type == "team" {
                    format!("aikey_vk_{}", key_ref)
                } else {
                    format!("aikey_personal_{}", key_ref)
                };
                let base_url = format!("http://127.0.0.1:{}/{}", proxy_port, provider_proxy_prefix(provider));
                env_lines.push(format!("{:<24} = {}", api_key_var, token_value));
                env_lines.push(format!("{:<24} = {}", base_url_var, base_url));
            }
        }

        let proxy_url = format!("http://127.0.0.1:{}/{}", proxy_port, provider_proxy_prefix(primary_provider));

        let status = if hook_msg.is_some() {
            "\u{2192} Shell hook just installed. Open a new terminal or: source ~/.aikey/active.env"
        } else {
            "\u{2713} Env vars applied (shell hook active)"
        };

        let mut rows: Vec<String> = Vec::new();
        for line in &env_lines {
            rows.push(line.clone());
        }
        rows.push(String::new()); // blank separator
        rows.push(status.to_string());
        rows.push(format!("\u{2192} Proxy: {}", proxy_url));

        let title = format!("'{}' [{}] is now active", display_name, primary_provider);
        crate::ui_frame::print_box("\u{2705}", &title, &rows);
        println!();
    }
    Ok(())
}

/// `aikey key alias <old-alias> <new-alias>`
///
/// Sets a local display name for a team key without touching the server alias.
/// The server alias is always preserved and shown alongside the local alias in `aikey list`.
pub fn handle_key_alias(old_alias: &str, new_alias: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Resolve by virtual_key_id first, then alias (local or server).
    let entry = storage::get_virtual_key_cache(old_alias)?
        .or_else(|| storage::get_virtual_key_cache_by_alias(old_alias).ok().flatten())
        .ok_or_else(|| format!(
            "Key '{}' not found in local cache. Run 'aikey key sync' first.",
            old_alias
        ))?;

    storage::set_virtual_key_local_alias(&entry.virtual_key_id, Some(new_alias))?;

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "virtual_key_id": entry.virtual_key_id,
            "server_alias": entry.alias,
            "local_alias": new_alias,
        }));
    } else {
        println!("{} Renamed {} → {}  {}",
            "✓".green().bold(),
            format!("'{}'", old_alias).dimmed(),
            format!("'{}'", new_alias).bold(),
            format!("(server alias: {})", entry.alias).dimmed());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derives the vault AES key from the master password.
/// Uses the same salt + KDF parameters stored in the vault DB.
fn derive_vault_key(
    password: &SecretString,
) -> Result<[u8; crypto::KEY_SIZE], String> {
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

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
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
