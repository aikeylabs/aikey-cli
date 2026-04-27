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
fn login_throttle_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(std::path::PathBuf::from(home).join(".aikey").join(".login_throttle.json"))
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
                // No cached password — prompt inline with star echo.
                eprintln!("    Restart proxy to apply.");
                match crate::prompt_hidden("    \u{1F512} Enter Master Password: ") {
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

    // --- Throttle: suppress rapid re-triggers of the email flow ---
    // Why: users who don't see an activation email often re-run `aikey login`
    // within seconds. Each re-run creates a fresh session and (when the user
    // hits "Send Login Link") another email — inflating the anti-spam rate
    // at QQ/Gmail. We block the second attempt within `LOGIN_THROTTLE_SECS`
    // unless --resend is passed. The file is advisory-only; concurrent
    // writes and missing files silently fall through.
    if !flag_resend {
        if let Some(last_started) = read_login_throttle() {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            if now > 0 && now >= last_started && now - last_started < LOGIN_THROTTLE_SECS {
                let elapsed = now - last_started;
                let remaining = LOGIN_THROTTLE_SECS - elapsed;
                if !json_mode {
                    eprintln!();
                    eprintln!("  {}", format!("A login email was just sent ({}s ago).", elapsed).yellow());
                    eprintln!("  • Check your inbox — and your spam folder.");
                    eprintln!("  • Add {} to your whitelist to avoid future filtering.", "invite@aikeylabs.com".bold());
                    eprintln!("  • To force a new email, wait {}s or run: {}", remaining, "aikey login --resend".bold());
                    eprintln!();
                }
                return Ok(());
            }
        }
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
        println!("    Run {} to view your team keys.", "'aikey list'".bold());
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
        let msg = e.to_string();
        if msg.contains("login expired") {
            format!(
                "{}. Run 'aikey login' to re-authenticate.",
                msg
            )
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
        Some(other) => Err(format!(
            "Unknown page '{}'. Available: overview, keys, vault, account, usage, import, referrals",
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
pub fn handle_browse(page: Option<&str>, port: Option<u16>, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Validate the page name at the CLI boundary. Doing it here (before
    // the local/JWT branch) means typos fail fast with a clear error
    // regardless of which mode the user is in — instead of silently
    // opening the overview page.
    let alias = web_page_alias(page)?;

    // Local-user mode: open console directly without JWT.
    // Why: personal edition has no login flow — LocalIdentityMiddleware handles
    // auth server-side, and the SPA is served with authMode:"local_bypass".
    if port.is_none() {
        if let Some(url) = try_local_browse_url(alias) {
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
    } else {
        println!("Opening User Console...");
        println!("  {}{}", base_url, path);
    }

    open_url_silently(&url);
    Ok(())
}

/// `aikey master [page] [--port PORT]` — open Master Console in the default browser.
///
/// Resolves the control panel URL from install-state.json or the stored
/// platform account, then opens `/master/<page>` in the browser.
/// Master console always requires admin login (handled by the web frontend).
pub fn handle_master_browse(page: Option<&str>, url_override: Option<&str>, port: Option<u16>, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let path = match page {
        Some("seats")                          => "/master/orgs/default/seats",
        Some("keys" | "virtual-keys")          => "/master/orgs/default/virtual-keys",
        Some("bindings")                       => "/master/orgs/default/bindings",
        Some("providers" | "provider-accounts") => "/master/orgs/default/provider-accounts",
        Some("events" | "control-events")      => "/master/orgs/default/control-events",
        Some("usage" | "usage-ledger")         => "/master/orgs/default/usage-ledger",
        Some("dashboard") | None               => "/master/dashboard",
        Some(other) => {
            return Err(format!(
                "Unknown page '{}'. Available: dashboard, seats, virtual-keys, bindings, providers, events, usage",
                other
            ).into());
        }
    };

    // Resolve base URL: --url > --port > install-state > stored account > interactive prompt.
    let base_url = if let Some(u) = url_override {
        u.to_string()
    } else if let Some(p) = port {
        format!("http://localhost:{}", p)
    } else if let Some(url) = try_local_control_url() {
        url
    } else if let Ok(Some(acc)) = storage::get_platform_account() {
        acc.control_url.clone()
    } else if !json_mode && std::io::stdin().is_terminal() {
        // Interactive prompt with a sensible default
        use std::io::Write;
        let default = "http://localhost:8090";
        print!("Control Panel URL [{}]: ", default);
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if input.is_empty() { default.to_string() } else { input.to_string() }
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

/// Returns the `control_panel_url` from install-state.json if available.
fn try_local_control_url() -> Option<String> {
    let home = dirs::home_dir()?;
    let state_path = home.join(".aikey").join("install-state.json");
    let content = std::fs::read_to_string(&state_path).ok()?;
    let state: serde_json::Value = serde_json::from_str(&content).ok()?;
    let url = state.get("control_panel_url")?.as_str()?;
    if url.is_empty() { None } else { Some(url.to_string()) }
}

/// Try to resolve a local-user browse URL from install-state.json.
///
/// Returns `Some(full_url)` if `control_plane_mode == "local"` and
/// `control_panel_url` is set; `None` otherwise (falls through to JWT flow).
/// Build a local-mode browse URL, taking a pre-validated alias
/// (produced by `web_page_alias`). Returning `None` means "not in
/// local/trial mode — caller should fall back to the JWT path".
fn try_local_browse_url(alias: &str) -> Option<String> {
    let home = dirs::home_dir()?;
    let state_path = home.join(".aikey").join("install-state.json");
    let content = std::fs::read_to_string(&state_path).ok()?;
    let state: serde_json::Value = serde_json::from_str(&content).ok()?;

    let mode = state.get("control_plane_mode")?.as_str()?;
    // Why: "local" and "trial" both run the control panel on the same machine.
    // Open the browser directly and let the web frontend handle auth — the CLI
    // should not gatekeep when the server is local.
    if mode != "local" && mode != "trial" {
        return None;
    }

    let base_url = state.get("control_panel_url")?.as_str()?;
    if base_url.is_empty() {
        return None;
    }

    // Both branches go through `/go/<alias>` so the web router owns
    // every real route. The alias is already validated by the caller.
    Some(format!("{}/go/{}", base_url.trim_end_matches('/'), alias))
}

/// Determine the base URL for `aikey web`.
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

// ---------------------------------------------------------------------------
// `aikey status` — combined overview dashboard
// ---------------------------------------------------------------------------

pub fn handle_status_overview(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;

    let vault_exists = storage::get_vault_path().map(|p| p.exists()).unwrap_or(false);
    let account = storage::get_platform_account().ok().flatten();

    // Collect key counts.
    let personal_count = if vault_exists {
        storage::list_entries().map(|v| v.len()).unwrap_or(0)
    } else {
        0
    };
    let team_keys = storage::list_virtual_key_cache().unwrap_or_default();
    let active_team = team_keys.iter().filter(|k| k.local_state == "active").count();
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
        let active_json = active_cfg.as_ref().map(|cfg| serde_json::json!({
            "key_type": cfg.key_type,
            "key_ref":  cfg.key_ref,
            "providers": cfg.providers,
        }));
        crate::json_output::print_json(serde_json::json!({
            "gateway": {
                "running": crate::commands_proxy::is_proxy_running(),
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
    rows.push(format!("\u{1F6F0}  {}", "Gateway".bold()));
    for line in crate::commands_proxy::status_rows() {
        rows.push(format!("  {}", line));
    }
    rows.push(String::new());

    // ── Login ───────────────────────────────────────────────────────────────
    rows.push(format!("\u{1F464} {}", "Login".bold()));
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
    rows.push(format!("\u{1F511} {}", "Keys".bold()));
    rows.push(format!("  personal:  {}", personal_count));
    rows.push(format!("  team:      {} total, {} active", team_total, active_team));
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
                            accts.into_iter().find(|a| a.provider_account_id == cfg.key_ref)
                                .and_then(|a| a.display_identity
                                    .filter(|s| !s.is_empty())
                                    .or(a.external_id))
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
            rows.push(format!("  active:    {} {} {}",
                label.bold(),
                format!("({})", type_label).dimmed(),
                format!("\u{2192} {}", prov_str).cyan()));
        }
        None => {
            rows.push(format!("  active:    {}", "none".dimmed()));
        }
    }
    rows.push(String::new());

    // ── Protocols ───────────────────────────────────────────────────────────
    rows.push(format!("\u{1F50C} {}", "Protocols".bold()));
    if providers.is_empty() {
        rows.push(format!("  {}", "no protocols configured".dimmed()));
        rows.push("  hint:    add a key with `aikey add <alias> --provider <code>`".to_string());
    } else {
        rows.push(format!("  {}",
            providers.iter().cloned().collect::<Vec<_>>().join(", ")));
    }

    crate::ui_frame::print_box("\u{1F4CA}", "Status", &rows);

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
                if active_cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey && active_cfg.key_ref == entry.virtual_key_id {
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
                        if cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey && cfg.key_ref == entry.virtual_key_id {
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
                if active_cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey && active_cfg.key_ref == entry.virtual_key_id {
                    let display = entry.local_alias.as_deref().unwrap_or(entry.alias.as_str());
                    let _ = write_active_env("team", &entry.virtual_key_id, display, &entry.supported_providers, crate::commands_proxy::proxy_port());
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
    /// Data-model canonical code for vault queries and provider bindings.
    /// Aliases like "claude" normalize to "anthropic"; "moonshot" shares "kimi".
    pub canonical_code: &'static str,
    /// URL path segment registered in the proxy. Must include `/v1` suffix
    /// for providers whose upstream has no `/v1` prefix AND whose SDK doesn't
    /// auto-prepend /v1 (kimi/moonshot use OpenAI-compatible SDKs that treat
    /// base_url as "already has /v1").
    pub proxy_path: &'static str,
    /// Provider-specific env var names written by `aikey use`/`aikey activate`.
    /// Kept distinct per brand even when canonical_code collides (e.g. moonshot
    /// has MOONSHOT_API_KEY independent from kimi's KIMI_API_KEY).
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
        // `canonical_code` historically meant "protocol family" — the code
        // that multiple brand-distinct entries (kimi + moonshot) share at
        // the vault-query grouping level. The registry's `family` field
        // captures exactly this; default-to-self for entries without one.
        canonical_code: entry.family,
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
            AddAction::Skipped  => "skipped",
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
        if lower.is_empty() { continue; }
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
    /// OAuth account — renames `provider_accounts.display_identity` (no
    /// UNIQUE; two accounts may legitimately share a label).
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
    ///   - oauth → new display_identity
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
            let conn = storage::open_connection()
                .map_err(|e| format!("open vault: {}", e))?;

            // Existence check on old
            let old_exists = conn.query_row(
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
            let new_exists = conn.query_row(
                "SELECT COUNT(*) FROM entries WHERE alias = ?1",
                rusqlite::params![&validated],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .map_err(|e| format!("check new alias '{}': {}", validated, e))?;
            if new_exists {
                return Err(format!("alias '{}' already exists", validated));
            }

            let n = conn.execute(
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
            let new_trimmed = new_value.trim().to_string();
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
            let new_trimmed = new_value.trim().to_string();
            // Existence check for precise 404
            match storage::get_provider_account(id)
                .map_err(|e| format!("get_provider_account '{}': {}", id, e))?
            {
                Some(_) => {}
                None => return Err(format!("provider_account_id '{}' not found", id)),
            }
            let conn = storage::open_connection()
                .map_err(|e| format!("open vault: {}", e))?;
            let n = conn.execute(
                "UPDATE provider_accounts SET display_identity = ?1 WHERE provider_account_id = ?2",
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
/// Moonshot/Kimi are intentionally left distinct here — they have
/// different env var tuples (MOONSHOT_API_KEY vs KIMI_API_KEY) and
/// different proxy paths, so their routes don't collide and
/// `oauth_provider_to_canonical` correctly passes both through unchanged.
pub(crate) fn write_bindings_canonical(
    providers: &[String],
    key_type_str: &str,
    key_ref: &str,
) -> Result<(), String> {
    for raw_provider in providers {
        let raw = raw_provider.to_lowercase();
        let canonical = oauth_provider_to_canonical(&raw);
        if canonical != raw.as_str() {
            // Best-effort cleanup of any stale non-canonical row. Silent
            // on error — worst case the stale row lingers until the next
            // activation UPSERTs over it via the canonical primary key.
            let _ = storage::remove_provider_binding(
                crate::profile_activation::DEFAULT_PROFILE,
                &raw,
            );
        }
        storage::set_provider_binding(
            crate::profile_activation::DEFAULT_PROFILE,
            canonical,
            key_type_str,
            key_ref,
        )
        .map_err(|e| format!("set_provider_binding: {}", e))?;
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

    if active_cfg.key_type != crate::credential_type::CredentialType::PersonalApiKey {
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

mod shell_integration;
pub use shell_integration::*;

/// Resolve an OAuth account by `provider_account_id` OR `display_identity`
/// (email). Returns `None` when no match — caller treats that as "not
/// OAuth, try next lookup kind".
///
/// Case-insensitive on both keys: account_id is a UUID-ish random string
/// so case doesn't practically matter, but emails are routinely typed
/// with varying case. Mirrors the lookup in
/// `connectivity::targets::targets_from_alias` so behaviour stays
/// symmetric between `aikey test` and `aikey use`.
fn resolve_oauth_account(alias_or_id: &str) -> Option<storage::ProviderAccountInfo> {
    let accounts = storage::list_provider_accounts_readonly().ok()?;
    accounts.into_iter().find(|a| {
        a.provider_account_id.eq_ignore_ascii_case(alias_or_id)
            || a.display_identity.as_deref()
                .map(|d| d.eq_ignore_ascii_case(alias_or_id))
                .unwrap_or(false)
    })
}

/// `aikey key use <alias-or-id>` / `aikey use <alias-or-id>`
///
/// Global mutex: deactivates ALL keys (personal + team), then activates the target.
/// Writes `~/.aikey/active.env` with provider env vars; installs shell hook on first use.
/// Accepts virtual_key_id, alias (local_alias preferred, then server alias),
/// or OAuth account (by provider_account_id or display_identity / email).
pub fn handle_key_use(
    alias_or_id: &str,
    no_hook: bool,
    provider_override: Option<&str>, // --provider flag or None
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy_port: u16 = crate::commands_proxy::proxy_port();

    // ── 1. Resolve key — try team keys, then personal, then OAuth ────────────
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
        (crate::credential_type::CredentialType::ManagedVirtualKey, entry.virtual_key_id.clone(), display, providers)
    } else if storage::entry_exists(alias_or_id).unwrap_or(false) {
        // Personal key — v1.0.2: use resolve_supported_providers.
        let stored = storage::resolve_supported_providers(alias_or_id).unwrap_or_default();
        let providers = if !stored.is_empty() { stored } else {
            const KNOWN: &[&str] = &["anthropic", "openai", "google", "deepseek", "kimi"];
            KNOWN.iter().map(|s| s.to_string()).collect()
        };
        (crate::credential_type::CredentialType::PersonalApiKey, alias_or_id.to_string(), alias_or_id.to_string(), providers)
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
                acct.display_identity.as_deref().unwrap_or(&acct.provider_account_id),
                acct.status,
                acct.provider,
            ).into());
        }
        let display = acct.display_identity.clone()
            .unwrap_or_else(|| acct.provider_account_id.clone());
        // OAuth accounts are single-provider by definition (Claude OAuth
        // → anthropic; Codex OAuth → openai; etc.). `provider_override`
        // would be redundant here; we carry the provider through the
        // normal binding flow for uniformity.
        let providers = vec![acct.provider.clone()];
        (crate::credential_type::CredentialType::PersonalOAuthAccount, acct.provider_account_id.clone(), display, providers)
    } else {
        return Err(format!(
            "Key '{}' not found in team keys, personal keys, or OAuth accounts.\n\
             Hints:\n\
             - run `aikey list` to see all known aliases / accounts\n\
             - for team keys, run `aikey key sync` if the cache may be stale\n\
             - for personal keys, re-add with: aikey add {}",
            alias_or_id, alias_or_id
        ).into());
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
            print!("Select protocol(s) to set as Primary (comma-separated): ");
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
        print!("Select protocol(s) to set as Primary (comma-separated): ");
        io::stdout().flush()?;
        let mut input = String::new(); io::stdin().read_line(&mut input)?;
        if input.trim().is_empty() { return Err("No protocol selected.".into()); }
        let mut selected = Vec::new();
        for part in input.trim().split(',').map(|s| s.trim()) {
            if let Ok(n) = part.parse::<usize>() {
                if n >= 1 && n <= providers.len() { let p = providers[n-1].clone(); if !selected.contains(&p) { selected.push(p); } }
            }
        }
        if selected.is_empty() { return Err("Invalid selection.".into()); }
        selected
    };

    // Write provider bindings via the shared core helper (normalizes
    // provider_code to canonical form + cleans any stale alias rows).
    write_bindings_canonical(&target_providers, key_type.as_str(), &key_ref)?;

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
            // Token-agnostic: writes scaffold once; token comes from KIMI_API_KEY env var.
            configure_kimi_cli(proxy_port);
        } else {
            // Switching away from kimi — restore Kimi CLI to standalone mode.
            unconfigure_kimi_cli();
        }

        // Codex CLI: inject openai_base_url when openai provider is active.
        // Why: Codex v0.118+ deprecated OPENAI_BASE_URL env var and reads
        // openai_base_url from ~/.codex/config.toml instead.
        let has_openai = providers.iter().any(|p| {
            let c = p.to_lowercase();
            c == "openai" || c == "gpt" || c == "chatgpt"
        });
        if has_openai {
            configure_codex_cli(proxy_port);
        } else {
            unconfigure_codex_cli();
        }
    }

    // ── 5. Output ─────────────────────────────────────────────────────────────
    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "key_type": key_type,
            "key_ref": key_ref,
            "display_name": display_name,
            "promoted_providers": target_providers,
            "all_active_providers": refresh.activated_providers,
            "active_env_written": true,
        }));
    } else {
        // Stage 4 (active-state cross-shell sync, 2026-04-27): the previous
        // "Env vars applied" message was a half-truth. `aikey` is a child
        // process — it cannot mutate the parent shell's env directly. The
        // precmd hook picks up the new active.env on the user's next prompt
        // (free, unconditional), but if they want to use the new key in
        // *this* prompt they can `source` the file. State that plainly.
        let status = if hook_msg.is_some() {
            "\u{2192} Shell hook just installed. Open a new terminal or: source ~/.aikey/active.env"
        } else {
            "\u{2713} Active key updated. Next prompt picks it up automatically.\n     To apply right now: source ~/.aikey/active.env"
        };

        let mut rows: Vec<String> = Vec::new();
        for b in &refresh.bindings {
            if let Some((api_key_var, _)) = provider_env_vars(&b.provider_code) {
                let display_ref = resolve_binding_display_name(b.key_source_type.as_str(), &b.key_source_ref);
                let is_changed = target_providers.contains(&b.provider_code);
                let arrow_ref = format!("\u{2192} {}", display_ref);
                let arrow_padded = format!("{:<22}", arrow_ref);
                let arrow_col = if is_changed { format!("\x1b[32m{}\x1b[0m", arrow_padded) } else { arrow_padded };
                rows.push(format!("  {:<14} {} \x1b[90m[{}]\x1b[0m",
                    b.provider_code, arrow_col, b.key_source_type));
                let _ = api_key_var;
            }
        }
        rows.push(String::new());
        rows.push(status.to_string());

        let title = format!("Set '{}' as Primary for {}", display_name, target_providers.join(", "));
        crate::ui_frame::print_box("\u{1F7E2}", &title, &rows);
        println!();
    }

    // Auto-install the Claude Code status-line integration when the user
    // promotes a key that covers the anthropic provider.  Idempotent —
    // `ensure_claude_statusline_installed` is safe to call every time.
    // See 费用小票-实施方案.md §5.6 for the trigger matrix.
    if target_providers.iter().any(|p| p.eq_ignore_ascii_case("anthropic")) {
        crate::commands_statusline::ensure_claude_statusline_installed();
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
pub fn handle_key_alias(old_alias: &str, new_alias: &str, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Decide target. Personal check is fast (single query); only fall
    // through to team resolution if the alias isn't personal.
    let is_personal = storage::list_entries().ok()
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
                    obj.insert("virtual_key_id".into(), serde_json::json!(entry.virtual_key_id));
                    obj.insert("server_alias".into(), serde_json::json!(entry.alias));
                    obj.insert("local_alias".into(), serde_json::json!(outcome.new_value));
                }
            }
        }
        crate::json_output::print_json(body);
    } else {
        let suffix = match target {
            RenameTarget::Team => {
                storage::get_virtual_key_cache(&outcome.id).ok().flatten()
                    .map(|e| format!(" (server alias: {})", e.alias))
                    .unwrap_or_default()
            }
            _ => String::new(),
        };
        println!("{} Renamed {} → {}  {}",
            "✓".green().bold(),
            format!("'{}'", old_alias).dimmed(),
            format!("'{}'", outcome.new_value).bold(),
            suffix.dimmed());
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
    fn env_vars_kimi_and_moonshot_are_distinct() {
        // IMPORTANT: kimi and moonshot have SEPARATE env var pairs here, even though
        // main.rs::canonical_provider remaps moonshot→kimi for URL routing.
        // A future dedup must preserve this asymmetry or explicitly change the contract.
        assert_eq!(provider_env_vars("kimi"),
            Some(("KIMI_API_KEY", "KIMI_BASE_URL")));
        assert_eq!(provider_env_vars("moonshot"),
            Some(("MOONSHOT_API_KEY", "MOONSHOT_BASE_URL")));
    }

    #[test]
    fn env_vars_deepseek() {
        assert_eq!(provider_env_vars("deepseek"),
            Some(("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL")));
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
            "anthropic", "claude",
            "openai", "codex", "gpt", "chatgpt",
            "google", "gemini",
            "kimi", "moonshot", "deepseek",
        ] {
            assert!(provider_env_vars(code).is_some(),
                "provider_env_vars returned None for known code '{}'", code);
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
            "anthropic", "claude",
            "openai", "codex", "gpt", "chatgpt",
            "google", "gemini",
            "kimi", "moonshot", "deepseek",
        ] {
            let info = super::provider_info(code).unwrap();
            assert_eq!(provider_env_vars(code), Some(info.env_vars),
                "env_vars mismatch for '{}'", code);
            assert_eq!(provider_proxy_prefix(code), info.proxy_path,
                "proxy_path mismatch for '{}'", code);
        }
    }

    #[test]
    fn provider_info_aliases_point_to_same_canonical() {
        use super::provider_info;
        // anthropic/claude
        assert_eq!(provider_info("anthropic").unwrap().canonical_code,
                   provider_info("claude").unwrap().canonical_code);
        // openai family (codex, gpt, chatgpt)
        let openai = provider_info("openai").unwrap().canonical_code;
        for alias in &["codex", "gpt", "chatgpt"] {
            assert_eq!(provider_info(alias).unwrap().canonical_code, openai,
                "alias '{}' should canonicalize to openai", alias);
        }
        // google/gemini
        assert_eq!(provider_info("google").unwrap().canonical_code,
                   provider_info("gemini").unwrap().canonical_code);
        // kimi/moonshot (moonshot canonicalizes to kimi)
        assert_eq!(provider_info("kimi").unwrap().canonical_code,
                   provider_info("moonshot").unwrap().canonical_code);
    }

    #[test]
    fn provider_extra_env_vars_kimi_has_model_name_and_context_size() {
        // Minimal-scaffold Kimi requires KIMI_MODEL_NAME so Kimi's empty-model
        // fallback can populate the model. Max context size is a convenience
        // default matching kimi-k2.5 / moonshot-v1-128k (both 131072).
        let kimi = provider_extra_env_vars("kimi");
        assert!(kimi.iter().any(|(k, _)| *k == "KIMI_MODEL_NAME"));
        assert!(kimi.iter().any(|(k, _)| *k == "KIMI_MODEL_MAX_CONTEXT_SIZE"));
        // Alias moonshot must return same extras.
        assert_eq!(kimi, provider_extra_env_vars("moonshot"));
    }

    #[test]
    fn provider_extra_env_vars_returns_empty_for_non_kimi() {
        for p in &["anthropic", "openai", "google", "deepseek"] {
            assert!(provider_extra_env_vars(p).is_empty(), "{} must have no extras", p);
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
        unsafe { std::env::set_var("AK_VAULT_PATH", db_path.to_str().unwrap()); }
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
    fn normalize_providers_leaves_moonshot_distinct_from_kimi() {
        // oauth_provider_to_canonical deliberately does NOT map moonshot → kimi
        // (their env vars and proxy paths differ even though canonical_code
        // in provider_info says they're the same family).
        assert_eq!(
            normalize_providers(&["moonshot".to_string(), "kimi".to_string()]),
            vec!["moonshot".to_string(), "kimi".to_string()],
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
        apply_add_core_on_conn(&conn, &key, "dup", b"s1", &["openai".to_string()], None, OnConflict::Error).unwrap();

        let err = apply_add_core_on_conn(&conn, &key, "dup", b"s2", &[], None, OnConflict::Error).unwrap_err();
        assert!(err.contains("already exists"), "err was: {}", err);
    }

    #[test]
    fn apply_add_core_on_conflict_replace_overwrites() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();

        apply_add_core_on_conn(&conn, &key, "rep", b"s1", &["openai".to_string()], None, OnConflict::Error).unwrap();
        let outcome = apply_add_core_on_conn(
            &conn, &key, "rep", b"s2", &["anthropic".to_string()], None, OnConflict::Replace,
        ).expect("replace ok");
        assert_eq!(outcome.action, AddAction::Replaced);
        assert_eq!(outcome.primary_provider.as_deref(), Some("anthropic"));
    }

    #[test]
    fn apply_add_core_on_conflict_skip_noops() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();

        apply_add_core_on_conn(&conn, &key, "keep", b"s1", &["openai".to_string()], None, OnConflict::Error).unwrap();
        let outcome = apply_add_core_on_conn(&conn, &key, "keep", b"s2", &[], None, OnConflict::Skip).expect("skip ok");
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
            &conn, &key, "with-url", b"s",
            &["openai".to_string()],
            Some("https://api.example.com/v1"),
            OnConflict::Error,
        )
        .unwrap();
        let metas = storage::list_entries_with_metadata().unwrap();
        let entry = metas.iter().find(|m| m.alias == "with-url").unwrap();
        assert_eq!(entry.base_url.as_deref(), Some("https://api.example.com/v1"));
    }

    #[test]
    fn apply_add_core_rejects_invalid_alias() {
        let (_dir, _lock) = setup_vault();
        let conn = storage::open_connection().expect("open");
        let key = dummy_vault_key();
        let err = apply_add_core_on_conn(
            &conn, &key, "  ", b"s", &[], None, OnConflict::Error,
        )
        .unwrap_err();
        assert!(err.contains("empty"), "err was: {}", err);

        let err2 = apply_add_core_on_conn(
            &conn, &key, "bad\nalias", b"s", &[], None, OnConflict::Error,
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
        apply_add_core_on_conn(&conn, &key, "old-name", b"s", &[], None, OnConflict::Error).unwrap();
        drop(conn);

        let outcome = apply_rename_core(RenameTarget::Personal, "old-name", "new-name")
            .expect("rename ok");
        assert_eq!(outcome.target, "personal");
        assert_eq!(outcome.id, "new-name");
        assert_eq!(outcome.old_id, "old-name");
        assert!(!storage::entry_exists("old-name").unwrap());
        assert!(storage::entry_exists("new-name").unwrap());
    }

    #[test]
    fn apply_rename_core_personal_not_found_errors() {
        let (_dir, _lock) = setup_vault();
        let err = apply_rename_core(RenameTarget::Personal, "ghost", "something")
            .unwrap_err();
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
        write_bindings_canonical(&["claude".to_string()], "personal_oauth_account", "acct-xyz")
            .expect("write ok");
        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        let row = bindings.iter().find(|b| b.provider_code == "anthropic").expect("anthropic row");
        assert_eq!(row.key_source_ref, "acct-xyz");
        // The raw "claude" provider_code row must NOT exist.
        assert!(bindings.iter().all(|b| b.provider_code != "claude"));
    }

    #[test]
    fn write_bindings_canonical_cleans_stale_alias_row() {
        let (_dir, _lock) = setup_vault();
        // Simulate a pre-fix CLI version that wrote a raw "codex" binding.
        storage::set_provider_binding("default", "codex", "personal_oauth_account", "stale-uuid").unwrap();
        assert!(storage::list_provider_bindings_readonly("default").unwrap()
            .iter().any(|b| b.provider_code == "codex"));

        // Now write canonical via the shared helper.
        write_bindings_canonical(&["codex".to_string()], "personal_oauth_account", "fresh-uuid").unwrap();

        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        // Stale raw-alias row must be gone.
        assert!(bindings.iter().all(|b| b.provider_code != "codex"),
            "expected no 'codex' row after canonical write, got: {:?}", bindings);
        // Canonical row must exist with the new ref.
        let row = bindings.iter().find(|b| b.provider_code == "openai").expect("openai row");
        assert_eq!(row.key_source_ref, "fresh-uuid");
    }

    #[test]
    fn write_bindings_canonical_leaves_moonshot_kimi_distinct() {
        let (_dir, _lock) = setup_vault();
        write_bindings_canonical(&["moonshot".to_string()], "personal", "k-moonshot").unwrap();
        write_bindings_canonical(&["kimi".to_string()], "personal", "k-kimi").unwrap();
        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        assert!(bindings.iter().any(|b| b.provider_code == "moonshot"));
        assert!(bindings.iter().any(|b| b.provider_code == "kimi"));
    }

    #[test]
    fn write_bindings_canonical_upserts_same_canonical() {
        let (_dir, _lock) = setup_vault();
        write_bindings_canonical(&["anthropic".to_string()], "personal", "first").unwrap();
        write_bindings_canonical(&["anthropic".to_string()], "personal", "second").unwrap();
        let bindings = storage::list_provider_bindings_readonly("default").unwrap();
        let anthropic_rows: Vec<_> = bindings.iter().filter(|b| b.provider_code == "anthropic").collect();
        assert_eq!(anthropic_rows.len(), 1, "UPSERT should leave exactly one row per canonical");
        assert_eq!(anthropic_rows[0].key_source_ref, "second");
    }
}
