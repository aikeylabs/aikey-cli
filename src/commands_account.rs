//! `aikey account` and team key command handlers.
//!
//! Covers:
//!  - `aikey account login` / `aikey account status` / `aikey account logout`
//!  - `aikey key list`  — show cached + server keys
//!  - `aikey key accept [id]` — download & claim a pending key (re-encrypts locally)
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
///   1. CLI flags (`--url`, `--token`)
///   2. Environment variable `AIKEY_CONTROL_URL`
///   3. Interactive prompt (suppressed in `--json` mode)
pub fn handle_login(
    json_mode: bool,
    flag_url: Option<String>,
    flag_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let default_url = std::env::var("AIKEY_CONTROL_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());

    let control_url = if let Some(u) = flag_url {
        u
    } else if json_mode {
        std::env::var("AIKEY_CONTROL_URL")
            .map_err(|_| "AIKEY_CONTROL_URL env var required in non-interactive mode (or use --url)")?
    } else {
        print!("Control service URL [{}]: ", default_url);
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

    let login_url = format!(
        "{}/auth/cli/login?s={}&d={}",
        control_url.trim_end_matches('/'),
        session.login_session_id,
        session.device_code,
    );

    if !json_mode {
        println!("Opening browser for login…");
        println!("If your browser did not open, visit:");
        println!("  {}", login_url);
        println!();
        println!("Enter your email in the browser, click 'Send Login Link',");
        println!("then check your email and click the activation link.");
        println!("Waiting… (session expires in {}s)", session.expires_in_seconds);
        println!();
        println!("Tip: if polling times out, copy the one-time token from");
        println!("     the activation page and re-run with --token SESSION_ID:LOGIN_TOKEN");
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
                eprintln!("Login session expired.");
                eprint!("Paste the one-time login token (or press Enter to cancel): ");
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

    storage::save_oauth_session(
        &account.account_id,
        &account.email,
        &access_token,
        &refresh_token,
        token_expires_at,
        control_url,
    )?;

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "account_id": account.account_id,
            "email": account.email,
        }));
    } else {
        println!("Logged in as {} ({})", account.email, account.account_id);
        println!("Run 'aikey key list' to view your team keys.");
    }
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
                println!("Control URL  : {}", acc.control_url);
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
/// Reads the local JWT token, appends it as a URL fragment so the web app can
/// pick it up from `location.hash` without the token ever hitting server logs.
///
/// When `control_url` points to localhost, automatically probes common dev-server
/// ports (3000, 5173) and prefers the first one that responds.  This lets
/// `aikey browse` work in both dev and production without extra flags.
pub fn handle_browse(page: Option<&str>, port: Option<u16>, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
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

/// `aikey account logout`
/// `aikey whoami` — compact identity card: login session + active key + vault state.
pub fn handle_whoami(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let account = storage::get_platform_account().ok().flatten();
    let active_cfg = storage::get_active_key_config().ok().flatten();
    let vault_exists = storage::get_vault_path().map(|p| p.exists()).unwrap_or(false);

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

    Ok(())
}

pub fn handle_logout(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    storage::clear_platform_account()?;
    if json_mode {
        crate::json_output::print_json(serde_json::json!({ "ok": true }));
    } else {
        println!("Logged out.");
    }
    Ok(())
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
        // Non-active keys must not remain locally active.
        let local_state = if item.key_status == "active" {
            existing
                .as_ref()
                .map(|e| e.local_state.clone())
                .unwrap_or_else(|| "synced_inactive".to_string())
        } else {
            "synced_inactive".to_string()
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
        };
        let _ = storage::upsert_virtual_key_cache(&entry);

        // If this key is currently active, refresh ~/.aikey/active.env with updated providers.
        // Handles the case where sync adds new providers to an already-active key.
        if !entry.supported_providers.is_empty() {
            if let Ok(Some(active_cfg)) = crate::storage::get_active_key_config() {
                if active_cfg.key_type == "team" && active_cfg.key_ref == entry.virtual_key_id {
                    let display = entry.local_alias.as_deref().unwrap_or(entry.alias.as_str());
                    let _ = write_active_env("team", &entry.virtual_key_id, display, &entry.supported_providers, 27200);
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
/// with local cache, then displays a table.  No vault password required —
/// key material stays encrypted; only metadata is shown.
pub fn handle_key_list(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let logged_in = storage::get_platform_account()?.is_some();

    // Sync metadata from server; warn on failure only in interactive mode.
    let server_ok = sync_managed_key_metadata();
    if !server_ok && !json_mode {
        if logged_in {
            eprintln!("Warning: could not reach control service. Showing local cache.");
        }
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

    let pending_count = cached.iter().filter(|e| e.share_status == "pending_claim").count();
    if pending_count > 0 {
        println!();
        println!("  {} key(s) pending. Run 'aikey key accept' to download all.", pending_count);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// aikey key accept
// ---------------------------------------------------------------------------

/// `aikey key accept [id]`
///
/// With no argument: fetches all pending keys from the server and accepts every
/// one in a single pass (vault password prompted once).
/// With an explicit id: accepts only that specific key (original behaviour).
///
/// Downloads the real provider key for each target, re-encrypts it with the
/// local vault AES key, stores in `managed_virtual_keys_cache`, and marks each
/// key as claimed on the server.
pub fn handle_key_accept(
    id: Option<&str>,
    password: &SecretString,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = get_authenticated_client()?;

    // Build the list of key IDs to accept.
    let ids_to_accept: Vec<String> = match id {
        Some(given_id) => vec![given_id.to_string()],
        None => {
            // No id given → accept all pending keys.
            let pending = client.get_pending_keys()?;
            if pending.is_empty() {
                if json_mode {
                    crate::json_output::print_json(serde_json::json!({
                        "ok": true,
                        "accepted": 0,
                        "message": "No pending keys."
                    }));
                } else {
                    println!("No pending team keys.");
                }
                return Ok(());
            }
            pending.into_iter().map(|k| k.virtual_key_id).collect()
        }
    };

    // Derive vault AES key once for all keys in this batch.
    let vault_key = derive_vault_key(password)?;

    let mut accepted: Vec<serde_json::Value> = Vec::new();

    for virtual_key_id in &ids_to_accept {
        if !json_mode {
            println!("  {} {}", "Fetching".dimmed(), virtual_key_id.dimmed());
        }

        // Fetch full delivery payload (includes plaintext provider key over TLS).
        let payload = match client.get_key_delivery(virtual_key_id) {
            Ok(p) => p,
            Err(e) => {
                if json_mode {
                    accepted.push(serde_json::json!({
                        "ok": false,
                        "virtual_key_id": virtual_key_id,
                        "error": e.to_string(),
                    }));
                } else {
                    eprintln!("  {} {}: {}", "✗".red(), "could not fetch key".red(), e);
                }
                continue;
            }
        };

        // Extract the primary binding target from the first slot.
        let binding = match payload.primary_binding() {
            Some(b) => b,
            None => {
                let msg = format!("Key {} has no active bindings — skipping.", virtual_key_id);
                if json_mode {
                    accepted.push(serde_json::json!({
                        "ok": false,
                        "virtual_key_id": virtual_key_id,
                        "error": msg,
                    }));
                } else {
                    eprintln!("Warning: {}", msg);
                }
                continue;
            }
        };
        let protocol_type = payload.primary_protocol_type().to_string();

        let (nonce, ciphertext) = crypto::encrypt(&vault_key, binding.provider_key.as_bytes())
            .map_err(|e| format!("Failed to encrypt provider key: {}", e))?;

        // Preserve local_alias if the key was previously accepted and renamed.
        let existing = storage::get_virtual_key_cache(&payload.virtual_key_id)
            .ok()
            .flatten();
        let existing_local_alias = existing.as_ref().and_then(|e| e.local_alias.clone());

        // Build supported_providers from payload (all active binding provider codes).
        // Fall back to just the primary binding's provider if payload.supported_providers is empty.
        let supported_providers = if !payload.supported_providers.is_empty() {
            payload.supported_providers.clone()
        } else if !binding.provider_code.is_empty() {
            vec![binding.provider_code.clone()]
        } else {
            vec![]
        };

        // Build per-provider base_url map from all delivery slots (preserves admin-configured URLs).
        let provider_base_urls: std::collections::HashMap<String, String> = payload.slots
            .iter()
            .flat_map(|slot| slot.binding_targets.iter())
            .map(|b| (b.provider_code.clone(), b.base_url.clone()))
            .collect();

        let entry = VirtualKeyCacheEntry {
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
            share_status: "claimed".to_string(),
            local_state: "synced_inactive".to_string(),
            expires_at: None,
            provider_key_nonce: Some(nonce),
            provider_key_ciphertext: Some(ciphertext),
            synced_at: 0,
            local_alias: existing_local_alias,
            supported_providers,
            provider_base_urls,
        };
        storage::upsert_virtual_key_cache(&entry)?;

        // Tell the server it is claimed.
        client.claim_key(virtual_key_id)?;

        if json_mode {
            accepted.push(serde_json::json!({
                "ok": true,
                "virtual_key_id": virtual_key_id,
                "alias": payload.alias,
                "provider_code": binding.provider_code,
            }));
        } else {
            println!("  {} Key {} {} accepted.",
                "✓".green().bold(),
                format!("'{}'", payload.alias).bold(),
                format!("[{}]", binding.provider_code).dimmed());
            println!("  {} Run {} to activate.",
                "→".dimmed(),
                format!("aikey key use {}", virtual_key_id).cyan());
        }
    }

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "accepted": accepted.len(),
            "keys": accepted,
        }));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// aikey key sync
// ---------------------------------------------------------------------------

/// `aikey key sync`
///
/// Refreshes all key metadata from the control service.  For keys that have
/// already been delivered (`share_status = claimed`) but are missing their
/// local ciphertext, re-fetches the delivery payload and re-encrypts.
pub fn handle_key_sync(
    password: &SecretString,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = get_authenticated_client()?;

    // Fetch all key metadata.
    let items = client.get_all_keys()?;
    let mut synced = 0usize;
    let mut downloaded = 0usize;

    let vault_key = derive_vault_key(password)?;

    for item in &items {
        let existing = storage::get_virtual_key_cache(&item.virtual_key_id)?;

        // Check if we need to (re-)download the actual key material.
        let needs_download = item.share_status == "claimed"
            && existing
                .as_ref()
                .map(|e| e.provider_key_ciphertext.is_none())
                .unwrap_or(true);

        if needs_download {
            match client.get_key_delivery(&item.virtual_key_id) {
                Ok(payload) => {
                    match payload.primary_binding() {
                        None => {
                            if !json_mode {
                                eprintln!("Warning: key {} has no active bindings — skipping.", item.virtual_key_id);
                            }
                        }
                        Some(binding) => {
                            let protocol_type = payload.primary_protocol_type().to_string();
                            let (nonce, ciphertext) =
                                crypto::encrypt(&vault_key, binding.provider_key.as_bytes())
                                    .map_err(|e| format!("Failed to encrypt provider key: {}", e))?;

                            let local_state = if payload.key_status == "active" {
                                existing
                                    .as_ref()
                                    .map(|e| e.local_state.clone())
                                    .unwrap_or_else(|| "synced_inactive".to_string())
                            } else {
                                "synced_inactive".to_string()
                            };

                            let sync_supported_providers = if !payload.supported_providers.is_empty() {
                                payload.supported_providers.clone()
                            } else if !binding.provider_code.is_empty() {
                                vec![binding.provider_code.clone()]
                            } else {
                                existing.as_ref().map(|e| e.supported_providers.clone()).unwrap_or_default()
                            };
                            let sync_provider_base_urls: std::collections::HashMap<String, String> = payload.slots
                                .iter()
                                .flat_map(|slot| slot.binding_targets.iter())
                                .map(|b| (b.provider_code.clone(), b.base_url.clone()))
                                .collect();
                            let entry = VirtualKeyCacheEntry {
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
                                local_state,
                                expires_at: None,
                                provider_key_nonce: Some(nonce),
                                provider_key_ciphertext: Some(ciphertext),
                                synced_at: 0,
                                local_alias: existing.as_ref().and_then(|e| e.local_alias.clone()),
                                supported_providers: sync_supported_providers,
                                provider_base_urls: sync_provider_base_urls,
                            };
                            storage::upsert_virtual_key_cache(&entry)?;
                            downloaded += 1;
                        }
                    }
                }
                Err(e) => {
                    if !json_mode {
                        eprintln!("Warning: could not fetch delivery for {}: {}", item.virtual_key_id, e);
                    }
                }
            }
        } else {
            // Metadata-only update.
            let local_state = if item.key_status == "active" {
                existing
                    .as_ref()
                    .map(|e| e.local_state.clone())
                    .unwrap_or_else(|| "synced_inactive".to_string())
            } else {
                "synced_inactive".to_string()
            };
            let nonce = existing.as_ref().and_then(|e| e.provider_key_nonce.clone());
            let ciphertext = existing.as_ref().and_then(|e| e.provider_key_ciphertext.clone());
            let base_url = existing.as_ref().map(|e| e.base_url.clone()).unwrap_or_default();
            let credential_id = existing.as_ref().map(|e| e.credential_id.clone()).unwrap_or_default();
            let credential_revision = existing.as_ref().map(|e| e.credential_revision.clone()).unwrap_or_default();
            let virtual_key_revision = existing.as_ref().map(|e| e.virtual_key_revision.clone()).unwrap_or_default();

            let meta_supported_providers = if !item.supported_providers.is_empty() {
                item.supported_providers.clone()
            } else {
                existing.as_ref().map(|e| e.supported_providers.clone()).unwrap_or_default()
            };
            // Preserve existing provider_base_urls — metadata sync doesn't re-deliver base URLs.
            let meta_provider_base_urls = existing.as_ref()
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
                local_alias: existing.as_ref().and_then(|e| e.local_alias.clone()),
                supported_providers: meta_supported_providers,
                provider_base_urls: meta_provider_base_urls,
            };
            storage::upsert_virtual_key_cache(&entry)?;
        }
        synced += 1;
    }

    if json_mode {
        crate::json_output::print_json(serde_json::json!({
            "ok": true,
            "synced": synced,
            "downloaded": downloaded,
        }));
    } else {
        println!("Sync complete: {} key(s) updated, {} key(s) downloaded.", synced, downloaded);
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
fn provider_proxy_prefix(provider_code: &str) -> &'static str {
    match provider_code.to_lowercase().as_str() {
        "anthropic" | "claude" => "anthropic",
        "openai" | "gpt" | "chatgpt" => "openai",
        "google" | "gemini"   => "google",
        "kimi"                => "kimi",
        "deepseek"            => "deepseek",
        "moonshot"            => "moonshot",
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
                key_ref.to_string()
            } else {
                format!("aikey_personal_{}", key_ref)
            };
            let base_url = format!("http://127.0.0.1:{}/{}", proxy_port, provider_proxy_prefix(provider));
            lines.push(format!("export {}=\"{}\"", api_key_var, token_value));
            lines.push(format!("export {}=\"{}\"", base_url_var, base_url));
        }
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
        eprint!(
            "  Install shell hook in {}? [Y/n]: ",
            rc_file
        );
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
    const PROXY_PORT: u16 = 27200;

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
        if entry.provider_key_ciphertext.is_none() {
            return Err(format!(
                "Key '{}' has not been delivered yet. Run 'aikey key accept {}' first.",
                entry.alias, entry.virtual_key_id
            ).into());
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
        // Personal key: look up alias in entries table and check for provider_code.
        let provider_code = storage::get_entry_provider_code(alias_or_id).map_err(|e| {
            format!(
                "Key '{}' not found. Run 'aikey key sync' or check personal keys with 'aikey list'.\nDetail: {}",
                alias_or_id, e
            )
        })?;
        // Check if the entry exists at all.
        let exists = storage::entry_exists(alias_or_id).unwrap_or(false);
        if !exists {
            return Err(format!(
                "Key '{}' not found in team keys or personal keys.\n\
                 If this is a personal key, re-add it with: aikey add {}",
                alias_or_id, alias_or_id
            ).into());
        }

        // Default list for generic gateway personal keys (no provider stored).
        const KNOWN: &[&str] = &["anthropic", "openai", "google", "deepseek", "kimi"];

        // Resolve which providers to activate:
        //   --provider <code>  → single provider (persist to DB)
        //   --provider          → show interactive menu, don't persist
        //   (no flag)           → use stored provider_code, or all defaults if none stored
        match provider_override {
            Some(ov) if !ov.is_empty() => {
                // Explicit --provider <code>: persist and activate that one.
                let code = ov.to_lowercase();
                let _ = storage::set_entry_provider_code(alias_or_id, Some(&code));
                let providers = vec![code];
                ("personal", alias_or_id.to_string(), alias_or_id.to_string(), providers)
            }
            Some(_empty) => {
                // --provider with no value: show selection menu (not persisted).
                if !std::io::stdin().is_terminal() || json_mode {
                    return Err(format!(
                        "Interactive provider selection requires a TTY.\n\
                         Specify with: aikey use {} --provider <code>",
                        alias_or_id
                    ).into());
                }
                use colored::Colorize;
                println!("Key '{}' has no provider set. Select one:", alias_or_id.bold());
                for (i, name) in KNOWN.iter().enumerate() {
                    println!("  {}  {}", format!("[{}]", i + 1).dimmed(), name);
                }
                print!("Choice: ");
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                let input = input.trim().to_lowercase();
                let chosen = if let Ok(n) = input.parse::<usize>() {
                    KNOWN.get(n.saturating_sub(1)).map(|s| s.to_string())
                } else if !input.is_empty() {
                    Some(input)
                } else {
                    None
                };
                let code = chosen.ok_or_else(|| format!(
                    "No provider selected. Specify with: aikey use {} --provider <code>",
                    alias_or_id
                ))?;
                let providers = vec![code];
                ("personal", alias_or_id.to_string(), alias_or_id.to_string(), providers)
            }
            None => {
                // No --provider flag: use stored code, or all defaults for generic gateway.
                let providers = match provider_code {
                    Some(code) if !code.is_empty() => vec![code],
                    _ => KNOWN.iter().map(|s| s.to_string()).collect(),
                };
                ("personal", alias_or_id.to_string(), alias_or_id.to_string(), providers)
            }
        }
    };

    if providers.is_empty() {
        return Err(format!(
            "Key '{}' has no supported providers — cannot write env vars.\n\
             Run 'aikey key sync' to refresh, or re-add with '--provider <code>'.",
            display_name
        ).into());
    }

    // ── 2. Global mutex — deactivate all team keys ────────────────────────────
    storage::set_all_virtual_keys_inactive()?;
    storage::clear_active_key_config()?;

    // ── 3. Activate the chosen key in the local state store ───────────────────
    if key_type == "team" {
        if let Some(ref entry) = team_entry {
            storage::set_virtual_key_local_state(&entry.virtual_key_id, "active")?;
        }
    }

    // ── 4. Write active key config (proxy reads this) ─────────────────────────
    storage::set_active_key_config(&storage::ActiveKeyConfig {
        key_type: key_type.to_string(),
        key_ref: key_ref.clone(),
        providers: providers.clone(),
    })?;
    let _ = storage::bump_vault_change_seq();

    // ── 4b. Notify the proxy of the config change (if already running) ────────
    crate::commands_proxy::try_reload_proxy();

    // ── 5. Write ~/.aikey/active.env (proxy sentinel tokens) ──────────────────
    write_active_env(key_type, &key_ref, &display_name, &providers, PROXY_PORT)?;

    // ── 6. Shell hook (one-time, first use) ───────────────────────────────────
    let hook_msg = if !json_mode { ensure_shell_hook(no_hook) } else { None };

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
        println!("{} {} {} is now {} {}.",
            "✓".green().bold(),
            format!("'{}'", display_name).bold(),
            format!("[{}]", primary_provider).dimmed(),
            "active".green().bold(),
            "(proxy)".dimmed());
        println!();
        for provider in &providers {
            if let Some((api_key_var, base_url_var)) = provider_env_vars(provider) {
                let token_value = if key_type == "team" {
                    key_ref.clone()
                } else {
                    format!("aikey_personal_{}", key_ref)
                };
                let base_url = format!("http://127.0.0.1:{}/{}", PROXY_PORT, provider_proxy_prefix(provider));
                println!("  {:<24} = {}", api_key_var.bold(), token_value.cyan());
                println!("  {:<24} = {}", base_url_var.bold(), base_url.cyan());
            }
        }
        println!();
        if let Some(msg) = hook_msg {
            println!("{}", msg.dimmed());
            println!();
            println!("{} Run: {}", "→".dimmed(), "source ~/.aikey/active.env".cyan());
            println!("{} Or open a new terminal window.", "→".dimmed());
        } else {
            println!("{} Press {} once again to apply in this terminal (to active shell hook).", "→".dimmed(), "Enter".bold());
            println!("{} Or open a new terminal window.", "→".dimmed());
        }
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
// Startup interactive accept prompt
// ---------------------------------------------------------------------------

/// Returns un-dismissed pending entries, or `None` if the prompt should be skipped
/// (nothing pending, not logged in, or not a TTY).
fn collect_pending_for_prompt() -> Option<Vec<storage::VirtualKeyCacheEntry>> {
    if storage::count_pending_virtual_keys().unwrap_or(0) == 0 {
        return None;
    }
    if storage::get_platform_account().ok().flatten().is_none() {
        return None;
    }
    if !io::stderr().is_terminal() {
        return None;
    }
    let entries: Vec<_> = storage::list_virtual_key_cache()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| {
            e.share_status == "pending_claim"
                && e.key_status == "active"
                && e.local_state != "prompt_dismissed"
        })
        .collect();
    if entries.is_empty() { None } else { Some(entries) }
}

/// Prints the pending-key banner and reads the user's choice.
/// Returns `true` if the user typed "y", `false` / dismissed / skipped otherwise.
fn show_pending_banner(pending_entries: &[storage::VirtualKeyCacheEntry]) -> bool {
    eprintln!();
    eprintln!("{}", format!("  {} new team key(s) pending to accept:", pending_entries.len())
        .yellow().bold());
    for e in pending_entries {
        let provider = if e.provider_code.is_empty() { "unknown" } else { &e.provider_code };
        eprintln!("  {} {}  {}",
            "•".yellow(),
            e.alias.bold(),
            format!("[{}]", provider).dimmed());
    }
    eprint!("\n  {} ", "Accept?".bold());
    eprint!("{}  {}  {} ",
        "[Y] yes".green(),
        "[N] never remind".red(),
        "Enter = skip".dimmed());
    eprint!(": ");
    io::stderr().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    match input.trim().to_lowercase().as_str() {
        "n" => {
            let ids: Vec<String> = pending_entries.iter().map(|e| e.virtual_key_id.clone()).collect();
            let _ = storage::dismiss_pending_keys(&ids);
            eprintln!("{}", "  Dismissed. Run 'aikey key accept' to download later.".dimmed());
            eprintln!();
            false
        }
        "y" => true,
        _ => {
            eprintln!();
            false
        }
    }
}

/// Accepts the given pending keys and prints a result line for each.
fn run_accept_batch(pending_entries: &[storage::VirtualKeyCacheEntry], password: &SecretString) {
    eprintln!();
    for e in pending_entries {
        match handle_key_accept(Some(e.virtual_key_id.as_str()), password, false) {
            Ok(_) => {}
            Err(err) => eprintln!("Warning: could not accept key {}: {}", e.alias, err),
        }
    }
    eprintln!();
}

/// Called at the start of commands that do **not** already have the vault
/// password in hand (e.g. `aikey proxy status`, `aikey stats`).
///
/// Shows the pending-key banner; if the user types Y, prompts for the vault
/// password and accepts all pending keys.  N dismisses permanently; Enter
/// skips until next time.  All failures are silently swallowed.
pub fn maybe_prompt_accept_pending() -> Result<(), String> {
    let pending = match collect_pending_for_prompt() {
        Some(p) => p,
        None => return Ok(()),
    };
    if show_pending_banner(&pending) {
        let password_str = match rpassword::prompt_password("Vault master password: ") {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        run_accept_batch(&pending, &SecretString::new(password_str));
    }
    Ok(())
}

/// Variant for commands that already hold the vault password (e.g. `aikey list`).
///
/// Reuses the caller's password so the user is not asked to type it twice.
pub fn maybe_prompt_accept_pending_with_password(password: &SecretString) -> Result<(), String> {
    let pending = match collect_pending_for_prompt() {
        Some(p) => p,
        None => return Ok(()),
    };
    if show_pending_banner(&pending) {
        run_accept_batch(&pending, password);
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

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
