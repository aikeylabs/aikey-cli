//! `aikey auth *` — Provider OAuth account management commands.
//!
//! CLI-side implementation of OAuth account lifecycle. The CLI does NOT implement
//! OAuth protocol — it delegates to aikey-proxy via HTTP API (`/oauth/*`).
//!
//! Architecture (D14): all auth command code lives here, not in main.rs.

use crate::cli::AuthAction;
use crate::credential_type::CredentialType;
use crate::storage as storage;
use colored::Colorize;
use std::io::{self, BufRead, Write};
use std::process::Command as ProcessCommand;

/// Dispatch `aikey auth <action>` to the appropriate handler.
pub fn handle_auth_command(
    action: &AuthAction,
    proxy_port: u16,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        AuthAction::Login { provider } => handle_login(provider, proxy_port, json_mode),
        AuthAction::Logout { target } => handle_logout(target, proxy_port, json_mode),
        AuthAction::List => handle_list(json_mode),
        AuthAction::Use { account } => handle_use(account, proxy_port, json_mode),
        AuthAction::Status { account } => handle_status(account.as_deref(), proxy_port, json_mode),
        AuthAction::Doctor { provider } => handle_doctor(provider.as_deref(), proxy_port),
    }
}

// ============================================================================
// aikey auth login <provider>
// ============================================================================

fn handle_login(provider: &str, proxy_port: u16, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Check proxy is running
    check_proxy_running(proxy_port)?;

    // 2. Start login (Phase 1)
    let base = proxy_base(proxy_port);
    let resp: serde_json::Value = ureq::post(&format!("{}/oauth/login", base))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({"provider": provider}).to_string())
        .map_err(|e| format!("Failed to start login: {}", e))?
        .into_json()?;

    let session_id = resp["id"].as_str().unwrap_or("").to_string();
    let flow_type = resp["flow_type"].as_str().unwrap_or("");
    let status = resp["status"].as_str().unwrap_or("");

    if status == "failed" || resp.get("error").is_some() {
        let err_msg = resp["error"].as_str()
            .or_else(|| resp["message"].as_str())
            .unwrap_or("Unknown error");
        if !json_mode {
            eprintln!("{} {}", "[X]".red(), err_msg);
            if let Some(hint) = resp["hint"].as_str() {
                eprintln!("    {}", hint);
            }
        }
        return Err(err_msg.to_string().into());
    }

    match flow_type {
        "setup_token" => login_setup_token(&base, &session_id, &resp, provider, proxy_port, json_mode),
        "auth_code" => login_auth_code(&base, &session_id, &resp, provider, proxy_port, json_mode),
        "device_code" => login_device_code(&base, &session_id, &resp, provider, proxy_port, json_mode),
        _ => Err(format!("Unknown flow type: {}", flow_type).into()),
    }
}

/// Claude: Setup Token — open browser, user pastes code#state
fn login_setup_token(
    base: &str, session_id: &str, resp: &serde_json::Value,
    provider: &str, _proxy_port: u16, json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_url = resp["auth_url"].as_str().unwrap_or("");

    if !json_mode {
        eprintln!("{} Note: Claude OAuth requires a Pro or Max subscription.", "[i]".cyan());
        eprintln!("{} Open this URL and click 'Authorize':", "[i]".cyan());
        eprintln!("\n  {}\n", auth_url);
    }

    // Try to open browser
    let _ = open_browser(auth_url);

    if !json_mode {
        eprint!("{} Paste the code from the callback page (format: authCode#state): ", "[i]".cyan());
        io::stderr().flush()?;
    }

    // Read code#state from stdin
    let mut code_state = String::new();
    io::stdin().lock().read_line(&mut code_state)?;
    let code_state = code_state.trim().to_string();

    if code_state.is_empty() {
        return Err("No code provided. Login cancelled.".into());
    }

    // Phase 2: submit code
    submit_code_and_finish(base, session_id, &code_state, provider, json_mode)
}

/// Codex: Auth Code — open browser, localhost callback auto-receives code
fn login_auth_code(
    base: &str, session_id: &str, resp: &serde_json::Value,
    provider: &str, _proxy_port: u16, json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_url = resp["auth_url"].as_str().unwrap_or("");

    if !json_mode {
        eprintln!("{} Opening browser for {} login...", "[i]".cyan(), provider);
    }
    let _ = open_browser(auth_url);

    if !json_mode {
        eprintln!("Waiting for authorization... (Ctrl+C to cancel)");
    }

    // Poll for completion (proxy handles the callback)
    poll_login_status(base, session_id, provider, json_mode)
}

/// Kimi: Device Code — show user_code, poll for completion
fn login_device_code(
    base: &str, session_id: &str, resp: &serde_json::Value,
    provider: &str, _proxy_port: u16, json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let user_code = resp["user_code"].as_str().unwrap_or("");
    let verify_url = resp["verification_url"].as_str().unwrap_or("");

    if !json_mode {
        eprintln!("{} Open this URL and enter the code:", "[i]".cyan());
        eprintln!("  URL:  {}", verify_url);
        eprintln!("  Code: {}", user_code.bold());
    }

    let _ = open_browser(verify_url);

    if !json_mode {
        eprintln!("Waiting for authorization...");
    }

    // Device Code: use POST /oauth/poll (triggers provider poll on each call).
    // Why not GET /oauth/status: status is read-only and won't drive device-code progress.
    poll_device_code(base, session_id, provider, json_mode)
}

/// Submit code#state and handle the result (used by setup_token flow).
fn submit_code_and_finish(
    base: &str, session_id: &str, code_state: &str,
    provider: &str, json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp: serde_json::Value = ureq::post(&format!("{}/oauth/login", base))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({
            "provider": provider,
            "code": code_state,
            "session_id": session_id,
        }).to_string())
        .map_err(|e| format!("Token exchange failed: {}", e))?
        .into_json()?;

    let account_id = resp["account_id"].as_str().unwrap_or("");
    let display = resp["display_identity"].as_str().unwrap_or(account_id);
    let expires_in = resp["expires_in"].as_i64().unwrap_or(0);

    if json_mode {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let days = expires_in / 86400;
        eprintln!("{} Logged in as {} ({}), expires in {} days",
            "[OK]".green(), display.bold(), provider, days);

        // D13: Kimi has no email — prompt for display name
        if display.is_empty() || !display.contains('@') {
            prompt_display_identity(base, account_id)?;
        }
    }

    Ok(())
}

/// Poll GET /oauth/status until success or failure (for auth_code and device_code flows).
fn poll_login_status(
    base: &str, session_id: &str, provider: &str, json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let timeout = std::time::Duration::from_secs(120);
    let start = std::time::Instant::now();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));

        if start.elapsed() > timeout {
            return Err("Login session expired (120s timeout). Try again.".into());
        }

        let resp: serde_json::Value = match ureq::get(&format!("{}/oauth/status?session_id={}", base, session_id))
            .call()
        {
            Ok(r) => r.into_json()?,
            Err(_) => continue,
        };

        let status = resp["status"].as_str().unwrap_or("");
        match status {
            "success" => {
                let account_id = resp["account_id"].as_str().unwrap_or("");
                let display = resp["display_identity"].as_str().unwrap_or(account_id);

                if json_mode {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    eprintln!("{} Logged in as {} ({})", "[OK]".green(), display.bold(), provider);

                    // D13: prompt for display name if no email
                    if display.is_empty() || !display.contains('@') {
                        prompt_display_identity(base, account_id)?;
                    }
                }
                return Ok(());
            }
            "failed" => {
                let err = resp["error"].as_str().unwrap_or("Login failed");
                if !json_mode {
                    eprintln!("{} {}", "[X]".red(), err);
                }
                return Err(err.to_string().into());
            }
            _ => {
                // Still pending
                if !json_mode {
                    eprint!(".");
                    io::stderr().flush()?;
                }
            }
        }
    }
}

/// Poll POST /oauth/poll for device-code flows (Kimi).
/// Each call triggers one poll attempt against the provider's token endpoint.
/// Returns when the user authorizes in browser or timeout is reached.
fn poll_device_code(
    base: &str, session_id: &str, provider: &str, json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let timeout = std::time::Duration::from_secs(300); // Device code flows allow longer timeout
    let start = std::time::Instant::now();
    // Kimi device code interval is typically 5s; respect provider's rate limit.
    let poll_interval = std::time::Duration::from_secs(5);

    loop {
        std::thread::sleep(poll_interval);

        if start.elapsed() > timeout {
            return Err("Device code expired (5min timeout). Run `aikey auth login` again.".into());
        }

        let resp_result = ureq::post(&format!("{}/oauth/poll", base))
            .set("Content-Type", "application/json")
            .send_string(&serde_json::json!({
                "session_id": session_id,
            }).to_string());

        match resp_result {
            Ok(r) => {
                // 200 = success (LoginResult with account_id, display_identity, etc.)
                let resp: serde_json::Value = r.into_json()?;
                let account_id = resp["account_id"].as_str().unwrap_or("");
                let display = resp["display_identity"].as_str().unwrap_or(account_id);

                if json_mode {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    eprintln!();
                    eprintln!("{} Logged in as {} ({})", "[OK]".green(), display.bold(), provider);

                    // D13: prompt for display name if no email
                    if display.is_empty() || !display.contains('@') {
                        prompt_display_identity(base, account_id)?;
                    }
                }
                return Ok(());
            }
            Err(ureq::Error::Status(code, resp)) => {
                // 4xx error from broker
                let body: serde_json::Value = resp.into_json().unwrap_or_default();
                let retry = body["retry"].as_bool().unwrap_or(false);

                if retry {
                    // Still pending — provider hasn't seen user authorization yet
                    if !json_mode {
                        eprint!(".");
                        io::stderr().flush()?;
                    }
                    continue;
                }

                // Non-retryable error (session expired, flow failed, etc.)
                let msg = body["message"].as_str().unwrap_or("Device code login failed");
                if !json_mode {
                    eprintln!();
                    eprintln!("{} {} (HTTP {})", "[X]".red(), msg, code);
                }
                return Err(msg.to_string().into());
            }
            Err(_) => {
                // Network error — retry silently
                continue;
            }
        }
    }
}

/// D13: Prompt user for display identity (Kimi accounts have no email).
fn prompt_display_identity(base: &str, account_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprint!("\nEnter a display name for this account (e.g. email or alias): ");
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().lock().read_line(&mut input)?;
    let input = input.trim();

    if !input.is_empty() {
        let _ = ureq::post(&format!("{}/oauth/accounts/{}/display-identity", base, account_id))
            .set("Content-Type", "application/json")
            .send_string(&serde_json::json!({"display_identity": input}).to_string());
        eprintln!("{} Display name set: {}", "[OK]".green(), input);
    }
    Ok(())
}

// ============================================================================
// aikey auth list
// ============================================================================

fn handle_list(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let accounts = storage::list_provider_accounts()?;

    if accounts.is_empty() {
        if !json_mode {
            eprintln!("No provider OAuth accounts. Login with: aikey auth login <provider>");
        }
        return Ok(());
    }

    if json_mode {
        let json: Vec<serde_json::Value> = accounts.iter().map(|a| {
            serde_json::json!({
                "provider_account_id": a.provider_account_id,
                "provider": a.provider,
                "status": a.status,
                "display_identity": a.display_identity,
                "account_tier": a.account_tier,
            })
        }).collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Build display data
        let display_rows: Vec<(String, String, String, String, String)> = accounts.iter().map(|a| {
            let identity = a.display_identity.as_deref()
                .filter(|s| !s.is_empty())
                .or_else(|| a.external_id.as_deref().map(|s| if s.len() > 12 { &s[..12] } else { s }))
                .unwrap_or("-").to_string();
            let status_display = match a.status.as_str() {
                "active" => format!("\u{25cf} {}", a.status),
                "reauth_required" => format!("\u{2717} {}", a.status),
                _ => format!("  {}", a.status),
            };
            let tier = a.account_tier.as_deref().unwrap_or("-").to_string();
            let expires = storage::get_provider_token_expires_at(&a.provider_account_id)
                .ok().flatten()
                .map(|exp| {
                    let rem = exp - now;
                    if rem <= 0 { "expired".to_string() }
                    else if rem > 86400 { format!("{}d", rem / 86400) }
                    else if rem > 3600 { format!("{}h", rem / 3600) }
                    else { format!("{}m", rem / 60) }
                }).unwrap_or_else(|| "-".to_string());
            (identity, a.provider.clone(), status_display, tier, expires)
        }).collect();

        // Dynamic widths
        let pad = 2;
        let w_id   = "IDENTITY".len().max(display_rows.iter().map(|r| r.0.len()).max().unwrap_or(0)) + pad;
        let w_prov = "PROVIDER".len().max(display_rows.iter().map(|r| r.1.len()).max().unwrap_or(0)) + pad;
        let w_st   = "STATUS".len().max(display_rows.iter().map(|r| r.2.len()).max().unwrap_or(0)) + pad;
        let w_tier = "TIER".len().max(display_rows.iter().map(|r| r.3.len()).max().unwrap_or(0)) + pad;

        println!("\n  Provider Accounts (OAuth):");
        println!("  {:<wi$}{:<wp$}{:<ws$}{:<wt$}{}",
            "IDENTITY", "PROVIDER", "STATUS", "TIER", "EXPIRES",
            wi = w_id, wp = w_prov, ws = w_st, wt = w_tier);
        for r in &display_rows {
            println!("  {:<wi$}{:<wp$}{:<ws$}{:<wt$}{}",
                r.0, r.1, r.2, r.3, r.4,
                wi = w_id, wp = w_prov, ws = w_st, wt = w_tier);
        }
        println!();
    }
    Ok(())
}

// ============================================================================
// aikey auth use <account>
// ============================================================================

fn handle_use(account: &str, _proxy_port: u16, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Match account: exact ID or fuzzy display_identity
    let target = find_account(account)?;

    if target.status != "active" && target.status != "idle" {
        return Err(format!(
            "Account {} has status '{}'. Run: aikey auth login {}",
            account, target.status, target.provider
        ).into());
    }

    // Map OAuth provider to canonical code (claude→anthropic, codex→openai)
    let canonical = oauth_provider_to_canonical(&target.provider);

    // Get old binding for the provider (for replacement notice)
    let old_binding = storage::get_provider_binding("default", canonical).ok().flatten();

    // Update per-provider binding (D8: same provider mutual exclusion)
    storage::set_provider_binding(
        "default",
        canonical,
        CredentialType::PersonalOAuthAccount.as_str(),
        &target.provider_account_id,
    )?;

    // Update global active_key_config
    storage::set_active_key_config(&storage::ActiveKeyConfig {
        key_type: CredentialType::PersonalOAuthAccount,
        key_ref: target.provider_account_id.clone(),
        providers: vec![canonical.to_string()],
    })?;

    // Refresh active.env from all provider bindings + reload proxy
    let _ = crate::profile_activation::refresh_implicit_profile_activation();
    // Trigger proxy reload
    let _ = crate::commands_proxy::post_admin_reload();

    // Output
    let display = target.display_identity.as_deref().unwrap_or(&target.provider_account_id);
    if json_mode {
        println!("{}", serde_json::json!({
            "ok": true,
            "provider": target.provider,
            "account_id": target.provider_account_id,
            "display_identity": display,
        }));
    } else {
        eprintln!("{} Now using {}/{} (OAuth) for {}",
            "[OK]".green(), target.provider, display.bold(), canonical);
        if let Some(old) = old_binding {
            if old.key_source_ref != target.provider_account_id {
                eprintln!("     Replaced: {} ({})", old.key_source_ref, old.key_source_type);
            }
        }
    }

    Ok(())
}

// ============================================================================
// aikey auth logout <target>
// ============================================================================

fn handle_logout(target: &str, proxy_port: u16, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let acct = find_account(target)?;
    let display = acct.display_identity.as_deref().unwrap_or(&acct.provider_account_id);

    // Confirm
    if !json_mode {
        eprint!("Logout from {}/{}? [y/N] ", acct.provider, display);
        io::stderr().flush()?;
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    // Delete via proxy broker API
    check_proxy_running(proxy_port)?;
    let base = proxy_base(proxy_port);
    let _ = ureq::post(&format!("{}/oauth/logout", base))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({"provider_account_id": acct.provider_account_id}).to_string());

    // Also clean up local bindings
    let _ = storage::delete_provider_account(&acct.provider_account_id);

    // If this was the active credential, clear it
    if let Ok(Some(cfg)) = storage::get_active_key_config() {
        if cfg.key_type == CredentialType::PersonalOAuthAccount && cfg.key_ref == acct.provider_account_id {
            let _ = storage::set_active_key_config(&storage::ActiveKeyConfig {
                key_type: CredentialType::PersonalApiKey,
                key_ref: String::new(),
                providers: vec![],
            });
            let _ = crate::profile_activation::refresh_implicit_profile_activation();
            let _ = crate::commands_proxy::post_admin_reload();
        }
    }

    if json_mode {
        println!("{}", serde_json::json!({"ok": true}));
    } else {
        eprintln!("{} Logged out from {}/{}", "[OK]".green(), acct.provider, display);
    }
    Ok(())
}

// ============================================================================
// aikey auth status / doctor
// ============================================================================

fn handle_status(account: Option<&str>, proxy_port: u16, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    match account {
        None => {
            // Show all accounts
            handle_list(json_mode)
        }
        Some(id) => {
            check_proxy_running(proxy_port)?;
            let base = proxy_base(proxy_port);
            let acct = find_account(id)?;

            let resp: serde_json::Value = ureq::get(
                &format!("{}/oauth/accounts/{}/health", base, acct.provider_account_id)
            )
            .call()
            .map_err(|e| format!("Failed to get health: {}", e))?
            .into_json()?;

            if json_mode {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                let display = acct.display_identity.as_deref().unwrap_or(&acct.provider_account_id);
                eprintln!("  Account:     {}/{}", acct.provider, display);
                eprintln!("  Status:      {}", resp["status"].as_str().unwrap_or("-"));
                eprintln!("  Token:       {}", resp["token_status"].as_str().unwrap_or("-"));
                let expires_in = resp["expires_in"].as_i64().unwrap_or(0);
                if expires_in > 86400 {
                    eprintln!("  Expires in:  {} days", expires_in / 86400);
                } else if expires_in > 3600 {
                    eprintln!("  Expires in:  {} hours", expires_in / 3600);
                } else if expires_in > 0 {
                    eprintln!("  Expires in:  {} minutes", expires_in / 60);
                }
            }
            Ok(())
        }
    }
}

fn handle_doctor(provider: Option<&str>, proxy_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let _provider = provider.unwrap_or("all");
    eprintln!("  Checking proxy...");

    // [1] Proxy running
    match check_proxy_running(proxy_port) {
        Ok(_) => eprintln!("  {} Proxy running on port {}", "\u{2713}".green(), proxy_port),
        Err(e) => {
            eprintln!("  {} Proxy not running: {}", "\u{2717}".red(), e);
            return Ok(());
        }
    }

    // [2] OAuth accounts
    let accounts = storage::list_provider_accounts().unwrap_or_default();
    if accounts.is_empty() {
        eprintln!("  {} No OAuth accounts", "[i]".cyan());
    } else {
        eprintln!("  {} {} OAuth account(s) found", "\u{2713}".green(), accounts.len());
        for a in &accounts {
            let display = a.display_identity.as_deref().unwrap_or("-");
            eprintln!("    {}/{} — {}", a.provider, display, a.status);
        }
    }

    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

fn proxy_base(port: u16) -> String {
    format!("http://127.0.0.1:{}", port)
}

fn check_proxy_running(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/health", proxy_base(port));
    match ureq::get(&url).timeout(std::time::Duration::from_secs(3)).call() {
        Ok(_) => Ok(()),
        Err(_) => Err(format!(
            "Proxy not running on port {}.\n  Start it with: aikey proxy start\n  Or set AIKEY_MASTER_PASSWORD and run: aikey-proxy",
            port
        ).into()),
    }
}

fn find_account(id_or_display: &str) -> Result<storage::ProviderAccountInfo, Box<dyn std::error::Error>> {
    // Try exact ID match first
    if let Ok(Some(acct)) = storage::get_provider_account(id_or_display) {
        return Ok(acct);
    }

    // Fuzzy match by display_identity or provider
    let all = storage::list_provider_accounts()?;
    let matches: Vec<_> = all.into_iter().filter(|a| {
        a.display_identity.as_deref().map_or(false, |d| d.contains(id_or_display))
            || a.provider == id_or_display
            || a.provider_account_id.contains(id_or_display)
    }).collect();

    match matches.len() {
        0 => Err(format!("Account '{}' not found. Run: aikey auth list", id_or_display).into()),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => {
            // Multiple matches — show them and ask user to be more specific
            eprintln!("Multiple accounts match '{}':", id_or_display);
            for a in &matches {
                let display = a.display_identity.as_deref().unwrap_or("-");
                eprintln!("  {} — {}/{}", a.provider_account_id, a.provider, display);
            }
            Err("Please specify the full account ID.".into())
        }
    }
}

/// Map OAuth provider name to canonical provider code used in bindings.
/// OAuth uses "claude"/"codex"/"kimi", but proxy routing uses "anthropic"/"openai"/"kimi".
fn oauth_provider_to_canonical(provider: &str) -> &str {
    match provider {
        "claude" => "anthropic",
        "codex" => "openai",
        _ => provider,
    }
}

/// Open a URL in the default browser (cross-platform).
fn open_browser(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    { let _ = ProcessCommand::new("open").arg(url).spawn(); }
    #[cfg(target_os = "linux")]
    { let _ = ProcessCommand::new("xdg-open").arg(url).spawn(); }
    #[cfg(target_os = "windows")]
    { let _ = ProcessCommand::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn(); }
    Ok(())
}
