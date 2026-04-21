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

/// Interactive provider picker for `aikey auth login` (no provider argument).
/// Shows user-friendly names (Claude, Codex, Kimi) and returns the broker code.
fn pick_oauth_provider() -> Result<String, Box<dyn std::error::Error>> {
    use crate::ui_select::{box_select, SelectResult};

    // Display name → broker provider code
    let choices = [
        ("Claude    (Anthropic) — requires Pro or Max subscription", "claude"),
        ("Codex     (OpenAI)    — requires ChatGPT Pro/Plus", "codex"),
        ("Kimi      (Moonshot AI)", "kimi"),
    ];

    let items: Vec<String> = choices.iter().map(|(label, _)| label.to_string()).collect();
    let selectable = vec![true; items.len()];

    match box_select("Select provider", "", &items, &selectable, 0)? {
        SelectResult::Selected(idx) => Ok(choices[idx].1.to_string()),
        SelectResult::Cancelled => Err("Cancelled.".into()),
    }
}

/// Dispatch `aikey auth <action>` to the appropriate handler.
pub fn handle_auth_command(
    action: &AuthAction,
    proxy_port: u16,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        AuthAction::Login { provider } => {
            let provider = match provider {
                Some(p) => p.clone(),
                None => pick_oauth_provider()?,
            };
            handle_login(&provider, proxy_port, json_mode)
        }
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

    // Normalize provider alias → broker provider code.
    // Why: broker uses "claude"/"codex"/"kimi", users may type canonical names.
    let provider = match provider.to_lowercase().as_str() {
        "anthropic" | "claude" => "claude",
        "openai" | "codex" | "chatgpt" => "codex",
        "kimi" | "moonshot" => "kimi",
        _ => provider,
    };

    // 2. Start login (Phase 1)
    let base = proxy_base(proxy_port);
    let http_result = ureq::post(&format!("{}/oauth/login", base))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({"provider": provider}).to_string());

    let resp: serde_json::Value = match http_result {
        Ok(r) => r.into_json()?,
        Err(ureq::Error::Status(code, response)) => {
            let body: serde_json::Value = response.into_json().unwrap_or_default();
            let msg = body["message"].as_str().unwrap_or("Failed to start login");
            let hint = body["hint"].as_str().unwrap_or("");
            if !json_mode {
                eprintln!("  {} {} (HTTP {})", "\u{25c6}".red(), msg, code);
                if !hint.is_empty() {
                    eprintln!("  \u{2502} {}", hint);
                }
            }
            return Err(msg.to_string().into());
        }
        Err(e) => return Err(format!("Failed to start login: {}", e).into()),
    };

    let session_id = resp["id"].as_str().unwrap_or("").to_string();
    let flow_type = resp["flow_type"].as_str().unwrap_or("");

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
        eprintln!();
        eprintln!("  {} Note: Claude OAuth requires a Pro or Max subscription.", "\u{25c6}".cyan());
        eprintln!("  {} Open this URL and click 'Authorize':", "\u{2502}".dimmed());
        eprintln!("  {}", "\u{2502}".dimmed());
        eprintln!("  {}   {}", "\u{2502}".dimmed(), auth_url);
        eprintln!("  {}", "\u{2502}".dimmed());
    }

    // Try to open browser
    let _ = open_browser(auth_url);

    // Read code#state with masked input (shows **** like Master Password).
    let code_state = crate::prompt_hidden("  \u{25c6} Paste the code (format: code#state): ")
        .map_err(|e| format!("Failed to read code: {}", e))?;
    let code_state = code_state.trim().to_string();

    if code_state.is_empty() {
        return Err("No code provided. Login cancelled.".into());
    }

    // Client-side state validation: broker will hard-reject on mismatch, but we
    // also confirm with the user to give them a chance to re-paste.
    // Extract expected state from auth_url query param.
    if !json_mode {
        if let Some(expected_state) = extract_state_param(auth_url) {
            let pasted_state = code_state.split('#').nth(1).unwrap_or("");
            if !expected_state.is_empty() && pasted_state != expected_state {
                if pasted_state.is_empty() {
                    eprintln!("  {} state missing from pasted code — expected code#state format", "\u{25c6}".yellow());
                } else {
                    eprintln!("  {} state mismatch — pasted state differs from expected (CSRF risk)", "\u{25c6}".yellow());
                }
                eprint!("  {} Continue anyway? [y/N] ", "\u{25c6}".yellow());
                io::stderr().flush()?;
                let mut confirm = String::new();
                io::stdin().lock().read_line(&mut confirm)?;
                if !confirm.trim().eq_ignore_ascii_case("y") && !confirm.trim().eq_ignore_ascii_case("yes") {
                    return Err("Login cancelled due to state mismatch.".into());
                }
            }
        }
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
        eprintln!();
        eprintln!("  {} Opening browser for {} login...", "\u{25c6}".cyan(), provider);
        eprintln!("  {}", "\u{2502}".dimmed());
    }
    let _ = open_browser(auth_url);

    if !json_mode {
        eprintln!("  {} Waiting for authorization... (Ctrl+C to cancel)", "\u{2502}".dimmed());
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
        eprintln!();
        eprintln!("  {} Open this URL and enter the code:", "\u{25c6}".cyan());
        eprintln!("  {}   URL:  {}", "\u{2502}".dimmed(), verify_url);
        eprintln!("  {}   Code: {}", "\u{2502}".dimmed(), user_code.bold());
        eprintln!("  {}", "\u{2502}".dimmed());
    }

    let _ = open_browser(verify_url);

    if !json_mode {
        eprintln!("  {} Waiting for authorization...", "\u{2502}".dimmed());
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
    let http_result = ureq::post(&format!("{}/oauth/login", base))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({
            "provider": provider,
            "code": code_state,
            "session_id": session_id,
        }).to_string());

    let resp: serde_json::Value = match http_result {
        Ok(r) => r.into_json()?,
        Err(ureq::Error::Status(code, response)) => {
            // Extract detailed error from broker response body.
            let body: serde_json::Value = response.into_json().unwrap_or_default();
            let msg = body["message"].as_str().unwrap_or("Token exchange failed");
            let hint = body["hint"].as_str().unwrap_or("");
            let err_code = body["error"].as_str().unwrap_or("");
            if !json_mode {
                eprintln!("  {} {} (HTTP {})", "\u{25c6}".red(), msg, code);
                if !hint.is_empty() {
                    eprintln!("  \u{2502} {}", hint);
                }
                if !err_code.is_empty() {
                    eprintln!("  \u{2502} error: {}", err_code);
                }
            }
            return Err(msg.to_string().into());
        }
        Err(e) => return Err(format!("Token exchange failed: {}", e).into()),
    };

    let account_id = resp["account_id"].as_str().unwrap_or("");
    let display = resp["display_identity"].as_str().unwrap_or(account_id);
    let expires_in = resp["expires_in"].as_i64().unwrap_or(0);

    // Generate route token for per-request proxy routing (API gateway).
    if !account_id.is_empty() {
        let _ = crate::storage::ensure_provider_account_route_token(account_id);
    }

    if json_mode {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let days = expires_in / 86400;
        eprintln!("  {} Logged in as {} ({}), expires in {} days",
            "\u{25c6}".green(), display.bold(), provider, days);

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

        // Per-request timeout prevents hanging on network issues.
        let resp: serde_json::Value = match ureq::get(&format!("{}/oauth/status?session_id={}", base, session_id))
            .timeout(std::time::Duration::from_secs(10))
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

                // Generate route token for per-request proxy routing (API gateway).
                if !account_id.is_empty() {
                    let _ = crate::storage::ensure_provider_account_route_token(account_id);
                }

                if json_mode {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    eprintln!("{} Logged in as {} ({})", "\u{25c6}".green(), display.bold(), provider);

                    // D13: prompt for display name if no email
                    if display.is_empty() || !display.contains('@') {
                        prompt_display_identity(base, account_id)?;
                    }

                    // Auto-install Claude Code status line integration on first
                    // successful Claude OAuth login. Idempotent — safe to re-run.
                    // See 费用小票-实施方案.md §5.6. kimi/codex do not have
                    // equivalent status-line hooks so we skip them here.
                    if provider == "claude" {
                        crate::commands_statusline::ensure_claude_statusline_installed();
                    }
                }
                return Ok(());
            }
            "failed" => {
                let err = resp["error"].as_str().unwrap_or("Login failed");
                if !json_mode {
                    eprintln!("{} {}", "\u{25c6}".red(), err);
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
    // Per-request timeout prevents hanging on network issues.
    let request_timeout = std::time::Duration::from_secs(10);

    // Network error backoff: start at 5s, double up to 60s max. Reset on success.
    // Bail out after MAX_CONSECUTIVE_NET_ERRORS to prevent infinite loops when
    // the network is persistently broken.
    const MAX_CONSECUTIVE_NET_ERRORS: u32 = 6;
    let mut net_error_count: u32 = 0;
    let mut backoff = std::time::Duration::from_secs(5);

    loop {
        std::thread::sleep(poll_interval);

        if start.elapsed() > timeout {
            return Err("Device code expired (5min timeout). Run `aikey auth login` again.".into());
        }

        let resp_result = ureq::post(&format!("{}/oauth/poll", base))
            .timeout(request_timeout)
            .set("Content-Type", "application/json")
            .send_string(&serde_json::json!({
                "session_id": session_id,
            }).to_string());

        match resp_result {
            Ok(r) => {
                // Ok path returns below, so no need to reset net_error_count/backoff here.
                // Err(Status) below handles the reset because it may loop back via `continue`.

                // 200 = success (LoginResult with account_id, display_identity, etc.)
                let resp: serde_json::Value = r.into_json()?;
                let account_id = resp["account_id"].as_str().unwrap_or("");
                let display = resp["display_identity"].as_str().unwrap_or(account_id);

                // Generate route token for per-request proxy routing (API gateway).
                if !account_id.is_empty() {
                    let _ = crate::storage::ensure_provider_account_route_token(account_id);
                }

                if json_mode {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    eprintln!();
                    eprintln!("{} Logged in as {} ({})", "\u{25c6}".green(), display.bold(), provider);

                    // D13: prompt for display name if no email
                    if display.is_empty() || !display.contains('@') {
                        prompt_display_identity(base, account_id)?;
                    }

                    // Auto-install Claude Code status line integration on first
                    // successful Claude OAuth login. Idempotent — safe to re-run.
                    // See 费用小票-实施方案.md §5.6.
                    if provider == "claude" {
                        crate::commands_statusline::ensure_claude_statusline_installed();
                    }
                }
                return Ok(());
            }
            Err(ureq::Error::Status(code, resp)) => {
                // Broker responded → network is fine, reset backoff counters.
                net_error_count = 0;
                backoff = std::time::Duration::from_secs(5);

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
                    eprintln!("{} {} (HTTP {})", "\u{25c6}".red(), msg, code);
                }
                return Err(msg.to_string().into());
            }
            Err(e) => {
                // Network error: exponential backoff + bail out after N consecutive failures.
                net_error_count += 1;
                if net_error_count >= MAX_CONSECUTIVE_NET_ERRORS {
                    if !json_mode {
                        eprintln!();
                        eprintln!("  {} Network errors during polling ({} in a row): {}",
                            "\u{25c6}".red(), net_error_count, e);
                        eprintln!("  \u{2502} Check: proxy is running, network is reachable");
                    }
                    return Err(format!("Polling aborted after {} network errors: {}", net_error_count, e).into());
                }
                if !json_mode {
                    eprintln!();
                    eprintln!("  {} network error ({}), retrying in {}s... [{}/{}]",
                        "\u{25c6}".yellow(), e, backoff.as_secs(), net_error_count, MAX_CONSECUTIVE_NET_ERRORS);
                }
                std::thread::sleep(backoff);
                backoff = std::cmp::min(backoff * 2, std::time::Duration::from_secs(60));
                continue;
            }
        }
    }
}

/// D13: Prompt user for display identity (Kimi accounts have no email).
/// Extract the `state=` query parameter from an OAuth authorization URL.
/// Handles multiple occurrences and URL encoding; returns None if not present.
fn extract_state_param(auth_url: &str) -> Option<String> {
    let query = auth_url.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        if kv.next() == Some("state") {
            if let Some(v) = kv.next() {
                // Decode %XX sequences minimally (state is base64url, usually no %).
                return Some(v.replace("%3D", "=").replace("%23", "#"));
            }
        }
    }
    None
}

fn prompt_display_identity(base: &str, account_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_DISPLAY_LEN: usize = 256;

    eprint!("\nEnter a display name for this account (e.g. email or alias, Enter to skip): ");
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().lock().read_line(&mut input)?;
    let input = input.trim();

    // Validation: skip empty, reject too-long, reject whitespace-only (already trimmed).
    if input.is_empty() {
        eprintln!("  {} Skipped. Update later via API.", "\u{2502}".dimmed());
        return Ok(());
    }
    if input.len() > MAX_DISPLAY_LEN {
        return Err(format!("Display name too long ({} chars, max {}).", input.len(), MAX_DISPLAY_LEN).into());
    }
    // Reject control chars that would corrupt logs/display.
    if input.chars().any(|c| c.is_control()) {
        return Err("Display name contains control characters.".into());
    }

    let resp = ureq::post(&format!("{}/oauth/accounts/{}/display-identity", base, account_id))
        .timeout(std::time::Duration::from_secs(10))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({"display_identity": input}).to_string());

    match resp {
        Ok(_) => {
            eprintln!("{} Display name set: {}", "\u{25c6}".green(), input);
            Ok(())
        }
        Err(e) => {
            // Server rejected or network error — surface it instead of silent "success".
            eprintln!("  {} Failed to save display name: {}", "\u{25c6}".red(), e);
            eprintln!("  \u{2502} Account created; you can retry via API later.");
            Ok(()) // Don't fail the login flow — account creation already succeeded.
        }
    }
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
            let tier = a.account_tier.as_deref().unwrap_or("-").to_string();
            let token_expires = storage::get_provider_token_expires_at(&a.provider_account_id)
                .ok().flatten();
            let expires = token_expires
                .map(|exp| {
                    let rem = exp - now;
                    if rem <= 0 { "expired".to_string() }
                    else if rem > 86400 { format!("{}d", rem / 86400) }
                    else if rem > 3600 { format!("{}h", rem / 3600) }
                    else { format!("{}m", rem / 60) }
                }).unwrap_or_else(|| "-".to_string());
            // Unified status: valid (empty), expired, invalid — same as `aikey list`
            let status_display = match a.status.as_str() {
                "active" | "idle" => {
                    if token_expires.map_or(false, |exp| exp <= now) {
                        "expired".to_string()
                    } else {
                        String::new() // valid → not displayed
                    }
                }
                "reauth_required" | "expired" => "expired".to_string(),
                _ => "invalid".to_string(),
            };
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
            "\u{25c6}".green(), target.provider, display.bold(), canonical);
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
        eprintln!("{} Logged out from {}/{}", "\u{25c6}".green(), acct.provider, display);
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
        eprintln!("  {} No OAuth accounts", "\u{25c6}".cyan());
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
    // Try exact ID match first (fastest path).
    if let Ok(Some(acct)) = storage::get_provider_account(id_or_display) {
        return Ok(acct);
    }

    // Match by priority: exact > prefix > substring.
    // Why prioritized: substring `alice` matches both `alice@x.com` AND `malice@x.com`,
    // which can silently target the wrong account on logout/use.
    let all = storage::list_provider_accounts()?;

    // Tier 1: exact match on display_identity or provider_account_id.
    let exact: Vec<_> = all.iter()
        .filter(|a|
            a.display_identity.as_deref() == Some(id_or_display)
            || a.provider_account_id == id_or_display
        )
        .cloned()
        .collect();
    if exact.len() == 1 {
        return Ok(exact.into_iter().next().unwrap());
    }
    if exact.len() > 1 {
        return Err(ambiguous_match_err(id_or_display, &exact));
    }

    // Tier 2: exact provider match (e.g. `claude` matches all Claude accounts).
    let by_provider: Vec<_> = all.iter()
        .filter(|a| a.provider == id_or_display)
        .cloned()
        .collect();
    if by_provider.len() == 1 {
        return Ok(by_provider.into_iter().next().unwrap());
    }
    if by_provider.len() > 1 {
        return Err(ambiguous_match_err(id_or_display, &by_provider));
    }

    // Tier 3: prefix match on display_identity or provider_account_id.
    // Safer than contains — `alice` matches `alice@x.com` but NOT `malice@x.com`.
    let prefix: Vec<_> = all.into_iter()
        .filter(|a|
            a.display_identity.as_deref().map_or(false, |d| d.starts_with(id_or_display))
            || a.provider_account_id.starts_with(id_or_display)
        )
        .collect();
    match prefix.len() {
        0 => Err(format!("Account '{}' not found. Run: aikey auth list", id_or_display).into()),
        1 => Ok(prefix.into_iter().next().unwrap()),
        _ => Err(ambiguous_match_err(id_or_display, &prefix)),
    }
}

fn ambiguous_match_err(needle: &str, matches: &[storage::ProviderAccountInfo]) -> Box<dyn std::error::Error> {
    eprintln!("Multiple accounts match '{}':", needle);
    for a in matches {
        let display = a.display_identity.as_deref().unwrap_or("-");
        eprintln!("  {} — {}/{}", a.provider_account_id, a.provider, display);
    }
    "Please specify the full account ID or unique prefix.".into()
}

/// Re-export from commands_account so existing call sites in this file stay
/// unchanged. The helper itself lives in the lib-accessible module because
/// connectivity-suite resolvers (lib scope) need the same normalization.
use crate::commands_account::oauth_provider_to_canonical;

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
