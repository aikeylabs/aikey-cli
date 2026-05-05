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
        AuthAction::Login { provider, alias } => {
            let provider = match provider {
                Some(p) => p.clone(),
                None => pick_oauth_provider()?,
            };
            handle_login(&provider, alias.as_deref(), proxy_port, json_mode)
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

fn handle_login(provider: &str, alias: Option<&str>, proxy_port: u16, json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
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
        "setup_token" => login_setup_token(&base, &session_id, &resp, provider, alias, proxy_port, json_mode),
        "auth_code" => login_auth_code(&base, &session_id, &resp, provider, alias, proxy_port, json_mode),
        "device_code" => login_device_code(&base, &session_id, &resp, provider, alias, proxy_port, json_mode),
        _ => Err(format!("Unknown flow type: {}", flow_type).into()),
    }
}

/// Claude: Setup Token — open browser, user pastes code#state
fn login_setup_token(
    base: &str, session_id: &str, resp: &serde_json::Value,
    provider: &str, alias: Option<&str>, _proxy_port: u16, json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_url = resp["auth_url"].as_str().unwrap_or("");

    let clipboard_ok = try_copy_to_clipboard(auth_url);

    if !json_mode {
        eprintln!();
        eprintln!("  {} Note: Claude OAuth requires a Pro or Max subscription.", "\u{25c6}".cyan());
        eprintln!("  {} Open this URL and click 'Authorize':", "\u{2502}".dimmed());
        eprintln!("  {}", "\u{2502}".dimmed());
        eprintln!("  {}   {}", "\u{2502}".dimmed(), auth_url);
        eprintln!("  {}", "\u{2502}".dimmed());
        if clipboard_ok {
            eprintln!("  {} {}", "\u{2502}".dimmed(), "Auth URL copied to clipboard.".dimmed());
            eprintln!("  {}", "\u{2502}".dimmed());
        }
    }

    // Try to open browser
    let _ = open_browser(auth_url);

    // Pasting can fail for two reasons: the user copies only the `code` part
    // (no `#state` suffix), or the state value doesn't match. Both used to
    // dead-end the flow and force the user to re-run `aikey auth login`. We
    // now allow up to MAX_PASTE_ATTEMPTS pastes within a single login session,
    // re-prompting on incomplete pastes and offering retry-as-default on a
    // CSRF state mismatch (the y/N confirmation is preserved because state
    // mismatch is a real security signal, not just a typo).
    let code_state = read_code_with_retry(auth_url, json_mode)?;

    // Phase 2: submit code
    submit_code_and_finish(base, session_id, &code_state, provider, alias, json_mode)
}

const MAX_PASTE_ATTEMPTS: u32 = 3;

/// Outcome of validating a `code#state` paste against the expected state from
/// the auth_url. Pulled out as an enum so the branching is unit-testable
/// without a real terminal / prompt_hidden round trip.
#[derive(Debug, PartialEq, Eq)]
enum PasteCheck {
    /// Submit the pasted code as-is (state matches, or no expected state to compare).
    Accept,
    /// `#state` segment is missing or empty — likely partial paste, re-prompt.
    MissingState,
    /// State value differs from expected — CSRF signal, gate behind y/N.
    StateMismatch,
}

fn classify_paste(expected_state: Option<&str>, pasted: &str) -> PasteCheck {
    let Some(expected) = expected_state else { return PasteCheck::Accept };
    if expected.is_empty() {
        return PasteCheck::Accept;
    }
    let pasted_state = pasted.split('#').nth(1).unwrap_or("");
    if pasted_state == expected {
        return PasteCheck::Accept;
    }
    if pasted_state.is_empty() {
        return PasteCheck::MissingState;
    }
    PasteCheck::StateMismatch
}

/// Prompts for the OAuth `code#state` paste with up to `MAX_PASTE_ATTEMPTS`
/// retries, performing client-side state validation against `auth_url`.
///
/// Behavior per attempt:
/// - Empty paste → cancel immediately (user pressed Enter without input).
/// - Missing `#state` (likely partial copy) → re-prompt without y/N.
/// - State value mismatch → CSRF warning, prompt `[r]etry / [y]continue / [n]cancel`,
///   default = retry. The y/n confirmation is preserved because state mismatch
///   is a real security signal that warrants explicit user override.
/// - Match (or no expected state available) → return the pasted code.
///
/// Returns `Err` when the user cancels, runs out of attempts, or hits an I/O error.
fn read_code_with_retry(auth_url: &str, json_mode: bool) -> Result<String, Box<dyn std::error::Error>> {
    let expected_state = if json_mode { None } else { extract_state_param(auth_url) };

    for attempt in 1..=MAX_PASTE_ATTEMPTS {
        let prompt = if attempt == 1 {
            "  \u{25c6} Paste the code (format: code#state): ".to_string()
        } else {
            format!(
                "  \u{25c6} Paste the code again [attempt {}/{}] (format: code#state, empty to cancel): ",
                attempt, MAX_PASTE_ATTEMPTS
            )
        };
        let pasted = crate::prompt_hidden(&prompt)
            .map_err(|e| format!("Failed to read code: {}", e))?;
        let pasted = pasted.trim().to_string();

        if pasted.is_empty() {
            return Err("No code provided. Login cancelled.".into());
        }

        match classify_paste(expected_state.as_deref(), &pasted) {
            PasteCheck::Accept => return Ok(pasted),
            PasteCheck::MissingState => {
                // Partial paste — most common cause is the user copying only
                // up to a whitespace/control char. Re-prompt without y/N noise.
                eprintln!(
                    "  {} Pasted code is missing the `#state` suffix — please paste the full `code#state` value.",
                    "\u{25c6}".yellow()
                );
                if attempt == MAX_PASTE_ATTEMPTS {
                    return Err("Too many invalid pastes. Run 'aikey auth login' again.".into());
                }
                continue;
            }
            PasteCheck::StateMismatch => {}
        }

        // State mismatch — keep the y/N gate because this is a CSRF signal.
        // Default action changes from "cancel" to "retry": pressing Enter
        // re-prompts instead of bailing.
        eprintln!(
            "  {} state mismatch — pasted state differs from expected (CSRF risk)",
            "\u{25c6}".yellow()
        );
        if attempt == MAX_PASTE_ATTEMPTS {
            // Last attempt: don't offer retry, just continue/cancel.
            eprint!("  {} Continue anyway? [y/N] ", "\u{25c6}".yellow());
            io::stderr().flush()?;
            let mut confirm = String::new();
            io::stdin().lock().read_line(&mut confirm)?;
            let answer = confirm.trim().to_ascii_lowercase();
            if answer == "y" || answer == "yes" {
                return Ok(pasted);
            }
            return Err("Login cancelled due to state mismatch.".into());
        }
        eprint!(
            "  {} [R]etry paste / [y] continue anyway / [n] cancel (default R): ",
            "\u{25c6}".yellow()
        );
        io::stderr().flush()?;
        let mut confirm = String::new();
        io::stdin().lock().read_line(&mut confirm)?;
        let answer = confirm.trim().to_ascii_lowercase();
        match answer.as_str() {
            "y" | "yes" => return Ok(pasted),
            "n" | "no" => return Err("Login cancelled due to state mismatch.".into()),
            _ => continue, // "", "r", "retry", anything else → re-prompt.
        }
    }
    Err("Too many invalid pastes. Run 'aikey auth login' again.".into())
}

/// Best-effort clipboard copy. Returns false on platforms where the clipboard
/// is unavailable (headless servers, CI containers, missing xclip/wl-copy)
/// without aborting the login flow.
fn try_copy_to_clipboard(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    crate::executor::copy_to_clipboard(text).is_ok()
}

/// Codex: Auth Code — open browser, localhost callback auto-receives code
fn login_auth_code(
    base: &str, session_id: &str, resp: &serde_json::Value,
    provider: &str, alias: Option<&str>, _proxy_port: u16, json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_url = resp["auth_url"].as_str().unwrap_or("");

    let clipboard_ok = try_copy_to_clipboard(auth_url);

    if !json_mode {
        eprintln!();
        eprintln!("  {} Opening browser for {} login...", "\u{25c6}".cyan(), provider);
        if clipboard_ok {
            eprintln!("  {} {}", "\u{2502}".dimmed(), "Auth URL copied to clipboard.".dimmed());
        }
        eprintln!("  {}", "\u{2502}".dimmed());
    }
    let _ = open_browser(auth_url);

    if !json_mode {
        eprintln!("  {} Waiting for authorization... (Ctrl+C to cancel)", "\u{2502}".dimmed());
    }

    // Poll for completion (proxy handles the callback)
    poll_login_status(base, session_id, provider, alias, json_mode)
}

/// Kimi: Device Code — show user_code, poll for completion
fn login_device_code(
    base: &str, session_id: &str, resp: &serde_json::Value,
    provider: &str, alias: Option<&str>, _proxy_port: u16, json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let user_code = resp["user_code"].as_str().unwrap_or("");
    let verify_url = resp["verification_url"].as_str().unwrap_or("");

    let clipboard_ok = try_copy_to_clipboard(verify_url);

    if !json_mode {
        eprintln!();
        eprintln!("  {} Open this URL and enter the code:", "\u{25c6}".cyan());
        eprintln!("  {}   URL:  {}", "\u{2502}".dimmed(), verify_url);
        eprintln!("  {}   Code: {}", "\u{2502}".dimmed(), user_code.bold());
        if clipboard_ok {
            eprintln!("  {}   {}", "\u{2502}".dimmed(), "Verification URL copied to clipboard.".dimmed());
        }
        eprintln!("  {}", "\u{2502}".dimmed());
    }

    let _ = open_browser(verify_url);

    if !json_mode {
        eprintln!("  {} Waiting for authorization...", "\u{2502}".dimmed());
    }

    // Device Code: use POST /oauth/poll (triggers provider poll on each call).
    // Why not GET /oauth/status: status is read-only and won't drive device-code progress.
    poll_device_code(base, session_id, provider, alias, json_mode)
}

/// Submit code#state and handle the result (used by setup_token flow).
fn submit_code_and_finish(
    base: &str, session_id: &str, code_state: &str,
    provider: &str, alias: Option<&str>, json_mode: bool,
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

    // Auto-bind as Primary for the freshly-logged-in provider, then
    // refresh active.env. Without this, `aikey auth login <provider>`
    // saves the OAuth account but leaves shell + proxy still pointed at
    // whichever credential was Primary before — UX divergence from the
    // personal-key path, which auto-binds in `Commands::Add`
    // (main.rs:1093-1099). `auto_assign_primaries_for_key` is
    // conservative: only fills providers that currently have no Primary,
    // so re-logging into a provider where another credential is already
    // Primary won't silently steal the binding (use `aikey use <display>`
    // for the explicit switch). `provider` here is the broker code
    // (claude/codex/kimi); the helper canonicalizes internally.
    if !account_id.is_empty() {
        let _ = crate::profile_activation::auto_assign_primaries_for_key(
            "personal_oauth_account",
            account_id,
            &[provider.to_string()],
        );
        let _ = crate::profile_activation::refresh_implicit_profile_activation();
    }

    // Install the shell hook so the next `claude`/`codex`/`kimi` invocation
    // routes through `aikey_preflight` (connectivity probe) before exec.
    // Why call it here: `aikey auth login <provider>` is a typical first-key
    // onboarding path (the user did not run `aikey add`), and `aikey use`
    // returns "No changes." in this scenario (auto-bind already wrote the
    // primary), so its hook-install branch never fires either. Without this
    // call, the user runs `claude` against the bare binary with no preflight
    // and no aikey injection — defeating the whole proxy gateway.
    // ensure_shell_hook is idempotent and JSON-mode safe.
    //
    // We MUST print the returned message (not discard it): on fresh install
    // it tells the user to run `source ~/.zshrc` for the wrapper to take
    // effect in the current shell. Without that hint, user-report
    // 2026-04-30 round 2 — auth-login appears successful, hook block lands
    // in .zshrc, but the running zsh process never reloads it, so `claude`
    // still bypasses the wrapper with no clue why.
    let hook_msg = if !json_mode {
        crate::commands_account::ensure_shell_hook(false)
    } else {
        None
    };

    if json_mode {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let days = expires_in / 86400;
        eprintln!("  {} Logged in as {} ({}), expires in {} days",
            "\u{25c6}".green(), display.bold(), provider, days);

        // Stage 11+: --alias 非空则直接写;否则旧逻辑(display 为空/非 email 时 prompt)
        if alias.is_some() || display.is_empty() || !display.contains('@') {
            resolve_display_identity(base, account_id, alias)?;
        }

        // Surface the hook-install message AFTER login confirmation so the
        // "▲ Run source ~/.zshrc" hint isn't buried under the OAuth banner.
        if let Some(msg) = hook_msg {
            eprintln!("{}", msg);
        }
    }

    Ok(())
}

/// Poll GET /oauth/status until success or failure (for auth_code and device_code flows).
fn poll_login_status(
    base: &str, session_id: &str, provider: &str, alias: Option<&str>, json_mode: bool,
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

                // Auto-bind as Primary + refresh active.env. See identical
                // block in `login_setup_token` for rationale (mirrors
                // `Commands::Add`'s post-write step so OAuth login produces
                // the same "ready to use" state). Conservative: only assigns
                // if no Primary exists for this provider yet.
                if !account_id.is_empty() {
                    let _ = crate::profile_activation::auto_assign_primaries_for_key(
                        "personal_oauth_account",
                        account_id,
                        &[provider.to_string()],
                    );
                    let _ = crate::profile_activation::refresh_implicit_profile_activation();
                }

                // Install the shell hook (preflight wrapper for claude/codex/kimi).
                // See identical block in `login_setup_token` for rationale —
                // both auth-login paths must install the hook so the user's
                // very next `claude`/`codex` invocation goes through the
                // proxy with a connectivity probe. Capture the message so the
                // "Run source ~/.zshrc" hint reaches the user.
                let hook_msg = if !json_mode {
                    crate::commands_account::ensure_shell_hook(false)
                } else {
                    None
                };

                if json_mode {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    eprintln!("{} Logged in as {} ({})", "\u{25c6}".green(), display.bold(), provider);

                    // Stage 11+: --alias 非空则直接写;否则旧逻辑
                    if alias.is_some() || display.is_empty() || !display.contains('@') {
                        resolve_display_identity(base, account_id, alias)?;
                    }

                    // Auto-install Claude Code status line integration on first
                    // successful Claude OAuth login. Idempotent — safe to re-run.
                    // See 费用小票-实施方案.md §5.6. kimi/codex do not have
                    // equivalent status-line hooks so we skip them here.
                    if provider == "claude" {
                        crate::commands_statusline::ensure_claude_statusline_installed();
                    }

                    // Surface the hook-install message AFTER login + statusline
                    // so the "▲ Run source ~/.zshrc" hint sits at the bottom
                    // where the user is currently looking.
                    if let Some(msg) = hook_msg {
                        eprintln!("{}", msg);
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
    base: &str, session_id: &str, provider: &str, alias: Option<&str>, json_mode: bool,
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

                    // Stage 11+: --alias 非空则直接写;否则旧逻辑
                    if alias.is_some() || display.is_empty() || !display.contains('@') {
                        resolve_display_identity(base, account_id, alias)?;
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

/// v4.1 Stage 11+: Resolve display name — 有 CLI `--alias` 参数则直接用,否则交互 prompt。
///
/// 被 3 个 OAuth flow(setup_token / auth_code / device_code)共用,取代旧的
/// `prompt_display_identity` 调用位置。non-interactive 模式下可以完全免交互。
fn resolve_display_identity(
    base: &str,
    account_id: &str,
    alias: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(a) = alias {
        return set_display_identity(base, account_id, a);
    }
    prompt_display_identity(base, account_id)
}

/// 写入 display_identity 到 broker(alias 已确定,跳过交互 prompt)
fn set_display_identity(base: &str, account_id: &str, alias: &str) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_DISPLAY_LEN: usize = 256;
    let input = alias.trim();
    if input.is_empty() {
        return Err("--alias is empty after trim.".into());
    }
    if input.len() > MAX_DISPLAY_LEN {
        return Err(format!("--alias too long ({} chars, max {}).", input.len(), MAX_DISPLAY_LEN).into());
    }
    if input.chars().any(|c| c.is_control()) {
        return Err("--alias contains control characters.".into());
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
            eprintln!("  {} Failed to save display name: {}", "\u{25c6}".red(), e);
            eprintln!("  \u{2502} Account created; you can retry via API later.");
            Ok(()) // Don't fail the login flow — account creation already succeeded.
        }
    }
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

    // Update per-provider binding via the shared canonical-write helper
    // (2026-04-24 rule — single source of truth for `user_profile_provider_
    // bindings` writes, handles stale alias cleanup as a side effect).
    crate::commands_account::write_bindings_canonical(
        &[target.provider.clone()], // raw — helper normalizes internally
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

#[cfg(test)]
mod tests {
    use super::{classify_paste, PasteCheck};

    // Regression guard for user report 2026-04-30:
    //
    //   "为什么运行 claude 没有触发连通性测试呢？"
    //
    // After `aikey auth login claude` + `aikey use` (which returned "No
    // changes." because auth-login already auto-bound primary), the user
    // ran `claude` and the preflight wrapper did not fire — because no
    // codepath had called ensure_shell_hook to write the v3 source line
    // into ~/.zshrc. This test pins that BOTH login completion paths
    // (login_setup_token and poll_login_status) call ensure_shell_hook.
    // Source-text check is intentional: a real end-to-end test needs an
    // OAuth provider mock; this catches the regression of someone removing
    // the call without recreating the bug.

    const SOURCE: &str = include_str!("mod.rs");

    // ── classify_paste: pure-function unit tests ──────────────────────────
    // The retry loop in read_code_with_retry depends on these branches.
    // Source-text guards below pin the loop wiring; here we cover the
    // semantic decisions.

    #[test]
    fn classify_paste_accepts_when_expected_state_unknown() {
        // json_mode and malformed auth_url both produce expected_state=None;
        // we must not hold up the user — submit and let the broker decide.
        assert_eq!(classify_paste(None, "raw_code_without_hash"), PasteCheck::Accept);
        assert_eq!(classify_paste(None, "code#anything"), PasteCheck::Accept);
    }

    #[test]
    fn classify_paste_accepts_when_expected_state_empty_string() {
        // Defensive: extract_state_param returned Some("") — treat same as None.
        assert_eq!(classify_paste(Some(""), "code#whatever"), PasteCheck::Accept);
    }

    #[test]
    fn classify_paste_accepts_on_exact_state_match() {
        assert_eq!(
            classify_paste(Some("abc123"), "code_value#abc123"),
            PasteCheck::Accept
        );
    }

    #[test]
    fn classify_paste_flags_missing_state_when_no_hash_in_paste() {
        // User copied only the `code` half, missing `#state`. The retry loop
        // must re-prompt without offering y/N (no CSRF signal yet — likely
        // a partial paste from an over-eager triple-click).
        assert_eq!(
            classify_paste(Some("abc123"), "code_value_only"),
            PasteCheck::MissingState
        );
    }

    #[test]
    fn classify_paste_flags_missing_state_when_hash_present_but_empty() {
        // Edge case: `code#` with empty state. Same UX path as no-hash.
        assert_eq!(
            classify_paste(Some("abc123"), "code_value#"),
            PasteCheck::MissingState
        );
    }

    #[test]
    fn classify_paste_flags_state_mismatch_on_wrong_value() {
        // Real CSRF signal: state present but doesn't match. Must surface
        // the y/N gate, not auto-retry.
        assert_eq!(
            classify_paste(Some("abc123"), "code_value#WRONG"),
            PasteCheck::StateMismatch
        );
    }

    // ── Source-text guards for the retry loop and clipboard wiring ────────

    #[test]
    fn auth_url_copied_to_clipboard_in_all_three_flows() {
        // setup_token (Claude), auth_code (Codex), device_code (Kimi) must
        // each call try_copy_to_clipboard so the user can paste the URL on
        // another device when the auto-launched browser doesn't fit.
        // Three call sites in production code + we don't count any test code.
        let prod_only = SOURCE.split("#[cfg(test)]").next().unwrap_or(SOURCE);
        let calls = prod_only.matches("try_copy_to_clipboard(").count();
        assert!(
            calls >= 4,
            "expected at least 4 try_copy_to_clipboard call sites \
             (1 helper definition + 3 flow call sites: login_setup_token, \
              login_auth_code, login_device_code); found {}",
            calls
        );
    }

    #[test]
    fn paste_retry_loop_is_wired_with_max_attempts() {
        // Pins the retry-on-bad-paste UX so a future refactor doesn't silently
        // revert to the old "first paste fails → cancel" behavior.
        assert!(
            SOURCE.contains("MAX_PASTE_ATTEMPTS"),
            "MAX_PASTE_ATTEMPTS constant must exist — drives the paste retry loop \
             that lets users re-paste without re-running `aikey auth login`."
        );
        assert!(
            SOURCE.contains("read_code_with_retry"),
            "read_code_with_retry must be the entrypoint for the setup_token paste flow."
        );
    }

    #[test]
    fn state_mismatch_prompt_defaults_to_retry_not_cancel() {
        // Behavioral pin: on a CSRF state mismatch the prompt offers retry,
        // continue, or cancel — and bare-Enter (default) means retry. Old
        // behavior was "[y/N]" with default = cancel, which forced the user
        // to re-run `aikey auth login` after a single mispaste.
        assert!(
            SOURCE.contains("[R]etry paste"),
            "state-mismatch prompt must surface retry as the default action, \
             not silently cancel like the pre-2026-04-30 [y/N] gate."
        );
    }

    #[test]
    fn auth_login_calls_ensure_shell_hook_in_both_paths() {
        // Both completion paths must install the hook so the user's next
        // `claude`/`codex` invocation routes through aikey_preflight.
        let occurrences = SOURCE
            .matches("commands_account::ensure_shell_hook(false)")
            .count();
        assert!(
            occurrences >= 2,
            "expected at least 2 calls to ensure_shell_hook(false) in commands_auth/mod.rs \
             (login_setup_token + poll_login_status); found {}. \
             Removing these calls means `aikey auth login` won't install the v3 hook \
             block in ~/.zshrc — the user's next `claude` runs the bare binary \
             with no preflight or proxy injection. See bugfix \
             2026-04-30-auth-login-skips-shell-hook-install.md.",
            occurrences
        );
    }
}
