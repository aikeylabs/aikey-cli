#[allow(dead_code)] mod active_env_migration;
#[allow(dead_code)] mod credential_type;
#[allow(dead_code)] mod team_token_normalize;
#[allow(dead_code)] mod storage;
#[allow(dead_code)] mod storage_acl;
#[allow(dead_code)] mod provider_registry;
mod crypto;
mod session;
mod executor;
#[allow(dead_code)] mod synapse;
#[allow(dead_code)] mod audit;
mod ratelimit;
#[allow(dead_code)] mod json_output;
#[allow(dead_code)] mod error_codes;
mod config;
#[allow(dead_code)] mod env_resolver;
#[allow(dead_code)] mod env_renderer;
#[allow(dead_code)] mod commands_project;
#[allow(dead_code)] mod connectivity;
// mod commands_env; // removed: env commands dropped
mod commands_proxy;
// Layer 1 (state-machine read path) + Layer 2 (write path). Stage 1-2
// of proxy lifecycle state machine refactor; commands_proxy.rs is in
// the process of being migrated to thin shells over these.
mod proxy_state;
mod proxy_proc;
mod proxy_lifecycle;
mod proxy_events;
#[allow(dead_code)] mod commands_account;
// migrations module is in lib.rs (used by both main.rs and executor.rs)
use aikeylabs_aikey_cli::migrations;
#[allow(dead_code)] mod platform_client;
// mod profiles; // removed: profile commands dropped
// mod core; // removed: profile-based resolver dropped
#[allow(dead_code)] mod global_config;
mod providers;
mod resolver;
#[allow(dead_code)] mod events;
#[allow(dead_code)] mod observability;
mod ui_frame;
#[allow(dead_code)] mod ui_select;
#[cfg(windows)] #[allow(dead_code)] mod ui_select_windows;
#[cfg(windows)] #[allow(dead_code)] mod prompt_hidden_windows;
#[cfg(windows)] #[allow(dead_code)] mod ui_frame_windows;
mod proxy_env;
#[allow(dead_code)] mod profile_activation;
mod commands_auth;
mod commands_statusline;
mod commands_watch;
mod commands_internal;
mod commands_import;
mod commands_init;
#[allow(dead_code)] mod usage_wal;
mod cli;

use cli::*;
use clap::Parser;
use secrecy::{ExposeSecret, SecretString};
use std::env;
use std::io::{self, IsTerminal, Write};
use zeroize::Zeroizing;
use aikeylabs_aikey_cli::prompt_hidden;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise process-global trace context (trace_id, span_id, command_id).
    // This must be called before any logging or proxy calls.
    observability::init_trace();

    let cli = Cli::try_parse().unwrap_or_else(|err| {
        // Intercept "unrecognized subcommand" errors and show a friendly message
        // with fuzzy suggestions instead of the raw clap output.
        use clap::error::ErrorKind;

        // Intercept top-level --help / -h: use our styled version.
        // Subcommand help (e.g. `aikey add --help`) still uses clap's default.
        if matches!(err.kind(), ErrorKind::DisplayHelp) {
            // Check if this is the top-level help (no subcommand context).
            // Clap's rendered help for subcommands contains "Usage: aikey <subcmd>",
            // while top-level contains "Usage: aikey [OPTIONS]".
            let rendered = err.to_string();
            if rendered.contains("aikey [OPTIONS]") {
                print_short_help();
                std::process::exit(0);
            }
            // Subcommand help — print clap's output, then append detailed notes.
            // Extract command path from "Usage: aikey <cmd> ..." line.
            let cmd_path = rendered.lines()
                .find(|l| l.starts_with("Usage: aikey "))
                .and_then(|l| {
                    // "Usage: aikey add [OPTIONS] <ALIAS>" → extract "add"
                    // "Usage: aikey proxy start [OPTIONS]" → extract "proxy start"
                    let after = l.strip_prefix("Usage: aikey ")?;
                    let parts: Vec<&str> = after.split_whitespace()
                        .take_while(|w| !w.starts_with('[') && !w.starts_with('<') && !w.starts_with('-'))
                        .collect();
                    if parts.is_empty() { None } else { Some(parts.join(" ")) }
                });

            // Print clap's rendered help first.
            eprint!("{}", rendered);

            // Append detailed notes if available.
            if let Some(ref cmd) = cmd_path {
                if let Some(notes) = command_detail_notes(cmd) {
                    eprintln!();
                    eprintln!("{}", notes);
                }
            }
            std::process::exit(0);
        }

        if matches!(err.kind(), ErrorKind::InvalidSubcommand | ErrorKind::UnknownArgument) {
            // Extract the bad token from the error message (clap embeds it in single quotes).
            let bad = err.to_string();
            let token = bad
                .split('\'')
                .nth(1)
                .unwrap_or("?")
                .to_string();

            // All top-level subcommand names for fuzzy matching.
            const KNOWN: &[&str] = &[
                "add", "get", "delete", "list", "update", "test", "export",
                "run", "use", "whoami", "login", "logout", "web", "browse", "master",
                "init", "doctor", "env", "key", "account", "secret",
                "project", "proxy",
                "change-password", "quickstart", "logs",
            ];

            let suggestion = KNOWN.iter()
                .filter_map(|s| {
                    let score = similarity(&token.to_lowercase(), s);
                    if score >= 0.5 { Some((*s, score)) } else { None }
                })
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

            eprintln!("error: unrecognized command '{}'", token);
            if let Some((hint, _)) = suggestion {
                eprintln!();
                eprintln!("  Did you mean '{}'?  Try: aikey {} --help", hint, hint);
            }

            // Why: `auth logout`, `auth use`, `auth status` each take a single
            // positional. When a user types `aikey auth logout kimi account3`
            // (OAuth display name with a space), the shell splits it into two
            // argv entries; the first is absorbed and the second surfaces here
            // as an "unrecognized command". Detect that shape and coach the
            // user to quote or use an account ID, which is far more actionable
            // than the generic fuzzy hint above.
            let argv: Vec<String> = std::env::args().skip(1).collect();
            if let Some(pos) = argv.iter().position(|a| a == "auth") {
                let rest = &argv[pos + 1..];
                let sub = rest.first().map(String::as_str);
                let takes_single_positional = matches!(sub, Some("logout") | Some("use") | Some("status"));
                // Count positional args after the sub (stop at first flag).
                let positionals = rest.iter().skip(1)
                    .take_while(|a| !a.starts_with('-'))
                    .count();
                if takes_single_positional && positionals >= 2 {
                    let joined = rest.iter().skip(1)
                        .take_while(|a| !a.starts_with('-'))
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!();
                    eprintln!("  Hint: if this is an OAuth account display name with spaces, quote it:");
                    eprintln!("      aikey auth {} \"{}\"", sub.unwrap(), joined);
                    eprintln!("  Or pass the account ID (see `aikey auth list`) which never has spaces.");
                }
            }

            eprintln!();
            eprintln!("  Run 'aikey --help' for a list of all commands.");
            std::process::exit(2);
        }
        // All other clap errors (missing required args, bad values, etc.) — print as-is.
        err.exit()
    });

    // Handle --version flag
    if cli.version {
        if cli.json {
            json_output::success(cli::build_version_json());
        } else {
            print_banner();
        }
        return Ok(());
    }

    // Handle --detail flag
    if cli.detail {
        print_detailed_help();
        return Ok(());
    }

    // Ensure a command was provided
    if cli.command.is_none() {
        if cli.json {
            json_output::error("No command specified. Use --help for usage information.", 1);
        } else {
            use colored::Colorize;
            print_banner();
            eprintln!();
            eprintln!("  {}", "Get started:".bold());
            eprintln!("    aikey quickstart                       {}", "See what to do next (state-aware)".dimmed());
            eprintln!("    aikey add                              {}", "Add a personal API key to the local vault".dimmed());
            eprintln!("    aikey auth login <claude|codex|kimi>   {}", "Sign in with an OAuth provider account".dimmed());
            eprintln!("    aikey list                             {}", "Show your keys (personal, team, OAuth)".dimmed());
            eprintln!("    aikey route                            {}", "Print proxy config for AI clients".dimmed());
            eprintln!("    aikey web                              {}", "Open the User Console in the browser".dimmed());
            eprintln!();
            eprintln!("  {}", "Run 'aikey --help' for all commands.".dimmed());
            // Blink runs AFTER the full screen is painted so the user sees
            // banner + hints together instead of being held by the animation.
            // 10 = blank + "Get started" + 6 commands + blank + hint.
            cli::animate_banner_blink(10);
            std::process::exit(1);
        }
    }

    // Determine command name for structured log fields (best-effort, no secrets).
    let cmd_name = command_name(cli.command.as_ref());

    observability::log_event(
        observability::EVENT_CLI_COMMAND_STARTED,
        &format!("command started: {}", cmd_name),
    );

    let start = std::time::Instant::now();

    // Execute command and log outcome.
    match run_command(&cli) {
        Ok(()) => {
            let duration_ms = start.elapsed().as_millis() as i64;
            let mut extra = std::collections::BTreeMap::new();
            extra.insert("duration_ms", serde_json::Value::from(duration_ms));
            extra.insert("command", serde_json::Value::from(cmd_name.clone()));
            observability::write_log(
                observability::Level::Info,
                &format!("command completed: {}", cmd_name),
                Some(observability::EVENT_CLI_COMMAND_COMPLETED),
                None,
                None,
                extra,
            );
        }
        Err(e) => {
            let duration_ms = start.elapsed().as_millis() as i64;
            use std::collections::BTreeMap;
            let mut extra = BTreeMap::new();
            extra.insert("duration_ms", serde_json::Value::from(duration_ms));
            extra.insert("command", serde_json::Value::from(cmd_name.clone()));
            observability::write_log(
                observability::Level::Error,
                &format!("command failed: {}", cmd_name),
                Some(observability::EVENT_CLI_COMMAND_FAILED),
                None,
                Some(&e.to_string()),
                extra,
            );
            // If vault authentication failed, the session cache may hold a stale password.
            // Auto-invalidate so the next command prompts fresh instead of silently
            // reusing the wrong password and triggering the rate-limiter again.
            let err_str = e.to_string();
            let is_auth_error = err_str.contains("Invalid master password")
                || err_str.contains("vault authentication failed");
            if is_auth_error {
                session::invalidate();
            }
            if cli.json {
                json_output::error(&err_str, 1);
            } else {
                eprintln!("Error: {}", e);
                if is_auth_error {
                    // Why split: when the rejected password came from AK_TEST_PASSWORD
                    // / AIKEY_MASTER_PASSWORD in the caller's environment, clearing the
                    // session cache does NOT unblock the user — the next invocation
                    // re-reads the same wrong env value and fails identically
                    // ("make restart stuck in auth-fail loop"). Tell the user that
                    // directly so they know env is the culprit, not the cache.
                    let from_env = std::env::var("AK_TEST_PASSWORD").is_ok()
                        || std::env::var("AIKEY_MASTER_PASSWORD").is_ok();
                    if from_env {
                        eprintln!("  Hint: rejected password came from AK_TEST_PASSWORD /");
                        eprintln!("        AIKEY_MASTER_PASSWORD in your environment.");
                        eprintln!("        Clearing the session cache will NOT help — either:");
                        eprintln!("          • unset the env var so the next command prompts you:");
                        eprintln!("              unset AK_TEST_PASSWORD AIKEY_MASTER_PASSWORD");
                        eprintln!("          • or set AIKEY_MASTER_PASSWORD to the correct password.");
                    } else {
                        eprintln!("  Hint: Session cache cleared — next command will prompt for your password.");
                    }
                }
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// Handle `aikey stats` command
#[allow(dead_code)]
fn handle_stats(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Count project configs
    let mut project_count = 0;
    if let Ok(entries) = std::fs::read_dir(".") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.starts_with("aikey.config.")) {
                project_count += 1;
            }
        }
    }

    // Count profiles from global config
    let mut profile_count = 0;
    if let Ok(config_file) = crate::global_config::config_path() {
        if config_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&config_file) {
                if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(profiles) = config.get("profiles").and_then(|v| v.as_array()) {
                        profile_count = profiles.len();
                    }
                }
            }
        }
    }

    // Check if vault exists
    let vault_exists = if let Ok(vault_path) = crate::storage::get_vault_path() {
        vault_path.exists()
    } else {
        false
    };

    if json_mode {
        let response = serde_json::json!({
            "ok": true,
            "projects": project_count,
            "profiles": profile_count,
            "vault_initialized": vault_exists
        });
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("AiKey Local Statistics");
        println!("======================");
        println!("Projects (current dir): {}", project_count);
        println!("Profiles: {}", profile_count);
        println!("Vault: {}", if vault_exists { "initialized" } else { "not initialized" });
        println!("\nNote: These statistics are local-only and do not involve any remote calls.");
    }

    Ok(())
}

/// Shared implementation of `aikey key list` (canonical) and `aikey list` (alias).
///
/// Renders a unified view of Personal Keys, Team Keys, and OAuth accounts in
/// one box — both entry points delegate here so the two commands always agree.
fn run_unified_list(
    password_stdin: bool,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Version-gated sync: only prompt for Master Password when the
    // server has changes (new keys, status updates, etc.).
    // No password needed when version is unchanged (most common case).
    // Force sync when local cache is empty but user is logged in —
    // version match alone is insufficient (cache may have been cleared
    // or previously synced under the wrong identity).
    let cache_empty = storage::list_virtual_key_cache().map(|c| c.is_empty()).unwrap_or(true);
    let logged_in = storage::get_platform_account().ok().flatten().is_some();
    let needs_sync = if cache_empty && logged_in {
        true
    } else {
        commands_account::check_sync_version_changed().unwrap_or(false)
    };
    if needs_sync {
        let password = prompt_vault_password(password_stdin, json_mode)?;
        let _ = commands_account::run_full_snapshot_sync(&password);
    }

    // Only active keys are shown; revoked / recycled / expired keys
    // are hidden so the output reflects currently usable keys only.
    let managed: Vec<_> = storage::list_virtual_key_cache()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.key_status == "active")
        .collect();

    let entries = storage::list_entries_with_metadata().unwrap_or_default();

    if json_mode {
        json_output::success(serde_json::json!({
            "secrets": entries,
            "managed_keys": managed.iter().map(|e| serde_json::json!({
                "virtual_key_id": e.virtual_key_id,
                "alias":          e.alias,
                "provider_code":  e.provider_code,
                "key_status":     e.key_status,
                "share_status":   e.share_status,
                "local_state":    e.local_state,
                "has_key":        e.provider_key_ciphertext.is_some(),
            })).collect::<Vec<_>>(),
        }));
    } else {
        use colored::Colorize;

        let bindings = storage::list_provider_bindings(
            profile_activation::DEFAULT_PROFILE
        ).unwrap_or_default();

        // Collect row data for auto-width calculation.
        // `active` = has at least one provider binding routing to this key.
        // Matches the `aikey route` convention: if the proxy is currently
        // serving some provider via this key, it's considered active.
        struct RowData { alias: String, providers: String, primary_for: String, has_primary: bool, status: String, created: String, suffix: String, active: bool }
        let mut personal_rows: Vec<RowData> = Vec::new();
        let mut team_rows: Vec<RowData> = Vec::new();

        for entry in &entries {
            let providers = if let Some(ref sp) = entry.supported_providers {
                if !sp.is_empty() { sp.join(",") } else { entry.provider_code.clone().unwrap_or_default() }
            } else { entry.provider_code.clone().unwrap_or_default() };
            let pf: Vec<&str> = bindings.iter()
                .filter(|b| b.key_source_type == credential_type::CredentialType::PersonalApiKey && b.key_source_ref == entry.alias)
                .map(|b| b.provider_code.as_str()).collect();
            let is_active = !pf.is_empty();
            personal_rows.push(RowData {
                alias: entry.alias.clone(), providers,
                primary_for: pf.join(","), has_primary: !pf.is_empty(),
                status: String::new(), // valid → not displayed
                created: entry.created_at.map(|ts| format_date(ts)).unwrap_or_default(),
                suffix: String::new(),
                active: is_active,
            });
        }
        for e in &managed {
            let display = e.local_alias.as_deref().unwrap_or(e.alias.as_str()).to_string();
            let pf: Vec<&str> = bindings.iter()
                .filter(|b| b.key_source_type == credential_type::CredentialType::ManagedVirtualKey && b.key_source_ref == e.virtual_key_id)
                .map(|b| b.provider_code.as_str()).collect();
            // Unified status display: valid (hidden), expired, invalid, pending.
            let status = if e.provider_key_ciphertext.is_none() {
                "pending".to_string() // key not yet delivered to local vault
            } else {
                match e.local_state.as_str() {
                    "active" | "synced_inactive" => match e.key_status.as_str() {
                        "active" => String::new(), // valid → not displayed
                        "expired" => "expired".to_string(),
                        _ => "invalid".to_string(), // revoked, recycled, etc.
                    },
                    "disabled_by_account_scope" | "disabled_by_account_status"
                    | "disabled_by_seat_status" | "disabled_by_key_status" => "invalid".to_string(),
                    _ => "invalid".to_string(),
                }
            };
            let suffix = if e.local_alias.is_some() { format!(" (\u{2190} {})", e.alias) } else { String::new() };
            let is_active = !pf.is_empty();
            team_rows.push(RowData {
                alias: display, providers: e.provider_code.clone(),
                primary_for: pf.join(","), has_primary: !pf.is_empty(),
                status, created: format_date(e.synced_at), suffix,
                active: is_active,
            });
        }

        let all_data: Vec<&RowData> = personal_rows.iter().chain(team_rows.iter()).collect();
        let headers = ["ALIAS", "PROTOCOLS", "USING FOR", "STATUS", "CREATED"];
        let pad = 2;
        let w_alias   = headers[0].len().max(all_data.iter().map(|r| r.alias.len()).max().unwrap_or(0)) + pad;
        let w_prov    = headers[1].len().max(all_data.iter().map(|r| r.providers.len()).max().unwrap_or(0)) + pad;
        let w_primary = headers[2].len().max(all_data.iter().map(|r| r.primary_for.len()).max().unwrap_or(0)) + pad;
        let w_status  = headers[3].len().max(all_data.iter().map(|r| r.status.len()).max().unwrap_or(0)) + pad;

        // Row format: `● ALIAS ...` when active, `  ALIAS ...` otherwise.
        // The 2-char prefix (marker + space) is shared with the header so
        // columns line up across Personal / Team / OAuth sections.
        let fmt_row = |r: &RowData| -> String {
            let marker = if r.active { "●".green().to_string() } else { " ".to_string() };
            let pf_padded = format!("{:<w$}", r.primary_for, w = w_primary);
            let pf_col = if r.has_primary { pf_padded.green().to_string() } else { pf_padded };
            let created_col = format!("\x1b[90m{}\x1b[0m", r.created);
            let prov_display = if r.providers.len() > w_prov {
                format!("{}...", &r.providers[..w_prov - 3])
            } else { r.providers.clone() };
            format!("{} {:<wa$}  {:<wp$}  {}  {:<ws$}  {}{}",
                marker, r.alias, prov_display, pf_col, r.status, created_col, r.suffix,
                wa = w_alias, wp = w_prov, ws = w_status)
        };
        // +2 accounts for the `● ` marker prefix that the row renderer adds.
        let sep_width = 2 + w_alias + 2 + w_prov + 2 + w_primary + 2 + w_status + 2 + 10;

        let mut rows: Vec<String> = Vec::new();
        rows.push(format!("\u{1F464} Personal \x1b[90m({})\x1b[0m", entries.len()));
        rows.push(format!("\x1b[2m  {:<wa$}  {:<wp$}  {:<wf$}  {:<ws$}  {}\x1b[0m",
            headers[0], headers[1], headers[2], headers[3], headers[4],
            wa = w_alias, wp = w_prov, wf = w_primary, ws = w_status));
        rows.push("\u{2500}".repeat(sep_width));
        if personal_rows.is_empty() { rows.push("(none)".to_string()); }
        else { for r in &personal_rows { rows.push(fmt_row(r)); } }

        rows.push(String::new());
        rows.push(format!("\u{1F465} Team \x1b[90m({})\x1b[0m", managed.len()));
        rows.push("\u{2500}".repeat(sep_width));
        if team_rows.is_empty() { rows.push("(none)".to_string()); }
        else { for r in &team_rows { rows.push(fmt_row(r)); } }

        // D7: OAuth accounts section
        let oauth_accounts = storage::list_provider_accounts().unwrap_or_default();
        if !oauth_accounts.is_empty() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            // Build row data for dynamic width calculation
            struct OAuthRow { identity: String, provider: String, use_for: String, has_use: bool, status: String, tier: String, expires: String }
            let oauth_rows: Vec<OAuthRow> = oauth_accounts.iter().map(|acct| {
                let identity = acct.display_identity.as_deref()
                    .filter(|s| !s.is_empty())
                    .or_else(|| acct.external_id.as_deref().map(|s| if s.len() > 12 { &s[..12] } else { s }))
                    .unwrap_or("-").to_string();
                let uf: Vec<&str> = bindings.iter()
                    .filter(|b| b.key_source_type == credential_type::CredentialType::PersonalOAuthAccount && b.key_source_ref == acct.provider_account_id)
                    .map(|b| b.provider_code.as_str()).collect();
                let token_expires = storage::get_provider_token_expires_at(&acct.provider_account_id)
                    .ok().flatten();
                let expires = token_expires
                    .map(|exp| {
                        let rem = exp - now;
                        if rem <= 0 { "expired".to_string() }
                        else if rem > 86400 { format!("{}d", rem / 86400) }
                        else if rem > 3600 { format!("{}h", rem / 3600) }
                        else { format!("{}m", rem / 60) }
                    }).unwrap_or_else(|| "-".to_string());
                // Unified status display: valid (hidden), expired, invalid.
                let status = match acct.status.as_str() {
                    "active" | "idle" => {
                        // Check token expiry for more precise status
                        if token_expires.map_or(false, |exp| exp <= now) {
                            "expired".to_string() // token expired, needs refresh
                        } else {
                            String::new() // valid → not displayed
                        }
                    }
                    "reauth_required" | "expired" => "expired".to_string(),
                    _ => "invalid".to_string(), // revoked, subscription_required, etc.
                };
                OAuthRow {
                    identity,
                    provider: acct.provider.clone(),
                    use_for: uf.join(","), has_use: !uf.is_empty(),
                    status,
                    tier: acct.account_tier.as_deref().unwrap_or("-").to_string(),
                    expires,
                }
            }).collect();

            // Dynamic column widths
            let pad = 2;
            let w_id   = "IDENTITY".len().max(oauth_rows.iter().map(|r| r.identity.len()).max().unwrap_or(0)) + pad;
            let w_prov = "PROTOCOL".len().max(oauth_rows.iter().map(|r| r.provider.len()).max().unwrap_or(0)) + pad;
            let w_uf   = "USING FOR".len().max(oauth_rows.iter().map(|r| r.use_for.len()).max().unwrap_or(0)) + pad;
            let w_st   = "STATUS".len().max(oauth_rows.iter().map(|r| r.status.len()).max().unwrap_or(0)) + pad;
            let w_tier = "TIER".len().max(oauth_rows.iter().map(|r| r.tier.len()).max().unwrap_or(0)) + pad;
            let _w_exp = "EXPIRES".len().max(oauth_rows.iter().map(|r| r.expires.len()).max().unwrap_or(0)) + pad;

            rows.push(String::new());
            rows.push(format!("\u{1F517} OAuth Accounts \x1b[90m({})\x1b[0m", oauth_accounts.len()));
            rows.push(format!("\x1b[2m  {:<wi$}{:<wp$}  {:<wu$}  {:<ws$}  {:<wt$}  {}\x1b[0m",
                "IDENTITY", "PROTOCOL", "USING FOR", "STATUS", "TIER", "EXPIRES",
                wi = w_id, wp = w_prov, wu = w_uf, ws = w_st, wt = w_tier));
            rows.push("\u{2500}".repeat(sep_width));
            for r in &oauth_rows {
                let uf_padded = format!("{:<w$}", r.use_for, w = w_uf);
                let uf_col = if r.has_use { uf_padded.green().to_string() } else { uf_padded };
                let tier_dim = format!("\x1b[90m{:<w$}\x1b[0m", r.tier, w = w_tier);
                let expires_dim = format!("\x1b[90m{}\x1b[0m", r.expires);
                // Active when this account is currently serving at least
                // one provider (matches the `aikey route` convention).
                let marker = if r.has_use { "●".green().to_string() } else { " ".to_string() };
                rows.push(format!("{} {:<wi$}{:<wp$}  {}  {:<ws$}  {}  {}",
                    marker, r.identity, r.provider, uf_col, r.status, tier_dim, expires_dim,
                    wi = w_id, wp = w_prov, ws = w_st));
            }
        }

        ui_frame::print_box("\u{1F511}", "Keys", &rows);
        // Legend lives outside the box so the frame stays focused on data.
        println!("  {} {}",
            "●".green(),
            "= active (set by `aikey use`)".dimmed());

        // Web console deeplink. URL is taken from the logged-in
        // platform_account (control_url) and falls back to the trial-
        // server default 127.0.0.1:8090 — same default the import
        // flow assumes (see commands_import.rs:168). Path /user/vault
        // opens this same table inside the web console for a richer
        // view. OSC-8 terminal-hyperlink wrapping was tried 2026-04-25
        // and dropped — the user's terminal didn't render it as
        // clickable, plain text is the universally-supported form.
        let vault_url = storage::get_platform_account()
            .ok()
            .flatten()
            .map(|acc| acc.control_url.trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:8090".to_string());
        let vault_url = format!("{}/user/vault", vault_url);
        println!("  {} {}",
            "↗".dimmed(),
            format!("Open in browser: {}", vault_url).dimmed());
        println!("  {} {}",
            "↗".dimmed(),
            "or run `aikey web --vault`".dimmed());
    }

    // Post-operation: warn if proxy is unreachable (e.g. after kill -9).
    commands_proxy::warn_if_proxy_down();
    Ok(())
}

fn run_command(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let command = cli.command.as_ref().unwrap();

    // 2026-04-29 prefix rename safety net (合约 B): auto-rewrite legacy
    // active.env on first invocation post-upgrade. Covers the case where
    // the installer hook didn't run (manual binary swap, machine-to-machine
    // copy of ~/.aikey/, hot-reload during dev).
    //
    // Failure here is non-fatal — print a warn line to stderr and continue
    // the user's actual command. The next invocation will retry. Skipped
    // for the explicit RefreshActiveEnv command (avoid recursion) and for
    // commands that predate active.env (Init / Version).
    match command {
        Commands::RefreshActiveEnv { .. } | Commands::Init | Commands::Version => {}
        _ => {
            if active_env_migration::active_env_has_legacy_form() {
                match active_env_migration::refresh_active_env(true) {
                    Ok(active_env_migration::RefreshOutcome::Refreshed { .. }) => {
                        eprintln!("[aikey] auto-rewrote ~/.aikey/active.env to new sentinel form (post-upgrade)");
                    }
                    Ok(active_env_migration::RefreshOutcome::NoLegacyDetected) => {}
                    Ok(active_env_migration::RefreshOutcome::NoBindingsToFollow) => {
                        // Legacy form present but no vault yet — likely a stale
                        // active.env from a prior install whose vault was wiped.
                        // Don't loop-warn on every command; the user's next
                        // `aikey add` / `aikey use` will overwrite it cleanly.
                    }
                    Err(e) => {
                        eprintln!(
                            "[aikey] WARN: active.env auto-migration failed: {}; \
                             run `aikey use <key>` to manually trigger or `aikey _refresh-active-env --if-legacy`",
                            e
                        );
                    }
                }
            }
        }
    }

    // Quarantine a corrupt vault file before anything else reads from it.
    // Why up here: `run_unified_list`, `whoami`, `status`, etc. all call
    // `storage::list_entries_with_metadata().unwrap_or_default()` which would
    // silently swallow a vault-open error and render an empty view — a
    // data-loss-looking UX that misleads users into thinking their keys are
    // gone. Quarantining before any command touches storage forces the issue
    // to surface (the user sees the ⚠ banner) and lets the follow-up init
    // proceed from a clean slate. Safe for db/init/version commands too —
    // helper is a no-op when the vault is fine.
    let _ = executor::ensure_vault_integrity_or_quarantine();

    // Auto-start proxy silently when AIKEY_MASTER_PASSWORD (or AK_TEST_PASSWORD)
    // is available in the environment.  Skipped for proxy lifecycle commands which
    // manage the process themselves, and for version/init which predate the proxy.
    match command {
        Commands::Proxy { .. } | Commands::Init | Commands::Db { .. } | Commands::Version | Commands::Statusline { action: None } | Commands::Statusline { action: Some(cli::StatuslineAction::Render { .. }) } | Commands::Watch => {}
        _ => { commands_proxy::try_auto_start_from_env(); }
    }

    // Non-blocking snapshot sync: checks server sync_version and pulls fresh
    // key state if it has changed since the last local pull. Skipped for proxy
    // lifecycle and init commands which either predate the vault or manage the
    // process themselves.
    match command {
        Commands::Proxy { .. } | Commands::Init | Commands::Db { .. } | Commands::Version | Commands::Statusline { action: None } | Commands::Statusline { action: Some(cli::StatuslineAction::Render { .. }) } | Commands::Watch => {}
        _ => { commands_account::try_background_snapshot_sync(); }
    }

    // Auto-apply pending vault schema migrations (idempotent).
    // Why here: ensures new tables/columns exist before any command accesses them.
    // Skipped for init/proxy/db which manage their own lifecycle.
    // Only runs if vault.db exists (no-op on fresh install).
    match command {
        Commands::Proxy { .. } | Commands::Init | Commands::Db { .. } | Commands::Version | Commands::Statusline { action: None } | Commands::Statusline { action: Some(cli::StatuslineAction::Render { .. }) } | Commands::Watch => {}
        _ => {
            if let Ok(vault_path) = storage::get_vault_path() {
                if vault_path.exists() {
                    if let Ok(conn) = rusqlite::Connection::open(&vault_path) {
                        let _ = migrations::upgrade_all(&conn);
                    }
                }
            }
        }
    }

    match command {
        Commands::Version => {
            if cli.json {
                json_output::success(cli::build_version_json());
            } else {
                cli::print_version_detail();
            }
            return Ok(());
        }
        Commands::Init => {
            // CLI shell: prompt + delegate to the shared init core. The
            // same core is reused by `_internal vault-op init` for the
            // web-driven first-run flow (per
            // 20260430-个人vault-Web首次设置-方案A.md).
            let password = prompt_password_secure("\u{1F512} Set Master Password: ", cli.password_stdin, cli.json)?;

            if !cli.json {
                println!("Initializing vault...");
            }

            if let Err(e) = commands_init::core::initialize(&password) {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }

            if cli.json {
                json_output::success(serde_json::json!({
                    "message": "Vault initialized successfully"
                }));
            } else {
                println!("Vault initialized successfully!");
            }
        }
        // Internal: database upgrade/rollback for schema management.
        // Why hidden: operational tool for install scripts and rollback automation,
        // not for end-user daily use. rollback.sh calls `aikey db rollback --to <ver>`
        // using the CURRENT binary BEFORE restoring the old binary from backup.
        Commands::Db { action } => {
            match action {
                DbAction::Upgrade => {
                    eprintln!("[db upgrade] Applying pending vault schema upgrades...");
                    let vault_path = storage::get_vault_path()
                        .map_err(|e| format!("Failed to resolve vault path: {}", e))?;
                    if !vault_path.exists() {
                        eprintln!("[db upgrade] No vault.db found — nothing to upgrade");
                        return Ok(());
                    }
                    let conn = rusqlite::Connection::open(&vault_path)
                        .map_err(|e| format!("Failed to open vault: {}", e))?;
                    migrations::upgrade_all(&conn)?;
                    eprintln!("[db upgrade] Done");
                }
                DbAction::Rollback { to } => {
                    eprintln!("[db rollback] Rolling back vault schema to {}", to);
                    let vault_path = storage::get_vault_path()
                        .map_err(|e| format!("Failed to resolve vault path: {}", e))?;
                    if !vault_path.exists() {
                        eprintln!("[db rollback] No vault.db found — nothing to rollback");
                        return Ok(());
                    }
                    let conn = rusqlite::Connection::open(&vault_path)
                        .map_err(|e| format!("Failed to open vault: {}", e))?;
                    migrations::rollback_to(&conn, &to)?;
                    eprintln!("[db rollback] Vault schema rolled back to {}", to);
                }
            }
        }
        // `_internal` IPC 子命令组：Go local-server spawn 调用，stdin-json 协议
        // 永远返回 Ok(()) —— 成功/失败都通过 stdout JSON 表达（见 commands_internal::dispatch 文档）
        Commands::Internal { action } => {
            commands_internal::dispatch(&action);
        }
        // Hidden: print the embedded hook-template hash so the precmd
        // drift-check can compare against the on-disk hook file header.
        Commands::HookHash { shell } => {
            let kind = match shell.as_str() {
                "zsh"  => commands_account::HookKind::Zsh,
                "bash" => commands_account::HookKind::Bash,
                "powershell" | "pwsh" => commands_account::HookKind::PowerShell,
                other  => return Err(format!(
                    "unknown shell '{}' — expected 'zsh', 'bash', or 'powershell'", other
                ).into()),
            };
            println!("{}", commands_account::hook_template_hash(kind));
        }
        Commands::RefreshActiveEnv { if_legacy } => {
            // 2026-04-29 prefix rename auto-migration entry. Called by
            // installer scripts at end of install/upgrade. Also called by
            // CLI main entry safety net (commands_proxy::ensure_active_env_migrated)
            // — but that path bypasses dispatch and goes straight to the
            // helper, so this branch is for the explicit installer call.
            //
            // Output is short status line on stderr + exit code: 0 on
            // success or no-op, 1 on backup/refresh failure. Installer
            // scripts log stderr but don't block on failure (the safety
            // net runs at next CLI invocation).
            match active_env_migration::refresh_active_env(*if_legacy) {
                Ok(active_env_migration::RefreshOutcome::NoLegacyDetected) => {
                    eprintln!("[aikey] active.env: no legacy form detected, no migration needed");
                }
                Ok(active_env_migration::RefreshOutcome::NoBindingsToFollow) => {
                    eprintln!("[aikey] active.env: no vault / no bindings yet, nothing to migrate. \
                               Run `aikey add <provider>:<alias>` then `aikey use <alias>` to set up.");
                }
                Ok(active_env_migration::RefreshOutcome::Refreshed { backup }) => {
                    if let Some(p) = backup {
                        eprintln!("[aikey] active.env: refreshed (backup: {})", p.display());
                    } else {
                        eprintln!("[aikey] active.env: refreshed (no prior file to backup)");
                    }
                }
                Err(e) => {
                    eprintln!("[aikey] active.env auto-migration failed: {}", e);
                    return Err(e.into());
                }
            }
        }
        Commands::Hook { action } => {
            handle_hook_command(action)?;
        }
        Commands::Add { alias, provider, providers, no_hook } => {
            // Reject empty / whitespace-only alias before any interactive prompt.
            // Why: an empty alias writes a ghost entry that is hard to target with
            // later commands (`get ""`, `delete ""`) and pollutes `list --json`.
            if alias.trim().is_empty() {
                let msg = "alias must not be empty";
                if cli.json { json_output::error(msg, 1); }
                return Err(msg.into());
            }
            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

            // Early password validation: fail fast before asking for API key,
            // providers, base URL, etc. Skip for first-time vault init.
            // Why: without this, users enter wrong password and go through the entire
            // interactive flow only to fail at the final write step.
            if storage::get_salt().is_ok() {
                if let Err(e) = executor::verify_vault_password(&password) {
                    if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); }
                }

                // Early alias check: fail fast before asking for API key, provider, etc.
                // Why: without this, users go through the entire interactive flow (API key,
                // provider selection, connectivity test, confirmation) only to get
                // "already exists" at the final write step.
                if let Ok(true) = storage::entry_exists(alias) {
                    let msg = format!("API Key '{}' already exists. Use 'aikey update {}' to modify it.", alias, alias);
                    if cli.json { json_output::error(&msg, 1); } else { return Err(msg.into()); }
                }
            }

            // Step 2: read secret value (from env, hidden TTY prompt, or stdin).
            let secret = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                Zeroizing::new(test_secret)
            } else if std::io::stdin().is_terminal() {
                let val = prompt_hidden("  \u{25c6} Enter API Key: ")
                    .map_err(|e| format!("Failed to read API Key value: {}", e))?;
                Zeroizing::new(val)
            } else {
                // Non-TTY (pipe / automation): read from stdin directly — no flag needed.
                let mut secret = Zeroizing::new(String::new());
                io::stdin().read_line(&mut secret)?;
                secret
            };

            // Step 3: resolve providers + base_url.
            // v1.0.2: multi-provider selection with checkbox TUI.
            //
            // Picker list is now driven by the provider registry (2026-04-24
            // — provider_registry.yaml). Entries with `picker: true` appear
            // here, in YAML declaration order. Adding a new provider = add
            // one YAML entry, not a `KNOWN_PROVIDERS` const edit.
            let picker_entries = provider_registry::picker_entries();
            let known_providers: Vec<(&'static str, &'static str)> = picker_entries
                .iter()
                .map(|e| (e.display, e.default_base_url))
                .collect();
            // Parallel map for downstream lookup by display label (the user
            // sees `display`, but the stored `provider_code` is `e.code`).
            let display_to_code: std::collections::HashMap<&'static str, &'static str> =
                picker_entries.iter().map(|e| (e.display, e.code)).collect();

            // v4.1 Stage 5+: --providers (multi) 优先级最高,然后是 --provider (single shorthand),
            // 都没给且 TTY 时进入交互式 multi-select。clap 的 `conflicts_with` 已保证 --provider /
            // --providers 不会同时给。
            let (resolved_providers, resolved_base_url): (Vec<String>, Option<String>) =
                if !providers.is_empty() {
                    // dedupe + lowercase,保持用户输入顺序
                    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                    let cleaned: Vec<String> = providers.iter()
                        .map(|p| p.trim().to_lowercase())
                        .filter(|p| !p.is_empty() && seen.insert(p.clone()))
                        .collect();
                    if cleaned.is_empty() {
                        return Err("--providers given but all entries were empty after trim.".into());
                    }
                    (cleaned, None)
                } else if let Some(code) = provider {
                    (vec![code.to_lowercase()], None)
                } else if std::io::stdin().is_terminal() && !cli.json {
                    use colored::Colorize;
                    let mut items: Vec<String> = known_providers.iter().map(|(n, _)| n.to_string()).collect();
                    items.push("Other protocol types...".to_string());
                    let custom_idx = known_providers.len();
                    let mut selected: Vec<String>;
                    let mut checked_state: Vec<bool> = vec![false; items.len()];

                    loop {
                        let selected_indices = match ui_select::box_multi_select("Select protocol type(s)", &items, &checked_state)? {
                            ui_select::MultiSelectResult::Confirmed(idx) => idx,
                            ui_select::MultiSelectResult::Cancelled => { eprintln!("  Cancelled."); return Ok(()); }
                        };
                        checked_state = vec![false; items.len()];
                        for &i in &selected_indices { if i < checked_state.len() { checked_state[i] = true; } }
                        selected = Vec::new();
                        let mut wants_custom = false;
                        for &idx in &selected_indices {
                            if idx < known_providers.len() {
                                // Translate the picker's display label back to canonical code
                                // via the display_to_code map built above. Users see "doubao
                                // (ARK)" but the vault stores "doubao".
                                let display_label = known_providers[idx].0;
                                let canonical_code = display_to_code
                                    .get(display_label)
                                    .copied()
                                    .unwrap_or(display_label)
                                    .to_string();
                                if !selected.contains(&canonical_code) { selected.push(canonical_code); }
                            } else if idx == custom_idx { wants_custom = true; }
                        }
                        if wants_custom {
                            print!("  \u{25c6} Other protocol type(s), comma-separated: ");
                            io::stdout().flush()?;
                            let mut custom = String::new();
                            io::stdin().read_line(&mut custom)?;
                            for code in custom.split(',').map(|s| s.trim().to_lowercase()) {
                                if !code.is_empty() && !selected.contains(&code) { selected.push(code); }
                            }
                        }
                        if !selected.is_empty() { break; }
                        use colored::Colorize;
                        eprintln!("  {} At least one protocol is required.\n", "\u{25c6}".yellow());
                    }

                    // Show default base URLs for selected providers so the user
                    // knows what they're accepting when pressing Enter.
                    let default_urls: Vec<String> = selected.iter()
                        .filter_map(|code| commands_project::default_base_url(code)
                            .map(|u| format!("{}: {}", code, u)))
                        .collect();
                    if !default_urls.is_empty() {
                        eprintln!("  \u{2502} Default Base URLs:");
                        for u in &default_urls { eprintln!("  \u{2502}   {}", u); }
                    }
                    print!("  \u{25c6} Base URL (press Enter to use defaults above): ");
                    io::stdout().flush()?;
                    let mut url_input = String::new();
                    io::stdin().read_line(&mut url_input)?;
                    let url_input = url_input.trim().to_string();
                    let base_url = if url_input.is_empty() { None } else { Some(url_input) };

                    eprintln!("  \u{2502} Protocols: {}", selected.join(", ").bold());
                    if let Some(ref u) = base_url { eprintln!("  \u{2502} Base URL:  {}", u.dimmed()); }
                    (selected, base_url)
                } else {
                    return Err("--provider <CODE> or --providers <c1,c2,...> is required in non-interactive mode.".into());
                };

            // Warn (not reject) when the user passed a provider code via
            // --provider / --providers that is not one of the built-in ones.
            // Why warn instead of reject: providers::Provider has a Custom(String)
            // variant — self-hosted LLMs and aggregator gateways are a first-class
            // feature. A hard reject would break that use case. But an unguarded
            // accept lets a typo like `openia` silently sail through and route
            // requests at a non-existent provider. The warning surfaces the typo
            // without blocking the custom case. Skipped for the interactive
            // picker branch because that flow has an explicit "Other provider
            // types..." option and thus no typo risk.
            let from_cli_flag = !providers.is_empty() || provider.is_some();
            if from_cli_flag && !cli.json {
                // "Known" = any provider that resolves in the registry (by code
                // or OAuth alias). The registry is broader than the picker list
                // — e.g. "claude" aliases "anthropic" so both are considered
                // known and skip the typo warning.
                let unknown: Vec<&String> = resolved_providers.iter()
                    .filter(|p| provider_registry::lookup(p.as_str()).is_none())
                    .collect();
                if !unknown.is_empty() {
                    use colored::Colorize;
                    let unk_list = unknown.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(", ");
                    eprintln!(
                        "  {} {} is not a built-in provider code.",
                        "warning:".yellow().bold(), unk_list
                    );
                    let known_codes: Vec<&'static str> = provider_registry::entries()
                        .iter().map(|e| e.code).collect();
                    eprintln!("  built-in: {}", known_codes.join(", "));
                    eprintln!("  If this is a custom provider / gateway, this is fine — continuing.");
                    eprintln!("  If it was a typo, Ctrl+C and retry with --provider <built-in>.");
                    eprintln!();
                }
            }

            // (`resolved_provider` — the first-provider shorthand — used to
            // live here; apply_add_core_on_conn takes `resolved_providers`
            // whole and writes provider_code = providers[0] internally.)

            // Step 4: connectivity test — routed through the unified suite so
            // `aikey add` shares one code path with doctor / test.
            if !cli.json && std::io::stdin().is_terminal() && env::var("AK_TEST_SECRET").is_err() {
                let targets = commands_project::targets_from_new_personal_key(
                    alias,
                    secret.trim(),
                    &resolved_providers,
                    resolved_base_url.as_deref(),
                );
                if !targets.is_empty() {
                    eprintln!();
                    let opts = commands_project::SuiteOptions {
                        show_proxy_row: true,
                        header_label:   None,
                        password:       None,
                        proxy_port:     commands_proxy::proxy_port(),
                    };
                    let outcome = commands_project::run_connectivity_suite(targets, opts, false);
                    if !outcome.any_chat_ok {
                        eprintln!();
                        eprint!("  \u{25c6} No chat test passed. Add anyway? [y/N] (default N): ");
                        io::stdout().flush()?;
                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;
                        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
                            eprintln!("  Cancelled."); return Ok(());
                        }
                    }
                    eprintln!();
                }
            }

            // Step 5: write to vault via the shared core.
            //
            // Funnels to `commands_account::apply_add_core_on_conn` — the same
            // helper used by `_internal vault-op add` and `_internal vault-op
            // batch_import`, so alias validation / canonical provider
            // normalization / ciphertext write / supported_providers +
            // provider_code + base_url metadata all land identically no matter
            // which caller wrote the row (2026-04-24 `_internal must reuse
            // public command core` rule — see `.claude/CLAUDE.md`).
            let vault_key = match executor::derive_vault_key(&password) {
                Ok(k) => k,
                Err(e) => {
                    if cli.json { json_output::error(&e, 1); }
                    return Err(e.into());
                }
            };
            let conn = match storage::open_connection() {
                Ok(c) => c,
                Err(e) => {
                    if cli.json { json_output::error(&e, 1); }
                    return Err(e.into());
                }
            };
            let outcome = match commands_account::apply_add_core_on_conn(
                &conn,
                &vault_key,
                alias,
                secret.trim().as_bytes(),
                &resolved_providers,
                resolved_base_url.as_deref(),
                commands_account::OnConflict::Error,
            ) {
                Ok(o) => o,
                Err(e) => {
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Add, Some(alias), false);
                    if cli.json { json_output::error(&e, 1); }
                    return Err(e.into());
                }
            };
            let _ = storage::bump_vault_change_seq();
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Add, Some(&outcome.alias), true);

            // Generate route token for per-request proxy routing (API gateway).
            // Outside the core because `ensure_entry_route_token` opens its
            // own connection — safe to run post-write on the same DB.
            let _ = storage::ensure_entry_route_token(&outcome.alias);

            // Auto-assign as Primary + refresh active.env.
            let newly_primary = profile_activation::auto_assign_primaries_for_key(
                "personal", alias, &resolved_providers,
            ).unwrap_or_default();
            if !newly_primary.is_empty() || !resolved_providers.is_empty() {
                let _ = profile_activation::refresh_implicit_profile_activation();
            }

            // Hook coverage v1 §H1: install shell hook on `aikey add` too,
            // not just on `aikey use`. First-key add is a typical onboarding
            // path — without the hook, the user would see active.env get
            // refreshed but their next prompt wouldn't auto-source it.
            // ensure_shell_hook honors --no-hook + AIKEY_NO_HOOK=1 + non-TTY
            // (H1.5 hardening), so this is safe in pipe/CI contexts too.
            let hook_msg = if !cli.json {
                commands_account::ensure_shell_hook(*no_hook)
            } else {
                None
            };

            // Auto-configure third-party CLI tools when relevant providers are added.
            if !cli.json {
                let proxy_port = commands_proxy::proxy_port();
                let has_openai = resolved_providers.iter().any(|p| {
                    let c = p.to_lowercase();
                    c == "openai" || c == "gpt" || c == "chatgpt"
                });
                if has_openai {
                    commands_account::configure_codex_cli(proxy_port);
                }

                let has_kimi = resolved_providers.iter().any(|p| {
                    let c = p.to_lowercase();
                    c == "kimi" || c == "moonshot"
                });
                if has_kimi {
                    commands_account::configure_kimi_cli(proxy_port);
                }
            }

            if cli.json {
                json_output::success(serde_json::json!({
                    "alias": alias,
                    "message": "Added key and refreshed current default activation.",
                    "providers": resolved_providers,
                    "primary_for": newly_primary,
                    "base_url": resolved_base_url,
                }));
            } else {
                use colored::Colorize;
                eprintln!("  {} API Key '{}' added.", "\u{25c6}".green(), alias.bold());
                eprintln!("  \u{2502} providers: {}", resolved_providers.join(", ").dimmed());
                if let Some(ref url) = resolved_base_url { eprintln!("  \u{2502} base_url:  {}", url.dimmed()); }
                if !newly_primary.is_empty() {
                    eprintln!("  \u{2502} {} Primary for: {}", "\u{2B50}".yellow(), newly_primary.join(", ").bold());
                }
                eprintln!("  \u{2502} Added key and refreshed current default activation.");
                if let Some(ref msg) = hook_msg {
                    eprintln!("  \u{2502}");
                    for line in msg.lines() {
                        eprintln!("  \u{2502} {}", line.trim_start());
                    }
                }

                // Auto-start proxy after adding a key so the user can immediately
                // use AI CLIs. Without this, `claude` / `cursor` would fail because
                // the proxy isn't running to route requests.
                // Round 9 fix #1: was is_proxy_running (PID-only); now uses
                // proxy_is_running_managed (Layer 1 identity + ownership +
                // /health) so PID-recycle / OrphanedPort scenarios trigger the
                // ensure_proxy_for_use path correctly.
                if !commands_proxy::proxy_is_running_managed() {
                    eprintln!();
                    commands_proxy::ensure_proxy_for_use(cli.password_stdin);
                }
                commands_proxy::maybe_warn_stale();
            }
        }
        Commands::Get { alias, timeout } => {
            let password = prompt_vault_password(cli.password_stdin, cli.json)?;
            let result = executor::get_secret(alias, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Get, Some(alias), result.is_ok());

            let secret = match result {
                Ok(s) => s,
                Err(e) => {
                    if cli.json {
                        json_output::error(&e, 1);
                    } else {
                        return Err(e.into());
                    }
                }
            };

            if cli.json {
                // JSON output: return the secret value directly for testing
                json_output::success(serde_json::json!({
                    "alias": alias,
                    "value": secret.as_str()
                }));
            } else {
                // Check if clipboard should be disabled (for testing)
                if std::env::var("AK_NO_CLIPBOARD").is_ok() {
                    println!("{}", secret.as_str());
                } else {
                    // Copy to clipboard
                    executor::copy_to_clipboard(&secret)?;
                    println!("Secret copied to clipboard.");

                    // Auto-clear clipboard after timeout (if enabled)
                    if *timeout > 0 {
                        println!("Clipboard will be cleared in {} seconds...", timeout);
                        executor::schedule_clipboard_clear(*timeout);
                    }
                }
            }
        }
        Commands::Delete { aliases } => {
            // Batch delete. Design (2026-04-22):
            //   - Single confirmation for the whole batch (N prompts for N
            //     aliases would be terrible UX — see CLAUDE.md 交互简洁性优先)
            //   - Single vault password prompt (same reason)
            //   - Per-alias outcome reported; partial failures do NOT abort
            //     the batch — user would rather know which one failed than
            //     re-type N-1 args after a single bad alias
            //   - Binding reconcile runs ONCE after all deletes, using the
            //     union of affected provider-codes, instead of N reconciles
            //   - Single-alias invocation (`ak delete x`) is unchanged
            //     behaviourally — same prompts, same exit code
            use colored::Colorize;

            // Dedupe while preserving order (user might type the same alias twice).
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            let ordered: Vec<String> = aliases.iter()
                .filter(|a| seen.insert((*a).clone()))
                .cloned()
                .collect();
            let batch = ordered.len();

            // Confirm once — batched prompt. Skip in JSON / non-interactive modes.
            if !cli.json && std::io::stdin().is_terminal() {
                if batch == 1 {
                    eprint!("  Delete API Key '{}'? This cannot be undone. [y/N] (default N): ",
                        ordered[0].bold());
                } else {
                    eprint!("  Delete {} API Keys ({})? This cannot be undone. [y/N] (default N): ",
                        batch, ordered.join(", ").bold());
                }
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
                    eprintln!("  Cancelled.");
                    return Ok(());
                }
            }

            // Single password prompt for the whole batch.
            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

            // Run per-alias deletes + collect outcomes. Don't short-circuit
            // on error — user wants to know which one failed and still have
            // the others removed.
            let mut per_alias: Vec<(String, Result<(), String>, Vec<profile_activation::ReconcileAction>)>
                = Vec::with_capacity(batch);
            for alias in &ordered {
                let result = executor::delete_secret(alias, &password);
                let _ = audit::log_audit_event(
                    &password, audit::AuditOperation::Delete, Some(alias), result.is_ok(),
                );
                let actions: Vec<profile_activation::ReconcileAction> = if result.is_ok() {
                    profile_activation::reconcile_provider_primary_after_key_removal(
                        "personal", alias,
                    ).unwrap_or_default()
                } else { Vec::new() };
                per_alias.push((alias.clone(), result, actions));
            }

            // One activation refresh at the end if ANY delete produced reconcile actions.
            let any_reconciled = per_alias.iter().any(|(_, _, a)| !a.is_empty());
            if any_reconciled {
                let _ = profile_activation::refresh_implicit_profile_activation();
            }

            let ok_count = per_alias.iter().filter(|(_, r, _)| r.is_ok()).count();
            let fail_count = batch - ok_count;

            if cli.json {
                let items: Vec<serde_json::Value> = per_alias.iter().map(|(a, r, _)| {
                    match r {
                        Ok(_)  => serde_json::json!({"alias": a, "ok": true}),
                        Err(e) => serde_json::json!({"alias": a, "ok": false, "error": e}),
                    }
                }).collect();
                let payload = serde_json::json!({
                    "deleted": ok_count,
                    "failed":  fail_count,
                    "items":   items,
                });
                if fail_count == 0 {
                    json_output::success(payload);
                } else {
                    // Partial/total failure: emit JSON + non-zero exit.
                    eprintln!("{}", serde_json::to_string_pretty(&payload).unwrap());
                    std::process::exit(if ok_count > 0 { 2 } else { 1 });
                }
            } else {
                for (alias, result, actions) in &per_alias {
                    match result {
                        Ok(()) => {
                            eprintln!("  {} API Key '{}' deleted.", "\u{2713}".green(), alias);
                            for action in actions {
                                match &action.outcome {
                                    profile_activation::ReconcileOutcome::Replaced { new_source_ref, .. } => {
                                        eprintln!("    {} '{}' promoted to Primary for {}",
                                            "\u{2B50}".yellow(), new_source_ref.bold(), action.provider_code);
                                    }
                                    profile_activation::ReconcileOutcome::Cleared => {
                                        eprintln!("    {} No replacement for {} — provider has no Primary",
                                            "\u{26A0}".yellow(), action.provider_code);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("  {} '{}': {}", "\u{2717}".red(), alias, e);
                        }
                    }
                }
                if batch > 1 {
                    eprintln!("  {} deleted, {} failed (of {} requested).", ok_count, fail_count, batch);
                }
                commands_proxy::maybe_warn_stale();
                // Partial failure → exit 2, total failure → 1, all ok → 0.
                if fail_count > 0 {
                    std::process::exit(if ok_count > 0 { 2 } else { 1 });
                }
            }
        }
        Commands::List => {
            // `aikey list` is a shortcut for `aikey key list` — both render the
            // same unified view (Personal + Team + OAuth).
            run_unified_list(cli.password_stdin, cli.json)?;
        }
        Commands::Update { alias } => {
            // Confirm before update (skip in JSON / non-interactive / test mode).
            if !cli.json && std::io::stdin().is_terminal() && env::var("AK_TEST_SECRET").is_err() {
                use colored::Colorize;
                eprint!("  Update API Key '{}'? The old value will be overwritten. [y/N] (default N): ", alias.bold());
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
                    eprintln!("  Cancelled.");
                    return Ok(());
                }
            }

            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

            // Early password validation — same reason as `add`.
            if storage::get_salt().is_ok() {
                if let Err(e) = executor::verify_vault_password(&password) {
                    if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); }
                }
            }

            // Check for test environment variable first
            let secret = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                Zeroizing::new(test_secret)
            } else if std::io::stdin().is_terminal() {
                // Hidden prompt on TTY
                let val = prompt_hidden("\u{1F511} Enter new API Key value: ")
                    .map_err(|e| format!("Failed to read API Key value: {}", e))?;
                Zeroizing::new(val)
            } else {
                // Plain stdin for pipes / automation
                if !cli.json {
                    print!("\u{1F511} Enter new API Key value: ");
                    io::stdout().flush()?;
                }
                let mut secret = Zeroizing::new(String::new());
                io::stdin().read_line(&mut secret)?;
                secret
            };

            let result = executor::update_secret(alias, secret.trim(), &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Update, Some(alias), result.is_ok());

            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }

            if cli.json {
                json_output::success(serde_json::json!({
                    "alias": alias,
                    "message": "API Key updated successfully"
                }));
            } else {
                use colored::Colorize;
                eprintln!("  {} API Key '{}' updated.", "\u{2713}".green(), alias);
                commands_proxy::maybe_warn_stale();
            }
        }
        Commands::Test { alias, provider: test_provider } => {
            // Structured exit codes so shell wrappers (claude/codex/kimi) can
            // branch without parsing output:
            //
            //   0  API(PROXY) passed — key/account is usable
            //   1  Ping(PROXY) failed — proxy can't reach upstream
            //   2  API(PROXY) failed — key rejected / account expired
            //   3  alias not found in any source
            //   5  aikey-proxy not running
            //
            // Ping(DIRECT) is informational only — never participates in the
            // exit-code decision.
            const EXIT_OK:                i32 = 0;
            const EXIT_PING_FAIL:         i32 = 1;
            const EXIT_API_FAIL:          i32 = 2;
            const EXIT_ALIAS_NOT_FOUND:   i32 = 3;
            const EXIT_PROXY_NOT_RUNNING: i32 = 5;

            // Pre-flight: the probe pipeline now ALWAYS goes through the
            // local proxy for API/Chat/ping-proxy. If the proxy is down we
            // can't even start — fail fast with a dedicated exit code so
            // wrappers don't misinterpret it as "key invalid". `aikey test`
            // stays a pure diagnostic: it does NOT auto-start the proxy.
            // Wrapper hooks (claude/codex/kimi) are expected to bring the
            // proxy up via `aikey proxy ensure-running` before calling us;
            // see hook.zsh `_aikey_preflight` for the orchestration.
            // Round 9 fix #1: was is_proxy_running (PID-only); now uses
            // proxy_is_running_managed (Layer 1) so OrphanedPort / Unresponsive
            // bail out with the "proxy not running" exit instead of
            // proceeding with broken probe targets.
            if !commands_proxy::proxy_is_running_managed() {
                let msg = "aikey-proxy is not running. Run `aikey proxy start` and retry.";
                if cli.json { json_output::error(msg, EXIT_PROXY_NOT_RUNNING); }
                else { eprintln!("{}", msg); std::process::exit(EXIT_PROXY_NOT_RUNNING); }
            }

            // Plan D (2026-04-22): personal keys probe via proxy using a
            // probe sentinel (post-2026-04-29 prefix rename: `aikey_probe_*`);
            // proxy does decryption server-side. CLI no longer prompts for
            // vault password, which is the
            // precondition for the `claude()` / `codex()` wrapper preflight
            // to run silently before every invocation.
            let proxy_port = commands_proxy::proxy_port();

            // Derive exit code from a suite outcome. Rules:
            //   - any row with api_ok → 0 (at least one target usable)
            //   - else any ping_ok → 2 (reached but all keys rejected)
            //   - else → 1 (couldn't reach upstream via proxy)
            //
            // Across multiple rows (e.g. a personal key bound to N providers),
            // success on ANY counts as overall success — matches the
            // `any_chat_ok` semantics used by `aikey add`.
            fn exit_code_from_outcome(outcome: &commands_project::SuiteOutcome) -> i32 {
                if outcome.rows.iter().any(|(_, r)| r.api_ok) { return EXIT_OK; }
                if outcome.rows.iter().any(|(_, r)| r.ping_ok) { return EXIT_API_FAIL; }
                EXIT_PING_FAIL
            }
            // Name inside the closure-esque fn needs the consts visible — Rust
            // fn scope inside a match arm is a regular item, so consts above
            // are accessible via their bindings at call time. (Kept local to
            // avoid leaking these into the module's public surface.)

            if let Some(ref alias) = alias {
                // ── Single-alias mode: resolve across personal/team/OAuth ──
                let targets = commands_project::targets_from_alias(
                    alias,
                    test_provider.as_deref(),
                    None,
                    proxy_port,
                );
                if targets.is_empty() {
                    let msg = format!(
                        "Alias '{}' not found in personal keys, team keys, or OAuth accounts.\n\
                         \n\
                         Hints:\n\
                         - run `aikey list` to see all known aliases\n\
                         - for team keys, run `aikey key sync` first in case the cache is stale",
                        alias);
                    if cli.json { json_output::error(&msg, EXIT_ALIAS_NOT_FOUND); }
                    else { eprintln!("{}", msg); std::process::exit(EXIT_ALIAS_NOT_FOUND); }
                }

                let opts = commands_project::SuiteOptions {
                    show_proxy_row: false,
                    header_label:   None,
                    password:       None,
                    proxy_port,
                };
                let outcome = if cli.json {
                    commands_project::run_connectivity_suite(targets, opts, true)
                } else {
                    use colored::Colorize;
                    if targets.len() == 1 {
                        let t = &targets[0];
                        eprintln!("  Testing '{}' ({} \u{2192} {})",
                            alias.bold(), t.display_label(), t.base_url.dimmed());
                    } else {
                        eprintln!("  Testing '{}' across {} provider(s)",
                            alias.bold(), targets.len());
                    }
                    eprintln!();
                    commands_project::run_connectivity_suite(targets, opts, false)
                };
                // Emit JSON BEFORE the exit; json_output::success exits with
                // code 0, which would clobber our structured exit code —
                // print raw JSON then exit with the right code instead.
                if cli.json {
                    let payload = serde_json::json!({
                        "status":  if exit_code_from_outcome(&outcome) == EXIT_OK { "success" } else { "failed" },
                        "alias":   alias,
                        "results": outcome.json_results,
                    });
                    eprintln!("{}", serde_json::to_string_pretty(&payload).unwrap());
                }
                std::process::exit(exit_code_from_outcome(&outcome));
            } else {
                // ── No alias: test all active bindings (personal/team/OAuth) ──
                let (targets, build_errors) =
                    commands_project::targets_from_active_bindings(None, proxy_port);

                if targets.is_empty() && build_errors.is_empty() {
                    if cli.json { json_output::error("No active provider bindings. Add a key first.", EXIT_ALIAS_NOT_FOUND); }
                    else { return Err("No active provider bindings. Add a key with `aikey add` first.".into()); }
                }

                let opts = commands_project::SuiteOptions {
                    show_proxy_row: true,
                    header_label:   None,
                    password:       None,
                    proxy_port,
                };
                let outcome = if cli.json {
                    commands_project::run_connectivity_suite(targets, opts, true)
                } else {
                    eprintln!("  Testing {} active provider binding(s)...\n",
                        targets.len() + build_errors.len());
                    let outcome = commands_project::run_connectivity_suite(targets, opts, false);
                    commands_project::render_cannot_test_block(&build_errors, false);
                    outcome
                };
                if cli.json {
                    let payload = serde_json::json!({
                        "status": if exit_code_from_outcome(&outcome) == EXIT_OK { "success" } else { "failed" },
                        "bindings_tested": outcome.json_results,
                        "build_errors": build_errors.iter().map(|e| serde_json::json!({
                            "label":  e.label(),
                            "reason": e.reason(),
                        })).collect::<Vec<_>>(),
                    });
                    eprintln!("{}", serde_json::to_string_pretty(&payload).unwrap());
                }
                std::process::exit(exit_code_from_outcome(&outcome));
            }
        }
        Commands::Export { pattern, output } => {
            let vault_password = prompt_password_secure("\u{1F512} Enter Master Password: ", cli.password_stdin, cli.json)?;
            let export_password = prompt_password_secure("\u{1F512} Enter Export Password: ", cli.password_stdin, cli.json)?;
            let output_path = std::path::Path::new(output);

            let result = synapse::export_vault(pattern, output_path, &vault_password, &export_password);
            let _ = audit::log_audit_event(&vault_password, audit::AuditOperation::Export, Some(pattern), result.is_ok());

            let count = match result {
                Ok(c) => c,
                Err(e) => {
                    if cli.json {
                        json_output::error(&e.to_string(), 1);
                    } else {
                        return Err(e.into());
                    }
                }
            };

            if cli.json {
                json_output::success(serde_json::json!({
                    "count": count,
                    "output": output,
                    "message": format!("Exported {} secret(s)", count)
                }));
            } else {
                println!("Exported {} secret(s) to {}", count, output);
            }
        }
        Commands::Run { provider, logical_model, model, tenant, profile, dry_run, direct, command } => {
            if command.is_empty() {
                let err_msg = "No command specified. Use -- to separate command from flags.";
                if cli.json {
                    json_output::error_stderr(err_msg, 1);
                } else {
                    return Err(err_msg.into());
                }
            }

            // Tenant precedence: --tenant > AIKEY_TENANT env var
            let env_tenant = std::env::var("AIKEY_TENANT").ok();
            let resolved_tenant = tenant.as_deref().or(env_tenant.as_deref());

            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

            // Profile override: --profile temporarily switches the active profile for this run.
            let _profile_guard = if let Some(p) = profile {
                let prev = global_config::get_current_profile().ok().flatten();
                global_config::set_current_profile(p)
                    .map_err(|e| format!("failed to set profile '{}': {}", p, e))?;
                Some(prev)
            } else {
                None
            };

            // --direct: bypass proxy — decrypt the real key and inject it directly
            // into the child process, overriding any proxy env vars from the shell.
            // Only personal keys are supported (team keys are always proxy-routed).
            if *direct {
                commands_account::handle_run_direct(command, &password, cli.json)?;
                return Ok(());
            }

            // Proxy guard: ensure aikey-proxy is running before executing the command.
            // Runs silently in the happy path; warns on failure but does not abort.
            if !*dry_run {
                commands_proxy::proxy_guard(&password);
            }

            if *dry_run {
                let infos = if let Some(provider_name) = provider {
                    let project_config = config::ProjectConfig::discover()
                        .ok()
                        .flatten()
                        .map(|(_, cfg)| cfg);
                    executor::dry_run_provider(provider_name, model.as_deref(), resolved_tenant, project_config.as_ref())?
                } else {
                    let project_config = config::ProjectConfig::discover()
                        .ok()
                        .flatten()
                        .map(|(_, cfg)| cfg);
                    if let Some(cfg) = project_config.as_ref() {
                        executor::dry_run_project_config(cfg, logical_model.as_deref(), resolved_tenant)?
                    } else {
                        return Err("No aikey.config.json found and no --provider specified.\n\
                            For dry-run, use: aikey run --provider anthropic --dry-run -- <cmd>".into());
                    }
                };

                if cli.json {
                    json_output::print_json(serde_json::json!({
                        "dry_run": true,
                        "command": command,
                        "injections": infos
                    }));
                } else {
                    // P1-Q4: Enhanced dry-run output
                    println!("Dry Run — Resolution Summary");
                    println!("============================");
                    println!();

                    for info in &infos {
                        println!("Environment Variable: {}", info.env_var);
                        println!("  Provider:      {}", info.provider);
                        if let Some(model) = &info.model {
                            println!("  Model:         {}", model);
                        }
                        if !info.key_alias.is_empty() {
                            println!("  Key Alias:     {}", info.key_alias);
                        }
                        println!("  Source:        {}", info.source);
                        if info.tenant_override {
                            println!("  Tenant Override: YES");
                        }
                        println!();
                    }

                    println!("Will inject {} variable(s) into:", infos.len());
                    println!("  {}", command.join(" "));
                    println!();
                    println!("Note: Secret values are hidden. Use 'aikey run' without --dry-run to execute.");
                }
            } else {
                let result = if let Some(provider_name) = provider {
                    // Provider-mode: resolve a single provider key via the 5-step resolver
                    let project_config = config::ProjectConfig::discover()
                        .ok()
                        .flatten()
                        .map(|(_, cfg)| cfg);

                    executor::run_with_provider(
                        provider_name,
                        model.as_deref(),
                        resolved_tenant,
                        project_config.as_ref(),
                        &password,
                        command,
                        cli.json,
                    )
                } else {
                    // No --provider: use project config if present, then active key
                    // via proxy, and finally fall back to vault-auto detection.
                    let project_config = config::ProjectConfig::discover()
                        .ok()
                        .flatten()
                        .map(|(_, cfg)| cfg);

                    if let Some(cfg) = project_config.as_ref() {
                        executor::run_with_project_config(cfg, &password, command, cli.json, logical_model.as_deref(), resolved_tenant)
                    } else if !storage::list_provider_bindings("default").unwrap_or_default().is_empty()
                        || storage::get_active_key_config().ok().flatten().is_some()
                    {
                        // Provider bindings exist, or legacy active key — route via proxy.
                        executor::run_with_active_key(command, cli.json)
                    } else {
                        executor::run_from_vault(&password, command, cli.json)
                    }
                };

                match result {
                    Ok((secrets_count, exit_code)) => {
                        if cli.json {
                            json_output::success_stderr(serde_json::json!({
                                "secrets_injected": secrets_count,
                                "exit_code": exit_code
                            }));
                        }
                    }
                    Err(e) => {
                        // Extract exit code from error message if present
                        let exit_code = if let Some(code_str) = e.strip_prefix("Command exited with code ") {
                            code_str.parse::<i32>().unwrap_or(1)
                        } else {
                            1
                        };

                        if cli.json {
                            json_output::error_with_data_stderr(
                                &e,
                                serde_json::json!({
                                    "exit_code": exit_code
                                }),
                                exit_code
                            );
                        } else {
                            eprintln!("Error: {}", e);
                            std::process::exit(exit_code);
                        }
                    }
                }
            }

            // Restore previous profile if we overrode it.
            if let Some(prev_profile) = _profile_guard {
                if let Some(p) = prev_profile {
                    let _ = global_config::set_current_profile(&p);
                }
            }

            // Post-operation: warn if proxy is unreachable (complements proxy_guard
            // which may have failed to start the proxy after a kill -9).
            if !*dry_run {
                commands_proxy::warn_if_proxy_down();
            }
        }
        Commands::ChangePassword => {
            let old_password = prompt_password_secure("\u{1F512} Enter Master Password: ", cli.password_stdin, cli.json)?;
            let new_password = prompt_password_secure("\u{1F512} Enter New Master Password: ", false, cli.json)?;
            let confirm_password = prompt_password_secure("\u{1F512} Confirm New Master Password: ", false, cli.json)?;

            if new_password.expose_secret() != confirm_password.expose_secret() {
                if cli.json {
                    json_output::error("Passwords do not match", 1);
                } else {
                    return Err("Passwords do not match".into());
                }
            }

            if !cli.json {
                println!("Changing master password...");
            }
            let result = storage::change_password(&old_password, &new_password);
            let _ = audit::log_audit_event(&old_password, audit::AuditOperation::Init, None, result.is_ok());

            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }

            // Invalidate cached session — the password has changed.
            session::invalidate();

            if cli.json {
                json_output::success(serde_json::json!({
                    "message": "Master password changed successfully."
                }));
            } else {
                println!("Master password changed successfully!");
            }
        }
        Commands::Secret { action } => {
            match action {
                SecretAction::Set { name, provider, from_stdin } => {
                    if !from_stdin {
                        let err_msg = "The --from-stdin flag is required for security. API Key values must not be passed via command-line arguments.";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    if let Err(e) = validate_secret_name(name) {
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": e
                            }), 1);
                        } else {
                            return Err(e.into());
                        }
                    }

                    let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

                    let existing = executor::list_secrets(&password);
                    let existing = match existing {
                        Ok(list) => list,
                        Err(e) => {
                            if cli.json {
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    };

                    if existing.iter().any(|alias| alias == name) {
                        let err_msg = format!(
                            "API Key '{}' already exists. Use 'aikey secret upsert {}' to overwrite.",
                            name, name
                        );
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::AliasExists.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    // Read secret value: hidden prompt on TTY, plain stdin for pipes
                    let secret = if std::io::stdin().is_terminal() {
                        let val = prompt_hidden("\u{1F511} Enter API Key value: ")
                            .map_err(|e| format!("Failed to read secret value: {}", e))?;
                        Zeroizing::new(val)
                    } else {
                        let mut buf = Zeroizing::new(String::new());
                        io::stdin().read_line(&mut buf)?;
                        buf
                    };
                    let secret_value = secret.trim();

                    if secret_value.is_empty() {
                        let err_msg = "Secret value cannot be empty";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    let result = executor::add_secret(name, secret_value, &password);
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Add, Some(name), result.is_ok());

                    match result {
                        Ok(_) => {
                            // Persist provider_code if supplied.
                            if let Some(code) = provider {
                                let _ = storage::set_entry_provider_code(name, Some(code.to_lowercase().as_str()));
                            }
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("API Key '{}' set successfully", name);
                                commands_proxy::maybe_warn_stale();
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                SecretAction::Upsert { name, provider, from_stdin } => {
                    if !from_stdin {
                        let err_msg = "The --from-stdin flag is required for security. API Key values must not be passed via command-line arguments.";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    if let Err(e) = validate_secret_name(name) {
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": e
                            }), 1);
                        } else {
                            return Err(e.into());
                        }
                    }

                    let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

                    // Read secret value: hidden prompt on TTY, plain stdin for pipes
                    let secret = if std::io::stdin().is_terminal() {
                        let val = prompt_hidden("\u{1F511} Enter API Key value: ")
                            .map_err(|e| format!("Failed to read secret value: {}", e))?;
                        Zeroizing::new(val)
                    } else {
                        let mut buf = Zeroizing::new(String::new());
                        io::stdin().read_line(&mut buf)?;
                        buf
                    };
                    let secret_value = secret.trim();

                    if secret_value.is_empty() {
                        let err_msg = "Secret value cannot be empty";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    // Check if secret exists to determine add vs update
                    let existing = executor::list_secrets(&password).unwrap_or_default();
                    let result = if existing.iter().any(|alias| alias == name) {
                        executor::update_secret(name, secret_value, &password)
                    } else {
                        executor::add_secret(name, secret_value, &password)
                    };
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Update, Some(name), result.is_ok());

                    match result {
                        Ok(_) => {
                            // Persist provider_code if supplied.
                            if let Some(code) = provider {
                                let _ = storage::set_entry_provider_code(name, Some(code.to_lowercase().as_str()));
                            }
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("API Key '{}' upserted successfully", name);
                                commands_proxy::maybe_warn_stale();
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                SecretAction::List => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;

                    let result = executor::list_secrets_with_metadata(&password);
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::List, None, result.is_ok());

                    match result {
                        Ok(secrets) => {
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "deprecated": true,
                                    "deprecation_hint": "use `aikey list` for the unified view",
                                    "secrets": secrets
                                }));
                            } else {
                                use colored::Colorize;
                                eprintln!("{}  {}",
                                    "deprecated:".yellow().bold(),
                                    "`aikey secret list` will be removed — use `aikey list` for the unified view (personal / team / OAuth).".dimmed());
                                eprintln!();
                                if secrets.is_empty() {
                                    println!("No API Keys stored.");
                                } else {
                                    println!("Stored API Keys:");
                                    for secret in secrets {
                                        println!("  {}", secret.alias);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                SecretAction::Delete { name } => {
                    let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

                    let result = executor::delete_secret(name, &password);
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Delete, Some(name), result.is_ok());

                    match result {
                        Ok(_) => {
                            // Reconcile provider bindings after removal.
                            let actions = profile_activation::reconcile_provider_primary_after_key_removal(
                                "personal", name,
                            ).unwrap_or_default();
                            if !actions.is_empty() {
                                let _ = profile_activation::refresh_implicit_profile_activation();
                            }

                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name,
                                    "reconciled_providers": actions.iter().map(|a| &a.provider_code).collect::<Vec<_>>(),
                                }));
                            } else {
                                use colored::Colorize;
                                println!("API Key '{}' deleted successfully", name);
                                for action in &actions {
                                    match &action.outcome {
                                        profile_activation::ReconcileOutcome::Replaced { new_source_ref, .. } => {
                                            eprintln!("  {} '{}' promoted to Primary for {}",
                                                "\u{2B50}".yellow(), new_source_ref.bold(), action.provider_code);
                                        }
                                        profile_activation::ReconcileOutcome::Cleared => {
                                            eprintln!("  {} No replacement for {} — provider has no Primary",
                                                "\u{26A0}".yellow(), action.provider_code);
                                        }
                                    }
                                }
                                commands_proxy::maybe_warn_stale();
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
            }
        }
        Commands::Project { action } => {
            match action {
                ProjectAction::Init => {
                    commands_project::handle_project_init(cli.json)?;
                }
                ProjectAction::Status => {
                    commands_project::handle_project_status(cli.json)?;
                }
                ProjectAction::Map { var, alias, env, provider, model, key_alias, impl_id } => {
                    commands_project::handle_project_map(var, alias, env.as_deref(), provider.as_deref(), model.as_deref(), key_alias.as_deref(), impl_id.as_deref(), cli.json)?;
                }
            }
        }
        Commands::Quickstart => {
            commands_project::handle_quickstart(cli.json)?;
        }
        Commands::Key { action } => {
            match action {
                KeyAction::Rotate { name, from_stdin } => {
                    let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;

                    // Why the four-way fork: before this, `key rotate` called
                    // prompt_hidden unconditionally when --from-stdin was off.
                    // In pipelines or CI that gives "Device not configured
                    // (os error 6)" from the /dev/tty open, with no actionable
                    // hint. Mirror `aikey update`: AK_TEST_SECRET wins, then
                    // explicit --from-stdin, then TTY, then plain stdin with
                    // a clear prompt instead of a cryptic open() error.
                    let new_value = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                        Zeroizing::new(test_secret)
                    } else if *from_stdin {
                        eprint!("Enter new value for '{}' (then press Enter): ", name);
                        let _ = io::stderr().flush();
                        let mut buf = Zeroizing::new(String::new());
                        io::stdin().read_line(&mut buf)?;
                        buf
                    } else if std::io::stdin().is_terminal() {
                        let val = prompt_hidden(&format!("\u{1F511} New value for '{}': ", name))
                            .map_err(|e| format!(
                                "Failed to read new key value: {}.\n\
                                 Tip: in non-interactive mode pass --from-stdin and pipe the value in, \
                                 or set AK_TEST_SECRET for scripted runs.",
                                e))?;
                        Zeroizing::new(val)
                    } else {
                        // Non-TTY, no flag, no env — accept piped stdin rather
                        // than erroring out. Quietly annotate on stderr so the
                        // caller knows what happened in case they expected a
                        // prompt.
                        if !cli.json {
                            eprintln!("(reading new value for '{}' from stdin; pass --from-stdin to silence this hint)", name);
                        }
                        let mut buf = Zeroizing::new(String::new());
                        io::stdin().read_line(&mut buf)?;
                        buf
                    };
                    let new_value_str = new_value.trim();

                    if new_value_str.is_empty() {
                        let err_msg = "New key value cannot be empty";
                        if cli.json {
                            json_output::print_json_exit(serde_json::json!({
                                "ok": false,
                                "code": error_codes::ErrorCode::InvalidInput.as_str(),
                                "message": err_msg
                            }), 1);
                        } else {
                            return Err(err_msg.into());
                        }
                    }

                    // Check if secret exists to determine add vs update
                    let existing = executor::list_secrets(&password).unwrap_or_default();
                    let result = if existing.iter().any(|alias| alias == name) {
                        executor::update_secret(name, new_value_str, &password)
                    } else {
                        executor::add_secret(name, new_value_str, &password)
                    };
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Update, Some(name), result.is_ok());

                    match result {
                        Ok(_) => {
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("Key '{}' rotated successfully", name);
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                let code = error_codes::ErrorCode::from_error_message(&e);
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "code": code.as_str(),
                                    "message": e
                                }), 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                KeyAction::List => {
                    run_unified_list(cli.password_stdin, cli.json)?;
                }
                KeyAction::Sync => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    commands_account::handle_key_sync(&password, cli.json)?;
                }
                KeyAction::Use { alias_or_id, no_hook } => {
                    commands_proxy::ensure_proxy_for_use(cli.password_stdin);
                    commands_account::handle_key_use(alias_or_id, *no_hook, None, cli.json)?;
                    commands_proxy::warn_if_proxy_down();
                }
                KeyAction::Alias { old_alias, new_alias } => {
                    commands_account::handle_key_alias(old_alias, new_alias, cli.json)?;
                }
            }
        }
        Commands::Account { action } => {
            match action {
                AccountAction::Login { url, token, email, resend } => {
                    commands_account::handle_login(
                        cli.json,
                        url.clone(),
                        token.clone(),
                        email.clone(),
                        *resend,
                    )?;
                }
                AccountAction::Status => {
                    commands_account::handle_account_status(cli.json)?;
                }
                AccountAction::Logout => {
                    commands_account::handle_logout(cli.json)?;
                }
                AccountAction::SetUrl { url } => {
                    commands_account::handle_set_control_url(url, cli.json)?;
                }
            }
        }
        Commands::Activate { alias, provider, shell } => {
            handle_activate(alias.as_deref(), provider.as_deref(), shell.as_deref())?;
        }
        Commands::Deactivate { shell } => {
            handle_deactivate(shell.as_deref())?;
        }
        Commands::Route { label, full } => {
            handle_route(label.as_deref(), *full, cli.json)?;
        }
        Commands::Login { url, token, email, resend } => {
            commands_account::handle_login(cli.json, url.clone(), token.clone(), email.clone(), *resend)?;
        }
        Commands::Logout => {
            commands_account::handle_logout(cli.json)?;
        }
        Commands::Use { alias_or_id, no_hook, provider } => {
            // One-time backfill: generate route_tokens for existing keys that lack them.
            // Why here: `aikey use` is the most common write-path command after upgrade.
            let backfilled = storage::backfill_route_tokens().unwrap_or(0);
            if backfilled > 0 {
                let _ = storage::bump_vault_change_seq();
            }

            match alias_or_id {
                Some(a) => {
                    // `aikey use <alias>` — provider-level promotion via handle_key_use.
                    commands_proxy::ensure_proxy_for_use(cli.password_stdin);
                    commands_account::handle_key_use(
                        a, *no_hook, provider.as_deref(), cli.json,
                    )?;
                }
                None => {
                    // `aikey use` (no args) — provider-tree interactive editor.
                    if !std::io::stdin().is_terminal() || cli.json {
                        return Err("alias required in non-interactive mode (usage: aikey use <ALIAS>)".into());
                    }
                    commands_proxy::ensure_proxy_for_use(cli.password_stdin);
                    let changes = pick_providers_interactively()?;
                    if changes.is_empty() {
                        eprintln!("  No changes.");
                    } else {
                        // Canonical-write (2026-04-24 rule) — interactive
                        // `aikey use` picker's selected bindings go through
                        // the same helper as every other write path.
                        for (prov, src_type, src_ref) in &changes {
                            commands_account::write_bindings_canonical(
                                &[prov.clone()],
                                src_type,
                                src_ref,
                            ).map_err(|e| format!("Failed to set binding: {}", e))?;
                        }
                        let refresh = profile_activation::refresh_implicit_profile_activation()
                            .map_err(|e| format!("Failed to refresh activation: {}", e))?;
                        if !*no_hook {
                            commands_account::ensure_shell_hook(false);
                        }

                        // Auto-configure / unconfigure third-party CLI tools.
                        let proxy_port = commands_proxy::proxy_port();
                        let all_providers: Vec<String> = refresh.bindings.iter()
                            .map(|b| b.provider_code.clone())
                            .collect();

                        let has_kimi = all_providers.iter().any(|p| {
                            let c = p.to_lowercase();
                            c == "kimi" || c == "moonshot"
                        });
                        if has_kimi {
                            commands_account::configure_kimi_cli(proxy_port);
                        } else {
                            commands_account::unconfigure_kimi_cli();
                        }

                        let has_openai = all_providers.iter().any(|p| {
                            let c = p.to_lowercase();
                            c == "openai" || c == "gpt" || c == "chatgpt"
                        });
                        if has_openai {
                            commands_account::configure_codex_cli(proxy_port);
                        } else {
                            commands_account::unconfigure_codex_cli();
                        }

                        // Print a summary box showing the final state.
                        use colored::Colorize;
                        let changed_providers: Vec<&str> = changes.iter()
                            .map(|(p, _, _)| p.as_str())
                            .collect();
                        let mut box_rows: Vec<String> = Vec::new();
                        for b in &refresh.bindings {
                            let display_name = resolve_binding_display_name(b.key_source_type.as_str(), &b.key_source_ref);
                            let is_changed = changed_providers.contains(&b.provider_code.as_str());
                            let value_raw = format!("\u{2192} {}", display_name);
                            let value_padded = format!("{:<28}", value_raw);
                            let value_col = if is_changed {
                                value_padded.green().to_string()
                            } else {
                                value_padded
                            };
                            box_rows.push(format!("  {:<14} {} \x1b[90m[{}]\x1b[0m",
                                b.provider_code, value_col, b.key_source_type));
                        }
                        box_rows.push(String::new());
                        box_rows.push(format!("{} Saved provider primary selections and refreshed current activation.",
                            "\u{2713}".green()));
                        ui_frame::print_box(
                            "\u{1F7E2}",
                            "Provider Key Selection — Confirmed",
                            &box_rows,
                        );

                        // Check if the shell hook is active: if AIKEY_ACTIVE_KEYS is set
                        // in the parent shell, precmd is working and will auto-refresh.
                        // If not, the user needs to source manually (first time or new terminal).
                        //
                        // Stage 3.6 windows-compat: route the hint through `reload_hint_for_shell`
                        // so PowerShell / cmd users see something runnable in their shell
                        // instead of `source ~/.zshrc` (which is a dead string off Unix).
                        // Stage 3 review fix: only append "(or open a new terminal)" when
                        // the hint is actually a runnable command — Cmd / Unknown already
                        // says "open a new terminal", appending it twice looks broken.
                        if std::env::var("AIKEY_ACTIVE_KEYS").is_err() {
                            let hint = commands_account::reload_hint_for_shell();
                            if commands_account::reload_hint_has_runnable_command() {
                                eprintln!("  \x1b[33m!\x1b[0m Run: \x1b[1m{hint}\x1b[0m  (or open a new terminal)");
                            } else {
                                eprintln!("  \x1b[33m!\x1b[0m {hint}");
                            }
                        }
                        println!();
                    }
                }
            }
            commands_proxy::warn_if_proxy_down();
        }
        Commands::Env { action } => {
            match action {
                None => {
                    // `aikey env` — read-only display of active.env + proxy.env.
                    use colored::Colorize;
                    let active_path = proxy_env::active_env_path().unwrap_or_default();
                    let proxy_path = proxy_env::proxy_env_path().unwrap_or_default();

                    // Active env section.
                    eprintln!("{}", "Active env:".bold());
                    eprintln!("  Path: {}", active_path.display().to_string().dimmed());
                    if active_path.exists() {
                        match proxy_env::read_active_env_lines() {
                            Ok(entries) if entries.is_empty() => {
                                eprintln!("  (empty)");
                            }
                            Ok(entries) => {
                                for (k, v) in &entries {
                                    eprintln!("  {}={}", k, proxy_env::mask_value(k, v).dimmed());
                                }
                                // Synthesize a readable bypass summary from the
                                // conditional `case` blocks (which we hide above).
                                // The resolved value comes from the file content.
                                if let Some(bypass) = proxy_env::read_active_bypass_summary() {
                                    eprintln!("  {}  {}",
                                        "no_proxy (bypass)".to_string(),
                                        bypass.dimmed());
                                }
                            }
                            Err(e) => eprintln!("  {}", format!("Error: {}", e).red()),
                        }
                    } else {
                        eprintln!("  {}", "(not found)".dimmed());
                    }
                    eprintln!();

                    // Proxy env section.
                    eprintln!("{}", "Proxy env:".bold());
                    eprintln!("  Path: {}", proxy_path.display().to_string().dimmed());
                    if proxy_path.exists() {
                        match proxy_env::read_proxy_env() {
                            Ok(map) if map.is_empty() => {
                                eprintln!("  (empty)");
                            }
                            Ok(map) => {
                                for (k, v) in &map {
                                    eprintln!("  {}={}", k, proxy_env::mask_value(k, v).dimmed());
                                }
                                eprintln!();
                                eprintln!("  Entries: {}  Hash: {}",
                                    map.len(), proxy_env::config_hash(&map).dimmed());
                            }
                            Err(e) => eprintln!("  {}", format!("Error: {}", e).red()),
                        }
                    } else {
                        eprintln!("  {}", "(not found — use `aikey env set -- KEY=VALUE` to create)".dimmed());
                    }

                    // Shell env (inherited): show proxy-related env vars from the current shell.
                    // These are inherited by the aikey-proxy process when it starts.
                    eprintln!();
                    eprintln!("{}", "Shell env (inherited by proxy):".bold());
                    let inherited_keys = [
                        "http_proxy", "https_proxy", "all_proxy",
                        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                        "no_proxy", "NO_PROXY",
                    ];
                    let mut found_any = false;
                    for key in &inherited_keys {
                        if let Ok(val) = std::env::var(key) {
                            if !val.is_empty() {
                                let display = if val.len() > 60 {
                                    format!("{}... ({} chars)", &val[..40], val.len())
                                } else {
                                    val
                                };
                                eprintln!("  {}={}", key, display.dimmed());
                                found_any = true;
                            }
                        }
                    }
                    if !found_any {
                        eprintln!("  {}", "(no proxy env vars detected)".dimmed());
                    }
                }
                Some(EnvAction::Set { args }) => {
                    // `aikey env set -- KEY=VALUE ...`
                    // Also supports stdin pipe: echo "K=V" | aikey env set
                    use colored::Colorize;

                    // Collect input: from args, or from stdin if args empty and stdin is piped.
                    let effective_args: Vec<String> = if !args.is_empty() {
                        args.clone()
                    } else if !std::io::stdin().is_terminal() {
                        let mut buf = String::new();
                        io::stdin().read_line(&mut buf)?;
                        vec![buf]
                    } else {
                        return Err(
                            "Usage: aikey env set -- KEY=VALUE [KEY2=VALUE2 ...]\n\
                             \n\
                             Examples:\n  \
                               aikey env set -- http_proxy=http://127.0.0.1:7890 https_proxy=http://127.0.0.1:7890\n  \
                               echo 'http_proxy=http://127.0.0.1:7890' | aikey env set\n\
                             \n\
                             Note: use spaces (not semicolons) to separate multiple entries,\n\
                             or quote the entire argument if using semicolons:\n  \
                               aikey env set -- 'export A=1; export B=2'".into()
                        );
                    };

                    // Parse new entries from args.
                    let new_entries = proxy_env::parse_set_args(&effective_args)
                        .map_err(|e| format!("Parse error: {}", e))?;

                    if new_entries.is_empty() {
                        return Err("No valid KEY=VALUE pairs found.".into());
                    }

                    // Read existing, merge, write back.
                    // Why explicit error: if the old file is corrupt, we must not
                    // silently discard it — user should fix it first.
                    let mut existing = proxy_env::read_proxy_env()
                        .map_err(|e| format!(
                            "Cannot parse existing ~/.aikey/proxy.env: {}\n\
                             Fix or remove the file before setting new values.", e
                        ))?;
                    for (k, v) in &new_entries {
                        existing.insert(k.clone(), v.clone());
                    }
                    proxy_env::write_proxy_env(&existing)?;

                    let path = proxy_env::proxy_env_path().unwrap_or_default();
                    eprintln!("{} Updated {}", "\u{2713}".green(), path.display());
                    for (k, _) in &new_entries {
                        eprintln!("  {} {}", "+".green(), k);
                    }

                    // Auto-restart proxy if running so new env takes effect immediately.
                    // Round 9 fix #1: was is_proxy_running (PID-only); now uses
                    // proxy_is_running_managed so we don't try to restart an
                    // OrphanedPort / Unresponsive instance that isn't ours.
                    if commands_proxy::proxy_is_running_managed() {
                        eprintln!();
                        eprintln!("  Restarting proxy to apply changes...");
                        let pw = session::try_get()
                            .or_else(|| std::env::var("AK_TEST_PASSWORD").ok().map(SecretString::new));
                        match pw {
                            Some(password) => {
                                match commands_proxy::handle_restart(None, &password) {
                                    Ok(()) => {
                                        eprintln!("  {} Proxy restarted with new env.", "\u{2713}".green());
                                    }
                                    Err(e) => {
                                        eprintln!("  {} Auto-restart failed: {}", "\u{26A0}".yellow(), e);
                                        eprintln!("  Run manually: {}", "aikey proxy restart".bold());
                                    }
                                }
                            }
                            None => {
                                eprintln!("  {} Cannot auto-restart (no cached password).",
                                    "\u{26A0}".yellow());
                                eprintln!("  Run manually: {}", "aikey proxy restart".bold());
                            }
                        }
                    } else {
                        eprintln!();
                        eprintln!("  Proxy not running. Changes will apply on next {}.",
                            "aikey proxy start".bold());
                    }
                }
            }
        }
        Commands::Web { page, import, vault, port } => {
            // Shortcut flags override the positional page. `--vault` and
            // `--import` are mutually informative — `--vault` wins when
            // both are passed (alphabetical fallback, intentional choice;
            // not worth surfacing a hard error for a typo combo).
            let effective_page: Option<&str> = if *vault {
                Some("vault")
            } else if *import {
                Some("import")
            } else {
                page.as_deref()
            };
            commands_account::handle_browse(effective_page, *port, cli.json)?;
        }
        Commands::Master { page, url, port } => {
            commands_account::handle_master_browse(page.as_deref(), url.as_deref(), *port, cli.json)?;
        }
        Commands::Import { file, non_interactive, yes, provider } => {
            commands_import::handle(
                file.as_deref(),
                *non_interactive,
                *yes,
                provider.as_deref(),
                cli.json,
            )?;
        }
        Commands::Status => {
            commands_account::handle_status_overview(cli.json)?;
            // Mode A addendum: append a local-server status line so users have
            // a single command for "is my console reachable". See
            // roadmap20260320/技术实现/update/20260422-批量导入-aikey-serve-命令移除.md
            if !cli.json {
                println!();
                println!("{}", commands_import::local_server_status_line());
            }
        }
        Commands::Whoami => {
            commands_account::handle_whoami(cli.json)?;
        }
        Commands::Doctor { detail } => {
            commands_project::handle_doctor(cli.json)?;
            if *detail && !cli.json {
                commands_project::handle_doctor_detail()?;
            }
        }
        Commands::Proxy { action } => {
            match action {
                ProxyAction::Start { config, foreground } => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    // Verify the password is valid before handing it to the proxy.
                    executor::list_secrets(&password)
                        .map_err(|e| format!("vault authentication failed: {}", e))?;
                    // Why: default is background (detach=true) so the terminal is not blocked.
                    // Use --foreground for debugging or when running under a process manager.
                    commands_proxy::handle_start(
                        config.as_deref(),
                        !*foreground,  // detach = !foreground
                        &password,
                    )?;
                }
                ProxyAction::Stop => {
                    commands_proxy::handle_stop()?;
                }
                ProxyAction::Status => {
                    commands_proxy::handle_status()?;
                }
                ProxyAction::Restart { config } => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    executor::list_secrets(&password)
                        .map_err(|e| format!("vault authentication failed: {}", e))?;
                    commands_proxy::handle_restart(config.as_deref(), &password)?;
                }
                ProxyAction::Verify => {
                    let password = prompt_vault_password(cli.password_stdin, cli.json)?;
                    executor::list_secrets(&password)
                        .map_err(|e| format!("vault authentication failed: {}", e))?;
                    commands_proxy::handle_verify(&password)?;
                }
                ProxyAction::EnsureRunning => {
                    // Wrapper-internal entry point (claude/codex/kimi shell hooks).
                    // Reuses the same `ensure_proxy_for_use` chain `aikey use` invokes:
                    //   already running → no-op silently
                    //   AIKEY_MASTER_PASSWORD set → silent start
                    //   interactive TTY → password prompt + start
                    //   non-TTY no env var → print one-line hint, do not block
                    // Exit non-zero only if the proxy is still down after the attempt,
                    // so wrapper hooks can fall back to their existing "Continue
                    // anyway?" path on rc=5 from the subsequent `aikey test`.
                    //
                    // Round 9 fix #1: was is_proxy_listening (PID + port);
                    // now uses proxy_is_running_managed (Layer 1 identity +
                    // ownership + /health). The original "PID + port" was
                    // already insufficient — port can be held by a different
                    // aikey-proxy instance. Layer 1 is the canonical
                    // "is it ours and healthy" answer for the wrapper exit-code
                    // contract (rc=5 means "not our proxy, fall back to user
                    // prompt"). Defense-in-depth note: the false-positive
                    // window from stale pidfile is now closed at the source
                    // (StartCleanupGuard, Round 6 fix #1) AND here.
                    commands_proxy::ensure_proxy_for_use(cli.password_stdin);
                    if !commands_proxy::proxy_is_running_managed() {
                        std::process::exit(5);
                    }
                }
            }
        }
        Commands::Logs { limit } => {
            let entries = events::list_events(*limit)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("No events recorded yet.");
            } else {
                println!("{:<6} {:<20} {:<10} {:<12} {:<5} {}",
                    "ID", "TIMESTAMP", "TYPE", "PROTOCOL", "EXIT", "COMMAND");
                println!("{}", "-".repeat(72));
                for e in &entries {
                    let ts = e.timestamp.to_string();
                    println!("{:<6} {:<20} {:<10} {:<12} {:<5} {}",
                        e.id,
                        ts,
                        e.event_type,
                        e.provider.as_deref().unwrap_or("-"),
                        e.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string()),
                        e.command.as_deref().unwrap_or("-"),
                    );
                }
            }
        }
        Commands::Auth { action } => {
            let proxy_port = commands_proxy::proxy_port();
            commands_auth::handle_auth_command(action, proxy_port, cli.json)?;
        }
        Commands::Statusline { action } => match action {
            None => {
                // Default: render one-line receipt for Claude Code status line.
                // Errors are swallowed so a broken WAL never breaks the user's
                // prompt — worst case the row is empty.
                let _ = commands_statusline::run();
            }
            Some(cli::StatuslineAction::Install { target, all, force }) => {
                commands_statusline::install(target.as_deref(), *all, *force)?;
            }
            Some(cli::StatuslineAction::Uninstall { target, all }) => {
                commands_statusline::uninstall(target.as_deref(), *all)?;
            }
            Some(cli::StatuslineAction::Status) => {
                commands_statusline::print_status()?;
            }
            Some(cli::StatuslineAction::LastActive) => {
                commands_statusline::last_active()?;
            }
            Some(cli::StatuslineAction::Render { target }) => {
                // Hook-invoked render path. Only `kimi` is wired today; other
                // targets are silently accepted so that a future Kimi-version
                // bump or a typo doesn't crash the user's Stop hook.
                if target == "kimi" {
                    let _ = commands_statusline::render_kimi();
                }
            }
        },
        Commands::Watch => {
            commands_watch::run()?;
        }
    }
    Ok(())
}

/// Secure password prompt with Zeroizing protection
///
/// SECURITY HARDENING:
// ---------------------------------------------------------------------------
// aikey route — show proxy route tokens for third-party AI clients
// ---------------------------------------------------------------------------

/// A single route entry for display/JSON output.
#[derive(serde::Serialize)]
struct RouteEntry {
    provider: String,
    #[serde(rename = "type")]
    key_type: String,
    label: String,
    api_key: String,
    base_url: String,
    active: bool,
}

/// Provider code (or brand alias) → canonical data-model code for display.
/// Unknown codes fall back to the lowercased input. Delegates to the unified
/// `commands_account::provider_info` table (L5 2026-04-17).
fn provider_canonical(code: &str) -> String {
    commands_account::provider_info(code)
        .map(|i| i.canonical_code.to_string())
        .unwrap_or_else(|| code.to_lowercase())
}

/// Provider code → proxy URL path segment used when building `base_url` for
/// third-party clients. Unknown codes fall back to the lowercased input so new
/// providers registered server-side keep working before the CLI knows them.
fn provider_proxy_path(code: &str) -> String {
    commands_account::provider_info(code)
        .map(|i| i.proxy_path.to_string())
        .unwrap_or_else(|| code.to_lowercase())
}

/// Threshold (in chars) below which a token is shown in full. Above it, the token
/// is truncated as "first 15 chars + ... + last 4 chars". Keep in sync with the
/// truncation formula so padding math stays consistent.
const TOKEN_TRUNCATE_THRESHOLD: usize = 24;
// Token column width. A truncated personal-bearer display is 22 chars; +1 pad
// is enough to keep base_url from touching the token. Previously 38, which left
// a big visual gap — user reported the API_KEY/BASE URL pairing felt far apart.
const TOKEN_DISPLAY_WIDTH: usize = 23;
const PROVIDER_COL_WIDTH: usize = 13;
const LABEL_COL_WIDTH: usize = 28; // wide enough for most emails; longer labels truncated

/// Truncates a string to a max visual width (by char count), appending "…" when cut.
/// Why char-based: handles non-ASCII labels (e.g. CJK) without splitting code points.
fn truncate_to(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{}\u{2026}", kept) // '…'
}

/// Category order for the route table. Team first, OAuth next, personal last,
/// so the user sees organization-wide keys before individual ones.
fn route_type_order(t: &str) -> u8 {
    match t {
        "team" => 0,
        "oauth" => 1,
        "personal" => 2,
        _ => 99,
    }
}

/// Render the copy-paste config panel for one or more route entries.
/// Same layout is used by `aikey route <label>` and the interactive picker
/// so both surfaces feel consistent.
fn print_route_config(entries: &[&RouteEntry]) {
    use colored::Colorize;
    if entries.is_empty() { return; }
    let head = entries[0];

    // Title: label + colored [type] badge + provider(s).
    let providers = {
        let mut ps: Vec<&str> = entries.iter().map(|e| e.provider.as_str()).collect();
        ps.sort(); ps.dedup();
        ps.join(", ")
    };
    let type_badge = match head.key_type.as_str() {
        "team" => "[team]".cyan().bold().to_string(),
        "oauth" => "[oauth]".magenta().bold().to_string(),
        "personal" => "[personal]".yellow().bold().to_string(),
        _ => format!("[{}]", head.key_type),
    };

    println!();
    println!("  \u{1F511}  {}  {}  {}",
        head.label.bold(),
        type_badge,
        format!("\u{2192} {}", providers).dimmed());
    println!("  {}", "\u{2500}".repeat(68).dimmed());
    println!();

    // Key/value block. Values are plain (no color) so they survive copy-paste.
    let show_pair = |e: &RouteEntry, prefix: Option<&str>| {
        if let Some(p) = prefix { println!("  {}", format!("[{}]", p).cyan()); }
        println!("    {}   {}", "base_url".dimmed(), e.base_url);
        println!("    {}    {}", "api_key".dimmed(), e.api_key);
    };

    if entries.len() == 1 {
        show_pair(head, None);
    } else {
        for (i, e) in entries.iter().enumerate() {
            show_pair(e, Some(&e.provider));
            if i + 1 < entries.len() { println!(); }
        }
    }

    // Shell export snippet — the most common downstream paste target.
    println!();
    println!("  {}", "shell snippet:".dimmed());
    for e in entries {
        let env_prefix = e.provider.to_uppercase();
        println!("    export {}_BASE_URL=\"{}\"", env_prefix, e.base_url);
        println!("    export {}_API_KEY=\"{}\"", env_prefix, e.api_key);
    }
    // Or let `aikey activate` set it up in the current terminal session —
    // handy when the user doesn't want to wire env vars manually.
    println!();
    println!("  {}", "or activate for this terminal:".dimmed());
    println!("    aikey activate {}", head.label.cyan());
    println!();
}

fn handle_route(
    label: Option<&str>,
    full: bool,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    let proxy_port = commands_proxy::proxy_port();
    let mut entries: Vec<RouteEntry> = Vec::new();
    let mut missing_token_count = 0usize;
    let mut db_error_count = 0usize;

    // Pre-index active bindings for O(1) lookup instead of O(N*M) linear scan.
    let bindings = storage::list_provider_bindings_readonly("default").unwrap_or_default();
    let active_set: std::collections::HashSet<(&'static str, String)> = bindings.iter()
        .map(|b| {
            let kind: &'static str = match b.key_source_type {
                credential_type::CredentialType::ManagedVirtualKey => "team",
                credential_type::CredentialType::PersonalApiKey => "personal",
                credential_type::CredentialType::PersonalOAuthAccount => "oauth",
            };
            (kind, b.key_source_ref.clone())
        })
        .collect();
    let is_active = |source_type: &'static str, source_ref: &str| -> bool {
        active_set.contains(&(source_type, source_ref.to_string()))
    };

    // 1. Team managed keys
    for vk in storage::list_virtual_key_cache_readonly().unwrap_or_default() {
        // Show any team key that's server-side active, so `aikey route` mirrors
        // `aikey list` (synced_inactive keys are still available — the user can
        // `aikey use` them). The `●` marker separately distinguishes routes the
        // proxy is actually serving right now.
        if vk.key_status != "active" {
            continue;
        }
        let display_alias = vk.local_alias.as_deref().unwrap_or(&vk.alias);
        // Team key static bearer — shared helper guarantees identical output
        // with `resolve_activate_key`'s team branch (no drift between
        // `aikey route` and `aikey activate` for the same team key).
        // Empty vk_id is an upstream bug; warn + skip the row rather than
        // emit a degenerate `aikey_team_` token.
        let token = match team_token_normalize::team_token_from_vk_id(&vk.virtual_key_id) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "[aikey route] WARN: skip team key '{}' — {} (raw vk_id={:?})",
                    vk.alias, e, vk.virtual_key_id
                );
                continue;
            }
        };
        let providers = if vk.supported_providers.is_empty() {
            vec![vk.provider_code.clone()]
        } else {
            vk.supported_providers.clone()
        };
        for prov in &providers {
            entries.push(RouteEntry {
                provider: prov.clone(),
                key_type: "team".to_string(),
                label: display_alias.to_string(),
                api_key: token.clone(),
                base_url: format!("http://127.0.0.1:{}/{}", proxy_port, provider_proxy_path(prov)),
                active: is_active("team", &vk.virtual_key_id),
            });
        }
    }

    // 2. OAuth accounts
    for acct in storage::list_provider_accounts_readonly().unwrap_or_default() {
        if acct.status != "active" { continue; }
        let label_str = acct.display_identity.as_deref()
            .unwrap_or(&acct.provider_account_id);
        match storage::get_provider_account_route_token_readonly(&acct.provider_account_id) {
            Ok(Some(token)) => {
                entries.push(RouteEntry {
                    provider: provider_canonical(&acct.provider),
                    key_type: "oauth".to_string(),
                    label: label_str.to_string(),
                    api_key: token,
                    base_url: format!("http://127.0.0.1:{}/{}", proxy_port, provider_proxy_path(&acct.provider)),
                    active: is_active("oauth", &acct.provider_account_id),
                });
            }
            Ok(None) => { missing_token_count += 1; }
            Err(e) => {
                eprintln!("  {} Failed to read route token for OAuth account '{}': {}",
                    "\u{26a0}".yellow(), label_str, e);
                db_error_count += 1;
            }
        }
    }

    // 3. Personal keys
    for meta in storage::list_entries_with_metadata_readonly().unwrap_or_default() {
        // Skip entries without a provider (plain secrets, not API keys).
        if meta.provider_code.is_none() && meta.supported_providers.is_none() {
            continue;
        }
        match storage::get_entry_route_token_readonly(&meta.alias) {
            Ok(Some(token)) => {
                let providers: Vec<String> = match (&meta.supported_providers, &meta.provider_code) {
                    (Some(list), _) if !list.is_empty() => list.clone(),
                    (_, Some(p)) => vec![p.clone()],
                    _ => Vec::new(),
                };
                for prov in &providers {
                    entries.push(RouteEntry {
                        provider: prov.clone(),
                        key_type: "personal".to_string(),
                        label: meta.alias.clone(),
                        api_key: token.clone(),
                        base_url: format!("http://127.0.0.1:{}/{}", proxy_port, provider_proxy_path(prov)),
                        active: is_active("personal", &meta.alias),
                    });
                }
            }
            Ok(None) => { missing_token_count += 1; }
            Err(e) => {
                eprintln!("  {} Failed to read route token for personal key '{}': {}",
                    "\u{26a0}".yellow(), meta.alias, e);
                db_error_count += 1;
            }
        }
    }

    // Sort: team first, then OAuth, then personal. Within each group, alphabetical
    // by label (so multi-provider keys cluster together) and then by provider.
    entries.sort_by(|a, b| {
        route_type_order(&a.key_type).cmp(&route_type_order(&b.key_type))
            .then_with(|| a.label.cmp(&b.label))
            .then_with(|| a.provider.cmp(&b.provider))
    });

    // If a specific label was requested, filter and show copy-paste config on stdout
    // so `aikey route my-key | pbcopy` works as documented in the quickstart.
    if let Some(target) = label {
        let matched: Vec<&RouteEntry> = entries.iter()
            .filter(|e| e.label.eq_ignore_ascii_case(target))
            .collect();
        if matched.is_empty() {
            let msg = format!("Label '{}' not found. Run `aikey route` to see available routes.", target);
            if json_mode { json_output::error(&msg, 1); } else { return Err(msg.into()); }
        }
        if json_mode {
            json_output::success(serde_json::json!({ "routes": matched }));
        } else {
            print_route_config(&matched);
        }
        return Ok(());
    }

    // No label — list all routes.
    if json_mode {
        json_output::success(serde_json::json!({ "routes": entries }));
    }

    if entries.is_empty() {
        eprintln!("  No routes available. Add keys with `aikey add` or `aikey auth login`.");
        return Ok(());
    }

    // Active marker (`●`) lives in a dedicated leftmost column, so the label
    // column no longer needs to reserve space for it inline.
    let label_inner = LABEL_COL_WIDTH;

    // Group entries by TYPE so the output reads as a tree:
    //   team / oauth / personal → provider + label + token + base_url
    // Entries are already sorted by `route_type_order`, so a simple group-by
    // on consecutive same-typed rows preserves the intended ordering.
    // Row number width derives from total count so `10.` and `1.` align on
    // the dot column. The number sits *inside* the tree branch so the
    // ordering cue follows the visual indent of each route.
    let num_width = entries.len().to_string().len();
    // Base-url column width for header separator sizing. Row layout is:
    //   indent(2) + marker(1) + sp + connector(2) + sp + num_col(nw+1) + sp +
    //   provider(pw) + sp + label(li) + sp + token(kw) + sp + base_url
    let base_url_width = entries.iter()
        .map(|e| e.base_url.chars().count())
        .max()
        .unwrap_or(0);
    let total_width = 2 + 1 + 1 + 2 + 1 + (num_width + 1) + 1 + PROVIDER_COL_WIDTH
        + 1 + label_inner + 1 + TOKEN_DISPLAY_WIDTH + 1 + base_url_width;

    // Table header. Spaces stand in for the marker/connector columns so the
    // data column labels line up with their rows:
    //   row: "  {marker} {connector(2)} {num(nw+1)} {prov(pw)} {label(li)} {token(kw)} {base_url}"
    //   hdr: "     {sp(2)}              {#(nw+1)}   {PROVIDER} {LABEL}     {API_KEY}   {BASE URL}"
    eprintln!();
    eprintln!("    {:<2} {:>nw$} {:<pw$} {:<li$} {:<kw$} {}",
        "",
        "#".dimmed(),
        "PROTOCOL".dimmed(),
        "LABEL".dimmed(),
        "API_KEY".dimmed(),
        "BASE URL".dimmed(),
        nw = num_width + 1, pw = PROVIDER_COL_WIDTH, li = label_inner,
        kw = TOKEN_DISPLAY_WIDTH);
    eprintln!("  {}", "\u{2500}".repeat(total_width.min(120)).dimmed());

    let mut prev_token = String::new();
    let mut i = 0;
    while i < entries.len() {
        let group_type = entries[i].key_type.clone();
        let group_end = entries[i..].iter()
            .position(|e| e.key_type != group_type)
            .map(|p| i + p)
            .unwrap_or(entries.len());

        // Group header (TYPE is the tree root) — indented past the marker column
        // so it aligns with the `#` header above.
        eprintln!("    {}", group_type.bold().cyan());

        let last_in_group = group_end - 1;
        for (idx, entry) in entries[i..group_end].iter().enumerate() {
            let real_idx = i + idx;
            let connector = if real_idx == last_in_group { "└─" } else { "├─" };

            // Collapse duplicate tokens on consecutive rows (same key, different providers).
            let token_display = if entry.api_key == prev_token {
                "\u{21b3} (same)".to_string()
            } else if full || entry.api_key.len() <= TOKEN_TRUNCATE_THRESHOLD {
                entry.api_key.clone()
            } else {
                format!("{}...{}", &entry.api_key[..15], &entry.api_key[entry.api_key.len()-4..])
            };
            prev_token = entry.api_key.clone();

            // Pad the plain string BEFORE applying .dimmed(); otherwise ANSI escape codes
            // inflate the byte count passed to {:<N} and break column alignment.
            let token_padded = format!("{:<kw$}", token_display, kw = TOKEN_DISPLAY_WIDTH);
            let active_marker = if entry.active {
                "\u{25cf}".green().to_string()
            } else {
                " ".to_string()
            };
            let label_display = truncate_to(&entry.label, label_inner);
            // 1-based row number, right-aligned with trailing dot.
            let num_col = format!("{:>nw$}.", real_idx + 1, nw = num_width);
            eprintln!("  {} {} {} {:<pw$} {:<li$} {} {}",
                active_marker, connector.dimmed(), num_col.dimmed(),
                entry.provider, label_display,
                token_padded.dimmed(), entry.base_url.dimmed(),
                pw = PROVIDER_COL_WIDTH, li = label_inner);
        }
        eprintln!();
        i = group_end;
    }

    // Count unique providers
    let mut providers: Vec<&str> = entries.iter().map(|e| e.provider.as_str()).collect();
    providers.sort();
    providers.dedup();
    eprintln!();
    // Legend + summary are dim: they're secondary context, the data above is
    // what the user actually came for.
    eprintln!("  {}",
        format!("{} = active (set by `aikey use`),  {} = same token as previous row",
            "\u{25cf}", "\u{21b3}").dimmed());
    eprintln!("  {}",
        format!("{} providers, {} routes available",
            providers.len(), entries.len()).dimmed());

    if missing_token_count > 0 {
        eprintln!();
        eprintln!("  {} {} keys missing route token. Run `aikey use` or `aikey add` to complete setup.",
            "\u{26a0}".yellow(), missing_token_count);
    }
    if db_error_count > 0 {
        eprintln!();
        eprintln!("  {} {} database error(s) while reading route tokens — check vault integrity.",
            "\u{26a0}".red(), db_error_count);
    }

    // Round 9 fix #1: was is_proxy_running (PID-only); now uses
    // proxy_is_running_managed so the warning fires correctly for
    // OrphanedPort / Unresponsive scenarios where the proxy is not ours.
    if !commands_proxy::proxy_is_running_managed() {
        eprintln!();
        eprintln!("  {} Proxy is not running. Start with: aikey proxy start", "\u{26a0}".yellow());
    }

    // Interactive picker: prompt only in a TTY session (not when output is
    // piped, redirected, or in automation). Enter with an empty input cancels;
    // a valid number prints the copy-paste config for that row.
    //
    // Why the 10s timeout + reader thread:
    //   A plain `stdin().read_line()` blocks forever, so `aikey route` left
    //   behind a process that never exited when the user walked away or
    //   ran the command inside a non-interactive wrapper that happened to
    //   pass the TTY check. The reader thread is detached — if the timer
    //   fires first, the thread stays blocked on `read_line` until the
    //   process exits (the OS reclaims it on `std::process::exit` /
    //   return-from-main). We accept the detach because (a) this is the
    //   very last action of `aikey route`, so we're seconds from exit
    //   anyway, and (b) bringing in `mio`/`tokio` just for a prompt timeout
    //   is disproportionate.
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        const PICKER_TIMEOUT: Duration = Duration::from_secs(10);

        eprintln!();
        eprint!("  {} {} ",
            "?".cyan().bold(),
            format!("Show config for route # (1-{}, Enter or 10s to cancel):", entries.len()).bold());
        let _ = std::io::stderr().flush();

        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            let mut buf = String::new();
            if std::io::stdin().read_line(&mut buf).is_ok() {
                let _ = tx.send(buf);
            }
        });

        match rx.recv_timeout(PICKER_TIMEOUT) {
            Ok(input) => {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    return Ok(());
                }
                match trimmed.parse::<usize>() {
                    Ok(n) if n >= 1 && n <= entries.len() => {
                        print_route_config(&[&entries[n - 1]]);
                    }
                    _ => {
                        eprintln!("  {} Invalid selection — expected a number between 1 and {}.",
                            "\u{26a0}".yellow(), entries.len());
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                eprintln!();
                eprintln!("  {} No selection within {}s — exiting.",
                    "\u{23f1}".dimmed(), PICKER_TIMEOUT.as_secs());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Reader thread errored before sending (EOF / closed stdin).
                // Treat as "no selection" and exit cleanly.
            }
        }
    } else {
        eprintln!();
        let example_label = entries.first().map(|e| e.label.as_str()).unwrap_or("my-key");
        eprintln!("  {} {} {}",
            "\u{27a4}".cyan(),
            "Copy-paste config:".bold(),
            format!("aikey route {}", example_label).cyan());
    }

    eprintln!();
    Ok(())
}

/// - Wraps password in Zeroizing<String> IMMEDIATELY upon input
/// P1-Q3: Handle aikey shell command
/// Starts an interactive subshell with non-sensitive context only.
/// Secrets are NOT exported as long-lived env vars; each command uses aikey run injection.
#[allow(dead_code)]
fn handle_shell_command(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    if json_mode {
        return Err("Shell mode is not supported in JSON mode".into());
    }

    // Get project config to determine context
    let config = config::ProjectConfig::discover()
        .ok()
        .flatten()
        .map(|(_, cfg)| cfg);

    let project_name = config.as_ref().map(|c| c.project.name.as_str()).unwrap_or("unknown");

    // Get current environment and profile
    let current_env = global_config::get_current_env().ok().flatten();
    let current_profile = global_config::get_current_profile().ok().flatten();

    println!("AiKey Shell - Advanced Mode");
    println!("===========================");
    println!("Project: {}", project_name);
    if let Some(env) = &current_env {
        println!("Environment: {}", env);
    }
    if let Some(profile) = &current_profile {
        println!("Profile: {}", profile);
    }
    println!();
    println!("⚠️  Security Notice:");
    println!("   Secrets are NOT exported to this shell.");
    println!("   Use 'aikey run -- <command>' to inject secrets per-command.");
    println!();
    println!("Type 'exit' to leave the AiKey shell.");
    println!();

    // Determine user's shell
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    // Build environment with non-sensitive context only
    let mut cmd = std::process::Command::new(&shell);

    // P1-Q3: Export only non-sensitive context
    if let Some(env) = current_env {
        cmd.env("AIKEY_ENV", env);
    }
    if let Some(profile) = current_profile {
        cmd.env("AIKEY_PROFILE", profile);
    }
    cmd.env("AIKEY_PROJECT", project_name);

    // Set a marker so users know they're in an aikey shell
    cmd.env("AIKEY_SHELL", "1");

    // Customize prompt to show we're in aikey shell
    let ps1 = std::env::var("PS1").unwrap_or_else(|_| "\\$ ".to_string());
    cmd.env("PS1", format!("(aikey) {}", ps1));

    // Start the subshell
    let status = cmd.status()?;

    // Cleanup message on exit
    println!();
    println!("Exited AiKey shell.");

    if !status.success() {
        if let Some(code) = status.code() {
            std::process::exit(code);
        }
    }

    Ok(())
}

/// Resolve a binding's key_source_ref to a human-readable display name.
fn resolve_binding_display_name(source_type: &str, source_ref: &str) -> String {
    if source_type == "team" {
        if let Ok(Some(entry)) = storage::get_virtual_key_cache(source_ref) {
            return entry.local_alias.unwrap_or(entry.alias);
        }
    }
    // OAuth accounts: show email identity instead of opaque provider_account_id
    if source_type == "personal_oauth_account" {
        if let Ok(Some(acct)) = storage::get_provider_account(source_ref) {
            if let Some(id) = acct.display_identity.as_deref().filter(|s: &&str| !s.is_empty()) {
                return id.to_string();
            }
            if let Some(id) = acct.external_id.as_deref().filter(|s: &&str| !s.is_empty()) {
                return id.to_string();
            }
        }
    }
    source_ref.to_string()
}

/// Truncate email username part if it exceeds `max_user_len`, keeping domain intact.
/// e.g. truncate_email("eFOreadeblakeE96j@muslim.com", 7) → "eFOread...@muslim.com"
/// Non-email strings are truncated at `max_user_len + 10` with trailing "...".
fn truncate_email(email: &str, max_user_len: usize) -> String {
    if let Some(at_pos) = email.find('@') {
        let user = &email[..at_pos];
        let domain = &email[at_pos..]; // includes '@'
        if user.len() > max_user_len {
            return format!("{}...{}", &user[..max_user_len], domain);
        }
    } else if email.len() > max_user_len + 10 {
        return format!("{}...", &email[..max_user_len + 10]);
    }
    email.to_string()
}

/// Prompt for the vault master password, adapting the message to whether the
/// vault already exists ("Enter") or is about to be created ("Set").
/// Returns the master password, using the 30-minute session cache when available.
/// Use for LOW-sensitivity commands (list, get, run, key sync, proxy start, ...).
/// After a successful vault operation the caller should call `session::refresh()`.
fn prompt_vault_password(password_stdin: bool, json_mode: bool) -> io::Result<SecretString> {
    // Skip cache when reading from stdin or in automated test mode.
    if !password_stdin && std::env::var("AK_TEST_PASSWORD").is_err() {
        if let Some(cached) = session::try_get() {
            // Slide the TTL forward on each successful cached use.
            session::refresh();
            return Ok(cached);
        }
    }
    let pw = prompt_vault_password_fresh(password_stdin, json_mode)?;
    // One-time prompt: ask user which session backend to use (keychain/file/disabled).
    session::maybe_configure_backend();
    // Store in cache after a fresh prompt (low-sensitivity path).
    session::store(&pw);
    Ok(pw)
}

/// Always prompts for the master password — never reads from cache.
/// Use for HIGH-sensitivity commands (add, delete, update, import, export,
/// secret set/upsert/delete, change-password, exec, run --direct).
fn prompt_vault_password_fresh(password_stdin: bool, json_mode: bool) -> io::Result<SecretString> {
    let vault_exists = storage::get_vault_path()
        .map(|p| p.exists())
        .unwrap_or(false);

    // Check if vault has a salt (= previously initialized with a password).
    // A vault file may exist but be empty (e.g., session backend created it before init).
    let vault_initialized = vault_exists && storage::get_salt().is_ok();

    if vault_initialized {
        // Existing vault — just ask for the password
        prompt_password_secure("\u{1F512} Enter Master Password: ", password_stdin, json_mode)
    } else {
        // No vault or empty vault (fresh install / --clear-install / no keys yet)
        // Why confirm: prevent typos from locking the user out permanently.
        if !json_mode && !password_stdin && std::env::var("AK_TEST_PASSWORD").is_err() {
            eprintln!();
            eprintln!("  \u{1F510} No vault found — setting up for the first time.");
            eprintln!("  Choose a master password to protect your API Keys.");
            eprintln!("  \u{26A0}\u{FE0F}  This password cannot be recovered if lost.");
            eprintln!();

            // Confirm password to prevent typo lockout
            loop {
                let pw1 = prompt_password_secure("\u{1F512} Set Master Password: ", false, false)?;
                let pw2 = prompt_password_secure("\u{1F512} Confirm Master Password: ", false, false)?;
                if pw1.expose_secret() == pw2.expose_secret() {
                    return Ok(pw1);
                }
                eprintln!("  Passwords do not match. Please try again.\n");
            }
        } else {
            // Non-interactive or test mode — single prompt, no confirm
            prompt_password_secure("\u{1F512} Set Master Password: ", password_stdin, json_mode)
        }
    }
}

fn prompt_password_secure(prompt: &str, password_stdin: bool, json_mode: bool) -> io::Result<SecretString> {
    // Check for test password environment variable
    if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        return Ok(SecretString::new(test_password));
    }

    // If password_stdin is true, read directly from stdin without prompt or TTY interaction
    if password_stdin {
        let mut password_raw = Zeroizing::new(String::new());
        io::stdin().read_line(&mut password_raw)?;
        let trimmed = password_raw.trim().to_string();
        return Ok(SecretString::new(trimmed));
    }

    // Interactive TTY path: show `*` per keystroke for visual feedback.
    let prompt_str = if json_mode { "" } else { prompt };
    let password = prompt_hidden(prompt_str).map_err(|e| {
        if e.kind() == io::ErrorKind::Other || e.raw_os_error() == Some(6) {
            io::Error::new(
                io::ErrorKind::Other,
                "aikey requires an interactive terminal to read the master password.\n\
                 Tip: run from a terminal, or set AK_TEST_PASSWORD for scripted use.",
            )
        } else {
            e
        }
    })?;

    // Wrap in Zeroizing for additional in-memory protection
    let password_raw = Zeroizing::new(password);
    let trimmed = password_raw.trim().to_string();
    Ok(SecretString::new(trimmed))
}

/// Show an interactive arrow-key picker with all activatable credentials.
/// Returns the alias / virtual_key_id / OAuth identity that the user selected,
/// which can be fed back into `resolve_activate_key` unchanged.
fn pick_key_interactively() -> Result<String, Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Gather personal keys
    let personal = storage::list_entries_with_metadata().unwrap_or_default();
    // Gather team keys
    let team = storage::list_virtual_key_cache().unwrap_or_default();
    // Gather OAuth accounts — activate supports these too.
    let oauth_accounts = storage::list_provider_accounts().unwrap_or_default();

    if personal.is_empty() && team.is_empty() && oauth_accounts.is_empty() {
        return Err("No credentials found. Add a personal key with `aikey add`, sync team keys with `aikey key sync`, or login with `aikey auth login <provider>`.".into());
    }

    // Active key for LOCAL column.
    //
    // `AIKEY_ACTIVE_LABEL` is the terminal-scoped active marker set by
    // `aikey activate` — that's what the picker cares about here, since the
    // picker itself drives activate. `active_cfg` (persistent primary set via
    // `aikey use`) is intentionally NOT used: in a shell where activate ran
    // kimi-local, the primary might still point at an OAuth account, which
    // would show a misleading ◀ marker on the wrong row.
    let active_label = std::env::var("AIKEY_ACTIVE_LABEL").unwrap_or_default();
    let active_cfg = storage::get_active_key_config().ok().flatten();

    // Provider bindings drive the persistent ● (in-use) marker — any key that
    // a binding routes through is "in use", matching `aikey list` / `aikey route`.
    let bindings = storage::list_provider_bindings(profile_activation::DEFAULT_PROFILE)
        .unwrap_or_default();

    // Build display rows; keep alias/id parallel for lookup after selection.
    // Layout per leaf row (inside the box):
    //   "> "(cursor,2) + "● "(in-use,2) + "├─ "(connector,3) + alias(alias_w) +
    //   "  "(2) + provider(provider_w) + " ◀ active"(9, optional)
    let mut items: Vec<String> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    // Track which rows are selectable (false for group headers & other-account keys).
    let mut selectable: Vec<bool> = Vec::new();

    // Dynamic column widths based on terminal size.
    // Fixed chrome around the data columns ≈ 32:
    //   outer(2) + │(1) + inner(2) + cursor(2) + ● (2) + connector(3) +
    //   gap(2) + marker(9) + inner(2) + │(1) + right-margin(6) = 32.
    let tw = ui_frame::term_width();
    let available = tw.saturating_sub(32);
    // Split available space: ~40% alias, ~60% provider, with minimums.
    let alias_w = (available * 2 / 5).max(10).min(30);
    let provider_w = available.saturating_sub(alias_w).max(10).min(40);

    // Filter team keys into usable / other-account as before.
    let visible_team: Vec<_> = team.iter()
        .filter(|e| {
            e.key_status == "active"
                && e.local_state != "stale"
                && e.local_state != "disabled_by_key_status"
                && e.local_state != "disabled_by_seat_status"
                && e.local_state != "disabled_by_account_status"
        })
        .collect();
    let (own_team, other_account_team): (Vec<_>, Vec<_>) = visible_team.into_iter()
        .partition(|e| e.local_state != "disabled_by_account_scope");
    let oauth_usable: Vec<_> = oauth_accounts.iter()
        .filter(|a| a.status == "active")
        .collect();

    // Helper: build a leaf row. `in_use` renders ●, `is_active` renders ◀ active.
    let fmt_leaf = |in_use: bool, connector: &str, alias_disp: &str, prov_disp: &str, is_active: bool| -> String {
        let use_mark = if in_use { "\u{25CF}".green().to_string() } else { " ".to_string() };
        let active_mk = if is_active { " \u{25C0} active" } else { "" };
        format!(
            "{} {} {:<aw$}  {:<pw$}{}",
            use_mark,
            connector.to_string().dimmed(),
            alias_disp, prov_disp, active_mk,
            aw = alias_w, pw = provider_w,
        )
    };

    // Personal group
    if !personal.is_empty() {
        items.push(format!("{}", "personal".bold().cyan()));
        aliases.push(String::new());
        selectable.push(false);

        let n = personal.len();
        for (i, entry) in personal.iter().enumerate() {
            let connector = if i + 1 == n { "\u{2514}\u{2500}" } else { "\u{251C}\u{2500}" };
            let provider_col = match (&entry.base_url, &entry.provider_code) {
                (Some(url), _) if !url.is_empty() => url.clone(),
                (_, Some(code)) if !code.is_empty() => code.clone(),
                _ => String::new(),
            };
            let in_use = bindings.iter().any(|b|
                b.key_source_type == credential_type::CredentialType::PersonalApiKey
                && b.key_source_ref == entry.alias);
            let is_active = !active_label.is_empty() && active_label == entry.alias;
            let alias_disp = if entry.alias.len() > alias_w { &entry.alias[..alias_w] } else { &entry.alias };
            let prov_disp = if provider_col.len() > provider_w { &provider_col[..provider_w] } else { &provider_col };
            items.push(fmt_leaf(in_use, connector, alias_disp, prov_disp, is_active));
            aliases.push(entry.alias.clone());
            selectable.push(true);
        }
    }

    // Team (own) group
    if !own_team.is_empty() {
        items.push(format!("{}", "team".bold().cyan()));
        aliases.push(String::new());
        selectable.push(false);

        let n = own_team.len();
        for (i, e) in own_team.iter().enumerate() {
            let connector = if i + 1 == n { "\u{2514}\u{2500}" } else { "\u{251C}\u{2500}" };
            let display_name = e.local_alias.as_deref().unwrap_or(e.alias.as_str());
            let in_use = bindings.iter().any(|b|
                b.key_source_type == credential_type::CredentialType::ManagedVirtualKey
                && b.key_source_ref == e.virtual_key_id);
            let is_active = !active_label.is_empty() && active_label == display_name;
            let alias_disp = if display_name.len() > alias_w { &display_name[..alias_w] } else { display_name };
            let prov_disp = if e.provider_code.len() > provider_w { &e.provider_code[..provider_w] } else { &e.provider_code };
            items.push(fmt_leaf(in_use, connector, alias_disp, prov_disp, is_active));
            aliases.push(e.virtual_key_id.clone());
            selectable.push(true);
        }
    }

    // OAuth group — `resolve_activate_key` accepts display_identity or
    // provider_account_id, so feed back whichever is more human-readable.
    if !oauth_usable.is_empty() {
        items.push(format!("{}", "oauth".bold().cyan()));
        aliases.push(String::new());
        selectable.push(false);

        let n = oauth_usable.len();
        for (i, acct) in oauth_usable.iter().enumerate() {
            let connector = if i + 1 == n { "\u{2514}\u{2500}" } else { "\u{251C}\u{2500}" };
            let identity = acct.display_identity.as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&acct.provider_account_id);
            let in_use = bindings.iter().any(|b|
                b.key_source_type == credential_type::CredentialType::PersonalOAuthAccount
                && b.key_source_ref == acct.provider_account_id);
            let is_active = !active_label.is_empty()
                && (active_label == identity || active_label == acct.provider_account_id);
            let id_disp = if identity.len() > alias_w { &identity[..alias_w] } else { identity };
            let prov_disp = if acct.provider.len() > provider_w { &acct.provider[..provider_w] } else { &acct.provider };
            items.push(fmt_leaf(in_use, connector, id_disp, prov_disp, is_active));
            aliases.push(identity.to_string());
            selectable.push(true);
        }
    }

    // Other-account team keys: shown at the bottom, dimmed, not selectable.
    if !other_account_team.is_empty() {
        let sep = format!("{}", "───── Other accounts (not selectable) ─────".dimmed());
        items.push(sep);
        aliases.push(String::new());
        selectable.push(false);

        for e in &other_account_team {
            let display_name = e.local_alias.as_deref().unwrap_or(e.alias.as_str());
            let alias_display = if display_name.len() > alias_w { &display_name[..alias_w] } else { display_name };
            let prov_display = if e.provider_code.len() > provider_w { &e.provider_code[..provider_w] } else { &e.provider_code };
            let raw = format!(
                "     {:<aw$}  {:<pw$}  [other account]",
                alias_display,
                prov_display,
                aw = alias_w,
                pw = provider_w,
            );
            items.push(format!("{}", raw.dimmed()));
            aliases.push(e.virtual_key_id.clone());
            selectable.push(false);
        }
    }

    // Header aligns under the alias column: 5 chars of leaf-row prefix
    // (●/space + space + connector + space) stand in for the label-less header.
    let header = format!("     {:<aw$}  {:<pw$}", "Alias", "Provider / Base URL", aw = alias_w, pw = provider_w);

    // Find initial cursor. Precedence:
    //   1. Terminal-active key (AIKEY_ACTIVE_LABEL env var) — the one the
    //      picker just marked ◀ active; jumping the cursor there lets the user
    //      confirm with Enter to re-activate or arrow-key to switch.
    //   2. Persistent primary (active_cfg, set by `aikey use`).
    //   3. First selectable row.
    let by_label = if active_label.is_empty() {
        None
    } else {
        // Row's `aliases[i]` holds the same value used as `label` when
        // activate ran: personal alias, team display name, or OAuth identity.
        (0..aliases.len()).find(|&i| selectable[i] && aliases[i] == active_label)
    };
    let by_cfg = active_cfg.as_ref().and_then(|cfg| {
        aliases.iter().position(|a| {
            (cfg.key_type == credential_type::CredentialType::ManagedVirtualKey && *a == cfg.key_ref)
                || (cfg.key_type == credential_type::CredentialType::PersonalApiKey && *a == cfg.key_ref)
                || (cfg.key_type == credential_type::CredentialType::PersonalOAuthAccount
                    && oauth_usable.iter().any(|o|
                        o.provider_account_id == cfg.key_ref
                        && (o.display_identity.as_deref() == Some(a.as_str())
                            || o.provider_account_id == *a)))
        })
    }).and_then(|i| if selectable[i] { Some(i) } else { None });
    let initial = by_label
        .or(by_cfg)
        .or_else(|| selectable.iter().position(|&s| s))
        .unwrap_or(0);

    match ui_select::box_select(
        "Select a key to activate",
        &header,
        &items,
        &selectable,
        initial,
    )? {
        ui_select::SelectResult::Selected(idx) => Ok(aliases[idx].clone()),
        ui_select::SelectResult::Cancelled => Err("Selection cancelled.".into()),
    }
}

/// Build provider groups and show the provider-tree interactive editor.
/// Returns a list of (provider_code, source_type, source_ref) changes to apply.
fn pick_providers_interactively() -> Result<Vec<(String, String, String)>, Box<dyn std::error::Error>> {
    let personal = storage::list_entries_with_metadata().unwrap_or_default();
    let team = storage::list_virtual_key_cache().unwrap_or_default();
    let oauth_accounts = storage::list_provider_accounts().unwrap_or_default();

    if personal.is_empty() && team.is_empty() && oauth_accounts.is_empty() {
        return Err("No keys found. Add a key with `aikey add`, sync team keys with `aikey key sync`, or login with `aikey auth login <provider>`.".into());
    }

    let bindings = storage::list_provider_bindings(
        profile_activation::DEFAULT_PROFILE
    ).unwrap_or_default();

    // Collect all known provider codes.
    let mut all_providers: Vec<String> = Vec::new();
    let mut add_prov = |code: &str| {
        let lc = code.to_lowercase();
        if !lc.is_empty() && !all_providers.contains(&lc) {
            all_providers.push(lc);
        }
    };
    for e in &personal {
        if let Some(ref sp) = e.supported_providers {
            for p in sp { add_prov(p); }
        } else if let Some(ref code) = e.provider_code {
            add_prov(code);
        }
    }
    let usable_team: Vec<_> = team.iter()
        .filter(|e| e.key_status == "active"
            && !e.local_state.starts_with("disabled_by_")
            && e.local_state != "stale"
            && e.provider_key_ciphertext.is_some())
        .collect();
    for e in &usable_team {
        if !e.supported_providers.is_empty() {
            for p in &e.supported_providers { add_prov(p); }
        } else {
            add_prov(&e.provider_code);
        }
    }
    for b in &bindings {
        // Map OAuth provider names in bindings to canonical codes
        // (older aikey auth use may have written "claude" instead of "anthropic").
        // Delegates to provider_canonical so a new alias added to provider_registry.yaml
        // (e.g. grok→xai) lights up here without touching this file — the prior inline
        // match was the kind of duplicated-canonicalization landmine flagged in
        // CLAUDE.md "禁止偷懒默认 → 重复代码".
        add_prov(&provider_canonical(&b.provider_code));
    }
    // Add OAuth account providers (mapped to canonical)
    for acct in &oauth_accounts {
        add_prov(&provider_canonical(&acct.provider));
    }
    all_providers.sort();

    if all_providers.is_empty() {
        return Err("No keys or accounts found.".into());
    }

    // Build ProviderGroup for each provider.
    let mut groups: Vec<ui_select::ProviderGroup> = Vec::new();

    for prov in &all_providers {
        let mut candidates: Vec<ui_select::KeyCandidate> = Vec::new();

        for e in &personal {
            let providers = if let Some(ref sp) = e.supported_providers {
                sp.clone()
            } else if let Some(ref code) = e.provider_code {
                vec![code.clone()]
            } else {
                vec![]
            };
            if providers.iter().any(|p| p.to_lowercase() == *prov) {
                candidates.push(ui_select::KeyCandidate {
                    label: e.alias.clone(),
                    source_type: "personal".to_string(),
                    source_ref: e.alias.clone(),
                    display_type: None,
                });
            }
        }

        for e in &usable_team {
            let providers = if !e.supported_providers.is_empty() {
                e.supported_providers.clone()
            } else {
                vec![e.provider_code.clone()]
            };
            if providers.iter().any(|p| p.to_lowercase() == *prov) {
                let label = e.local_alias.as_deref().unwrap_or(e.alias.as_str()).to_string();
                candidates.push(ui_select::KeyCandidate {
                    label,
                    source_type: "team".to_string(),
                    source_ref: e.virtual_key_id.clone(),
                    display_type: None,
                });
            }
        }

        // OAuth accounts — match by canonical provider (claude→anthropic, codex→openai).
        // Same family as the bindings loop above: delegate to provider_canonical
        // instead of duplicating the alias map inline.
        for acct in &oauth_accounts {
            if provider_canonical(&acct.provider) == *prov {
                let identity = acct.display_identity.as_deref()
                    .filter(|s| !s.is_empty())
                    .or_else(|| acct.external_id.as_deref().map(|s| if s.len() > 12 { &s[..12] } else { s }))
                    .unwrap_or(&acct.provider_account_id);
                // Truncate long email username for picker display
                // e.g. "eFOreadeblakeE96j@muslim.com" → "eFOread...@muslim.com"
                // Why: long emails overflow the interactive picker box width.
                let identity_truncated = truncate_email(identity, 10);
                let label = identity_truncated;
                // Tier suffix: p=pro, f=free, m=max, etc.
                let tier_tag = match acct.account_tier.as_deref() {
                    Some("pro") => "p",
                    Some("max") => "m",
                    Some("free") => "f",
                    Some(t) if !t.is_empty() && t != "-" => &t[..1],
                    _ => "",
                };
                let source_display = if tier_tag.is_empty() {
                    "oauth".to_string()
                } else {
                    format!("oauth({})", tier_tag)
                };
                candidates.push(ui_select::KeyCandidate {
                    label,
                    source_type: "personal_oauth_account".to_string(), // DB value
                    source_ref: acct.provider_account_id.clone(),
                    display_type: Some(source_display), // UI: "oauth" or "oauth(f)"
                });
            }
        }

        // Match binding by canonical provider code (claude→anthropic, codex→openai).
        // The `|| b.provider_code == *prov` tail keeps the legacy raw-equality path
        // for any future bindings row that's already canonical: provider_canonical
        // is idempotent, so the OR is belt-and-suspenders against an in-flight
        // migration where canonicalization status varies row-to-row.
        let current_binding = bindings.iter().find(|b|
            provider_canonical(&b.provider_code) == *prov || b.provider_code == *prov
        );
        let selected = current_binding.and_then(|b| {
            candidates.iter().position(|c|
                c.source_type == b.key_source_type.as_str() && c.source_ref == b.key_source_ref
            )
        });

        groups.push(ui_select::ProviderGroup {
            provider_code: prov.clone(),
            candidates,
            selected,
            expanded: true,
        });
    }

    // Snapshot original selections for diffing.
    let original_selections: Vec<Option<usize>> = groups.iter()
        .map(|g| g.selected)
        .collect();

    match ui_select::provider_tree_select(&mut groups)? {
        ui_select::ProviderTreeResult::Confirmed(updated_groups) => {
            let mut changes: Vec<(String, String, String)> = Vec::new();
            for (i, g) in updated_groups.iter().enumerate() {
                if g.selected != original_selections[i] {
                    if let Some(sel) = g.selected {
                        let c = &g.candidates[sel];
                        changes.push((
                            g.provider_code.clone(),
                            c.source_type.clone(),
                            c.source_ref.clone(),
                        ));
                    }
                }
            }
            Ok(changes)
        }
        ui_select::ProviderTreeResult::Cancelled => {
            eprintln!("  Selection cancelled.");
            Ok(vec![])
        }
    }
}

// ============================================================================
// activate / deactivate — shell-eval output for temporary key switching
// ============================================================================

/// Escape a string for safe use inside single quotes in sh/bash/zsh.
/// Internal single quotes become '\'' (end-quote, escaped-quote, re-open-quote).
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Escape a string for safe use inside single quotes in PowerShell.
/// Internal single quotes are doubled: ' → ''.
fn powershell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Escape a string for safe use in cmd.exe `set` statements.
/// Rejects labels containing characters that could break cmd parsing.
/// Why `+` allowed: email-tag syntax (alice+work@example.com) is common.
/// Why not more chars: cmd's `set VAR=VALUE` treats `& | ^ > < ( ) % !` specially.
fn cmd_escape(s: &str) -> Result<String, String> {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-' | '+')) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Label '{}' contains characters unsafe for cmd.exe. \
             Allowed: [a-zA-Z0-9._@+-]. Use PowerShell (--shell powershell) for broader label support.",
            s
        ))
    }
}

/// Sanitize a label for safe embedding in an interactive prompt string.
/// Rewrites any character that would trigger shell re-expansion (parameter,
/// command, history, escape sequences) to `_`.
///
/// Why sanitize, not escape: bash PS1 with `promptvars` (ON by default) and zsh
/// PROMPT with `PROMPT_SUBST` (common via oh-my-zsh) re-expand `$(...)`, ``...``,
/// `$var` during display. Even with backslash escaping, expansion semantics make
/// true literal display fragile across shell versions. Replacing with `_` yields
/// a predictable, injection-free cosmetic label.
fn sanitize_prompt_label(s: &str) -> String {
    s.chars().map(|c| match c {
        // Shell re-expansion vectors.
        '\\' | '$' | '`' | '!' | '\n' | '\r' | '\t' => '_',
        other => other,
    }).collect()
}

/// Escape label for safe embedding in zsh PROMPT: strip expansion metacharacters
/// first, then escape the zsh-specific `%` prompt-expansion marker.
fn zsh_prompt_escape(s: &str) -> String {
    sanitize_prompt_label(s).replace('%', "%%")
}

/// Escape label for safe embedding in bash PS1 with promptvars enabled.
fn bash_prompt_escape(s: &str) -> String {
    sanitize_prompt_label(s)
}

/// All known provider env var pairs — used by deactivate to unset everything.
const ALL_PROVIDER_ENV_PAIRS: &[(&str, &str)] = &[
    ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"),
    ("OPENAI_API_KEY", "OPENAI_BASE_URL"),
    ("GOOGLE_API_KEY", "GOOGLE_BASE_URL"),
    ("GEMINI_API_KEY", "GEMINI_BASE_URL"),
    ("KIMI_API_KEY", "KIMI_BASE_URL"),
    ("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL"),
    ("MOONSHOT_API_KEY", "MOONSHOT_BASE_URL"),
];

/// All known provider env var names (flattened from ALL_PROVIDER_ENV_PAIRS).
fn all_provider_vars() -> Vec<&'static str> {
    ALL_PROVIDER_ENV_PAIRS.iter().flat_map(|(k, v)| [*k, *v]).collect()
}

/// Probe all three sources (team, OAuth, personal) to check where `alias` exists.
/// Returns the source labels in priority order (team > oauth > personal).
/// Used by `aikey activate` to warn about ambiguity before resolving.
fn probe_alias_sources(alias: &str) -> Vec<&'static str> {
    let mut sources = Vec::new();

    let team_exists = storage::get_virtual_key_cache(alias).ok().flatten().is_some()
        || storage::get_virtual_key_cache_by_alias(alias).ok().flatten().is_some();
    if team_exists {
        sources.push("team");
    }

    let oauth_exists = storage::list_provider_accounts_readonly()
        .unwrap_or_default()
        .iter()
        .any(|a| {
            let id = a.display_identity.as_deref().unwrap_or(&a.provider_account_id);
            id.eq_ignore_ascii_case(alias) || a.provider_account_id.eq_ignore_ascii_case(alias)
        });
    if oauth_exists {
        sources.push("OAuth");
    }

    if storage::entry_exists(alias).unwrap_or(false) {
        sources.push("personal");
    }

    sources
}

/// Resolve key alias → (display_label, route_token, target_provider).
///
/// Resolution order: team keys → OAuth accounts → personal keys.
/// Mirrors `handle_route`'s data sources and `handle_key_use`'s resolution.
fn resolve_activate_key(
    alias: &str,
    provider_override: Option<&str>,
) -> Result<(String, String, String), Box<dyn std::error::Error>> {
    // ── 1. Try team managed keys ────────────────────────────────────────────
    let team_entry = storage::get_virtual_key_cache(alias)?
        .or_else(|| storage::get_virtual_key_cache_by_alias(alias).ok().flatten());

    if let Some(ref vk) = team_entry {
        if vk.key_status != "active" {
            return Err(format!(
                "Key '{}' has status '{}' and cannot be activated.",
                vk.alias, vk.key_status
            ).into());
        }
        // Why: must match the same filter used by `aikey route` (local_state == "active")
        // so users never activate a key that is invisible in the route table.
        if vk.local_state != "active" {
            return Err(format!(
                "Key '{}' is not available (state: {}). Run 'aikey key sync' to refresh.",
                vk.alias, vk.local_state
            ).into());
        }
        let display = vk.local_alias.as_deref().unwrap_or(&vk.alias).to_string();
        // Team key static bearer — shared helper (same as handle_route's
        // team branch). Empty vk_id is upstream bug; surface it as a user-
        // visible error so they can run `aikey key sync` to refresh.
        let token = team_token_normalize::team_token_from_vk_id(&vk.virtual_key_id)
            .map_err(|e| format!(
                "Team key '{}' has empty vk_id ({}). Run: aikey key sync",
                vk.alias, e
            ))?;
        let providers = if !vk.supported_providers.is_empty() {
            vk.supported_providers.clone()
        } else if !vk.provider_code.is_empty() {
            vec![vk.provider_code.clone()]
        } else {
            vec![]
        };
        let target = resolve_single_provider(&display, &providers, provider_override)?;
        return Ok((display, token, target));
    }

    // ── 2. Try OAuth accounts ───────────────────────────────────────────────
    for acct in storage::list_provider_accounts_readonly().unwrap_or_default() {
        if acct.status != "active" { continue; }
        let identity = acct.display_identity.as_deref()
            .unwrap_or(&acct.provider_account_id);
        if !identity.eq_ignore_ascii_case(alias)
            && !acct.provider_account_id.eq_ignore_ascii_case(alias) {
            continue;
        }
        let token = storage::get_provider_account_route_token_readonly(&acct.provider_account_id)?
            .ok_or_else(|| format!("No route token for '{}'. Run `aikey use` first to generate tokens.", identity))?;
        let providers = vec![acct.provider.clone()];
        let target = resolve_single_provider(identity, &providers, provider_override)?;
        return Ok((identity.to_string(), token, target));
    }

    // ── 3. Try personal keys ────────────────────────────────────────────────
    if storage::entry_exists(alias).unwrap_or(false) {
        let providers = storage::resolve_supported_providers(alias).unwrap_or_default();
        if providers.is_empty() {
            return Err(format!(
                "Key '{}' has no provider configured. Re-add with: aikey add {} --provider <code>",
                alias, alias
            ).into());
        }
        let token = storage::get_entry_route_token_readonly(alias)?
            .ok_or_else(|| format!("No route token for '{}'. Run `aikey use` first to generate tokens.", alias))?;
        let target = resolve_single_provider(alias, &providers, provider_override)?;
        return Ok((alias.to_string(), token, target));
    }

    Err(format!(
        "Key '{}' not found in team keys, OAuth accounts, or personal keys.\n\
         Run 'aikey list' to see available keys.",
        alias
    ).into())
}

/// Narrow to a single provider. Errors if multi-provider and no override given.
///
/// Returns the **canonical** provider code (e.g. `anthropic`, not `claude`).
/// Why: downstream the result becomes `AIKEY_ACTIVE_KEYS=<provider>=<label>`,
/// and the shell hook's preflight wrapper greps `^anthropic=` / `^openai=`
/// hard-coded. A non-canonical raw OAuth value (`claude` / `codex`) would
/// silently miss that lookup → preflight skipped with no output (bugfix
/// 2026-04-25-activate-provider-canonicalization).
fn resolve_single_provider(
    display: &str,
    providers: &[String],
    provider_override: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(ov) = provider_override {
        let code = provider_canonical(ov);
        if !providers.iter().any(|p| provider_canonical(p) == code) {
            return Err(format!(
                "Key '{}' does not support provider '{}'. Supported: {}.\n  Try: aikey activate {} --provider {}",
                display, code, providers.join(", "), display, provider_canonical(&providers[0])
            ).into());
        }
        return Ok(code);
    }
    if providers.len() == 1 {
        return Ok(provider_canonical(&providers[0]));
    }
    Err(format!(
        "Key '{}' supports multiple providers: {}. Specify --provider <name>:\n  aikey activate {} --provider {}",
        display, providers.join(", "), display, provider_canonical(&providers[0])
    ).into())
}

/// Auto-detect the current shell from the SHELL environment variable.
/// Returns "zsh", "bash", "powershell", "cmd", or None if unrecognized.
fn detect_shell() -> Option<&'static str> {
    let shell_env = std::env::var("SHELL").unwrap_or_default();
    if shell_env.contains("zsh") { return Some("zsh"); }
    if shell_env.contains("bash") { return Some("bash"); }
    // Windows: PSModulePath is set in PowerShell sessions.
    if std::env::var("PSModulePath").is_ok() { return Some("powershell"); }
    // Windows cmd: PROMPT env var is typically set.
    if std::env::var("PROMPT").is_ok() && cfg!(windows) { return Some("cmd"); }
    None
}

/// Probe whether the user is running a shell we recognise but don't yet support,
/// so the error message can point them at a concrete workaround instead of a
/// generic "could not detect" hint.
fn detect_unsupported_shell() -> Option<&'static str> {
    let shell_env = std::env::var("SHELL").unwrap_or_default();
    if shell_env.contains("fish") { return Some("fish"); }
    // Nushell sets $SHELL to the nu binary; also check $NU_VERSION for robustness.
    if shell_env.contains("/nu") || std::env::var("NU_VERSION").is_ok() {
        return Some("nushell");
    }
    None
}

/// Build the error message shown when `--shell` was not provided and auto-detect
/// couldn't identify the shell. For known-but-unsupported shells (fish, nushell),
/// point the user at the manual workaround via `aikey route`.
fn shell_detection_error() -> String {
    if let Some(unsupp) = detect_unsupported_shell() {
        format!(
            "{} shell is not yet supported by `aikey activate`.\n  \
             Workaround: run `aikey route <alias>` to get the API Key + base URL\n  \
             and export them manually with your shell's native syntax.",
            unsupp
        )
    } else {
        "Could not detect shell type. Pass --shell explicitly, e.g.:\n  \
         eval $(aikey activate <alias> --shell zsh)"
            .into()
    }
}

/// `aikey activate <alias> [--shell <shell>]` — output eval-safe export statements.
///
/// Stdout: only eval-safe shell statements (captured by wrapper function).
/// Stderr: all human-readable messages (flows through to terminal).
/// When `--shell` is omitted, auto-detects from the SHELL env var.
fn handle_activate(
    alias: Option<&str>,
    provider_override: Option<&str>,
    shell: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Resolve alias: either explicit arg, or interactive pick when omitted.
    let picked: String;
    let alias: &str = match alias {
        Some(a) => a,
        None => {
            use std::io::IsTerminal;
            if !std::io::stderr().is_terminal() {
                return Err(
                    "alias required in non-interactive mode (usage: aikey activate <ALIAS>)".into()
                );
            }
            picked = pick_key_interactively()?;
            picked.as_str()
        }
    };

    let detected;
    let shell = match shell {
        Some(s) => s,
        None => {
            detected = detect_shell().ok_or_else(shell_detection_error)?;
            detected
        }
    };

    // Direct-invocation guard (2026-04-27): refuse to dump shell code +
    // "Activated" message when stdout is a TTY (i.e., the user typed
    // `aikey activate <alias>` instead of `eval $(aikey activate ...)`).
    //
    // Why this matters: previously the binary printed the eval-able
    // shell snippet on stdout AND a dim-grey "Activated" line on stderr,
    // even when nothing was consuming stdout. Users saw "Activated" and
    // assumed env vars were set in their shell — but they weren't. The
    // very next `claude` / `codex` then failed with "Not logged in" /
    // "Missing OPENAI_API_KEY" with no obvious explanation. Real session
    // captured 2026-04-25 showed the user re-running `aikey activate`
    // twice in disbelief before giving up.
    //
    // New behavior on direct invocation:
    //   - Show a prominent yellow warning + the exact eval command.
    //   - Skip the shell-code dump (would never reach a wrapper anyway).
    //   - Skip the "Activated" message (since nothing was activated).
    //   - Return Ok(()) — exit non-zero would feel punitive; the user's
    //     intent was clear and we've explained what to do.
    //
    // Pipe / eval / redirect path (stdout NOT a TTY) keeps the original
    // behavior verbatim — shell code on stdout, hint + "Activated" on
    // stderr. That's the supported invocation pattern.
    if io::stdout().is_terminal() {
        eprintln!();
        eprintln!("\x1b[1;33m  \u{26a0} Activation needs `eval` to apply env vars to your current shell.\x1b[0m");
        eprintln!();
        eprintln!("  Run:");
        eprintln!("    \x1b[1;36meval $(aikey activate {} --shell {})\x1b[0m", alias, shell);
        eprintln!();
        eprintln!("\x1b[90m  (A direct call only prints the eval-able shell snippet — it does NOT activate.)\x1b[0m");
        return Ok(());
    }

    // From here on we know stdout is being captured (eval / pipe / redirect),
    // so the original hint pattern is safe — stderr stays visible to the user
    // while stdout contains only the eval target.
    eprintln!("\x1b[90m  Detected shell: {}. Wrap with eval to apply:\x1b[0m", shell);
    eprintln!("\x1b[90m  eval $(aikey activate {} --shell {})\x1b[0m", alias, shell);

    // M2: warn if alias collides across sources. Priority (team > OAuth > personal)
    // is preserved by resolve_activate_key, but silent selection can confuse users.
    let sources = probe_alias_sources(alias);
    if sources.len() > 1 {
        eprintln!("\x1b[33m  \u{26a0} Alias '{}' exists in multiple sources: {}. Using {} (priority: team > OAuth > personal).\x1b[0m",
            alias, sources.join(", "), sources[0]);
        eprintln!("\x1b[90m    Rename one with `aikey rename` to remove the ambiguity.\x1b[0m");
    }

    let (label, token, provider) = resolve_activate_key(alias, provider_override)?;

    let proxy_port = commands_proxy::proxy_port();
    let (api_key_var, base_url_var) = commands_account::provider_env_vars_pub(&provider)
        .ok_or_else(|| format!("Unknown provider '{}' — no env var mapping.", provider))?;
    let base_url = format!(
        "http://127.0.0.1:{}/{}",
        proxy_port,
        commands_account::provider_proxy_prefix_pub(&provider)
    );

    let provider_vars = all_provider_vars();

    match shell {
        "zsh" | "bash" => {
            let (prompt_var, orig_prompt_var, prompt_label) = if shell == "zsh" {
                ("PROMPT", "_AIKEY_ORIG_PROMPT", zsh_prompt_escape(&label))
            } else {
                ("PS1", "_AIKEY_ORIG_PS1", bash_prompt_escape(&label))
            };

            // M5: save user's current provider env values (if any) BEFORE unset,
            // so deactivate can restore them. Guarded by -z check so nested
            // activates don't overwrite the original save.
            for var in &provider_vars {
                println!(
                    "if [ -n \"${v}\" ] && [ -z \"$_AIKEY_ORIG_{v}\" ]; then _AIKEY_ORIG_{v}=\"${v}\"; fi",
                    v = var
                );
            }

            println!("unset {}", provider_vars.join(" "));
            // Stage 4 (active-state cross-shell sync): _AIKEY_EXPLICIT_ALIAS
            // is the canonical "this shell is pinned by an explicit
            // `aikey activate`" marker — precmd uses it to skip auto-sync
            // from active.env. AIKEY_ACTIVE_LABEL is kept during a 1-2
            // version grace window so older hooks (which still gate on
            // LABEL) keep working unchanged. After grace, drop the LABEL.
            println!("export _AIKEY_EXPLICIT_ALIAS={}", shell_escape(&label));
            println!("export AIKEY_ACTIVE_LABEL={}", shell_escape(&label));
            println!("export _AIKEY_PROMPT_LABEL={}", shell_escape(&prompt_label));
            // Why: preexec hook (preexec.zsh/preexec.bash) reads AIKEY_ACTIVE_KEYS
            // to print "[aikey] claude → <label>". Without this override, it keeps
            // showing the label set by `aikey use` (persisted in active.env), which
            // is stale once activate has replaced the provider env vars in this shell.
            // Single-provider pair is correct: activate also unsets all other providers'
            // env vars above, so no other labels should be displayed in this terminal.
            // Deactivate/quit/exit restore via precmd re-sourcing active.env (automatic).
            println!(
                "export AIKEY_ACTIVE_KEYS={}",
                shell_escape(&format!("{}={}", provider, label))
            );
            println!("export {}={}", api_key_var, shell_escape(&token));
            println!("export {}={}", base_url_var, shell_escape(&base_url));
            println!(
                "if [ -z \"${op}\" ]; then {op}=\"${pv}\"; fi",
                op = orig_prompt_var, pv = prompt_var
            );
            // Activate replaces the prompt with a minimal template that omits
            // user@host — keeps the focus on the active key + working directory.
            // The original prompt is saved above, so `aikey deactivate` restores
            // full customization. Advanced users who want their starship /
            // powerlevel10k prompt preserved can set AIKEY_PROMPT_MODE=prepend.
            //
            // Label is rendered in cyan to match the CLI's accent color. For
            // bash, `\[...\]` marks non-printing escape bytes so readline
            // line-length math stays correct.
            // The working-dir portion shows only the basename (zsh `%1~`,
            // bash `\W`); `\\$ ` in bash renders `$` for users / `#` for root.
            let (label_block, minimal_rest) = if shell == "zsh" {
                ("%F{cyan}($_AIKEY_PROMPT_LABEL)%f", "%1~ %# ")
            } else {
                (
                    "\\[\\e[36m\\]($_AIKEY_PROMPT_LABEL)\\[\\e[0m\\]",
                    "\\W\\\\$ ",
                )
            };
            println!(
                "if [ \"$AIKEY_PROMPT_MODE\" = prepend ]; then {pv}=\"{lbl} ${op}\"; else {pv}=\"{lbl} {rest}\"; fi",
                pv = prompt_var, lbl = label_block, op = orig_prompt_var, rest = minimal_rest
            );

            // Define `quit` as a shell-local command that undoes activate
            // without closing the terminal. Earlier versions hooked EXIT so
            // `exit` would deactivate, but `exit` also kills the terminal —
            // `quit` lets users drop back to their original prompt in-place.
            //
            // `command aikey` bypasses the installed `aikey()` shell wrapper —
            // if we called `aikey deactivate` directly, the wrapper would
            // append `--shell zsh` a second time and clap rejects the
            // duplicate flag, silently breaking `quit`. The function
            // self-unsets so a later activate installs a fresh definition.
            println!(
                "quit() {{ eval \"$(command aikey deactivate --shell {sh} 2>/dev/null)\" 2>/dev/null; unset -f quit 2>/dev/null; }}",
                sh = shell
            );
        }
        "powershell" => {
            // M5: save user's current provider env vars (if any) before overwrite.
            for var in &provider_vars {
                println!(
                    "if ($env:{v} -and -not $env:_AIKEY_ORIG_{v}) {{ $env:_AIKEY_ORIG_{v} = $env:{v} }}",
                    v = var
                );
            }
            for var in &provider_vars {
                println!("Remove-Item Env:\\{} -ErrorAction SilentlyContinue", var);
            }
            // Stage 4: see zsh/bash branch comment.
            println!("$env:_AIKEY_EXPLICIT_ALIAS = {}", powershell_escape(&label));
            println!("$env:AIKEY_ACTIVE_LABEL = {}", powershell_escape(&label));
            println!("$env:_AIKEY_PROMPT_LABEL = {}", powershell_escape(&label));
            println!(
                "$env:AIKEY_ACTIVE_KEYS = {}",
                powershell_escape(&format!("{}={}", provider, label))
            );
            println!("$env:{} = {}", api_key_var, powershell_escape(&token));
            println!("$env:{} = {}", base_url_var, powershell_escape(&base_url));
            // M4: store the original prompt as a ScriptBlock in a global variable,
            // not a stringified env var. Avoids Invoke-Expression (arbitrary code
            // execution from env var) and preserves closure scope for module-defined
            // prompt helpers (oh-my-posh, starship).
            println!("if (-not (Get-Variable -Scope Global -Name _aikeyOrigPrompt -ErrorAction SilentlyContinue)) {{ Set-Variable -Scope Global -Name _aikeyOrigPrompt -Value (Get-Item function:prompt).ScriptBlock }}");
            println!("function global:prompt {{ \"($env:_AIKEY_PROMPT_LABEL) \" + (& $global:_aikeyOrigPrompt) }}");
            // `quit` deactivates in-place without closing the PowerShell host.
            // Resolve the binary via `Get-Command -CommandType Application` so
            // any user-defined `aikey` function wrapper is bypassed (same
            // rationale as the POSIX `command` prefix above).
            println!("function global:quit {{ $_akbin = (Get-Command aikey -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source; if ($_akbin) {{ Invoke-Expression (& $_akbin deactivate --shell powershell 2>$null) }}; Remove-Item function:\\quit -ErrorAction SilentlyContinue }}");
        }
        "cmd" => {
            let safe_label = cmd_escape(&label)?;
            // M5: save user's current provider env vars (if any) before overwrite.
            for var in &provider_vars {
                println!(
                    "if defined {v} if not defined _AIKEY_ORIG_{v} set \"_AIKEY_ORIG_{v}=%{v}%\"",
                    v = var
                );
            }
            for var in &provider_vars {
                println!("set {}=", var);
            }
            // Stage 4: see zsh/bash branch comment.
            println!("set _AIKEY_EXPLICIT_ALIAS={}", safe_label);
            println!("set AIKEY_ACTIVE_LABEL={}", safe_label);
            println!("set _AIKEY_PROMPT_LABEL={}", safe_label);
            // provider is a lowercase ASCII identifier; safe_label is cmd-escaped.
            println!("set AIKEY_ACTIVE_KEYS={}={}", provider, safe_label);
            println!("set {}={}", api_key_var, token);
            println!("set {}={}", base_url_var, base_url);
            println!("prompt (%_AIKEY_PROMPT_LABEL%) $P$G");
        }
        other => {
            return Err(format!(
                "Unsupported shell '{}'. Supported: zsh, bash, powershell, cmd.",
                other
            ).into());
        }
    }

    // Human-readable confirmation on stderr (not captured by wrapper).
    eprintln!("\x1b[90m  Activated: {} \u{2192} {} ({})\x1b[0m", label, provider, shell);

    // Show how to undo. The `quit` shell-local function is defined above for
    // zsh / bash / powershell (it eval's `aikey deactivate` in-place); cmd
    // has no equivalent so we skip the hint there.
    //
    // Why hint at all: users hit `Ctrl-D` or close the terminal to exit,
    // unaware there's a softer "stay in shell, drop the active key" path.
    // Surfacing it once at activate time costs one dim line.
    if shell != "cmd" {
        eprintln!("\x1b[90m  Run \x1b[36m`quit`\x1b[0m\x1b[90m to deactivate this shell.\x1b[0m");
    }

    // Auto-install Claude Code status line when activating an anthropic key.
    // Idempotent — if the user already has the statusLine wired up (or
    // intentionally opted out with a different entry) this is a no-op.
    // See 费用小票-实施方案.md §5.6.
    if provider.eq_ignore_ascii_case("anthropic") {
        commands_statusline::ensure_claude_statusline_installed();
    }
    Ok(())
}

/// `aikey deactivate [--shell <shell>]` — output eval-safe unset statements.
/// When `--shell` is omitted, auto-detects from the SHELL env var.
fn handle_deactivate(
    shell: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let detected;
    let shell = match shell {
        Some(s) => s,
        None => {
            detected = detect_shell().ok_or_else(shell_detection_error)?;
            eprintln!("\x1b[90m  Detected shell: {}. Wrap with eval to apply:\x1b[0m", detected);
            eprintln!("\x1b[90m  eval $(aikey deactivate --shell {})\x1b[0m", detected);
            detected
        }
    };

    let provider_vars = all_provider_vars();

    match shell {
        "zsh" | "bash" => {
            let (prompt_var, orig_prompt_var) = if shell == "zsh" {
                ("PROMPT", "_AIKEY_ORIG_PROMPT")
            } else {
                ("PS1", "_AIKEY_ORIG_PS1")
            };
            // Stage 4: clear both new and grace-period legacy pin vars.
            println!("unset _AIKEY_EXPLICIT_ALIAS AIKEY_ACTIVE_LABEL _AIKEY_PROMPT_LABEL");
            println!("unset {}", provider_vars.join(" "));
            println!(
                "if [ -n \"${op}\" ]; then {pv}=\"${op}\"; unset {op}; fi",
                pv = prompt_var, op = orig_prompt_var
            );
            // Global defaults from active.env first, then user's pre-activate values
            // override (M5). User's manual values thus win over any aikey-managed
            // global settings, matching the state they saw before activate.
            println!("[ -f ~/.aikey/active.env ] && source ~/.aikey/active.env");
            for var in &provider_vars {
                println!(
                    "if [ -n \"$_AIKEY_ORIG_{v}\" ]; then export {v}=\"$_AIKEY_ORIG_{v}\"; unset _AIKEY_ORIG_{v}; fi",
                    v = var
                );
            }
        }
        "powershell" => {
            // Stage 4: include _AIKEY_EXPLICIT_ALIAS alongside the legacy LABEL.
            let all_vars: Vec<&str> = provider_vars.iter().copied()
                .chain(["_AIKEY_EXPLICIT_ALIAS", "AIKEY_ACTIVE_LABEL", "_AIKEY_PROMPT_LABEL"].iter().copied())
                .collect();
            for var in &all_vars {
                println!("Remove-Item Env:\\{} -ErrorAction SilentlyContinue", var);
            }
            // M4: restore original prompt ScriptBlock (not re-eval a string env var).
            println!("if (Get-Variable -Scope Global -Name _aikeyOrigPrompt -ErrorAction SilentlyContinue) {{ Set-Item function:global:prompt $global:_aikeyOrigPrompt; Remove-Variable -Scope Global -Name _aikeyOrigPrompt }}");
            // Restore global settings from active.env.flat (plain KEY=VALUE, no sh syntax).
            // Why .flat instead of .env: active.env contains sh-expansion like ${NO_PROXY:-}
            // which PowerShell would import as literal text, breaking proxy bypass config.
            // active.env.flat is generated alongside active.env with pure literal values.
            println!("$_af = if ($env:HOME) {{ Join-Path $env:HOME '.aikey' 'active.env.flat' }} else {{ Join-Path $env:USERPROFILE '.aikey' 'active.env.flat' }}");
            println!("if (Test-Path $_af) {{ Get-Content $_af | ForEach-Object {{ if ($_ -match '^(\\w+)=(.*)$') {{ [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process') }} }} }}");
            // M5: user's pre-activate values override the global fallback.
            for var in &provider_vars {
                println!(
                    "if ($env:_AIKEY_ORIG_{v}) {{ $env:{v} = $env:_AIKEY_ORIG_{v}; Remove-Item Env:\\_AIKEY_ORIG_{v} -ErrorAction SilentlyContinue }}",
                    v = var
                );
            }
        }
        "cmd" => {
            // Stage 4: include _AIKEY_EXPLICIT_ALIAS alongside the legacy LABEL.
            let all_vars: Vec<&str> = provider_vars.iter().copied()
                .chain(["_AIKEY_EXPLICIT_ALIAS", "AIKEY_ACTIVE_LABEL", "_AIKEY_PROMPT_LABEL"].iter().copied())
                .collect();
            for var in &all_vars {
                println!("set {}=", var);
            }
            println!("prompt $P$G");
            // Restore global settings from active.env.flat (plain KEY=VALUE).
            // Why .flat: active.env has sh-expansion syntax that cmd can't parse correctly.
            // Why usebackq: without it, `in ("path")` treats the path as a literal string
            // instead of a filename, so for /f would parse the path text, not file contents.
            // Why %HOME% fallback: resolve_aikey_dir() uses HOME→USERPROFILE→"." priority;
            // cmd must match by checking %HOME% first, then falling back to %USERPROFILE%.
            println!("set \"_AF=\"");
            println!("if defined HOME (set \"_AF=%HOME%\\.aikey\\active.env.flat\")");
            println!("if not defined _AF if defined USERPROFILE (set \"_AF=%USERPROFILE%\\.aikey\\active.env.flat\")");
            println!("if defined _AF if exist \"%_AF%\" (for /f \"usebackq tokens=1,* delims==\" %%A in (\"%_AF%\") do set \"%%A=%%B\")");
            println!("set \"_AF=\"");
            // M5: user's pre-activate values override the global fallback.
            for var in &provider_vars {
                println!(
                    "if defined _AIKEY_ORIG_{v} (set \"{v}=%_AIKEY_ORIG_{v}%\" & set \"_AIKEY_ORIG_{v}=\")",
                    v = var
                );
            }
        }
        other => {
            return Err(format!(
                "Unsupported shell '{}'. Supported: zsh, bash, powershell, cmd.",
                other
            ).into());
        }
    }

    eprintln!("\x1b[90m  Deactivated: restored global settings ({})\x1b[0m", shell);
    Ok(())
}

/// Convert a `refresh_hook_file_only` error into a user-actionable
/// message. The original messages from the lower layer can be opaque
/// OS errors ("拒绝访问。 (os error 5)") that don't tell the user what
/// to do next. This wrapper detects the common Windows-specific
/// failure modes — sharing-violation from another shell holding the
/// hook file open — and appends a remediation step.
///
/// Why this lives in main.rs rather than `refresh_hook_file_only`:
/// the lower layer returns a `String` error so the Web envelope path
/// (`web_install_hook_file_layer1`) can classify it via prefix match.
/// Mutating that prefix would force every classifier to be updated in
/// lockstep. Instead we keep the raw error stable and rewrite it for
/// human consumption only at the CLI boundary.
fn augment_hook_update_error(raw: &str) -> String {
    // The string format we produce upstream is:
    //   "failed to write hook file: <io::Error::Display>"
    // On Windows EACCES this expands to either:
    //   "... 拒绝访问。 (os error 5)"   (Chinese-locale Windows)
    //   "... Access is denied. (os error 5)"
    //   "... (os error 32)"             (sharing violation)
    let is_eacces = raw.contains("os error 5") || raw.contains("os error 32");
    if !is_eacces {
        return raw.to_string();
    }
    let mut out = String::new();
    out.push_str(raw);
    out.push_str("\n\nThis usually means another PowerShell window has loaded an outdated\n");
    out.push_str("hook.ps1 that holds the file open via a leaked file handle (pre-2026-04-29\n");
    out.push_str("hooks used a streaming reader whose handle survived `break`).\n\n");
    out.push_str("To fix:\n");
    out.push_str("  1. Close ALL other PowerShell / pwsh windows that have aikey loaded.\n");
    out.push_str("  2. Open a fresh PowerShell.\n");
    out.push_str("  3. Run: aikey hook update      (without sudo — elevation does not help)\n\n");
    out.push_str("Why elevation does NOT help: the failure is a sharing-violation between\n");
    out.push_str("two user-mode processes; both are owned by you and both have full ACL.\n");
    out.push_str("Closing the holding shell releases the handle; running elevated does not.");
    out
}

/// `aikey hook` subcommand family — explicit user entry points to the
/// hash-based drift detector and rc-wiring lifecycle.
///
/// Three operations, deliberately distinct (Stage 8 + hook coverage v1):
///
///   `update`  — Layer 1 only: regenerate ~/.aikey/hook.{zsh,bash} from
///               the binary's embedded template. Routes through
///               `refresh_hook_file_only`. Never touches rc.
///   `status`  — Read-only: reports three hashes (file / binary /
///               loaded) and a derived state string. Output is stdout
///               and grep-friendly so `aikey hook status | grep state:`
///               works as a CI signal.
///   `install` — Layer 1 + Layer 2: render hook file AND wire rc.
///               Routes through `ensure_shell_hook(false)` which prompts
///               before mutating ~/.zshrc / ~/.bashrc. Refuses non-TTY
///               (H1.5 + v1/v2 migration guard).
///
/// Why `update` is NOT a wrapper around `ensure_shell_hook`: that helper
/// also wires rc, which is precisely the side effect users running
/// `update` are trying to avoid. The split was made deliberately during
/// the Stage 8 reviewer round 3 — see plan §3.2.
fn handle_hook_command(action: &HookAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        HookAction::Update => {
            // Honor the standard skip env var so CI / installer scripts can
            // disable hook writes globally without a per-command flag.
            if std::env::var("AIKEY_NO_HOOK").map(|v| v == "1").unwrap_or(false) {
                eprintln!("\x1b[90m  Skipped: AIKEY_NO_HOOK=1 set in environment.\x1b[0m");
                return Ok(());
            }
            // Pre-flight: warn if running elevated on Windows. The native
            // `sudo` shim defaults to forceNewWindow mode which spawns the
            // elevated process in a separate console that closes on exit —
            // any error we print is invisible. Worse: elevation does NOT
            // help here. The canonical failure mode of `aikey hook update`
            // is another non-elevated PowerShell session holding hook.ps1
            // open via a leaked StreamReader handle (pre-2026-04-29 hooks);
            // sharing-violation is orthogonal to elevation, so the elevated
            // process hits the same EACCES. The right fix is to close the
            // other shells, not to elevate.
            // See bugfix 2026-04-29-aikey-hook-update-eacces-and-sudo-silent-failure.md.
            if profile_activation::is_running_elevated() {
                eprintln!("\x1b[33m  ⚠ Running elevated on Windows.\x1b[0m");
                eprintln!("\x1b[90m    Elevation does not help `aikey hook update` succeed —\x1b[0m");
                eprintln!("\x1b[90m    EACCES on hook.ps1 is typically caused by another\x1b[0m");
                eprintln!("\x1b[90m    PowerShell session holding the file open, not by ACL.\x1b[0m");
                eprintln!("\x1b[90m    If this command fails: close other PS shells, then run\x1b[0m");
                eprintln!("\x1b[90m    `aikey hook update` again WITHOUT sudo.\x1b[0m");
            }
            // Stage 8 / reviewer round-3 fix: use the *pure* refresh path that
            // only rewrites ~/.aikey/hook.{zsh,bash}. The earlier draft called
            // `ensure_shell_hook(false)` which, on first install, prompts the
            // user AND appends a `source` line to their rc — surprising for a
            // low-risk recovery command. `refresh_hook_file_only` writes the
            // hook file and returns; rc wiring is the job of `aikey hook
            // install` (Layer 2 only, no binding change) or `aikey use
            // <alias>` (when the user is also picking a key).
            match commands_account::refresh_hook_file_only(None) {
                Ok(path) => {
                    eprintln!("\x1b[90m  ✓ Regenerated {} from current binary.\x1b[0m", path.display());
                    let basename = path.file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("hook.zsh");
                    eprintln!("\x1b[90m    Open shells will pick it up via the drift detector on next prompt,\x1b[0m");
                    eprintln!("\x1b[90m    or run: source ~/.aikey/{}\x1b[0m", basename);
                    // Helpful follow-up: if rc isn't yet wired (typical of
                    // recovery scenarios where the user blew away their
                    // dotfiles), tell them how to install it without us
                    // silently mutating files behind their back.
                    let home = std::env::var("HOME").unwrap_or_default();
                    let rc_has_source = ["/.zshrc", "/.bashrc", "/.bash_profile"].iter().any(|rc| {
                        let rc_path = format!("{}{}", home, rc);
                        std::fs::read_to_string(&rc_path)
                            .map(|c| c.contains("# BEGIN aikey") || c.contains(&format!("source ~/.aikey/{}", basename)))
                            .unwrap_or(false)
                    });
                    if !rc_has_source {
                        eprintln!("\x1b[90m    Note: no rc-file `source` line detected. To install it, run\x1b[0m");
                        eprintln!("\x1b[90m      \x1b[36maikey hook install\x1b[0m\x1b[90m            (rc only, no binding change), or\x1b[0m");
                        eprintln!("\x1b[90m      \x1b[36maikey use <alias>\x1b[0m\x1b[90m             (also activates that key).\x1b[0m");
                        eprintln!("\x1b[90m    Both prompt for confirmation before touching your rc file.\x1b[0m");
                    }
                    Ok(())
                }
                Err(e) => Err(augment_hook_update_error(&e).into()),
            }
        }
        HookAction::Status { shell } => {
            let detected;
            let shell_str: &str = match shell.as_deref() {
                Some(s) => s,
                None => {
                    detected = detect_shell().ok_or_else(shell_detection_error)?;
                    detected
                }
            };
            let kind = match shell_str {
                "zsh" => commands_account::HookKind::Zsh,
                "bash" => commands_account::HookKind::Bash,
                "powershell" | "pwsh" => commands_account::HookKind::PowerShell,
                other => return Err(format!(
                    "unsupported shell '{}' for hook status — expected zsh, bash, or powershell", other
                ).into()),
            };
            let hook_filename = match kind {
                commands_account::HookKind::Zsh => "hook.zsh",
                commands_account::HookKind::Bash => "hook.bash",
                commands_account::HookKind::PowerShell => "hook.ps1",
            };

            let aikey_dir = commands_account::resolve_aikey_dir();
            let hook_path = aikey_dir.join(hook_filename);

            let file_hash = std::fs::read_to_string(&hook_path)
                .ok()
                .and_then(|c| {
                    c.lines()
                        .take(8)
                        .find_map(|line| {
                            line.strip_prefix("# Hook-Template-Hash: ")
                                .map(|s| s.trim().to_string())
                        })
                });
            let binary_hash = commands_account::hook_template_hash(kind);
            let loaded_hash = std::env::var("_AIKEY_HOOK_LOADED_HASH").ok();

            let state = compute_hook_status_state(
                hook_path.exists(),
                file_hash.as_deref(),
                &binary_hash,
                loaded_hash.as_deref(),
            );

            println!("hook file:   {}", hook_path.display());
            println!("file hash:   {}", file_hash.as_deref().unwrap_or("<missing or unparseable>"));
            println!("binary hash: {}", binary_hash);
            println!("loaded hash: {}", loaded_hash.as_deref().unwrap_or("<not set in this process env>"));
            println!("state:       {}", state);
            Ok(())
        }
        HookAction::Install { shell, no_hook } => {
            // Hook coverage v1 §H3: explicit Layer 1 + Layer 2 onboarding
            // for users who set up everything via Web and never touched
            // CLI — running this once wires their rc and unlocks the
            // active-state cross-shell sync.
            //
            // Two paths by `--no-hook`:
            //   --no-hook → Layer 1 only, equivalent to `aikey hook update`
            //               (matches the docstring contract on the Install
            //                variant). Routes through refresh_hook_file_only
            //                so non-TTY / sandbox / CI invocations succeed.
            //   default   → Layer 1 + Layer 2, prompts for rc consent.
            //               Routes through ensure_shell_hook which honors
            //                the H1.5 non-TTY refusal.
            //
            // Implementation note: shell auto-detection happens inside the
            // helpers (uses $SHELL). The --shell flag is forwarded only on
            // the Layer-1-only path (refresh_hook_file_only takes it); for
            // the full install path, ensure_shell_hook is currently hard-
            // wired to $SHELL — decoupling rc selection from $SHELL is out
            // of scope for v1.
            if std::env::var("AIKEY_NO_HOOK").map(|v| v == "1").unwrap_or(false) {
                eprintln!("\x1b[90m  Skipped: AIKEY_NO_HOOK=1 set in environment.\x1b[0m");
                return Ok(());
            }

            if *no_hook {
                match commands_account::refresh_hook_file_only(shell.as_deref()) {
                    Ok(path) => {
                        eprintln!(
                            "\x1b[90m  ✓ Hook file rendered at {} (Layer 1 only; rc untouched).\x1b[0m",
                            path.display(),
                        );
                        eprintln!(
                            "\x1b[90m    To wire rc later: \x1b[36maikey hook install\x1b[0m",
                        );
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                }
            } else {
                match commands_account::ensure_shell_hook(false) {
                    Some(msg) => {
                        println!("{}", msg);
                    }
                    None => {
                        eprintln!("\x1b[90m  ✓ Shell hook installed and rc wired.\x1b[0m");
                        eprintln!("\x1b[90m    Open a new terminal or `source` your rc file to activate.\x1b[0m");
                    }
                }
                Ok(())
            }
        }
    }
}

/// Pure state-machine for `aikey hook status`. Extracted from
/// `handle_hook_command` so it can be unit-tested without touching the
/// filesystem or shell env.
///
/// Decision tree:
///   - file missing                     → not installed
///   - file_hash != binary_hash         → file outdated (user upgraded
///                                        binary without re-running
///                                        `aikey use` / `aikey hook update`)
///   - file matches binary AND loaded   → shell stale (this shell sourced
///     present AND loaded != binary       the old version before user
///                                        regenerated; fix: re-source)
///   - file matches binary AND no       → in-sync (loaded hash unknown —
///     loaded hash visible                the hook was never sourced in
///                                        this shell, or it's an old hook
///                                        that didn't record the hash)
///   - file matches binary AND loaded   → in-sync (canonical good state)
///     == binary
///
/// Why loaded_hash is checked last: even if binary == file, a long-running
/// shell from before a regenerate may still hold the old wrappers in memory.
fn compute_hook_status_state(
    file_exists: bool,
    file_hash: Option<&str>,
    binary_hash: &str,
    loaded_hash: Option<&str>,
) -> &'static str {
    if !file_exists {
        return "not installed (run: aikey hook update)";
    }
    if file_hash != Some(binary_hash) {
        return "file outdated (run: aikey hook update)";
    }
    match loaded_hash {
        Some(loaded) if loaded != binary_hash => {
            "shell stale (run: source ~/.aikey/hook.<zsh|bash>)"
        }
        Some(_) => "in-sync",
        None => "in-sync (loaded hash unknown — old hook or unsourced shell)",
    }
}

#[cfg(test)]
mod hook_command_tests {
    use super::compute_hook_status_state;

    // Reviewer round-3 fix: the earlier draft only had substring tests on
    // the hook templates. The actual state machine for `aikey hook status`
    // had no test coverage. These cases pin every branch of the decision
    // tree so a refactor that breaks one (e.g. swapping the precedence of
    // file-vs-binary check and loaded-vs-binary check) gets caught.

    #[test]
    fn state_not_installed_when_file_missing() {
        let state = compute_hook_status_state(false, None, "abc", None);
        assert!(state.starts_with("not installed"), "got: {}", state);
    }

    #[test]
    fn state_not_installed_when_file_missing_even_if_loaded_present() {
        // A shell with a sourced hook but the file later deleted should
        // still report 'not installed' — the file's the source of truth.
        let state = compute_hook_status_state(false, None, "abc", Some("abc"));
        assert!(state.starts_with("not installed"), "got: {}", state);
    }

    #[test]
    fn state_file_outdated_when_hash_mismatch() {
        let state = compute_hook_status_state(true, Some("old"), "new", None);
        assert!(state.starts_with("file outdated"), "got: {}", state);
    }

    #[test]
    fn state_file_outdated_takes_precedence_over_shell_stale() {
        // file=old binary=new loaded=old: file outdated wins (fix the
        // file first, then the shell will reload).
        let state = compute_hook_status_state(true, Some("old"), "new", Some("old"));
        assert_eq!(state, "file outdated (run: aikey hook update)");
    }

    #[test]
    fn state_file_outdated_when_header_missing_but_file_exists() {
        // File exists but Hook-Template-Hash header was scrubbed → grep
        // returns None → file_hash is None → mismatch with non-empty
        // binary hash → file outdated.
        let state = compute_hook_status_state(true, None, "abc", None);
        assert!(state.starts_with("file outdated"), "got: {}", state);
    }

    #[test]
    fn state_shell_stale_when_loaded_differs_from_binary() {
        let state = compute_hook_status_state(true, Some("abc"), "abc", Some("old"));
        assert!(state.starts_with("shell stale"), "got: {}", state);
    }

    #[test]
    fn state_in_sync_when_all_three_match() {
        let state = compute_hook_status_state(true, Some("abc"), "abc", Some("abc"));
        assert_eq!(state, "in-sync");
    }

    #[test]
    fn state_in_sync_loaded_unknown_when_no_env_var() {
        // No _AIKEY_HOOK_LOADED_HASH in env: hook either was never
        // sourced in this shell, or it's a pre-Stage-1 hook that didn't
        // record the hash. We report soft state, not an error.
        let state = compute_hook_status_state(true, Some("abc"), "abc", None);
        assert!(
            state.starts_with("in-sync") && state.contains("loaded hash unknown"),
            "got: {}", state
        );
    }
}

#[cfg(test)]
mod refresh_hook_file_only_tests {
    use super::commands_account::refresh_hook_file_only;

    // Reviewer round-3 fix: cover the new pure-refresh helper (Stage 8).
    // Cases that don't need filesystem mocks:
    //   - AIKEY_NO_HOOK=1 short-circuits with Err (no write)
    //   - explicit shell parameter respected
    //   - unknown shell parameter rejected
    //
    // We don't cover happy-path filesystem writes here because that's
    // already covered by shell_integration::hook_tests::write_hook_file_*
    // which writes to a tmp HOME and reads back the rendered content.

    #[test]
    fn refresh_short_circuits_when_aikey_no_hook_set() {
        // Save+restore around the env var manipulation so we don't leak
        // state into other tests in the same process.
        let prev = std::env::var("AIKEY_NO_HOOK").ok();
        // Safety: tests in this module run sequentially under cargo's
        // default thread scheduling for tests touching process env. The
        // explicit save/restore keeps it well-behaved if a future
        // -j>1 reorganisation lands.
        unsafe { std::env::set_var("AIKEY_NO_HOOK", "1"); }
        let res = refresh_hook_file_only(Some("zsh"));
        match prev {
            Some(v) => unsafe { std::env::set_var("AIKEY_NO_HOOK", v) },
            None => unsafe { std::env::remove_var("AIKEY_NO_HOOK") },
        }
        match res {
            Err(msg) => assert!(msg.contains("AIKEY_NO_HOOK"), "got: {}", msg),
            Ok(p) => panic!("expected Err when AIKEY_NO_HOOK=1, got Ok({})", p.display()),
        }
    }

    #[test]
    fn refresh_rejects_unknown_shell() {
        // Don't want to depend on $SHELL or AIKEY_NO_HOOK state, so pass
        // explicit shell. If AIKEY_NO_HOOK happens to be set in the test
        // environment, that takes precedence and the test below would
        // get "AIKEY_NO_HOOK" error — handle both for robustness.
        let res = refresh_hook_file_only(Some("fish"));
        match res {
            Err(msg) => assert!(
                msg.contains("unsupported shell") || msg.contains("AIKEY_NO_HOOK"),
                "got: {}", msg
            ),
            Ok(p) => panic!("expected Err for shell=fish, got Ok({})", p.display()),
        }
    }
}

#[cfg(test)]
mod hook_update_error_hint_tests {
    use super::augment_hook_update_error;

    // Bugfix 2026-04-29-aikey-hook-update-eacces-and-sudo-silent-failure.md:
    // when `aikey hook update` fails with a Windows sharing-violation
    // (os error 5 / 32) the user must see actionable next steps, not
    // just the opaque OS message.

    #[test]
    fn eacces_message_gets_remediation_hint() {
        let raw = "failed to write hook file: 拒绝访问。 (os error 5)";
        let aug = augment_hook_update_error(raw);
        assert!(aug.starts_with(raw), "original message must be preserved verbatim");
        assert!(aug.contains("Close ALL other PowerShell"), "missing close-shells step: {}", aug);
        assert!(aug.contains("without sudo"), "missing no-sudo guidance: {}", aug);
        assert!(aug.contains("elevation does not help") || aug.contains("elevation does NOT help"),
            "missing elevation explanation: {}", aug);
    }

    #[test]
    fn sharing_violation_also_gets_hint() {
        // ERROR_SHARING_VIOLATION (32) is the other common transient
        // hold mode (e.g. Windows Search indexer), not just EACCES.
        let raw = "failed to write hook file: The process cannot access the file (os error 32)";
        let aug = augment_hook_update_error(raw);
        assert!(aug.contains("Close ALL other PowerShell"), "got: {}", aug);
    }

    #[test]
    fn unrelated_error_passes_through_unchanged() {
        // Non-EACCES errors (e.g. ENOENT, EROFS) should not get the
        // close-shells hint — that would mislead the user. Only the
        // sharing-violation family gets the augmentation.
        let raw = "failed to write hook file: No such file or directory (os error 2)";
        let aug = augment_hook_update_error(raw);
        assert_eq!(aug, raw, "non-EACCES error should pass through");
    }

    #[test]
    fn english_locale_eacces_also_gets_hint() {
        // Don't lock in the Chinese-locale "拒绝访问" prefix — match
        // on the OS error code, not the localised string.
        let raw = "failed to write hook file: Access is denied. (os error 5)";
        let aug = augment_hook_update_error(raw);
        assert!(aug.contains("Close ALL other PowerShell"), "got: {}", aug);
    }
}

#[cfg(test)]
#[path = "activate_tests.rs"]
mod activate_tests;

