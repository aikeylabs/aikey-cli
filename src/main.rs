#[allow(dead_code)] mod credential_type;
#[allow(dead_code)] mod storage;
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
// mod commands_env; // removed: env commands dropped
mod commands_proxy;
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
mod proxy_env;
#[allow(dead_code)] mod profile_activation;
mod commands_auth;
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
            print_banner();
            eprintln!();
            eprintln!("  Run 'aikey --help' for a list of commands.");
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
                    eprintln!("  Hint: Session cache cleared — next command will prompt for your password.");
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

fn run_command(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let command = cli.command.as_ref().unwrap();

    // Auto-start proxy silently when AIKEY_MASTER_PASSWORD (or AK_TEST_PASSWORD)
    // is available in the environment.  Skipped for proxy lifecycle commands which
    // manage the process themselves, and for version/init which predate the proxy.
    match command {
        Commands::Proxy { .. } | Commands::Init | Commands::Db { .. } | Commands::Version => {}
        _ => { commands_proxy::try_auto_start_from_env(); }
    }

    // Non-blocking snapshot sync: checks server sync_version and pulls fresh
    // key state if it has changed since the last local pull. Skipped for proxy
    // lifecycle and init commands which either predate the vault or manage the
    // process themselves.
    match command {
        Commands::Proxy { .. } | Commands::Init | Commands::Db { .. } | Commands::Version => {}
        _ => { commands_account::try_background_snapshot_sync(); }
    }

    // Auto-apply pending vault schema migrations (idempotent).
    // Why here: ensures new tables/columns exist before any command accesses them.
    // Skipped for init/proxy/db which manage their own lifecycle.
    // Only runs if vault.db exists (no-op on fresh install).
    match command {
        Commands::Proxy { .. } | Commands::Init | Commands::Db { .. } | Commands::Version => {}
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
            let password = prompt_password_secure("\u{1F512} Set Master Password: ", cli.password_stdin, cli.json)?;
            let mut salt = [0u8; 16];
            crypto::generate_salt(&mut salt)?;

            if !cli.json {
                println!("Initializing vault...");
            }

            let result = storage::initialize_vault(&salt, &password);
            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }

            audit::initialize_audit_log()?;
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Init, None, true);

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
        Commands::Add { alias, provider } => {
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
            const KNOWN_PROVIDERS: &[(&str, &str)] = &[
                ("anthropic", "https://api.anthropic.com"),
                ("openai",    "https://api.openai.com/v1"),
                ("google",    "https://generativelanguage.googleapis.com"),
                ("deepseek",  "https://api.deepseek.com/v1"),
                ("kimi",      "https://api.kimi.com/coding/v1"),
            ];

            let (resolved_providers, resolved_base_url): (Vec<String>, Option<String>) =
                if let Some(code) = provider {
                    (vec![code.to_lowercase()], None)
                } else if std::io::stdin().is_terminal() && !cli.json {
                    use colored::Colorize;
                    let mut items: Vec<String> = KNOWN_PROVIDERS.iter().map(|(n, _)| n.to_string()).collect();
                    items.push("Other provider types...".to_string());
                    let custom_idx = KNOWN_PROVIDERS.len();
                    let mut selected: Vec<String>;
                    let mut checked_state: Vec<bool> = vec![false; items.len()];

                    loop {
                        let selected_indices = match ui_select::box_multi_select("Select provider type(s)", &items, &checked_state)? {
                            ui_select::MultiSelectResult::Confirmed(idx) => idx,
                            ui_select::MultiSelectResult::Cancelled => { eprintln!("  Cancelled."); return Ok(()); }
                        };
                        checked_state = vec![false; items.len()];
                        for &i in &selected_indices { if i < checked_state.len() { checked_state[i] = true; } }
                        selected = Vec::new();
                        let mut wants_custom = false;
                        for &idx in &selected_indices {
                            if idx < KNOWN_PROVIDERS.len() {
                                let name = KNOWN_PROVIDERS[idx].0.to_string();
                                if !selected.contains(&name) { selected.push(name); }
                            } else if idx == custom_idx { wants_custom = true; }
                        }
                        if wants_custom {
                            print!("  \u{25c6} Other provider type(s), comma-separated: ");
                            io::stdout().flush()?;
                            let mut custom = String::new();
                            io::stdin().read_line(&mut custom)?;
                            for code in custom.split(',').map(|s| s.trim().to_lowercase()) {
                                if !code.is_empty() && !selected.contains(&code) { selected.push(code); }
                            }
                        }
                        if !selected.is_empty() { break; }
                        use colored::Colorize;
                        eprintln!("  {} At least one provider is required.\n", "\u{25c6}".yellow());
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

                    eprintln!("  \u{2502} Providers: {}", selected.join(", ").bold());
                    if let Some(ref u) = base_url { eprintln!("  \u{2502} Base URL:  {}", u.dimmed()); }
                    (selected, base_url)
                } else {
                    return Err("--provider is required in non-interactive mode.".into());
                };

            let resolved_provider = resolved_providers.first().cloned();

            // Step 4: connectivity test.
            if !cli.json && std::io::stdin().is_terminal() && env::var("AK_TEST_SECRET").is_err() {
                let test_targets: Vec<(String, String)> = resolved_providers.iter().map(|code| {
                    let url = resolved_base_url.as_deref()
                        .or_else(|| commands_project::default_base_url(code))
                        .unwrap_or("https://unknown").to_string();
                    (code.clone(), url)
                }).collect();
                if !test_targets.is_empty() {
                    eprintln!();
                    let suite = commands_project::run_connectivity_test(&test_targets, secret.trim(), false);
                    if !suite.any_chat_ok {
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

            // Step 5: write to vault.
            let result = executor::add_secret(alias, secret.trim(), &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Add, Some(alias), result.is_ok());
            if let Err(e) = result {
                if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); }
            }

            // Persist provider metadata.
            let _ = storage::set_entry_supported_providers(alias, &resolved_providers);
            if let Some(ref code) = resolved_provider {
                let _ = storage::set_entry_provider_code(alias, Some(code.as_str()));
            }
            if let Some(ref url) = resolved_base_url {
                let _ = storage::set_entry_base_url(alias, Some(url.as_str()));
            }

            // Generate route token for per-request proxy routing (API gateway).
            let _ = storage::ensure_entry_route_token(alias);

            // Auto-assign as Primary + refresh active.env.
            let newly_primary = profile_activation::auto_assign_primaries_for_key(
                "personal", alias, &resolved_providers,
            ).unwrap_or_default();
            if !newly_primary.is_empty() || !resolved_providers.is_empty() {
                let _ = profile_activation::refresh_implicit_profile_activation();
            }

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
                    let token_value = format!("aikey_personal_{}", alias);
                    commands_account::configure_kimi_cli(&token_value, proxy_port);
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

                // Auto-start proxy after adding a key so the user can immediately
                // use AI CLIs. Without this, `claude` / `cursor` would fail because
                // the proxy isn't running to route requests.
                if !commands_proxy::is_proxy_running() {
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
        Commands::Delete { alias } => {
            // Confirm before deletion (skip in JSON / non-interactive mode).
            if !cli.json && std::io::stdin().is_terminal() {
                use colored::Colorize;
                eprint!("  Delete API Key '{}'? This cannot be undone. [y/N] (default N): ", alias.bold());
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
                    eprintln!("  Cancelled.");
                    return Ok(());
                }
            }

            let password = prompt_vault_password_fresh(cli.password_stdin, cli.json)?;
            let result = executor::delete_secret(alias, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Delete, Some(alias), result.is_ok());

            if let Err(e) = result {
                if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); }
            }

            // Reconcile provider bindings after removal.
            let actions = profile_activation::reconcile_provider_primary_after_key_removal(
                "personal", alias,
            ).unwrap_or_default();
            if !actions.is_empty() {
                let _ = profile_activation::refresh_implicit_profile_activation();
            }

            if cli.json {
                json_output::success(serde_json::json!({
                    "alias": alias,
                    "message": "API Key deleted successfully"
                }));
            } else {
                use colored::Colorize;
                eprintln!("  {} API Key '{}' deleted.", "\u{2713}".green(), alias);
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
        Commands::List => {
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
                let password = prompt_vault_password(cli.password_stdin, cli.json)?;
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

            if cli.json {
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
                struct RowData { alias: String, providers: String, primary_for: String, has_primary: bool, status: String, created: String, suffix: String }
                let mut personal_rows: Vec<RowData> = Vec::new();
                let mut team_rows: Vec<RowData> = Vec::new();

                for entry in &entries {
                    let providers = if let Some(ref sp) = entry.supported_providers {
                        if !sp.is_empty() { sp.join(",") } else { entry.provider_code.clone().unwrap_or_default() }
                    } else { entry.provider_code.clone().unwrap_or_default() };
                    let pf: Vec<&str> = bindings.iter()
                        .filter(|b| b.key_source_type == credential_type::CredentialType::PersonalApiKey && b.key_source_ref == entry.alias)
                        .map(|b| b.provider_code.as_str()).collect();
                    personal_rows.push(RowData {
                        alias: entry.alias.clone(), providers,
                        primary_for: pf.join(","), has_primary: !pf.is_empty(),
                        status: String::new(), // valid → not displayed
                        created: entry.created_at.map(|ts| format_date(ts)).unwrap_or_default(),
                        suffix: String::new(),
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
                    team_rows.push(RowData {
                        alias: display, providers: e.provider_code.clone(),
                        primary_for: pf.join(","), has_primary: !pf.is_empty(),
                        status, created: format_date(e.synced_at), suffix,
                    });
                }

                let all_data: Vec<&RowData> = personal_rows.iter().chain(team_rows.iter()).collect();
                let headers = ["ALIAS", "PROVIDERS", "USING FOR", "STATUS", "CREATED"];
                let pad = 2;
                let w_alias   = headers[0].len().max(all_data.iter().map(|r| r.alias.len()).max().unwrap_or(0)) + pad;
                let w_prov    = headers[1].len().max(all_data.iter().map(|r| r.providers.len()).max().unwrap_or(0)) + pad;
                let w_primary = headers[2].len().max(all_data.iter().map(|r| r.primary_for.len()).max().unwrap_or(0)) + pad;
                let w_status  = headers[3].len().max(all_data.iter().map(|r| r.status.len()).max().unwrap_or(0)) + pad;

                let fmt_row = |r: &RowData| -> String {
                    let pf_padded = format!("{:<w$}", r.primary_for, w = w_primary);
                    let pf_col = if r.has_primary { pf_padded.green().to_string() } else { pf_padded };
                    let created_col = format!("\x1b[90m{}\x1b[0m", r.created);
                    let prov_display = if r.providers.len() > w_prov {
                        format!("{}...", &r.providers[..w_prov - 3])
                    } else { r.providers.clone() };
                    format!("{:<wa$}  {:<wp$}  {}  {:<ws$}  {}{}",
                        r.alias, prov_display, pf_col, r.status, created_col, r.suffix,
                        wa = w_alias, wp = w_prov, ws = w_status)
                };
                let sep_width = w_alias + 2 + w_prov + 2 + w_primary + 2 + w_status + 2 + 10;

                let mut rows: Vec<String> = Vec::new();
                rows.push(format!("\u{1FAAA} Personal Keys ({})", entries.len()));
                rows.push(format!("\x1b[2m{:<wa$}  {:<wp$}  {:<wf$}  {:<ws$}  {}\x1b[0m",
                    headers[0], headers[1], headers[2], headers[3], headers[4],
                    wa = w_alias, wp = w_prov, wf = w_primary, ws = w_status));
                rows.push("\u{2500}".repeat(sep_width));
                if personal_rows.is_empty() { rows.push("(none)".to_string()); }
                else { for r in &personal_rows { rows.push(fmt_row(r)); } }

                rows.push(String::new());
                rows.push(format!("\u{1F465} Team Keys ({})", managed.len()));
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
                    let w_prov = "PROVIDER".len().max(oauth_rows.iter().map(|r| r.provider.len()).max().unwrap_or(0)) + pad;
                    let w_uf   = "USING FOR".len().max(oauth_rows.iter().map(|r| r.use_for.len()).max().unwrap_or(0)) + pad;
                    let w_st   = "STATUS".len().max(oauth_rows.iter().map(|r| r.status.len()).max().unwrap_or(0)) + pad;
                    let w_tier = "TIER".len().max(oauth_rows.iter().map(|r| r.tier.len()).max().unwrap_or(0)) + pad;
                    let _w_exp = "EXPIRES".len().max(oauth_rows.iter().map(|r| r.expires.len()).max().unwrap_or(0)) + pad;

                    rows.push(String::new());
                    rows.push(format!("\u{1F517} Provider Accounts - OAuth ({})", oauth_accounts.len()));
                    rows.push(format!("\x1b[2m{:<wi$}{:<wp$}  {:<wu$}  {:<ws$}  {:<wt$}  {}\x1b[0m",
                        "IDENTITY", "PROVIDER", "USING FOR", "STATUS", "TIER", "EXPIRES",
                        wi = w_id, wp = w_prov, wu = w_uf, ws = w_st, wt = w_tier));
                    rows.push("\u{2500}".repeat(sep_width));
                    for r in &oauth_rows {
                        let uf_padded = format!("{:<w$}", r.use_for, w = w_uf);
                        let uf_col = if r.has_use { uf_padded.green().to_string() } else { uf_padded };
                        let tier_dim = format!("\x1b[90m{:<w$}\x1b[0m", r.tier, w = w_tier);
                        let expires_dim = format!("\x1b[90m{}\x1b[0m", r.expires);
                        rows.push(format!("{:<wi$}{:<wp$}  {}  {:<ws$}  {}  {}",
                            r.identity, r.provider, uf_col, r.status, tier_dim, expires_dim,
                            wi = w_id, wp = w_prov, ws = w_st));
                    }
                }

                ui_frame::print_box("\u{1F511}", "Keys", &rows);
            }

            // Post-operation: warn if proxy is unreachable (e.g. after kill -9).
            commands_proxy::warn_if_proxy_down();
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
            let password = prompt_vault_password(cli.password_stdin, cli.json)?;

            if let Some(ref alias) = alias {
                // ── Test a specific key by alias ─────────────────────
                let key_value = match executor::get_secret(alias, &password) {
                    Ok(s) => s,
                    Err(e) => { if cli.json { json_output::error(&e, 1); } else { return Err(e.into()); } }
                };
                let meta = storage::list_entries_with_metadata().unwrap_or_default()
                    .into_iter().find(|m| m.alias == *alias);
                let provider_code = test_provider.as_ref().map(|p| p.to_lowercase())
                    .or_else(|| meta.as_ref().and_then(|m| m.provider_code.clone()));
                let base_url_override = meta.as_ref().and_then(|m| m.base_url.clone());

                let targets: Vec<(String, String)> = if let Some(ref code) = provider_code {
                    let url = base_url_override.as_deref()
                        .or_else(|| commands_project::default_base_url(code))
                        .unwrap_or("https://unknown").to_string();
                    vec![(code.clone(), url)]
                } else if let Some(ref url) = base_url_override {
                    let mut t: Vec<(String, String)> = commands_project::PROVIDER_DEFAULTS.iter()
                        .map(|(c, _)| (c.to_string(), url.clone())).collect();
                    t.push(("custom".to_string(), url.clone())); t
                } else {
                    commands_project::PROVIDER_DEFAULTS.iter().map(|(c, u)| (c.to_string(), u.to_string())).collect()
                };

                if cli.json {
                    let suite = commands_project::run_connectivity_test(&targets, key_value.trim(), true);
                    json_output::success(serde_json::json!({ "alias": alias, "results": suite.json_results }));
                } else {
                    use colored::Colorize;
                    if targets.len() == 1 { let (code, url) = &targets[0]; eprintln!("  Testing '{}' ({} \u{2192} {})", alias.bold(), code, url.dimmed()); }
                    else { eprintln!("  Testing '{}' against {} providers", alias.bold(), targets.len()); }
                    eprintln!();
                    commands_project::run_connectivity_test(&targets, key_value.trim(), false);
                }
            } else {
                // ── No alias: test all current Primary keys in one table ─
                let bindings = storage::list_provider_bindings(profile_activation::DEFAULT_PROFILE).unwrap_or_default();
                if bindings.is_empty() {
                    if cli.json { json_output::error("No active provider bindings. Add a key first.", 1); }
                    else { return Err("No active provider bindings. Add a key with `aikey add` first.".into()); }
                }
                use colored::Colorize;

                struct TestItem { provider: String, url: String, key: String, display: String, source_type: String }
                let mut items: Vec<TestItem> = Vec::new();
                let mut skipped_team: Vec<(String, String)> = Vec::new();

                for b in &bindings {
                    let display = resolve_binding_display_name(b.key_source_type.as_str(), &b.key_source_ref);
                    if b.key_source_type == credential_type::CredentialType::PersonalApiKey {
                        let kv = match executor::get_secret(&b.key_source_ref, &password) {
                            Ok(s) => s,
                            Err(e) => { if !cli.json { eprintln!("  {} {} \u{2192} '{}': {}", "\u{2717}".red(), b.provider_code, b.key_source_ref, e); } continue; }
                        };
                        let bu = storage::get_entry_base_url(&b.key_source_ref).unwrap_or(None);
                        let url = bu.as_deref().or_else(|| commands_project::default_base_url(&b.provider_code)).unwrap_or("https://unknown").to_string();
                        items.push(TestItem { provider: b.provider_code.clone(), url, key: kv.to_string(), display, source_type: b.key_source_type.as_str().to_string() });
                    } else { skipped_team.push((b.provider_code.clone(), display)); }
                }

                if cli.json {
                    let mut all_json: Vec<serde_json::Value> = Vec::new();
                    for item in &items {
                        let r = commands_project::test_provider_connectivity(&item.provider, &item.url, item.key.trim());
                        all_json.push(serde_json::json!({ "provider": item.provider, "alias": item.display, "source_type": item.source_type, "base_url": item.url,
                            "ping_ok": r.ping_ok, "ping_ms": r.ping_ms, "api_ok": r.api_ok, "api_ms": r.api_ms, "api_status": r.api_status,
                            "chat_ok": r.chat_ok, "chat_ms": r.chat_ms, "chat_status": r.chat_status }));
                    }
                    json_output::success(serde_json::json!({ "bindings_tested": all_json }));
                } else {
                    eprintln!("  Testing {} active provider binding(s)...\n", bindings.len());
                    const W_PROV: usize = 12; const W_ALIAS: usize = 16; const W_PING: usize = 16; const W_API: usize = 30;
                    eprintln!("  {:<wp$} {:<wa$} {:<wpi$} {:<wap$} {}", "Provider".dimmed(), "Key".dimmed(), "Ping".dimmed(), "API".dimmed(), "Chat".dimmed(),
                        wp = W_PROV, wa = W_ALIAS, wpi = W_PING, wap = W_API);
                    eprintln!("  {}", "\u{2500}".repeat(W_PROV + W_ALIAS + W_PING + W_API + 20).dimmed());

                    let mut any_reachable = false;
                    for item in &items {
                        eprint!("  {:<wp$} {:<wa$} ", item.provider.bold(), item.display.dimmed(), wp = W_PROV, wa = W_ALIAS);
                        let _ = io::stderr().flush();
                        let r = commands_project::test_provider_connectivity(&item.provider, &item.url, item.key.trim());
                        let ping_raw = if r.ping_ok { format!("ok ({}ms)", r.ping_ms) } else { format!("fail ({}ms)", r.ping_ms) };
                        let ping_col = if r.ping_ok { format!("{:<w$}", ping_raw, w = W_PING).green().to_string() } else { format!("{:<w$}", ping_raw, w = W_PING).red().to_string() };
                        eprint!("{} ", ping_col); let _ = io::stderr().flush();
                        if !r.ping_ok { eprintln!("{:<w$} {}", "\u{2014}".dimmed(), "\u{2014}".dimmed(), w = W_API); }
                        else {
                            any_reachable = true;
                            let api_raw = if r.api_ok { let h = r.api_status.map(|s| commands_project::api_status_hint(s)).unwrap_or_default(); format!("ok ({}ms, {})", r.api_ms, h) } else { format!("fail ({}ms)", r.api_ms) };
                            let api_col = if r.api_ok { format!("{:<w$}", api_raw, w = W_API).green().to_string() } else { format!("{:<w$}", api_raw, w = W_API).red().to_string() };
                            eprint!("{} ", api_col); let _ = io::stderr().flush();
                            if !r.api_ok { eprintln!("{}", "\u{2014}".dimmed()); }
                            else if r.chat_ok { let h = r.chat_status.map(|s| commands_project::chat_status_hint(s)).unwrap_or_default(); eprintln!("{}", format!("ok ({}ms, {})", r.chat_ms, h).green()); }
                            else { eprintln!("{}", format!("fail ({}ms)", r.chat_ms).red()); }
                        }
                    }
                    for (prov, display) in &skipped_team { eprintln!("  {:<wp$} {:<wa$} {}", prov.bold(), display.dimmed(), "skipped [team]".dimmed(), wp = W_PROV, wa = W_ALIAS); }

                    eprintln!();
                    if !any_reachable { eprintln!("  {:<12} {}", "proxy".bold(), "skipped (all providers unreachable)".dimmed()); }
                    else if commands_proxy::is_proxy_running() {
                        let proxy_addr = commands_proxy::doctor_proxy_addr();
                        if let Some(prov) = items.first().map(|i| i.provider.as_str()) {
                            eprint!("  {:<12} ", "proxy".bold());
                            let r = commands_project::test_proxy_connectivity(&proxy_addr, prov);
                            if r.ok { let h = r.status.map(|s| commands_project::proxy_status_hint(s)).unwrap_or_default(); eprintln!("{} ({} ms, {})", "ok".green(), r.ms, h); }
                            else { eprintln!("{} ({} ms)", "failed".red(), r.ms); }
                        }
                    } else { eprintln!("  {:<12} {}", "proxy".bold(), "not running".dimmed()); }
                }
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
                                    "secrets": secrets
                                }));
                            } else if secrets.is_empty() {
                                println!("No API Keys stored.");
                            } else {
                                println!("Stored API Keys:");
                                for secret in secrets {
                                    println!("  {}", secret.alias);
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

                    let new_value = if *from_stdin {
                        eprint!("Enter new value for '{}' (then press Enter): ", name);
                        let _ = io::stderr().flush();
                        let mut buf = Zeroizing::new(String::new());
                        io::stdin().read_line(&mut buf)?;
                        buf
                    } else {
                        let val = prompt_hidden(&format!("\u{1F511} New value for '{}': ", name))
                            .map_err(|e| format!("Failed to read new key value: {}", e))?;
                        Zeroizing::new(val)
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
                    commands_account::handle_key_list(cli.json)?;
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
                AccountAction::Login { url, token, email } => {
                    commands_account::handle_login(
                        cli.json,
                        url.clone(),
                        token.clone(),
                        email.clone(),
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
            handle_activate(alias, provider.as_deref(), shell.as_deref())?;
        }
        Commands::Deactivate { shell } => {
            handle_deactivate(shell.as_deref())?;
        }
        Commands::Route { label, full } => {
            handle_route(label.as_deref(), *full, cli.json)?;
        }
        Commands::Login { url, token, email } => {
            commands_account::handle_login(cli.json, url.clone(), token.clone(), email.clone())?;
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
                        for (prov, src_type, src_ref) in &changes {
                            storage::set_provider_binding(
                                profile_activation::DEFAULT_PROFILE,
                                prov, src_type, src_ref,
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
                            if let Some(b) = refresh.bindings.iter().find(|b| {
                                let c = b.provider_code.to_lowercase();
                                c == "kimi" || c == "moonshot"
                            }) {
                                let token = format!("aikey_{}_{}", b.key_source_type, b.key_source_ref);
                                commands_account::configure_kimi_cli(&token, proxy_port);
                            }
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
                        if std::env::var("AIKEY_ACTIVE_KEYS").is_err() {
                            eprintln!("  \x1b[33m!\x1b[0m Run: \x1b[1msource ~/.zshrc\x1b[0m  (or open a new terminal)");
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
                    if commands_proxy::is_proxy_running() {
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
        Commands::Web { page, port } => {
            commands_account::handle_browse(page.as_deref(), *port, cli.json)?;
        }
        Commands::Master { page, url, port } => {
            commands_account::handle_master_browse(page.as_deref(), url.as_deref(), *port, cli.json)?;
        }
        Commands::Status => {
            commands_account::handle_status_overview(cli.json)?;
        }
        Commands::Whoami => {
            commands_account::handle_whoami(cli.json)?;
        }
        Commands::Doctor => {
            commands_project::handle_doctor(cli.json)?;
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
                    "ID", "TIMESTAMP", "TYPE", "PROVIDER", "EXIT", "COMMAND");
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

/// Maps broker/brand provider codes to canonical codes for proxy path-prefix routing.
/// "claude" → "anthropic", "codex" → "openai", "moonshot" → "kimi", etc.
fn canonical_provider(code: &str) -> &str {
    match code.to_lowercase().as_str() {
        "claude" => "anthropic",
        "codex" | "gpt" | "chatgpt" => "openai",
        "gemini" => "google",
        "moonshot" => "kimi",
        _ => code,
    }
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

    // Collect active bindings for "●" marker.
    let bindings = storage::list_provider_bindings_readonly("default").unwrap_or_default();
    let is_active = |source_type: &str, source_ref: &str| -> bool {
        bindings.iter().any(|b| {
            b.key_source_ref == source_ref && match source_type {
                "team" => b.key_source_type == credential_type::CredentialType::ManagedVirtualKey,
                "personal" => b.key_source_type == credential_type::CredentialType::PersonalApiKey,
                "oauth" => b.key_source_type == credential_type::CredentialType::PersonalOAuthAccount,
                _ => false,
            }
        })
    };

    // 1. Team managed keys
    for vk in storage::list_virtual_key_cache_readonly().unwrap_or_default() {
        // Only show team keys that the proxy will actually register in Registry.
        // synced_inactive keys exist in vault but are NOT loaded by proxy.
        if vk.local_state != "active" {
            continue;
        }
        let display_alias = vk.local_alias.as_deref().unwrap_or(&vk.alias);
        // Team keys use virtual_key_id directly (already has aikey_vk_ prefix from server).
        let token = if vk.virtual_key_id.starts_with("aikey_vk_") {
            vk.virtual_key_id.clone()
        } else {
            format!("aikey_vk_{}", vk.virtual_key_id)
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
                base_url: format!("http://127.0.0.1:{}/{}", proxy_port, canonical_provider(prov)),
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
                    provider: canonical_provider(&acct.provider).to_string(),
                    key_type: "oauth".to_string(),
                    label: label_str.to_string(),
                    api_key: token,
                    base_url: format!("http://127.0.0.1:{}/{}", proxy_port, canonical_provider(&acct.provider)),
                    active: is_active("oauth", &acct.provider_account_id),
                });
            }
            Ok(None) => { missing_token_count += 1; }
            Err(_) => { missing_token_count += 1; }
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
                let providers = meta.supported_providers.as_deref()
                    .unwrap_or_else(|| meta.provider_code.as_ref()
                        .map(|p| std::slice::from_ref(p))
                        .unwrap_or(&[]));
                for prov in providers {
                    entries.push(RouteEntry {
                        provider: prov.clone(),
                        key_type: "personal".to_string(),
                        label: meta.alias.clone(),
                        api_key: token.clone(),
                        base_url: format!("http://127.0.0.1:{}/{}", proxy_port, canonical_provider(prov)),
                        active: is_active("personal", &meta.alias),
                    });
                }
            }
            Ok(None) => { missing_token_count += 1; }
            Err(_) => { missing_token_count += 1; }
        }
    }

    // If a specific label was requested, filter and show copy-paste config.
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
            let first = matched[0];
            eprintln!("  # Configuration for: {} ({}, {})\n", first.label, first.key_type, first.provider);
            if matched.len() == 1 {
                eprintln!("  base_url:  {}", first.base_url);
                eprintln!("  api_key:   {}", first.api_key);
            } else {
                for entry in &matched {
                    eprintln!("  [{}]", entry.provider);
                    eprintln!("  base_url:  {}", entry.base_url);
                    eprintln!("  api_key:   {}", entry.api_key);
                    eprintln!();
                }
            }
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

    // Table header
    eprintln!();
    eprintln!("  {:<13} {:<10} {:<22} {:<38} {}",
        "PROVIDER", "TYPE", "LABEL", "API_KEY", "BASE URL");
    eprintln!("  {}", "\u{2500}".repeat(95));

    for entry in &entries {
        let token_display = if full || entry.api_key.len() <= 24 {
            entry.api_key.clone()
        } else {
            // Truncate: first 15 chars + "..." + last 4 chars
            format!("{}...{}", &entry.api_key[..15], &entry.api_key[entry.api_key.len()-4..])
        };
        eprintln!("  {:<13} {:<10} {:<20}{} {:<38} {}",
            entry.provider, entry.key_type, entry.label,
            if entry.active { "\u{25cf}".green().to_string() } else { " ".to_string() },
            token_display.dimmed(), entry.base_url.dimmed());
    }

    // Count unique providers
    let mut providers: Vec<&str> = entries.iter().map(|e| e.provider.as_str()).collect();
    providers.sort();
    providers.dedup();
    eprintln!();
    eprintln!("  {} = active (set by `aikey use`)", "\u{25cf}".green());
    eprintln!("  {} providers, {} routes available", providers.len(), entries.len());
    eprintln!();
    let example_label = entries.first().map(|e| e.label.as_str()).unwrap_or("my-key");
    eprintln!("  {} {} {}",
        "\u{27a4}".cyan(),
        "Copy-paste config:".bold(),
        format!("aikey route {}", example_label).cyan());

    if missing_token_count > 0 {
        eprintln!();
        eprintln!("  {} {} keys missing route token. Run `aikey use` or `aikey add` to complete setup.",
            "\u{26a0}".yellow(), missing_token_count);
    }

    if !commands_proxy::is_proxy_running() {
        eprintln!();
        eprintln!("  {} Proxy is not running. Start with: aikey proxy start", "\u{26a0}".yellow());
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

/// Show an interactive arrow-key picker with all available personal + team keys.
/// Returns the alias/id that the user selected.
#[allow(dead_code)]
fn pick_key_interactively() -> Result<String, Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Gather personal keys
    let personal = storage::list_entries_with_metadata().unwrap_or_default();
    // Gather team keys
    let team = storage::list_virtual_key_cache().unwrap_or_default();

    if personal.is_empty() && team.is_empty() {
        return Err("No keys found. Add a personal key with `aikey add` or sync team keys with `aikey key sync`.".into());
    }

    // Active key for LOCAL column
    let active_cfg = storage::get_active_key_config().ok().flatten();

    // Build display rows; keep alias/id parallel for lookup after selection.
    // Format: TYPE  ALIAS  PROVIDER / BASE_URL  [active marker]
    let mut items: Vec<String> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    // Track which rows are selectable (false for separator & other-account keys).
    let mut selectable: Vec<bool> = Vec::new();

    // Dynamic column widths based on terminal size.
    // Layout: "personal  " (10) + alias_w + "  " (2) + provider_w + " ◀ active" (9)
    let tw = ui_frame::term_width();
    // Reserve: 10 (type+space) + 2 (gap) + 9 (active marker) + 10 (box borders/margins)
    let available = tw.saturating_sub(31);
    // Split available space: ~40% alias, ~60% provider, with minimums.
    let alias_w = (available * 2 / 5).max(10).min(30);
    let provider_w = available.saturating_sub(alias_w).max(10).min(40);

    for entry in &personal {
        let provider_col = match (&entry.base_url, &entry.provider_code) {
            (Some(url), _) if !url.is_empty() => url.clone(),
            (_, Some(code)) if !code.is_empty() => code.clone(),
            _ => String::new(),
        };
        let is_active = active_cfg.as_ref().map_or(false, |cfg| {
            cfg.key_type == credential_type::CredentialType::PersonalApiKey && cfg.key_ref == entry.alias
        });
        let active_marker = if is_active { " ◀ active" } else { "" };
        let alias_display = if entry.alias.len() > alias_w { &entry.alias[..alias_w] } else { &entry.alias };
        let prov_display = if provider_col.len() > provider_w { &provider_col[..provider_w] } else { &provider_col };
        let row = format!(
            "personal  {:<aw$}  {:<pw$}{}",
            alias_display,
            prov_display,
            active_marker,
            aw = alias_w,
            pw = provider_w,
        );
        items.push(row);
        aliases.push(entry.alias.clone());
        selectable.push(true);
    }

    // Filter out unusable team keys (revoked, expired, stale, etc.).
    // Only show keys that are either usable or belong to another account (for visibility).
    let visible_team: Vec<_> = team.iter()
        .filter(|e| {
            e.key_status == "active"
                && e.local_state != "stale"
                && e.local_state != "disabled_by_key_status"
                && e.local_state != "disabled_by_seat_status"
                && e.local_state != "disabled_by_account_status"
        })
        .collect();

    // Partition: current account (selectable) vs other account (view-only).
    let (own_team, other_account_team): (Vec<_>, Vec<_>) = visible_team.into_iter()
        .partition(|e| e.local_state != "disabled_by_account_scope");

    for e in &own_team {
        let display_name = e.local_alias.as_deref().unwrap_or(e.alias.as_str());
        let is_active = active_cfg.as_ref().map_or(false, |cfg| {
            cfg.key_type == credential_type::CredentialType::ManagedVirtualKey && cfg.key_ref == e.virtual_key_id
        });
        let active_marker = if is_active { " ◀ active" } else { "" };
        let alias_display = if display_name.len() > alias_w { &display_name[..alias_w] } else { display_name };
        let prov_display = if e.provider_code.len() > provider_w { &e.provider_code[..provider_w] } else { &e.provider_code };
        let row = format!(
            "team      {:<aw$}  {:<pw$}{}",
            alias_display,
            prov_display,
            active_marker,
            aw = alias_w,
            pw = provider_w,
        );
        items.push(row);
        aliases.push(e.virtual_key_id.clone());
        selectable.push(true);
    }

    // Other-account keys: shown at the bottom, dimmed, not selectable.
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
                "team      {:<aw$}  {:<pw$}  [other account]",
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

    let header = format!("        {:<aw$}  {:<pw$}", "Alias", "Provider / Base URL", aw = alias_w, pw = provider_w);

    // Find initial cursor: prefer the currently active key, else first selectable.
    let initial = active_cfg.as_ref()
        .and_then(|cfg| {
            aliases.iter().position(|a| {
                (cfg.key_type == credential_type::CredentialType::ManagedVirtualKey && *a == cfg.key_ref)
                    || (cfg.key_type == credential_type::CredentialType::PersonalApiKey && *a == cfg.key_ref)
            })
        })
        .and_then(|i| if selectable[i] { Some(i) } else { None })
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
        // (older aikey auth use may have written "claude" instead of "anthropic")
        let canonical = match b.provider_code.as_str() {
            "claude" => "anthropic",
            "codex" => "openai",
            _ => b.provider_code.as_str(),
        };
        add_prov(canonical);
    }
    // Add OAuth account providers (mapped to canonical)
    for acct in &oauth_accounts {
        match acct.provider.as_str() {
            "claude" => add_prov("anthropic"),
            "codex" => add_prov("openai"),
            _ => add_prov(&acct.provider),
        }
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

        // OAuth accounts — match by canonical provider (claude→anthropic, codex→openai)
        for acct in &oauth_accounts {
            let canonical = match acct.provider.as_str() {
                "claude" => "anthropic",
                "codex" => "openai",
                _ => acct.provider.as_str(),
            };
            if canonical == *prov {
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

        // Match binding by canonical provider code (claude→anthropic, codex→openai)
        let current_binding = bindings.iter().find(|b| {
            let b_canonical = match b.provider_code.as_str() {
                "claude" => "anthropic",
                "codex" => "openai",
                _ => b.provider_code.as_str(),
            };
            b_canonical == *prov || b.provider_code == *prov
        });
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
fn cmd_escape(s: &str) -> Result<String, String> {
    // cmd `set VAR=VALUE` is unquoted; reject dangerous characters.
    if s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-')) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Label '{}' contains characters unsafe for cmd.exe. \
             Allowed: [a-zA-Z0-9._@-]",
            s
        ))
    }
}

/// Escape label for safe embedding in zsh PROMPT (prompt expansion: % is special).
fn zsh_prompt_escape(s: &str) -> String {
    s.replace('%', "%%")
}

/// Escape label for safe embedding in bash PS1 (prompt expansion: \\ is special).
fn bash_prompt_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
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
        if vk.local_state.starts_with("disabled_by_") {
            return Err(format!(
                "Key '{}' is unavailable (state: {}). Run 'aikey key sync' to refresh.",
                vk.alias, vk.local_state
            ).into());
        }
        let display = vk.local_alias.as_deref().unwrap_or(&vk.alias).to_string();
        let token = if vk.virtual_key_id.starts_with("aikey_vk_") {
            vk.virtual_key_id.clone()
        } else {
            format!("aikey_vk_{}", vk.virtual_key_id)
        };
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
fn resolve_single_provider(
    display: &str,
    providers: &[String],
    provider_override: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(ov) = provider_override {
        let code = ov.to_lowercase();
        if !providers.iter().any(|p| p.to_lowercase() == code) {
            return Err(format!(
                "Key '{}' does not support provider '{}'. Supported: {}",
                display, code, providers.join(", ")
            ).into());
        }
        return Ok(code);
    }
    if providers.len() == 1 {
        return Ok(providers[0].to_lowercase());
    }
    Err(format!(
        "Key '{}' supports multiple providers: {}. Specify --provider <name>.",
        display, providers.join(", ")
    ).into())
}

/// Auto-detect the current shell from the SHELL environment variable.
/// Returns "zsh", "bash", "powershell", or None if unrecognized.
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

/// `aikey activate <alias> [--shell <shell>]` — output eval-safe export statements.
///
/// Stdout: only eval-safe shell statements (captured by wrapper function).
/// Stderr: all human-readable messages (flows through to terminal).
/// When `--shell` is omitted, auto-detects from the SHELL env var.
fn handle_activate(
    alias: &str,
    provider_override: Option<&str>,
    shell: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let detected;
    let (shell, via_wrapper) = match shell {
        Some(s) => (s, true),
        None => {
            detected = detect_shell().ok_or(
                "Could not detect shell type. Pass --shell explicitly, e.g.:\n\
                 eval $(aikey activate <alias> --shell zsh)"
            )?;
            // When user calls binary directly (no wrapper), remind them to eval.
            eprintln!("\x1b[90m  Detected shell: {}. Wrap with eval to apply:\x1b[0m", detected);
            eprintln!("\x1b[90m  eval $(aikey activate {} --shell {})\x1b[0m", alias, detected);
            (detected, false)
        }
    };
    // When called directly (not via wrapper), stdout is visible on terminal.
    // Dim it so it doesn't distract — the user can't eval it anyway.
    let dim = if via_wrapper { "" } else { "\x1b[90m" };
    let reset = if via_wrapper { "" } else { "\x1b[0m" };

    let (label, token, provider) = resolve_activate_key(alias, provider_override)?;

    // Why: resolve_activate_key may generate a new route token (first activate of a
    // personal/OAuth key). The proxy's in-memory Registry won't know about it until
    // the vault change-seq is bumped and a reload is triggered. Without this, the
    // token we just output would hit TOKEN_INVALID on the running proxy.
    let _ = storage::bump_vault_change_seq();
    commands_proxy::try_reload_proxy();

    let proxy_port = commands_proxy::proxy_port();
    let (api_key_var, base_url_var) = commands_account::provider_env_vars_pub(&provider)
        .ok_or_else(|| format!("Unknown provider '{}' — no env var mapping.", provider))?;
    let base_url = format!(
        "http://127.0.0.1:{}/{}",
        proxy_port,
        commands_account::provider_proxy_prefix_pub(&provider)
    );

    // When called directly (not via wrapper), dim stdout so shell statements
    // don't visually distract — the user can't eval them from a direct call anyway.
    if !via_wrapper { print!("{}", dim); }

    match shell {
        "zsh" => {
            let prompt_label = zsh_prompt_escape(&label);
            let unset_vars: Vec<&str> = ALL_PROVIDER_ENV_PAIRS.iter()
                .flat_map(|(k, v)| [*k, *v])
                .collect();
            println!("unset {}", unset_vars.join(" "));
            println!("export AIKEY_ACTIVE_LABEL={}", shell_escape(&label));
            println!("export _AIKEY_PROMPT_LABEL={}", shell_escape(&prompt_label));
            println!("export {}={}", api_key_var, shell_escape(&token));
            println!("export {}={}", base_url_var, shell_escape(&base_url));
            println!("if [ -z \"$_AIKEY_ORIG_PROMPT\" ]; then _AIKEY_ORIG_PROMPT=\"$PROMPT\"; fi");
            println!("PROMPT=\"($_AIKEY_PROMPT_LABEL) $_AIKEY_ORIG_PROMPT\"");
        }
        "bash" => {
            let prompt_label = bash_prompt_escape(&label);
            let unset_vars: Vec<&str> = ALL_PROVIDER_ENV_PAIRS.iter()
                .flat_map(|(k, v)| [*k, *v])
                .collect();
            println!("unset {}", unset_vars.join(" "));
            println!("export AIKEY_ACTIVE_LABEL={}", shell_escape(&label));
            println!("export _AIKEY_PROMPT_LABEL={}", shell_escape(&prompt_label));
            println!("export {}={}", api_key_var, shell_escape(&token));
            println!("export {}={}", base_url_var, shell_escape(&base_url));
            println!("if [ -z \"$_AIKEY_ORIG_PS1\" ]; then _AIKEY_ORIG_PS1=\"$PS1\"; fi");
            println!("PS1=\"($_AIKEY_PROMPT_LABEL) $_AIKEY_ORIG_PS1\"");
        }
        "powershell" => {
            let unset_vars: Vec<&str> = ALL_PROVIDER_ENV_PAIRS.iter()
                .flat_map(|(k, v)| [*k, *v])
                .collect();
            for var in &unset_vars {
                println!("Remove-Item Env:\\{} -ErrorAction SilentlyContinue", var);
            }
            println!("$env:AIKEY_ACTIVE_LABEL = {}", powershell_escape(&label));
            println!("$env:_AIKEY_PROMPT_LABEL = {}", powershell_escape(&label));
            println!("$env:{} = {}", api_key_var, powershell_escape(&token));
            println!("$env:{} = {}", base_url_var, powershell_escape(&base_url));
            println!("if (-not $env:_AIKEY_ORIG_PROMPT_FN) {{ $env:_AIKEY_ORIG_PROMPT_FN = (Get-Item function:prompt).ScriptBlock.ToString() }}");
            println!("function global:prompt {{ \"($env:_AIKEY_PROMPT_LABEL) \" + (Invoke-Expression $env:_AIKEY_ORIG_PROMPT_FN) }}");
        }
        "cmd" => {
            let safe_label = cmd_escape(&label)?;
            let unset_vars: Vec<&str> = ALL_PROVIDER_ENV_PAIRS.iter()
                .flat_map(|(k, v)| [*k, *v])
                .collect();
            for var in &unset_vars {
                println!("set {}=", var);
            }
            println!("set AIKEY_ACTIVE_LABEL={}", safe_label);
            println!("set _AIKEY_PROMPT_LABEL={}", safe_label);
            println!("set {}={}", api_key_var, token);
            println!("set {}={}", base_url_var, base_url);
            println!("prompt (%_AIKEY_PROMPT_LABEL%) $P$G");
        }
        other => {
            if !via_wrapper { print!("{}", reset); }
            return Err(format!(
                "Unsupported shell '{}'. Supported: zsh, bash, powershell, cmd.",
                other
            ).into());
        }
    }

    if !via_wrapper { println!("{}", reset); }

    // Human-readable confirmation on stderr (not captured by wrapper).
    eprintln!("\x1b[90m  Activated: {} \u{2192} {} ({})\x1b[0m", label, provider, shell);
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
            detected = detect_shell().ok_or(
                "Could not detect shell type. Pass --shell explicitly, e.g.:\n\
                 eval $(aikey deactivate --shell zsh)"
            )?;
            eprintln!("\x1b[90m  Detected shell: {}. Wrap with eval to apply:\x1b[0m", detected);
            eprintln!("\x1b[90m  eval $(aikey deactivate --shell {})\x1b[0m", detected);
            detected
        }
    };

    match shell {
        "zsh" => {
            let unset_vars: Vec<&str> = ALL_PROVIDER_ENV_PAIRS.iter()
                .flat_map(|(k, v)| [*k, *v])
                .collect();
            println!("unset AIKEY_ACTIVE_LABEL _AIKEY_PROMPT_LABEL");
            println!("unset {}", unset_vars.join(" "));
            println!("if [ -n \"$_AIKEY_ORIG_PROMPT\" ]; then PROMPT=\"$_AIKEY_ORIG_PROMPT\"; unset _AIKEY_ORIG_PROMPT; fi");
            println!("[ -f ~/.aikey/active.env ] && source ~/.aikey/active.env");
        }
        "bash" => {
            let unset_vars: Vec<&str> = ALL_PROVIDER_ENV_PAIRS.iter()
                .flat_map(|(k, v)| [*k, *v])
                .collect();
            println!("unset AIKEY_ACTIVE_LABEL _AIKEY_PROMPT_LABEL");
            println!("unset {}", unset_vars.join(" "));
            println!("if [ -n \"$_AIKEY_ORIG_PS1\" ]; then PS1=\"$_AIKEY_ORIG_PS1\"; unset _AIKEY_ORIG_PS1; fi");
            println!("[ -f ~/.aikey/active.env ] && source ~/.aikey/active.env");
        }
        "powershell" => {
            let all_vars: Vec<&str> = ALL_PROVIDER_ENV_PAIRS.iter()
                .flat_map(|(k, v)| [*k, *v])
                .chain(["AIKEY_ACTIVE_LABEL", "_AIKEY_PROMPT_LABEL"].iter().copied())
                .collect();
            for var in &all_vars {
                println!("Remove-Item Env:\\{} -ErrorAction SilentlyContinue", var);
            }
            println!("if ($env:_AIKEY_ORIG_PROMPT_FN) {{ function global:prompt {{ Invoke-Expression $env:_AIKEY_ORIG_PROMPT_FN }}; Remove-Item Env:\\_AIKEY_ORIG_PROMPT_FN -ErrorAction SilentlyContinue }}");
            // Restore global settings from active.env.flat (plain KEY=VALUE, no sh syntax).
            // Why .flat instead of .env: active.env contains sh-expansion like ${NO_PROXY:-}
            // which PowerShell would import as literal text, breaking proxy bypass config.
            // active.env.flat is generated alongside active.env with pure literal values.
            println!("$_af = if ($env:HOME) {{ Join-Path $env:HOME '.aikey' 'active.env.flat' }} else {{ Join-Path $env:USERPROFILE '.aikey' 'active.env.flat' }}");
            println!("if (Test-Path $_af) {{ Get-Content $_af | ForEach-Object {{ if ($_ -match '^(\\w+)=(.*)$') {{ [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process') }} }} }}");
        }
        "cmd" => {
            let all_vars: Vec<&str> = ALL_PROVIDER_ENV_PAIRS.iter()
                .flat_map(|(k, v)| [*k, *v])
                .chain(["AIKEY_ACTIVE_LABEL", "_AIKEY_PROMPT_LABEL"].iter().copied())
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

#[cfg(test)]
mod activate_tests {
    use super::*;

    // ── shell_escape ────────────────────────────────────────────────────────

    #[test]
    fn shell_escape_plain() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn shell_escape_single_quote() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_escape_dollar_parens() {
        assert_eq!(shell_escape("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn shell_escape_backtick() {
        assert_eq!(shell_escape("`cmd`"), "'`cmd`'");
    }

    #[test]
    fn shell_escape_newline() {
        assert_eq!(shell_escape("a\nb"), "'a\nb'");
    }

    #[test]
    fn shell_escape_double_quotes() {
        assert_eq!(shell_escape(r#"test"key"#), r#"'test"key'"#);
    }

    // ── powershell_escape ───────────────────────────────────────────────────

    #[test]
    fn powershell_escape_single_quote() {
        assert_eq!(powershell_escape("it's"), "'it''s'");
    }

    #[test]
    fn powershell_escape_plain() {
        assert_eq!(powershell_escape("hello"), "'hello'");
    }

    // ── cmd_escape ──────────────────────────────────────────────────────────

    #[test]
    fn cmd_escape_safe() {
        assert!(cmd_escape("my-key_01.test@host").is_ok());
    }

    #[test]
    fn cmd_escape_unsafe_ampersand() {
        assert!(cmd_escape("a&b").is_err());
    }

    #[test]
    fn cmd_escape_unsafe_pipe() {
        assert!(cmd_escape("a|b").is_err());
    }

    #[test]
    fn cmd_escape_unsafe_spaces() {
        assert!(cmd_escape("a b").is_err());
    }

    // ── prompt escaping ─────────────────────────────────────────────────────

    #[test]
    fn zsh_prompt_escape_percent() {
        assert_eq!(zsh_prompt_escape("%F{red}evil%f"), "%%F{red}evil%%f");
    }

    #[test]
    fn zsh_prompt_escape_safe_label() {
        assert_eq!(zsh_prompt_escape("my-key-01"), "my-key-01");
    }

    #[test]
    fn bash_prompt_escape_backslash() {
        assert_eq!(bash_prompt_escape("\\u@\\h"), "\\\\u@\\\\h");
    }

    #[test]
    fn bash_prompt_escape_safe_label() {
        assert_eq!(bash_prompt_escape("my-key-01"), "my-key-01");
    }

    // ── resolve_single_provider ─────────────────────────────────────────────

    #[test]
    fn single_provider_no_override() {
        let providers = vec!["anthropic".to_string()];
        let result = resolve_single_provider("key1", &providers, None);
        assert_eq!(result.unwrap(), "anthropic");
    }

    #[test]
    fn multi_provider_no_override_errors() {
        let providers = vec!["anthropic".to_string(), "openai".to_string()];
        let result = resolve_single_provider("key1", &providers, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("multiple providers"));
    }

    #[test]
    fn multi_provider_with_override() {
        let providers = vec!["anthropic".to_string(), "openai".to_string()];
        let result = resolve_single_provider("key1", &providers, Some("openai"));
        assert_eq!(result.unwrap(), "openai");
    }

    #[test]
    fn provider_override_not_supported() {
        let providers = vec!["anthropic".to_string()];
        let result = resolve_single_provider("key1", &providers, Some("openai"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not support"));
    }
}

