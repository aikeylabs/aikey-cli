use crate::config::{ProjectConfig, ProviderConfig, EnvTemplate, LogicalModelMapping};
use crate::json_output;
use crate::global_config;
use crate::storage;
use secrecy::SecretString;
use zeroize::Zeroizing;
use std::io::{self, Write};


// Connectivity test code moved to `crate::connectivity` in 2026-04-21. The
// `pub use` below preserves callsite paths (`commands_project::TestTarget`
// etc.) while the canonical home is now `crate::connectivity::*`.
pub use crate::connectivity::*;

pub fn handle_project_init(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::path::Path::new("aikey.config.json");

    // Check if config already exists
    if config_path.exists() {
        if json_mode {
            return Err("Config file already exists".into());
        }

        println!("Found existing aikey.config.json");
        print!("Would you like to update it? (y/n): ");
        io::stdout().flush().ok();

        let mut response = String::new();
        io::stdin().read_line(&mut response).ok();

        if !response.trim().eq_ignore_ascii_case("y") {
            return Err("Cancelled".into());
        }
    }

    // Get project name
    let folder_name = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "My Project".to_string());

    let project_name = if json_mode {
        folder_name
    } else {
        print!("Project name [{}]: ", folder_name);
        io::stdout().flush().ok();

        let mut name = String::new();
        io::stdin().read_line(&mut name).ok();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            folder_name
        } else {
            trimmed.to_string()
        }
    };

    // Get language/stack
    let stack = if json_mode {
        "node".to_string()
    } else {
        println!("\nSelect language/stack:");
        println!("  1) Node.js");
        println!("  2) Python");
        println!("  3) Other");
        print!("Choice [1]: ");
        io::stdout().flush().ok();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).ok();
        match choice.trim() {
            "2" => "python".to_string(),
            "3" => "other".to_string(),
            _ => "node".to_string(),
        }
    };

    // Get .env target
    let env_target = if json_mode {
        ".env".to_string()
    } else {
        print!("\n.env file target [.env]: ");
        io::stdout().flush().ok();

        let mut target = String::new();
        io::stdin().read_line(&mut target).ok();
        let trimmed = target.trim();
        if trimmed.is_empty() {
            ".env".to_string()
        } else {
            trimmed.to_string()
        }
    };

    // Get required variables
    let suggested_vars = match stack.as_str() {
        "python" => EnvTemplate::python_vars(),
        "other" => EnvTemplate::other_vars(),
        _ => EnvTemplate::node_vars(),
    };

    let required_vars = if json_mode {
        suggested_vars.iter().map(|s| s.to_string()).collect()
    } else {
        println!("\nSuggested environment variables for {}:", stack);
        for (i, var) in suggested_vars.iter().enumerate() {
            println!("  {}) {}", i + 1, var);
        }
        print!("Use suggested? (y/n) [y]: ");
        io::stdout().flush().ok();

        let mut response = String::new();
        io::stdin().read_line(&mut response).ok();

        if response.trim().eq_ignore_ascii_case("n") {
            println!("Enter variable names (comma-separated):");
            let mut vars_input = String::new();
            io::stdin().read_line(&mut vars_input).ok();
            vars_input
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            suggested_vars.iter().map(|s| s.to_string()).collect()
        }
    };

    // Create and save config
    let mut config = ProjectConfig::new(project_name);
    config.env.target = env_target;
    config.required_vars = required_vars;

    config.save(config_path)?;

    if !json_mode {
        println!("\n✓ Created aikey.config.json");
        println!("\nNext steps:");
        println!("  1. Run 'aikey add <provider>:<alias>' to add provider keys (e.g. aikey add anthropic:default)");
        println!("  2. Run 'aikey env generate' to create/update your .env file (non-sensitive only)");
        println!("  3. Use 'aikey run -- <command>' to run with secrets injected");
        println!("  4. Use 'aikey project status' to check configuration");
    }

    Ok(())
}

/// Handle `aikey project status` command
pub fn handle_project_status(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let discovered = ProjectConfig::discover()?;
    let (config_path, config) = match discovered {
        Some(pair) => pair,
        None => {
            if json_mode {
                json_output::print_json_exit(serde_json::json!({
                    "ok": false,
                    "code": crate::error_codes::ErrorCode::InvalidInput.as_str(),
                    "message": "No aikey.config.json found in current directory or parent directories"
                }), 1);
            }
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No aikey.config.json found in current directory or parent directories")));
        }
    };

    let template_parts: Vec<String> = config.required_vars
        .iter()
        .map(|var| format!("{}={{{}}}", var, var))
        .collect();
    let _template = template_parts.join("\n");

    let _project_path = config_path.parent().and_then(|p| p.to_str());
    let _config_path_str = config_path.to_str();

    // Check which required vars are satisfied by checking vault entries
    let total = config.required_vars.len();
    let mut satisfied = 0;
    let mut missing_vars = Vec::new();

    let stored = storage::list_entries().unwrap_or_default();
    let stored_set: std::collections::HashSet<&str> = stored.iter().map(|s| s.as_str()).collect();
    for var in &config.required_vars {
        if stored_set.contains(var.as_str()) {
            satisfied += 1;
        } else {
            missing_vars.push(var.clone());
        }
    }

    if json_mode {
        let response = serde_json::json!({
            "ok": true,
            "config_path": config_path.display().to_string(),
            "project_name": config.project.name,
            "required_vars": config.required_vars,
            "satisfied": satisfied,
            "total": total,
            "missing_vars": missing_vars
        });
        json_output::print_json(response);
    } else {
        println!("Project Configuration Status");
        println!("============================");
        println!("Config path: {}", config_path.display());
        println!("Project name: {}", config.project.name);
        println!("Required variables: {}/{} satisfied", satisfied, total);

        if satisfied < total {
            println!("\nMissing variables:");
            for var in &missing_vars {
                println!("  - {}", var);
            }
            println!("\nRun 'aikey env generate' to update your .env file");
        } else {
            println!("\n✓ All required variables are satisfied");
        }
    }

    Ok(())
}

/// Handle `aikey quickstart` command.
///
/// Prints a state-aware landing page showing the most useful next steps.
/// Vault initialization is no longer bundled here — `aikey add` / `aikey auth
/// login` / `aikey login` each handle their own prerequisites when run.
pub fn handle_quickstart(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;

    // Gather state. All queries tolerate a missing/unreadable vault by
    // returning empty results — the landing page still works pre-vault.
    let vault_exists = storage::get_vault_path().map(|p| p.exists()).unwrap_or(false);
    let personal_count = if vault_exists {
        storage::list_entries().map(|v| v.len()).unwrap_or(0)
    } else { 0 };
    let team_active = storage::list_virtual_key_cache()
        .map(|v| v.into_iter().filter(|k| k.key_status == "active").count())
        .unwrap_or(0);
    let oauth_active = storage::list_provider_accounts()
        .map(|v| v.into_iter().filter(|a| a.status == "active").count())
        .unwrap_or(0);
    let logged_in = storage::get_platform_account().ok().flatten().is_some();
    let proxy_running = crate::commands_proxy::is_proxy_running();

    // User-facing categorization:
    //   key       = personal + team (raw API keys stored in the vault)
    //   account   = OAuth provider accounts
    //   login     = team Control Panel session
    let total_keys = personal_count + team_active;
    let total_credentials = total_keys + oauth_active;

    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": true,
            "state": {
                "personal_keys": personal_count,
                "team_keys_active": team_active,
                "oauth_accounts_active": oauth_active,
                "logged_in": logged_in,
                "proxy_running": proxy_running,
            }
        }));
        return Ok(());
    }

    // Helper: print a command + inline description with consistent spacing.
    let tip = |cmd: &str, desc: &str| {
        println!("     {}  {}",
            format!("{:<50}", cmd).cyan(),
            format!("# {}", desc).dimmed());
    };

    // --- Banner --------------------------------------------------------
    println!();
    println!("  \u{1F680} {}", "AiKey Quickstart".bold());
    println!("  {}", "Next steps tailored to your current state.".dimmed());
    println!("  {}", "\u{2500}".repeat(68).dimmed());
    println!();

    // --- Section 1: no raw key yet → add one -------------------------
    if total_keys == 0 {
        println!("  {}", "\u{1F511} Add your first API key".bold());
        tip("aikey add my-key --provider openai", "or anthropic | kimi");
        println!();
    }

    // --- Section 2: has key → activate + review ----------------------
    if total_keys > 0 {
        let summary = format!("You have {} key{}",
            total_keys, if total_keys == 1 { "" } else { "s" });
        println!("  {} {}", "\u{2713}".green().bold(), summary.bold());
        tip("aikey use", "pick which key to activate for routing");
        tip("aikey list", "review every credential");
        println!();
    }

    // --- Section 3: no OAuth account → offer to add one ------------
    if oauth_active == 0 {
        println!("  {}", "\u{29BF} Add a subscription account".bold());
        tip("aikey auth login claude", "or codex | kimi");
        println!();
    }

    // --- Section 4: not logged into a team → offer team login ------
    if !logged_in {
        println!("  {}", "\u{1F465} Join your team".bold());
        tip("aikey login --control-url https://your.team.host", "team-managed keys auto-sync");
        println!();
    }

    // --- Section 5: two or more credentials → show route picker ----
    if total_credentials >= 2 {
        println!("  {}", "\u{1F517} Multiple routes available".bold());
        tip("aikey route", "pick a base_url + api_key for your IDE or CLI");
        println!();
    }

    // --- Section 6: logged in → web console shortcut --------------
    if logged_in {
        println!("  {}", "\u{1F310} Manage via the User Console".bold());
        tip("aikey web", "open the web console in your browser");
        println!();
    }

    // --- Section 7: proxy not running → nudge to start ------------
    if !proxy_running {
        println!("  {}", "\u{26A0}  Proxy is not running".yellow().bold());
        tip("aikey proxy start", "required for routing to work");
        println!();
    }

    // --- Footer --------------------------------------------------
    println!("  {}", "\u{2500}".repeat(68).dimmed());
    tip("aikey doctor", "check system health");
    tip("aikey --help", "all commands");
    println!();

    Ok(())
}


/// Handle `aikey project map` — bind a required var to a vault alias, and optionally
/// add an envMappings entry when --env, --provider, and --key-alias are provided.
pub fn handle_project_map(
    var: &str,
    alias: &str,
    env: Option<&str>,
    provider: Option<&str>,
    model: Option<&str>,
    key_alias: Option<&str>,
    impl_id: Option<&str>,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Verify master password before mutating config
    let prompt_str = if json_mode { "" } else { "\u{1F512} Enter Master Password: " };
    let password = crate::prompt_hidden(prompt_str)?;
    let password_raw = Zeroizing::new(password);
    let secret = SecretString::new(password_raw.trim().to_string());

    // Verify the password is correct by attempting to list secrets
    crate::executor::list_secrets(&secret)
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)) as Box<dyn std::error::Error>)?;

    let (config_path, mut config) = ProjectConfig::discover()?
        .ok_or("No aikey.config.json found")?;

    // Always update bindings / required_vars
    config.bindings.insert(var.to_string(), alias.to_string());
    if !config.required_vars.contains(&var.to_string()) {
        config.required_vars.push(var.to_string());
    }

    // Optionally write an envMappings entry
    if let (Some(env_name), Some(prov), Some(ka)) = (env, provider, key_alias) {
        let logical_name = var.to_string();
        let entry = LogicalModelMapping {
            provider: prov.to_string(),
            provider_model_id: model.map(|m| m.to_string()),
            key_alias: ka.to_string(),
            impl_id: impl_id.map(|i| i.to_string()),
        };
        config
            .env_mappings
            .entry(env_name.to_string())
            .or_default()
            .insert(logical_name, entry);
    }

    config.save(&config_path)?;

    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": true,
            "var": var,
            "alias": alias
        }));
    } else {
        println!("Mapped {} → {}", var, alias);
    }

    Ok(())
}

/// Handle `aikey provider add` — add/update a provider entry in the project config
pub fn handle_provider_add(
    name: &str,
    key_alias: &str,
    default_model: Option<&str>,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, mut config) = ProjectConfig::discover()?
        .ok_or("No aikey.config.json found")?;

    config.providers.insert(name.to_string(), ProviderConfig {
        key_alias: key_alias.to_string(),
        default_model: default_model.map(|s| s.to_string()),
    });

    config.save(&config_path)?;

    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": true,
            "provider": name,
            "key_alias": key_alias,
            "default_model": default_model
        }));
    } else {
        println!("Provider '{}' added (alias: {})", name, key_alias);
    }

    Ok(())
}

/// Handle `aikey provider rm` — remove a provider from the profile config
pub fn handle_provider_rm(
    name: &str,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, mut config) = ProjectConfig::discover()?
        .ok_or("No aikey.config.json found")?;

    if !json_mode {
        let key_alias = config.providers.get(name)
            .map(|p| p.key_alias.as_str())
            .unwrap_or(name);
        let profile = global_config::get_current_profile()
            .ok()
            .flatten()
            .unwrap_or_else(|| "default".to_string());
        print!("Remove {}:{} from profile '{}' config? (y/N) ", name, key_alias, profile);
        io::stdout().flush().ok();
        let mut response = String::new();
        io::stdin().read_line(&mut response).ok();
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    if config.providers.remove(name).is_none() {
        let msg = format!("Provider '{}' not found in config", name);
        if json_mode {
            json_output::print_json_exit(serde_json::json!({
                "ok": false,
                "message": msg
            }), 1);
        }
        return Err(msg.into());
    }

    config.save(&config_path)?;

    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": true,
            "provider": name
        }));
    } else {
        println!("Provider '{}' removed", name);
    }

    Ok(())
}

/// Handle `aikey provider ls` — list providers in the project config
pub fn handle_provider_ls(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (_, config) = ProjectConfig::discover()?
        .ok_or("No aikey.config.json found")?;

    if json_mode {
        let providers: Vec<_> = config.providers.iter().map(|(name, cfg)| {
            serde_json::json!({
                "name": name,
                "key_alias": cfg.key_alias,
                "default_model": cfg.default_model
            })
        }).collect();
        json_output::print_json(serde_json::json!({ "ok": true, "providers": providers }));
    } else if config.providers.is_empty() {
        println!("No providers configured.");
    } else {
        println!("Providers:");
        let mut names: Vec<_> = config.providers.keys().collect();
        names.sort();
        for name in names {
            let cfg = &config.providers[name];
            if let Some(model) = &cfg.default_model {
                println!("  {} (alias: {}, model: {})", name, cfg.key_alias, model);
            } else {
                println!("  {} (alias: {})", name, cfg.key_alias);
            }
        }
    }

    Ok(())
}

/// Handle `aikey doctor` — connectivity and health diagnostics.
///
/// No master password required. Checks run sequentially and stream output
/// as each result arrives so the user sees progress immediately.
pub fn handle_doctor(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    use colored::Colorize;
    use std::time::Instant;

    // Accumulates results for --json mode.
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut any_failed = false;
    // Deferred suite — run after the emit closure is dropped (borrow conflict).
    // (targets, build_errors) — targets flow into run_connectivity_suite;
    // build_errors drive the "cannot test" block beneath the table.
    let mut deferred_suite: Option<(Vec<TestTarget>, Vec<BuildTargetError>)> = None;

    // Helper: print one check row, collect for JSON.
    // label is left-padded to 18 chars; detail is the right-hand info string.
    let mut emit = |label: &str, ok: bool, detail: &str, hint: Option<&str>| {
        // Sub-detail rows (label starts with whitespace) belong to the most
        // recent top-level check. Render them as a dim tree branch so the
        // failure is called out once by its parent instead of stacking ✗ icons.
        let is_sub = label.starts_with(' ');
        if !json_mode {
            if is_sub {
                let trimmed = label.trim_start();
                println!("    {} {}",
                    format!("↳ {:<16}", trimmed).dimmed(),
                    detail.dimmed());
                if let Some(h) = hint {
                    println!("      {}", format!("· {}", h).dimmed());
                }
            } else {
                let icon = if ok { "✓".green() } else { "✗".red() };
                println!("{} {:<18} {}", icon, label, detail);
                if let Some(h) = hint {
                    println!("  {}", format!("↳ {}", h).dimmed());
                }
            }
        }
        results.push(serde_json::json!({
            "check": label,
            "ok": ok,
            "detail": detail,
            "hint": hint,
        }));
        // Only top-level failures bubble up to overall status; sub-rows are
        // already captured via their parent.
        if !ok && !is_sub { any_failed = true; }
    };

    if !json_mode {
        println!("{}", "─".repeat(52).dimmed());
    }

    // ── 0. Version info ─────────────────────────────────────
    {
        let cli_rev = env!("AIKEY_BUILD_REVISION");
        let cli_bid = env!("AIKEY_BUILD_ID");
        let cli_ver = env!("CARGO_PKG_VERSION");
        let cli_str = if cli_bid == "unknown" {
            format!("{}+{}", cli_ver, cli_rev)
        } else {
            format!("{}+{}.{}", cli_ver, cli_rev, cli_bid)
        };
        emit("cli version", true, &cli_str, None);

        // Probe proxy /version
        let proxy_port = crate::commands_proxy::proxy_port();
        let proxy_url = format!("http://127.0.0.1:{}/version", proxy_port);
        match ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .get(&proxy_url).call()
        {
            Ok(resp) => {
                if let Ok(body) = resp.into_string() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                        let ver = v.get("version").and_then(|x| x.as_str()).unwrap_or("?");
                        let rev = v.get("revision").and_then(|x| x.as_str()).unwrap_or("?");
                        let bid = v.get("build_id").and_then(|x| x.as_str()).unwrap_or("?");
                        let proxy_str = if bid == "unknown" {
                            format!("{}+{}", ver, rev)
                        } else {
                            format!("{}+{}.{}", ver, rev, bid)
                        };
                        let matched = cli_bid != "unknown" && bid != "unknown" && cli_bid == bid;
                        let mismatch_hint = if cli_bid != "unknown" && bid != "unknown" && cli_bid != bid {
                            Some("BuildID mismatch — CLI and proxy from different builds. Run: make restart")
                        } else { None };
                        emit("proxy version", true, &proxy_str, mismatch_hint);
                        if matched {
                            emit("build match", true, &format!("BuildID={}", bid), None);
                        }
                    }
                }
            }
            Err(_) => {
                emit("proxy version", false, "proxy not reachable", Some("proxy /version check will retry after proxy starts"));
            }
        }

        // Probe backend services (docker or native).
        // control/collector/query = server-mode docker services.
        // trial-server = local-server or full-trial on :8090.
        for (name, port) in &[
            ("control", 8080u16), ("collector", 27300), ("query", 27310),
            ("trial-server", 8090),
        ] {
            let url = format!("http://127.0.0.1:{}/version", port);
            match ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_millis(500))
                .build()
                .get(&url).call()
            {
                Ok(resp) => {
                    if let Ok(body) = resp.into_string() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                            let ver = v.get("version").and_then(|x| x.as_str()).unwrap_or("?");
                            let rev = v.get("revision").and_then(|x| x.as_str()).unwrap_or("?");
                            let bid = v.get("build_id").and_then(|x| x.as_str()).unwrap_or("?");
                            let svc_str = if bid == "unknown" {
                                format!("{}+{}", ver, rev)
                            } else {
                                format!("{}+{}.{}", ver, rev, bid)
                            };
                            emit(&format!("{} version", name), true, &svc_str, None);
                        }
                    }
                }
                Err(_) => {} // Silently skip — docker services are optional
            }
        }

        if !json_mode {
            println!("{}", "─".repeat(52).dimmed());
        }
    }

    // ── 1. Internet connectivity ─────────────────────────────
    // Why HTTP GET instead of TCP ping: users behind an HTTP proxy (e.g.
    // upstream_proxy in proxy config) can reach the internet via HTTP but
    // direct TCP to 1.1.1.1:443 is blocked, causing a false "unreachable".
    {
        let start = Instant::now();
        let ok = crate::connectivity::runtime::build_proxy_aware_agent(std::time::Duration::from_secs(5))
            .head("https://www.gstatic.com/generate_204")
            .call()
            .is_ok();
        let ms = start.elapsed().as_millis();
        emit("internet",
            ok,
            &if ok { format!("reachable  ({} ms)", ms) } else { "unreachable".to_string() },
            if ok { None } else { Some("check network connection or VPN") });
    }

    // ── 2. Vault ─────────────────────────────────────────────
    {
        let vault_path = storage::get_vault_path().ok();
        let exists = vault_path.as_ref().map(|p| p.exists()).unwrap_or(false);
        let detail = match &vault_path {
            Some(p) if exists => format!("found  ({})", p.display()),
            Some(p) => format!("not found  ({})", p.display()),
            None => "cannot resolve path".to_string(),
        };
        emit("vault", exists, &detail,
            if exists { None } else { Some("run 'aikey init' to create your vault") });
    }

    // ── 3. Session cache ─────────────────────────────────────
    {
        let cached = crate::session::try_get().is_some();
        emit("session",
            true,  // not a failure either way — just informational
            if cached { "password cached" } else { "no cache  (will prompt on next command)" },
            None);
    }

    // ── 4. Proxy process + reachability ──────────────────────
    let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
    let (mut proxy_up, proxy_pid) = crate::commands_proxy::doctor_proxy_status();
    {
        let detail = match (proxy_up, proxy_pid) {
            (true, Some(pid)) => {
                // Measure latency against /health.
                let start = Instant::now();
                let url = format!("http://{}/health", proxy_addr);
                let ok = ureq::get(&url).call().is_ok();
                let ms = start.elapsed().as_millis();
                if ok { format!("running  (pid {}, {} ms)", pid, ms) }
                else   { format!("pid {} alive but /health unreachable", pid) }
            }
            (false, Some(pid)) => format!("pid {} alive but port not open", pid),
            _ => "not running".to_string(),
        };

        if proxy_up {
            emit("proxy", true, &detail, None);
        } else {
            emit("proxy", false, &detail, Some("attempting restart..."));
            // Auto-restart: try env var first, then prompt for password.
            if !json_mode {
                crate::commands_proxy::ensure_proxy_for_use(false);
                // Re-check after restart attempt.
                let (up, _) = crate::commands_proxy::doctor_proxy_status();
                if up {
                    proxy_up = true;
                    emit("proxy restart", true, "proxy restarted successfully", None);
                } else {
                    emit("proxy restart", false, "restart failed",
                        Some("run 'aikey proxy start' manually to debug"));
                }
            }
        }
    }

    // ── 5. Provider + proxy connectivity ────────────────────
    // Build targets via the unified helper so Personal / Team / OAuth go
    // through the same code path as `aikey test` and `aikey add`. Deferred
    // execution happens below the emit closure to avoid the &mut results
    // borrow conflict that predates this refactor.
    if proxy_up {
        let bindings = storage::list_provider_bindings(
            crate::profile_activation::DEFAULT_PROFILE,
        ).unwrap_or_default();

        if bindings.is_empty() {
            if !json_mode {
                println!("  {} {:<18} {}",
                    "·".dimmed(), "providers",
                    "no provider bindings — run 'aikey add' first".dimmed());
            }
        } else {
            // Try session cache first; if expired and there are bindings
            // that need decryption (PersonalApi), prompt for Master Password.
            let has_personal = bindings.iter().any(|b|
                b.key_source_type == crate::credential_type::CredentialType::PersonalApiKey);
            let pw = crate::session::try_get().or_else(|| {
                use std::io::IsTerminal;
                if has_personal && !json_mode && std::io::stdin().is_terminal() {
                    crate::prompt_hidden("  \u{25c6} Enter Master Password to test API keys: ")
                        .ok()
                        .map(|p| secrecy::SecretString::new(p))
                } else {
                    None
                }
            });
            let proxy_port = crate::commands_proxy::proxy_port();
            let (targets, build_errors) = targets_from_active_bindings(pw.as_ref(), proxy_port);

            if targets.is_empty() && build_errors.is_empty() {
                if !json_mode {
                    println!("  {} {:<18} {}",
                        "\u{b7}".dimmed(), "providers",
                        "no provider bindings configured".dimmed());
                }
            } else {
                // Deferred: run after emit closure is dropped (borrow conflict).
                deferred_suite = Some((targets, build_errors));
            }
        }
    }

    // ── 7. Shell hook installed ───────────────────────────────
    {
        let home = std::env::var("HOME").unwrap_or_default();
        let shell = std::env::var("SHELL").unwrap_or_default();
        let hook_marker = "# aikey shell hook";

        let rc_file = if shell.contains("zsh") {
            Some(format!("{}/.zshrc", home))
        } else if shell.contains("bash") {
            // Check .bashrc first, then .bash_profile.
            let bashrc = format!("{}/.bashrc", home);
            let profile = format!("{}/.bash_profile", home);
            if std::path::Path::new(&bashrc).exists() { Some(bashrc) }
            else { Some(profile) }
        } else {
            None
        };

        let installed = rc_file.as_ref().map_or(false, |rc| {
            std::fs::read_to_string(rc)
                .map(|c| c.contains(hook_marker))
                .unwrap_or(false)
        });

        if installed {
            emit("shell hook", true, "installed", None);
        } else if rc_file.is_some() {
            emit("shell hook", false, "not installed",
                Some("installing shell hook..."));
            // Trigger installation (prompts user in TTY mode).
            if !json_mode {
                let _ = crate::commands_account::ensure_shell_hook(false);
            }
        } else {
            emit("shell hook", false, "unsupported shell",
                Some("add 'source ~/.aikey/active.env' to your shell config manually"));
        }
    }

    // ── 8. SQLite WAL size ──────────────────────────────────
    {
        if let Ok(vault_path) = storage::get_vault_path() {
            let wal_path = vault_path.with_extension("db-wal");
            if wal_path.exists() {
                let wal_size = std::fs::metadata(&wal_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                let wal_mb = wal_size / (1024 * 1024);
                if wal_mb >= 1000 {
                    emit("vault WAL", false,
                        &format!("{}MB — needs checkpoint", wal_mb),
                        Some("run: sqlite3 ~/.aikey/data/vault.db 'PRAGMA wal_checkpoint(TRUNCATE);'"));
                } else {
                    emit("vault WAL", true,
                        &format!("{}MB", wal_mb), None);
                }
            }
        }
    }

    // ── 9. Control service ───────────────────────────────────
    if let Ok(Some(account)) = storage::get_platform_account() {
        let url = format!("{}/health", account.control_url.trim_end_matches('/'));
        let start = Instant::now();
        let ok = ureq::get(&url).call().is_ok();
        let ms = start.elapsed().as_millis();
        let detail = if ok {
            format!("reachable  ({}, {} ms)", account.control_url, ms)
        } else {
            format!("unreachable  ({})", account.control_url)
        };
        emit("control service", ok, &detail,
            if ok { None } else { Some("check network or try 'aikey login' again") });
    }

    // ── 10. Usage pipeline health ─────────────────────────────
    // ── 10. Usage pipeline health ─────────────────────────────
    // Two data sources:
    //   a) Proxy /metrics — reporter delivery state (generated/uploaded/failed/dropped)
    //   b) Control /v1/diagnostics/pipeline — full-chain watermarks + canary health
    //
    // Why both: proxy /metrics shows the "sender side" (is reporter working?),
    // diagnostics shows the "receiver side" (did data arrive and get projected?).
    if !json_mode {
        println!("{}", "─".repeat(52).dimmed());
    }
    {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(3))
            .build();

        // a) Proxy reporter metrics
        let proxy_metrics = if proxy_up {
            let url = format!("http://{}/metrics", proxy_addr);
            agent.get(&url).call().ok()
                .and_then(|r| r.into_string().ok())
        } else { None };

        // b) Diagnostics — served by collector-service. In trial, control and
        //    collector live on the same port so {control_url}/v1/diagnostics/
        //    pipeline works directly. In production, diagnostics are on the
        //    collector container which is reachable via an endpoint advertised
        //    by {control_url}/system/status under endpoints.collector.
        //    Discovery order: system/status → collector → fallback to control.
        let diag_json = storage::get_platform_account().ok().flatten()
            .and_then(|acct| {
                let control_base = acct.control_url.trim_end_matches('/').to_string();

                // Probe /system/status for a collector endpoint (production path).
                let collector_base: String = agent
                    .get(&format!("{}/system/status", control_base))
                    .call().ok()
                    .and_then(|r| r.into_string().ok())
                    .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
                    .and_then(|v| v.get("endpoints")
                        .and_then(|e| e.get("collector"))
                        .and_then(|c| c.get("url"))
                        .and_then(|u| u.as_str())
                        .map(|s| s.trim_end_matches('/').to_string()))
                    .unwrap_or_else(|| control_base.clone());

                let url = format!("{}/v1/diagnostics/pipeline", collector_base);
                let resp = agent.get(&url).call().ok()
                    .and_then(|r| r.into_string().ok());
                // Fallback: some older deployments serve diagnostics under
                // control_url. If collector probe failed, try control as a
                // last resort before giving up.
                if resp.is_some() || collector_base == control_base {
                    resp
                } else {
                    let fallback = format!("{}/v1/diagnostics/pipeline", control_base);
                    agent.get(&fallback).call().ok()
                        .and_then(|r| r.into_string().ok())
                }
            });

        check_usage_pipeline(
            proxy_metrics.as_deref(),
            diag_json.as_deref(),
            &mut emit,
        );
    }

    // Drop emit to release &mut results, then run the deferred suite.
    drop(emit);

    if let Some((targets, build_errors)) = deferred_suite {
        let outcome = run_connectivity_suite(
            targets,
            SuiteOptions {
                show_proxy_row: true,
                header_label: Some("Connectivity Test"),
                password: None,   // PersonalApi plaintext is already baked into each target
                proxy_port: crate::commands_proxy::proxy_port(),
            },
            json_mode,
        );
        if json_mode {
            results.extend(outcome.json_results);
        } else {
            render_cannot_test_block(&build_errors, json_mode);
        }
    }

    if !json_mode {
        println!("{}", "─".repeat(52).dimmed());
        if any_failed {
            println!("{}", "Some checks failed — see hints above.".yellow());
        } else {
            println!("{}", "All checks passed.".green());
        }
    } else {
        json_output::print_json(serde_json::json!({
            "ok": !any_failed,
            "checks": results,
        }));
    }

    Ok(())
}


// ---------------------------------------------------------------------------
// Usage pipeline health check for `aikey doctor`
// ---------------------------------------------------------------------------

/// Parses proxy /metrics and control /v1/diagnostics/pipeline to emit a
/// comprehensive usage-pipeline section in `aikey doctor`.
///
/// Two data sources:
///   - proxy_metrics: reporter delivery state (sender side)
///   - diag_json: full-chain watermarks + canary-driven health (receiver side)
fn check_usage_pipeline(
    proxy_metrics: Option<&str>,
    diag_json: Option<&str>,
    emit: &mut dyn FnMut(&str, bool, &str, Option<&str>),
) {
    let metrics: Option<serde_json::Value> = proxy_metrics
        .and_then(|s| serde_json::from_str(s).ok());
    let diag: Option<serde_json::Value> = diag_json
        .and_then(|s| serde_json::from_str(s).ok());

    // --- Header: use diagnostics health if available, fall back to reporter state ---
    let diag_health = diag.as_ref()
        .and_then(|d| d.get("watermark_health").and_then(|v| v.as_str()));
    let diag_stale = diag.as_ref()
        .and_then(|d| d.get("stale_stage").and_then(|v| v.as_str()));

    let reporter = metrics.as_ref()
        .and_then(|m| m.get("reporter"));

    // If neither source is available
    if reporter.is_none() && diag.is_none() {
        emit("usage-pipeline", true, "reporter not enabled (standalone mode)", None);
        return;
    }

    // Determine overall health: worst-of-both from diagnostics watermarks AND
    // proxy canary probe result. Why not trust diagnostics health alone: diagnostics
    // only sees watermark freshness (DWD has recent canary → healthy), but misses
    // canary probe failures at the query stage. Doctor has both data sources and
    // must combine them to avoid "healthy overall but canary probe failed" contradiction.
    let canary_status = metrics.as_ref()
        .and_then(|m| m.get("canary"))
        .and_then(|c| c.get("status").and_then(|v| v.as_str()))
        .unwrap_or("");
    let canary_stage = metrics.as_ref()
        .and_then(|m| m.get("canary"))
        .and_then(|c| c.get("failed_stage").and_then(|v| v.as_str()))
        .unwrap_or("");
    // "unavailable" = diagnostics endpoint missing (server-mode), not a pipeline fault.
    // Only "failed" or "partial" should degrade the overall health.
    let canary_is_failure = canary_status == "failed" || canary_status == "partial";

    let (pipeline_ok, health_label) = if canary_is_failure && !canary_stage.is_empty() {
        // Canary probe failure overrides watermark health
        (false, format!("degraded — canary failed at {}", canary_stage))
    } else {
        match diag_health {
            Some("healthy") => (true, "healthy".to_string()),
            Some("degraded") => {
                let label = if let Some(stage) = diag_stale {
                    format!("degraded — stale at {}", stage)
                } else {
                    "degraded".to_string()
                };
                (false, label)
            }
            _ => {
                // Fall back to reporter consecutive failures
                let consecutive = reporter.and_then(|r| r.get("consecutive_failures"))
                    .and_then(|v| v.as_i64()).unwrap_or(0);
                if consecutive >= 5 { (false, "degraded".to_string()) }
                else { (true, "healthy".to_string()) }
            }
        }
    };

    // Override label to "idle" if reporter exists but no events have flowed yet.
    // Avoids showing "healthy" when nothing has been verified.
    let reporter_idle = reporter
        .and_then(|r| r.get("usage_events_generated_total").and_then(|v| v.as_i64()))
        .map(|g| g == 0)
        .unwrap_or(false);
    let (pipeline_ok, health_label) = if pipeline_ok && reporter_idle {
        (true, "idle (awaiting first event)".to_string())
    } else {
        (pipeline_ok, health_label)
    };

    let hint = if !pipeline_ok {
        Some("run: curl http://127.0.0.1:8090/v1/diagnostics/pipeline")
    } else { None };
    emit("usage-pipeline", pipeline_ok, &health_label, hint);

    // --- Reporter stats (from proxy /metrics) ---
    if let Some(r) = reporter {
        let generated = r.get("usage_events_generated_total").and_then(|v| v.as_i64()).unwrap_or(0);
        let uploaded = r.get("usage_events_upload_success_total").and_then(|v| v.as_i64()).unwrap_or(0);
        let failed = r.get("usage_events_upload_failed_total").and_then(|v| v.as_i64()).unwrap_or(0);
        let dropped = r.get("usage_events_dropped_total").and_then(|v| v.as_i64()).unwrap_or(0);
        let consecutive = r.get("consecutive_failures").and_then(|v| v.as_i64()).unwrap_or(0);
        let terminal = r.get("terminal_fail_count").and_then(|v| v.as_i64()).unwrap_or(0);
        let last_status = r.get("last_upload_status").and_then(|v| v.as_str()).unwrap_or("");
        let last_upload = r.get("last_upload_at").and_then(|v| v.as_str()).unwrap_or("");
        let last_error_code = r.get("last_error_code").and_then(|v| v.as_i64()).unwrap_or(0);
        let queue_depth = r.get("usage_queue_depth").and_then(|v| v.as_i64()).unwrap_or(0);
        let wal_fail = r.get("usage_wal_append_failed_total").and_then(|v| v.as_i64()).unwrap_or(0);

        let upload_time = format_time_short(last_upload);
        let status_display = if last_status.is_empty() { "idle" } else { last_status };

        // Reporter is ok if currently healthy (consecutive < 5 and last status not terminal).
        // Historical failures with last_status=ok means it recovered — show ✓ with hint.
        let reporter_ok = consecutive < 5 && last_status != "terminal_failed";
        let reporter_hint = if terminal > 0 && last_status == "ok" {
            Some("recovered, but has terminal failures in dead_letter.jsonl")
        } else if terminal > 0 {
            Some("terminal failures — check collector_token")
        } else if failed > 0 {
            Some("retryable failures detected")
        } else { None };
        emit("  reporter", reporter_ok,
            &format!("{} generated, {} uploaded, {} failed, {} dropped",
                generated, uploaded, failed, dropped),
            reporter_hint);
        let upload_hint = if consecutive > 0 {
            Some(format!("{} consecutive failures, last HTTP {}", consecutive, last_error_code))
        } else { None };
        emit("  last upload", reporter_ok,
            &format!("{} ({})", upload_time, status_display),
            upload_hint.as_deref());

        if queue_depth > 0 || wal_fail > 0 {
            let mut parts = Vec::new();
            if queue_depth > 0 { parts.push(format!("{} queued", queue_depth)); }
            if wal_fail > 0 { parts.push(format!("{} WAL write failures", wal_fail)); }
            emit("  queue/WAL", wal_fail == 0, &parts.join(", "), None);
        }

        if terminal > 0 {
            emit("  dead letters", false,
                &format!("{} events", terminal),
                Some("review ~/.aikey/data/usage-wal/dead_letter.jsonl"));
        }
    }

    // --- Watermarks (from diagnostics) ---
    if let Some(ref d) = diag {
        let biz = d.get("business_watermarks");
        let canary_wm = d.get("canary_watermarks");

        let biz_ods = biz.and_then(|w| w.get("ods_latest_ingested_at")).and_then(|v| v.as_str()).unwrap_or("");
        let biz_dwd = biz.and_then(|w| w.get("dwd_latest_projected_at")).and_then(|v| v.as_str()).unwrap_or("");
        let can_ods = canary_wm.and_then(|w| w.get("ods_latest_ingested_at")).and_then(|v| v.as_str()).unwrap_or("");
        let can_dwd = canary_wm.and_then(|w| w.get("dwd_latest_projected_at")).and_then(|v| v.as_str()).unwrap_or("");

        let biz_ods_t = format_time_short(biz_ods);
        let biz_dwd_t = format_time_short(biz_dwd);
        let can_dwd_t = format_time_short(can_dwd);

        // Show watermarks if there's any data.
        // Why "(UTC)": watermarks come from SQLite datetime('now') which is UTC,
        // while proxy reporter timestamps are local time. Label prevents confusion.
        if biz_ods_t != "never" || biz_dwd_t != "never" {
            emit("  watermarks", true,
                &format!("ODS: {}, DWD: {} (UTC)", biz_ods_t, biz_dwd_t),
                None);
        }

        // Show canary watermark
        if can_dwd_t != "never" {
            emit("  canary last seen", true,
                &format!("ODS: {}, DWD: {} (UTC)", format_time_short(can_ods), can_dwd_t),
                None);
        }

        // Show lag if present
        if let Some(lag) = d.get("lag").and_then(|l| l.get("ods_to_dwd_seconds")).and_then(|v| v.as_i64()) {
            if lag > 60 {
                emit("  lag", false,
                    &format!("ODS→DWD: {}s", lag),
                    Some("projector may be stalled"));
            }
        }
    }

    // --- Canary probe result (from proxy /metrics) ---
    let canary = metrics.as_ref().and_then(|m| m.get("canary"));

    if let Some(c) = canary {
        let status = c.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
        let round_trip = c.get("round_trip_ms").and_then(|v| v.as_i64()).unwrap_or(0);
        let failed_stage = c.get("failed_stage").and_then(|v| v.as_str()).unwrap_or("");
        let ods = c.get("ods_received").and_then(|v| v.as_bool()).unwrap_or(false);
        let dwd = c.get("dwd_projected").and_then(|v| v.as_bool()).unwrap_or(false);

        let ok = status == "ok";
        // Canary checks ODS and DWD only (no query-stage check yet — P2/P3).
        let stages = format!("ODS {} DWD {}",
            if ods { "✓" } else { "✗" },
            if dwd { "✓" } else { "✗" });

        let detail = if status == "unavailable" {
            format!("diagnostics endpoint not available  ({})", failed_stage)
        } else if ok {
            format!("ok ({:.1}s)  {}", round_trip as f64 / 1000.0, stages)
        } else {
            format!("{} — stuck at: {}  {}", status, failed_stage, stages)
        };

        let hint = if status == "unavailable" {
            Some("diagnostics not registered on this server — canary limited to reporter metrics")
        } else if !ok && !failed_stage.is_empty() {
            Some(match failed_stage {
                "ingest" => "events not reaching ODS — check reporter + collector",
                "projection" => "ODS ok but DWD stalled — check projector worker",
                _ => "run: curl http://127.0.0.1:8090/v1/diagnostics/pipeline",
            })
        } else { None };

        emit("  canary probe", ok, &detail, hint);
    }
}

/// Extract a short time display from an RFC3339-ish timestamp.
/// "2026-04-16T16:43:07Z" → "16:43:07"
/// Zero time or empty → "never"
fn format_time_short(ts: &str) -> String {
    if ts.is_empty() || ts.starts_with("0001-") {
        return "never".to_string();
    }
    if let Some(t_part) = ts.split('T').nth(1) {
        let clean = t_part.trim_end_matches('Z');
        // Truncate to HH:MM:SS — drop sub-seconds, timezone offset
        let base = clean.split('+').next().unwrap_or(clean);
        let base = if let Some(p) = base.rfind('-') {
            if p > 0 { &base[..p] } else { base }
        } else { base };
        // Drop fractional seconds (everything after first '.')
        if let Some(dot) = base.find('.') {
            base[..dot].to_string()
        } else {
            base.to_string()
        }
    } else {
        ts.to_string()
    }
}

// ---------------------------------------------------------------------------
// Connectivity-suite unit tests (2026-04-21)
//
// Scope: exercise the pure parts of the target builders + the display-layer
// helpers. Network-bound probes (test_provider_connectivity, tcp_ping) are
// not tested here — they require a running proxy / upstream and belong in
// tests/e2e_*.
// ---------------------------------------------------------------------------

