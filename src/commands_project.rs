use crate::config::{ProjectConfig, ProviderConfig, EnvTemplate, LogicalModelMapping};
use crate::json_output;
use crate::global_config;
use crate::{crypto, storage, audit};
use secrecy::SecretString;
use zeroize::Zeroizing;
use std::io::{self, Write};

/// Handle `aikey project init` command
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

/// Handle `aikey quickstart` command
pub fn handle_quickstart(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Step 0: initialize vault if it doesn't exist yet
    let vault_path = storage::get_vault_path()?;
    if !vault_path.exists() {
        if json_mode {
            json_output::print_json(serde_json::json!({
                "step": "vault_init",
                "message": "Vault not found. Initializing vault first."
            }));
        } else {
            println!("No vault found. Let's create one first.");
            println!("You'll set a master password to protect your API Keys.\n");
        }

        let password = if let Ok(test_pw) = std::env::var("AK_TEST_PASSWORD") {
            // CI / sandbox mode: bypass interactive prompt via env var.
            // AK_TEST_PASSWORD is only set in test environments; production never sets it.
            SecretString::new(test_pw)
        } else if json_mode {
            // JSON / scripted mode: read password from stdin (suitable for piped CI).
            let mut pw = String::new();
            io::stdin().read_line(&mut pw)?;
            SecretString::new(pw.trim().to_string().into())
        } else {
            let pw = crate::prompt_hidden("\u{1F512} Set Master Password: ")
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            SecretString::new(pw.into())
        };
        let mut salt = [0u8; 16];
        crypto::generate_salt(&mut salt)?;
        storage::initialize_vault(&salt, &password)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        audit::initialize_audit_log()?;
        let _ = audit::log_audit_event(&password, audit::AuditOperation::Init, None, true);

        if !json_mode {
            println!("Vault initialized.\n");
        }
    }

    let config_path = std::path::Path::new("aikey.config.json");

    // Check if config already exists
    if config_path.exists() {
        if json_mode {
            let response = serde_json::json!({
                "ok": true,
                "message": "AiKey project config detected",
                "config_exists": true
            });
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
        } else {
            println!("✓ AiKey project config detected");
            println!("\nYour project is already configured!");
            println!("\nNext steps:");
            println!("  • Run 'aikey project status' to check your configuration");
            println!("  • Run 'aikey env generate' to create/update your .env file (non-sensitive only)");
            println!("  • Use 'aikey run -- <command>' to run with secrets injected");
        }
        return Ok(());
    }

    // No config exists, guide through project init
    if !json_mode {
        println!("Welcome to AiKey!");
        println!("================");
        println!("\nThis wizard will help you set up AiKey for your project.");
        println!("You'll configure which environment variables your project needs,");
        println!("and AiKey will help you manage them securely.\n");
    }

    // Reuse project init logic
    handle_project_init(json_mode)?;

    // Print additional quickstart guidance
    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": true,
            "message": "AiKey project initialized",
            "config_exists": false,
            "config_path": config_path.display().to_string()
        }));
    } else {
        println!("\nSetup complete!");
        println!("\nWhat's next?");
        println!("\n1. Add keys to your local vault:");
        println!("   $ aikey add <provider>:<alias>");
        println!("\n2. Generate your .env file (non-sensitive only):");
        println!("   $ aikey env generate");
        println!("\n3. Run your app with secrets injected:");
        println!("   $ aikey run -- <command>");
        println!("\nTip: Run 'aikey project status' anytime to check your configuration");
    }

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
    // Deferred connectivity test — run after emit closure is dropped.
    let mut deferred_connectivity: Option<(Vec<(String, String)>, String)> = None;

    // Helper: print one check row, collect for JSON.
    // label is left-padded to 18 chars; detail is the right-hand info string.
    let mut emit = |label: &str, ok: bool, detail: &str, hint: Option<&str>| {
        let icon = if ok { "✓".green() } else { "✗".red() };
        if !json_mode {
            println!("{} {:<18} {}", icon, label, detail);
            if let Some(h) = hint {
                println!("  {}", format!("→ {}", h).dimmed());
            }
        }
        results.push(serde_json::json!({
            "check": label,
            "ok": ok,
            "detail": detail,
            "hint": hint,
        }));
        if !ok { any_failed = true; }
    };

    if !json_mode {
        println!("{}", "─".repeat(52).dimmed());
    }

    // ── 1. Internet connectivity ─────────────────────────────
    {
        let r = tcp_ping("1.1.1.1", 443, 3);
        emit("internet",
            r.0,
            &if r.0 { format!("reachable  ({} ms)", r.1) } else { "unreachable".to_string() },
            if r.0 { None } else { Some("check network connection or VPN") });
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
    if proxy_up {
        let base = format!("http://{}", proxy_addr);

        // Fetch the active key's provider list from proxy metadata.
        let targets: Vec<(String, String)> = ureq::get(&format!("{}/health/provider-targets", base))
            .call()
            .ok()
            .and_then(|r| r.into_json::<serde_json::Value>().ok())
            .and_then(|j| {
                j["targets"].as_array().map(|arr| {
                    arr.iter()
                        .filter_map(|t| {
                            let p = t["provider"].as_str()?.to_string();
                            let u = t["base_url"].as_str()?.to_string();
                            Some((p, u))
                        })
                        .collect()
                })
            })
            .unwrap_or_default();

        if targets.is_empty() {
            if !json_mode {
                println!("  {} {:<18} {}",
                    "·".dimmed(), "providers",
                    "no active key — run 'aikey use' first".dimmed());
            }
        } else {
            // Try to decrypt the active personal key for direct API probes.
            // Uses session-cached password if available; skips API probe otherwise
            // (ping + proxy test still run).
            let api_key = crate::session::try_get()
                .and_then(|pw| {
                    let cfg = crate::storage::get_active_key_config().ok()??;
                    if cfg.key_type == "personal" {
                        crate::executor::get_secret(&cfg.key_ref, &pw).ok()
                            .map(|z| z.to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            // Deferred: run after emit closure is dropped (borrow conflict).
            deferred_connectivity = Some((targets, api_key));
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

    // Drop emit to release &mut results, then run deferred connectivity test.
    drop(emit);

    if let Some((targets, api_key)) = deferred_connectivity {
        let suite = run_connectivity_test(&targets, &api_key, json_mode);
        if json_mode {
            results.extend(suite.json_results);
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
// Provider connectivity test (reused by `aikey add` and `aikey doctor`)
// ---------------------------------------------------------------------------

/// TCP ping: connect to host:port with a timeout. Returns (ok, latency_ms).
/// Supports both IP addresses and hostnames (DNS resolution included).
pub fn tcp_ping(host: &str, port: u16, timeout_secs: u64) -> (bool, u128) {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::{Duration, Instant};

    let addr_str = format!("{}:{}", host, port);
    let start = Instant::now();

    // Resolve hostname to socket address (includes DNS lookup).
    let resolved = match addr_str.to_socket_addrs() {
        Ok(mut addrs) => addrs.next(),
        Err(_) => return (false, start.elapsed().as_millis()),
    };
    let sock_addr = match resolved {
        Some(a) => a,
        None => return (false, start.elapsed().as_millis()),
    };

    let ok = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(timeout_secs)).is_ok();
    (ok, start.elapsed().as_millis())
}

/// Result of a provider connectivity test.
pub struct ConnectivityResult {
    pub ping_ok: bool,
    pub ping_ms: u128,
    pub api_ok: bool,
    pub api_ms: u128,
    pub api_status: Option<u16>,
    pub chat_ok: bool,
    pub chat_ms: u128,
    pub chat_status: Option<u16>,
}

/// Default base URLs for known providers.
pub const PROVIDER_DEFAULTS: &[(&str, &str)] = &[
    ("anthropic", "https://api.anthropic.com"),
    ("openai",    "https://api.openai.com"),
    ("google",    "https://generativelanguage.googleapis.com"),
    ("deepseek",  "https://api.deepseek.com"),
    // Why: Kimi Coding CLI uses api.kimi.com/coding/v1 (not api.moonshot.cn).
    // Store without /v1 here — the CLI connectivity test appends /v1/... itself.
    ("kimi",      "https://api.kimi.com/coding"),
    ("glm",       "https://open.bigmodel.cn/api/paas"),
];

/// Resolve the default base URL for a provider code.
pub fn default_base_url(provider_code: &str) -> Option<&'static str> {
    PROVIDER_DEFAULTS.iter()
        .find(|(c, _)| *c == provider_code)
        .map(|(_, u)| *u)
}

/// Test connectivity to a provider: first TCP ping, then API probe.
///
/// - **Ping**: TCP connect to the provider host on port 443 (fast, no auth).
/// - **API**: HTTP GET with the real key (validates both network and key).
///   Any HTTP response (including 401/403) is treated as "reachable".
///   Only connection errors count as failure.
pub fn test_provider_connectivity(
    provider_code: &str,
    base_url: &str,
    api_key: &str,
) -> ConnectivityResult {
    use std::time::{Duration, Instant};

    // 1. TCP ping — extract host and port from base_url
    let is_http = base_url.starts_with("http://");
    let host_port = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(base_url);
    let (host, port) = if let Some(idx) = host_port.rfind(':') {
        let h = &host_port[..idx];
        let p = host_port[idx+1..].parse::<u16>().unwrap_or(if is_http { 80 } else { 443 });
        (h, p)
    } else {
        (host_port, if is_http { 80 } else { 443 })
    };
    let (ping_ok, ping_ms) = tcp_ping(host, port, 5);

    if !ping_ok {
        return ConnectivityResult {
            ping_ok: false, ping_ms,
            api_ok: false, api_ms: 0, api_status: None,
            chat_ok: false, chat_ms: 0, chat_status: None,
        };
    }

    // 2. API probe with real key (GET — lightweight, no side effects)
    let test_url = if provider_code == "google" {
        format!("{}{}?key={}", base_url.trim_end_matches('/'), probe_suffix(provider_code, base_url), api_key)
    } else {
        format!("{}{}", base_url.trim_end_matches('/'), probe_suffix(provider_code, base_url))
    };
    let (auth_key, auth_val) = probe_auth(provider_code, api_key);

    let api_start = Instant::now();
    let mut api_req = ureq::get(&test_url)
        .timeout(Duration::from_secs(10));
    if provider_code != "google" {
        api_req = api_req.set(auth_key, &auth_val);
    }
    let api_result = api_req.call();
    let api_ms = api_start.elapsed().as_millis();

    let (api_ok, api_status) = match api_result {
        Ok(r) => (true, Some(r.status())),
        Err(ureq::Error::Status(code, _)) => (true, Some(code)),
        Err(_) => (false, None),
    };

    if !api_ok {
        return ConnectivityResult {
            ping_ok, ping_ms,
            api_ok, api_ms, api_status,
            chat_ok: false, chat_ms: 0, chat_status: None,
        };
    }

    // 3. Chat probe — send a minimal completion request with max_tokens=1
    let chat_url = if provider_code == "google" {
        format!("{}{}?key={}", base_url.trim_end_matches('/'), chat_suffix(provider_code, base_url), api_key)
    } else {
        format!("{}{}", base_url.trim_end_matches('/'), chat_suffix(provider_code, base_url))
    };
    let (chat_auth_key, chat_auth_val) = probe_auth(provider_code, api_key);
    let body = chat_body(provider_code);

    let chat_start = Instant::now();
    let mut req = ureq::post(&chat_url)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(15));
    // Google uses ?key= in URL; skip header auth. Others use header.
    if provider_code != "google" {
        req = req.set(chat_auth_key, &chat_auth_val);
    }
    if provider_code == "anthropic" {
        req = req.set("anthropic-version", "2023-06-01");
    }
    let chat_result = req.send_string(&body.to_string());
    let chat_ms = chat_start.elapsed().as_millis();

    let (chat_ok, chat_status) = match chat_result {
        Ok(r) => {
            let s = r.status();
            // Only 2xx means the chat actually completed.
            (s >= 200 && s < 300, Some(s))
        }
        Err(ureq::Error::Status(code, _)) => {
            // Server responded but chat failed (auth error, model not found, etc.)
            (false, Some(code))
        }
        Err(_) => (false, None),
    };

    ConnectivityResult {
        ping_ok, ping_ms,
        api_ok, api_ms, api_status,
        chat_ok, chat_ms, chat_status,
    }
}

/// Result of a proxy connectivity probe.
pub struct ProxyProbeResult {
    pub ok: bool,
    pub ms: u128,
    pub status: Option<u16>,
}

/// Test a key through the proxy (full chain: CLI → proxy → provider).
/// Uses the active key's token for authentication.
pub fn test_proxy_connectivity(proxy_addr: &str, provider_code: &str) -> ProxyProbeResult {
    use std::time::{Duration, Instant};

    // Proxy strips the provider prefix and forwards to the real provider.
    // The proxy's upstream base_url never ends with /v1, so use full /v1/... paths.
    let proxy_base = format!("http://{}/{}", proxy_addr, provider_code);
    let proxy_url = format!("{}{}", proxy_base, probe_suffix(provider_code, &proxy_base));
    let active_cfg = crate::storage::get_active_key_config().ok().flatten();
    let bearer = active_cfg.as_ref()
        .map(|cfg| {
            if cfg.key_type == "team" {
                format!("aikey_vk_{}", cfg.key_ref)
            } else {
                format!("aikey_personal_{}", cfg.key_ref)
            }
        })
        .unwrap_or_else(|| "aikey_test_probe".to_string());

    let (auth_key, auth_val) = probe_auth(provider_code, &bearer);
    let start = Instant::now();
    let result = ureq::get(&proxy_url)
        .set(auth_key, &auth_val)
        .timeout(Duration::from_secs(10))
        .call();
    let ms = start.elapsed().as_millis();

    let (ok, status) = match result {
        Ok(r) => (true, Some(r.status())),
        Err(ureq::Error::Status(code, _)) => (true, Some(code)),
        Err(_) => (false, None),
    };
    ProxyProbeResult { ok, ms, status }
}

/// Format a proxy probe status code into a human-readable hint.
pub fn proxy_status_hint(status: u16) -> String {
    match status {
        200 => "routing ok, key valid".to_string(),
        400 | 404 | 405 => "routing ok".to_string(),
        401 | 403 => "routing ok, key rejected by provider".to_string(),
        503 => "proxy has no active key for this provider".to_string(),
        _ => format!("HTTP {}", status),
    }
}

/// Build the probe URL suffix for a provider.
/// Checks if base_url already ends with /v1 to avoid double /v1/v1.
fn probe_suffix(provider_code: &str, base_url: &str) -> String {
    let base_has_v1 = base_url.trim_end_matches('/').ends_with("/v1");
    match provider_code {
        "anthropic" if base_has_v1 => "/messages".to_string(),
        "anthropic" => "/v1/messages".to_string(),
        "google" => "/v1beta/models".to_string(),
        "custom" => String::new(),
        _ if base_has_v1 => "/models".to_string(),
        _ => "/v1/models".to_string(),
    }
}

/// Build the chat completion URL suffix for a provider.
/// Checks if base_url already ends with /v1 to avoid double /v1/v1.
fn chat_suffix(provider_code: &str, base_url: &str) -> String {
    let base_has_v1 = base_url.trim_end_matches('/').ends_with("/v1");
    match provider_code {
        "anthropic" if base_has_v1 => "/messages".to_string(),
        "anthropic" => "/v1/messages".to_string(),
        "google" => "/v1beta/models/gemini-2.0-flash:generateContent".to_string(),
        _ if base_has_v1 => "/chat/completions".to_string(),
        _ => "/v1/chat/completions".to_string(),
    }
}

/// Default model name per provider for the chat probe.
fn probe_model(provider_code: &str) -> &'static str {
    match provider_code {
        "anthropic" => "claude-sonnet-4-20250514",
        "openai"    => "gpt-4o-mini",
        "deepseek"  => "deepseek-chat",
        "kimi"      => "moonshot-v1-8k",
        "google"    => "gemini-2.0-flash",
        "glm" | "zhipu" => "glm-4-flash",
        "yi"        => "yi-lightning",
        "qwen" | "dashscope" => "qwen-turbo",
        "mistral"   => "mistral-small-latest",
        _           => "gpt-4o-mini", // fallback: most gateways understand this
    }
}

/// Build a minimal chat request body for a provider.
fn chat_body(provider_code: &str) -> serde_json::Value {
    let model = probe_model(provider_code);
    match provider_code {
        "anthropic" => serde_json::json!({
            "model": model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}]
        }),
        "google" => serde_json::json!({
            "contents": [{"parts": [{"text": "hi"}]}],
            "generationConfig": {"maxOutputTokens": 1}
        }),
        _ => serde_json::json!({
            "model": model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}]
        }),
    }
}

/// Build the auth header (key, value) for a provider probe.
fn probe_auth(provider_code: &str, api_key: &str) -> (&'static str, String) {
    match provider_code {
        "anthropic" => ("x-api-key", api_key.to_string()),
        // Google uses ?key= query param, but we pass it as header too for proxy compatibility.
        // The actual URL builder appends ?key= for direct calls.
        "google"    => ("x-goog-api-key", api_key.to_string()),
        _           => ("Authorization", format!("Bearer {}", api_key)),
    }
}

/// Format a chat probe status code into a human-readable hint.
pub fn chat_status_hint(status: u16) -> String {
    match status {
        200 => "valid".to_string(),
        400 => "bad request".to_string(),
        401 => "invalid key".to_string(),
        403 => "forbidden".to_string(),
        404 => "not found".to_string(),
        422 => "invalid request".to_string(),
        429 => "rate limited".to_string(),
        _ if status >= 500 => format!("server error ({})", status),
        _ => format!("HTTP {}", status),
    }
}

/// Format an API probe status code into a human-readable hint.
pub fn api_status_hint(status: u16) -> String {
    match status {
        200 => "valid key".to_string(),
        401 | 403 => "reachable, key rejected".to_string(),
        404 => "reachable".to_string(),
        _ => format!("HTTP {}", status),
    }
}

/// Result of a full connectivity test suite.
pub struct TestSuiteResult {
    /// JSON results (populated only in json_mode).
    pub json_results: Vec<serde_json::Value>,
    /// Whether at least one provider's chat probe succeeded.
    pub any_chat_ok: bool,
}

/// Run a full connectivity test suite: direct provider tests + proxy test.
/// Prints results to stderr. Returns test suite result with `any_chat_ok`.
///
/// Used by `aikey test`, `aikey add`, and `aikey doctor`.
pub fn run_connectivity_test(
    targets: &[(String, String)],
    api_key: &str,
    json_mode: bool,
) -> TestSuiteResult {
    use colored::Colorize;

    if json_mode {
        let mut any_chat = false;
        let mut results: Vec<serde_json::Value> = targets.iter().map(|(code, url)| {
            let r = test_provider_connectivity(code, url, api_key);
            if r.chat_ok { any_chat = true; }
            serde_json::json!({
                "provider": code, "base_url": url,
                "ping_ok": r.ping_ok, "ping_ms": r.ping_ms,
                "api_ok": r.api_ok, "api_ms": r.api_ms, "api_status": r.api_status,
                "chat_ok": r.chat_ok, "chat_ms": r.chat_ms, "chat_status": r.chat_status,
            })
        }).collect();

        // Proxy test
        if crate::commands_proxy::is_proxy_running() {
            let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
            let prov = targets.iter().find(|(c, _)| c != "custom").map(|(c, _)| c.as_str());
            if let Some(prov) = prov {
                let r = test_proxy_connectivity(&proxy_addr, prov);
                results.push(serde_json::json!({
                    "provider": "proxy", "proxy_addr": proxy_addr,
                    "ok": r.ok, "ms": r.ms, "status": r.status,
                }));
            }
        }
        return TestSuiteResult { json_results: results, any_chat_ok: any_chat };
    }

    // Interactive output — table, rows appended as each test completes.
    const W_PROV: usize = 12;
    const W_PING: usize = 16;
    const W_API:  usize = 30;

    let mut any_reachable = false;
    let mut any_chat_ok = false;

    // Header
    eprintln!("  {:<W_PROV$} {:<W_PING$} {:<W_API$} {}",
        "Provider".dimmed(), "Ping".dimmed(), "API".dimmed(), "Chat".dimmed(),
        W_PROV = W_PROV, W_PING = W_PING, W_API = W_API);
    eprintln!("  {}", "─".repeat(W_PROV + W_PING + W_API + 20).dimmed());

    for (code, url) in targets {
        // Print provider name immediately so user sees progress.
        eprint!("  {:<W_PROV$} ", code.bold(), W_PROV = W_PROV);
        use std::io::Write;
        let _ = std::io::stderr().flush();

        let r = test_provider_connectivity(code, url, api_key);

        // Ping column
        let ping_raw = if r.ping_ok { format!("ok ({}ms)", r.ping_ms) } else { format!("fail ({}ms)", r.ping_ms) };
        let ping_col = if r.ping_ok { format!("{:<W$}", ping_raw, W = W_PING).green().to_string() }
                       else         { format!("{:<W$}", ping_raw, W = W_PING).red().to_string() };
        eprint!("{} ", ping_col);
        let _ = std::io::stderr().flush();

        if !r.ping_ok {
            // API + Chat columns: skip
            eprintln!("{:<W_API$} {}", "—".dimmed(), "—".dimmed(), W_API = W_API);
        } else {
            any_reachable = true;

            // API column
            let api_raw = if r.api_ok {
                let hint = r.api_status.map(|s| api_status_hint(s)).unwrap_or_default();
                format!("ok ({}ms, {})", r.api_ms, hint)
            } else {
                format!("fail ({}ms)", r.api_ms)
            };
            let api_col = if r.api_ok { format!("{:<W$}", api_raw, W = W_API).green().to_string() }
                          else         { format!("{:<W$}", api_raw, W = W_API).red().to_string() };
            eprint!("{} ", api_col);
            let _ = std::io::stderr().flush();

            // Chat column
            if !r.api_ok {
                eprintln!("{}", "—".dimmed());
            } else if r.chat_ok {
                any_chat_ok = true;
                let hint = r.chat_status.map(|s| chat_status_hint(s)).unwrap_or_default();
                eprintln!("{}", format!("ok ({}ms, {})", r.chat_ms, hint).green());
            } else {
                eprintln!("{}", format!("fail ({}ms)", r.chat_ms).red());
            }
        }
    }

    // Proxy test
    eprintln!();
    if !any_reachable {
        eprintln!("  {:<12} {}", "proxy".bold(), "skipped (all providers unreachable)".dimmed());
    } else if crate::commands_proxy::is_proxy_running() {
        let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
        eprint!("  {:<12} ", "proxy".bold());
        let proxy_provider = targets.iter()
            .find(|(c, _)| c != "custom")
            .map(|(c, _)| c.as_str());
        if let Some(prov) = proxy_provider {
            let r = test_proxy_connectivity(&proxy_addr, prov);
            if r.ok {
                let hint = r.status.map(|s| proxy_status_hint(s)).unwrap_or_default();
                eprintln!("{} ({} ms, {})", "ok".green(), r.ms, hint);
            } else {
                eprintln!("{} ({} ms)", "failed".red(), r.ms);
            }
        } else {
            eprintln!("{}", "skipped — use --provider <code> to test proxy routing".dimmed());
        }
    } else {
        eprintln!("  {:<12} {}", "proxy".bold(), "not running".dimmed());
    }

    TestSuiteResult { json_results: Vec::new(), any_chat_ok }
}
