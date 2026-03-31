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
        println!("  1. Run 'aikey secret set <provider>:<alias>' to add provider keys (e.g. aikey secret set anthropic:default)");
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

    // Get current profile
    let profile_name = global_config::get_current_profile()
        .ok()
        .flatten()
        .unwrap_or_else(|| "default".to_string());

    // Check which required vars are satisfied by checking profile bindings
    let total = config.required_vars.len();
    let mut satisfied = 0;
    let mut missing_vars = Vec::new();

    // Get profile bindings to check satisfaction
    if let Ok(conn) = storage::open_connection() {
        if let Ok(bindings) = storage::get_profile_bindings(&conn, &profile_name) {
            let binding_domains: std::collections::HashSet<String> = bindings.iter().map(|(domain, _)| domain.clone()).collect();
            for var in &config.required_vars {
                if binding_domains.contains(var) {
                    satisfied += 1;
                } else {
                    missing_vars.push(var.clone());
                }
            }
        }
    }

    if json_mode {
        let response = serde_json::json!({
            "ok": true,
            "config_path": config_path.display().to_string(),
            "project_name": config.project.name,
            "profile": profile_name,
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
        println!("Current profile: {}", profile_name);
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
            println!("You'll set a master password to protect your secrets.\n");
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
            let pw = rpassword::prompt_password("Set Master Password: ")
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
        println!("   $ aikey secret set <name> --from-stdin");
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
    let prompt_str = if json_mode { "" } else { "Enter Master Password: " };
    let password = rpassword::prompt_password(prompt_str)?;
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
        let start = Instant::now();
        use std::net::TcpStream;
        let ok = TcpStream::connect_timeout(
            &"1.1.1.1:443".parse().unwrap(),
            std::time::Duration::from_secs(3),
        ).is_ok();
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

    // Collects provider connectivity results from the parallel block; merged into `results`
    // and `any_failed` after all `emit` calls (to avoid borrow-conflict with the emit closure).
    let mut prov_merge: Option<(Vec<serde_json::Value>, bool)> = None;

    // ── 4. Proxy process + reachability ──────────────────────
    let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
    let (proxy_up, proxy_pid) = crate::commands_proxy::doctor_proxy_status();
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
        let hint = if proxy_up { None } else {
            Some("run 'aikey proxy start' or just run any aikey command (auto-start)")
        };
        emit("proxy", proxy_up, &detail, hint);
    }

    // ── 5. Provider connectivity (parallel, streaming) ───────
    if proxy_up {
        let base = format!("http://{}", proxy_addr);

        // Fetch the active key's provider list (no probing — just metadata).
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
            let n = targets.len();
            let is_tty = atty::is(atty::Stream::Stdout);

            // Print placeholder rows (TTY only — non-TTY results append in completion order).
            if !json_mode && is_tty {
                for (name, _) in &targets {
                    println!("{} {:<18} {}", "·".dimmed(), name, "testing...".dimmed());
                }
                use std::io::Write;
                std::io::stdout().flush().ok();
            }

            // Spawn one thread per provider; each probes via HTTP GET (any response = reachable).
            let (tx, rx) = std::sync::mpsc::channel::<(usize, bool, u128)>();
            for (i, (_, url)) in targets.iter().enumerate() {
                let tx2 = tx.clone();
                let url = url.clone();
                std::thread::spawn(move || {
                    let start = Instant::now();
                    let agent = ureq::AgentBuilder::new()
                        .timeout(std::time::Duration::from_secs(5))
                        .build();
                    // Any HTTP response (including 4xx/5xx) means network is reachable.
                    let ok = match agent.get(&url).call() {
                        Ok(_) => true,
                        Err(ureq::Error::Status(_, _)) => true,
                        Err(_) => false,
                    };
                    let ms = start.elapsed().as_millis();
                    tx2.send((i, ok, ms)).ok();
                });
            }
            drop(tx);

            // Receive results; update the pre-printed placeholder line in-place (TTY mode).
            // Collect into a local vec to avoid conflicting with the `emit` closure borrow on
            // `results` and `any_failed` (emit is still used after this block for key/control checks).
            let mut prov_items: Vec<serde_json::Value> = Vec::with_capacity(n);
            let mut prov_any_failed = false;
            for (i, ok, ms) in rx.iter() {
                let name = &targets[i].0;
                // Show the hostname of the probed URL so it's clear what was tested.
                let host = targets[i].1
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or(&targets[i].1);
                let detail = if ok {
                    format!("reachable  ({}, {} ms)", host, ms)
                } else {
                    format!("unreachable  ({})", host)
                };

                if !json_mode {
                    use std::io::Write;
                    let icon = if ok { "✓".green() } else { "✗".red() };
                    let line = format!("{} {:<18} {}", icon, name, detail);
                    if is_tty {
                        // Move cursor up to row i (counted from the bottom of the block),
                        // overwrite the placeholder, then restore position to the bottom.
                        // The trailing \r resets the column to 0 so subsequent println!
                        // calls start at the left margin, not mid-line.
                        let up = n - i;
                        print!("\x1b[{}A\r\x1b[2K{}", up, line);
                        print!("\x1b[{}B\r", up);
                    } else {
                        println!("{}", line);
                    }
                    std::io::stdout().flush().ok();
                }

                prov_items.push(serde_json::json!({
                    "check": format!("provider:{}", name),
                    "ok": ok,
                    "detail": detail,
                }));
                if !ok {
                    prov_any_failed = true;
                }
            }

            if !json_mode && prov_any_failed {
                println!("  {}", "→ check firewall, VPN, or provider status page".dimmed());
            }
            // Merge into outer results after the parallel section finishes.
            prov_merge = Some((prov_items, prov_any_failed));
        }

        // ── 6. Active key validity (via proxy) ────────────────
        if let Ok(resp) = ureq::get(&format!("{}/health/keys", base)).call() {
            if let Ok(body) = resp.into_string() {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(keys) = json["keys"].as_array() {
                        for k in keys {
                            let provider = k["provider"].as_str().unwrap_or("?");
                            let key_ref  = k["key_ref"].as_str().unwrap_or("?");
                            let ok       = k["ok"].as_bool().unwrap_or(false);
                            let ms       = k["latency_ms"].as_i64().unwrap_or(0);
                            let err      = k["error"].as_str().unwrap_or("");
                            let label = provider.to_string();
                            let detail = if ok {
                                format!("valid  ({}, {} ms)", key_ref, ms)
                            } else {
                                format!("failed  ({}): {}", key_ref, err)
                            };
                            let hint = if ok { None } else if err.contains("invalid") || err.contains("401") || err.contains("403") {
                                Some("re-add the key with 'aikey add' or re-accept with 'aikey key accept'")
                            } else {
                                Some("check provider reachability above")
                            };
                            emit(&label, ok, &detail, hint);
                        }
                    } else if json["message"].as_str().is_some() {
                        emit("active key", true, "no key active  (run 'aikey use' to activate one)", None);
                    }
                }
            }
        }
    }

    // ── 7. Control service ───────────────────────────────────
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

    // Merge provider connectivity results (collected during the parallel block above).
    // Done here — after all emit() calls — to avoid the borrow conflict between the emit
    // closure's captured &mut results/any_failed and the provider block's direct access.
    if let Some((items, failed)) = prov_merge {
        results.extend(items);
        if failed { any_failed = true; }
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
