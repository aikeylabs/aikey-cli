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
    // Per-provider keys for multi-binding doctor tests: (provider_code, key, is_oauth).
    let mut deferred_keys: Option<Vec<(String, String, bool)>> = None;

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
        let ok = build_proxy_aware_agent(std::time::Duration::from_secs(5))
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
    // Why: reuses the same all-bindings approach as `aikey test` (no alias)
    // so that doctor shows every configured provider, not just the active key.
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
            struct DoctorItem { provider: String, url: String, key: String, is_oauth: bool }
            let mut items: Vec<DoctorItem> = Vec::new();

            // Try session cache first; if expired and there are API key bindings,
            // prompt for Master Password so we can decrypt and test them.
            let has_api_key_bindings = bindings.iter().any(|b|
                b.key_source_type == crate::credential_type::CredentialType::PersonalApiKey
                || b.key_source_type == crate::credential_type::CredentialType::ManagedVirtualKey);
            let pw = crate::session::try_get().or_else(|| {
                use std::io::IsTerminal;
                if has_api_key_bindings && !json_mode && std::io::stdin().is_terminal() {
                    crate::prompt_hidden("  \u{25c6} Enter Master Password to test API keys: ")
                        .ok()
                        .map(|p| secrecy::SecretString::new(p))
                } else {
                    None
                }
            });
            let proxy_port = crate::commands_proxy::proxy_port();
            for b in &bindings {
                if b.key_source_type == crate::credential_type::CredentialType::PersonalApiKey {
                    if let Some(ref pw) = pw {
                        if let Ok(kv) = crate::executor::get_secret(&b.key_source_ref, pw) {
                            let bu = storage::get_entry_base_url(&b.key_source_ref)
                                .unwrap_or(None);
                            let url = bu.as_deref()
                                .or_else(|| default_base_url(&b.provider_code))
                                .unwrap_or("https://unknown")
                                .to_string();
                            items.push(DoctorItem {
                                provider: b.provider_code.clone(),
                                url,
                                key: kv.to_string(),
                                is_oauth: false,
                            });
                        }
                    }
                } else if b.key_source_type == crate::credential_type::CredentialType::PersonalOAuthAccount {
                    // OAuth: test connectivity through proxy (ping + API reachable).
                    // Why not full chat probe: OAuth providers require provider-specific
                    // persona headers (?beta=true, metadata.user_id, originator, etc.)
                    // that differ per provider. Full chat validation should use
                    // `aikey auth doctor` which tests the actual CLI→proxy→provider chain.
                    let prefix = crate::commands_account::provider_proxy_prefix_pub(&b.provider_code);
                    let url = format!("http://127.0.0.1:{}/{}", proxy_port, prefix);
                    let sentinel = format!("aikey_personal_{}", b.key_source_ref);
                    items.push(DoctorItem {
                        provider: b.provider_code.clone(),
                        url,
                        key: sentinel,
                        is_oauth: true,
                    });
                }
                // team keys: tested via proxy only (no decryption needed here)
            }

            if items.is_empty() {
                if !json_mode {
                    println!("  {} {:<18} {}",
                        "\u{b7}".dimmed(), "providers",
                        "no provider bindings configured".dimmed());
                }
            } else {
                let targets: Vec<(String, String)> = items.iter()
                    .map(|i| (i.provider.clone(), i.url.clone()))
                    .collect();
                // Deferred: run after emit closure is dropped (borrow conflict).
                deferred_connectivity = Some((targets, String::new()));
                // Store per-provider keys for deferred use.
                // Display label uses provider + (oauth) suffix for visual distinction.
                deferred_keys = Some(items.into_iter()
                    .map(|i| (i.provider.clone(), i.key, i.is_oauth))
                    .collect());
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

        // b) Control diagnostics (if control service is reachable)
        let diag_json = storage::get_platform_account().ok().flatten()
            .and_then(|acct| {
                let url = format!("{}/v1/diagnostics/pipeline",
                    acct.control_url.trim_end_matches('/'));
                agent.get(&url).call().ok()
                    .and_then(|r| r.into_string().ok())
            });

        check_usage_pipeline(
            proxy_metrics.as_deref(),
            diag_json.as_deref(),
            &mut emit,
        );
    }

    // Drop emit to release &mut results, then run deferred tests.
    drop(emit);

    if let Some((targets, _)) = deferred_connectivity {
        if let Some(keys) = deferred_keys {
            // Multi-binding mode: test each provider with its own key.
            run_multi_key_connectivity_test(&targets, &keys, json_mode, &mut results);
        } else {
            let suite = run_connectivity_test(&targets, "", json_mode);
            if json_mode {
                results.extend(suite.json_results);
            }
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
/// Default base URLs for known providers — always use the official recommended URL.
/// chat_suffix() / probe_suffix() detect trailing /v1 to avoid double /v1/v1.
pub const PROVIDER_DEFAULTS: &[(&str, &str)] = &[
    ("anthropic", "https://api.anthropic.com"),
    ("openai",    "https://api.openai.com/v1"),
    ("google",    "https://generativelanguage.googleapis.com"),
    ("deepseek",  "https://api.deepseek.com/v1"),
    ("kimi",      "https://api.kimi.com/coding/v1"),
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
/// Build a ureq agent that respects proxy.env (https_proxy / http_proxy).
/// Why: in China and other restricted networks, direct connections to
/// api.openai.com etc. are blocked. The user's proxy.env configures an
/// outbound proxy (e.g., socks5://127.0.0.1:7890) that the connectivity
/// test must use — otherwise TCP ping and HTTP probes time out.
fn build_proxy_aware_agent(timeout: std::time::Duration) -> ureq::Agent {
    let mut builder = ureq::AgentBuilder::new().timeout(timeout);

    // Try https_proxy, then http_proxy, then all_proxy from proxy.env or env.
    let proxy_url = crate::proxy_env::read_proxy_env_var("https_proxy")
        .or_else(|| crate::proxy_env::read_proxy_env_var("http_proxy"))
        .or_else(|| crate::proxy_env::read_proxy_env_var("all_proxy"))
        .or_else(|| std::env::var("https_proxy").ok())
        .or_else(|| std::env::var("http_proxy").ok())
        .or_else(|| std::env::var("all_proxy").ok());

    if let Some(url) = proxy_url {
        if let Ok(proxy) = ureq::Proxy::new(&url) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build()
}

pub fn test_provider_connectivity(
    provider_code: &str,
    base_url: &str,
    api_key: &str,
) -> ConnectivityResult {
    use std::time::{Duration, Instant};

    // Check if user has a network proxy configured (proxy.env or env vars).
    let has_proxy = crate::proxy_env::read_proxy_env_var("https_proxy").is_some()
        || crate::proxy_env::read_proxy_env_var("http_proxy").is_some()
        || crate::proxy_env::read_proxy_env_var("all_proxy").is_some()
        || std::env::var("https_proxy").is_ok()
        || std::env::var("http_proxy").is_ok()
        || std::env::var("all_proxy").is_ok();

    // 1. TCP ping — extract host and port from base_url
    // Why: skip TCP ping when a network proxy is configured, because direct
    // TCP connect to the provider host will fail in restricted networks even
    // though HTTP requests through the proxy succeed fine.
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

    let (ping_ok, ping_ms) = if has_proxy {
        // With a proxy, skip TCP ping and go straight to HTTP probe.
        (true, 0)
    } else {
        tcp_ping(host, port, 5)
    };

    if !ping_ok {
        return ConnectivityResult {
            ping_ok: false, ping_ms,
            api_ok: false, api_ms: 0, api_status: None,
            chat_ok: false, chat_ms: 0, chat_status: None,
        };
    }

    let agent = build_proxy_aware_agent(Duration::from_secs(10));

    // 2. API probe with real key (GET — lightweight, no side effects)
    let test_url = if provider_code == "google" {
        format!("{}{}?key={}", base_url.trim_end_matches('/'), probe_suffix(provider_code, base_url), api_key)
    } else {
        format!("{}{}", base_url.trim_end_matches('/'), probe_suffix(provider_code, base_url))
    };
    let (auth_key, auth_val) = probe_auth(provider_code, api_key);

    let api_start = Instant::now();
    let mut api_req = agent.get(&test_url);
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
    // Why ?beta=true: Claude OAuth API requires this query param. Without it,
    // Anthropic returns 429 business rejection (not real rate limit).
    // When going through proxy, the proxy forwards the query params to upstream.
    // OAuth accounts go through the proxy (base_url is localhost).
    // Provider-specific adjustments are needed for OAuth persona requirements.
    let is_via_proxy = base_url.contains("127.0.0.1") || base_url.contains("localhost");

    let (chat_url, body) = if provider_code == "openai" && is_via_proxy {
        // Codex OAuth: uses Responses API via chatgpt.com/backend-api/codex.
        // Required fields: model=gpt-5.4, instructions, input=array, store=false, stream=true
        // Why gpt-5.4: ChatGPT accounts only support Codex-specific models (not gpt-4o-mini).
        // Why stream=true + store=false: Codex API enforces these for ChatGPT accounts.
        // Ref: verified 2026-04-16 against chatgpt.com/backend-api/codex/responses
        let url = format!("{}/responses", base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": "gpt-5.4",
            "instructions": "Say hi.",
            "input": [{"role": "user", "content": "hi"}],
            "store": false,
            "stream": true
        });
        (url, body)
    } else if provider_code == "anthropic" && is_via_proxy {
        // Claude OAuth: requires ?beta=true + metadata.user_id
        let url = format!("{}{}?beta=true", base_url.trim_end_matches('/'), chat_suffix(provider_code, base_url));
        let mut body = chat_body(provider_code);
        if let Some(obj) = body.as_object_mut() {
            obj.insert("metadata".to_string(), serde_json::json!({"user_id": "aikey_doctor_probe"}));
        }
        (url, body)
    } else if provider_code == "google" {
        let url = format!("{}{}?key={}", base_url.trim_end_matches('/'), chat_suffix(provider_code, base_url), api_key);
        (url, chat_body(provider_code))
    } else {
        let url = format!("{}{}", base_url.trim_end_matches('/'), chat_suffix(provider_code, base_url));
        (url, chat_body(provider_code))
    };
    let (chat_auth_key, chat_auth_val) = probe_auth(provider_code, api_key);

    let chat_agent = build_proxy_aware_agent(Duration::from_secs(15));
    let chat_start = Instant::now();
    let mut req = chat_agent.post(&chat_url)
        .set("Content-Type", "application/json");
    // Google uses ?key= in URL; skip header auth. Others use header.
    if provider_code != "google" {
        req = req.set(chat_auth_key, &chat_auth_val);
    }
    if provider_code == "anthropic" {
        req = req.set("anthropic-version", "2023-06-01");
    }
    // Why: KIMI Coding API (api.kimi.com/coding/v1) requires a User-Agent
    // matching its coding-agent whitelist (e.g. "claude-code", "kimi-cli").
    // Without it, KIMI returns access_terminated_error (HTTP 403).
    // We use "claude-code/1.0 (aikey)" to satisfy the whitelist while
    // identifying ourselves. This only affects the connectivity probe.
    if provider_code == "kimi" {
        req = req.set("User-Agent", "claude-code/1.0");
    }
    let chat_result = req.send_string(&body.to_string());
    let chat_ms = chat_start.elapsed().as_millis();

    let (chat_ok, chat_status) = match chat_result {
        Ok(r) => {
            let s = r.status();
            (s >= 200 && s < 300, Some(s))
        }
        Err(ureq::Error::Status(code, _)) => {
            // 429 = auth passed but rate limited → treat as connectivity OK.
            // Why: Claude OAuth returns 429 as business rejection when persona
            // headers are incomplete, but also for genuine rate limits. Either way,
            // the key is valid and the provider is reachable.
            //
            // 404 for openai via proxy = Codex uses Responses API, not Chat Completions.
            // The probe endpoint doesn't exist, but the provider is reachable (API probe passed).
            let ok = code == 429;
            (ok, Some(code))
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
            if cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey {
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
        // Why haiku: sonnet/opus hit rate limits on OAuth accounts (429 business rejection).
        // Haiku is lighter and skips stricter quota checks. Verified in research.
        "anthropic" => "claude-haiku-4-5-20251001",
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
        429 => "rate limited, key valid".to_string(),
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

/// Run connectivity tests with per-provider API keys (used by `aikey doctor`).
/// Each target is tested with its own key from the `keys` map.
fn run_multi_key_connectivity_test(
    targets: &[(String, String)],
    keys: &[(String, String, bool)],  // (provider_code, key, is_oauth)
    json_mode: bool,
    results: &mut Vec<serde_json::Value>,
) {
    use colored::Colorize;
    use std::io::Write;

    let key_map: std::collections::HashMap<&str, (&str, bool)> = keys.iter()
        .map(|(p, k, oauth)| (p.as_str(), (k.as_str(), *oauth)))
        .collect();

    if json_mode {
        for (code, url) in targets {
            let (api_key, is_oauth) = key_map.get(code.as_str()).copied().unwrap_or(("", false));
            let r = test_provider_connectivity(code, url, api_key);
            results.push(serde_json::json!({
                "provider": code, "base_url": url, "is_oauth": is_oauth,
                "ping_ok": r.ping_ok, "ping_ms": r.ping_ms,
                "api_ok": r.api_ok, "api_ms": r.api_ms, "api_status": r.api_status,
                "chat_ok": r.chat_ok, "chat_ms": r.chat_ms, "chat_status": r.chat_status,
            }));
        }
        return;
    }

    // Interactive table — same layout as run_connectivity_test / aikey test.
    const W_PROV: usize = 18; const W_PING: usize = 16; const W_API: usize = 30;
    eprintln!("  {:<wp$} {:<wpi$} {:<wap$} {}",
        "Provider".dimmed(), "Ping".dimmed(), "API".dimmed(), "Chat".dimmed(),
        wp = W_PROV, wpi = W_PING, wap = W_API);
    eprintln!("  {}", "\u{2500}".repeat(W_PROV + W_PING + W_API + 20).dimmed());

    let mut any_reachable = false;
    let mut failed_hints: Vec<String> = Vec::new();
    for (code, url) in targets {
        let (api_key, is_oauth) = key_map.get(code.as_str()).copied().unwrap_or(("", false));
        let display_name = if is_oauth { format!("{} (oauth)", code) } else { code.clone() };
        eprint!("  {:<wp$} ", display_name.bold(), wp = W_PROV);
        let _ = std::io::stderr().flush();
        let r = test_provider_connectivity(code, url, api_key);

        // Ping column
        let ping_raw = if r.ping_ok { format!("ok ({}ms)", r.ping_ms) } else { format!("fail ({}ms)", r.ping_ms) };
        let ping_col = if r.ping_ok { format!("{:<w$}", ping_raw, w = W_PING).green().to_string() } else { format!("{:<w$}", ping_raw, w = W_PING).red().to_string() };
        eprint!("{} ", ping_col); let _ = std::io::stderr().flush();

        if !r.ping_ok {
            eprintln!("{:<w$} {}", "\u{2014}".dimmed(), "\u{2014}".dimmed(), w = W_API);
            failed_hints.push(format!("{}: ping failed — check network, VPN, or firewall", display_name));
        } else {
            any_reachable = true;
            // API column
            let api_raw = if r.api_ok { let h = r.api_status.map(|s| api_status_hint(s)).unwrap_or_default(); format!("ok ({}ms, {})", r.api_ms, h) } else { format!("fail ({}ms)", r.api_ms) };
            let api_col = if r.api_ok { format!("{:<w$}", api_raw, w = W_API).green().to_string() } else { format!("{:<w$}", api_raw, w = W_API).red().to_string() };
            eprint!("{} ", api_col); let _ = std::io::stderr().flush();
            // Chat column
            if !r.api_ok {
                eprintln!("{}", "\u{2014}".dimmed());
                failed_hints.push(format!("{}: API unreachable — check proxy config or provider URL", display_name));
            } else if r.chat_ok {
                let hint = r.chat_status.map(|s| chat_status_hint(s)).unwrap_or_default();
                eprintln!("{}", format!("ok ({}ms, {})", r.chat_ms, hint).green());
            } else {
                let hint = r.chat_status.map(|s| format!(", HTTP {}: {}", s, chat_status_hint(s))).unwrap_or_default();
                eprintln!("{}", format!("fail ({}ms{})", r.chat_ms, hint).red());
                // Actionable hint based on HTTP status + context
                let suggestion = match (r.chat_status, is_oauth, code.as_str()) {
                    (Some(404), true, "openai") => format!("{}: Codex uses Responses API (not Chat Completions) — probe skipped; actual usage works", display_name),
                    (Some(400), _, _) => format!("{}: chat 400 — missing header or invalid body", display_name),
                    (Some(401), _, _) => format!("{}: chat 401 — invalid key or token expired. Run: aikey auth login {}", display_name, code),
                    (Some(403), _, _) => format!("{}: chat 403 — access denied. Check subscription status", display_name),
                    (Some(429), _, _) => format!("{}: chat 429 — rate limited (key is valid, try again later)", display_name),
                    (Some(s), _, _) if s >= 500 => format!("{}: chat {} — provider server error; try again later", display_name, s),
                    (None, _, _) => format!("{}: chat failed — network error. Check: ~/.aikey/logs/aikey-proxy/current.jsonl", display_name),
                    (Some(s), _, _) => format!("{}: chat HTTP {} — unexpected error", display_name, s),
                };
                failed_hints.push(suggestion);
            }
        }
    }

    // Print actionable hints for failures
    if !failed_hints.is_empty() && !json_mode {
        eprintln!();
        for hint in &failed_hints {
            eprintln!("  {} {}", "\u{2192}".dimmed(), hint.dimmed());
        }
    }

    // Proxy test
    eprintln!();
    if !any_reachable {
        eprintln!("  {:<12} {}", "proxy".bold(), "skipped (all providers unreachable)".dimmed());
    } else if crate::commands_proxy::is_proxy_running() {
        let proxy_addr = crate::commands_proxy::doctor_proxy_addr();
        if let Some(prov) = targets.iter().find(|(c, _)| c != "custom").map(|(c, _)| c.as_str()) {
            eprint!("  {:<12} ", "proxy".bold());
            let r = test_proxy_connectivity(&proxy_addr, prov);
            if r.ok { let h = r.status.map(|s| proxy_status_hint(s)).unwrap_or_default(); eprintln!("{} ({} ms, {})", "ok".green(), r.ms, h); }
            else { eprintln!("{} ({} ms)", "failed".red(), r.ms); }
        }
    } else {
        eprintln!("  {:<12} {}", "proxy".bold(), "not running".dimmed());
    }
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
