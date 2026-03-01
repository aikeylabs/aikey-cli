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
        println!("  1. Run 'aikey setup' to create a profile and add keys");
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

        let password = if json_mode {
            // In JSON mode read from stdin without prompt
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

/// Handle `aikey setup` — alias for quickstart (initialize vault and configure first profile)
pub fn handle_setup(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    handle_quickstart(json_mode)
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

/// Handle `aikey doctor` — run diagnostics and health checks
pub fn handle_doctor(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut checks: Vec<serde_json::Value> = Vec::new();
    let mut all_ok = true;

    // Check 1: project config exists
    let config_result = ProjectConfig::discover();
    let config_ok = config_result.as_ref().map(|r| r.is_some()).unwrap_or(false);
    checks.push(serde_json::json!({
        "check": "project_config",
        "ok": config_ok,
        "message": if config_ok { "aikey.config.json found" } else { "No aikey.config.json found in current or parent directories" }
    }));
    if !config_ok { all_ok = false; }

    // Check 2: if config found, verify all key aliases exist in vault
    if config_ok {
        if let Ok(Some((_, config))) = config_result {
            // Prompt for password to check vault
            let password_result = rpassword::prompt_password("Enter Master Password (for vault check): ");
            if let Ok(password_str) = password_result {
                let password = SecretString::new(password_str);
                if let Ok(secrets) = crate::executor::list_secrets(&password) {
                    for (provider_name, provider_cfg) in &config.providers {
                        let alias = &provider_cfg.key_alias;
                        let resolved = secrets.contains(alias);
                        checks.push(serde_json::json!({
                            "check": format!("key_alias:{}", alias),
                            "provider": provider_name,
                            "ok": resolved,
                            "message": if resolved {
                                format!("Key alias '{}' resolves", alias)
                            } else {
                                format!("Key alias '{}' not found in vault", alias)
                            }
                        }));
                        if !resolved { all_ok = false; }
                    }
                } else {
                    checks.push(serde_json::json!({
                        "check": "vault_access",
                        "ok": false,
                        "message": "Failed to access vault (incorrect password or vault corrupted)"
                    }));
                    all_ok = false;
                }
            } else {
                checks.push(serde_json::json!({
                    "check": "vault_access",
                    "ok": false,
                    "message": "Password prompt failed"
                }));
                all_ok = false;
            }
        }
    }

    if json_mode {
        json_output::print_json(serde_json::json!({
            "ok": all_ok,
            "checks": checks
        }));
    } else {
        for check in &checks {
            let ok = check["ok"].as_bool().unwrap_or(false);
            let msg = check["message"].as_str().unwrap_or("");
            let icon = if ok { "✓" } else { "✗" };
            println!("{} {}", icon, msg);
        }
        if all_ok {
            println!("\nAll checks passed.");
        } else {
            println!("\nSome checks failed. See above for details.");
        }
    }

    Ok(())
}
