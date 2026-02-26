use crate::config::{ProjectConfig, ProviderConfig, EnvTemplate};
use crate::daemon_client::DaemonClient;
use crate::json_output;
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
        println!("  1. Set up profiles and keys using the browser extension");
        println!("  2. Run 'aikey env generate' to create your .env file");
        println!("  3. Use 'aikey project status' to check configuration");
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
    let template = template_parts.join("\n");

    let project_path = config_path.parent().and_then(|p| p.to_str());
    let config_path_str = config_path.to_str();

    let client = DaemonClient::new_default();
    let result = client.resolve_env_details(&template, project_path, config_path_str, false)?;

    let profile_name = result.get("profile_name")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let satisfied = result.get("satisfied").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let total = result.get("total").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    let mut missing_vars = Vec::new();
    if let Some(vars) = result.get("resolved_vars").and_then(|v| v.as_array()) {
        for var in vars {
            let name = var.get("name").and_then(|v| v.as_str());
            let source = var.get("source").and_then(|v| v.as_str());
            if let (Some(name), Some(source)) = (name, source) {
                if source == "Missing" {
                    missing_vars.push(name.to_string());
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
            println!("  • Run 'aikey env generate' to create/update your .env file");
            println!("  • Use 'aikey env inject' to inject secrets into your shell");
            println!("\nFor more information:");
            println!("  • Browser extension: Configure profiles and manage keys");
            println!("  • VS Code extension: Insert from AiKey, view project status");
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
        println!("\n🎉 Setup complete!");
        println!("\n📚 What's next?");
        println!("\n1. Configure your profiles and keys:");
        println!("   • Install the AiKey browser extension to manage profiles");
        println!("   • Add your API keys (OpenAI, Anthropic, etc.) to your profile");
        println!("\n2. Generate your .env file:");
        println!("   $ aikey env generate");
        println!("\n3. Inject secrets into your shell:");
        println!("   $ eval \"$(AIKEY_INJECT_MODE=eval aikey env inject)\"");
        println!("\n4. Use the VS Code extension:");
        println!("   • Install 'AiKey' from the VS Code marketplace");
        println!("   • Use 'Insert from AiKey' to insert secrets into your code");
        println!("   • View project status in the AiKey panel");
        println!("\n💡 Tip: Run 'aikey project status' anytime to check your configuration");
    }

    Ok(())
}

/// Handle `aikey setup` — alias for quickstart (initialize vault and configure first profile)
pub fn handle_setup(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    handle_quickstart(json_mode)
}

/// Handle `aikey project map` — bind a required var to a vault alias in the project config
pub fn handle_project_map(
    var: &str,
    alias: &str,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, mut config) = ProjectConfig::discover()?
        .ok_or("No aikey.config.json found")?;

    config.bindings.insert(var.to_string(), alias.to_string());

    if !config.required_vars.contains(&var.to_string()) {
        config.required_vars.push(var.to_string());
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

/// Handle `aikey provider rm` — remove a provider from the project config
pub fn handle_provider_rm(
    name: &str,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, mut config) = ProjectConfig::discover()?
        .ok_or("No aikey.config.json found")?;

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
