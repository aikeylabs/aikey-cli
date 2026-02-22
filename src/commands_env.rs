use crate::config::ProjectConfig;
use crate::env_resolver::EnvResolver;
use crate::env_renderer::EnvRenderer;
use std::collections::HashMap;

/// Handle `aikey env generate` command
pub fn handle_env_generate(
    dry_run: bool,
    env_file_override: Option<&str>,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_config_path, config) = ProjectConfig::discover()?
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No aikey.config.json found")) as Box<dyn std::error::Error>)?;

    let env_target = env_file_override.unwrap_or(&config.env.target);
    let env_path = std::path::Path::new(env_target);

    // Get current profile
    let current_profile = get_current_profile()?;

    // For now, use empty profile vars (in full implementation, resolve from vault)
    let profile_vars: HashMap<String, String> = HashMap::new();

    let resolved = EnvResolver::resolve(&config, &current_profile, &profile_vars)
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error>)?;

    // Get changes summary
    let existing_content = if env_path.exists() {
        std::fs::read_to_string(env_path).ok()
    } else {
        None
    };

    let (added, updated, missing) = EnvRenderer::get_changes_summary(
        existing_content.as_deref(),
        &resolved,
    );

    if json_mode {
        let response = serde_json::json!({
            "dry_run": dry_run,
            "env_file": env_target,
            "added": added,
            "updated": updated,
            "missing": missing
        });
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    } else {
        println!("Environment Generation");
        println!("======================");
        println!("Target: {}", env_target);
        println!("Profile: {}", current_profile);

        if !added.is_empty() {
            println!("\nAdded variables:");
            for var in &added {
                println!("  + {}", var);
            }
        }

        if !updated.is_empty() {
            println!("\nUpdated variables:");
            for var in &updated {
                println!("  ~ {}", var);
            }
        }

        if !missing.is_empty() {
            println!("\nMissing values (will be empty):");
            for var in &missing {
                println!("  ? {}", var);
            }
        }

        if dry_run {
            println!("\n(dry-run mode - no changes written)");
        } else {
            // Write the file
            EnvRenderer::write_env_file(env_path, &resolved, true)?;
            println!("\n✓ Updated {}", env_target);
        }
    }

    Ok(())
}

/// Handle `aikey env inject` command
pub fn handle_env_inject(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (_config_path, config) = ProjectConfig::discover()?
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No aikey.config.json found")) as Box<dyn std::error::Error>)?;

    let current_profile = get_current_profile()?;
    let profile_vars: HashMap<String, String> = HashMap::new();

    let resolved = EnvResolver::resolve(&config, &current_profile, &profile_vars)
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error>)?;

    if json_mode {
        let vars: Vec<_> = resolved
            .iter()
            .map(|v| {
                serde_json::json!({
                    "name": v.name,
                    "set": v.value.is_some()
                })
            })
            .collect();

        let response = serde_json::json!({
            "profile": current_profile,
            "variables": vars
        });
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    } else {
        println!("Environment Injection");
        println!("====================");
        println!("Profile: {}", current_profile);
        println!("\nVariables to inject:");

        for var in &resolved {
            let status = if var.value.is_some() { "✓" } else { "✗" };
            println!("  {} {}", status, var.name);
        }

        println!("\nNote: Full env injection support coming in a future release.");
        println!("Use 'aikey exec --env VAR=alias -- command' for now.");
    }

    Ok(())
}

/// Get current profile from global config
pub fn get_current_profile() -> Result<String, Box<dyn std::error::Error>> {
    if let Some(config_dir) = dirs::config_dir() {
        let config_file = config_dir.join("aikey").join("config.json");

        if config_file.exists() {
            let content = std::fs::read_to_string(&config_file)?;

            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(profile) = config.get("current_profile").and_then(|v| v.as_str()) {
                    return Ok(profile.to_string());
                }
            }
        }
    }

    Ok("default".to_string())
}
