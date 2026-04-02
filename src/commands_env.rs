use crate::config::ProjectConfig;
use crate::env_renderer::EnvRenderer;
use crate::{core, storage, global_config};
use secrecy::SecretString;
use zeroize::Zeroizing;

fn prompt_password_for_env(json_mode: bool) -> Result<SecretString, Box<dyn std::error::Error>> {
    #[cfg(test)]
    if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        return Ok(SecretString::new(test_password));
    }

    let prompt_str = if json_mode { "" } else { "Enter Master Password: " };
    let password = rpassword::prompt_password(prompt_str)?;
    let password_raw = Zeroizing::new(password);
    Ok(SecretString::new(password_raw.trim().to_string()))
}

/// Handle `aikey env generate` command
pub fn handle_env_generate(
    dry_run: bool,
    env_file_override: Option<&str>,
    json_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, config) = ProjectConfig::discover()?
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No aikey.config.json found")) as Box<dyn std::error::Error>)?;

    let env_target = env_file_override.unwrap_or(&config.env.target);
    let env_path = std::path::Path::new(env_target);

    // Get current profile
    let password = prompt_password_for_env(json_mode)?;
    let current_profile = global_config::get_current_profile()
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error>)?
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No active profile")) as Box<dyn std::error::Error>)?;

    // Resolve environment variables
    let resolved = resolve_env_direct(&config, &current_profile, &password, Some(&config_path))?;

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

        // P0 Security Warning: Inform users that secrets are not written to .env
        let has_secrets = resolved.iter().any(|v| !matches!(v.name.as_str(), "AIKEY_PROJECT" | "AIKEY_ENV" | "AIKEY_PROFILE"));
        if has_secrets {
            println!("\n⚠️  Security Notice:");
            println!("   API keys and secrets are NOT written to .env files.");
            println!("   Only non-sensitive context (AIKEY_PROJECT, AIKEY_ENV, AIKEY_PROFILE) is written.");
            println!("   Secrets are injected at runtime via 'aikey run -- <command>'.");
        }

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
    let (config_path, config) = ProjectConfig::discover()?
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No aikey.config.json found")) as Box<dyn std::error::Error>)?;

    // Get current profile
    let password = prompt_password_for_env(json_mode)?;
    let current_profile = global_config::get_current_profile()
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error>)?
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No active profile")) as Box<dyn std::error::Error>)?;

    // Resolve environment variables
    let resolved = resolve_env_direct(&config, &current_profile, &password, Some(&config_path))?;

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
        // Check if we're being eval'd (output would be shell commands)
        let is_eval_mode = std::env::var("AIKEY_INJECT_MODE").unwrap_or_default() == "eval";

        if is_eval_mode {
            eprintln!("❌ ERROR: Plaintext shell injection is not supported in this Stage 0 Rust CLI.");
            eprintln!();
            eprintln!("   'aikey env inject' in eval mode would expose secrets in your shell.");
            eprintln!();
            eprintln!("   Use 'aikey run -- <command>' instead for secure injection.");
            eprintln!();
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Plaintext secret exposure is not supported (use aikey run instead)"
            )));
        }

        // Human-readable output with usage instructions
        println!("Environment Injection");
        println!("====================");
        println!("Profile: {}", current_profile);
        println!("\nVariables to inject:");

        for var in &resolved {
            let status = if var.value.is_some() { "✓" } else { "✗" };
            println!("  {} {}", status, var.name);
        }

        println!("\nSecurity Notice:");
        println!("  Direct shell injection is intentionally not supported.");
        println!("  Use 'aikey run -- <command>' to run a command with secrets injected securely.");
    }

    Ok(())
}

/// Handle `aikey env check` command
pub fn handle_env_check(json_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, config) = ProjectConfig::discover()?.ok_or_else(|| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No aikey.config.json found",
        )) as Box<dyn std::error::Error>
    })?;

    // Get current profile
    let password = prompt_password_for_env(json_mode)?;
    let current_profile = global_config::get_current_profile()
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error>)?
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No active profile")) as Box<dyn std::error::Error>)?;

    // Resolve environment variables
    let resolved = resolve_env_direct(&config, &current_profile, &password, Some(&config_path))?;

    let total = resolved.len();
    let satisfied: Vec<_> = resolved.iter().filter(|v| v.value.is_some()).collect();
    let missing: Vec<_> = resolved.iter().filter(|v| v.value.is_none()).collect();
    let satisfied_count = satisfied.len();
    let missing_count = missing.len();

    if json_mode {
        let response = serde_json::json!({
            "ok": missing_count == 0,
            "profile": current_profile,
            "total": total,
            "satisfied": satisfied_count,
            "missing": missing_count,
            "missing_vars": missing.iter().map(|v| &v.name).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("Environment Check");
        println!("=================");
        println!("Profile: {}", current_profile);
        println!("Status: {}/{} variables satisfied", satisfied_count, total);

        if !missing.is_empty() {
            println!("\nMissing variables:");
            for var in &missing {
                println!("  ✗ {}", var.name);
            }
            println!("\nTo configure these variables:");
            println!("  • Add keys to your local vault: 'aikey add <provider>:<alias>'");
            println!("  • Run 'aikey project map' / 'aikey provider add' to bind vars to keys");
            println!("  • Then run 'aikey env generate' to create non-sensitive placeholders in .env");
        } else {
            println!("\n✓ All required variables are configured");
        }
    }

    // Exit with code 2 if there are missing vars, 0 if all satisfied
    if missing_count > 0 {
        std::process::exit(2);
    }

    Ok(())
}

/// Handle `aikey env inject -- <command>` — run a command with project env vars injected.
/// P0-B1: MUST be equivalent to `aikey run -- <cmd>` (same implementation path, same semantics).
pub fn handle_env_run(
    command: &[String],
    json_mode: bool,
    logical_model: Option<&str>,
    tenant: Option<&str>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, config) = ProjectConfig::discover()?
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No aikey.config.json found")) as Box<dyn std::error::Error>)?;

    // P0-B1: env inject -- <cmd> uses the same execution path as run -- <cmd>
    // This ensures: same injection-set algorithm, same dry-run contract, same exit codes, same events
    if dry_run {
        // Dry-run mode: show what would be injected without executing
        let infos = crate::executor::dry_run_project_config(&config, logical_model, tenant)?;

        if json_mode {
            crate::json_output::print_json(serde_json::json!({
                "dry_run": true,
                "command": command,
                "injections": infos
            }));
        } else {
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
            println!("Note: Secret values are hidden. Use 'aikey env inject' without --dry-run to execute.");
        }
        Ok(())
    } else {
        // Execute mode: run the command with injected secrets
        let password = prompt_password_for_env(json_mode)?;
        match crate::executor::run_with_project_config(&config, &password, command, json_mode, logical_model, tenant) {
            Ok((_, exit_code)) => {
                if exit_code != 0 {
                    std::process::exit(exit_code);
                }
                Ok(())
            }
            Err(e) => {
                // Propagate non-zero exit codes from the subprocess
                if let Some(code_str) = e.strip_prefix("Command exited with code ") {
                    std::process::exit(code_str.parse::<i32>().unwrap_or(1));
                }
                Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error>)
            }
        }
    }
}

/// Resolve environment variables directly
fn resolve_env_direct(
    config: &ProjectConfig,
    _current_profile: &str,
    password: &SecretString,
    _config_path: Option<&std::path::Path>,
) -> Result<Vec<crate::env_resolver::ResolvedVar>, Box<dyn std::error::Error>> {
    let conn = storage::open_connection()
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error>)?;
    let context = core::Core::resolve_environment_with_config(&conn, password, config)
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error>)?;

    Ok(context.resolved_vars)
}
