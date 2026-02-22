use crate::config::{ProjectConfig, EnvTemplate};
use crate::env_resolver::EnvResolver;
use crate::commands_env::get_current_profile;
use std::collections::HashMap;
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
    config.requiredVars = required_vars;

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
    let (config_path, config) = ProjectConfig::discover()?
        .ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No aikey.config.json found in current directory or parent directories")) as Box<dyn std::error::Error>)?;

    // Get current profile
    let current_profile = get_current_profile()?;

    // For now, we'll use an empty profile vars map since we don't have vault access here
    // In a full implementation, this would resolve from the vault
    let profile_vars: HashMap<String, String> = HashMap::new();

    let resolved = EnvResolver::resolve(&config, &current_profile, &profile_vars)?;
    let (satisfied, total) = EnvResolver::count_satisfied(&resolved);

    if json_mode {
        let response = serde_json::json!({
            "config_path": config_path.display().to_string(),
            "project_name": config.project.name,
            "profile": current_profile,
            "required_vars": config.requiredVars,
            "satisfied": satisfied,
            "total": total
        });
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    } else {
        println!("Project Configuration Status");
        println!("============================");
        println!("Config path: {}", config_path.display());
        println!("Project name: {}", config.project.name);
        println!("Current profile: {}", current_profile);
        println!("Required variables: {}/{} satisfied", satisfied, total);

        if satisfied < total {
            println!("\nMissing variables:");
            for var in &resolved {
                if var.value.is_none() {
                    println!("  - {}", var.name);
                }
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
    if !json_mode {
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
