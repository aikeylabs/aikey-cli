mod storage;
mod crypto;
mod executor;
mod synapse;
mod audit;
mod ratelimit;
mod json_output;
mod error_codes;
mod config;
mod env_resolver;
mod env_renderer;
mod commands_project;
mod commands_env;
mod profiles;
mod core;
mod global_config;
mod providers;
mod resolver;
mod events;

use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use std::env;
use std::io::{self, Write};
use zeroize::Zeroizing;
use rpassword::prompt_password;
use error_codes::msgs;

#[derive(Parser)]
#[command(name = "aikey", about = "AiKey - Secure local-first secret management", version = "0.2.0", disable_version_flag = true)]
struct Cli {
    /// Read password from stdin instead of prompting (for automation/testing)
    #[arg(long, global = true)]
    password_stdin: bool,

    /// Output in JSON format (where supported)
    #[arg(long, global = true)]
    json: bool,

    /// Print version information
    #[arg(short = 'V', long)]
    version: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add {
        alias: String,
    },
    Get {
        alias: String,
        /// Clipboard auto-clear timeout in seconds (default: 30, 0 to disable)
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },
    Delete {
        alias: String,
    },
    List,
    Update {
        alias: String,
    },
    Export {
        /// Pattern to match secrets (e.g., "*", "api_*")
        pattern: String,
        /// Output file path (.akb format)
        output: String,
    },
    Import {
        /// Input file path (.akb format)
        file: String,
    },
    /// Execute a command with secrets injected as environment variables
    Exec {
        /// Environment variable mappings in the form ENV_VAR=alias
        #[arg(short, long = "env", value_name = "ENV_VAR=alias")]
        env_mappings: Vec<String>,
        /// The command to execute (use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Execute a command with all secrets automatically injected as environment variables
    Run {
        /// Resolve a specific provider's key and inject it (e.g. openai, anthropic)
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,

        /// Logical model name for narrowing injection (e.g. chat-main, embeddings)
        #[arg(long, value_name = "LOGICAL_MODEL")]
        logical_model: Option<String>,

        /// Model hint passed through to the process (sets AIKEY_MODEL env var)
        #[arg(long, value_name = "MODEL")]
        model: Option<String>,

        /// Tenant override for multi-tenant key resolution
        #[arg(long, value_name = "TENANT")]
        tenant: Option<String>,

        /// Show what would be resolved without executing the command
        #[arg(long)]
        dry_run: bool,

        /// The command to execute (use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Change the master password
    ChangePassword,
    /// Secret management commands (Platform API v0.2)
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Profile management commands
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Environment variable management commands
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },
    /// Project configuration commands
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Provider management commands
    Provider {
        #[command(subcommand)]
        action: ProviderAction,
    },
    /// Quick setup wizard for new projects
    Quickstart,
    /// Initialize vault and configure first profile (alias for init + quickstart)
    Setup,
    /// Show local usage statistics
    Stats,
    /// Show recent run/exec event log
    Logs {
        /// Number of entries to show (default: 20)
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },
    /// Manage API keys (rotate, etc.)
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Run diagnostics and health checks
    Doctor,
    /// Show project/env/profile status and resolution summary (no secrets)
    Status,
    /// Start an interactive shell with non-sensitive context (advanced mode)
    Shell,
}

#[derive(Subcommand)]
enum KeyAction {
    /// Rotate a secret to a new value
    Rotate {
        /// Secret name/alias to rotate
        name: String,
        /// Read new value from stdin instead of interactive prompt
        #[arg(long)]
        from_stdin: bool,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Set a secret value (reads from stdin for security)
    Set {
        /// Secret name/alias
        name: String,
        /// Read secret value from stdin
        #[arg(long)]
        from_stdin: bool,
    },
    /// Upsert a secret value (reads from stdin for security)
    Upsert {
        /// Secret name/alias
        name: String,
        /// Read secret value from stdin
        #[arg(long)]
        from_stdin: bool,
    },
    /// List all secrets (metadata only)
    List,
    /// Delete a secret
    Delete {
        /// Secret name/alias
        name: String,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// List all profiles
    List,
    /// Switch to a different profile
    Use { name: String },
    /// Show profile details
    Show { name: String },
    /// Show current active profile
    Current,
    /// Create a new profile
    Create { name: String },
    /// Delete a profile
    Delete { name: String },
}

#[derive(Subcommand)]
enum EnvAction {
    /// Generate or update .env file from project config
    Generate {
        /// Preview changes without writing
        #[arg(long)]
        dry_run: bool,
        /// Override the target .env file path
        #[arg(long)]
        env_file: Option<String>,
    },
    /// Run a command with secrets injected, or show an injection preview
    Inject {
        /// Command to run with secrets injected (use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
        /// Logical model name for narrowing injection (e.g. chat-main, embeddings)
        #[arg(long, value_name = "LOGICAL_MODEL")]
        logical_model: Option<String>,
        /// Tenant override for multi-tenant key resolution
        #[arg(long, value_name = "TENANT")]
        tenant: Option<String>,
        /// Show what would be resolved without executing the command
        #[arg(long)]
        dry_run: bool,
    },
    /// Check if all required environment variables can be resolved
    Check,
    /// Switch the active logical environment (e.g. dev, staging, prod)
    Use {
        /// Environment name to activate
        name: String,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// Initialize a new project configuration
    Init,
    /// Show project configuration status
    Status,
    /// Map a required variable to a vault alias in the project config
    Map {
        /// Environment variable name (e.g. OPENAI_API_KEY)
        var: String,
        /// Vault alias to bind it to (e.g. openai-work)
        alias: String,
        /// Logical environment name for envMappings (e.g. dev, prod)
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
        /// Provider name for envMappings entry (e.g. openai)
        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,
        /// Concrete model ID for envMappings entry (e.g. gpt-4o-mini)
        #[arg(long, value_name = "MODEL")]
        model: Option<String>,
        /// Vault key alias for envMappings entry (overrides positional alias for envMappings)
        #[arg(long = "key-alias", value_name = "ALIAS")]
        key_alias: Option<String>,
        /// Provider-specific model implementation ID (e.g. gpt-4o-mini)
        #[arg(long, value_name = "IMPL")]
        impl_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProviderAction {
    /// Add a provider to the project config
    Add {
        /// Provider name (e.g. openai, anthropic)
        name: String,
        /// Vault alias for the provider's API key
        #[arg(long, value_name = "ALIAS")]
        key_alias: String,
        /// Default model for this provider
        #[arg(long, value_name = "MODEL")]
        default_model: Option<String>,
    },
    /// Remove a provider from the profile config
    Rm {
        /// Provider name to remove
        name: String,
    },
    /// List providers in the project config
    Ls,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Handle --version flag
    if cli.version {
        const VERSION: &str = env!("CARGO_PKG_VERSION");
        if cli.json {
            json_output::success(serde_json::json!({
                "version": VERSION
            }));
        } else {
            println!("aikey {}", VERSION);
        }
        return Ok(());
    }

    // Ensure a command was provided
    if cli.command.is_none() {
        if cli.json {
            json_output::error("No command specified. Use --help for usage information.", 1);
        } else {
            eprintln!("Error: No command specified. Use --help for usage information.");
            std::process::exit(1);
        }
    }

    // Wrapper to handle JSON error output
    if let Err(e) = run_command(&cli) {
        if cli.json {
            json_output::error(&e.to_string(), 1);
        } else {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Handle `aikey stats` command
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
    if let Some(config_dir) = dirs::config_dir() {
        let config_file = config_dir.join("aikey").join("config.json");
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
    let vault_exists = if let Some(config_dir) = dirs::config_dir() {
        let vault_path = config_dir.join("aikey").join("vault.db");
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
    match command {
        Commands::Init => {
            let password = prompt_password_secure("Set Master Password: ", cli.password_stdin, cli.json)?;
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
        Commands::Add { alias } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

            // Check for test environment variable first
            let secret = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                Zeroizing::new(test_secret)
            } else {
                // Secure secret input with explicit flush
                if !cli.json {
                    print!("Enter Secret: ");
                    io::stdout().flush()?;
                }

                let mut secret = Zeroizing::new(String::new());
                io::stdin().read_line(&mut secret)?;
                secret
            };

            let result = executor::add_secret(alias, secret.trim(), &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Add, Some(alias), result.is_ok());

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
                    "message": "Secret added successfully"
                }));
            } else {
                eprintln!("Secret '{}' added successfully", alias);
            }
        }
        Commands::Get { alias, timeout } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;
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
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;
            let result = executor::delete_secret(alias, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Delete, Some(alias), result.is_ok());

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
                    "message": "Secret deleted successfully"
                }));
            } else {
                println!("Secret deleted.");
            }
        }
        Commands::List => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

            if cli.json {
                // JSON mode: return array of objects with metadata
                let result = executor::list_secrets_with_metadata(&password);
                let _ = audit::log_audit_event(&password, audit::AuditOperation::List, None, result.is_ok());

                match result {
                    Ok(entries) => {
                        json_output::success(serde_json::json!({
                            "secrets": entries
                        }));
                    }
                    Err(err) => {
                        json_output::error(&err, 1);
                    }
                }
            } else {
                // Text mode: return simple list of aliases
                let result = executor::list_secrets(&password);
                let _ = audit::log_audit_event(&password, audit::AuditOperation::List, None, result.is_ok());

                let entries = match result {
                    Ok(e) => e,
                    Err(err) => {
                        return Err(err.into());
                    }
                };

                // Human-readable output
                if entries.is_empty() {
                    println!("No secrets stored.");
                } else {
                    println!("Stored secrets:");
                    for entry in entries {
                        println!("  {}", entry);
                    }
                }
            }
        }
        Commands::Update { alias } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

            // Check for test environment variable first
            let secret = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                Zeroizing::new(test_secret)
            } else {
                // Secure secret input with explicit flush
                if !cli.json {
                    print!("Enter New Secret: ");
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
                    "message": "Secret updated successfully"
                }));
            } else {
                eprintln!("Secret '{}' updated successfully", alias);
            }
        }
        Commands::Export { pattern, output } => {
            let vault_password = prompt_password_secure("Enter Vault Master Password: ", cli.password_stdin, cli.json)?;
            let export_password = prompt_password_secure("Enter Export Password: ", cli.password_stdin, cli.json)?;
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
        Commands::Import { file } => {
            let export_password = prompt_password_secure("Enter Export Password: ", cli.password_stdin, cli.json)?;
            let vault_password = prompt_password_secure("Enter Vault Master Password: ", cli.password_stdin, cli.json)?;
            let input_path = std::path::Path::new(file);

            let result = synapse::import_vault(input_path, &export_password, &vault_password);
            let _ = audit::log_audit_event(&vault_password, audit::AuditOperation::Import, Some(file), result.is_ok());

            let import_result = match result {
                Ok(r) => r,
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
                    "added": import_result.added,
                    "updated": import_result.updated,
                    "skipped": import_result.skipped
                }));
            } else {
                eprintln!("Import complete:");
                eprintln!("  Added: {}", import_result.added);
                eprintln!("  Updated: {}", import_result.updated);
                eprintln!("  Skipped: {}", import_result.skipped);
            }
        }
        Commands::Exec { env_mappings, command } => {
            if command.is_empty() {
                let err_msg = "No command specified. Use -- to separate command from flags.";
                if cli.json {
                    json_output::error(err_msg, 1);
                } else {
                    return Err(err_msg.into());
                }
            }

            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

            let result = executor::exec_with_env(env_mappings, &password, command);

            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }
        }
        Commands::Run { provider, logical_model, model, tenant, dry_run, command } => {
            if command.is_empty() {
                let err_msg = "No command specified. Use -- to separate command from flags.";
                if cli.json {
                    json_output::error_stderr(err_msg, 1);
                } else {
                    return Err(err_msg.into());
                }
            }

            // P1-Q2: Tenant precedence: --tenant > AIKEY_TENANT env var
            let env_tenant = std::env::var("AIKEY_TENANT").ok();
            let resolved_tenant = tenant.as_deref().or(env_tenant.as_deref());

            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

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
                        return Err(msgs::NO_CONFIG_FOUND_HINT.into());
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
                    // No --provider: use project config to inject all configured provider keys
                    let project_config = config::ProjectConfig::discover()
                        .ok()
                        .flatten()
                        .map(|(_, cfg)| cfg);

                    if let Some(cfg) = project_config.as_ref() {
                        executor::run_with_project_config(cfg, &password, command, cli.json, logical_model.as_deref(), resolved_tenant)
                    } else {
                        return Err(msgs::NO_CONFIG_FOUND_HINT.into());
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
        }
        Commands::ChangePassword => {
            let old_password = prompt_password_secure("Enter Current Master Password: ", cli.password_stdin, cli.json)?;
            let new_password = prompt_password_secure("Enter New Master Password: ", false, cli.json)?;
            let confirm_password = prompt_password_secure("Confirm New Master Password: ", false, cli.json)?;

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

            if cli.json {
                json_output::success(serde_json::json!({
                    "message": "Master password changed successfully"
                }));
            } else {
                println!("Master password changed successfully!");
            }
        }
        Commands::Secret { action } => {
            match action {
                SecretAction::Set { name, from_stdin } => {
                    if !from_stdin {
                        let err_msg = "The --from-stdin flag is required for security. Secret values must not be passed via command-line arguments.";
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

                    let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

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
                        let err_msg = format!("Secret '{}' already exists", name);
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

                    // Read secret value from stdin
                    let mut secret = Zeroizing::new(String::new());
                    io::stdin().read_line(&mut secret)?;
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
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("Secret '{}' set successfully", name);
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
                SecretAction::Upsert { name, from_stdin } => {
                    if !from_stdin {
                        let err_msg = "The --from-stdin flag is required for security. Secret values must not be passed via command-line arguments.";
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

                    let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

                    let mut secret = Zeroizing::new(String::new());
                    io::stdin().read_line(&mut secret)?;
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
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("Secret '{}' upserted successfully", name);
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
                    let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

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
                                println!("No secrets stored.");
                            } else {
                                println!("Stored secrets:");
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
                    let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

                    let result = executor::delete_secret(name, &password);
                    let _ = audit::log_audit_event(&password, audit::AuditOperation::Delete, Some(name), result.is_ok());

                    match result {
                        Ok(_) => {
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "name": name
                                }));
                            } else {
                                println!("Secret '{}' deleted successfully", name);
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
        Commands::Profile { action } => {
            match action {
                ProfileAction::List => {
                    let profiles = storage::get_all_profiles()
                        .map(|ps| ps.into_iter().map(|p| p.name).collect::<Vec<_>>());
                    match profiles {
                        Ok(profiles) => {
                            if cli.json {
                                let profiles_json: Vec<_> = profiles
                                    .iter()
                                    .map(|name| serde_json::json!({
                                        "name": name,
                                        "description": serde_json::Value::Null
                                    }))
                                    .collect();
                                json_output::print_json(serde_json::Value::Array(profiles_json));
                            } else {
                                if profiles.is_empty() {
                                    println!("No profiles configured.");
                                } else {
                                    println!("Profiles:");
                                    for profile in profiles {
                                        println!("  {}", profile);
                                    }
                                }
                            }
                        }
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
                    }
                }
                ProfileAction::Use { name } => {
                    match storage::set_active_profile(name) {
                        Ok(profile) => {
                            let _ = global_config::set_current_profile(&profile.name);
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "profile": profile.name
                                }));
                            } else {
                                println!("Switched to profile: {}", profile.name);
                            }
                        }
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
                    }
                }
                ProfileAction::Show { name } => {
                    let profiles = storage::get_all_profiles()
                        .map(|ps| ps.into_iter().map(|p| p.name).collect::<Vec<_>>());
                    match profiles {
                        Ok(profiles) => {
                            if profiles.contains(name) {
                                if cli.json {
                                    json_output::success(serde_json::json!({
                                        "profile": name
                                    }));
                                } else {
                                    println!("Profile: {}", name);
                                }
                            } else {
                                let err_msg = format!("Profile '{}' not found", name);
                                if cli.json {
                                    json_output::error(&err_msg, 1);
                                } else {
                                    return Err(err_msg.into());
                                }
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                json_output::error(&e, 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                ProfileAction::Current => {
                    match global_config::get_current_profile() {
                        Ok(Some(profile_name)) => {
                            if cli.json {
                                json_output::print_json(serde_json::json!({
                                    "ok": true,
                                    "profile": profile_name
                                }));
                            } else {
                                println!("Current profile: {}", profile_name);
                            }
                        }
                        Ok(None) => {
                            if cli.json {
                                json_output::print_json_exit(serde_json::json!({
                                    "ok": false,
                                    "profile": serde_json::Value::Null,
                                    "code": error_codes::ErrorCode::NoActiveProfile.as_str()
                                }), 1);
                            } else {
                                return Err("No active profile set".into());
                            }
                        }
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
                    }
                }
                ProfileAction::Create { name } => {
                    match storage::create_profile(name) {
                        Ok(profile) => {
                            if cli.json {
                                json_output::success(serde_json::json!({
                                    "ok": true,
                                    "profile": profile.name
                                }));
                            } else {
                                println!("Profile '{}' created successfully", profile.name);
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                json_output::error(&e, 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
                ProfileAction::Delete { name } => {
                    match storage::delete_profile(name) {
                        Ok(_) => {
                            if cli.json {
                                json_output::success(serde_json::json!({
                                    "ok": true,
                                    "message": format!("Profile '{}' deleted", name)
                                }));
                            } else {
                                println!("Profile '{}' deleted successfully", name);
                            }
                        }
                        Err(e) => {
                            if cli.json {
                                json_output::error(&e, 1);
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                }
            }
        }
        Commands::Env { action } => {
            match action {
                EnvAction::Generate { dry_run, env_file } => {
                    commands_env::handle_env_generate(*dry_run, env_file.as_deref(), cli.json)?;
                }
                EnvAction::Inject { command, logical_model, tenant, dry_run } => {
                    if command.is_empty() {
                        commands_env::handle_env_inject(cli.json)?;
                    } else {
                        // P0-B1: env inject -- <cmd> MUST be equivalent to run -- <cmd>
                        // Apply same tenant precedence: --tenant > AIKEY_TENANT env var
                        let env_tenant = std::env::var("AIKEY_TENANT").ok();
                        let resolved_tenant = tenant.as_deref().or(env_tenant.as_deref());

                        commands_env::handle_env_run(command, cli.json, logical_model.as_deref(), resolved_tenant, *dry_run)?;
                    }
                }
                EnvAction::Check => {
                    commands_env::handle_env_check(cli.json)?;
                }
                EnvAction::Use { name } => {
                    global_config::set_current_env(name)
                        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                    if cli.json {
                        json_output::print_json(serde_json::json!({
                            "ok": true,
                            "env": name
                        }));
                    } else {
                        println!("Switched to environment: {}", name);
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
        Commands::Provider { action } => {
            match action {
                ProviderAction::Add { name, key_alias, default_model } => {
                    commands_project::handle_provider_add(name, key_alias, default_model.as_deref(), cli.json)?;
                }
                ProviderAction::Rm { name } => {
                    commands_project::handle_provider_rm(name, cli.json)?;
                }
                ProviderAction::Ls => {
                    commands_project::handle_provider_ls(cli.json)?;
                }
            }
        }
        Commands::Quickstart => {
            commands_project::handle_quickstart(cli.json)?;
        }
        Commands::Setup => {
            commands_project::handle_setup(cli.json)?;
        }
        Commands::Stats => {
            handle_stats(cli.json)?;
        }
        Commands::Key { action } => {
            match action {
                KeyAction::Rotate { name, from_stdin } => {
                    let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

                    let new_value = if *from_stdin {
                        let mut buf = Zeroizing::new(String::new());
                        io::stdin().read_line(&mut buf)?;
                        buf
                    } else {
                        let val = rpassword::prompt_password(format!("New value for '{}': ", name))
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
            }
        }
        Commands::Doctor => {
            commands_project::handle_doctor(cli.json)?;
        }
        Commands::Status => {
            commands_project::handle_project_status(cli.json)?;
        }
        Commands::Shell => {
            handle_shell_command(cli.json)?;
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
    }
    Ok(())
}

/// Secure password prompt with Zeroizing protection
///
/// SECURITY HARDENING:
/// - Wraps password in Zeroizing<String> IMMEDIATELY upon input
/// P1-Q3: Handle aikey shell command
/// Starts an interactive subshell with non-sensitive context only.
/// Secrets are NOT exported as long-lived env vars; each command uses aikey run injection.
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

/// - Disables TTY echo for interactive password entry
/// - Converts to SecretString only after zeroizing wrapper is in place
/// - Ensures raw password string is wiped from memory on scope exit
/// - Supports AK_TEST_PASSWORD environment variable for testing
/// - Supports reading from stdin when password_stdin is true
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

    // Interactive TTY path: disable echo using rpassword
    // In JSON mode我们依然不打印提示文案，避免污染机器可读输出
    let prompt_str = if json_mode { "" } else { prompt };
    let password = prompt_password(prompt_str)?;

    // Wrap in Zeroizing for additional in-memory protection
    let password_raw = Zeroizing::new(password);
    let trimmed = password_raw.trim().to_string();
    Ok(SecretString::new(trimmed))
}
