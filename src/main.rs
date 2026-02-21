mod storage;
mod crypto;
mod executor;
mod synapse;
mod audit;
mod ratelimit;
mod json_output;

use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use std::env;
use std::io::{self, Write};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "aikey", about = "AiKey - Secure local-first secret management", version = "0.1.0")]
struct Cli {
    /// Read password from stdin instead of prompting (for automation/testing)
    #[arg(long, global = true)]
    password_stdin: bool,

    /// Output in JSON format (where supported)
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
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
        /// The command to execute (use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Change the master password
    ChangePassword,
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
}

#[derive(Subcommand)]
enum ProfileAction {
    /// List all profiles
    List,
    /// Switch to a different profile
    Use { name: String },
    /// Show profile details
    Show { name: String },
}

#[derive(Subcommand)]
enum EnvAction {
    /// Inject secrets into environment (use 'aikey exec' for now)
    Inject,
    /// Export secrets to .env file
    Export,
    /// Check required environment variables
    Check,
}

#[derive(Subcommand)]
enum ProjectAction {
    /// Initialize a new project configuration
    Init,
    /// Show project configuration status
    Status,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

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

fn run_command(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.command {
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
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

            if command.is_empty() {
                let err_msg = "No command specified. Use -- to separate command from flags.";
                if cli.json {
                    json_output::error(err_msg, 1);
                } else {
                    return Err(err_msg.into());
                }
            }

            let result = executor::exec_with_env(env_mappings, &password, command);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Exec, None, result.is_ok());

            if let Err(e) = result {
                if cli.json {
                    json_output::error(&e, 1);
                } else {
                    return Err(e.into());
                }
            }
        }
        Commands::Run { command } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin, cli.json)?;

            if command.is_empty() {
                let err_msg = "No command specified. Use -- to separate command from flags.";
                if cli.json {
                    json_output::error_stderr(err_msg, 1);
                } else {
                    return Err(err_msg.into());
                }
            }

            let result = executor::run_with_all_secrets(&password, command, cli.json);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Exec, None, result.is_ok());

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
        Commands::Profile { action } => {
            match action {
                ProfileAction::List => {
                    if cli.json {
                        println!("[]");
                    } else {
                        println!("No profiles configured.");
                        println!("Profile management will be available in a future release.");
                    }
                }
                ProfileAction::Use { name } => {
                    // Store profile preference in config file
                    if let Some(config_dir) = dirs::config_dir() {
                        let aikey_dir = config_dir.join("aikey");
                        std::fs::create_dir_all(&aikey_dir)?;
                        let config_file = aikey_dir.join("config.json");

                        let config = serde_json::json!({
                            "current_profile": name
                        });

                        std::fs::write(config_file, serde_json::to_string_pretty(&config)?)?;
                        println!("Switched to profile: {}", name);
                        println!("Note: Profile functionality is limited in this preview.");
                    } else {
                        return Err("Could not determine config directory".into());
                    }
                }
                ProfileAction::Show { name } => {
                    if cli.json {
                        let profile_info = serde_json::json!({
                            "name": name,
                            "status": "not_implemented"
                        });
                        println!("{}", serde_json::to_string_pretty(&profile_info)?);
                    } else {
                        println!("Profile: {}", name);
                        println!("Profile details will be available in a future release.");
                    }
                }
            }
        }
        Commands::Env { action } => {
            match action {
                EnvAction::Inject => {
                    if cli.json {
                        let response = serde_json::json!({
                            "message": "Use 'aikey exec --env VAR=alias -- command' instead",
                            "status": "not_implemented"
                        });
                        println!("{}", serde_json::to_string_pretty(&response)?);
                    } else {
                        println!("Use 'aikey exec --env VAR=alias -- command' for now.");
                        println!("'aikey env inject' will be implemented in a future release.");
                    }
                }
                EnvAction::Export => {
                    if cli.json {
                        let response = serde_json::json!({
                            "status": "not_implemented"
                        });
                        println!("{}", serde_json::to_string_pretty(&response)?);
                    } else {
                        println!("Environment export is not implemented yet.");
                        println!("This feature will be available in a future release.");
                    }
                }
                EnvAction::Check => {
                    if cli.json {
                        let response = serde_json::json!({
                            "status": "not_implemented"
                        });
                        println!("{}", serde_json::to_string_pretty(&response)?);
                    } else {
                        println!("Environment check is not implemented yet.");
                        println!("This feature will be available in a future release.");
                    }
                }
            }
        }
        Commands::Project { action } => {
            match action {
                ProjectAction::Init => {
                    let config_path = std::path::Path::new("aikey.config.json");
                    if config_path.exists() {
                        return Err("aikey.config.json already exists in current directory".into());
                    }

                    let config = serde_json::json!({
                        "version": "1",
                        "project": {
                            "name": "My AI App"
                        },
                        "env": {
                            "target": ".env"
                        },
                        "requiredVars": [],
                        "defaults": {
                            "profile": "default"
                        }
                    });

                    std::fs::write(config_path, serde_json::to_string_pretty(&config)?)?;

                    if cli.json {
                        let response = serde_json::json!({
                            "status": "created",
                            "path": "aikey.config.json"
                        });
                        println!("{}", serde_json::to_string_pretty(&response)?);
                    } else {
                        println!("Created aikey.config.json in current directory");
                    }
                }
                ProjectAction::Status => {
                    let mut current_dir = std::env::current_dir()?;
                    let mut found = false;
                    let mut config_path_str = String::new();

                    loop {
                        let config_path = current_dir.join("aikey.config.json");
                        if config_path.exists() {
                            config_path_str = config_path.display().to_string();
                            found = true;
                            break;
                        }

                        if !current_dir.pop() {
                            break;
                        }
                    }

                    if cli.json {
                        let response = if found {
                            serde_json::json!({
                                "found": true,
                                "path": config_path_str
                            })
                        } else {
                            serde_json::json!({
                                "found": false
                            })
                        };
                        println!("{}", serde_json::to_string_pretty(&response)?);
                    } else {
                        if found {
                            println!("Found: {}", config_path_str);
                        } else {
                            println!("No aikey.config.json found in current directory or parent directories");
                        }
                    }
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
/// - Explicitly flushes stdout before reading to prevent TTY leaks
/// - Converts to SecretString only after zeroizing wrapper is in place
/// - Ensures raw password string is wiped from memory on scope exit
/// - Supports AK_TEST_PASSWORD environment variable for testing
/// - Supports reading from stdin when password_stdin is true
fn prompt_password_secure(prompt: &str, password_stdin: bool, json_mode: bool) -> io::Result<SecretString> {
    // Check for test password environment variable
    if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        return Ok(SecretString::new(test_password));
    }

    // If password_stdin is true, read directly from stdin without prompt
    if password_stdin {
        let mut password_raw = Zeroizing::new(String::new());
        io::stdin().read_line(&mut password_raw)?;
        let trimmed = password_raw.trim().to_string();
        return Ok(SecretString::new(trimmed));
    }

    // Only show prompt if not in JSON mode
    if !json_mode {
        print!("{}", prompt);
        io::stdout().flush()?;
    }

    // Read password into Zeroizing container IMMEDIATELY
    let mut password_raw = Zeroizing::new(String::new());
    io::stdin().read_line(&mut password_raw)?;

    // Trim and convert to SecretString while maintaining zeroizing protection
    let trimmed = password_raw.trim().to_string();
    let secret = SecretString::new(trimmed);

    // password_raw is automatically zeroized when it goes out of scope
    Ok(secret)
}
