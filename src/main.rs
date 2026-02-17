mod storage;
mod crypto;
mod executor;
mod synapse;
mod audit;
mod ratelimit;

use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use std::env;
use std::io::{self, Write};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "ak", about = "AIKeyLabs AK - Zero-Trust Executor", version = "0.1.0")]
struct Cli {
    /// Read password from stdin instead of prompting (for automation/testing)
    #[arg(long, global = true)]
    password_stdin: bool,

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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            let password = prompt_password_secure("Set Master Password: ", cli.password_stdin)?;
            let mut salt = [0u8; 16];
            crypto::generate_salt(&mut salt)?;
            println!("Initializing vault...");
            storage::initialize_vault(&salt, &password)?;
            audit::initialize_audit_log()?;
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Init, None, true);
            println!("Vault initialized successfully!");
        }
        Commands::Add { alias } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin)?;

            // Check for test environment variable first
            let secret = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                Zeroizing::new(test_secret)
            } else {
                // Secure secret input with explicit flush
                print!("Enter Secret: ");
                io::stdout().flush()?;

                let mut secret = Zeroizing::new(String::new());
                io::stdin().read_line(&mut secret)?;
                secret
            };

            let result = executor::add_secret(&alias, secret.trim(), &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Add, Some(&alias), result.is_ok());
            result?;
            eprintln!("Secret '{}' added successfully", alias);
        }
        Commands::Get { alias, timeout } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin)?;
            let result = executor::get_secret(&alias, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Get, Some(&alias), result.is_ok());
            let secret = result?;

            // Check if clipboard should be disabled (for testing)
            if std::env::var("AK_NO_CLIPBOARD").is_ok() {
                println!("{}", secret.as_str());
            } else {
                // Copy to clipboard
                executor::copy_to_clipboard(&secret)?;
                println!("Secret copied to clipboard.");

                // Auto-clear clipboard after timeout (if enabled)
                if timeout > 0 {
                    println!("Clipboard will be cleared in {} seconds...", timeout);
                    executor::schedule_clipboard_clear(timeout);
                }
            }
        }
        Commands::Delete { alias } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin)?;
            let result = executor::delete_secret(&alias, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Delete, Some(&alias), result.is_ok());
            result?;
            println!("Secret deleted.");
        }
        Commands::List => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin)?;
            let result = executor::list_secrets(&password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::List, None, result.is_ok());
            let entries = result?;

            if entries.is_empty() {
                println!("No secrets stored.");
            } else {
                println!("Stored secrets:");
                for entry in entries {
                    println!("  {}", entry);
                }
            }
        }
        Commands::Update { alias } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin)?;

            // Check for test environment variable first
            let secret = if let Ok(test_secret) = env::var("AK_TEST_SECRET") {
                Zeroizing::new(test_secret)
            } else {
                // Secure secret input with explicit flush
                print!("Enter New Secret: ");
                io::stdout().flush()?;

                let mut secret = Zeroizing::new(String::new());
                io::stdin().read_line(&mut secret)?;
                secret
            };

            let result = executor::update_secret(&alias, secret.trim(), &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Update, Some(&alias), result.is_ok());
            result?;
            eprintln!("Secret '{}' updated successfully", alias);
        }
        Commands::Export { pattern, output } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin)?;
            let output_path = std::path::Path::new(&output);

            let result = synapse::export_vault(&pattern, output_path, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Export, Some(&pattern), result.is_ok());
            let count = result?;
            println!("Exported {} secret(s) to {}", count, output);
        }
        Commands::Import { file } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin)?;
            let input_path = std::path::Path::new(&file);

            let result = synapse::import_vault(input_path, &password);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Import, Some(&file), result.is_ok());
            let import_result = result?;
            eprintln!("Import complete:");
            eprintln!("  Added: {}", import_result.added);
            eprintln!("  Updated: {}", import_result.updated);
            eprintln!("  Skipped: {}", import_result.skipped);
        }
        Commands::Exec { env_mappings, command } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin)?;

            if command.is_empty() {
                return Err("No command specified. Use -- to separate command from flags.".into());
            }

            let result = executor::exec_with_env(&env_mappings, &password, &command);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Exec, None, result.is_ok());
            result?;
        }
        Commands::Run { command } => {
            let password = prompt_password_secure("Enter Master Password: ", cli.password_stdin)?;

            if command.is_empty() {
                return Err("No command specified. Use -- to separate command from flags.".into());
            }

            let result = executor::run_with_all_secrets(&password, &command);
            let _ = audit::log_audit_event(&password, audit::AuditOperation::Exec, None, result.is_ok());
            result?;
        }
        Commands::ChangePassword => {
            let old_password = prompt_password_secure("Enter Current Master Password: ", cli.password_stdin)?;
            let new_password = prompt_password_secure("Enter New Master Password: ", false)?;
            let confirm_password = prompt_password_secure("Confirm New Master Password: ", false)?;

            if new_password.expose_secret() != confirm_password.expose_secret() {
                return Err("Passwords do not match".into());
            }

            println!("Changing master password...");
            let result = storage::change_password(&old_password, &new_password);
            let _ = audit::log_audit_event(&old_password, audit::AuditOperation::Init, None, result.is_ok());
            result?;
            println!("Master password changed successfully!");
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
fn prompt_password_secure(prompt: &str, password_stdin: bool) -> io::Result<SecretString> {
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

    // Explicit flush to ensure prompt is visible and TTY is clean
    print!("{}", prompt);
    io::stdout().flush()?;

    // Read password into Zeroizing container IMMEDIATELY
    let mut password_raw = Zeroizing::new(String::new());
    io::stdin().read_line(&mut password_raw)?;

    // Trim and convert to SecretString while maintaining zeroizing protection
    let trimmed = password_raw.trim().to_string();
    let secret = SecretString::new(trimmed);

    // password_raw is automatically zeroized when it goes out of scope
    Ok(secret)
}
