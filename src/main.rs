mod storage;
mod crypto;
mod executor;
mod synapse;

use clap::{Parser, Subcommand};
use secrecy::SecretString;
use std::io::{self, Write};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "ak", about = "AIKeyLabs AK - Zero-Trust Executor", version = "0.1.0")]
struct Cli {
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
    },
    Delete {
        alias: String,
    },
    List,
    Update {
        alias: String,
    },
    Export {
        #[arg(short, long, default_value = "*")]
        pattern: String,
        #[arg(short, long)]
        output: String,
    },
    Import {
        #[arg(short, long)]
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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            println!("Initializing vault...");
            let password = prompt_password_secure("Set Master Password: ")?;
            let mut salt = [0u8; 16];
            crypto::generate_salt(&mut salt)?;
            storage::initialize_vault(&salt, &password)?;
            println!("Vault initialized successfully!");
        }
        Commands::Add { alias } => {
            let password = prompt_password_secure("Enter Master Password: ")?;

            // Secure secret input with explicit flush
            print!("Enter Secret: ");
            io::stdout().flush()?;

            let mut secret = Zeroizing::new(String::new());
            io::stdin().read_line(&mut secret)?;

            executor::add_secret(&alias, secret.trim(), &password)?;
            println!("Secret added successfully!");
        }
        Commands::Get { alias } => {
            let password = prompt_password_secure("Enter Master Password: ")?;
            let secret = executor::get_secret(&alias, &password)?;
            println!("Secret: {}", &*secret);
        }
        Commands::Delete { alias } => {
            let password = prompt_password_secure("Enter Master Password: ")?;
            executor::delete_secret(&alias, &password)?;
            println!("Secret deleted.");
        }
        Commands::List => {
            let password = prompt_password_secure("Enter Master Password: ")?;
            let entries = executor::list_secrets(&password)?;

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
            let password = prompt_password_secure("Enter Master Password: ")?;

            // Secure secret input with explicit flush
            print!("Enter New Secret: ");
            io::stdout().flush()?;

            let mut secret = Zeroizing::new(String::new());
            io::stdin().read_line(&mut secret)?;

            executor::update_secret(&alias, secret.trim(), &password)?;
            println!("Secret updated successfully!");
        }
        Commands::Export { pattern, output } => {
            let password = prompt_password_secure("Enter Master Password: ")?;
            let output_path = std::path::Path::new(&output);

            let count = synapse::export_vault(&pattern, output_path, &password)?;
            println!("Exported {} secret(s) to {}", count, output);
        }
        Commands::Import { file } => {
            let password = prompt_password_secure("Enter Master Password: ")?;
            let input_path = std::path::Path::new(&file);

            let result = synapse::import_vault(input_path, &password)?;
            println!("Import complete:");
            println!("  Added: {}", result.added);
            println!("  Updated: {}", result.updated);
            println!("  Skipped: {}", result.skipped);
        }
        Commands::Exec { env_mappings, command } => {
            let password = prompt_password_secure("Enter Master Password: ")?;

            if command.is_empty() {
                return Err("No command specified. Use -- to separate command from flags.".into());
            }

            executor::exec_with_env(&env_mappings, &password, &command)?;
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
fn prompt_password_secure(prompt: &str) -> io::Result<SecretString> {
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
