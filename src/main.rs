mod crypto;
mod executor;
mod storage;
mod synapse;

use clap::{Parser, Subcommand};
use secrecy::SecretString;
use std::io::{self, Write};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "ak", about = "AiKeyLabs - Neural Secret Vault", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add { alias: String },
    Get { alias: String },
    Delete { alias: String },
    List,
    Update { alias: String },
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
    Run {
        aliases: Vec<String>,
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Execute a command with secrets injected as environment variables
    Exec {
        /// Environment variable mappings in the form ENV_VAR=alias
        #[arg(short, long = "env", value_name = "ENV_VAR=alias")]
        env_mappings: Vec<String>,
        /// The command to execute (use -- to separate)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            println!("Initializing vault...");
            let password = prompt_password("Set Master Password: ")?;
            let mut salt = [0u8; 16];
            crypto::generate_salt(&mut salt)?;
            // Pass password directly instead of using environment variable
            storage::initialize_vault(&salt, &password)?;
            println!("Vault initialized successfully!");
        }
        Commands::Add { alias } => {
            let password = prompt_password("Enter Master Password: ")?;
            print!("Enter Secret: ");
            io::stdout().flush()?;

            // Use Zeroizing to protect secret in memory
            let mut secret = Zeroizing::new(String::new());
            io::stdin().read_line(&mut secret)?;

            executor::add_secret(&alias, secret.trim(), &password)?;
            println!("Secret added successfully!");
        }
        Commands::Get { alias } => {
            let password = prompt_password("Enter Master Password: ")?;

            // get_secret now returns Zeroizing<String>
            let secret = executor::get_secret(&alias, &password)?;
            println!("Secret: {}", &*secret);
            // secret is automatically zeroized on drop
        }
        Commands::Delete { alias } => {
            let password = prompt_password("Enter Master Password: ")?;
            executor::delete_secret(&alias, &password)?;
            println!("Secret deleted.");
        }
        Commands::List => {
            // Refactored to use executor layer with password verification
            let password = prompt_password("Enter Master Password: ")?;
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
            let password = prompt_password("Enter Master Password: ")?;
            print!("Enter New Secret: ");
            io::stdout().flush()?;

            let mut secret = Zeroizing::new(String::new());
            io::stdin().read_line(&mut secret)?;

            executor::update_secret(&alias, secret.trim(), &password)?;
            println!("Secret updated successfully!");
        }
        Commands::Export { pattern, output } => {
            let password = prompt_password("Enter Master Password: ")?;
            let output_path = std::path::Path::new(&output);

            let count = synapse::export_vault(&pattern, output_path, &password)?;
            println!("Exported {} secret(s) to {}", count, output);
        }
        Commands::Import { file } => {
            let password = prompt_password("Enter Master Password: ")?;
            let input_path = std::path::Path::new(&file);

            let result = synapse::import_vault(input_path, &password)?;
            println!("Import complete:");
            println!("  Added: {}", result.added);
            println!("  Updated: {}", result.updated);
            println!("  Skipped: {}", result.skipped);
        }
        Commands::Run { aliases, command } => {
            let password = prompt_password("Enter Master Password: ")?;
            let command_str = command.join(" ");

            executor::run_with_secrets(&aliases, &password, &command_str)?;
        }
        Commands::Exec { env_mappings, command } => {
            let password = prompt_password("Enter Master Password: ")?;

            if command.is_empty() {
                return Err("No command specified. Use -- to separate command from flags.".into());
            }

            executor::exec_with_env(&env_mappings, &password, &command)?;
        }
    }
    Ok(())
}

fn prompt_password(prompt: &str) -> io::Result<SecretString> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut pass = String::new();
    io::stdin().read_line(&mut pass)?;
    Ok(SecretString::new(pass.trim().to_string()))
}
