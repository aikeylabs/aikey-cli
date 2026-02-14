mod crypto;
mod executor;
mod storage;
mod synapse;

use clap::{Parser, Subcommand};
use secrecy::{SecretString, ExposeSecret};
use std::io::{self, Write};

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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            println!("Initializing vault...");
            let password = prompt_password("Set Master Password: ")?;
            let mut salt = [0u8; 16];
            crypto::generate_salt(&mut salt)?;
            std::env::set_var("AK_MASTER_PASSWORD", password.expose_secret());
            storage::initialize_vault(&salt)?;
            println!("Vault initialized successfully!");
        }
        Commands::Add { alias } => {
            let password = prompt_password("Enter Master Password: ")?;
            print!("Enter Secret: ");
            io::stdout().flush()?;
            let mut secret = String::new();
            io::stdin().read_line(&mut secret)?;
            executor::add_secret(&alias, secret.trim(), &password)?;
            println!("Secret added successfully!");
        }
        Commands::Get { alias } => {
            let password = prompt_password("Enter Master Password: ")?;
            let secret = executor::get_secret(&alias, &password)?;
            println!("Secret: {}", secret);
        }
        Commands::Delete { alias } => {
            let password = prompt_password("Enter Master Password: ")?;
            executor::delete_secret(&alias, &password)?;
            println!("Secret deleted.");
        }
        Commands::List => {
            let entries = storage::list_entries()?;
            for entry in entries {
                println!("{}", entry);
            }
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
