use aikeylabs_ak::{crypto, storage, synapse, executor};
use clap::{Parser, Subcommand};
use inquire::Confirm;
use rand::RngCore;
use secrecy::SecretString;

/// AiKeyLabs - Secure local secret management CLI
#[derive(Parser)]
#[command(name = "ak")]
#[command(about = "AiKeyLabs - Secure local secret management", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the local encrypted vault
    Init,

    /// Add a new secret to the vault
    Add {
        /// Alias for the secret
        alias: String,
        /// Use clipboard content as secret value (Magic Add)
        #[arg(long)]
        magic: bool,
    },

    /// Retrieve a secret from the vault (copies to clipboard)
    Get {
        /// Alias of the secret to retrieve
        alias: String,
        /// Print secret to stdout instead of copying to clipboard
        #[arg(long)]
        print: bool,
    },

    /// List all secret aliases
    List,

    /// Delete a secret from the vault
    Delete {
        /// Alias of the secret to delete
        alias: String,
    },

    /// Update an existing secret in the vault
    Update {
        /// Alias of the secret to update
        alias: String,
        /// New secret value (if not provided, will prompt)
        value: Option<String>,
    },

    /// Run a command with secrets injected as environment variables
    Run {
        /// Command and arguments to execute (use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
    },

    /// Export secrets to an encrypted .akb file
    Export {
        /// Pattern to match secrets (e.g., "openai-*", "*")
        pattern: String,
        /// Output file path (e.g., "backup.akb")
        output: String,
    },

    /// Import secrets from an encrypted .akb file
    Import {
        /// Input file path (e.g., "backup.akb")
        input: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init => handle_init(),
        Commands::Add { alias, magic } => handle_add(&alias, magic),
        Commands::Get { alias, print } => handle_get(&alias, print),
        Commands::List => handle_list(),
        Commands::Delete { alias } => handle_delete(&alias),
        Commands::Update { alias, value } => handle_update(&alias, value),
        Commands::Run { args } => handle_run(&args),
        Commands::Export { pattern, output } => handle_export(&pattern, &output),
        Commands::Import { input } => handle_import(&input),
    };

    if let Err(e) = result {
        eprintln!("\x1b[31mError: {}\x1b[0m", e);
        std::process::exit(1);
    }
}

/// Securely prompts for a password without echoing to terminal
/// Returns a SecretString that is automatically zeroized on drop
fn prompt_password(prompt: &str) -> Result<SecretString, String> {
    eprint!("{}", prompt);
    let password = rpassword::read_password()
        .map_err(|e| format!("Failed to read password: {}", e))?;
    Ok(SecretString::new(password))
}

/// Prompts for a secret value (similar to password but returns String)
fn prompt_secret(prompt: &str) -> Result<String, String> {
    eprint!("{}", prompt);
    let secret = rpassword::read_password()
        .map_err(|e| format!("Failed to read secret: {}", e))?;
    Ok(secret)
}

fn handle_init() -> Result<(), String> {
    eprintln!("Initializing AiKeyLabs vault...");

    // Check for non-interactive mode (for testing)
    let password = if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        SecretString::new(test_password)
    } else {
        // Prompt for master password
        let password = prompt_password("Enter master password: ")?;
        let password_confirm = prompt_password("Confirm master password: ")?;

        use secrecy::ExposeSecret;
        if password.expose_secret() != password_confirm.expose_secret() {
            return Err("Passwords do not match".to_string());
        }

        password
    };

    // Generate random salt
    let mut salt = [0u8; crypto::SALT_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    // Derive key to verify password strength (and test the derivation)
    let _key = crypto::derive_key(&password, &salt)?;

    // Initialize database with salt
    storage::initialize_vault(&salt)?;

    eprintln!("✓ Vault initialized successfully at ~/.aikey/vault.db");
    eprintln!("✓ Master password set");
    eprintln!("\nYou can now add secrets with: ak add <alias>");

    Ok(())
}

fn handle_add(alias: &str, magic: bool) -> Result<(), String> {
    // Check if vault exists
    storage::ensure_vault_exists()?;

    // Check for non-interactive mode (for testing)
    let password = if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        SecretString::new(test_password)
    } else {
        // Prompt for master password
        prompt_password("Enter master password: ")?
    };

    // Get secret value
    let secret = if magic {
        // Magic Add: Use clipboard content
        executor::read_from_clipboard()?
    } else if let Ok(test_secret) = std::env::var("AK_TEST_SECRET") {
        // Non-interactive mode for testing
        test_secret
    } else {
        // Check clipboard for potential secrets
        let mut secret = String::new();
        let mut used_clipboard = false;

        if let Ok(clipboard_content) = executor::read_from_clipboard() {
            // Detect common secret patterns
            if executor::is_potential_secret(&clipboard_content) {
                let use_clipboard = Confirm::new(&format!(
                    "Detected potential secret in clipboard ({}... pattern). Use it?",
                    &clipboard_content.chars().take(10).collect::<String>()
                ))
                .with_default(true)
                .prompt()
                .unwrap_or(false);

                if use_clipboard {
                    secret = clipboard_content;
                    used_clipboard = true;
                }
            }
        }

        // If not using clipboard, prompt for secret value
        if !used_clipboard {
            eprint!("Enter secret value for '{}': ", alias);
            secret = rpassword::read_password()
                .map_err(|e| format!("Failed to read secret: {}", e))?;
        }

        secret
    };

    // Add the secret using executor (performs password verification)
    executor::add_secret(alias, &secret, &password)?;

    eprintln!("✓ Secret '{}' added successfully", alias);

    Ok(())
}

fn handle_get(alias: &str, print: bool) -> Result<(), String> {
    // Check if vault exists
    storage::ensure_vault_exists()?;

    // Check for non-interactive mode (for testing)
    let password = if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        SecretString::new(test_password)
    } else {
        // Prompt for master password
        prompt_password("Enter master password: ")?
    };

    // Get the secret using executor
    let secret_str = executor::get_secret(alias, &password)?;

    // Copy to clipboard or print to stdout
    if print {
        println!("{}", secret_str);
    } else {
        executor::copy_to_clipboard(&secret_str)?;
        eprintln!("✓ Secret '{}' copied to clipboard", alias);
    }

    Ok(())
}

fn handle_list() -> Result<(), String> {
    // Check if vault exists
    storage::ensure_vault_exists()?;

    let aliases = executor::list_secrets()?;

    if aliases.is_empty() {
        eprintln!("No secrets stored yet. Use 'ak add <alias>' to add one.");
    } else {
        eprintln!("Stored secrets:");
        for alias in aliases {
            eprintln!("  • {}", alias);
        }
    }

    Ok(())
}

fn handle_delete(alias: &str) -> Result<(), String> {
    // Check if vault exists
    storage::ensure_vault_exists()?;

    executor::delete_secret(alias)?;
    eprintln!("✓ Secret '{}' deleted successfully", alias);
    Ok(())
}

fn handle_update(alias: &str, value: Option<String>) -> Result<(), String> {
    // Check if vault exists
    storage::ensure_vault_exists()?;

    // Check if the entry exists
    if !storage::entry_exists(alias)? {
        return Err(format!("Secret '{}' not found", alias));
    }

    // Get the secret value
    let secret = if let Some(val) = value {
        val
    } else if let Ok(test_secret) = std::env::var("AK_TEST_SECRET") {
        test_secret
    } else {
        prompt_secret("Enter new secret value: ")?
    };

    // Get master password
    let password = if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        SecretString::new(test_password)
    } else {
        prompt_password("Enter master password: ")?
    };

    // Update the secret (delete old, add new)
    executor::update_secret(alias, &secret, &password)?;
    eprintln!("✓ Secret '{}' updated successfully", alias);
    Ok(())
}

fn handle_run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("No command specified. Usage: ak run -- <command> [args...]".to_string());
    }

    // Check if vault exists
    storage::ensure_vault_exists()?;

    // Check for non-interactive mode (for testing)
    let password = if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        SecretString::new(test_password)
    } else {
        // Prompt for master password
        prompt_password("Enter master password: ")?
    };

    // Get all entries count for display
    let entries = storage::get_all_entries()?;
    if entries.is_empty() {
        eprintln!("Warning: No secrets in vault. Running command without injected environment variables.");
    } else {
        eprintln!("✓ Injecting {} secret(s) as environment variables", entries.len());
    }

    // Run command with secrets using executor
    let status = executor::run_with_secrets(args, &password)?;

    // Exit with the same code as the child process
    if let Some(code) = status.code() {
        std::process::exit(code);
    } else {
        // Process was terminated by a signal
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                eprintln!("Process terminated by signal {}", signal);
                std::process::exit(128 + signal);
            }
        }
        std::process::exit(1);
    }
}

fn handle_export(pattern: &str, output: &str) -> Result<(), String> {
    use std::path::Path;

    // Check if vault exists
    storage::ensure_vault_exists()?;

    // Check if output file already exists
    let output_path = Path::new(output);
    if output_path.exists() {
        let confirm = Confirm::new(&format!("File '{}' already exists. Overwrite?", output))
            .with_default(false)
            .prompt()
            .map_err(|e| format!("Failed to get confirmation: {}", e))?;

        if !confirm {
            return Err("Export cancelled".to_string());
        }
    }

    // Prompt for master password
    let password = if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        SecretString::new(test_password)
    } else {
        prompt_password("Enter master password: ")?
    };

    eprintln!("Exporting secrets matching pattern '{}'...", pattern);

    // Perform export using executor
    let count = executor::export_secrets(pattern, output_path, &password)?;

    eprintln!("✓ Successfully exported {} secret(s) to '{}'", count, output);
    eprintln!("⚠️  Keep this file secure - it contains encrypted secrets!");

    Ok(())
}

fn handle_import(input: &str) -> Result<(), String> {
    use std::path::Path;

    // Check if vault exists
    storage::ensure_vault_exists()?;

    // Check if input file exists
    let input_path = Path::new(input);
    if !input_path.exists() {
        return Err(format!("File '{}' not found", input));
    }

    // Prompt for master password
    let password = if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        SecretString::new(test_password)
    } else {
        prompt_password("Enter master password: ")?
    };

    eprintln!("Importing secrets from '{}'...", input);

    // Perform import using executor
    let result = executor::import_secrets(input_path, &password)?;

    // Display detailed table if there are operations
    if !result.operations.is_empty() {
        eprintln!("\n┌─────────────────────────────────┬──────────┬────────────────────────┐");
        eprintln!("│ Alias                           │ Status   │ Version (Old -> New)   │");
        eprintln!("├─────────────────────────────────┼──────────┼────────────────────────┤");

        for op in &result.operations {
            let status_str = match op.status {
                synapse::ImportStatus::Added => "Added   ",
                synapse::ImportStatus::Updated => "Updated ",
                synapse::ImportStatus::Skipped => "Skipped ",
            };

            let version_str = match op.old_version {
                Some(old_v) => format!("v{} -> v{}", old_v, op.new_version),
                None => "New".to_string(),
            };

            // Handle skipped entries differently
            let version_display = if op.status == synapse::ImportStatus::Skipped {
                format!("v{} (Keep Local)", op.old_version.unwrap_or(0))
            } else {
                version_str
            };

            eprintln!("│ {:<31} │ {} │ {:<22} │",
                truncate_string(&op.alias, 31),
                status_str,
                truncate_string(&version_display, 22)
            );
        }

        eprintln!("└─────────────────────────────────┴──────────┴────────────────────────┘");
    }

    eprintln!("\n✓ Import complete:");
    eprintln!("  • Added: {} new secret(s)", result.added);
    eprintln!("  • Updated: {} secret(s)", result.updated);
    eprintln!("  • Skipped: {} secret(s) (local version newer)", result.skipped);

    Ok(())
}

/// Helper function to truncate strings for table display
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[0..max_len-3])
    }
}
