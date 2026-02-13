mod crypto;
mod storage;

use clap::{Parser, Subcommand};
use inquire::{Password, Confirm};
use rand::RngCore;
use arboard::Clipboard;
use std::collections::HashMap;
use zeroize::Zeroizing;

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
    },

    /// List all secret aliases
    List,

    /// Delete a secret from the vault
    Delete {
        /// Alias of the secret to delete
        alias: String,
    },

    /// Run a command with secrets injected as environment variables
    Run {
        /// Command and arguments to execute (use -- to separate)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init => handle_init(),
        Commands::Add { alias, magic } => handle_add(&alias, magic),
        Commands::Get { alias } => handle_get(&alias),
        Commands::List => handle_list(),
        Commands::Delete { alias } => handle_delete(&alias),
        Commands::Run { args } => handle_run(&args),
    };

    if let Err(e) = result {
        eprintln!("\x1b[31mError: {}\x1b[0m", e);
        std::process::exit(1);
    }
}

fn handle_init() -> Result<(), String> {
    eprintln!("Initializing AiKeyLabs vault...");

    // Check for non-interactive mode (for testing)
    let password = if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        test_password
    } else {
        // Prompt for master password
        let password = Password::new("Enter master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .prompt()
            .map_err(|e| format!("Failed to read password: {}", e))?;

        let password_confirm = Password::new("Confirm master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .prompt()
            .map_err(|e| format!("Failed to read password: {}", e))?;

        if password != password_confirm {
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
        test_password
    } else {
        // Prompt for master password
        Password::new("Enter master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .prompt()
            .map_err(|e| format!("Failed to read password: {}", e))?
    };

    // Get salt from database
    let salt = storage::get_salt()?;

    // Derive encryption key
    let key = crypto::derive_key(&password, &salt)
        .map_err(|_| "Invalid master password or corrupted vault.".to_string())?;

    // Verify password by attempting to decrypt an existing entry (if any exist)
    verify_password(&key)?;

    // Get secret value
    let secret = if magic {
        // Magic Add: Use clipboard content
        let mut clipboard = Clipboard::new()
            .map_err(|e| format!("Failed to access clipboard: {}", e))?;
        clipboard.get_text()
            .map_err(|e| format!("Failed to read from clipboard: {}", e))?
    } else if let Ok(test_secret) = std::env::var("AK_TEST_SECRET") {
        // Non-interactive mode for testing
        test_secret
    } else {
        // Check clipboard for potential secrets
        let mut secret = String::new();
        let mut used_clipboard = false;

        if let Ok(mut clipboard) = Clipboard::new() {
            if let Ok(clipboard_content) = clipboard.get_text() {
                // Detect common secret patterns
                if is_potential_secret(&clipboard_content) {
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
        }

        // If not using clipboard, prompt for secret value
        if !used_clipboard {
            secret = Password::new(&format!("Enter secret value for '{}':", alias))
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .prompt()
                .map_err(|e| format!("Failed to read secret: {}", e))?;
        }

        secret
    };

    // Encrypt the secret
    let (nonce, ciphertext) = crypto::encrypt(&key, secret.as_bytes())?;

    // Store in database
    storage::store_entry(alias, &nonce, &ciphertext)?;

    eprintln!("✓ Secret '{}' added successfully", alias);

    Ok(())
}

/// Verifies the password by attempting to decrypt an existing entry
/// Returns Ok if vault is empty or password is correct
fn verify_password(key: &[u8; crypto::KEY_SIZE]) -> Result<(), String> {
    // Get all entries to check if vault has any secrets
    let entries = storage::list_entries()?;

    // If vault is empty, password is valid (nothing to verify against)
    if entries.is_empty() {
        return Ok(());
    }

    // Try to decrypt the first entry to verify password
    let first_alias = &entries[0];
    let (nonce, ciphertext) = storage::get_entry(first_alias)?;

    // Attempt decryption - this will fail if password is wrong
    crypto::decrypt(key, &nonce, &ciphertext)
        .map_err(|_| "Invalid master password".to_string())?;

    Ok(())
}

/// Detects if a string matches common secret patterns
fn is_potential_secret(text: &str) -> bool {
    let trimmed = text.trim();

    // Check for common API key patterns
    if trimmed.starts_with("sk-") ||           // OpenAI, Stripe
       trimmed.starts_with("pk-") ||           // Stripe public key
       trimmed.starts_with("rk-") ||           // Stripe restricted key
       trimmed.starts_with("Bearer ") ||       // Bearer tokens
       trimmed.starts_with("ghp_") ||          // GitHub personal access token
       trimmed.starts_with("gho_") ||          // GitHub OAuth token
       trimmed.starts_with("ghs_") ||          // GitHub server token
       trimmed.starts_with("github_pat_") ||   // GitHub fine-grained PAT
       trimmed.starts_with("glpat-") ||        // GitLab personal access token
       trimmed.starts_with("AKIA") ||          // AWS access key
       trimmed.starts_with("AIza") ||          // Google API key
       trimmed.starts_with("ya29.") {          // Google OAuth token
        return true;
    }

    // Check for JWT tokens (three base64 segments separated by dots)
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() == 3 && parts.iter().all(|p| p.len() > 10 && p.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')) {
        return true;
    }

    // Check for long alphanumeric strings (likely API keys)
    if trimmed.len() >= 32 && trimmed.len() <= 512 &&
       trimmed.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return true;
    }

    false
}

fn handle_get(alias: &str) -> Result<(), String> {
    // Check if vault exists
    storage::ensure_vault_exists()?;

    // Check for non-interactive mode (for testing)
    let password = if let Ok(test_password) = std::env::var("AK_TEST_PASSWORD") {
        test_password
    } else {
        // Prompt for master password
        Password::new("Enter master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .prompt()
            .map_err(|e| format!("Failed to read password: {}", e))?
    };

    // Get salt from database
    let salt = storage::get_salt()?;

    // Derive encryption key
    let key = crypto::derive_key(&password, &salt)
        .map_err(|_| "Invalid master password or corrupted vault.".to_string())?;

    // Retrieve encrypted entry
    let (nonce, ciphertext) = storage::get_entry(alias)?;

    // Decrypt the secret
    let plaintext = crypto::decrypt(&key, &nonce, &ciphertext)
        .map_err(|_| "Invalid master password or corrupted vault.".to_string())?;

    // Convert to string
    let secret_str = String::from_utf8(plaintext.to_vec())
        .map_err(|_| "Secret contains invalid UTF-8".to_string())?;

    // Copy to clipboard
    let mut clipboard = Clipboard::new()
        .map_err(|e| format!("Failed to access clipboard: {}", e))?;
    clipboard.set_text(&secret_str)
        .map_err(|e| format!("Failed to copy to clipboard: {}", e))?;

    eprintln!("✓ Secret '{}' copied to clipboard", alias);

    Ok(())
}

fn handle_list() -> Result<(), String> {
    // Check if vault exists
    storage::ensure_vault_exists()?;

    let aliases = storage::list_entries()?;

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

    storage::delete_entry(alias)?;
    eprintln!("✓ Secret '{}' deleted successfully", alias);
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
        test_password
    } else {
        // Prompt for master password
        Password::new("Enter master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .prompt()
            .map_err(|e| format!("Failed to read password: {}", e))?
    };

    // Get salt from database
    let salt = storage::get_salt()?;

    // Derive encryption key
    let key = crypto::derive_key(&password, &salt)
        .map_err(|_| "Invalid master password or corrupted vault.".to_string())?;

    // Fetch all encrypted entries
    let entries = storage::get_all_entries()?;

    if entries.is_empty() {
        eprintln!("Warning: No secrets in vault. Running command without injected environment variables.");
    } else {
        eprintln!("✓ Injecting {} secret(s) as environment variables", entries.len());
    }

    // Decrypt all entries into a HashMap with secure memory handling
    let mut decrypted_map: HashMap<String, Zeroizing<String>> = HashMap::new();

    for (alias, nonce, ciphertext) in entries {
        let plaintext = crypto::decrypt(&key, &nonce, &ciphertext)
            .map_err(|_| "Invalid master password or corrupted vault.".to_string())?;
        let secret_str = String::from_utf8(plaintext.to_vec())
            .map_err(|_| format!("Secret '{}' contains invalid UTF-8", alias))?;

        decrypted_map.insert(alias, Zeroizing::new(secret_str));
    }

    // Spawn the child process with injected environment variables
    let mut child = std::process::Command::new(&args[0])
        .args(&args[1..])
        .envs(decrypted_map.iter().map(|(k, v)| (k, v.as_str())))
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to spawn command '{}': {}", args[0], e))?;

    // Immediately drop the decrypted map to zero memory
    drop(decrypted_map);

    // Wait for the child process to complete
    let status = child.wait()
        .map_err(|e| format!("Failed to wait for child process: {}", e))?;

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
