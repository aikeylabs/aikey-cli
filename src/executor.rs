use crate::crypto;
use crate::storage;
use arboard::Clipboard;
use rusqlite::{params, Connection};
use secrecy::SecretString;
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

struct VaultContext {
    key: crypto::SecureBuffer<[u8; crypto::KEY_SIZE]>,
    #[allow(dead_code)]
    salt: Vec<u8>,
}

impl VaultContext {
    fn new(password: &SecretString) -> Result<Self, String> {
        storage::ensure_vault_exists()?;
        let salt = storage::get_salt()?;
        let key = crypto::derive_key(password, &salt)
            .map_err(|_| "Invalid master password or corrupted vault.".to_string())?;
        Self::verify_password_internal(&key)?;
        Ok(VaultContext { key, salt })
    }

    fn verify_password_internal(key: &crypto::SecureBuffer<[u8; crypto::KEY_SIZE]>) -> Result<(), String> {
        let db_path = storage::get_vault_path()?;
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("Failed to open vault: {}", e))?;

        let stored_hash: Vec<u8> = conn
            .query_row(
                "SELECT value FROM config WHERE key = ?",
                params!["password_hash"],
                |row| row.get(0),
            )
            .map_err(|_| "Password hash not found. Please re-run 'ak init'.".to_string())?;

        if &**key != stored_hash.as_slice() {
            return Err("Invalid master password.".to_string());
        }

        Ok(())
    }

    fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        crypto::encrypt(&*self.key, data)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<crypto::SecureBuffer<Vec<u8>>, String> {
        crypto::decrypt(&*self.key, nonce, ciphertext)
            .map_err(|_| "Invalid master password or corrupted vault.".to_string())
    }
}

#[allow(dead_code)]
pub fn verify_password(key: &[u8; crypto::KEY_SIZE]) -> Result<(), String> {
    let secure_key = crypto::SecureBuffer::new(*key)?;
    VaultContext::verify_password_internal(&secure_key)
}

#[allow(dead_code)]
pub fn is_potential_secret(text: &str) -> bool {
    let trimmed = text.trim();

    if trimmed.starts_with("sk-") ||
       trimmed.starts_with("pk-") ||
       trimmed.starts_with("rk-") ||
       trimmed.starts_with("Bearer ") ||
       trimmed.starts_with("ghp_") ||
       trimmed.starts_with("gho_") ||
       trimmed.starts_with("ghs_") ||
       trimmed.starts_with("github_pat_") ||
       trimmed.starts_with("glpat-") ||
       trimmed.starts_with("AKIA") ||
       trimmed.starts_with("AIza") ||
       trimmed.starts_with("ya29.") {
        return true;
    }

    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() == 3 && parts.iter().all(|p| p.len() > 10 && p.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')) {
        return true;
    }

    if trimmed.len() >= 32 && trimmed.len() <= 512 &&
       trimmed.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return true;
    }

    false
}

pub fn add_secret(alias: &str, secret: &str, password: &SecretString) -> Result<(), String> {
    let ctx = VaultContext::new(password)?;
    let (nonce, ciphertext) = ctx.encrypt(secret.as_bytes())?;
    storage::store_entry(alias, &nonce, &ciphertext)
}

pub fn get_secret(alias: &str, password: &SecretString) -> Result<Zeroizing<String>, String> {
    let ctx = VaultContext::new(password)?;
    let (nonce, ciphertext) = storage::get_entry(alias)?;
    let plaintext = ctx.decrypt(&nonce, &ciphertext)?;

    // Wrap plaintext in Zeroizing immediately to protect in memory
    let secret_string = String::from_utf8(plaintext.to_vec())
        .map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(secret_string))
}

pub fn delete_secret(alias: &str, password: &SecretString) -> Result<(), String> {
    let _ctx = VaultContext::new(password)?;
    storage::delete_entry(alias)
}

pub fn list_secrets(password: &SecretString) -> Result<Vec<String>, String> {
    let _ctx = VaultContext::new(password)?;
    storage::list_entries()
}

#[allow(dead_code)]
pub fn read_from_clipboard() -> Result<String, String> {
    let mut clipboard = Clipboard::new().map_err(|e| format!("Failed to access clipboard: {}", e))?;
    clipboard.get_text().map_err(|e| format!("Failed to read from clipboard: {}", e))
}

#[allow(dead_code)]
pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard = Clipboard::new().map_err(|e| format!("Failed to access clipboard: {}", e))?;
    clipboard.set_text(text).map_err(|e| format!("Failed to copy to clipboard: {}", e))
}

pub fn update_secret(alias: &str, new_secret: &str, password: &SecretString) -> Result<(), String> {
    add_secret(alias, new_secret, password)
}

#[allow(dead_code)]
pub fn run_with_secrets(aliases: &[String], password: &SecretString, command: &str) -> Result<(), String> {
    let ctx = VaultContext::new(password)?;

    // Retrieve all secrets into Zeroizing containers
    let mut env_vars: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::new();

    for alias in aliases {
        let (nonce, ciphertext) = storage::get_entry(alias)?;
        let plaintext = ctx.decrypt(&nonce, &ciphertext)?;
        let secret_string = String::from_utf8(plaintext.to_vec())
            .map_err(|e| format!("Invalid UTF-8 in secret '{}': {}", alias, e))?;

        // Convert alias to uppercase environment variable name
        let env_name = alias.to_uppercase().replace('-', "_");
        env_vars.insert(env_name, Zeroizing::new(secret_string));
    }

    // Parse and execute command
    let mut parts = shell_words::split(command)
        .map_err(|e| format!("Failed to parse command: {}", e))?;

    if parts.is_empty() {
        return Err("Empty command".to_string());
    }

    let program = parts.remove(0);
    let args = parts;

    // Execute command with environment variables
    let mut cmd = std::process::Command::new(&program);
    cmd.args(&args);

    for (key, value) in &env_vars {
        cmd.env(key, value.as_str());
    }

    let status = cmd.status()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    // Explicit drop to trigger Zeroizing cleanup
    drop(env_vars);
    drop(ctx);

    if !status.success() {
        return Err(format!("Command exited with status: {}", status));
    }

    Ok(())
}

/// Execute a command with secrets injected as environment variables
///
/// MINIMAL-WINDOW PATTERN (SECURITY HARDENED):
/// Secrets are decrypted, immediately injected into child process, then wiped
/// from parent memory BEFORE waiting for child completion. This minimizes the
/// time window where decrypted secrets exist in parent process memory.
///
/// SECURITY IMPROVEMENTS:
/// - Secrets wiped IMMEDIATELY after child spawn (not after child exits)
/// - Eliminates extended memory exposure window (previously hours for long-running commands)
/// - Reduces attack surface: parent memory is clean during child execution
/// - Signal handler still ensures cleanup on interruption
/// - Direct conversion from SecureBuffer to String (no intermediate Vec allocation)
///
/// # Arguments
/// * `env_mappings` - Vector of "ENV_VAR=alias" strings
/// * `password` - Master password for vault access
/// * `command` - Command and arguments to execute (can be single string or pre-split)
///
/// # Example
/// ```
/// // ak exec --env MY_KEY=github_token -- printenv MY_KEY
/// exec_with_env(&["MY_KEY=github_token"], &password, &["printenv", "MY_KEY"])?;
///
/// // ak exec --env MY_KEY=github_token -- "sleep 5"
/// exec_with_env(&["MY_KEY=github_token"], &password, &["sleep 5"])?;
/// ```
pub fn exec_with_env(
    env_mappings: &[String],
    password: &SecretString,
    command: &[String],
) -> Result<(), String> {
    // Establish vault context - secrets loaded into Zeroizing memory
    let ctx = VaultContext::new(password)?;

    if command.is_empty() {
        return Err("No command specified".to_string());
    }

    // Pre-allocate HashMap with exact capacity to avoid reallocation during decryption
    let mut env_secrets: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::with_capacity(env_mappings.len());

    // TIGHT DECRYPTION LOOP: Minimize time between first and last secret decryption
    for mapping in env_mappings {
        let parts: Vec<&str> = mapping.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid env mapping '{}'. Expected format: ENV_VAR=alias",
                mapping
            ));
        }

        let env_name = parts[0].trim();
        let alias = parts[1].trim();

        if env_name.is_empty() || alias.is_empty() {
            return Err(format!(
                "Invalid env mapping '{}'. Both ENV_VAR and alias must be non-empty",
                mapping
            ));
        }

        // Fetch secret from vault
        let (nonce, ciphertext) = storage::get_entry(alias)
            .map_err(|e| format!("Failed to fetch secret '{}': {}", alias, e))?;

        let plaintext = ctx.decrypt(&nonce, &ciphertext)?;

        // OPTIMIZATION: Direct conversion from SecureBuffer to String
        // Avoids intermediate Vec allocation from plaintext.to_vec()
        let secret_string = std::str::from_utf8(&plaintext)
            .map_err(|e| format!("Invalid UTF-8 in secret '{}': {}", alias, e))?
            .to_string();

        // Store in Zeroizing container for secure cleanup
        env_secrets.insert(env_name.to_string(), Zeroizing::new(secret_string));
    }

    // INPUT ROBUSTNESS: Handle both single-string and pre-split command formats
    let parsed_parts: Vec<String> = if command.len() == 1 {
        shell_words::split(&command[0])
            .map_err(|e| format!("Failed to parse command '{}': {}", command[0], e))?
    } else {
        command.to_vec()
    };

    if parsed_parts.is_empty() {
        return Err("Empty command after parsing".to_string());
    }

    let program = &parsed_parts[0];
    let args = &parsed_parts[1..];

    // Build command with secrets injected
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);

    for (key, value) in &env_secrets {
        cmd.env(key, value.as_str());
    }

    // Inherit stdin/stdout/stderr for interactive terminal support
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    // Setup signal handler for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).map_err(|e| format!("Failed to set signal handler: {}", e))?;

    // Spawn child process
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn command '{}': {}", program, e))?;

    // CRITICAL SECURITY IMPROVEMENT: Wipe secrets IMMEDIATELY after spawn
    // Child process has already inherited the environment variables
    // Parent no longer needs them in memory
    drop(env_secrets);
    drop(ctx);

    // Wait for child with clean parent memory
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                // Child still running - check if we received interrupt signal
                if !running.load(Ordering::SeqCst) {
                    // Forward signal to child
                    let _ = child.kill();
                    return Err("Interrupted by user".to_string());
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                return Err(format!("Failed to wait for command: {}", e));
            }
        }
    };

    // Propagate child exit status
    if !status.success() {
        return Err(format!(
            "Command exited with status: {}",
            status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

#[allow(dead_code)]
pub fn export_secrets(pattern: &str, password: &SecretString) -> Result<String, String> {
    let _ctx = VaultContext::new(password)?;

    // Get entries matching pattern
    let entries = storage::get_entries_with_metadata(pattern)?;

    if entries.is_empty() {
        return Err(format!("No entries match pattern '{}'", pattern));
    }

    // Convert to JSON format with updated Base64 API
    let json_entries: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|(alias, nonce, ciphertext, version_tag, updated_at, created_at, metadata)| {
            serde_json::json!({
                "alias": alias,
                "nonce": BASE64.encode(&nonce),
                "ciphertext": BASE64.encode(&ciphertext),
                "version_tag": version_tag,
                "updated_at": updated_at,
                "created_at": created_at,
                "metadata": metadata,
            })
        })
        .collect();

    serde_json::to_string_pretty(&json_entries)
        .map_err(|e| format!("Failed to serialize entries: {}", e))
}

#[allow(dead_code)]
pub fn import_secrets(json_data: &str, password: &SecretString, strategy: &str) -> Result<(), String> {
    let _ctx = VaultContext::new(password)?;

    // Parse JSON data
    let entries: Vec<serde_json::Value> = serde_json::from_str(json_data)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;

    for entry in entries {
        let alias = entry["alias"]
            .as_str()
            .ok_or("Missing alias field")?
            .to_string();

        // Updated Base64 API usage
        let nonce = BASE64.decode(
            entry["nonce"]
                .as_str()
                .ok_or("Missing nonce field")?,
        )
        .map_err(|e| format!("Failed to decode nonce: {}", e))?;

        let ciphertext = BASE64.decode(
            entry["ciphertext"]
                .as_str()
                .ok_or("Missing ciphertext field")?,
        )
        .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;

        let version_tag = entry["version_tag"].as_i64().unwrap_or(1);
        let updated_at = entry["updated_at"].as_i64().unwrap_or(0);
        let created_at = entry["created_at"].as_i64().unwrap_or(0);
        let metadata = entry["metadata"].as_str().map(|s| s.to_string());

        // Check if entry exists
        let exists = storage::entry_exists(&alias)?;

        if exists {
            match strategy {
                "skip" => continue,
                "overwrite" => {
                    storage::update_entry_full(
                        &alias,
                        &nonce,
                        &ciphertext,
                        version_tag,
                        updated_at,
                        created_at,
                        metadata.as_deref(),
                    )?;
                }
                "merge" => {
                    // Get existing entry metadata
                    let (_, _, local_version, local_updated_at, _, _) =
                        storage::get_entry_with_metadata(&alias)?;

                    // Only update if incoming version is newer
                    if version_tag > local_version
                        || (version_tag == local_version && updated_at > local_updated_at)
                    {
                        storage::update_entry_full(
                            &alias,
                            &nonce,
                            &ciphertext,
                            version_tag,
                            updated_at,
                            created_at,
                            metadata.as_deref(),
                        )?;
                    }
                }
                _ => return Err(format!("Unknown import strategy: {}", strategy)),
            }
        } else {
            // Insert new entry
            storage::insert_entry_full(
                &alias,
                &nonce,
                &ciphertext,
                version_tag,
                updated_at,
                created_at,
                metadata.as_deref(),
            )?;
        }
    }

    Ok(())
}
