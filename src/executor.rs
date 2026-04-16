use crate::audit;
use crate::crypto;
use crate::storage;
use crate::config::ProjectConfig;
use crate::providers::Provider;
use crate::events::EventBuilder;
use crate::global_config;
use crate::error_codes::msgs;
use arboard::Clipboard;
use rusqlite::params;
use secrecy::SecretString;
use zeroize::Zeroizing;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use rayon::prelude::*;
use serde::Serialize;

/// P1-Q4: Dry-run output information
#[derive(Debug, Clone, Serialize)]
pub struct DryRunInfo {
    /// Environment variable name that will be injected
    pub env_var: String,
    /// Provider name (e.g., "openai", "anthropic")
    pub provider: String,
    /// Resolved model ID (if any)
    pub model: Option<String>,
    /// Vault key alias that will be used
    pub key_alias: String,
    /// Whether tenant override was applied
    pub tenant_override: bool,
    /// Resolution source (e.g., "LogicalModel", "Base", "Tenant", "Explicit")
    pub source: String,
}

struct VaultContext {
    key: crypto::SecureBuffer<[u8; crypto::KEY_SIZE]>,
    #[allow(dead_code)]
    salt: Vec<u8>,
}

impl VaultContext {
    fn new(password: &SecretString) -> Result<Self, String> {
        // Auto-initialize vault on first use so the user never needs a separate
        // initialization step before using any vault command.
        // Check for master_salt (not just file existence) because session backend
        // selection may have created the DB file before vault init runs.
        let vault_path = storage::get_vault_path()?;
        let needs_init = if vault_path.exists() {
            storage::get_salt().is_err()
        } else {
            true
        };
        if needs_init {
            let mut salt = [0u8; 16];
            crypto::generate_salt(&mut salt)?;
            storage::initialize_vault(&salt, password)?;
            let _ = audit::initialize_audit_log();
            let _ = audit::log_audit_event(password, audit::AuditOperation::Init, None, true);
        }

        // Check rate limiting before attempting authentication
        let mut rate_limiter = crate::ratelimit::RateLimiter::load()?;
        rate_limiter.check_allowed()?;

        let salt = storage::get_salt()?;

        // Get KDF parameters from database
        let (m_cost, t_cost, p_cost) = storage::get_kdf_params()?;

        let key = crypto::derive_key_with_params(password, &salt, m_cost, t_cost, p_cost)
            .map_err(|_| msgs::INVALID_PASSWORD.to_string())?;

        // Verify password with rate limiting
        match Self::verify_password_internal(&key) {
            Ok(_) => {
                // Success - reset rate limiter
                rate_limiter.record_success()?;

                // Apply pending version migrations (idempotent).
                // Why here: after password is verified and before any vault operation,
                // ensure the schema is up to date. CREATE TABLE IF NOT EXISTS and
                // ALTER TABLE ADD COLUMN are safe to run on every open.
                let conn = storage::open_connection()?;
                let _ = super::migrations::upgrade_all(&conn);

                Ok(VaultContext { key, salt })
            }
            Err(e) => {
                // Failure - record attempt
                rate_limiter.record_failure()?;
                Err(e)
            }
        }
    }

    fn verify_password_internal(key: &crypto::SecureBuffer<[u8; crypto::KEY_SIZE]>) -> Result<(), String> {
        let conn = storage::open_connection()?;

        // Try to get stored password hash
        let stored_hash_result: Result<Vec<u8>, rusqlite::Error> = conn
            .query_row(
                "SELECT value FROM config WHERE key = ?",
                params!["password_hash"],
                |row| row.get(0),
            );

        match stored_hash_result {
            Ok(stored_hash) => {
                // Password hash exists, verify it
                if key.as_slice() != stored_hash.as_slice() {
                    return Err(msgs::INVALID_PASSWORD.to_string());
                }
                Ok(())
            }
            Err(_) => {
                // Password hash doesn't exist (old database or migration).
                // Why not just accept: a wrong password would be stored as the real hash,
                // locking the user out permanently. Instead, verify by trying to decrypt
                // an existing entry. If no entries exist (empty vault), accept and store.
                let has_entries: bool = conn
                    .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get::<_, i64>(0))
                    .map(|n| n > 0)
                    .unwrap_or(false);

                if has_entries {
                    // Vault has data — try to decrypt the first entry to verify password
                    let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = conn
                        .query_row(
                            "SELECT nonce, ciphertext FROM entries LIMIT 1",
                            [],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .map_err(|_| msgs::INVALID_PASSWORD.to_string())?;

                    crypto::decrypt(key, &nonce, &ciphertext)
                        .map_err(|_| msgs::INVALID_PASSWORD.to_string())?;
                }

                // Password verified (or empty vault) — store hash for future checks
                conn.execute(
                    "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                    params!["password_hash", &**key],
                )
                .map_err(|e| format!("Failed to store password hash during migration: {}", e))?;
                Ok(())
            }
        }
    }

    fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        crypto::encrypt(&self.key, data)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<crypto::SecureBuffer<Vec<u8>>, String> {
        crypto::decrypt(&self.key, nonce, ciphertext)
            .map_err(|_| msgs::INVALID_PASSWORD.to_string())
    }
}

#[allow(dead_code)]
pub fn verify_password(key: &[u8; crypto::KEY_SIZE]) -> Result<(), String> {
    let secure_key = crypto::SecureBuffer::new(*key)?;
    VaultContext::verify_password_internal(&secure_key)
}

/// Quick password check without creating a full VaultContext.
/// Used for early validation in `aikey add` before the interactive flow.
pub fn verify_vault_password(password: &SecretString) -> Result<(), String> {
    let _ = VaultContext::new(password)?;
    Ok(())
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
    // Check if the secret already exists
    if storage::get_entry(alias).is_ok() {
        return Err(format!("API Key '{}' already exists. Use 'update' command to modify it.", alias));
    }

    let ctx = VaultContext::new(password)?;
    let (nonce, ciphertext) = ctx.encrypt(secret.as_bytes())?;
    storage::store_entry(alias, &nonce, &ciphertext)?;
    let _ = storage::bump_vault_change_seq();
    Ok(())
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
    storage::delete_entry(alias)?;
    let _ = storage::bump_vault_change_seq();
    Ok(())
}

pub fn list_secrets(password: &SecretString) -> Result<Vec<String>, String> {
    let _ctx = VaultContext::new(password)?;
    storage::list_entries()
}

pub fn list_secrets_with_metadata(password: &SecretString) -> Result<Vec<storage::SecretMetadata>, String> {
    let _ctx = VaultContext::new(password)?;
    storage::list_entries_with_metadata()
}

#[allow(dead_code)]
pub fn read_from_clipboard() -> Result<String, String> {
    let mut clipboard = Clipboard::new().map_err(|e| format!("Failed to access clipboard: {}", e))?;
    clipboard.get_text().map_err(|e| format!("Failed to read from clipboard: {}", e))
}

pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard = Clipboard::new().map_err(|e| format!("Failed to access clipboard: {}", e))?;
    clipboard.set_text(text).map_err(|e| format!("Failed to copy to clipboard: {}", e))
}

/// Schedule clipboard clearing after a timeout
///
/// SECURITY: Spawns a background thread that clears the clipboard after the specified
/// timeout. This prevents secrets from persisting indefinitely in clipboard history.
///
/// # Arguments
/// * `timeout_secs` - Number of seconds to wait before clearing clipboard
///
/// # Implementation Notes
/// - Uses detached thread to avoid blocking CLI exit
/// - Thread sleeps for the timeout duration, then clears clipboard
/// - If clipboard access fails during clear, error is silently ignored
pub fn schedule_clipboard_clear(timeout_secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(timeout_secs));
        // Attempt to clear clipboard, ignore errors (user may have already changed it)
        let _ = copy_to_clipboard("");
    });
}

pub fn update_secret(alias: &str, new_secret: &str, password: &SecretString) -> Result<(), String> {
    // First check if the secret exists
    if storage::get_entry(alias).is_err() {
        return Err(format!("API Key '{}' not found", alias));
    }

    // Encrypt and store the new value
    let ctx = VaultContext::new(password)?;
    let (nonce, ciphertext) = ctx.encrypt(new_secret.as_bytes())?;
    storage::store_entry(alias, &nonce, &ciphertext)?;
    let _ = storage::bump_vault_change_seq();
    Ok(())
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
    inject_context_vars(&mut cmd, None);

    let status = cmd.status()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    // Explicit drop to trigger Zeroizing cleanup
    drop(env_vars);
    drop(ctx);

    if !status.success() {
        let exit_code = status.code().unwrap_or(1);
        std::process::exit(exit_code);
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
/// ```no_run
/// use secrecy::SecretString;
/// use aikeylabs_aikey_cli::executor::exec_with_env;
///
/// # fn main() -> Result<(), String> {
/// let password = SecretString::new("master_password".to_string());
///
/// // ak exec --env MY_KEY=github_token -- printenv MY_KEY
/// exec_with_env(&["MY_KEY=github_token".to_string()], &password, &["printenv".to_string(), "MY_KEY".to_string()])?;
///
/// // ak exec --env MY_KEY=github_token -- "sleep 5"
/// exec_with_env(&["MY_KEY=github_token".to_string()], &password, &["sleep".to_string(), "5".to_string()])?;
/// # Ok(())
/// # }
/// ```
#[allow(dead_code)]
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

    // PARALLEL DECRYPTION: Use rayon for concurrent secret decryption
    // This significantly improves performance for vaults with 100+ secrets
    let decryption_results: Result<Vec<(String, Zeroizing<String>)>, String> = env_mappings
        .par_iter()
        .map(|mapping| {
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
                .map_err(|_| format!("Missing key: {}", alias))?;

            let plaintext = ctx.decrypt(&nonce, &ciphertext)?;

            // OPTIMIZATION: Direct conversion from SecureBuffer to String
            // Avoids intermediate Vec allocation from plaintext.to_vec()
            let secret_string = std::str::from_utf8(&plaintext)
                .map_err(|e| format!("Invalid UTF-8 in secret '{}': {}", alias, e))?
                .to_string();

            Ok((env_name.to_string(), Zeroizing::new(secret_string)))
        })
        .collect();

    // Collect results into HashMap
    for (env_name, secret) in decryption_results? {
        env_secrets.insert(env_name, secret);
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

    let t0 = std::time::Instant::now();

    // Wait for child with clean parent memory
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                // Child still running - check if we received interrupt signal
                if !running.load(Ordering::SeqCst) {
                    // Forward signal to child
                    let _ = child.kill();
                    let _ = EventBuilder::new("exec")
                        .command(&parsed_parts.join(" "))
                        .duration_ms(t0.elapsed().as_millis() as i64)
                        .error("Interrupted by user")
                        .record();
                    return Err("Interrupted by user".to_string());
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                return Err(format!("Failed to wait for command: {}", e));
            }
        }
    };

    let duration_ms = t0.elapsed().as_millis() as i64;
    let exit_code = status.code().unwrap_or(1);

    let _ = EventBuilder::new("exec")
        .command(&parsed_parts.join(" "))
        .exit_code(exit_code)
        .duration_ms(duration_ms)
        .secrets_count(env_mappings.len() as i32)
        .record();

    // Propagate child exit status
    if !status.success() {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Execute a command with ALL secrets from the vault injected as environment variables
///
/// This is a simplified version that uses .status() for better test compatibility.
/// Unlike exec_with_env, this doesn't use explicit stdio inheritance or signal handling,
/// making it compatible with test frameworks like assert_cmd.
///
/// # Arguments
/// * `password` - Master password for vault access
/// * `command` - Command and arguments to execute
///
/// # Example
/// ```no_run
/// use secrecy::SecretString;
/// use aikeylabs_aikey_cli::executor::run_with_all_secrets;
///
/// # fn main() -> Result<(), String> {
/// let password = SecretString::new("master_password".to_string());
///
/// // ak run -- printenv
/// let (secrets_count, exit_code) = run_with_all_secrets(&password, &["printenv".to_string()], false)?;
/// # Ok(())
/// # }
/// ```
#[allow(dead_code)]
pub fn run_with_all_secrets(
    password: &SecretString,
    command: &[String],
    json_mode: bool,
) -> Result<(usize, i32), String> {
    // Establish vault context
    let ctx = VaultContext::new(password)?;

    // Get all secret aliases from the vault
    let aliases = list_secrets(password)?;

    if aliases.is_empty() {
        return Err("No secrets found in vault".to_string());
    }

    let secrets_count = aliases.len();
    if !json_mode {
        eprintln!("Injecting {} secret(s)", secrets_count);
    }

    // Decrypt all secrets into Zeroizing containers
    let mut env_secrets: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::with_capacity(aliases.len());

    for alias in &aliases {
        let (nonce, ciphertext) = storage::get_entry(alias)?;
        let plaintext = ctx.decrypt(&nonce, &ciphertext)?;
        let secret_string = std::str::from_utf8(&plaintext)
            .map_err(|e| format!("Invalid UTF-8 in secret '{}': {}", alias, e))?
            .to_string();

        let env_name = alias.to_uppercase().replace('-', "_");
        env_secrets.insert(env_name, Zeroizing::new(secret_string));
    }

    // Parse command
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

    // Build and execute command
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);

    for (key, value) in &env_secrets {
        cmd.env(key, value.as_str());
    }
    inject_context_vars(&mut cmd, None);

    // In JSON mode, suppress child process output to avoid polluting JSON response
    // In normal mode, inherit stdio to show command output
    if json_mode {
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    } else {
        cmd.stdin(std::process::Stdio::inherit());
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());
    }

    let t0 = std::time::Instant::now();
    let status = cmd.status()
        .map_err(|e| format!("Failed to execute command '{}': {}", program, e))?;

    // Wipe secrets from memory
    drop(env_secrets);
    drop(ctx);

    let exit_code = status.code().unwrap_or(1);
    let duration_ms = t0.elapsed().as_millis() as i64;

    // Get current env and profile from global config for event recording
    let current_env = crate::global_config::get_current_env().ok().flatten();
    let current_profile = crate::global_config::get_current_profile().ok().flatten();

    let mut event = EventBuilder::new("run")
        .command(&parsed_parts.join(" "))
        .exit_code(exit_code)
        .duration_ms(duration_ms)
        .secrets_count(secrets_count as i32);

    if let Some(env) = current_env {
        event = event.env(&env);
    }
    if let Some(prof) = current_profile {
        event = event.profile(&prof);
    }

    let _ = event.record();

    // Return secrets count and exit code
    if !status.success() {
        return Err(format!("Command exited with code {}", exit_code));
    }

    Ok((secrets_count, exit_code))
}

/// Inject non-sensitive context vars (AIKEY_PROJECT, AIKEY_ENV, AIKEY_PROFILE) into a Command.
/// Values are sourced from global config; missing values are silently skipped.
fn inject_context_vars(cmd: &mut std::process::Command, project_name: Option<&str>) {
    if let Some(name) = project_name {
        cmd.env("AIKEY_PROJECT", name);
    }
    if let Ok(Some(env)) = global_config::get_current_env() {
        cmd.env("AIKEY_ENV", env);
    }
    if let Ok(Some(profile)) = global_config::get_current_profile() {
        cmd.env("AIKEY_PROFILE", profile);
    }
}

/// Shared helper: parse `command`, build a child process with `env_secrets` injected,
/// run it, wipe secrets, and return `(secrets_count, exit_code)`.
///
/// `project_name` is forwarded to `inject_context_vars` for AIKEY_PROJECT.
/// Returns `Err("Command exited with code N")` on non-zero exit so callers can
/// propagate the exit code uniformly.
fn spawn_with_env(
    env_secrets: std::collections::HashMap<String, Zeroizing<String>>,
    command: &[String],
    json_mode: bool,
    project_name: Option<&str>,
) -> Result<(usize, i32), String> {
    let secrets_count = env_secrets.len();

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

    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    for (key, value) in &env_secrets {
        cmd.env(key, value.as_str());
    }
    inject_context_vars(&mut cmd, project_name);

    if json_mode {
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    } else {
        cmd.stdin(std::process::Stdio::inherit());
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());
    }

    let status = cmd
        .status()
        .map_err(|e| format!("Failed to execute command '{}': {}", program, e))?;

    drop(env_secrets);

    let exit_code = status.code().unwrap_or(1);
    if !status.success() {
        return Err(format!("Command exited with code {}", exit_code));
    }

    Ok((secrets_count, exit_code))
}

/// Compute injection set from env_mappings with tenant override tracking
/// Returns (provider, keyAlias, model, tenant_override_applied)
/// tenant_override_applied is true ONLY when a tenant override actually matched and changed the key_alias
///
/// Stage0 Decision H & I: Collision detection
/// - De-duplicate by final env_var
/// - If same env_var maps to multiple different key_alias values → FAIL FAST with actionable guidance
fn compute_injection_set_with_tenant_tracking(
    config: &ProjectConfig,
    env: &str,
    logical_model_filter: Option<&str>,
    tenant: Option<&str>,
) -> Result<Vec<(String, String, Option<String>, bool)>, String> {
    use crate::resolver::{resolve, ResolveRequest};
    use std::collections::HashMap;

    let mut injection_set = Vec::new();
    let mut env_var_to_entries: HashMap<String, Vec<(String, String, String)>> = HashMap::new(); // env_var -> [(logical_model, provider, key_alias)]

    // Get env_mappings for the current environment
    if let Some(env_map) = config.env_mappings.get(env) {
        for (logical_model_name, _mapping) in env_map {
            // If --logical-model is specified, filter to that model only
            if let Some(filter) = logical_model_filter {
                if logical_model_name != filter {
                    continue;
                }
            }

            // Resolve WITHOUT tenant to get base key_alias
            let base_request = ResolveRequest {
                logical_model: Some(logical_model_name.clone()),
                env: Some(env.to_string()),
                tenant: None,
                ..Default::default()
            };
            let base_key_alias = resolve(&base_request, Some(config))
                .ok()
                .map(|r| r.key_alias);

            // Resolve WITH tenant to get final key_alias
            let request = ResolveRequest {
                logical_model: Some(logical_model_name.clone()),
                env: Some(env.to_string()),
                tenant: tenant.map(|s| s.to_string()),
                ..Default::default()
            };

            if let Ok(resolved) = resolve(&request, Some(config)) {
                let env_var = Provider::parse(&resolved.provider).env_var();

                // Track for collision detection
                env_var_to_entries
                    .entry(env_var.clone())
                    .or_default()
                    .push((
                        logical_model_name.clone(),
                        resolved.provider.clone(),
                        resolved.key_alias.clone(),
                    ));

                // Strict tenant_override_applied: true ONLY when override actually changed the key_alias
                let tenant_override_applied = tenant.is_some()
                    && base_key_alias.is_some()
                    && base_key_alias.as_ref() != Some(&resolved.key_alias);

                injection_set.push((
                    resolved.provider,
                    resolved.key_alias,
                    resolved.model,
                    tenant_override_applied,
                ));
            }
        }
    }

    // Stage0 Decision H & I: Collision detection
    // If same env_var maps to multiple different key_alias values → FAIL FAST
    for (env_var, entries) in &env_var_to_entries {
        let unique_aliases: std::collections::HashSet<&String> = entries.iter().map(|(_, _, alias)| alias).collect();

        if unique_aliases.len() > 1 {
            // Collision detected: same env_var → multiple different key_alias values
            let mut error_msg = format!(
                "Collision detected: env_var '{}' maps to multiple different key aliases:\n",
                env_var
            );

            for (logical_model, provider, key_alias) in entries {
                error_msg.push_str(&format!(
                    "  - logical_model '{}' (provider: {}) → {}\n",
                    logical_model, provider, key_alias
                ));
            }

            error_msg.push_str("\nFix:\n");
            error_msg.push_str("  - Use --logical-model <name> to narrow injection to a single model\n");
            error_msg.push_str("  - Or update envMappings to use different providers for these models\n");

            return Err(error_msg);
        }
    }

    // De-duplicate by (provider, key_alias) to avoid injecting the same credential twice
    let mut seen = std::collections::HashSet::new();
    let mut deduplicated = Vec::new();

    for entry in injection_set {
        let key = (entry.0.clone(), entry.1.clone());
        if !seen.contains(&key) {
            seen.insert(key);
            deduplicated.push(entry);
        }
    }

    Ok(deduplicated)
}

/// Execute a command with secrets resolved from a project config.
///
/// Resolution order (Stage0 Decision I - mapping-closed boundary):
/// - If `envMappings[env]` exists and is non-empty: inject only mapping-derived credentials (closed set)
/// - If `envMappings[env]` is missing/empty: fall back to `config.providers`
/// - `config.required_vars` are always resolved independently
///
/// Returns `(secrets_injected, exit_code)`.
/// P1-Q1: Compute injection set from env_mappings
/// Returns a de-duplicated list of (provider, keyAlias, model) tuples
fn compute_injection_set_from_env_mappings(
    config: &ProjectConfig,
    env: &str,
    logical_model_filter: Option<&str>,
    tenant: Option<&str>,
) -> Result<Vec<(String, String, Option<String>)>, String> {
    compute_injection_set_with_tenant_tracking(config, env, logical_model_filter, tenant)
        .map(|set| set.into_iter().map(|(provider, key_alias, model, _)| (provider, key_alias, model)).collect())
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

/// Dry-run for provider mode.
///
/// Resolves the provider key alias and returns the list of env var names that
/// would be injected, without actually running any command.
///
/// Stage0 Decision H: --dry-run output contract
/// - No execution occurs
/// - No secret values shown
/// - Stable output ordering (sorted by env_var)
/// - Strict tenant_override_applied (true only when override actually matched and changed key_alias)
/// - Implements mapping-closed boundary (same as run)

/// Execute a command with a single provider's key resolved via the 5-step resolver.
/// Password-based version (no daemon).
///
/// Uses `resolver::resolve` to determine the vault alias, then fetches it directly
/// and injects it as the provider's canonical env var (e.g. `OPENAI_API_KEY`).
/// If `model` is resolved, it is also injected as `AIKEY_MODEL`.
pub fn run_with_provider(
    provider: &str,
    model: Option<&str>,
    tenant: Option<&str>,
    config: Option<&ProjectConfig>,
    password: &SecretString,
    command: &[String],
    json_mode: bool,
) -> Result<(usize, i32), String> {
    use crate::resolver::{resolve, ResolveRequest};

    let ctx = VaultContext::new(password)?;

    let request = ResolveRequest {
        provider: provider.to_string(),
        model: model.map(|s| s.to_string()),
        tenant: tenant.map(|s| s.to_string()),
        ..Default::default()
    };

    let resolved = resolve(&request, config).map_err(|e| e.to_string())?;

    // Fetch secret from vault
    let (nonce, ciphertext) = storage::get_entry(&resolved.key_alias)
        .map_err(|_| format!("Missing key: {} in vault", resolved.key_alias))?;
    let plaintext = ctx.decrypt(&nonce, &ciphertext)?;
    let secret = std::str::from_utf8(&plaintext)
        .map_err(|e| format!("Invalid UTF-8 in secret: {}", e))?
        .to_string();

    let mut env_secrets: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::new();
    env_secrets.insert(resolved.env_var.clone(), Zeroizing::new(secret));

    if let Some(m) = &resolved.model {
        env_secrets.insert("AIKEY_MODEL".to_string(), Zeroizing::new(m.clone()));
    }

    let secrets_count = env_secrets.len();
    if !json_mode {
        eprintln!("Injecting {} secret(s) for provider '{}'", secrets_count, provider);
    }

    let parsed_parts: Vec<String> = if command.len() == 1 {
        shell_words::split(&command[0])
            .map_err(|e| format!("Failed to parse command '{}': {}", command[0], e))?
    } else {
        command.to_vec()
    };

    let t0 = std::time::Instant::now();
    let result = spawn_with_env(env_secrets, command, json_mode, config.map(|c| c.project.name.as_str()));
    let duration_ms = t0.elapsed().as_millis() as i64;
    let exit_code = match &result {
        Ok((_, c)) => *c,
        Err(e) => e.strip_prefix("Command exited with code ")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1)
    };

    // Get context for event recording
    let project_name = config.map(|c| c.project.name.as_str());
    let current_env = crate::global_config::get_current_env().ok().flatten();
    let current_profile = crate::global_config::get_current_profile().ok().flatten();

    let mut event = EventBuilder::new("run")
        .provider(provider)
        .command(&parsed_parts.join(" "))
        .exit_code(exit_code)
        .duration_ms(duration_ms)
        .secrets_count(secrets_count as i32);

    if let Some(proj) = project_name {
        event = event.project(proj);
    }
    if let Some(env) = current_env {
        event = event.env(&env);
    }
    if let Some(prof) = current_profile {
        event = event.profile(&prof);
    }

    let _ = event.record();

    result
}

/// Build env var map from provider bindings for injection into a child process.
///
/// Pure logic extracted from `run_with_active_key` for testability.
/// Returns `(env_map, injected_provider_codes, used_legacy_fallback)`.
pub fn build_run_env(
    bindings: &[crate::storage::ProviderBinding],
    legacy_cfg: Option<&crate::storage::ActiveKeyConfig>,
    proxy_port: u16,
) -> Result<(std::collections::HashMap<String, String>, Vec<String>, bool), String> {
    use crate::commands_account::{provider_env_vars_pub, provider_proxy_prefix_pub};

    let mut env_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut injected_providers: Vec<String> = Vec::new();
    let mut used_legacy = false;

    if !bindings.is_empty() {
        // ---- New model: per-provider bindings ----
        for binding in bindings {
            let token = match &binding.key_source_type {
                crate::credential_type::CredentialType::ManagedVirtualKey => format!("aikey_vk_{}", binding.key_source_ref),
                crate::credential_type::CredentialType::PersonalApiKey => format!("aikey_personal_{}", binding.key_source_ref),
                crate::credential_type::CredentialType::PersonalOAuthAccount => format!("aikey_oauth_{}", binding.key_source_ref),
            };

            if let Some((api_var, base_var)) = provider_env_vars_pub(&binding.provider_code) {
                env_map.insert(api_var.to_string(), token);
                let base_url = format!(
                    "http://127.0.0.1:{}/{}",
                    proxy_port,
                    provider_proxy_prefix_pub(&binding.provider_code),
                );
                env_map.insert(base_var.to_string(), base_url);
                injected_providers.push(binding.provider_code.clone());
            }
        }
    } else if let Some(active_cfg) = legacy_cfg {
        // ---- Fallback: legacy single-key active_key_config (pre-migration compat) ----
        used_legacy = true;
        let providers: Vec<String> = if active_cfg.providers.is_empty() {
            vec!["anthropic", "openai", "google", "deepseek", "kimi"]
                .into_iter().map(String::from).collect()
        } else {
            active_cfg.providers.clone()
        };

        let token_value = if active_cfg.key_type == crate::credential_type::CredentialType::ManagedVirtualKey {
            format!("aikey_vk_{}", active_cfg.key_ref)
        } else {
            format!("aikey_personal_{}", active_cfg.key_ref)
        };

        for provider in &providers {
            if let Some((api_var, base_var)) = provider_env_vars_pub(provider) {
                env_map.insert(api_var.to_string(), token_value.clone());
                let base_url = format!(
                    "http://127.0.0.1:{}/{}",
                    proxy_port,
                    provider_proxy_prefix_pub(provider),
                );
                env_map.insert(base_var.to_string(), base_url);
                injected_providers.push(provider.clone());
            }
        }
    }

    Ok((env_map, injected_providers, used_legacy))
}

/// Execute a command using provider-level key bindings via proxy.
///
/// Reads `user_profile_provider_bindings` (profile = "default") to determine
/// per-provider key sources, then injects proxy-routed env vars (e.g.
/// `ANTHROPIC_API_KEY=aikey_vk_xxx`, `OPENAI_API_KEY=aikey_personal_yyy`,
/// `*_BASE_URL=http://127.0.0.1:27200/{provider}`) into the child process.
///
/// Fallback: if no provider bindings exist (pre-migration vault), falls back
/// to the legacy `active_key_config` single-key model for backward compat.
///
/// Returns `(secrets_injected, exit_code)`.
pub fn run_with_active_key(
    command: &[String],
    json_mode: bool,
) -> Result<(usize, i32), String> {
    let bindings = crate::storage::list_provider_bindings("default")
        .map_err(|e| format!("Failed to read provider bindings: {}", e))?;

    let legacy_cfg = crate::storage::get_active_key_config()
        .map_err(|e| format!("Failed to read active key config: {}", e))?;

    let proxy_port: u16 = crate::commands_proxy::proxy_port();

    let (env_map, injected_providers, used_legacy) =
        build_run_env(&bindings, legacy_cfg.as_ref(), proxy_port)?;

    if injected_providers.is_empty() {
        return Err("No provider bindings configured. Run `aikey use` to set up provider key bindings.".to_string());
    }

    let mut env_secrets: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::new();
    for (k, v) in env_map {
        env_secrets.insert(k, Zeroizing::new(v));
    }

    if !json_mode {
        eprintln!("Injecting {} provider(s) via proxy:", injected_providers.len());
        if !used_legacy {
            for binding in &bindings {
                if injected_providers.contains(&binding.provider_code) {
                    eprintln!("  {} -> {}:{}", binding.provider_code, binding.key_source_type, binding.key_source_ref);
                }
            }
        } else {
            eprintln!("  (legacy active_key_config fallback)");
        }
    }

    spawn_with_env(env_secrets, command, json_mode, None)
}

/// Execute a command with secrets resolved from a project config.
/// Password-based version (no daemon).
///
/// Resolution order (Stage0 Decision I - mapping-closed boundary):
/// - If `envMappings[env]` exists and is non-empty: inject only mapping-derived credentials (closed set)
/// - If `envMappings[env]` is missing/empty: fall back to `config.providers`
/// Fallback injection when no project config and no `--provider` flag is given.
///
/// Scans vault aliases for `{provider}:{name}` patterns, picks the `:default`
/// variant per provider (or first found), and injects the canonical env var for
/// each detected provider.  This allows `aikey run -- <cmd>` to work without any
/// project config file.
///
/// Returns `(secrets_injected, exit_code)`.
pub fn run_from_vault(
    password: &SecretString,
    command: &[String],
    json_mode: bool,
) -> Result<(usize, i32), String> {
    let ctx = VaultContext::new(password)?;
    let aliases = storage::list_entries().unwrap_or_default();

    if aliases.is_empty() {
        return Err(
            "No API Keys stored. Add one with:\n  aikey add anthropic:default".to_string()
        );
    }

    // Group aliases by provider prefix (format: "provider:name").
    // Prefer ":default" variant; fall back to first seen per provider.
    let mut provider_alias: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for alias in &aliases {
        if let Some((provider, _)) = alias.split_once(':') {
            let is_default = alias.ends_with(":default");
            if is_default || !provider_alias.contains_key(provider) {
                provider_alias.insert(provider.to_string(), alias.clone());
            }
        }
    }

    if provider_alias.is_empty() {
        return Err(
            "No provider keys found in vault (expected format: provider:alias).\n\
             Add one with: aikey add anthropic:default".to_string()
        );
    }

    let mut env_secrets: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::new();

    for (provider_name, key_alias) in &provider_alias {
        let env_var = Provider::parse(provider_name).env_var();
        match storage::get_entry(key_alias) {
            Ok((nonce, ciphertext)) => {
                match ctx.decrypt(&nonce, &ciphertext) {
                    Ok(plaintext) => {
                        let secret = std::str::from_utf8(&plaintext)
                            .map_err(|e| format!("Invalid UTF-8 in secret '{}': {}", key_alias, e))?
                            .to_string();
                        env_secrets.insert(env_var, Zeroizing::new(secret));
                    }
                    Err(e) => {
                        if !json_mode {
                            eprintln!("Warning: could not decrypt '{}': {}", key_alias, e);
                        }
                    }
                }
            }
            Err(e) => {
                if !json_mode {
                    eprintln!("Warning: could not fetch '{}': {}", key_alias, e);
                }
            }
        }
    }

    if env_secrets.is_empty() {
        return Err("No secrets could be decrypted from vault.".to_string());
    }

    let secrets_count = env_secrets.len();
    if !json_mode {
        eprintln!("Injecting {} secret(s) (vault-auto)", secrets_count);
    }

    spawn_with_env(env_secrets, command, json_mode, None)
}

/// - `config.required_vars` are always resolved independently
///
/// Returns `(secrets_injected, exit_code)`.
pub fn run_with_project_config(
    config: &ProjectConfig,
    password: &SecretString,
    command: &[String],
    json_mode: bool,
    logical_model: Option<&str>,
    tenant: Option<&str>,
) -> Result<(usize, i32), String> {
    let ctx = VaultContext::new(password)?;
    let mut env_secrets: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::new();

    // Stage0 Decision I: Mapping-closed injection boundary
    let current_env = crate::global_config::get_current_env().ok().flatten();
    let has_env_mappings = current_env.as_ref()
        .and_then(|env| config.env_mappings.get(env.as_str()))
        .map(|map| !map.is_empty())
        .unwrap_or(false);

    if has_env_mappings {
        // Mapping-closed mode: inject only from env_mappings
        let injection_set = compute_injection_set_from_env_mappings(
            config,
            current_env.as_ref().unwrap(),
            logical_model,
            tenant,
        )?;

        for (provider, key_alias, _model) in injection_set {
            let env_var = Provider::parse(&provider).env_var();
            match storage::get_entry(&key_alias) {
                Ok((nonce, ciphertext)) => {
                    match ctx.decrypt(&nonce, &ciphertext) {
                        Ok(plaintext) => {
                            let secret = std::str::from_utf8(&plaintext)
                                .map_err(|e| format!("Invalid UTF-8 in secret '{}': {}", key_alias, e))?
                                .to_string();
                            env_secrets.insert(env_var, Zeroizing::new(secret));
                        }
                        Err(e) => {
                            if !json_mode {
                                eprintln!("Warning: could not decrypt secret '{}': {}", key_alias, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !json_mode {
                        eprintln!("Warning: could not fetch secret '{}' for provider '{}': {}", key_alias, provider, e);
                    }
                }
            }
        }
    } else {
        // Fallback mode: use config.providers (legacy compatibility)
        for (provider_name, provider_cfg) in &config.providers {
            let env_var = Provider::parse(provider_name).env_var();
            match storage::get_entry(&provider_cfg.key_alias) {
                Ok((nonce, ciphertext)) => {
                    match ctx.decrypt(&nonce, &ciphertext) {
                        Ok(plaintext) => {
                            let secret = std::str::from_utf8(&plaintext)
                                .map_err(|e| format!("Invalid UTF-8 in secret: {}", e))?
                                .to_string();
                            env_secrets.insert(env_var, Zeroizing::new(secret));
                        }
                        Err(e) => {
                            if !json_mode {
                                eprintln!("Warning: could not decrypt secret '{}': {}", provider_cfg.key_alias, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !json_mode {
                        eprintln!("Warning: could not fetch secret '{}' for provider '{}': {}", provider_cfg.key_alias, provider_name, e);
                    }
                }
            }
        }
    }

    // 2. requiredVars resolution via bindings
    // Stage0 Decision I: requiredVars collision detection
    for var_name in &config.required_vars {
        if env_secrets.contains_key(var_name) {
            return Err(format!(
                "Collision detected: requiredVars entry '{}' collides with a provider env var.\n\
                 \n\
                 Fix:\n\
                 - Remove '{}' from requiredVars if it should come from a provider\n\
                 - Or rename the provider env var to avoid collision\n\
                 - requiredVars and provider env vars must not overlap",
                var_name, var_name
            ));
        }

        // Use binding if exists, otherwise use var_name as alias
        let alias = config.bindings.get(var_name)
            .cloned()
            .unwrap_or_else(|| var_name.clone());

        match storage::get_entry(&alias) {
            Ok((nonce, ciphertext)) => {
                match ctx.decrypt(&nonce, &ciphertext) {
                    Ok(plaintext) => {
                        let secret = std::str::from_utf8(&plaintext)
                            .map_err(|e| format!("Invalid UTF-8 in secret: {}", e))?
                            .to_string();
                        env_secrets.insert(var_name.clone(), Zeroizing::new(secret));
                    }
                    Err(e) => {
                        if !json_mode {
                            eprintln!("Warning: could not decrypt secret '{}': {}", alias, e);
                        }
                    }
                }
            }
            Err(e) => {
                if !json_mode {
                    eprintln!("Warning: could not fetch secret '{}' for var '{}': {}", alias, var_name, e);
                }
            }
        }
    }

    let secrets_count = env_secrets.len();
    if !json_mode {
        let mode = if has_env_mappings { "mapping-closed" } else { "provider-fallback" };
        eprintln!("Injecting {} secret(s) ({})", secrets_count, mode);
    }

    let parsed_parts: Vec<String> = if command.len() == 1 {
        shell_words::split(&command[0])
            .map_err(|e| format!("Failed to parse command '{}': {}", command[0], e))?
    } else {
        command.to_vec()
    };

    let t0 = std::time::Instant::now();
    let result = spawn_with_env(env_secrets, command, json_mode, Some(config.project.name.as_str()));
    let duration_ms = t0.elapsed().as_millis() as i64;
    let exit_code = match &result {
        Ok((_, c)) => *c,
        Err(e) => e.strip_prefix("Command exited with code ")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1)
    };

    // Get current profile from global config for event recording
    let current_profile = crate::global_config::get_current_profile().ok().flatten();

    let mut event = EventBuilder::new("run")
        .command(&parsed_parts.join(" "))
        .exit_code(exit_code)
        .duration_ms(duration_ms)
        .secrets_count(secrets_count as i32)
        .project(&config.project.name);

    if let Some(env) = &current_env {
        event = event.env(env);
    }
    if let Some(prof) = current_profile {
        event = event.profile(&prof);
    }

    let _ = event.record();

    result
}

/// Dry-run for provider mode - shows what would be injected without executing.
/// No password needed (metadata only).
pub fn dry_run_provider(
    provider: &str,
    model: Option<&str>,
    tenant: Option<&str>,
    config: Option<&ProjectConfig>,
) -> Result<Vec<DryRunInfo>, String> {
    use crate::resolver::{resolve, ResolveRequest, ResolveSource};

    let request = ResolveRequest {
        provider: provider.to_string(),
        model: model.map(|s| s.to_string()),
        tenant: tenant.map(|s| s.to_string()),
        ..Default::default()
    };

    let resolved = resolve(&request, config).map_err(|e| e.to_string())?;

    let source = match resolved.source {
        ResolveSource::Explicit => "Explicit",
        ResolveSource::Tenant => "Tenant",
        ResolveSource::Base => "Base",
        ResolveSource::LogicalModel => "LogicalModel",
    };

    let info = DryRunInfo {
        env_var: resolved.env_var,
        provider: resolved.provider,
        model: resolved.model,
        key_alias: resolved.key_alias,
        tenant_override: resolved.source == ResolveSource::Tenant,
        source: source.to_string(),
    };

    Ok(vec![info])
}

/// Dry-run for project config mode - shows what would be injected without executing.
/// No password needed (metadata only).
pub fn dry_run_project_config(
    config: &ProjectConfig,
    logical_model: Option<&str>,
    tenant: Option<&str>,
) -> Result<Vec<DryRunInfo>, String> {
    let current_env = crate::global_config::get_current_env()
        .ok()
        .flatten()
        .ok_or("No current environment set. Use 'aikey env use <env>'")?;

    let has_env_mappings = config.env_mappings.get(&current_env)
        .map(|map| !map.is_empty())
        .unwrap_or(false);

    let mut infos = Vec::new();

    if has_env_mappings {
        // Use compute_injection_set_with_tenant_tracking for accurate tenant_override tracking
        let injection_set = compute_injection_set_with_tenant_tracking(
            config,
            &current_env,
            logical_model,
            tenant,
        )?;

        for (provider, key_alias, model, tenant_override_applied) in injection_set {
            let env_var = Provider::parse(&provider).env_var();
            infos.push(DryRunInfo {
                env_var,
                provider,
                model,
                key_alias,
                tenant_override: tenant_override_applied,
                source: "LogicalModel".to_string(),
            });
        }
    } else {
        // Fallback mode: use config.providers
        for (provider_name, provider_cfg) in &config.providers {
            let env_var = Provider::parse(provider_name).env_var();
            infos.push(DryRunInfo {
                env_var,
                provider: provider_name.clone(),
                model: provider_cfg.default_model.clone(),
                key_alias: provider_cfg.key_alias.clone(),
                tenant_override: false,
                source: "Base".to_string(),
            });
        }
    }

    // Sort byr stable output
    infos.sort_by(|a, b| a.env_var.cmp(&b.env_var));

    Ok(infos)
}
