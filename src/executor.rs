use crate::crypto;
use crate::storage;
use crate::config::ProjectConfig;
use crate::providers::Provider;
use crate::daemon_client::DaemonClient;
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
        storage::ensure_vault_exists()?;

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
                // Password hash doesn't exist (old database), create it for future use
                // This is a migration path for databases created before password verification was added
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
        return Err(format!("Secret '{}' already exists. Use 'update' command to modify it.", alias));
    }

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
        return Err(format!("Secret '{}' not found", alias));
    }

    // Encrypt and store the new value
    let ctx = VaultContext::new(password)?;
    let (nonce, ciphertext) = ctx.encrypt(new_secret.as_bytes())?;
    storage::store_entry(alias, &nonce, &ciphertext)
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
/// use aikeylabs_ak::executor::exec_with_env;
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
/// use aikeylabs_ak::executor::run_with_all_secrets;
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

    let _ = EventBuilder::new("run")
        .command(&parsed_parts.join(" "))
        .exit_code(exit_code)
        .duration_ms(duration_ms)
        .secrets_count(secrets_count as i32)
        .record();

    // Return secrets count and exit code
    if !status.success() {
        return Err(format!("Command exited with code {}", exit_code));
    }

    Ok((secrets_count, exit_code))
}

/// Execute a command with environment variables resolved via daemon RPC
/// This avoids direct vault access and relies on daemon for secret retrieval.
pub fn exec_with_env_via_daemon(
    env_mappings: &[String],
    command: &[String],
    client: &DaemonClient,
) -> Result<(), String> {
    if command.is_empty() {
        return Err("No command specified".to_string());
    }

    let mut env_secrets: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::with_capacity(env_mappings.len());

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

            // Fetch secret value via daemon
            let value = client.get_secret(alias)?;
            Ok((env_name.to_string(), Zeroizing::new(value)))
        })
        .collect();

    for (env_name, secret) in decryption_results? {
        env_secrets.insert(env_name, secret);
    }

    spawn_with_env(env_secrets, command, false, None).map(|_| ())
}

/// Inject non-sensitive context vars (AIKEY_PROJECT, AIKEY_ENV, AIKEY_PROFILE)
/// into a Command. Values are sourced from global config; missing values are silently skipped.
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

/// Execute a command with ALL secrets fetched via daemon RPC
pub fn run_with_all_secrets_via_daemon(
    command: &[String],
    json_mode: bool,
    client: &DaemonClient,
) -> Result<(usize, i32), String> {
    let aliases = client.list_secrets()?;

    if aliases.is_empty() {
        return Err("No secrets found in vault".to_string());
    }

    let secrets_count = aliases.len();
    if !json_mode {
        eprintln!("Injecting {} secret(s)", secrets_count);
    }

    let mut env_secrets: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::with_capacity(aliases.len());

    for alias in &aliases {
        let value = client.get_secret(alias)?;
        let env_name = alias.to_uppercase().replace('-', "_");
        env_secrets.insert(env_name, Zeroizing::new(value));
    }

    spawn_with_env(env_secrets, command, json_mode, None)
}

/// Execute a command with a single provider's key resolved via the 5-step resolver.
///
/// Uses `resolver::resolve` to determine the vault alias, then fetches it via daemon
/// and injects it as the provider's canonical env var (e.g. `OPENAI_API_KEY`).
/// If `model` is resolved, it is also injected as `AIKEY_MODEL`.
pub fn run_with_provider_via_daemon(
    provider: &str,
    model: Option<&str>,
    tenant: Option<&str>,
    config: Option<&ProjectConfig>,
    command: &[String],
    json_mode: bool,
    client: &DaemonClient,
) -> Result<(usize, i32), String> {
    use crate::resolver::{resolve, ResolveRequest};

    let request = ResolveRequest {
        provider: provider.to_string(),
        model: model.map(|s| s.to_string()),
        tenant: tenant.map(|s| s.to_string()),
        ..Default::default()
    };

    let resolved = resolve(&request, config).map_err(|e| e.to_string())?;

    let profile = client.get_current_profile().unwrap_or_else(|_| "default".to_string());
    let secret = client.get_secret(&resolved.key_alias)
        .map_err(|_| format!("Missing key: {}:{} in profile '{}'", provider, resolved.key_alias, profile))?;

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
    let exit_code = match &result { Ok((_, c)) => *c, Err(e) => e.strip_prefix("Command exited with code ").and_then(|s| s.parse().ok()).unwrap_or(1) };

    let _ = EventBuilder::new("run")
        .provider(provider)
        .command(&parsed_parts.join(" "))
        .exit_code(exit_code)
        .duration_ms(duration_ms)
        .secrets_count(secrets_count as i32)
        .record();

    result
}

/// Compute injection set from env_mappings with tenant override tracking
/// Returns (provider, keyAlias, model, tenant_override_applied)
/// tenant_override_applied is true ONLY when a tenant override actually matched and changed the key_alias
fn compute_injection_set_with_tenant_tracking(
    config: &ProjectConfig,
    env: &str,
    logical_model_filter: Option<&str>,
    tenant: Option<&str>,
) -> Vec<(String, String, Option<String>, bool)> {
    use crate::resolver::{resolve, ResolveRequest};
    use std::collections::HashSet;

    let mut injection_set = Vec::new();
    let mut seen = HashSet::new();

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
                let key = (resolved.provider.clone(), resolved.key_alias.clone());
                if !seen.contains(&key) {
                    seen.insert(key);

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
    }

    injection_set
}

/// Execute a command with secrets resolved from a project config via daemon RPC.
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
) -> Vec<(String, String, Option<String>)> {
    compute_injection_set_with_tenant_tracking(config, env, logical_model_filter, tenant)
        .into_iter()
        .map(|(provider, key_alias, model, _)| (provider, key_alias, model))
        .collect()
}

pub fn run_with_project_config_via_daemon(
    config: &ProjectConfig,
    command: &[String],
    json_mode: bool,
    client: &DaemonClient,
    logical_model: Option<&str>,
    tenant: Option<&str>,
) -> Result<(usize, i32), String> {
    let mut env_secrets: std::collections::HashMap<String, Zeroizing<String>> =
        std::collections::HashMap::new();

    // Stage0 Decision I: Mapping-closed injection boundary
    // If envMappings[env] exists and is non-empty, inject only mapping-derived credentials (closed set)
    // Only fall back to config.providers when mappings are missing/empty
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
        );

        for (provider, key_alias, _model) in injection_set {
            let env_var = Provider::parse(&provider).env_var();
            match client.get_secret(&key_alias) {
                Ok(value) => {
                    env_secrets.insert(env_var, Zeroizing::new(value));
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
            match client.get_secret(&provider_cfg.key_alias) {
                Ok(value) => { env_secrets.insert(env_var, Zeroizing::new(value)); }
                Err(e) => {
                    if !json_mode {
                        eprintln!("Warning: could not fetch secret '{}' for provider '{}': {}", provider_cfg.key_alias, provider_name, e);
                    }
                }
            }
        }
    }

    // 2. requiredVars resolution via active profile bindings
    // Build a domain->alias map from the active profile's bindings
    let binding_map: std::collections::HashMap<String, String> = client
        .get_current_profile()
        .ok()
        .and_then(|profile| client.list_bindings(&profile).ok())
        .unwrap_or_default()
        .into_iter()
        .collect();

    for var_name in &config.required_vars {
        if env_secrets.contains_key(var_name) {
            continue; // already set by providers block
        }
        // binding map: domain -> alias; fall back to var_name as alias
        let alias = binding_map.get(var_name).cloned().unwrap_or_else(|| var_name.clone());
        match client.get_secret(&alias) {
            Ok(value) => { env_secrets.insert(var_name.clone(), Zeroizing::new(value)); }
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
    let exit_code = match &result { Ok((_, c)) => *c, Err(e) => e.strip_prefix("Command exited with code ").and_then(|s| s.parse().ok()).unwrap_or(1) };

    let _ = EventBuilder::new("run")
        .command(&parsed_parts.join(" "))
        .exit_code(exit_code)
        .duration_ms(duration_ms)
        .secrets_count(secrets_count as i32)
        .record();

    result
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

/// Dry-run variant of `run_with_provider_via_daemon`.
///
/// Resolves the provider key alias and returns the list of env var names that
/// would be injected, without actually running any command.
pub fn dry_run_provider(
    provider: &str,
    model: Option<&str>,
    tenant: Option<&str>,
    config: Option<&ProjectConfig>,
    client: &DaemonClient,
) -> Result<Vec<DryRunInfo>, String> {
    use crate::resolver::{resolve, ResolveRequest, ResolveSource};

    let request = ResolveRequest {
        provider: provider.to_string(),
        model: model.map(|s| s.to_string()),
        tenant: tenant.map(|s| s.to_string()),
        ..Default::default()
    };

    let resolved = resolve(&request, config).map_err(|e| e.to_string())?;

    // Validate the secret is accessible
    let profile = client.get_current_profile().unwrap_or_else(|_| "default".to_string());
    client.get_secret(&resolved.key_alias)
        .map_err(|_| format!("Missing key: {}:{} in profile '{}'", provider, resolved.key_alias, profile))?;

    // P1-Q4: Return detailed dry-run information
    let tenant_override = matches!(resolved.source, ResolveSource::Tenant);
    let source = format!("{:?}", resolved.source);

    let mut infos = vec![DryRunInfo {
        env_var: resolved.env_var.clone(),
        provider: resolved.provider.clone(),
        model: resolved.model.clone(),
        key_alias: resolved.key_alias.clone(),
        tenant_override,
        source,
    }];

    // Add AIKEY_MODEL if model is present
    if resolved.model.is_some() {
        infos.push(DryRunInfo {
            env_var: "AIKEY_MODEL".to_string(),
            provider: resolved.provider.clone(),
            model: resolved.model.clone(),
            key_alias: String::new(), // Not applicable for AIKEY_MODEL
            tenant_override: false,
            source: "Context".to_string(),
        });
    }

    Ok(infos)
}

/// Dry-run variant of `run_with_project_config_via_daemon`.
///
/// Stage0 Decision H: --dry-run output contract
/// - No execution occurs
/// - No secret values shown
/// - Stable output ordering (sorted by env_var)
/// - Strict tenant_override_applied (true only when override actually matched and changed key_alias)
/// - Implements mapping-closed boundary (same as run)
pub fn dry_run_project_config(
    config: &ProjectConfig,
    client: &DaemonClient,
    logical_model: Option<&str>,
    tenant: Option<&str>,
) -> Result<Vec<DryRunInfo>, String> {
    let mut infos: Vec<DryRunInfo> = Vec::new();
    let profile = client.get_current_profile().unwrap_or_else(|_| "default".to_string());

    // Stage0 Decision I: Mapping-closed injection boundary (same as run)
    let current_env = crate::global_config::get_current_env().ok().flatten();
    let has_env_mappings = current_env.as_ref()
        .and_then(|env| config.env_mappings.get(env.as_str()))
        .map(|map| !map.is_empty())
        .unwrap_or(false);

    if has_env_mappings {
        // Mapping-closed mode: inject only from env_mappings
        let injection_set = compute_injection_set_with_tenant_tracking(
            config,
            current_env.as_ref().unwrap(),
            logical_model,
            tenant,
        );

        for (provider, key_alias, model, tenant_override_applied) in injection_set {
            let env_var = Provider::parse(&provider).env_var();
            client.get_secret(&key_alias)
                .map_err(|_| format!("Missing key: {}:{} in profile '{}'", provider, key_alias, profile))?;

            infos.push(DryRunInfo {
                env_var,
                provider: provider.clone(),
                model,
                key_alias: key_alias.clone(),
                tenant_override: tenant_override_applied,
                source: "LogicalModel".to_string(),
            });
        }
    } else {
        // Fallback mode: use config.providers (legacy compatibility)
        for (provider_name, provider_cfg) in &config.providers {
            let env_var = Provider::parse(provider_name).env_var();
            client.get_secret(&provider_cfg.key_alias)
                .map_err(|_| format!("Missing key: {}:{} in profile '{}'", provider_name, provider_cfg.key_alias, profile))?;

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

    let binding_map: std::collections::HashMap<String, String> = client
        .list_bindings(&profile)
        .unwrap_or_default()
        .into_iter()
        .collect();

    for var_name in &config.required_vars {
        // Skip if already added from providers
        if infos.iter().any(|info| info.env_var == *var_name) {
            continue;
        }
        let alias = binding_map.get(var_name).cloned().unwrap_or_else(|| var_name.clone());
        client.get_secret(&alias)
            .map_err(|_| format!("Missing key: {} in profile '{}'", alias, profile))?;

        infos.push(DryRunInfo {
            env_var: var_name.clone(),
            provider: "custom".to_string(),
            model: None,
            key_alias: alias,
            tenant_override: false,
            source: "Binding".to_string(),
        });
    }

    // Stage0 Decision H: Stable output ordering (sort by env_var)
    infos.sort_by(|a, b| a.env_var.cmp(&b.env_var));

    Ok(infos)
}
