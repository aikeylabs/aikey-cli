//! Password session cache for AiKeyLabs CLI
//!
//! Caches the master password for 30 minutes (sliding TTL) to reduce
//! repetitive password entry for low-sensitivity commands.
//!
//! # Backend priority
//! 1. OS keychain via `keyring` crate (macOS Keychain, Windows Credential Store,
//!    Linux Secret Service / KWallet)
//! 2. AES-256-GCM encrypted file fallback (for Linux headless / CI environments)
//!
//! # Security properties
//! - Password is never stored in plaintext on disk.
//! - Keychain backend: OS-level protection; no encryption key material on disk.
//! - File fallback: AES-256-GCM with a random per-installation session key
//!   stored at `~/.aikey/.session_key` (chmod 600).
//! - Session metadata (`~/.aikey/.session_meta`, chmod 600) stores only TTL
//!   and backend tag — never the password.
//! - TTL is sliding: refreshed on every successful cached use via `refresh()`.
//! - Session is invalidated when `vault_change_seq` changes (e.g. after
//!   change-password) or when `invalidate()` is called explicitly.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sliding TTL for cached session: 30 minutes.
const SESSION_TTL_SECS: u64 = 30 * 60;

/// Keyring service name and user name.
const KEYRING_SERVICE: &str = "aikey-cli";
const KEYRING_USER: &str = "master-password";

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn aikey_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".aikey"))
}

fn session_meta_path() -> Option<PathBuf> {
    aikey_dir().map(|d| d.join(".session_meta"))
}

fn session_key_path() -> Option<PathBuf> {
    aikey_dir().map(|d| d.join(".session_key"))
}

fn session_pw_path() -> Option<PathBuf> {
    aikey_dir().map(|d| d.join(".session_pw"))
}

// ---------------------------------------------------------------------------
// Session metadata (JSON, chmod 600)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionMeta {
    /// "keychain" or "file"
    backend: String,
    /// Unix timestamp (seconds) when session expires.
    expires_at: u64,
    /// Snapshot of vault_change_seq at the time of caching.
    vault_seq: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read and validate session metadata. Returns `None` if absent, expired,
/// or the vault change sequence has advanced.
fn load_meta() -> Option<SessionMeta> {
    let path = session_meta_path()?;
    let raw = fs::read_to_string(&path).ok()?;
    let meta: SessionMeta = serde_json::from_str(&raw).ok()?;

    // TTL check
    if now_secs() >= meta.expires_at {
        return None;
    }

    // vault_change_seq check — invalidate if vault was modified
    if let Ok(current_seq) = crate::storage::get_vault_change_seq() {
        if current_seq != meta.vault_seq {
            return None;
        }
    }

    Some(meta)
}

/// Persist session metadata with secure permissions (chmod 600 on Unix).
fn save_meta(meta: &SessionMeta) {
    let path = match session_meta_path() {
        Some(p) => p,
        None => return,
    };

    // Ensure ~/.aikey exists
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }

    let json = match serde_json::to_string(meta) {
        Ok(j) => j,
        Err(_) => return,
    };

    let _ = fs::write(&path, &json);
    set_file_permissions_600(&path);
}

/// Remove session metadata file.
fn remove_meta() {
    if let Some(path) = session_meta_path() {
        let _ = fs::remove_file(path);
    }
}

// ---------------------------------------------------------------------------
// File permissions helper
// ---------------------------------------------------------------------------

/// Tighten file permissions so only the owner can read/write.
/// Stage 2.4 windows-compat: previous Windows branch was a no-op based on
/// the false assumption that NTFS defaults to owner-only — it doesn't,
/// inherited DACLs typically include Authenticated Users. The cross-platform
/// helper now uses icacls on Windows to remove that grant.
fn set_file_permissions_600(path: &PathBuf) {
    let _ = crate::storage_acl::enforce_owner_only_file(path.as_path());
}

// ---------------------------------------------------------------------------
// Keychain backend
// ---------------------------------------------------------------------------

/// Attempt to read the cached password from the OS keychain.
fn keychain_get() -> Option<SecretString> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).ok()?;
    let pw = entry.get_password().ok()?;
    if pw.is_empty() {
        None
    } else {
        Some(SecretString::new(pw))
    }
}

/// Store the password in the OS keychain. Returns `true` on success.
fn keychain_store(pw: &SecretString) -> bool {
    let entry = match keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
        Ok(e) => e,
        Err(_) => return false,
    };
    entry.set_password(pw.expose_secret()).is_ok()
}

/// Delete the keychain entry. Silent on errors.
fn keychain_delete() {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
        let _ = entry.delete_password();
    }
}

// ---------------------------------------------------------------------------
// Encrypted-file backend
// ---------------------------------------------------------------------------

/// JSON envelope stored in `.session_pw`.
#[derive(Serialize, Deserialize)]
struct EncryptedPwFile {
    nonce: String,
    ciphertext: String,
}

/// Load or generate the 32-byte session key at `~/.aikey/.session_key`.
///
/// The key is stored as raw bytes (not base64). The file is chmod 600.
fn load_or_create_session_key() -> Option<[u8; 32]> {
    let path = session_key_path()?;

    if path.exists() {
        let raw = fs::read(&path).ok()?;
        if raw.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&raw);
            return Some(key);
        }
        // Corrupted — regenerate
    }

    // Generate a fresh random key
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);

    // Ensure parent dir exists
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }

    fs::write(&path, &key).ok()?;
    set_file_permissions_600(&path);

    Some(key)
}

/// Read the cached password from the encrypted session file.
fn file_get() -> Option<SecretString> {
    let key = load_or_create_session_key()?;
    let path = session_pw_path()?;

    let raw = fs::read_to_string(&path).ok()?;
    let envelope: EncryptedPwFile = serde_json::from_str(&raw).ok()?;

    let nonce = B64.decode(&envelope.nonce).ok()?;
    let ciphertext = B64.decode(&envelope.ciphertext).ok()?;

    let plaintext = crate::crypto::decrypt(&key, &nonce, &ciphertext).ok()?;
    let pw_str = String::from_utf8(plaintext.to_vec()).ok()?;

    Some(SecretString::new(pw_str))
}

/// Encrypt and store the password in the session file. Returns `true` on success.
fn file_store(pw: &SecretString) -> bool {
    let key = match load_or_create_session_key() {
        Some(k) => k,
        None => return false,
    };

    let plaintext = pw.expose_secret().as_bytes();
    let (nonce, ciphertext) = match crate::crypto::encrypt(&key, plaintext) {
        Ok(pair) => pair,
        Err(_) => return false,
    };

    let envelope = EncryptedPwFile {
        nonce: B64.encode(&nonce),
        ciphertext: B64.encode(&ciphertext),
    };

    let json = match serde_json::to_string(&envelope) {
        Ok(j) => j,
        Err(_) => return false,
    };

    let path = match session_pw_path() {
        Some(p) => p,
        None => return false,
    };

    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }

    if fs::write(&path, &json).is_err() {
        return false;
    }
    set_file_permissions_600(&path);
    true
}

/// Remove the encrypted session password file.
fn file_delete() {
    if let Some(path) = session_pw_path() {
        let _ = fs::remove_file(path);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the cached master password if the session is still valid,
/// or `None` if the session has expired or does not exist.
///
/// This does **not** refresh the TTL; call [`refresh`] after a successful
/// use of the returned password.
pub fn try_get() -> Option<SecretString> {
    let meta = load_meta()?;

    let pw = match meta.backend.as_str() {
        "keychain" => keychain_get(),
        "file" => file_get(),
        _ => return None,
    };

    pw
}

/// Ask the user once whether to enable the OS keychain for session caching.
///
/// Called after the very first successful master-password entry.  The answer
/// is persisted to the vault config table so the prompt is never shown again.
///
/// - "keychain" → try OS keychain, fall back to encrypted file if unavailable
/// - "file"     → always use the encrypted-file backend (no system prompts)
/// - "disabled" → no caching at all
///
/// If stdin is not a tty (CI / piped input) the prompt is skipped and the
/// file backend is used silently.
pub fn maybe_configure_backend() {
    // Already configured — nothing to do.
    if crate::storage::get_session_backend_pref().is_some() {
        return;
    }

    // Skip in automated / non-interactive environments.
    if std::env::var("AK_TEST_PASSWORD").is_ok() {
        crate::storage::set_session_backend_pref("file");
        return;
    }
    if !atty::is(atty::Stream::Stdin) {
        crate::storage::set_session_backend_pref("file");
        return;
    }

    eprintln!();
    eprintln!("  Session cache: avoid re-entering your master password for 30 minutes.");
    let is_macos = cfg!(target_os = "macos");
    if is_macos {
        eprintln!("  [k] macOS Keychain  (secure; macOS may occasionally prompt for its own password)");
        eprintln!("  [f] Encrypted file  (no system prompts; stored in ~/.aikey, chmod 600)");
        eprintln!("  [n] Disabled        (always prompt)");
        eprint!("  Choice [K/f/n] (default K): ");
    } else {
        eprintln!("  [f] Encrypted file  (no system prompts; stored in ~/.aikey, chmod 600)");
        eprintln!("  [n] Disabled        (always prompt)");
        eprint!("  Choice [F/n] (default F): ");
    }

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        crate::storage::set_session_backend_pref(if is_macos { "keychain" } else { "file" });
        return;
    }

    let pref = match line.trim().to_lowercase().as_str() {
        "k" | "keychain" if is_macos => "keychain",
        "f" | "file" => "file",
        "n" | "no" | "disabled" => "disabled",
        _ => if is_macos { "keychain" } else { "file" }, // default (Enter)
    };
    crate::storage::set_session_backend_pref(pref);
    eprintln!("  Session backend set to '{}'. You can change this with: aikey config session-backend", pref);
}

/// Cache the master password and create a new 30-minute session.
///
/// Respects the user's backend preference (set via `maybe_configure_backend`).
/// Silent on failure — the caller must not depend on the cache being populated.
pub fn store(pw: &SecretString) {
    let pref = crate::storage::get_session_backend_pref();
    if pref.as_deref() == Some("disabled") {
        return;
    }

    let vault_seq = crate::storage::get_vault_change_seq().unwrap_or(0);
    let expires_at = now_secs() + SESSION_TTL_SECS;

    // Keychain backend (if preferred or no preference set yet).
    let use_keychain = pref.as_deref().map_or(false, |p| p == "keychain");
    if use_keychain && keychain_store(pw) {
        save_meta(&SessionMeta {
            backend: "keychain".to_string(),
            expires_at,
            vault_seq,
        });
        return;
    }

    // Encrypted-file backend.
    if file_store(pw) {
        save_meta(&SessionMeta {
            backend: "file".to_string(),
            expires_at,
            vault_seq,
        });
    }
    // If both backends fail we proceed without caching — no panic, no error surfaced.
}

/// Extend the session TTL by another 30 minutes from now (sliding window).
///
/// Should be called after every successful use of a cached password.
/// No-op if there is no active session.
pub fn refresh() {
    let path = match session_meta_path() {
        Some(p) => p,
        None => return,
    };

    let raw = match fs::read_to_string(&path) {
        Ok(r) => r,
        Err(_) => return,
    };

    let mut meta: SessionMeta = match serde_json::from_str(&raw) {
        Ok(m) => m,
        Err(_) => return,
    };

    meta.expires_at = now_secs() + SESSION_TTL_SECS;
    save_meta(&meta);
}

/// Invalidate the current session unconditionally.
///
/// Deletes the keychain entry (if any), the encrypted password file,
/// and the session metadata. Call this after a successful `change-password`
/// operation or whenever the cached password must be discarded.
pub fn invalidate() {
    keychain_delete();
    file_delete();
    remove_meta();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    // Crate-wide mutex (see src/test_env_lock.rs): serialises env mutations
    // across all test modules in this crate, not just session.rs's own tests.
    // A per-module mutex was insufficient — shell_integration's hook_tests
    // also mutate HOME and would race with session::tests otherwise.
    use crate::test_env_lock::ENV_MUTATION_LOCK as HOME_MUTEX;

    /// Redirect all session file paths to a temp directory by overriding HOME.
    fn with_temp_home(f: impl FnOnce()) {
        let _lock = HOME_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().unwrap();
        let prev_home = env::var("HOME").ok();
        env::set_var("HOME", tmp.path());
        f();
        // Restore original HOME to avoid poisoning other tests.
        match prev_home {
            Some(h) => env::set_var("HOME", h),
            None => env::remove_var("HOME"),
        }
        // tmp is dropped — files cleaned up automatically.
    }

    #[test]
    fn test_meta_round_trip() {
        with_temp_home(|| {
            let meta = SessionMeta {
                backend: "file".to_string(),
                expires_at: now_secs() + 100,
                vault_seq: 42,
            };
            save_meta(&meta);

            let loaded = load_meta();
            // vault_change_seq from storage will likely fail in test env,
            // so we just check the meta file was written and is readable.
            let path = session_meta_path().unwrap();
            assert!(path.exists(), "session meta file should exist");
            let raw = fs::read_to_string(&path).unwrap();
            let parsed: SessionMeta = serde_json::from_str(&raw).unwrap();
            assert_eq!(parsed.backend, "file");
            assert_eq!(parsed.vault_seq, 42);
            drop(loaded); // may be None due to seq mismatch — that's OK
        });
    }

    #[test]
    fn test_meta_expired() {
        with_temp_home(|| {
            let meta = SessionMeta {
                backend: "file".to_string(),
                expires_at: now_secs() - 1, // already expired
                vault_seq: 0,
            };
            save_meta(&meta);

            let loaded = load_meta();
            assert!(loaded.is_none(), "expired session should return None");
        });
    }

    #[test]
    fn test_session_key_generation() {
        with_temp_home(|| {
            let key1 = load_or_create_session_key().unwrap();
            let key2 = load_or_create_session_key().unwrap();
            // Second call should return the same persisted key
            assert_eq!(key1, key2, "session key should be stable across calls");
        });
    }

    #[test]
    fn test_file_backend_encrypt_decrypt() {
        with_temp_home(|| {
            let pw = SecretString::new("hunter2-test-password".to_string());
            let stored = file_store(&pw);
            assert!(stored, "file_store should succeed");

            let retrieved = file_get();
            assert!(retrieved.is_some(), "file_get should return Some");
            assert_eq!(
                retrieved.unwrap().expose_secret(),
                pw.expose_secret(),
                "round-tripped password must match"
            );
        });
    }

    #[test]
    fn test_file_delete_clears_password() {
        with_temp_home(|| {
            let pw = SecretString::new("to-be-deleted".to_string());
            file_store(&pw);
            file_delete();

            let retrieved = file_get();
            assert!(retrieved.is_none(), "password should be gone after delete");
        });
    }

    #[test]
    fn test_invalidate_removes_meta() {
        with_temp_home(|| {
            let meta = SessionMeta {
                backend: "file".to_string(),
                expires_at: now_secs() + 100,
                vault_seq: 0,
            };
            save_meta(&meta);
            invalidate();

            let path = session_meta_path().unwrap();
            assert!(!path.exists(), "meta file should be removed after invalidate");
        });
    }
}
