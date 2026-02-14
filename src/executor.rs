use crate::crypto;
use crate::storage;
use arboard::Clipboard;
use rusqlite::{params, Connection};
use secrecy::SecretString;

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

// 修正了 Claude 代码中的拼写错误 ad_secret -> add_secret
pub fn add_secret(alias: &str, secret: &str, password: &SecretString) -> Result<(), String> {
    let ctx = VaultContext::new(password)?;
    let (nonce, ciphertext) = ctx.encrypt(secret.as_bytes())?;
    storage::store_entry(alias, &nonce, &ciphertext)
}

pub fn get_secret(alias: &str, password: &SecretString) -> Result<String, String> {
    let ctx = VaultContext::new(password)?;
    let (nonce, ciphertext) = storage::get_entry(alias)?;
    let plaintext = ctx.decrypt(&nonce, &ciphertext)?;
    String::from_utf8(plaintext.to_vec()).map_err(|e| e.to_string())
}

pub fn delete_secret(alias: &str, password: &SecretString) -> Result<(), String> {
    let _ctx = VaultContext::new(password)?;
    storage::delete_entry(alias)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn update_secret(alias: &str, new_secret: &str, password: &SecretString) -> Result<(), String> {
    add_secret(alias, new_secret, password)
}

#[allow(dead_code)]
pub fn run_with_secrets(_aliases: &[String], _password: &SecretString, _command: &str) -> Result<(), String> {
    todo!("run_with_secrets not yet implemented")
}

#[allow(dead_code)]
pub fn export_secrets(_pattern: &str, _password: &SecretString) -> Result<String, String> {
    todo!("export_secrets not yet implemented")
}

#[allow(dead_code)]
pub fn import_secrets(_json_data: &str, _password: &SecretString, _strategy: &str) -> Result<(), String> {
    todo!("import_secrets not yet implemented")
}
