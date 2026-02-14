//! Executor: Neural Hub for AiKeyLabs operations
use crate::crypto;
use crate::storage;
use secrecy::{SecretString, ExposeSecret};
use rusqlite::{params, Connection};

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
        let conn = Connection::open(&db_path).map_err(|e| format!("Failed to open vault: {}", e))?;

        let stored_hash: Vec<u8> = conn.query_row(
            "SELECT value FROM config WHERE key = ?",
            params!["password_hash"],
            |row| row.get(0),
        ).map_err(|_| "Password hash not found.".to_string())?;

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
            .map_err(|_| "Decryption failed. Potential vault corruption.".to_string())
    }
}

pub fn is_potential_secret(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.starts_with("sk-") || trimmed.starts_with("ghp_") || trimmed.starts_with("AKIA") || trimmed.len() >= 32 {
        return true;
    }
    false
}

pub fn add_secret(alias: &str, secret: &str, password: &SecretString) -> Result<(), String> {
    let ctx = VaultContext::new(password)?;
    let (nonce, ciphertext) = ctx.encrypt(secret.as_bytes())?;
    storage::store_entry(alias, &nonce, &ciphertext)?;
    Ok(())
}

pub fn get_secret(alias: &str, password: &SecretString) -> Result<String, String> {
    let ctx = VaultContext::new(password)?;
    let (nonce, ciphertext) = storage::get_entry(alias)?;
    let plaintext = ctx.decrypt(&nonce, &ciphertext)?;
    
    String::from_utf8((*plaintext).clone())
        .map_err(|_| "Decrypted data is not valid UTF-8".to_string())
}

pub fn list_secrets() -> Result<Vec<String>, String> {
    storage::list_entries()
}

pub fn delete_secret(alias: &str, password: &SecretString) -> Result<(), String> {
    let _ctx = VaultContext::new(password)?;
    storage::delete_entry(alias)
}
