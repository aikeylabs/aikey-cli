//! Cryptographic operations for AiKeyLabs vault
//!
//! This module provides secure key derivation and encryption/decryption
//! using industry-standard algorithms (Argon2id + AES-256-GCM).

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

/// Argon2id parameters for key derivation
/// - Memory: 64 MiB (65536 KiB)
/// - Iterations: 3
/// - Parallelism: 4 threads
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// AES-GCM nonce size (96 bits / 12 bytes)
pub const NONCE_SIZE: usize = 12;

/// Salt size for Argon2 (128 bits / 16 bytes)
pub const SALT_SIZE: usize = 16;

/// Derived key size (256 bits / 32 bytes for AES-256)
pub const KEY_SIZE: usize = 32;

/// Derives a 256-bit encryption key from a master password using Argon2id
///
/// # Arguments
/// * `password` - Master password (will be zeroized after use)
/// * `salt` - Random salt (must be SALT_SIZE bytes)
///
/// # Returns
/// A zeroizing 32-byte key suitable for AES-256-GCM
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_SIZE]>, String> {
    if salt.len() != SALT_SIZE {
        return Err(format!("Salt must be {} bytes", SALT_SIZE));
    }

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    Ok(key)
}

/// Encrypts plaintext using AES-256-GCM
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// A tuple of (nonce, ciphertext) where nonce is 12 bytes
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypts ciphertext using AES-256-GCM
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce used during encryption
/// * `ciphertext` - Encrypted data
///
/// # Returns
/// Decrypted plaintext as a zeroizing vector
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if nonce.len() != NONCE_SIZE {
        return Err(format!("Nonce must be {} bytes", NONCE_SIZE));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed: invalid key or corrupted data".to_string())?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let password = "test_password_123";
        let salt = [0u8; SALT_SIZE];

        let key = derive_key(password, &salt).unwrap();
        assert_eq!(key.len(), KEY_SIZE);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; KEY_SIZE];
        let plaintext = b"Hello, AiKeyLabs!";

        let (nonce, ciphertext) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }
}
