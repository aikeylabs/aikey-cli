//! Cryptographic operations for AiKeyLabs vault
//!
//! This module provides secure key derivation and encryption/decryption
//! using industry-standard algorithms (Argon2id + AES-256-GCM).
//!
//! Memory Sovereignty: All sensitive data is protected with SecureBuffer,
//! which uses mlock to pin memory and prevents swapping to disk.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretString};
use std::ops::{Deref, DerefMut};
use std::fmt;

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

/// SecureBuffer: Memory-locked buffer for sensitive data
///
/// Uses mlock to pin memory pages and prevent swapping to disk.
/// Automatically zeroizes on drop.
pub struct SecureBuffer<T: Zeroize> {
    data: T,
    locked: bool,
}

impl<T: Zeroize> SecureBuffer<T> {
    /// Creates a new SecureBuffer and attempts to lock it in RAM
    pub fn new(data: T) -> Result<Self, String> {
        let mut buffer = SecureBuffer {
            data,
            locked: false,
        };

        buffer.lock()?;
        Ok(buffer)
    }

    /// Locks the buffer in memory using mlock (Unix) or VirtualLock (Windows)
    #[cfg(unix)]
    fn lock(&mut self) -> Result<(), String> {
        let ptr = &self.data as *const T as *const libc::c_void;
        let len = std::mem::size_of::<T>();

        unsafe {
            if libc::mlock(ptr, len) != 0 {
                return Err(format!("Failed to lock memory: {}", std::io::Error::last_os_error()));
            }
        }

        self.locked = true;
        Ok(())
    }

    #[cfg(windows)]
    fn lock(&mut self) -> Result<(), String> {
        use windows_sys::Win32::System::Memory::VirtualLock;

        let ptr = &self.data as *const T as *const std::ffi::c_void;
        let len = std::mem::size_of::<T>();

        unsafe {
            if VirtualLock(ptr, len) == 0 {
                return Err(format!("Failed to lock memory: {}", std::io::Error::last_os_error()));
            }
        }

        self.locked = true;
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    fn lock(&mut self) -> Result<(), String> {
        // On unsupported platforms, we can't lock memory but still provide the wrapper
        self.locked = false;
        Ok(())
    }

    /// Unlocks the buffer from memory
    #[cfg(unix)]
    fn unlock(&mut self) {
        if self.locked {
            let ptr = &self.data as *const T as *const libc::c_void;
            let len = std::mem::size_of::<T>();

            unsafe {
                libc::munlock(ptr, len);
            }

            self.locked = false;
        }
    }

    #[cfg(windows)]
    fn unlock(&mut self) {
        if self.locked {
            use windows_sys::Win32::System::Memory::VirtualUnlock;

            let ptr = &self.data as *const T as *const std::ffi::c_void;
            let len = std::mem::size_of::<T>();

            unsafe {
                VirtualUnlock(ptr, len);
            }

            self.locked = false;
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn unlock(&mut self) {
        self.locked = false;
    }
}

impl<T: Zeroize> Deref for SecureBuffer<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for SecureBuffer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: Zeroize> Drop for SecureBuffer<T> {
    fn drop(&mut self) {
        self.unlock();
        self.data.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for SecureBuffer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBuffer<REDACTED>")
    }
}

/// Derives a 256-bit encryption key from a master password using Argon2id
///
/// # Arguments
/// * `password` - Master password (SecretString, automatically zeroized)
/// * `salt` - Random salt (must be SALT_SIZE bytes)
///
/// # Returns
/// A SecureBuffer containing the 32-byte key, locked in RAM
pub fn derive_key(password: &SecretString, salt: &[u8]) -> Result<SecureBuffer<[u8; KEY_SIZE]>, String> {
    if salt.len() != SALT_SIZE {
        return Err(format!("Salt must be {} bytes", SALT_SIZE));
    }

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    SecureBuffer::new(key)
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
/// Decrypted plaintext as a SecureBuffer, locked in RAM
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<SecureBuffer<Vec<u8>>, String> {
    if nonce.len() != NONCE_SIZE {
        return Err(format!("Nonce must be {} bytes", NONCE_SIZE));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed: invalid key or corrupted data".to_string())?;

    SecureBuffer::new(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let password = SecretString::new("test_password_123".to_string());
        let salt = [0u8; SALT_SIZE];

        let key = derive_key(&password, &salt).unwrap();
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

/// Generates a random salt for key derivation
pub fn generate_salt(salt: &mut [u8; SALT_SIZE]) -> Result<(), String> {
    use rand::RngCore;
    use rand::rngs::OsRng;
    OsRng.fill_bytes(salt);
    Ok(())
}
