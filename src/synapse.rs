//! Synapse: Export/Import with military-grade integrity
//!
//! Binary format (.akb): [Magic: 'AKLB'] + [Version: u16] + [KDF_Salt: 16b] + [Encrypted_Payload] + [HMAC_SHA256: 32b]
//!
//! Security features:
//! - Separate encryption and integrity keys derived from master password
//! - HMAC-SHA256 signature verification before decryption
//! - Smart merge logic based on version_tag and updated_at timestamps
//! - All sensitive buffers protected by SecureBuffer and Zeroize

use crate::crypto::{self, SecureBuffer, SALT_SIZE, KEY_SIZE};
use crate::storage;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use secrecy::SecretString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Magic bytes for .akb format: "AKLB" (AiKeyLabs Binary)
const MAGIC: &[u8; 4] = b"AKLB";

/// Current format version
const FORMAT_VERSION: u16 = 1;

/// HMAC signature size (SHA-256 = 32 bytes)
const HMAC_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Represents a single vault entry for export/import
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultEntry {
    pub alias: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub version_tag: i64,
    pub updated_at: i64,
    pub created_at: i64,
    pub metadata: Option<String>,
}

/// Export package structure (before encryption)
#[derive(Serialize, Deserialize)]
struct ExportPackage {
    entries: Vec<VaultEntry>,
    exported_at: i64,
}

/// Derives two distinct keys from the master password:
/// - Encryption key (for AES-GCM)
/// - Integrity key (for HMAC)
fn derive_dual_keys(
    password: &SecretString,
    salt: &[u8],
) -> Result<(SecureBuffer<[u8; KEY_SIZE]>, SecureBuffer<[u8; KEY_SIZE]>), String> {
    // Derive base key
    let base_key = crypto::derive_key(password, salt)?;

    // Derive encryption key by hashing base_key with context "encryption"
    let mut encryption_key = [0u8; KEY_SIZE];
    let mut mac = HmacSha256::new_from_slice(&*base_key)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;
    mac.update(b"encryption");
    let result = mac.finalize();
    encryption_key.copy_from_slice(&result.into_bytes()[0..KEY_SIZE]);

    // Derive integrity key by hashing base_key with context "integrity"
    let mut integrity_key = [0u8; KEY_SIZE];
    let mut mac = HmacSha256::new_from_slice(&*base_key)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;
    mac.update(b"integrity");
    let result = mac.finalize();
    integrity_key.copy_from_slice(&result.into_bytes()[0..KEY_SIZE]);

    Ok((
        SecureBuffer::new(encryption_key)?,
        SecureBuffer::new(integrity_key)?,
    ))
}

/// Exports vault entries matching the pattern to a .akb file
///
/// # Arguments
/// * `pattern` - Glob pattern for filtering entries (e.g., "openai-*", "*")
/// * `output_path` - Path to write the .akb file
/// * `password` - Master password for re-authentication
pub fn export_vault(
    pattern: &str,
    output_path: &Path,
    password: &SecretString,
) -> Result<usize, String> {
    // Re-authenticate by verifying password
    let salt = storage::get_salt()?;
    let key = crypto::derive_key(password, &salt)?;

    // Verify password by attempting to decrypt an entry (if any exist)
    let entries_list = storage::list_entries()?;
    if !entries_list.is_empty() {
        let (nonce, ciphertext) = storage::get_entry(&entries_list[0])?;
        let _ = crypto::decrypt(&key, &nonce, &ciphertext)
            .map_err(|_| "Authentication failed: incorrect password".to_string())?;
    }

    // Get entries matching pattern
    let entries = storage::get_entries_with_metadata(pattern)?;

    if entries.is_empty() {
        return Err(format!("No entries match pattern '{}'", pattern));
    }

    let entry_count = entries.len();

    // Create export package
    let package = ExportPackage {
        entries: entries
            .into_iter()
            .map(
                |(alias, nonce, ciphertext, version_tag, updated_at, created_at, metadata)| {
                    VaultEntry {
                        alias,
                        nonce,
                        ciphertext,
                        version_tag,
                        updated_at,
                        created_at,
                        metadata,
                    }
                },
            )
            .collect(),
        exported_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    };

    // Serialize package
    let serialized = bincode::serialize(&package)
        .map_err(|e| format!("Serialization failed: {}", e))?;

    // Generate fresh salt for this export
    let mut export_salt = [0u8; SALT_SIZE];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut export_salt);

    // Derive encryption and integrity keys
    let (encryption_key, integrity_key) = derive_dual_keys(password, &export_salt)?;

    // Encrypt the serialized package
    let (nonce, ciphertext) = crypto::encrypt(&encryption_key, &serialized)?;

    // Combine nonce and ciphertext for the encrypted payload
    let mut encrypted_payload = Vec::new();
    encrypted_payload.extend_from_slice(&nonce);
    encrypted_payload.extend_from_slice(&ciphertext);

    // Build the binary format: [Magic][Version][Salt][Encrypted_Payload]
    let mut buffer = Vec::new();
    buffer.extend_from_slice(MAGIC);
    buffer.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    buffer.extend_from_slice(&export_salt);
    buffer.extend_from_slice(&encrypted_payload);

    // Calculate HMAC over everything
    let mut mac = HmacSha256::new_from_slice(&*integrity_key)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;
    mac.update(&buffer);
    let hmac_result = mac.finalize();
    let hmac_bytes = hmac_result.into_bytes();

    // Append HMAC
    buffer.extend_from_slice(&hmac_bytes);

    // Write to file
    let mut file = File::create(output_path)
        .map_err(|e| format!("Failed to create export file: {}", e))?;

    file.write_all(&buffer)
        .map_err(|e| format!("Failed to write export file: {}", e))?;

    // Set restrictive permissions (0600 on Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file
            .metadata()
            .map_err(|e| format!("Failed to get file metadata: {}", e))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(output_path, perms)
            .map_err(|e| format!("Failed to set file permissions: {}", e))?;
    }

    Ok(entry_count)
}

/// Import operation details for a single entry
#[derive(Debug, Clone)]
pub struct ImportOperation {
    pub alias: String,
    pub status: ImportStatus,
    pub old_version: Option<i64>,
    pub new_version: i64,
}

/// Import status for an entry
#[derive(Debug, Clone, PartialEq)]
pub enum ImportStatus {
    Added,
    Updated,
    Skipped,
}

/// Import result statistics with detailed operations
#[derive(Debug)]
pub struct ImportResult {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
    pub operations: Vec<ImportOperation>,
}

/// Imports vault entries from a .akb file with smart merge logic
///
/// # Arguments
/// * `input_path` - Path to the .akb file
/// * `password` - Master password for authentication
pub fn import_vault(
    input_path: &Path,
    password: &SecretString,
) -> Result<ImportResult, String> {
    // Read the entire file
    let mut file =
        File::open(input_path).map_err(|e| format!("Failed to open import file: {}", e))?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read import file: {}", e))?;

    // Verify minimum size
    let min_size = MAGIC.len() + 2 + SALT_SIZE + HMAC_SIZE;
    if buffer.len() < min_size {
        return Err("Invalid .akb file: too small".to_string());
    }

    // Verify magic bytes
    if &buffer[0..4] != MAGIC {
        return Err("Invalid .akb file: incorrect magic bytes".to_string());
    }

    // Extract version
    let version = u16::from_le_bytes([buffer[4], buffer[5]]);
    if version != FORMAT_VERSION {
        return Err(format!("Unsupported .akb format version: {}", version));
    }

    // Extract salt
    let export_salt = &buffer[6..6 + SALT_SIZE];

    // Split HMAC from the rest
    let hmac_offset = buffer.len() - HMAC_SIZE;
    let data_with_payload = &buffer[0..hmac_offset];
    let hmac_received = &buffer[hmac_offset..];

    // Derive keys
    let (encryption_key, integrity_key) = derive_dual_keys(password, export_salt)?;

    // Verify HMAC FIRST (before any decryption)
    let mut mac = HmacSha256::new_from_slice(&*integrity_key)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;
    mac.update(data_with_payload);

    mac.verify_slice(hmac_received).map_err(|_| {
        "⚠️  SECURITY WARNING: HMAC verification failed. File may be corrupted or tampered with."
            .to_string()
    })?;

    // Extract encrypted payload (nonce + ciphertext)
    let encrypted_payload = &buffer[6 + SALT_SIZE..hmac_offset];

    // Split nonce and ciphertext
    if encrypted_payload.len() < crypto::NONCE_SIZE {
        return Err("Invalid .akb file: encrypted payload too small".to_string());
    }

    let nonce = &encrypted_payload[0..crypto::NONCE_SIZE];
    let ciphertext = &encrypted_payload[crypto::NONCE_SIZE..];

    // Decrypt payload
    let decrypted = crypto::decrypt(&encryption_key, nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    // Deserialize package
    let package: ExportPackage =
        bincode::deserialize(&decrypted).map_err(|e| format!("Deserialization failed: {}", e))?;

    // Smart merge logic
    let mut stats = ImportResult {
        added: 0,
        updated: 0,
        skipped: 0,
        operations: Vec::new(),
    };

    for entry in package.entries {
        match storage::get_entry_with_metadata(&entry.alias) {
            Ok((_, _, local_version, local_updated_at, _, _)) => {
                // Entry exists locally - apply smart merge
                if entry.version_tag > local_version {
                    // Incoming version is newer
                    storage::update_entry_full(
                        &entry.alias,
                        &entry.nonce,
                        &entry.ciphertext,
                        entry.version_tag,
                        entry.updated_at,
                        entry.created_at,
                        entry.metadata.as_deref(),
                    )?;
                    stats.updated += 1;
                    stats.operations.push(ImportOperation {
                        alias: entry.alias.clone(),
                        status: ImportStatus::Updated,
                        old_version: Some(local_version),
                        new_version: entry.version_tag,
                    });
                } else if entry.version_tag == local_version && entry.updated_at > local_updated_at
                {
                    // Same version but incoming is more recent
                    storage::update_entry_full(
                        &entry.alias,
                        &entry.nonce,
                        &entry.ciphertext,
                        entry.version_tag,
                        entry.updated_at,
                        entry.created_at,
                        entry.metadata.as_deref(),
                    )?;
                    stats.updated += 1;
                    stats.operations.push(ImportOperation {
                        alias: entry.alias.clone(),
                        status: ImportStatus::Updated,
                        old_version: Some(local_version),
                        new_version: entry.version_tag,
                    });
                } else {
                    // Local version is newer or same - skip
                    stats.skipped += 1;
                    stats.operations.push(ImportOperation {
                        alias: entry.alias.clone(),
                        status: ImportStatus::Skipped,
                        old_version: Some(local_version),
                        new_version: entry.version_tag,
                    });
                }
            }
            Err(_) => {
                // Entry doesn't exist locally - add it
                storage::insert_entry_full(
                    &entry.alias,
                    &entry.nonce,
                    &entry.ciphertext,
                    entry.version_tag,
                    entry.updated_at,
                    entry.created_at,
                    entry.metadata.as_deref(),
                )?;
                stats.added += 1;
                stats.operations.push(ImportOperation {
                    alias: entry.alias.clone(),
                    status: ImportStatus::Added,
                    old_version: None,
                    new_version: entry.version_tag,
                });
            }
        }
    }

    Ok(stats)
}
