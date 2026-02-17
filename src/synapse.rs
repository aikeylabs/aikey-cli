//! Synapse - Vault Export/Import Module (.akb Binary Format)
//!
//! Provides secure export and import functionality using the .akb binary format.
//!
//! ## .akb File Format (Version 1)
//!
//! ```text
//! [Header: 64 bytes] + [Encrypted Payload: variable] + [HMAC: 32 bytes]
//! ```
//!
//! ### Header Structure (64 bytes):
//! - Magic bytes: "AKB1" (4 bytes)
//! - Version: 1 (1 byte)
//! - Reserved: 0x00 (3 bytes)
//! - KDF Salt: Random 16 bytes for Argon2id
//! - KDF Params: m_cost (4 bytes), t_cost (4 bytes), p_cost (4 bytes)
//! - Encryption Nonce: 12 bytes for AES-GCM
//! - Padding: 16 bytes (reserved for future use)
//!
//! ### Security Properties:
//! - **Forward Secrecy**: Each export uses a fresh random salt
//! - **Integrity**: HMAC-SHA256 detects tampering
//! - **Authenticity**: HMAC proves correct password was used
//! - **Confidentiality**: AES-256-GCM encrypts the payload
//! - **Key Separation**: Independent keys for encryption and HMAC

use crate::{crypto, storage};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Magic bytes identifying .akb format version 1
const AKB_MAGIC: &[u8; 4] = b"AKB1";
const AKB_VERSION: u8 = 1;
const HEADER_SIZE: usize = 64;
const HMAC_SIZE: usize = 32;

/// KDF parameters stored in .akb header
#[derive(Serialize, Deserialize, Debug)]
struct KdfParams {
    salt: [u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

/// .akb file header (64 bytes fixed size)
#[derive(Serialize, Deserialize, Debug)]
struct AkbHeader {
    magic: [u8; 4],
    version: u8,
    _reserved: [u8; 3],
    kdf_params: KdfParams,
    encryption_nonce: [u8; 12],
    _padding: [u8; 16],
}

/// Entry format for serialization (includes metadata)
///
/// Schema Version History:
/// - v1: Initial format with alias, nonce, ciphertext, version_tag, created_at, updated_at, metadata
#[derive(Serialize, Deserialize)]
struct EntryData {
    /// Schema version for forward/backward compatibility
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    alias: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    version_tag: i64,
    created_at: i64,
    updated_at: i64,
    metadata: Option<String>,
}

/// Default schema version (v1)
fn default_schema_version() -> u32 {
    1
}

impl EntryData {
    /// Current schema version
    const CURRENT_SCHEMA_VERSION: u32 = 1;

    /// Check if this entry is compatible with current schema
    fn is_compatible(&self) -> bool {
        self.schema_version <= Self::CURRENT_SCHEMA_VERSION
    }
}

pub struct ImportResult {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
}

/// Derives two independent 256-bit keys from password for encryption and HMAC
///
/// Uses Argon2id to derive 64 bytes total, then splits into:
/// - First 32 bytes: AES-256-GCM encryption key
/// - Last 32 bytes: HMAC-SHA256 key
///
/// This ensures cryptographic separation between encryption and authentication.
fn derive_dual_keys(
    password: &SecretString,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(crypto::SecureBuffer<[u8; 32]>, crypto::SecureBuffer<[u8; 32]>), String> {
    use argon2::{Argon2, Params, Version};

    if salt.len() != crypto::SALT_SIZE {
        return Err(format!("Salt must be {} bytes", crypto::SALT_SIZE));
    }

    // Derive 64 bytes: 32 for encryption + 32 for HMAC
    let params = Params::new(m_cost, t_cost, p_cost, Some(64))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key_material = [0u8; 64];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key_material)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    // Split into two independent keys
    let mut enc_key = [0u8; 32];
    let mut hmac_key = [0u8; 32];
    enc_key.copy_from_slice(&key_material[0..32]);
    hmac_key.copy_from_slice(&key_material[32..64]);

    // Zeroize source material
    key_material.zeroize();

    Ok((
        crypto::SecureBuffer::new(enc_key)?,
        crypto::SecureBuffer::new(hmac_key)?,
    ))
}

/// Export vault entries to .akb binary format
///
/// # Arguments
/// * `pattern` - Glob pattern for filtering entries (e.g., "*", "api_*")
/// * `output_path` - Path to write .akb file
/// * `password` - Master password for encryption
///
/// # Returns
/// Number of entries exported
pub fn export_vault(
    pattern: &str,
    output_path: &Path,
    password: &SecretString,
) -> Result<usize, Box<dyn std::error::Error>> {
    // Fetch entries matching pattern with full metadata
    let entries = storage::get_entries_with_metadata(pattern)
        .map_err(|e| format!("Failed to fetch entries: {}", e))?;

    if entries.is_empty() {
        return Err(format!("No entries match pattern '{}'", pattern).into());
    }

    // Convert to serializable format
    let entry_data: Vec<EntryData> = entries
        .into_iter()
        .map(|(alias, nonce, ciphertext, version_tag, created_at, updated_at, metadata)| {
            EntryData {
                schema_version: EntryData::CURRENT_SCHEMA_VERSION,
                alias,
                nonce,
                ciphertext,
                version_tag,
                created_at,
                updated_at,
                metadata,
            }
        })
        .collect();

    let count = entry_data.len();

    // Generate fresh salt for this export (forward secrecy)
    let mut export_salt = [0u8; crypto::SALT_SIZE];
    crypto::generate_salt(&mut export_salt)?;

    // Use same KDF parameters as vault for consistency
    // In test mode, use faster parameters to avoid timeouts
    let (m_cost, t_cost, p_cost) = if std::env::var("AK_TEST_PASSWORD").is_ok() {
        (256, 1, 1) // Fast for tests
    } else {
        (65536, 3, 4) // 64 MiB for production
    };

    // Derive dual keys: encryption + HMAC
    let (enc_key, hmac_key) = derive_dual_keys(password, &export_salt, m_cost, t_cost, p_cost)?;

    // Serialize payload
    let payload = bincode::serialize(&entry_data)
        .map_err(|e| format!("Serialization failed: {}", e))?;

    // Encrypt payload with AES-256-GCM
    let (nonce, ciphertext) = crypto::encrypt(&*enc_key, &payload)?;

    // Build header
    let header = AkbHeader {
        magic: *AKB_MAGIC,
        version: AKB_VERSION,
        _reserved: [0u8; 3],
        kdf_params: KdfParams {
            salt: export_salt,
            m_cost,
            t_cost,
            p_cost,
        },
        encryption_nonce: nonce.try_into().map_err(|_| "Invalid nonce size")?,
        _padding: [0u8; 16],
    };

    // Serialize header to fixed 64 bytes
    let header_bytes = bincode::serialize(&header)
        .map_err(|e| format!("Header serialization failed: {}", e))?;

    if header_bytes.len() != HEADER_SIZE {
        return Err(format!(
            "Header size mismatch: expected {}, got {}",
            HEADER_SIZE,
            header_bytes.len()
        )
        .into());
    }

    // Compute HMAC over [header + ciphertext]
    let mut mac = HmacSha256::new_from_slice(&*hmac_key)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;
    mac.update(&header_bytes);
    mac.update(&ciphertext);
    let hmac_tag = mac.finalize().into_bytes();

    // Assemble final file: [header][ciphertext][hmac]
    let mut file_data = Vec::with_capacity(HEADER_SIZE + ciphertext.len() + HMAC_SIZE);
    file_data.extend_from_slice(&header_bytes);
    file_data.extend_from_slice(&ciphertext);
    file_data.extend_from_slice(&hmac_tag);

    // Write to file
    fs::write(output_path, file_data)
        .map_err(|e| format!("Failed to write file: {}", e))?;

    // Set restrictive permissions (0600 on Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(output_path)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(output_path, perms)?;
    }

    Ok(count)
}

/// Import vault entries from .akb binary format
///
/// # Arguments
/// * `input_path` - Path to .akb file
/// * `password` - Master password for decryption
///
/// # Returns
/// ImportResult with counts of added/updated/skipped entries
///
/// # Security
/// - Verifies HMAC before decryption (fail-fast on tampering)
/// - Uses smart merge: only updates if incoming version is newer
pub fn import_vault(
    input_path: &Path,
    password: &SecretString,
) -> Result<ImportResult, Box<dyn std::error::Error>> {
    // Read entire file
    let file_data = fs::read(input_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    // Validate minimum size: header + hmac
    if file_data.len() < HEADER_SIZE + HMAC_SIZE {
        return Err(format!(
            "Invalid .akb file: too small (expected at least {} bytes, got {})",
            HEADER_SIZE + HMAC_SIZE,
            file_data.len()
        )
        .into());
    }

    // Parse header (first 64 bytes)
    let header: AkbHeader = bincode::deserialize(&file_data[0..HEADER_SIZE])
        .map_err(|_| "Invalid .akb file: corrupted header")?;

    // Verify magic bytes
    if &header.magic != AKB_MAGIC {
        return Err(format!(
            "Invalid .akb file: wrong magic bytes (expected {:?}, got {:?})",
            AKB_MAGIC, header.magic
        )
        .into());
    }

    // Verify version
    if header.version != AKB_VERSION {
        return Err(format!(
            "Unsupported .akb version: {} (expected {})",
            header.version, AKB_VERSION
        )
        .into());
    }

    // Extract ciphertext and HMAC
    let ciphertext = &file_data[HEADER_SIZE..file_data.len() - HMAC_SIZE];
    let stored_hmac = &file_data[file_data.len() - HMAC_SIZE..];

    // Derive keys using stored KDF parameters
    let (enc_key, hmac_key) = derive_dual_keys(
        password,
        &header.kdf_params.salt,
        header.kdf_params.m_cost,
        header.kdf_params.t_cost,
        header.kdf_params.p_cost,
    )?;

    // CRITICAL: Verify HMAC BEFORE decryption (fail-fast on tampering)
    let mut mac = HmacSha256::new_from_slice(&*hmac_key)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;
    mac.update(&file_data[0..HEADER_SIZE]); // header
    mac.update(ciphertext);
    mac.verify_slice(stored_hmac).map_err(|_| {
        "HMAC verification failed: file corrupted, tampered, or wrong password"
    })?;

    // Decrypt payload
    let plaintext = crypto::decrypt(&*enc_key, &header.encryption_nonce, ciphertext)?;

    // Deserialize entries
    let entries: Vec<EntryData> = bincode::deserialize(&plaintext)
        .map_err(|e| format!("Failed to deserialize entries: {}", e))?;

    // Import entries with smart merge logic
    let mut result = ImportResult {
        added: 0,
        updated: 0,
        skipped: 0,
    };

    for entry in entries {
        // Check schema compatibility
        if !entry.is_compatible() {
            return Err(format!(
                "Incompatible schema version {} for entry '{}'. Current version: {}. Please upgrade ak.",
                entry.schema_version,
                entry.alias,
                EntryData::CURRENT_SCHEMA_VERSION
            )
            .into());
        }

        let exists = storage::entry_exists(&entry.alias)?;

        if exists {
            // Get existing entry metadata
            let (_, _, local_version, local_updated_at, _, _) =
                storage::get_entry_with_metadata(&entry.alias)?;

            // Smart merge: only update if incoming version is newer
            if entry.version_tag > local_version
                || (entry.version_tag == local_version && entry.updated_at > local_updated_at)
            {
                storage::update_entry_full(
                    &entry.alias,
                    &entry.nonce,
                    &entry.ciphertext,
                    entry.version_tag,
                    entry.updated_at,
                    entry.created_at,
                    entry.metadata.as_deref(),
                )?;
                result.updated += 1;
            } else {
                result.skipped += 1;
            }
        } else {
            // Insert new entry
            storage::insert_entry_full(
                &entry.alias,
                &entry.nonce,
                &entry.ciphertext,
                entry.version_tag,
                entry.updated_at,
                entry.created_at,
                entry.metadata.as_deref(),
            )?;
            result.added += 1;
        }
    }

    Ok(result)
}
