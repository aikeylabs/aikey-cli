//! Synapse - Vault Export/Import Module
//!
//! Provides secure export and import functionality for vault data.

use crate::executor;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct ExportFormat {
    version: String,
    secrets: HashMap<String, String>,
}

pub struct ImportResult {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
}

/// Export secrets matching a pattern to a JSON file
pub fn export_vault(
    pattern: &str,
    output_path: &Path,
    password: &SecretString,
) -> Result<usize, Box<dyn std::error::Error>> {
    // Get all secrets
    let aliases = executor::list_secrets(password)?;

    let mut secrets = HashMap::new();
    let mut count = 0;

    for alias in aliases {
        // Simple pattern matching (supports * wildcard)
        if pattern == "*" || alias.contains(pattern.trim_matches('*')) {
            let secret = executor::get_secret(&alias, password)?;
            // Extract String from Zeroizing for serialization
            secrets.insert(alias, secret.to_string());
            count += 1;
        }
    }

    let export_data = ExportFormat {
        version: "1.0".to_string(),
        secrets,
    };

    let json = serde_json::to_string_pretty(&export_data)?;
    fs::write(output_path, json)?;

    Ok(count)
}

/// Import secrets from a JSON file
pub fn import_vault(
    input_path: &Path,
    password: &SecretString,
) -> Result<ImportResult, Box<dyn std::error::Error>> {
    let json = fs::read_to_string(input_path)?;
    let import_data: ExportFormat = serde_json::from_str(&json)?;

    let existing_aliases = executor::list_secrets(password)?;

    let mut result = ImportResult {
        added: 0,
        updated: 0,
        skipped: 0,
    };

    for (alias, secret) in import_data.secrets {
        if existing_aliases.contains(&alias) {
            // Update existing secret
            match executor::update_secret(&alias, secret.as_str(), password) {
                Ok(_) => result.updated += 1,
                Err(_) => result.skipped += 1,
            }
        } else {
            // Add new secret
            match executor::add_secret(&alias, secret.as_str(), password) {
                Ok(_) => result.added += 1,
                Err(_) => result.skipped += 1,
            }
        }
    }

    Ok(result)
}
