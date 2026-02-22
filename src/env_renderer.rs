use crate::env_resolver::ResolvedVar;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Renders resolved environment variables to different targets
pub struct EnvRenderer;

impl EnvRenderer {
    /// Generate .env file content from resolved variables
    pub fn render_env_file(resolved: &[ResolvedVar]) -> String {
        let mut lines = Vec::new();

        for var in resolved {
            let value = var.value.as_deref().unwrap_or("");
            lines.push(format!("{}={}", var.name, value));
        }

        lines.join("\n")
    }

    /// Merge new variables with existing .env file content
    pub fn merge_env_file(
        existing_content: Option<&str>,
        resolved: &[ResolvedVar],
    ) -> String {
        let mut lines = Vec::new();
        let mut processed_keys = std::collections::HashSet::new();

        // If there's existing content, preserve unknown lines and comments
        if let Some(content) = existing_content {
            for line in content.lines() {
                let trimmed = line.trim();

                // Preserve empty lines and comments
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    lines.push(line.to_string());
                    continue;
                }

                // Check if this is a known key
                if let Some(key) = trimmed.split('=').next() {
                    if resolved.iter().any(|v| v.name == key) {
                        // Skip known keys; we'll add them later
                        processed_keys.insert(key.to_string());
                    } else {
                        // Preserve unknown keys
                        lines.push(line.to_string());
                    }
                }
            }
        }

        // Add all resolved variables
        for var in resolved {
            let value = var.value.as_deref().unwrap_or("");
            lines.push(format!("{}={}", var.name, value));
        }

        lines.join("\n")
    }

    /// Write .env file with merge semantics
    pub fn write_env_file(
        path: &Path,
        resolved: &[ResolvedVar],
        merge: bool,
    ) -> Result<(), String> {
        let content = if merge && path.exists() {
            let existing = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read existing .env file: {}", e))?;
            Self::merge_env_file(Some(&existing), resolved)
        } else {
            Self::render_env_file(resolved)
        };

        fs::write(path, content)
            .map_err(|e| format!("Failed to write .env file: {}", e))?;

        Ok(())
    }

    /// Get a summary of changes that would be made
    pub fn get_changes_summary(
        existing_content: Option<&str>,
        resolved: &[ResolvedVar],
    ) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut added = Vec::new();
        let mut updated = Vec::new();
        let mut missing = Vec::new();

        let existing_map: HashMap<String, String> = if let Some(content) = existing_content {
            content
                .lines()
                .filter_map(|line| {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        if let Some((key, value)) = trimmed.split_once('=') {
                            return Some((key.to_string(), value.to_string()));
                        }
                    }
                    None
                })
                .collect()
        } else {
            HashMap::new()
        };

        for var in resolved {
            if var.value.is_none() {
                missing.push(var.name.clone());
            } else if existing_map.contains_key(&var.name) {
                updated.push(var.name.clone());
            } else {
                added.push(var.name.clone());
            }
        }

        (added, updated, missing)
    }
}
