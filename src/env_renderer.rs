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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_resolver::{ResolvedVar, VarSource};

    #[test]
    fn test_render_env_file() {
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("value1".to_string()),
                source: VarSource::Profile,
            },
            ResolvedVar {
                name: "KEY2".to_string(),
                value: Some("value2".to_string()),
                source: VarSource::Profile,
            },
        ];

        let content = EnvRenderer::render_env_file(&resolved);
        assert_eq!(content, "KEY1=value1\nKEY2=value2");
    }

    #[test]
    fn test_render_env_file_with_missing() {
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("value1".to_string()),
                source: VarSource::Profile,
            },
            ResolvedVar {
                name: "KEY2".to_string(),
                value: None,
                source: VarSource::Missing,
            },
        ];

        let content = EnvRenderer::render_env_file(&resolved);
        assert_eq!(content, "KEY1=value1\nKEY2=");
    }

    #[test]
    fn test_merge_env_file_no_existing() {
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("value1".to_string()),
                source: VarSource::Profile,
            },
        ];

        let content = EnvRenderer::merge_env_file(None, &resolved);
        assert_eq!(content, "KEY1=value1");
    }

    #[test]
    fn test_merge_env_file_preserves_comments() {
        let existing = "# This is a comment\nKEY1=old_value\n# Another comment\nUNKNOWN_KEY=keep_this";
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("new_value".to_string()),
                source: VarSource::Profile,
            },
        ];

        let content = EnvRenderer::merge_env_file(Some(existing), &resolved);
        assert!(content.contains("# This is a comment"));
        assert!(content.contains("# Another comment"));
        assert!(content.contains("UNKNOWN_KEY=keep_this"));
        assert!(content.contains("KEY1=new_value"));
        assert!(!content.contains("KEY1=old_value"));
    }

    #[test]
    fn test_merge_env_file_updates_known_keys() {
        let existing = "KEY1=old1\nKEY2=old2\nUNKNOWN=keep";
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("new1".to_string()),
                source: VarSource::Profile,
            },
            ResolvedVar {
                name: "KEY2".to_string(),
                value: Some("new2".to_string()),
                source: VarSource::Profile,
            },
        ];

        let content = EnvRenderer::merge_env_file(Some(existing), &resolved);
        assert!(content.contains("UNKNOWN=keep"));
        assert!(content.contains("KEY1=new1"));
        assert!(content.contains("KEY2=new2"));
        assert!(!content.contains("old1"));
        assert!(!content.contains("old2"));
    }

    #[test]
    fn test_get_changes_summary_all_new() {
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("value1".to_string()),
                source: VarSource::Profile,
            },
            ResolvedVar {
                name: "KEY2".to_string(),
                value: Some("value2".to_string()),
                source: VarSource::Profile,
            },
        ];

        let (added, updated, missing) = EnvRenderer::get_changes_summary(None, &resolved);
        assert_eq!(added.len(), 2);
        assert_eq!(updated.len(), 0);
        assert_eq!(missing.len(), 0);
    }

    #[test]
    fn test_get_changes_summary_with_updates() {
        let existing = "KEY1=old_value";
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("new_value".to_string()),
                source: VarSource::Profile,
            },
            ResolvedVar {
                name: "KEY2".to_string(),
                value: Some("value2".to_string()),
                source: VarSource::Profile,
            },
        ];

        let (added, updated, missing) = EnvRenderer::get_changes_summary(Some(existing), &resolved);
        assert_eq!(added, vec!["KEY2"]);
        assert_eq!(updated, vec!["KEY1"]);
        assert_eq!(missing.len(), 0);
    }

    #[test]
    fn test_get_changes_summary_with_missing() {
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("value1".to_string()),
                source: VarSource::Profile,
            },
            ResolvedVar {
                name: "KEY2".to_string(),
                value: None,
                source: VarSource::Missing,
            },
        ];

        let (added, updated, missing) = EnvRenderer::get_changes_summary(None, &resolved);
        assert_eq!(added, vec!["KEY1"]);
        assert_eq!(updated.len(), 0);
        assert_eq!(missing, vec!["KEY2"]);
    }
}
