use crate::env_resolver::ResolvedVar;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Renders resolved environment variables to different targets
pub struct EnvRenderer;

impl EnvRenderer {
    /// Generate .env file content from resolved variables.
    /// Per Stage 0 P0 requirement: .env must NEVER contain provider secrets.
    /// Only non-sensitive context variables (AIKEY_PROJECT, AIKEY_ENV, AIKEY_PROFILE)
    /// are written. All other variables get a placeholder.
    pub fn render_env_file(resolved: &[ResolvedVar]) -> String {
        let mut lines = Vec::new();

        for var in resolved {
            // P0: Only write non-sensitive context variables
            if Self::is_aikey_context_var(&var.name) {
                let value = var.value.as_deref().unwrap_or("");
                lines.push(format!("{}={}", var.name, value));
            } else {
                // All other variables (including API keys) get a placeholder
                lines.push(format!("{}=<managed-by-aikey>", var.name));
            }
        }

        lines.join("\n")
    }

    /// Check if a variable is a non-sensitive AiKey context variable
    fn is_aikey_context_var(name: &str) -> bool {
        matches!(name, "AIKEY_PROJECT" | "AIKEY_ENV" | "AIKEY_PROFILE")
    }

    /// Merge new variables with existing .env file content
    /// Per Stage 0 P0 requirement: .env must NEVER contain provider secrets.
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

        // Add all resolved variables (P0: only context vars get real values)
        for var in resolved {
            if Self::is_aikey_context_var(&var.name) {
                let value = var.value.as_deref().unwrap_or("");
                lines.push(format!("{}={}", var.name, value));
            } else {
                // All other variables (including API keys) get a placeholder
                lines.push(format!("{}=<managed-by-aikey>", var.name));
            }
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
                name: "AIKEY_PROJECT".to_string(),
                value: Some("my-project".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "OPENAI_API_KEY".to_string(),
                value: Some("sk-secret123".to_string()),
                source: VarSource::Profile,
                is_sensitive: true,
            },
        ];

        let content = EnvRenderer::render_env_file(&resolved);
        // P0: Only AIKEY_* context vars get real values
        assert!(content.contains("AIKEY_PROJECT=my-project"));
        // P0: API keys get placeholders
        assert!(content.contains("OPENAI_API_KEY=<managed-by-aikey>"));
        assert!(!content.contains("sk-secret123"));
    }

    #[test]
    fn test_render_env_file_with_missing() {
        let resolved = vec![
            ResolvedVar {
                name: "AIKEY_ENV".to_string(),
                value: Some("dev".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "OPENAI_API_KEY".to_string(),
                value: None,
                source: VarSource::Missing,
                is_sensitive: true,
            },
        ];

        let content = EnvRenderer::render_env_file(&resolved);
        assert!(content.contains("AIKEY_ENV=dev"));
        assert!(content.contains("OPENAI_API_KEY=<managed-by-aikey>"));
    }

    #[test]
    fn test_merge_env_file_no_existing() {
        let resolved = vec![
            ResolvedVar {
                name: "AIKEY_PROFILE".to_string(),
                value: Some("work".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
        ];

        let content = EnvRenderer::merge_env_file(None, &resolved);
        assert_eq!(content, "AIKEY_PROFILE=work");
    }

    #[test]
    fn test_merge_env_file_preserves_comments() {
        let existing = "# This is a comment\nAIKEY_PROJECT=old_value\n# Another comment\nUNKNOWN_KEY=keep_this";
        let resolved = vec![
            ResolvedVar {
                name: "AIKEY_PROJECT".to_string(),
                value: Some("new_value".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
        ];

        let content = EnvRenderer::merge_env_file(Some(existing), &resolved);
        assert!(content.contains("# This is a comment"));
        assert!(content.contains("# Another comment"));
        assert!(content.contains("UNKNOWN_KEY=keep_this"));
        assert!(content.contains("AIKEY_PROJECT=new_value"));
        assert!(!content.contains("AIKEY_PROJECT=old_value"));
    }

    #[test]
    fn test_merge_env_file_updates_known_keys() {
        let existing = "AIKEY_PROJECT=old1\nAIKEY_ENV=old2\nUNKNOWN=keep";
        let resolved = vec![
            ResolvedVar {
                name: "AIKEY_PROJECT".to_string(),
                value: Some("new1".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "AIKEY_ENV".to_string(),
                value: Some("new2".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
        ];

        let content = EnvRenderer::merge_env_file(Some(existing), &resolved);
        assert!(content.contains("UNKNOWN=keep"));
        assert!(content.contains("AIKEY_PROJECT=new1"));
        assert!(content.contains("AIKEY_ENV=new2"));
        assert!(!content.contains("old1"));
        assert!(!content.contains("old2"));
    }

    #[test]
    fn test_get_changes_summary_all_new() {
        let resolved = vec![
            ResolvedVar {
                name: "AIKEY_PROJECT".to_string(),
                value: Some("my-project".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "OPENAI_API_KEY".to_string(),
                value: Some("sk-secret".to_string()),
                source: VarSource::Profile,
                is_sensitive: true,
            },
        ];

        let (added, updated, missing) = EnvRenderer::get_changes_summary(None, &resolved);
        assert_eq!(added.len(), 2);
        assert_eq!(updated.len(), 0);
        assert_eq!(missing.len(), 0);
    }

    #[test]
    fn test_get_changes_summary_with_updates() {
        let existing = "AIKEY_PROJECT=old_value";
        let resolved = vec![
            ResolvedVar {
                name: "AIKEY_PROJECT".to_string(),
                value: Some("new_value".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "AIKEY_ENV".to_string(),
                value: Some("dev".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
        ];

        let (added, updated, missing) = EnvRenderer::get_changes_summary(Some(existing), &resolved);
        assert_eq!(added, vec!["AIKEY_ENV"]);
        assert_eq!(updated, vec!["AIKEY_PROJECT"]);
        assert_eq!(missing.len(), 0);
    }

    #[test]
    fn test_get_changes_summary_with_missing() {
        let resolved = vec![
            ResolvedVar {
                name: "AIKEY_PROJECT".to_string(),
                value: Some("my-project".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "OPENAI_API_KEY".to_string(),
                value: None,
                source: VarSource::Missing,
                is_sensitive: true,
            },
        ];

        let (added, updated, missing) = EnvRenderer::get_changes_summary(None, &resolved);
        assert_eq!(added, vec!["AIKEY_PROJECT"]);
        assert_eq!(updated.len(), 0);
        assert_eq!(missing, vec!["OPENAI_API_KEY"]);
    }

    #[test]
    fn test_p0_security_no_secrets_in_env_file() {
        // P0 Critical: Verify that API keys are NEVER written to .env
        let resolved = vec![
            ResolvedVar {
                name: "AIKEY_PROJECT".to_string(),
                value: Some("my-project".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "OPENAI_API_KEY".to_string(),
                value: Some("sk-real-secret-key-12345".to_string()),
                source: VarSource::Profile,
                is_sensitive: true,
            },
            ResolvedVar {
                name: "ANTHROPIC_API_KEY".to_string(),
                value: Some("sk-ant-real-secret".to_string()),
                source: VarSource::Profile,
                is_sensitive: true,
            },
        ];

        let content = EnvRenderer::render_env_file(&resolved);

        // Context vars should have real values
        assert!(content.contains("AIKEY_PROJECT=my-project"));

        // API keys must NEVER appear in plaintext
        assert!(!content.contains("sk-real-secret-key-12345"));
        assert!(!content.contains("sk-ant-real-secret"));

        // API keys should have placeholders
        assert!(content.contains("OPENAI_API_KEY=<managed-by-aikey>"));
        assert!(content.contains("ANTHROPIC_API_KEY=<managed-by-aikey>"));
    }
}
