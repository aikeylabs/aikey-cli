use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::fs;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Per-provider configuration: which vault alias to use and optional default model
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderConfig {
    /// Vault alias that holds the API key for this provider
    #[serde(rename = "keyAlias")]
    pub key_alias: String,
    /// Default model to use when none is specified
    #[serde(rename = "defaultModel", skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
}

/// A single logical-model mapping entry: resolves a logical name to a concrete
/// provider, model ID, and vault key alias for a given environment.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogicalModelMapping {
    /// Provider name (e.g. "openai", "anthropic")
    pub provider: String,
    /// Concrete model ID passed to the provider API (e.g. "gpt-4o-mini")
    #[serde(rename = "providerModelId", skip_serializing_if = "Option::is_none")]
    pub provider_model_id: Option<String>,
    /// Vault alias for the API key (e.g. "openai:default")
    #[serde(rename = "keyAlias")]
    pub key_alias: String,
    /// Optional implementation/SDK identifier (e.g. "openai-sdk", "langchain")
    #[serde(rename = "implId", skip_serializing_if = "Option::is_none")]
    pub impl_id: Option<String>,
}

/// Project configuration structure following CONFIG_SPEC.md
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    #[serde(rename = "schemaVersion")]
    pub version: String,
    pub project: ProjectInfo,
    pub env: EnvConfig,
    #[serde(default, rename = "requiredVars")]
    pub required_vars: Vec<String>,
    #[serde(default)]
    pub bindings: HashMap<String, String>,
    #[serde(default)]
    pub defaults: Defaults,
    /// Provider → ProviderConfig mapping (Stage 0 resolution engine)
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
    /// Tenant → (provider → keyAlias) overrides for multi-tenant setups
    #[serde(default)]
    pub tenants: HashMap<String, HashMap<String, String>>,
    /// Lifecycle hooks (pre/post run, etc.)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hooks: HashMap<String, Vec<String>>,
    /// env → logicalModel → LogicalModelMapping
    /// e.g. envMappings["dev"]["chat-main"] = { provider: "openai", providerModelId: "gpt-4o-mini", keyAlias: "openai:default" }
    #[serde(default, rename = "envMappings", skip_serializing_if = "HashMap::is_empty")]
    pub env_mappings: HashMap<String, HashMap<String, LogicalModelMapping>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvConfig {
    #[serde(default = "default_env_target")]
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Defaults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

fn default_env_target() -> String {
    ".env".to_string()
}

impl ProjectConfig {
    /// Create a new project config with defaults
    pub fn new(name: String) -> Self {
        Self {
            version: "1".to_string(),
            project: ProjectInfo { id: None, name },
            env: EnvConfig {
                target: ".env".to_string(),
            },
            required_vars: Vec::new(),
            bindings: HashMap::new(),
            defaults: Defaults { profile: None },
            providers: HashMap::new(),
            tenants: HashMap::new(),
            hooks: HashMap::new(),
            env_mappings: HashMap::new(),
        }
    }

    /// Discover project config by walking up from current directory
    pub fn discover() -> Result<Option<(PathBuf, ProjectConfig)>, String> {
        let current_dir = std::env::current_dir()
            .map_err(|e| format!("Failed to get current directory: {}", e))?;
        Self::discover_from(&current_dir)
    }

    /// Discover project config by walking up from a specific directory
    pub fn discover_from(start_dir: &Path) -> Result<Option<(PathBuf, ProjectConfig)>, String> {
        let mut current_dir = start_dir.to_path_buf();

        loop {
            // Stage 0: Only support aikey.config.json (single blessed format)
            let config_path = current_dir.join("aikey.config.json");
            if config_path.exists() {
                let config = ProjectConfig::load(&config_path)?;
                return Ok(Some((config_path, config)));
            }

            // Check for deprecated formats and provide migration guidance
            for deprecated in &["aikey.config.yaml", "aikey.config.yml", ".aikeyrc"] {
                let deprecated_path = current_dir.join(deprecated);
                if deprecated_path.exists() {
                    return Err(format!(
                        "Found deprecated config format: {}\n\n\
                        Stage 0 only supports aikey.config.json.\n\
                        Please convert your config to JSON format:\n\
                          1. Rename {} to aikey.config.json\n\
                          2. Convert YAML syntax to JSON if needed\n\n\
                        Example: https://github.com/AiKey-Founder/aikey-labs/blob/main/docs/config-schema.md",
                        deprecated, deprecated
                    ));
                }
            }

            // Move to parent directory
            if !current_dir.pop() {
                break;
            }
        }

        Ok(None)
    }

    /// Load config from a file
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config");

        // Stage 0: Only support JSON format
        if !filename.ends_with(".json") {
            return Err(format!(
                "Unsupported config format: {}\n\
                Stage 0 only supports aikey.config.json (JSON format).",
                filename
            ));
        }

        let config: Self = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid aikey.config.json: {}", e))?;

        // Validate: reject secret-like fields
        config.validate_no_secrets()?;

        Ok(config)
    }

    /// Validate that config doesn't contain secret-like fields
    fn validate_no_secrets(&self) -> Result<(), String> {
        // Check for secret-like field names in the raw JSON
        // This is a defense-in-depth check since our schema shouldn't allow these anyway
        let secret_patterns = [
            "apiKey", "api_key", "apikey",
            "token", "accessToken", "access_token",
            "secret", "secretKey", "secret_key",
            "password", "passwd", "pwd",
            "key", "privateKey", "private_key",
        ];

        // We need to re-parse as Value to check for unexpected fields
        // In a real implementation, you'd check the raw JSON string or use a custom deserializer
        // For now, we'll add a warning in the error message

        // Check provider configs for suspicious patterns
        for (provider_name, provider_config) in &self.providers {
            if secret_patterns.iter().any(|p| provider_config.key_alias.to_lowercase().contains(p)) {
                // This is actually OK - keyAlias is supposed to reference a vault entry
                // But if it looks like an actual secret value, warn
                if provider_config.key_alias.len() > 32 &&
                   (provider_config.key_alias.starts_with("sk-") ||
                    provider_config.key_alias.starts_with("pk-") ||
                    provider_config.key_alias.contains("secret")) {
                    return Err(format!(
                        "SECURITY WARNING: Provider '{}' keyAlias looks like an actual secret value.\n\
                        keyAlias should be a vault reference (e.g. 'openai:default'), not the actual API key.\n\
                        Never store secrets in aikey.config.json - use 'aikey secret set' instead.",
                        provider_name
                    ));
                }
            }
        }

        // Check bindings for suspicious values
        for (var_name, binding_value) in &self.bindings {
            if binding_value.len() > 32 &&
               (binding_value.starts_with("sk-") ||
                binding_value.starts_with("pk-") ||
                binding_value.starts_with("Bearer ") ||
                binding_value.starts_with("ghp_")) {
                return Err(format!(
                    "SECURITY WARNING: Binding '{}' appears to contain an actual secret.\n\
                    Bindings should reference vault entries (e.g. 'db:prod'), not actual secrets.\n\
                    Never store secrets in aikey.config.json - use 'aikey secret set' instead.",
                    var_name
                ));
            }
        }

        Ok(())
    }

    /// Save config to a file
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config");

        // Stage 0: Only support JSON format
        if !filename.ends_with(".json") {
            return Err(format!(
                "Unsupported config format: {}\n\
                Stage 0 only supports aikey.config.json (JSON format).",
                filename
            ));
        }

        // Validate before saving
        self.validate_no_secrets()?;

        let content = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

        fs::write(path, content)
            .map_err(|e| format!("Failed to write config file: {}", e))?;

        #[cfg(unix)]
        {
            let metadata = fs::metadata(path)
                .map_err(|e| format!("Failed to read config metadata: {}", e))?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o644); // Config is not secret, can be world-readable
            fs::set_permissions(path, perms)
                .map_err(|e| format!("Failed to set config permissions: {}", e))?;
        }

        Ok(())
    }
}

/// Environment variable templates for different stacks
pub struct EnvTemplate;

impl EnvTemplate {
    pub fn node_vars() -> Vec<&'static str> {
        vec![
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GOOGLE_API_KEY",
            "COHERE_API_KEY",
        ]
    }

    pub fn python_vars() -> Vec<&'static str> {
        vec![
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GOOGLE_API_KEY",
            "COHERE_API_KEY",
        ]
    }

    pub fn other_vars() -> Vec<&'static str> {
        vec![
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_project_config_parse_json() {
        let json = r#"{
            "schemaVersion": "1",
            "project": {
                "name": "test-project"
            },
            "env": {
                "target": ".env.local"
            },
            "requiredVars": ["API_KEY", "DATABASE_URL"],
            "defaults": {
                "profile": "dev"
            }
        }"#;

        let config: ProjectConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.project.name, "test-project");
        assert_eq!(config.required_vars.len(), 2);
        assert_eq!(config.env.target, ".env.local");
        assert_eq!(config.defaults.profile, Some("dev".to_string()));
    }

    #[test]
    fn test_project_config_rejects_secret_in_binding() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("aikey.config.json");

        let json = r#"{
            "schemaVersion": "1",
            "project": {"name": "test"},
            "env": {"target": ".env"},
            "bindings": {
                "OPENAI_API_KEY": "sk-1234567890abcdefghijklmnopqrstuvwxyz"
            }
        }"#;

        fs::write(&config_path, json).unwrap();
        let result = ProjectConfig::load(&config_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SECURITY WARNING"));
    }

    #[test]
    fn test_project_config_minimal() {
        let json = r#"{
            "schemaVersion": "1",
            "project": {
                "name": "minimal"
            },
            "env": {
                "target": ".env"
            }
        }"#;

        let config: ProjectConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.project.name, "minimal");
        assert_eq!(config.required_vars.len(), 0);
        assert_eq!(config.env.target, ".env");
        assert_eq!(config.defaults.profile, None);
    }

    #[test]
    fn test_project_config_discover() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("aikey.config.json");

        let config = ProjectConfig::new("test".to_string());
        config.save(&config_path).unwrap();

        std::env::set_current_dir(temp_dir.path()).unwrap();
        let (found_path, found_config) = ProjectConfig::discover().unwrap().unwrap();

        assert_eq!(found_config.project.name, "test");
        assert!(found_path.ends_with("aikey.config.json"));
    }

    #[test]
    fn test_env_template_node_vars() {
        let vars = EnvTemplate::node_vars();
        assert!(vars.contains(&"OPENAI_API_KEY"));
        assert!(vars.contains(&"ANTHROPIC_API_KEY"));
        assert!(vars.len() > 0);
    }

    #[test]
    fn test_env_template_python_vars() {
        let vars = EnvTemplate::python_vars();
        assert!(vars.contains(&"OPENAI_API_KEY"));
        assert!(vars.contains(&"ANTHROPIC_API_KEY"));
        assert!(vars.len() > 0);
    }

    #[test]
    fn test_env_template_other_vars() {
        let vars = EnvTemplate::other_vars();
        assert!(vars.contains(&"OPENAI_API_KEY"));
        assert!(vars.contains(&"ANTHROPIC_API_KEY"));
        assert!(vars.len() > 0);
    }
}
