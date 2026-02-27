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
            // Try each config file name in order
            for filename in &["aikey.config.json", "aikey.config.yaml", "aikey.config.yml", ".aikeyrc"] {
                let config_path = current_dir.join(filename);
                if config_path.exists() {
                    let config = ProjectConfig::load(&config_path)?;
                    return Ok(Some((config_path, config)));
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

        if filename.ends_with(".json") || filename == ".aikeyrc" {
            serde_json::from_str(&content)
                .map_err(|e| format!("Invalid aikey.config.json: {}", e))
        } else if filename.ends_with(".yaml") || filename.ends_with(".yml") {
            serde_yaml::from_str(&content)
                .map_err(|e| format!("Invalid aikey.config.json: {}", e))
        } else {
            Err("Invalid aikey.config.json: unsupported file format".to_string())
        }
    }

    /// Save config to a file
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config");

        let content = if filename.ends_with(".json") || filename == ".aikeyrc" {
            serde_json::to_string_pretty(self)
                .map_err(|e| format!("Failed to serialize config: {}", e))?
        } else if filename.ends_with(".yaml") || filename.ends_with(".yml") {
            serde_yaml::to_string(self)
                .map_err(|e| format!("Failed to serialize config: {}", e))?
        } else {
            return Err("Unsupported config file format".to_string());
        };

        fs::write(path, content)
            .map_err(|e| format!("Failed to write config file: {}", e))?;

        #[cfg(unix)]
        {
            let metadata = fs::metadata(path)
                .map_err(|e| format!("Failed to read config metadata: {}", e))?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
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
    fn test_project_config_parse_yaml() {
        let yaml = r#"
schemaVersion: "1"
project:
  name: test-project
env:
  target: .env.local
requiredVars:
  - API_KEY
  - DATABASE_URL
defaults:
  profile: dev
"#;

        let config: ProjectConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.project.name, "test-project");
        assert_eq!(config.required_vars.len(), 2);
        assert_eq!(config.env.target, ".env.local");
        assert_eq!(config.defaults.profile, Some("dev".to_string()));
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
