use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub version: String,
    #[serde(rename = "currentProfile")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_profile: Option<String>,
    #[serde(rename = "currentEnv")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_env: Option<String>,
    #[serde(rename = "currentOrg")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_org: Option<String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            version: "1".to_string(),
            current_profile: None,
            current_env: None,
            current_org: None,
        }
    }
}

pub fn config_path() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("AIKEY_CONFIG") {
        return Ok(PathBuf::from(path));
    }

    let config_dir = dirs::config_dir().ok_or_else(|| "Could not determine config directory".to_string())?;
    Ok(config_dir.join("aikey").join("config.json"))
}

pub fn load_config() -> Result<GlobalConfig, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(GlobalConfig::default());
    }

    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read global config: {}", e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse global config: {}", e))
}

pub fn save_config(config: &GlobalConfig) -> Result<(), String> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    let content = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize global config: {}", e))?;
    fs::write(&path, content)
        .map_err(|e| format!("Failed to write global config: {}", e))?;

    Ok(())
}

pub fn set_current_profile(profile: &str) -> Result<(), String> {
    let mut config = load_config()?;
    config.current_profile = Some(profile.to_string());
    save_config(&config)
}

pub fn get_current_profile() -> Result<Option<String>, String> {
    let config = load_config()?;
    Ok(config.current_profile)
}

pub fn set_current_env(env: &str) -> Result<(), String> {
    let mut config = load_config()?;
    config.current_env = Some(env.to_string());
    save_config(&config)
}

pub fn get_current_env() -> Result<Option<String>, String> {
    let config = load_config()?;
    Ok(config.current_env)
}

