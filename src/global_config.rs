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

    let home = dirs::home_dir().ok_or_else(|| "Could not determine home directory".to_string())?;
    let new_path = home.join(".aikey").join("config").join("config.json");

    // Auto-migrate from legacy path (dirs::config_dir()/aikey/config.json)
    if !new_path.exists() {
        if let Some(legacy_dir) = dirs::config_dir() {
            let legacy_path = legacy_dir.join("aikey").join("config.json");
            if legacy_path.exists() {
                if let Some(parent) = new_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if fs::copy(&legacy_path, &new_path).is_ok() {
                    let _ = fs::remove_file(&legacy_path);
                    // Clean up empty legacy dir
                    let legacy_aikey_dir = legacy_dir.join("aikey");
                    let _ = fs::remove_dir(&legacy_aikey_dir); // only succeeds if empty
                }
            }
        }
    }

    Ok(new_path)
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

