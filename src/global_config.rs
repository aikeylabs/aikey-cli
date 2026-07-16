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
    /// Claude Desktop takeover persistent consent (D3): `"always"` = take
    /// over silently on future `use`; `"never"` = never ask, never write.
    /// Absent = ask each time a real 1p→3p takeover is needed. Cleared by
    /// any aikey-performed restore (D6 supplement: 还原即清同意) — external
    /// flips do NOT clear it. Lives here (existing config.json truth source)
    /// instead of a new pref file — careful-api principle.
    #[serde(rename = "claudeDesktopConsent")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_desktop_consent: Option<String>,
    /// Codex takeover persistent refusal (方案一 2026-07-16): `"never"` =
    /// never ask again, never write `~/.codex/config.toml`. Unlike Claude
    /// Desktop there is deliberately no `"always"` — a granted consent
    /// persists as the written aikey block in config.toml itself (the
    /// first-time prompt can never fire again once the block exists).
    /// Cleared by `aikey hook install codex` (explicit actionable consent,
    /// mirrors `aikey desktop install` lifting Claude Desktop's refusal).
    #[serde(rename = "codexConsent")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_consent: Option<String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            version: "1".to_string(),
            current_profile: None,
            current_env: None,
            current_org: None,
            claude_desktop_consent: None,
            codex_consent: None,
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

    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read global config: {}", e))?;
    // Tolerate a UTF-8 BOM from Windows editors/tools (see crate::strip_bom docs).
    serde_json::from_str(crate::strip_bom(&content))
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
    fs::write(&path, content).map_err(|e| format!("Failed to write global config: {}", e))?;

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

/// Claude Desktop takeover consent (D3). Value is `"always"` or `"never"`;
/// anything else stored is treated as absent by readers (defensive).
#[allow(dead_code)] // consumed by the P2 reconcile/consent wiring
pub fn get_claude_desktop_consent() -> Result<Option<String>, String> {
    Ok(load_config()?
        .claude_desktop_consent
        .filter(|v| v == "always" || v == "never"))
}

#[allow(dead_code)] // consumed by the P2 reconcile/consent wiring
pub fn set_claude_desktop_consent(value: &str) -> Result<(), String> {
    let mut config = load_config()?;
    config.claude_desktop_consent = Some(value.to_string());
    save_config(&config)
}

/// D6 supplement (还原即清同意): every aikey-performed restore clears an
/// `always` grant so the next takeover asks again. `never` survives — it
/// never produced a takeover, so a restore says nothing about it; its only
/// exits are `aikey desktop uninstall` (clears both) or an explicit
/// `aikey desktop install` (the command itself is actionable consent).
#[allow(dead_code)] // consumed by the P2 restore wiring
pub fn clear_claude_desktop_consent_always() -> Result<(), String> {
    let mut config = load_config()?;
    if config.claude_desktop_consent.as_deref() == Some("always") {
        config.claude_desktop_consent = None;
        save_config(&config)?;
    }
    Ok(())
}

#[allow(dead_code)] // consumed by `aikey desktop uninstall` (P2)
pub fn clear_claude_desktop_consent() -> Result<(), String> {
    let mut config = load_config()?;
    if config.claude_desktop_consent.is_some() {
        config.claude_desktop_consent = None;
        save_config(&config)?;
    }
    Ok(())
}

/// Codex takeover consent (方案一). Only `"never"` is meaningful; anything
/// else stored is treated as absent by readers (defensive, mirrors the
/// claude reader above). See the `codex_consent` field docs for why there
/// is no `"always"` counterpart.
pub fn get_codex_consent() -> Result<Option<String>, String> {
    Ok(load_config()?.codex_consent.filter(|v| v == "never"))
}

pub fn set_codex_consent_never() -> Result<(), String> {
    let mut config = load_config()?;
    config.codex_consent = Some("never".to_string());
    save_config(&config)
}

/// Exit from a standing "never" — wired to `aikey hook install codex`
/// (running that command is itself actionable consent).
pub fn clear_codex_consent() -> Result<(), String> {
    let mut config = load_config()?;
    if config.codex_consent.is_some() {
        config.codex_consent = None;
        save_config(&config)?;
    }
    Ok(())
}
