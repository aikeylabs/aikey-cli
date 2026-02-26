//! AiKey SDK — embed secret resolution in your Rust application.
//!
//! # Quick start
//!
//! ```no_run
//! use aikey_sdk::AikeyClient;
//! use secrecy::SecretString;
//!
//! let client = AikeyClient::new(SecretString::new("my-master-password".into()));
//!
//! // Resolve a key alias to its plaintext value
//! let secret = client.get_secret("my-openai-key").unwrap();
//!
//! // Resolve a provider name → env-var name + plaintext value
//! let resolved = client.resolve_provider("openai", None).unwrap();
//! println!("Set {} = <redacted>", resolved.env_var);
//! ```

use aikeylabs_aikey_cli::{
    executor,
    providers::Provider,
    resolver::{resolve, ResolveRequest, ResolveResult},
    config::ProjectConfig,
};
use secrecy::SecretString;
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors returned by the SDK.
#[derive(Debug, Error)]
pub enum AikeyError {
    #[error("vault error: {0}")]
    Vault(String),

    #[error("resolution error: {0}")]
    Resolution(String),

    #[error("config error: {0}")]
    Config(String),
}

/// A resolved provider secret ready for injection into a subprocess environment.
pub struct ProviderSecret {
    /// The environment variable name the provider SDK reads (e.g. `OPENAI_API_KEY`).
    pub env_var: String,
    /// The vault alias that was used.
    pub key_alias: String,
    /// The resolved model hint, if any.
    pub model: Option<String>,
    /// The plaintext secret value (zeroed on drop).
    pub secret: Zeroizing<String>,
}

/// Main entry point for the AiKey SDK.
///
/// Holds the master password and provides methods to fetch secrets from the
/// local AiKey vault without spawning a subprocess.
pub struct AikeyClient {
    password: SecretString,
}

impl AikeyClient {
    /// Create a new client with the given master password.
    pub fn new(password: SecretString) -> Self {
        Self { password }
    }

    /// Fetch a secret by its vault alias.
    ///
    /// Returns the plaintext value wrapped in [`Zeroizing`] so it is wiped
    /// from memory when dropped.
    pub fn get_secret(&self, alias: &str) -> Result<Zeroizing<String>, AikeyError> {
        executor::get_secret(alias, &self.password)
            .map_err(AikeyError::Vault)
    }

    /// Resolve a provider name to its env-var name and plaintext secret.
    ///
    /// Looks up the key alias from the nearest `aikey.config.json` (if present),
    /// then fetches the secret from the vault.
    ///
    /// # Arguments
    /// * `provider` — provider name, e.g. `"openai"`, `"anthropic"`
    /// * `key_alias` — optional explicit vault alias; overrides config lookup
    pub fn resolve_provider(
        &self,
        provider: &str,
        key_alias: Option<&str>,
    ) -> Result<ProviderSecret, AikeyError> {
        let config = ProjectConfig::discover()
            .map_err(AikeyError::Config)?
            .map(|(_path, cfg)| cfg);

        let request = ResolveRequest {
            provider: provider.to_string(),
            key_alias: key_alias.map(str::to_string),
            ..Default::default()
        };

        let result: ResolveResult = resolve(&request, config.as_ref())
            .map_err(|e| AikeyError::Resolution(e.to_string()))?;

        let secret = executor::get_secret(&result.key_alias, &self.password)
            .map_err(AikeyError::Vault)?;

        Ok(ProviderSecret {
            env_var: result.env_var,
            key_alias: result.key_alias,
            model: result.model,
            secret,
        })
    }

    /// Return the environment variable name for a provider without touching the vault.
    ///
    /// Useful for building env maps before you have the password.
    pub fn env_var_for(provider: &str) -> String {
        Provider::from_str(provider).env_var()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_for_known_providers() {
        assert_eq!(AikeyClient::env_var_for("openai"),    "OPENAI_API_KEY");
        assert_eq!(AikeyClient::env_var_for("anthropic"), "ANTHROPIC_API_KEY");
        assert_eq!(AikeyClient::env_var_for("google"),    "GOOGLE_API_KEY");
    }

    #[test]
    fn env_var_for_custom_provider() {
        assert_eq!(AikeyClient::env_var_for("myservice"), "AIKEY_MYSERVICE_API_KEY");
    }
}
