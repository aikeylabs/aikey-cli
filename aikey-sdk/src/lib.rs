//! AiKey SDK — embed secret resolution in your Rust application.
//!
//! # Quick start
//!
//! ## Logical-model-first resolution (Recommended - P1)
//!
//! ```no_run
//! use aikey_sdk::AikeyClient;
//! use secrecy::SecretString;
//!
//! let client = AikeyClient::new(SecretString::new("my-master-password".into()));
//!
//! // Resolve a logical model → provider/model/secret
//! let resolved = client.resolve_logical_model("chat-main", "dev", None).unwrap();
//! println!("Provider: {}", resolved.env_var);
//! println!("Model: {:?}", resolved.model);
//! // Use resolved.secret for API calls
//! ```
//!
//! ## P1: SDK Golden Path - client.chat()
//!
//! ```no_run
//! use aikey_sdk::{AikeyClient, ChatMessage, ChatRole};
//! use secrecy::SecretString;
//!
//! let client = AikeyClient::new(SecretString::new("my-master-password".into()));
//!
//! // Chat with automatic provider resolution
//! let messages = vec![
//!     ChatMessage::new(ChatRole::User, "Hello, how are you?"),
//! ];
//!
//! let response = client.chat("chat-main", "dev", messages, None).unwrap();
//! println!("Response: {}", response.content);
//! ```
//!
//! ## Provider-first resolution (Legacy)
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
use serde::{Deserialize, Serialize};

mod adapters;
use adapters::{ProviderAdapter, OpenAIAdapter, AnthropicAdapter};

/// Errors returned by the SDK.
#[derive(Debug, Error)]
pub enum AikeyError {
    #[error("vault error: {0}")]
    Vault(String),

    #[error("resolution error: {0}")]
    Resolution(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("provider error: {0}")]
    Provider(String),

    #[error("HTTP error: {0}")]
    Http(String),
}

impl From<reqwest::Error> for AikeyError {
    fn from(err: reqwest::Error) -> Self {
        AikeyError::Http(err.to_string())
    }
}

/// Chat message role
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

/// Chat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

impl ChatMessage {
    pub fn new(role: ChatRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }
}

/// Normalized chat response
#[derive(Debug, Clone)]
pub struct ChatResponse {
    /// The response content
    pub content: String,
    /// The model that generated the response
    pub model: String,
    /// The provider that was used
    pub provider: String,
    /// Token usage information (if available)
    pub usage: Option<TokenUsage>,
}

/// Token usage information
#[derive(Debug, Clone)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
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

    /// P1: Resolve a logical model to its provider, env-var name, and plaintext secret.
    ///
    /// Uses logical-model-first resolution: env + logicalModel → provider/modelId/keyAlias.
    /// This is the recommended approach for Stage 0 applications.
    ///
    /// # Arguments
    /// * `logical_model` — logical model name, e.g. `"chat-main"`, `"embeddings"`
    /// * `env` — environment name, e.g. `"dev"`, `"staging"`, `"prod"`
    /// * `tenant` — optional tenant name for multi-tenant overrides
    pub fn resolve_logical_model(
        &self,
        logical_model: &str,
        env: &str,
        tenant: Option<&str>,
    ) -> Result<ProviderSecret, AikeyError> {
        let config = ProjectConfig::discover()
            .map_err(AikeyError::Config)?
            .map(|(_path, cfg)| cfg);

        let request = ResolveRequest {
            logical_model: Some(logical_model.to_string()),
            env: Some(env.to_string()),
            tenant: tenant.map(str::to_string),
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

    /// P1: Chat with automatic provider resolution (SDK Golden Path)
    ///
    /// Resolves the logical model to a provider, fetches the API key, and makes a chat request.
    /// Includes 30s timeout, 3 retries with exponential backoff, and normalized error handling.
    ///
    /// # Arguments
    /// * `logical_model` — logical model name, e.g. `"chat-main"`, `"chat-advanced"`
    /// * `env` — environment name, e.g. `"dev"`, `"staging"`, `"prod"`
    /// * `messages` — conversation messages
    /// * `tenant` — optional tenant name for multi-tenant overrides
    pub fn chat(
        &self,
        logical_model: &str,
        env: &str,
        messages: Vec<ChatMessage>,
        tenant: Option<&str>,
    ) -> Result<ChatResponse, AikeyError> {
        // Resolve logical model to provider/model/key
        let config = ProjectConfig::discover()
            .map_err(AikeyError::Config)?
            .map(|(_path, cfg)| cfg);

        let request = ResolveRequest {
            logical_model: Some(logical_model.to_string()),
            env: Some(env.to_string()),
            tenant: tenant.map(str::to_string),
            ..Default::default()
        };

        let result: ResolveResult = resolve(&request, config.as_ref())
            .map_err(|e| AikeyError::Resolution(e.to_string()))?;

        let secret = executor::get_secret(&result.key_alias, &self.password)
            .map_err(AikeyError::Vault)?;

        // Select appropriate adapter based on provider
        let adapter: Box<dyn ProviderAdapter> = match result.provider.as_str() {
            "openai" => Box::new(OpenAIAdapter::new()),
            "anthropic" => Box::new(AnthropicAdapter::new()),
            _ => return Err(AikeyError::Provider(format!("Unsupported provider: {}", result.provider))),
        };

        // Make chat request with retry logic
        let model = result.model.ok_or_else(|| {
            AikeyError::Resolution(format!("No model specified for logical model '{}'", logical_model))
        })?;

        adapter.chat(&secret, &model, messages)
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
