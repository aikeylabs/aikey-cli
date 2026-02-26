//! Stage 0 five-step resolution engine.
//!
//! Resolution order (first match wins):
//!   1. Context   – active profile name + project root
//!   2. Base      – providers[provider].keyAlias from project config
//!   3. Tenant    – tenants[tenant][provider] override
//!   4. Explicit  – caller-supplied key_alias override
//!   5. Fetch     – vault lookup of the resolved alias → plaintext secret

use crate::config::ProjectConfig;
use crate::providers::Provider;

/// Input context for a single resolution request.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ResolveRequest {
    /// Provider name (e.g. "openai", "anthropic")
    pub provider: String,
    /// Optional model hint (passed through; not used for key lookup)
    pub model: Option<String>,
    /// Active profile name (e.g. "work", "personal")
    pub profile: Option<String>,
    /// Tenant name for multi-tenant override (e.g. "acme-corp")
    pub tenant: Option<String>,
    /// Explicit vault alias; bypasses config lookup when set
    pub key_alias: Option<String>,
}

/// The outcome of a successful resolution.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResolveResult {
    /// The vault alias that was used to fetch the secret
    pub key_alias: String,
    /// The environment variable name the provider SDK expects
    pub env_var: String,
    /// The resolved model (from request or config default)
    pub model: Option<String>,
    /// Which step produced the key_alias
    pub source: ResolveSource,
}

/// Which resolution step produced the key_alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveSource {
    /// Caller supplied an explicit alias
    Explicit,
    /// Tenant override from config
    Tenant,
    /// Base provider mapping from config
    Base,
}

/// Errors that can occur during resolution (before vault fetch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No provider name was given
    MissingProvider,
    /// No alias could be found for the provider in any config layer
    NoAliasFound { provider: String },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::MissingProvider =>
                write!(f, "provider name is required"),
            ResolveError::NoAliasFound { provider } =>
                write!(f, "no key alias found for provider '{}'; add it to aikey.config.json providers section", provider),
        }
    }
}

/// Pure resolution logic — no I/O, no vault access.
///
/// Steps 1-4 are handled here. Step 5 (vault fetch) is the caller's
/// responsibility so this function stays testable without a real vault.
pub fn resolve(
    request: &ResolveRequest,
    config: Option<&ProjectConfig>,
) -> Result<ResolveResult, ResolveError> {
    if request.provider.is_empty() {
        return Err(ResolveError::MissingProvider);
    }

    let provider = Provider::parse(&request.provider);
    let env_var = provider.env_var();

    // Step 4 – explicit alias (highest priority, short-circuits everything)
    if let Some(alias) = &request.key_alias {
        let model = resolve_model(request, config);
        return Ok(ResolveResult {
            key_alias: alias.clone(),
            env_var,
            model,
            source: ResolveSource::Explicit,
        });
    }

    // Steps 2 & 3 require a project config
    if let Some(cfg) = config {
        // Step 3 – tenant override
        if let Some(tenant) = &request.tenant {
            if let Some(tenant_map) = cfg.tenants.get(tenant) {
                if let Some(alias) = tenant_map.get(&request.provider) {
                    let model = resolve_model(request, config);
                    return Ok(ResolveResult {
                        key_alias: alias.clone(),
                        env_var,
                        model,
                        source: ResolveSource::Tenant,
                    });
                }
            }
        }

        // Step 2 – base provider mapping
        if let Some(provider_cfg) = cfg.providers.get(&request.provider) {
            let model = request.model.clone()
                .or_else(|| provider_cfg.default_model.clone());
            return Ok(ResolveResult {
                key_alias: provider_cfg.key_alias.clone(),
                env_var,
                model,
                source: ResolveSource::Base,
            });
        }
    }

    // Steps 1 & 5 – no config match; caller must handle vault lookup by alias
    Err(ResolveError::NoAliasFound {
        provider: request.provider.clone(),
    })
}

/// Resolve the model: request > config default > None
fn resolve_model(request: &ResolveRequest, config: Option<&ProjectConfig>) -> Option<String> {
    if request.model.is_some() {
        return request.model.clone();
    }
    config.and_then(|cfg| {
        cfg.providers.get(&request.provider)
            .and_then(|p| p.default_model.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProjectConfig, ProviderConfig};
    use std::collections::HashMap;

    fn make_config() -> ProjectConfig {
        let mut providers = HashMap::new();
        providers.insert("openai".to_string(), ProviderConfig {
            key_alias: "work-openai".to_string(),
            default_model: Some("gpt-4o".to_string()),
        });
        providers.insert("anthropic".to_string(), ProviderConfig {
            key_alias: "personal-claude".to_string(),
            default_model: Some("claude-opus-4-6".to_string()),
        });

        let mut tenant_map = HashMap::new();
        tenant_map.insert("openai".to_string(), "acme-openai".to_string());
        let mut tenants = HashMap::new();
        tenants.insert("acme-corp".to_string(), tenant_map);

        ProjectConfig {
            version: "1".to_string(),
            project: crate::config::ProjectInfo { id: None, name: "test".to_string() },
            env: crate::config::EnvConfig { target: ".env".to_string() },
            required_vars: vec![],
            bindings: HashMap::new(),
            defaults: crate::config::Defaults { profile: None },
            providers,
            tenants,
            hooks: HashMap::new(),
        }
    }

    #[test]
    fn test_step2_base_mapping() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "openai".to_string(),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.key_alias, "work-openai");
        assert_eq!(result.env_var, "OPENAI_API_KEY");
        assert_eq!(result.model, Some("gpt-4o".to_string()));
        assert_eq!(result.source, ResolveSource::Base);
    }

    #[test]
    fn test_step3_tenant_override() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "openai".to_string(),
            tenant: Some("acme-corp".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.key_alias, "acme-openai");
        assert_eq!(result.source, ResolveSource::Tenant);
    }

    #[test]
    fn test_step4_explicit_alias() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "openai".to_string(),
            key_alias: Some("my-custom-alias".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.key_alias, "my-custom-alias");
        assert_eq!(result.source, ResolveSource::Explicit);
    }

    #[test]
    fn test_explicit_beats_tenant() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "openai".to_string(),
            tenant: Some("acme-corp".to_string()),
            key_alias: Some("override".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.key_alias, "override");
        assert_eq!(result.source, ResolveSource::Explicit);
    }

    #[test]
    fn test_model_from_request_beats_config_default() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "openai".to_string(),
            model: Some("gpt-4o-mini".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.model, Some("gpt-4o-mini".to_string()));
    }

    #[test]
    fn test_no_config_no_alias_returns_error() {
        let req = ResolveRequest {
            provider: "openai".to_string(),
            ..Default::default()
        };
        let err = resolve(&req, None).unwrap_err();
        assert_eq!(err, ResolveError::NoAliasFound { provider: "openai".to_string() });
    }

    #[test]
    fn test_missing_provider_returns_error() {
        let req = ResolveRequest::default();
        let err = resolve(&req, None).unwrap_err();
        assert_eq!(err, ResolveError::MissingProvider);
    }

    #[test]
    fn test_unknown_provider_in_config_returns_error() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "cohere".to_string(),
            ..Default::default()
        };
        let err = resolve(&req, Some(&cfg)).unwrap_err();
        assert_eq!(err, ResolveError::NoAliasFound { provider: "cohere".to_string() });
    }

    #[test]
    fn test_no_config_explicit_alias_succeeds() {
        let req = ResolveRequest {
            provider: "anthropic".to_string(),
            key_alias: Some("my-key".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, None).unwrap();
        assert_eq!(result.key_alias, "my-key");
        assert_eq!(result.env_var, "ANTHROPIC_API_KEY");
        assert_eq!(result.source, ResolveSource::Explicit);
    }
}
