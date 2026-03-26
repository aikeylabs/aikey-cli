//! Stage 0 resolution engine with logical-model-first support.
//!
//! Resolution order (first match wins):
//!   1. Context   – active profile name + project root + env
//!   2. Logical   – envMappings[env][logicalModel] → provider/modelId/keyAlias (P1)
//!   3. Base      – providers[provider].keyAlias from project config
//!   4. Tenant    – tenants[tenant][provider] override
//!   5. Explicit  – caller-supplied key_alias override
//!   6. Fetch     – vault lookup of the resolved alias → plaintext secret

use crate::config::ProjectConfig;
use crate::providers::Provider;

/// Input context for a single resolution request.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ResolveRequest {
    /// Provider name (e.g. "openai", "anthropic") - used for provider-first resolution
    pub provider: String,
    /// Logical model name (e.g. "chat-main", "embeddings") - used for logical-model-first resolution (P1)
    pub logical_model: Option<String>,
    /// Environment name (e.g. "dev", "staging", "prod") - used with logical_model for P1 resolution
    pub env: Option<String>,
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
    /// The provider name that was resolved
    pub provider: String,
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
    /// Logical model mapping from envMappings (P1)
    LogicalModel,
}

/// Errors that can occur during resolution (before vault fetch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No provider name or logical model was given
    MissingInput,
    /// No alias could be found for the provider in any config layer
    NoAliasFound { provider: String, profile: Option<String> },
    /// Logical model not found in envMappings
    LogicalModelNotFound { logical_model: String, env: String },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::MissingInput =>
                write!(f, "either provider name or logical model is required"),
            ResolveError::NoAliasFound { provider, profile } => {
                let profile_str = profile.as_deref().unwrap_or("default");
                write!(f, "Missing key: {}:<keyAlias> in profile '{}'.\nFix: run 'aikey provider add --key-alias <alias> {}' or 'aikey quickstart'", provider, profile_str, provider)
            }
            ResolveError::LogicalModelNotFound { logical_model, env } => {
                write!(f, "Logical model '{}' not found in envMappings for env '{}'.\nFix: run 'aikey project map' to configure logical model mappings", logical_model, env)
            }
        }
    }
}

/// Pure resolution logic — no I/O, no vault access.
///
/// P1: Supports both logical-model-first and provider-first resolution.
/// Steps 1-5 are handled here. Step 6 (vault fetch) is the caller's
/// responsibility so this function stays testable without a real vault.
pub fn resolve(
    request: &ResolveRequest,
    config: Option<&ProjectConfig>,
) -> Result<ResolveResult, ResolveError> {
    // Validate input: need either provider or (logical_model + env)
    let has_provider = !request.provider.is_empty();
    let has_logical_model = request.logical_model.is_some() && request.env.is_some();

    if !has_provider && !has_logical_model {
        return Err(ResolveError::MissingInput);
    }

    // Step 5 – explicit alias (highest priority, short-circuits everything)
    if let Some(alias) = &request.key_alias {
        // If we have a logical model, resolve through envMappings to get provider
        let (provider, model) = if has_logical_model {
            resolve_logical_model_metadata(request, config)?
        } else {
            (request.provider.clone(), resolve_model_provider_first(request, config))
        };

        let provider_obj = Provider::parse(&provider);
        let env_var = provider_obj.env_var();

        return Ok(ResolveResult {
            key_alias: alias.clone(),
            env_var,
            model,
            provider,
            source: ResolveSource::Explicit,
        });
    }

    // P1: Step 2 – Logical model resolution (env + logicalModel → provider/modelId/keyAlias)
    if let (Some(logical_model), Some(env)) = (&request.logical_model, &request.env) {
        if let Some(cfg) = config {
            if let Some(env_map) = cfg.env_mappings.get(env) {
                if let Some(mapping) = env_map.get(logical_model) {
                    let provider_obj = Provider::parse(&mapping.provider);
                    let env_var = provider_obj.env_var();

                    // Apply tenant override if present
                    let key_alias = if let Some(tenant) = &request.tenant {
                        if let Some(tenant_map) = cfg.tenants.get(tenant) {
                            if let Some(tenant_alias) = tenant_map.get(&mapping.provider) {
                                tenant_alias.clone()
                            } else {
                                mapping.key_alias.clone()
                            }
                        } else {
                            mapping.key_alias.clone()
                        }
                    } else {
                        mapping.key_alias.clone()
                    };

                    return Ok(ResolveResult {
                        key_alias,
                        env_var,
                        model: request.model.clone().or_else(|| mapping.provider_model_id.clone()),
                        provider: mapping.provider.clone(),
                        source: ResolveSource::LogicalModel,
                    });
                }
            }

            // Logical model not found in envMappings
            return Err(ResolveError::LogicalModelNotFound {
                logical_model: logical_model.clone(),
                env: env.clone(),
            });
        }
    }

    // Provider-first resolution (fallback or when no logical model specified)
    if !has_provider {
        return Err(ResolveError::MissingInput);
    }

    let provider = Provider::parse(&request.provider);
    let env_var = provider.env_var();

    // Steps 3 & 4 require a project config
    if let Some(cfg) = config {
        // Step 4 – tenant override
        if let Some(tenant) = &request.tenant {
            if let Some(tenant_map) = cfg.tenants.get(tenant) {
                if let Some(alias) = tenant_map.get(&request.provider) {
                    let model = resolve_model_provider_first(request, config);
                    return Ok(ResolveResult {
                        key_alias: alias.clone(),
                        env_var,
                        model,
                        provider: request.provider.clone(),
                        source: ResolveSource::Tenant,
                    });
                }
            }
        }

        // Step 3 – base provider mapping
        if let Some(provider_cfg) = cfg.providers.get(&request.provider) {
            let model = request.model.clone()
                .or_else(|| provider_cfg.default_model.clone());
            return Ok(ResolveResult {
                key_alias: provider_cfg.key_alias.clone(),
                env_var,
                model,
                provider: request.provider.clone(),
                source: ResolveSource::Base,
            });
        }
    }

    // Steps 1 & 6 – no config match; caller must handle vault lookup by alias
    Err(ResolveError::NoAliasFound {
        provider: request.provider.clone(),
        profile: request.profile.clone(),
    })
}

/// Resolve provider and model from logical model mapping
fn resolve_logical_model_metadata(
    request: &ResolveRequest,
    config: Option<&ProjectConfig>,
) -> Result<(String, Option<String>), ResolveError> {
    if let (Some(logical_model), Some(env)) = (&request.logical_model, &request.env) {
        if let Some(cfg) = config {
            if let Some(env_map) = cfg.env_mappings.get(env) {
                if let Some(mapping) = env_map.get(logical_model) {
                    let model = request.model.clone()
                        .or_else(|| mapping.provider_model_id.clone());
                    return Ok((mapping.provider.clone(), model));
                }
            }
        }
        return Err(ResolveError::LogicalModelNotFound {
            logical_model: logical_model.clone(),
            env: env.clone(),
        });
    }
    Err(ResolveError::MissingInput)
}

/// Resolve the model for provider-first resolution: request > config default > None
fn resolve_model_provider_first(request: &ResolveRequest, config: Option<&ProjectConfig>) -> Option<String> {
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
    use crate::config::{ProjectConfig, ProviderConfig, LogicalModelMapping};
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

        // P1: Add envMappings for logical-model-first resolution
        let mut env_mappings = HashMap::new();
        let mut dev_mappings = HashMap::new();
        dev_mappings.insert("chat-main".to_string(), LogicalModelMapping {
            provider: "openai".to_string(),
            provider_model_id: Some("gpt-4o-mini".to_string()),
            key_alias: "openai:dev".to_string(),
            impl_id: None,
        });
        dev_mappings.insert("chat-advanced".to_string(), LogicalModelMapping {
            provider: "anthropic".to_string(),
            provider_model_id: Some("claude-opus-4-6".to_string()),
            key_alias: "anthropic:dev".to_string(),
            impl_id: None,
        });
        env_mappings.insert("dev".to_string(), dev_mappings);

        let mut prod_mappings = HashMap::new();
        prod_mappings.insert("chat-main".to_string(), LogicalModelMapping {
            provider: "openai".to_string(),
            provider_model_id: Some("gpt-4o".to_string()),
            key_alias: "openai:prod".to_string(),
            impl_id: None,
        });
        env_mappings.insert("prod".to_string(), prod_mappings);

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
            env_mappings,
        }
    }

    // Provider-first resolution tests
    #[test]
    fn test_step3_base_mapping() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "openai".to_string(),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.key_alias, "work-openai");
        assert_eq!(result.env_var, "OPENAI_API_KEY");
        assert_eq!(result.model, Some("gpt-4o".to_string()));
        assert_eq!(result.provider, "openai");
        assert_eq!(result.source, ResolveSource::Base);
    }

    #[test]
    fn test_step4_tenant_override() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "openai".to_string(),
            tenant: Some("acme-corp".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.key_alias, "acme-openai");
        assert_eq!(result.env_var, "OPENAI_API_KEY");
        assert_eq!(result.provider, "openai");
        assert_eq!(result.source, ResolveSource::Tenant);
    }

    #[test]
    fn test_step5_explicit_alias() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "anthropic".to_string(),
            key_alias: Some("my-custom-key".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.key_alias, "my-custom-key");
        assert_eq!(result.env_var, "ANTHROPIC_API_KEY");
        assert_eq!(result.provider, "anthropic");
        assert_eq!(result.source, ResolveSource::Explicit);
    }

    // P1: Logical-model-first resolution tests
    #[test]
    fn test_logical_model_resolution_dev() {
        let cfg = make_config();
        let req = ResolveRequest {
            logical_model: Some("chat-main".to_string()),
            env: Some("dev".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.key_alias, "openai:dev");
        assert_eq!(result.env_var, "OPENAI_API_KEY");
        assert_eq!(result.model, Some("gpt-4o-mini".to_string()));
        assert_eq!(result.provider, "openai");
        assert_eq!(result.source, ResolveSource::LogicalModel);
    }

    #[test]
    fn test_logical_model_resolution_prod() {
        let cfg = make_config();
        let req = ResolveRequest {
            logical_model: Some("chat-main".to_string()),
            env: Some("prod".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        assert_eq!(result.key_alias, "openai:prod");
        assert_eq!(result.env_var, "OPENAI_API_KEY");
        assert_eq!(result.model, Some("gpt-4o".to_string()));
        assert_eq!(result.provider, "openai");
        assert_eq!(result.source, ResolveSource::LogicalModel);
    }

    #[test]
    fn test_logical_model_with_tenant_override() {
        let cfg = make_config();
        let req = ResolveRequest {
            logical_model: Some("chat-main".to_string()),
            env: Some("dev".to_string()),
            tenant: Some("acme-corp".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        // Tenant override should apply to the resolved provider
        assert_eq!(result.key_alias, "acme-openai");
        assert_eq!(result.env_var, "OPENAI_API_KEY");
        assert_eq!(result.provider, "openai");
        assert_eq!(result.source, ResolveSource::LogicalModel);
    }

    #[test]
    fn test_logical_model_not_found() {
        let cfg = make_config();
        let req = ResolveRequest {
            logical_model: Some("nonexistent".to_string()),
            env: Some("dev".to_string()),
            ..Default::default()
        };
        let err = resolve(&req, Some(&cfg)).unwrap_err();
        assert_eq!(err, ResolveError::LogicalModelNotFound {
            logical_model: "nonexistent".to_string(),
            env: "dev".to_string(),
        });
    }

    #[test]
    fn test_logical_model_env_not_found() {
        let cfg = make_config();
        let req = ResolveRequest {
            logical_model: Some("chat-main".to_string()),
            env: Some("staging".to_string()),
            ..Default::default()
        };
        let err = resolve(&req, Some(&cfg)).unwrap_err();
        assert_eq!(err, ResolveError::LogicalModelNotFound {
            logical_model: "chat-main".to_string(),
            env: "staging".to_string(),
        });
    }

    #[test]
    fn test_missing_input_returns_error() {
        let req = ResolveRequest::default();
        let err = resolve(&req, None).unwrap_err();
        assert_eq!(err, ResolveError::MissingInput);
    }

    #[test]
    fn test_unknown_provider_in_config_returns_error() {
        let cfg = make_config();
        let req = ResolveRequest {
            provider: "cohere".to_string(),
            ..Default::default()
        };
        let err = resolve(&req, Some(&cfg)).unwrap_err();
        assert_eq!(err, ResolveError::NoAliasFound { provider: "cohere".to_string(), profile: None });
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
        assert_eq!(result.provider, "anthropic");
        assert_eq!(result.source, ResolveSource::Explicit);
    }

    #[test]
    fn test_logical_model_with_explicit_alias() {
        let cfg = make_config();
        let req = ResolveRequest {
            logical_model: Some("chat-main".to_string()),
            env: Some("dev".to_string()),
            key_alias: Some("my-override".to_string()),
            ..Default::default()
        };
        let result = resolve(&req, Some(&cfg)).unwrap();
        // Explicit alias should win, but provider should come from logical model
        assert_eq!(result.key_alias, "my-override");
        assert_eq!(result.provider, "openai");
        assert_eq!(result.env_var, "OPENAI_API_KEY");
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
        assert_eq!(err, ResolveError::NoAliasFound { provider: "openai".to_string(), profile: None });
    }
}
