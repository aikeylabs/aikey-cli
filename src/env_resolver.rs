use crate::config::ProjectConfig;
use std::collections::HashMap;

/// Represents a resolved environment variable with its source
#[derive(Debug, Clone)]
pub struct ResolvedVar {
    pub name: String,
    pub value: Option<String>,
    pub source: VarSource,
    /// True when the value is a secret (API key, token, etc.) that must not be
    /// written to disk in plaintext. `env generate` will emit a placeholder
    /// instead of the real value for these variables.
    pub is_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VarSource {
    Profile,
    Environment,
    Default,
    Missing,
}

/// Resolves environment variables from project config and current profile
pub struct EnvResolver;

impl EnvResolver {
    /// Resolve all required variables for a project
    pub fn resolve(
        config: &ProjectConfig,
        _profile_name: &str,
        profile_vars: &HashMap<String, String>,
    ) -> Result<Vec<ResolvedVar>, String> {
        let mut resolved = Vec::new();

        for var_name in &config.required_vars {
            let value = profile_vars.get(var_name).cloned();
            let source = if value.is_some() {
                VarSource::Profile
            } else {
                VarSource::Missing
            };
            // Variables bound to a vault alias hold secrets (API keys, tokens).
            let is_sensitive = config.bindings.contains_key(var_name);

            resolved.push(ResolvedVar {
                name: var_name.clone(),
                value,
                source,
                is_sensitive,
            });
        }

        Ok(resolved)
    }

    /// Check if all required variables are satisfied
    pub fn all_satisfied(resolved: &[ResolvedVar]) -> bool {
        resolved.iter().all(|v| v.value.is_some())
    }

    /// Count satisfied variables
    pub fn count_satisfied(resolved: &[ResolvedVar]) -> (usize, usize) {
        let total = resolved.len();
        let satisfied = resolved.iter().filter(|v| v.value.is_some()).count();
        (satisfied, total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProjectConfig;

    #[test]
    fn test_resolve_all_satisfied() {
        let config = ProjectConfig::new("test".to_string());
        let mut config = config;
        config.required_vars = vec!["KEY1".to_string(), "KEY2".to_string()];

        let mut profile_vars = HashMap::new();
        profile_vars.insert("KEY1".to_string(), "value1".to_string());
        profile_vars.insert("KEY2".to_string(), "value2".to_string());

        let resolved = EnvResolver::resolve(&config, "default", &profile_vars).unwrap();

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "KEY1");
        assert_eq!(resolved[0].value, Some("value1".to_string()));
        assert_eq!(resolved[0].source, VarSource::Profile);
        assert_eq!(resolved[1].name, "KEY2");
        assert_eq!(resolved[1].value, Some("value2".to_string()));
        assert_eq!(resolved[1].source, VarSource::Profile);
    }

    #[test]
    fn test_resolve_partial_satisfied() {
        let config = ProjectConfig::new("test".to_string());
        let mut config = config;
        config.required_vars = vec!["KEY1".to_string(), "KEY2".to_string(), "KEY3".to_string()];

        let mut profile_vars = HashMap::new();
        profile_vars.insert("KEY1".to_string(), "value1".to_string());

        let resolved = EnvResolver::resolve(&config, "default", &profile_vars).unwrap();

        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0].value, Some("value1".to_string()));
        assert_eq!(resolved[0].source, VarSource::Profile);
        assert_eq!(resolved[1].value, None);
        assert_eq!(resolved[1].source, VarSource::Missing);
        assert_eq!(resolved[2].value, None);
        assert_eq!(resolved[2].source, VarSource::Missing);
    }

    #[test]
    fn test_resolve_none_satisfied() {
        let config = ProjectConfig::new("test".to_string());
        let mut config = config;
        config.required_vars = vec!["KEY1".to_string(), "KEY2".to_string()];

        let profile_vars = HashMap::new();
        let resolved = EnvResolver::resolve(&config, "default", &profile_vars).unwrap();

        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().all(|v| v.value.is_none()));
        assert!(resolved.iter().all(|v| v.source == VarSource::Missing));
    }

    #[test]
    fn test_all_satisfied() {
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("value1".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "KEY2".to_string(),
                value: Some("value2".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
        ];

        assert!(EnvResolver::all_satisfied(&resolved));
    }

    #[test]
    fn test_not_all_satisfied() {
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("value1".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "KEY2".to_string(),
                value: None,
                source: VarSource::Missing,
                is_sensitive: false,
            },
        ];

        assert!(!EnvResolver::all_satisfied(&resolved));
    }

    #[test]
    fn test_count_satisfied() {
        let resolved = vec![
            ResolvedVar {
                name: "KEY1".to_string(),
                value: Some("value1".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "KEY2".to_string(),
                value: None,
                source: VarSource::Missing,
                is_sensitive: false,
            },
            ResolvedVar {
                name: "KEY3".to_string(),
                value: Some("value3".to_string()),
                source: VarSource::Profile,
                is_sensitive: false,
            },
        ];

        let (satisfied, total) = EnvResolver::count_satisfied(&resolved);
        assert_eq!(satisfied, 2);
        assert_eq!(total, 3);
    }
}
