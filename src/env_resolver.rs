use crate::config::ProjectConfig;
use std::collections::HashMap;

/// Represents a resolved environment variable with its source
#[derive(Debug, Clone)]
pub struct ResolvedVar {
    pub name: String,
    pub value: Option<String>,
    pub source: VarSource,
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

        for var_name in &config.requiredVars {
            let value = profile_vars.get(var_name).cloned();
            let source = if value.is_some() {
                VarSource::Profile
            } else {
                VarSource::Missing
            };

            resolved.push(ResolvedVar {
                name: var_name.clone(),
                value,
                source,
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
