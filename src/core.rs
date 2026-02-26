//! Core module for integrated profile, binding, and environment management
//!
//! This module provides high-level operations that coordinate between:
//! - Profile management (profiles.rs)
//! - Secret bindings (storage.rs)
//! - Environment resolution (env_resolver.rs)
//! - Secret retrieval (executor.rs)

use crate::config::ProjectConfig;
use crate::env_resolver::{EnvResolver, ResolvedVar};
use crate::executor;
use crate::profiles;
use crate::storage;
use rusqlite::Connection;
use secrecy::SecretString;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Represents a complete environment context for a project
#[derive(Debug, Clone)]
pub struct EnvironmentContext {
    /// The active profile name
    pub profile_name: String,
    /// Resolved environment variables with their sources
    pub resolved_vars: Vec<ResolvedVar>,
    /// Actual secret values (only populated when needed)
    pub secret_values: HashMap<String, Zeroizing<String>>,
}

impl EnvironmentContext {
    /// Check if all required variables are satisfied
    pub fn is_complete(&self) -> bool {
        EnvResolver::all_satisfied(&self.resolved_vars)
    }

    /// Get satisfaction status
    pub fn satisfaction_status(&self) -> (usize, usize) {
        EnvResolver::count_satisfied(&self.resolved_vars)
    }

    /// Get a resolved variable by name
    pub fn get_var(&self, name: &str) -> Option<&ResolvedVar> {
        self.resolved_vars.iter().find(|v| v.name == name)
    }

    /// Get a secret value by name
    pub fn get_secret_value(&self, name: &str) -> Option<&Zeroizing<String>> {
        self.secret_values.get(name)
    }
}

/// Core operations for environment management
pub struct Core;

impl Core {
    fn build_binding_map(
        conn: &Connection,
        profile_name: &str,
        config: &ProjectConfig,
    ) -> Result<HashMap<String, String>, String> {
        let mut map = HashMap::new();

        // Stored bindings: domain (env var) -> alias
        let stored = storage::get_profile_bindings(conn, profile_name)?;
        for (domain, alias) in stored {
            map.insert(domain, alias);
        }

        // Config bindings: logical alias -> env var (invert to env var -> alias)
        for (logical_alias, env_var) in &config.bindings {
            map.entry(env_var.clone()).or_insert_with(|| logical_alias.clone());
        }

        Ok(map)
    }

    /// Resolve environment for a project with the active profile
    ///
    /// This is the main entry point for getting a complete environment context.
    /// It:
    /// 1. Discovers the project config
    /// 2. Gets the active profile
    /// 3. Retrieves bindings for that profile
    /// 4. Resolves all required variables
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `password` - Master password for vault access
    ///
    /// # Returns
    /// An EnvironmentContext with resolved variables, or an error if:
    /// - No project config found
    /// - No active profile set
    /// - Vault access fails
    pub fn resolve_environment(
        conn: &Connection,
        password: &SecretString,
    ) -> Result<EnvironmentContext, String> {
        // Discover project config
        let (_config_path, config) = ProjectConfig::discover()?
            .ok_or_else(|| "No project configuration found. Run 'aikey project init' first.".to_string())?;

        Self::resolve_environment_with_config(conn, password, &config)
    }

    /// Resolve environment using a provided config (no discovery)
    pub fn resolve_environment_with_config(
        conn: &Connection,
        password: &SecretString,
        config: &ProjectConfig,
    ) -> Result<EnvironmentContext, String> {
        // Get active profile (auto-create default if missing)
        let profile = if let Some(profile) = profiles::get_active_profile(conn)? {
            profile
        } else {
            let default_name = config.defaults.profile.clone().unwrap_or_else(|| "default".to_string());
            profiles::set_active_profile(conn, &default_name)?
        };

        let binding_map = Self::build_binding_map(conn, &profile.name, config)?;

        // Convert bindings to a HashMap for resolution using env var name -> secret value
        let mut profile_vars = HashMap::new();
        for var_name in &config.required_vars {
            let alias = binding_map.get(var_name).cloned().unwrap_or_else(|| var_name.clone());
            if let Ok(secret_value) = executor::get_secret(&alias, password) {
                profile_vars.insert(var_name.clone(), secret_value.to_string());
            }
        }

        // Resolve variables
        let resolved_vars = EnvResolver::resolve(config, &profile.name, &profile_vars)?;

        Ok(EnvironmentContext {
            profile_name: profile.name,
            resolved_vars,
            secret_values: HashMap::new(),
        })
    }

    /// Resolve environment metadata without accessing secret values
    pub fn resolve_environment_metadata_with_config(
        conn: &Connection,
        config: &ProjectConfig,
    ) -> Result<EnvironmentContext, String> {
        let profile = if let Some(profile) = profiles::get_active_profile(conn)? {
            profile
        } else {
            let default_name = config.defaults.profile.clone().unwrap_or_else(|| "default".to_string());
            profiles::set_active_profile(conn, &default_name)?
        };

        Self::resolve_environment_metadata_for_profile_with_config(conn, &profile.name, config)
    }

    /// Resolve environment metadata for a specific profile without accessing secret values
    pub fn resolve_environment_metadata_for_profile_with_config(
        conn: &Connection,
        profile_name: &str,
        config: &ProjectConfig,
    ) -> Result<EnvironmentContext, String> {
        let profiles_list = profiles::list_profiles(conn)?;
        let profile = profiles_list
            .iter()
            .find(|p| p.name == profile_name)
            .ok_or_else(|| format!("Profile '{}' not found", profile_name))?
            .clone();

        let binding_map = Self::build_binding_map(conn, &profile.name, config)?;
        let mut profile_vars = HashMap::new();
        for var_name in &config.required_vars {
            let alias = binding_map.get(var_name).cloned().unwrap_or_else(|| var_name.clone());
            if storage::entry_exists(&alias).unwrap_or(false) {
                profile_vars.insert(var_name.clone(), "set".to_string());
            }
        }

        let resolved_vars = EnvResolver::resolve(config, &profile.name, &profile_vars)?;

        Ok(EnvironmentContext {
            profile_name: profile.name,
            resolved_vars,
            secret_values: HashMap::new(),
        })
    }

    /// Resolve environment for a specific profile
    ///
    /// Similar to resolve_environment but allows specifying a profile name.
    pub fn resolve_environment_for_profile(
        conn: &Connection,
        profile_name: &str,
        password: &SecretString,
    ) -> Result<EnvironmentContext, String> {
        // Discover project config
        let (_config_path, config) = ProjectConfig::discover()?
            .ok_or_else(|| "No project configuration found. Run 'aikey project init' first.".to_string())?;

        Self::resolve_environment_for_profile_with_config(conn, profile_name, password, &config)
    }

    /// Resolve environment for a specific profile using a provided config
    pub fn resolve_environment_for_profile_with_config(
        conn: &Connection,
        profile_name: &str,
        password: &SecretString,
        config: &ProjectConfig,
    ) -> Result<EnvironmentContext, String> {
        // Get the specified profile
        let profiles_list = profiles::list_profiles(conn)?;
        let profile = profiles_list
            .iter()
            .find(|p| p.name == profile_name)
            .ok_or_else(|| format!("Profile '{}' not found", profile_name))?
            .clone();

        let binding_map = Self::build_binding_map(conn, &profile.name, config)?;

        // Convert bindings to a HashMap for resolution
        let mut profile_vars = HashMap::new();
        for var_name in &config.required_vars {
            let alias = binding_map.get(var_name).cloned().unwrap_or_else(|| var_name.clone());
            if let Ok(secret_value) = executor::get_secret(&alias, password) {
                profile_vars.insert(var_name.clone(), secret_value.to_string());
            }
        }

        // Resolve variables
        let resolved_vars = EnvResolver::resolve(config, &profile.name, &profile_vars)?;

        Ok(EnvironmentContext {
            profile_name: profile.name,
            resolved_vars,
            secret_values: HashMap::new(),
        })
    }

    /// Bind a secret to a profile for a specific environment variable
    ///
    /// This creates a binding between a profile and a secret alias, indicating
    /// that the secret should be used to populate a specific environment variable.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `profile_name` - Name of the profile
    /// * `secret_alias` - Alias of the secret to bind
    ///
    /// # Returns
    /// Ok if binding was created, or an error if:
    /// - Profile doesn't exist
    /// - Secret doesn't exist
    /// - Database error
    pub fn bind_secret_to_profile(
        conn: &Connection,
        profile_name: &str,
        domain: &str,
        secret_alias: &str,
    ) -> Result<(), String> {
        // Verify profile exists
        let profiles_list = profiles::list_profiles(conn)?;
        if !profiles_list.iter().any(|p| p.name == profile_name) {
            return Err(format!("Profile '{}' not found", profile_name));
        }

        // Verify secret exists
        storage::get_entry(secret_alias)?;

        // Create binding
        storage::add_profile_binding(conn, profile_name, domain, secret_alias)
    }

    /// Remove a binding between a secret and a profile
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `profile_name` - Name of the profile
    /// * `secret_alias` - Alias of the secret to unbind
    pub fn unbind_secret_from_profile(
        conn: &Connection,
        profile_name: &str,
        domain: &str,
        secret_alias: &str,
    ) -> Result<(), String> {
        storage::remove_profile_binding(conn, profile_name, domain, secret_alias)
    }

    /// List all bindings for a profile
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `profile_name` - Name of the profile
    ///
    /// # Returns
    /// A vector of secret aliases bound to this profile
    pub fn list_profile_bindings(
        conn: &Connection,
        profile_name: &str,
    ) -> Result<Vec<(String, String)>, String> {
        storage::get_profile_bindings(conn, profile_name)
    }

    /// Get environment variables as a HashMap suitable for process execution
    ///
    /// This retrieves the actual secret values for all resolved variables
    /// and returns them as a HashMap ready to be passed to a subprocess.
    ///
    /// # Arguments
    /// * `context` - The environment context
    /// * `password` - Master password for vault access
    ///
    /// # Returns
    /// A HashMap of environment variable names to their values
    pub fn get_env_vars_for_execution(
        context: &EnvironmentContext,
        password: &SecretString,
    ) -> Result<HashMap<String, Zeroizing<String>>, String> {
        let mut env_vars = HashMap::new();

        for var in &context.resolved_vars {
            if let Some(alias) = &var.value {
                let secret_value = executor::get_secret(alias, password)?;
                env_vars.insert(var.name.clone(), secret_value);
            }
        }

        Ok(env_vars)
    }

    /// Create a new profile with bindings
    ///
    /// This is a convenience method that creates a profile and optionally
    /// binds secrets to it in one operation.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `profile_name` - Name for the new profile
    /// * `bindings` - Optional vector of secret aliases to bind
    pub fn create_profile_with_bindings(
        conn: &Connection,
        profile_name: &str,
        bindings: Option<Vec<String>>,
    ) -> Result<(), String> {
        // Create the profile
        profiles::create_profile(conn, profile_name)?;

        // Add bindings if provided
        if let Some(binding_list) = bindings {
            for alias in binding_list {
                Self::bind_secret_to_profile(conn, profile_name, "default", &alias)?;
            }
        }

        Ok(())
    }

    /// Delete a profile and all its bindings
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `profile_name` - Name of the profile to delete
    pub fn delete_profile_with_bindings(
        conn: &Connection,
        profile_name: &str,
    ) -> Result<(), String> {
        profiles::delete_profile(conn, profile_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_context_is_complete() {
        let context = EnvironmentContext {
            profile_name: "test".to_string(),
            resolved_vars: vec![
                ResolvedVar {
                    name: "KEY1".to_string(),
                    value: Some("secret1".to_string()),
                    source: crate::env_resolver::VarSource::Profile,
                },
                ResolvedVar {
                    name: "KEY2".to_string(),
                    value: Some("secret2".to_string()),
                    source: crate::env_resolver::VarSource::Profile,
                },
            ],
            secret_values: HashMap::new(),
        };

        assert!(context.is_complete());
    }

    #[test]
    fn test_environment_context_not_complete() {
        let context = EnvironmentContext {
            profile_name: "test".to_string(),
            resolved_vars: vec![
                ResolvedVar {
                    name: "KEY1".to_string(),
                    value: Some("secret1".to_string()),
                    source: crate::env_resolver::VarSource::Profile,
                },
                ResolvedVar {
                    name: "KEY2".to_string(),
                    value: None,
                    source: crate::env_resolver::VarSource::Missing,
                },
            ],
            secret_values: HashMap::new(),
        };

        assert!(!context.is_complete());
    }

    #[test]
    fn test_environment_context_satisfaction_status() {
        let context = EnvironmentContext {
            profile_name: "test".to_string(),
            resolved_vars: vec![
                ResolvedVar {
                    name: "KEY1".to_string(),
                    value: Some("secret1".to_string()),
                    source: crate::env_resolver::VarSource::Profile,
                },
                ResolvedVar {
                    name: "KEY2".to_string(),
                    value: None,
                    source: crate::env_resolver::VarSource::Missing,
                },
                ResolvedVar {
                    name: "KEY3".to_string(),
                    value: Some("secret3".to_string()),
                    source: crate::env_resolver::VarSource::Profile,
                },
            ],
            secret_values: HashMap::new(),
        };

        let (satisfied, total) = context.satisfaction_status();
        assert_eq!(satisfied, 2);
        assert_eq!(total, 3);
    }

    #[test]
    fn test_environment_context_get_var() {
        let context = EnvironmentContext {
            profile_name: "test".to_string(),
            resolved_vars: vec![
                ResolvedVar {
                    name: "KEY1".to_string(),
                    value: Some("secret1".to_string()),
                    source: crate::env_resolver::VarSource::Profile,
                },
            ],
            secret_values: HashMap::new(),
        };

        let var = context.get_var("KEY1");
        assert!(var.is_some());
        assert_eq!(var.unwrap().name, "KEY1");
    }
}
